#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Any

from common import (
    DATA_DIR,
    TEMP_ROOT,
    TOOL_DIR,
    VERSION,
    ByteProgress,
    ErrorArgumentParser,
    SingleUseStoreTrueAction,
    compare_versions,
    format_bytes,
    is_sha256,
    parse_json,
    parse_version,
    relative_path_parts,
    sha256_file,
)

UPDATE_CONFIG_FILE = DATA_DIR / "update.json"
GITHUB_RELEASES_API = "https://api.github.com/repos/DarkLotus8000/Ninja-Patch-Tool/releases/latest"
GITHUB_RELEASES_URL = "https://github.com/DarkLotus8000/Ninja-Patch-Tool/releases"
UPDATE_ATTEMPTS = 3
STALE_UPDATE_AGE_SECONDS = 7 * 24 * 60 * 60


def add_update_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-a",
        "--auto-update",
        action=SingleUseStoreTrueAction,
        help="Enable automatic updating for this run, overriding data/update.json",
    )
    group.add_argument(
        "-n",
        "--no-auto-update",
        action=SingleUseStoreTrueAction,
        help="Disable automatic updating for this run, overriding data/update.json",
    )
    group.add_argument(
        "-u",
        "--check-update",
        action=SingleUseStoreTrueAction,
        help="Check GitHub Releases for a newer version without installing it",
    )


def _move_file_if_absent_windows(source: Path, destination: Path) -> None:
    # FAT/exFAT do not support hard links. MoveFileEx without MOVEFILE_REPLACE_EXISTING gives us the same important
    # property on Windows: atomic publication within the directory without overwriting a config another process won.
    if sys.platform != "win32":
        raise OSError("Atomic non-overwriting update config fallback is Windows-only.")

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    kernel32.MoveFileExW.restype = wintypes.BOOL
    if kernel32.MoveFileExW(str(source), str(destination), 0x8):  # MOVEFILE_WRITE_THROUGH
        return

    error = ctypes.get_last_error()
    if error in {80, 183}:  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
        raise FileExistsError(error, "Update configuration already exists.", str(destination))
    raise OSError(error, "Could not publish the default update configuration.", str(destination))


def _create_default_update_config() -> None:
    UPDATE_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = UPDATE_CONFIG_FILE.with_name(f"{UPDATE_CONFIG_FILE.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as file:
            file.write(json.dumps({"auto_update": True}, indent=2) + "\n")
        try:
            # Hard-link publication is atomic and never overwrites a config that another process created first.
            os.link(temporary, UPDATE_CONFIG_FILE)
        except FileExistsError:
            pass
        except OSError:
            try:
                _move_file_if_absent_windows(temporary, UPDATE_CONFIG_FILE)
            except FileExistsError:
                pass
    finally:
        temporary.unlink(missing_ok=True)


def load_auto_update_setting() -> bool:
    if not UPDATE_CONFIG_FILE.exists():
        try:
            _create_default_update_config()
        except OSError as exc:
            print(
                f"[Update] Warning: Could not create {UPDATE_CONFIG_FILE}; automatic updating is disabled for this run: {exc}",
                file=sys.stderr,
            )
            return False

    try:
        config = parse_json(UPDATE_CONFIG_FILE.read_text(encoding="utf-8"))
        if not isinstance(config, dict) or not isinstance(config.get("auto_update"), bool):
            raise ValueError('Expected a JSON object containing boolean "auto_update".')
        return config["auto_update"]
    except (OSError, ValueError) as exc:
        print(
            f"[Update] Warning: Invalid update configuration; automatic updating is disabled for this run: {exc}",
            file=sys.stderr,
        )
        return False


def _request(url: str, timeout: float):
    if not url.lower().startswith("https://"):
        raise RuntimeError(f"Update URL is not HTTPS: {url}")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"NinjaPatchTool/{VERSION}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    return urllib.request.urlopen(request, timeout=timeout)


def _request_json(url: str) -> dict[str, Any]:
    with _request(url, 5) as response:
        payload = response.read()
    result = parse_json(payload)
    if not isinstance(result, dict):
        raise RuntimeError("GitHub returned an unexpected response.")
    return result


def latest_release() -> dict[str, Any]:
    release = _request_json(GITHUB_RELEASES_API)
    tag = release.get("tag_name")
    assets = release.get("assets")
    html_url = release.get("html_url")
    if not isinstance(tag, str) or not tag.strip():
        raise RuntimeError("Latest GitHub Release does not contain a valid tag name.")
    parse_version(tag)
    if not isinstance(assets, list):
        raise RuntimeError("Latest GitHub Release does not contain an asset list.")
    if not isinstance(html_url, str) or not html_url.lower().startswith("https://github.com/"):
        html_url = GITHUB_RELEASES_URL
    version = tag[1:] if tag[:1].lower() == "v" else tag
    return {"tag": tag, "version": version, "assets": assets, "url": html_url}


def find_release_asset(release: dict[str, Any], name: str) -> tuple[str, int | None]:
    for asset in release["assets"]:
        if not isinstance(asset, dict) or asset.get("name") != name:
            continue
        url = asset.get("browser_download_url")
        size = asset.get("size")
        if not isinstance(url, str) or not url.lower().startswith("https://"):
            raise RuntimeError(f"GitHub Release asset has an invalid download URL: {name}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            size = None
        return url, size
    raise RuntimeError(f"Required GitHub Release asset is missing: {name}")


def check_for_update() -> dict[str, Any] | None:
    release = latest_release()
    if compare_versions(release["version"], VERSION) <= 0:
        return None
    return release


def check_update_only() -> int:
    try:
        release = latest_release()
        comparison = compare_versions(release["version"], VERSION)
        if comparison < 0:
            print(
                f"[Update] Local Ninja Patch Tool v{VERSION} is newer than the latest release "
                f"v{release['version']}."
            )
        elif comparison == 0:
            print(f"[Update] Ninja Patch Tool v{VERSION} is up to date.")
        else:
            print(
                f"[Update] Ninja Patch Tool v{release['version']} is available.\n"
                f"Current version: v{VERSION}\n"
                f"Release: {release['url']}"
            )
        return 0
    except KeyboardInterrupt:
        print("\nUpdate check cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: Update check failed: {exc}", file=sys.stderr)
        return 1


def handle_early_update_request(argv: list[str]) -> int | None:
    try:
        cleanup_temporary_updater()
        cleanup_stale_temporary_updaters()
        cleanup_stale_update_work()
        parser = ErrorArgumentParser()
        add_update_arguments(parser)
        args, remaining = parser.parse_known_args(argv)
        if not args.check_update:
            return None
        if remaining:
            parser.error("--check-update must be used without operation arguments")
        return check_update_only()
    except KeyboardInterrupt:
        print("\nStartup cancelled.", file=sys.stderr)
        return 130


def _ensure_free_space(path: Path, required: int, purpose: str) -> None:
    if required <= 0:
        return
    free = shutil.disk_usage(path).free
    if free < required:
        raise RuntimeError(
            f"Not enough free disk space to {purpose}: {format_bytes(required)} required, {format_bytes(free)} available."
        )


def _download_file(
    url: str,
    destination: Path,
    expected_size: int | None = None,
    progress_label: str | None = None,
) -> None:
    temporary = destination.with_name(destination.name + ".part")
    temporary.unlink(missing_ok=True)
    written = 0
    progress = ByteProgress(progress_label, expected_size) if progress_label is not None and expected_size is not None else None
    try:
        with _request(url, 30) as response, temporary.open("xb") as output:
            while chunk := response.read(8 * 1024 * 1024):
                if output.write(chunk) != len(chunk):
                    raise RuntimeError(f"Could not completely write downloaded update file: {destination.name}")
                written += len(chunk)
                if progress is not None:
                    progress.update(len(chunk))
        if expected_size is not None and written != expected_size:
            raise RuntimeError(
                f"Downloaded size does not match GitHub metadata for {destination.name}: "
                f"{format_bytes(written)} instead of {format_bytes(expected_size)}"
            )
        if progress is not None:
            progress.finish()
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _read_expected_checksum(path: Path, archive_name: str) -> str:
    lines = [line.strip() for line in path.read_text(encoding="ascii").splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError("Release checksum file must contain exactly one non-empty line.")
    parts = lines[0].split()
    if len(parts) != 2 or not is_sha256(parts[0]) or parts[1].lstrip("*") != archive_name:
        raise RuntimeError("Release checksum file has an unexpected format or filename.")
    return parts[0].lower()


def _safe_archive_parts(name: str) -> tuple[str, ...]:
    # ZIP member names are POSIX-style. Reject backslashes rather than normalizing them, then apply the same strict
    # Windows path rules used by Ninja Patch manifests (reserved devices, ADS syntax, trailing dots/spaces, etc.).
    if not name or "\\" in name or "\0" in name:
        raise RuntimeError(f"Unsafe update archive path: {name!r}")
    try:
        return relative_path_parts(name)
    except ValueError as exc:
        raise RuntimeError(f"Unsafe update archive path: {name!r}") from exc


def extract_release_archive(archive_path: Path, destination: Path, release_version: str) -> Path:
    expected_root = f"NinjaPatchTool-v{release_version}"
    seen: set[str] = set()
    destination.mkdir(parents=True, exist_ok=False)

    with zipfile.ZipFile(archive_path, "r") as archive:
        members = archive.infolist()
        if not members:
            raise RuntimeError("Downloaded release archive is empty.")

        extracted_size = 0
        for member in members:
            parts = _safe_archive_parts(member.filename.rstrip("/"))
            if not parts or parts[0] != expected_root:
                raise RuntimeError(f"Unexpected release archive root: {member.filename}")
            folded = member.filename.rstrip("/").casefold()
            if folded in seen:
                raise RuntimeError(f"Release archive contains a duplicate path: {member.filename}")
            seen.add(folded)
            mode = (member.external_attr >> 16) & 0xFFFF
            if mode & 0o170000 == 0o120000:
                raise RuntimeError(f"Release archive contains a symbolic link: {member.filename}")
            if not member.is_dir():
                extracted_size += member.file_size

        # The staged release remains present while it is copied into the installation, so allow space for both copies.
        _ensure_free_space(destination.parent, extracted_size * 2, "extract and install the update")

        for member in members:
            clean_name = member.filename.rstrip("/")
            if not clean_name:
                continue
            parts = _safe_archive_parts(clean_name)
            relative = parts[1:]
            target = destination.joinpath(*relative)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=8 * 1024 * 1024)

    required = (
        "add_base.exe",
        "verify_base.exe",
        "make_patch.exe",
        "apply_patch.exe",
        "updater.exe",
        "README.txt",
        "data/index.json",
        "data/update.json",
        "data/hdiffz.exe",
        "data/hpatchz.exe",
    )
    missing = [name for name in required if not (destination / Path(name)).is_file()]
    if missing:
        raise RuntimeError("Downloaded release is incomplete; missing: " + ", ".join(missing))
    try:
        index = parse_json((destination / "data" / "index.json").read_text(encoding="utf-8"))
        if not isinstance(index, dict):
            raise ValueError("index.json must contain a JSON object.")
        update_config = parse_json((destination / "data" / "update.json").read_text(encoding="utf-8"))
        if not isinstance(update_config, dict) or not isinstance(update_config.get("auto_update"), bool):
            raise ValueError('update.json must contain boolean "auto_update".')
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Downloaded release contains invalid JSON data: {exc}") from exc
    licenses = destination / "data" / "licenses"
    if not licenses.is_dir() or not any(path.is_file() for path in licenses.iterdir()):
        raise RuntimeError("Downloaded release does not contain its license files.")
    return destination


def download_release(release: dict[str, Any], work: Path) -> Path:
    version = release["version"]
    archive_name = f"NinjaPatchTool-v{version}-Windows-x64.zip"
    checksum_name = archive_name + ".sha256"
    archive_url, archive_size = find_release_asset(release, archive_name)
    checksum_url, checksum_size = find_release_asset(release, checksum_name)
    archive_path = work / archive_name
    checksum_path = work / checksum_name

    if archive_size is not None:
        _ensure_free_space(work, archive_size + (checksum_size or 0), "download the update")

    last_error: Exception | None = None
    for attempt in range(1, UPDATE_ATTEMPTS + 1):
        archive_path.unlink(missing_ok=True)
        checksum_path.unlink(missing_ok=True)
        try:
            print(f"[Update] Downloading Ninja Patch Tool v{version} (attempt {attempt}/{UPDATE_ATTEMPTS})...")
            _download_file(checksum_url, checksum_path, checksum_size)
            _download_file(archive_url, archive_path, archive_size, "[Update] Download")
            expected = _read_expected_checksum(checksum_path, archive_name)
            actual = sha256_file(archive_path)
            if actual.lower() != expected:
                raise RuntimeError("Downloaded release SHA-256 does not match its checksum file.")
            return archive_path
        except Exception as exc:
            last_error = exc
            if attempt < UPDATE_ATTEMPTS:
                print(f"[Update] Download failed (attempt {attempt}/{UPDATE_ATTEMPTS}): {exc}", file=sys.stderr)
                time.sleep(attempt)
    raise RuntimeError(f"Update download failed after {UPDATE_ATTEMPTS} attempts: {last_error}")


def _copy_updater_for_launch() -> Path:
    updater = TOOL_DIR / "updater.exe"
    if not updater.is_file():
        raise RuntimeError(f"Updater executable is missing: {updater}")
    temporary = Path(tempfile.gettempdir()) / f"NinjaPatchToolUpdater_{uuid.uuid4().hex}.exe"
    shutil.copy2(updater, temporary)
    return temporary


def launch_updater(stage: Path, argv: list[str], target_version: str) -> None:
    temporary_updater = _copy_updater_for_launch()
    command = [
        str(temporary_updater),
        "--install-dir",
        str(TOOL_DIR),
        "--stage-dir",
        str(stage),
        "--parent-pid",
        str(os.getpid()),
        "--target-version",
        target_version,
        "--relaunch-executable",
        str(Path(sys.executable).resolve()),
        "--relaunch-cwd",
        str(Path.cwd().resolve()),
        "--",
        *argv,
    ]
    try:
        subprocess.Popen(command, cwd=TOOL_DIR)
    except BaseException:
        temporary_updater.unlink(missing_ok=True)
        raise


def cleanup_stale_update_work(max_age_seconds: int = STALE_UPDATE_AGE_SECONDS) -> None:
    if max_age_seconds < 0 or not TEMP_ROOT.is_dir():
        return
    cutoff = time.time() - max_age_seconds
    try:
        candidates = list(TEMP_ROOT.iterdir())
    except OSError:
        return

    for work in candidates:
        if not work.name.startswith("update_"):
            continue
        try:
            if work.is_symlink() or not work.is_dir() or work.stat().st_mtime > cutoff:
                continue
            # A backup means an interrupted/incomplete transaction may need manual recovery. Never remove it here.
            if any(path.name.startswith("backup_") for path in work.iterdir()):
                continue
            shutil.rmtree(work)
        except OSError:
            # Startup cleanup is best-effort and must never block normal tool use.
            continue


def cleanup_stale_temporary_updaters(max_age_seconds: int = STALE_UPDATE_AGE_SECONDS) -> None:
    if sys.platform != "win32" or max_age_seconds < 0:
        return
    try:
        temp_dir = Path(tempfile.gettempdir()).resolve()
        cutoff = time.time() - max_age_seconds
        candidates = list(temp_dir.glob("NinjaPatchToolUpdater_*.exe"))
    except OSError:
        return

    for path in candidates:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_mtime > cutoff:
                continue
            # Windows will refuse deletion while an executable is still mapped by a running updater process.
            path.unlink(missing_ok=True)
        except OSError:
            continue


def _schedule_delete_on_reboot(path: Path) -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.MoveFileExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        kernel32.MoveFileExW.restype = ctypes.c_int
        # Optional best-effort fallback only; normal retries and later stale cleanup are the primary cleanup paths.
        kernel32.MoveFileExW(str(path), None, 0x4)  # MOVEFILE_DELAY_UNTIL_REBOOT
    except Exception:
        pass


def cleanup_temporary_updater() -> None:
    value = os.environ.pop("NPT_UPDATER_CLEANUP", None)
    if not value:
        return
    path = Path(value)
    try:
        expected_parent = Path(tempfile.gettempdir()).resolve()
        resolved = path.resolve()
    except OSError:
        return
    if resolved.parent != expected_parent or not resolved.name.startswith("NinjaPatchToolUpdater_") or resolved.suffix.lower() != ".exe":
        return
    for _ in range(30):
        try:
            resolved.unlink(missing_ok=True)
            return
        except OSError:
            time.sleep(0.1)
    try:
        if resolved.exists():
            _schedule_delete_on_reboot(resolved)
    except OSError:
        pass


def handle_automatic_update(args: argparse.Namespace, argv: list[str]) -> int | None:
    # The updater sets this one-shot flag when it relaunches the original command. An environment flag is used instead
    # of injecting --no-auto-update, which would conflict if the original command explicitly used --auto-update.
    if os.environ.pop("NPT_SKIP_UPDATE_CHECK_ONCE", None) == "1":
        return None
    if args.no_auto_update:
        return None

    enabled = True if args.auto_update else load_auto_update_setting()
    if not enabled:
        return None

    # Source checkouts are development environments; never replace source files automatically.
    if not getattr(sys, "frozen", False):
        if args.auto_update:
            print("[Update] Automatic installation is only available in the Windows release executables.", file=sys.stderr)
        return None

    work: Path | None = None
    try:
        release = check_for_update()
        if release is None:
            return None
        print(f"[Update] Ninja Patch Tool v{release['version']} is available (current: v{VERSION}).")
        TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        work = TEMP_ROOT / f"update_{uuid.uuid4().hex}"
        work.mkdir()
        archive = download_release(release, work)
        stage = extract_release_archive(archive, work / "stage", release["version"])
        launch_updater(stage, argv, release["version"])
        print("[Update] Update verified. Restarting through the updater...")
        return 0
    except KeyboardInterrupt:
        print("\nUpdate cancelled.", file=sys.stderr)
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        return 130
    except Exception as exc:
        print(f"[Update] Warning: Automatic update failed; continuing with v{VERSION}: {exc}", file=sys.stderr)
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        return None
