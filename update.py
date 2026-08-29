#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
import uuid
import zipfile
from contextlib import contextmanager
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
    cleanup_temp_root_if_empty,
    compare_versions,
    format_bytes,
    is_sha256,
    natural_sort_key,
    parse_json,
    parse_version,
    process_identity,
    process_matches_identity,
    relative_path_parts,
    sha256_file,
    validate_index,
)

UPDATE_CONFIG_FILE = DATA_DIR / "update.json"
GITHUB_RELEASES_API = "https://api.github.com/repos/DarkLotus8000/Ninja-Patch-Tool/releases/latest"
GITHUB_RELEASES_URL = "https://github.com/DarkLotus8000/Ninja-Patch-Tool/releases"
UPDATE_ATTEMPTS = 3
STALE_UPDATE_AGE_SECONDS = 7 * 24 * 60 * 60
UPDATE_INSTALLER_ARGUMENT = "--update-installer"
UPDATE_SESSION_FILE = "update_session.json"

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

def _read_update_config() -> dict[str, Any]:
    if not UPDATE_CONFIG_FILE.exists():
        _create_default_update_config()
    config = parse_json(UPDATE_CONFIG_FILE.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("auto_update"), bool):
        raise ValueError('Expected a JSON object containing boolean "auto_update".')
    return config

def _write_update_config(config: dict[str, Any]) -> None:
    UPDATE_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = UPDATE_CONFIG_FILE.with_name(f"{UPDATE_CONFIG_FILE.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as file:
            file.write(json.dumps(config, indent=2) + "\n")
        temporary.replace(UPDATE_CONFIG_FILE)
    finally:
        temporary.unlink(missing_ok=True)

def load_auto_update_setting() -> bool:
    try:
        return _read_update_config()["auto_update"]
    except OSError as exc:
        message = "Could not create" if not UPDATE_CONFIG_FILE.exists() else "Could not read"
        print(f'[Update] Warning: {message} {UPDATE_CONFIG_FILE}; automatic updating is disabled for this run: {exc}', file=sys.stderr)
        return False
    except ValueError as exc:
        print(f'[Update] Warning: Invalid update configuration; automatic updating is disabled for this run: {exc}', file=sys.stderr)
        return False

def _stored_check_time(config: dict[str, Any], key: str) -> int | None:
    value = config.get(key)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None

def automatic_update_check_due(now: float | None = None) -> bool:
    # Cooldown state is best-effort. A damaged/unreadable config must not create a second failure mode here; the normal
    # auto-update setting validation already decides whether automatic updating itself is allowed.
    try:
        config = _read_update_config()
    except (OSError, ValueError):
        return True

    current = time.time() if now is None else now
    successful = _stored_check_time(config, "last_successful_check")
    failed = _stored_check_time(config, "last_failed_check")

    if failed is not None and (successful is None or failed >= successful):
        age = current - failed
        return age < 0 or age >= 15 * 60
    if successful is not None:
        age = current - successful
        return age < 0 or age >= 24 * 60 * 60
    return True

def _record_update_check_result(result: str, now: float | None = None) -> None:
    # Source checkouts must not write runtime cooldown state into the repository.
    if not getattr(sys, "frozen", False):
        return

    # State persistence must never turn an otherwise successful update check into a user-visible failure.
    try:
        config = _read_update_config()
        timestamp = int(time.time() if now is None else now)
        if result == "success":
            config["last_successful_check"] = timestamp
            config.pop("last_failed_check", None)
        elif result == "failure":
            config["last_failed_check"] = timestamp
            config.pop("last_successful_check", None)
        elif result == "update_available":
            # Do not let an earlier no-update cooldown suppress installation after an explicit check discovers a release.
            config.pop("last_successful_check", None)
            config.pop("last_failed_check", None)
        else:
            raise ValueError(f"Unknown update check result: {result}")
        _write_update_config(config)
    except (OSError, ValueError):
        pass

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
            _record_update_check_result("success")
            print(f"[Update] Local Ninja Patch Tool v{VERSION} is newer than the latest release v{release['version']}.")
        elif comparison == 0:
            _record_update_check_result("success")
            print(f"[Update] Ninja Patch Tool v{VERSION} is up to date.")
        else:
            _record_update_check_result("update_available")
            print(f"[Update] Ninja Patch Tool v{release['version']} is available.\nCurrent version: v{VERSION}\nRelease: {release['url']}")
        return 0
    except KeyboardInterrupt:
        print("\nUpdate check cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        _record_update_check_result("failure")
        print(f"ERROR: Update check failed: {exc}", file=sys.stderr)
        return 1

def cleanup_legacy_updater_executable() -> None:
    # v1.4 shipped a separate updater.exe. v1.4.1 and later use a temporary self-copy instead, so remove the obsolete
    # helper on the first normal launch after an in-place/automatic update. Source runs never touch release files.
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return

    legacy_updater = TOOL_DIR / "updater.exe"
    try:
        if legacy_updater.resolve() == Path(sys.executable).resolve():
            return
        legacy_updater.unlink(missing_ok=True)
    except OSError:
        # Migration cleanup is best-effort. A locked or otherwise undeletable legacy helper must never block NPT.
        pass

def handle_early_update_request(argv: list[str]) -> int | None:
    # Every release executable contains the installer logic in this update module. A temporary copy of whichever executable
    # initiated the update enters this hidden mode and performs the installation after the original process exits.
    if argv[:1] == [UPDATE_INSTALLER_ARGUMENT]:
        return run_update_installer(argv[1:])
    if UPDATE_INSTALLER_ARGUMENT in argv:
        print("ERROR: Invalid internal updater arguments.", file=sys.stderr)
        return 1

    try:
        cleanup_legacy_updater_executable()
        cleanup_relaunched_update_work()
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
        validate_index(index)
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

def _current_application_path() -> Path:
    executable = Path(sys.executable).resolve()
    if not executable.is_file():
        raise RuntimeError(f"Current Ninja Patch Tool executable is missing: {executable}")
    return executable

def _validate_temporary_updater(executable: Path) -> None:
    expected = f"Ninja Patch Tool v{VERSION}"
    try:
        result = subprocess.run(
            [str(executable), UPDATE_INSTALLER_ARGUMENT, "--version"],
            cwd=TOOL_DIR,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Temporary Ninja Patch Tool updater did not respond to --version within 15 seconds: {executable}"
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"Temporary Ninja Patch Tool updater could not be started: {executable}: {exc}") from exc

    actual = result.stdout.strip()
    if result.returncode != 0:
        detail = result.stderr.strip() or actual or f"exit code {result.returncode}"
        raise RuntimeError(f"Temporary Ninja Patch Tool updater failed its version check: {executable}\n{detail}")
    if actual != expected:
        raise RuntimeError(
            "Temporary Ninja Patch Tool updater version does not match this release.\n"
            f"Expected: {expected}\n"
            f"Actual: {actual or '(no version output)'}"
        )

def _copy_application_for_update(work: Path) -> Path:
    source = _current_application_path()
    temporary = work / "NinjaPatchToolUpdater.exe"
    shutil.copy2(source, temporary)
    _validate_temporary_updater(temporary)
    return temporary

def launch_updater(temporary_updater: Path, stage: Path, argv: list[str], target_version: str) -> None:
    # Revalidate the already-created self-copy immediately before handoff. The copy lives in this update work directory,
    # so no system temporary directory or separate shipped updater executable is needed.
    _validate_temporary_updater(temporary_updater)
    command = [
        str(temporary_updater),
        UPDATE_INSTALLER_ARGUMENT,
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
    subprocess.Popen(command, cwd=TOOL_DIR)

def _update_session_is_active(work: Path) -> bool:
    session = work / UPDATE_SESSION_FILE
    if not session.is_file() or sys.platform != "win32":
        return False
    try:
        state = parse_json(session.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            return False
        pid = state.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return False
        return process_matches_identity(pid, state.get("process_identity"))
    except Exception:
        # If process inspection itself fails, be conservative and leave the work directory alone.
        return True

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
            # A self-updater now runs from inside update_<id>. Never delete its directory while that process is alive.
            if _update_session_is_active(work):
                continue
            shutil.rmtree(work)
        except OSError:
            # Startup cleanup is best-effort and must never block normal tool use.
            continue
    cleanup_temp_root_if_empty(TEMP_ROOT)

def cleanup_relaunched_update_work() -> None:
    value = os.environ.pop("NPT_UPDATE_WORK_CLEANUP", None)
    if not value:
        return

    raw_work = Path(value)
    try:
        if raw_work.is_symlink():
            return
        expected_parent = TEMP_ROOT.resolve()
        work = raw_work.resolve()
    except OSError:
        return
    if work.parent != expected_parent or not work.name.startswith("update_") or not work.is_dir():
        return

    # This environment variable is set only after a successful handoff or after a successful rollback. An incomplete
    # rollback never relaunches with cleanup enabled, so any transient backup still present here is safe to remove.
    # The relaunched process can race the final few milliseconds of the temporary updater shutting down. Retry briefly
    # until Windows releases the mapped self-copy, then leave any stubborn directory for normal stale cleanup later.
    for _ in range(50):
        try:
            shutil.rmtree(work)
            break
        except FileNotFoundError:
            break
        except OSError:
            time.sleep(0.1)
    cleanup_temp_root_if_empty(TEMP_ROOT)

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

    if not automatic_update_check_due():
        return None

    work: Path | None = None
    try:
        release = check_for_update()
        if release is None:
            _record_update_check_result("success")
            return None
        TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        work = TEMP_ROOT / f"update_{uuid.uuid4().hex}"
        work.mkdir()
        temporary_updater = _copy_application_for_update(work)
        _record_update_check_result("update_available")
        print(f"[Update] Ninja Patch Tool v{release['version']} is available (current: v{VERSION}).")
        archive = download_release(release, work)
        stage = extract_release_archive(archive, work / "stage", release["version"])
        launch_updater(temporary_updater, stage, argv, release["version"])
        print("[Update] Update verified. Restarting to install...")
        return 0
    except KeyboardInterrupt:
        print("\nUpdate cancelled.", file=sys.stderr)
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        cleanup_temp_root_if_empty(TEMP_ROOT)
        return 130
    except Exception as exc:
        _record_update_check_result("failure")
        print(f"[Update] Warning: Automatic update failed; continuing with v{VERSION}: {exc}", file=sys.stderr)
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        cleanup_temp_root_if_empty(TEMP_ROOT)
        return None

def ignore_interrupts() -> None:
    # Once the updater handoff has started, interruption must not stop file replacement or rollback halfway through.
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            signal.signal(sig, signal.SIG_IGN)

@contextmanager
def updater_install_lock(install_dir: Path, timeout_seconds: int = 120):
    import ctypes

    resolved = str(install_dir.resolve()).casefold()
    digest = hashlib.sha256(resolved.encode("utf-8")).hexdigest()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.ReleaseMutex.argtypes = [ctypes.c_void_p]
    kernel32.ReleaseMutex.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    handle = kernel32.CreateMutexW(None, False, f"Local\\DarkLotus.NinjaPatchTool.updater.{digest}")
    if not handle:
        raise OSError(ctypes.get_last_error(), "Could not create the updater installation mutex.")
    try:
        result = kernel32.WaitForSingleObject(handle, timeout_seconds * 1000)
        if result == 0x102:  # WAIT_TIMEOUT
            raise RuntimeError("Timed out waiting for another Ninja Patch Tool update to finish.")
        if result not in {0, 0x80}:  # WAIT_OBJECT_0 / WAIT_ABANDONED
            raise OSError(ctypes.get_last_error(), "Could not acquire the updater installation mutex.")
        try:
            yield
        finally:
            kernel32.ReleaseMutex(handle)
    finally:
        kernel32.CloseHandle(handle)

def wait_for_process_exit(pid: int, timeout_seconds: int = 30) -> None:
    if pid <= 0:
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: process no longer exists.
            return
        raise OSError(error, f"Could not open Ninja Patch Tool process {pid}.")
    try:
        result = kernel32.WaitForSingleObject(handle, timeout_seconds * 1000)
        if result == 0x102:
            raise RuntimeError("Timed out waiting for Ninja Patch Tool to exit.")
        if result not in {0, 0x80}:
            raise OSError(ctypes.get_last_error(), "Could not wait for Ninja Patch Tool to exit.")
    finally:
        kernel32.CloseHandle(handle)

def write_update_session(work: Path) -> None:
    session = work / UPDATE_SESSION_FILE
    temporary = session.with_name(f"{session.name}.{uuid.uuid4().hex}.tmp")
    state = {
        "pid": os.getpid(),
        "process_identity": process_identity(os.getpid()),
    }
    try:
        temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8", newline="\n")
        temporary.replace(session)
    finally:
        temporary.unlink(missing_ok=True)

def _remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)

def _copy_item(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, destination)
    else:
        shutil.copy2(source, destination)

def _read_index(path: Path, label: str) -> dict:
    try:
        index = parse_json(path.read_text(encoding="utf-8"))
        validate_index(index)
        return index
    except Exception as exc:
        raise RuntimeError(f"{label} index.json is invalid: {exc}") from exc

def _write_merged_index(release_path: Path, installed_path: Path, output_path: Path) -> None:
    release_index = _read_index(release_path, "Release")
    installed_index = _read_index(installed_path, "Installed")

    merged = dict(installed_index)
    for release_name, release_entry in release_index.items():
        release_name_folded = release_name.casefold()
        release_manifest_id = release_entry["steam_manifest_id"]
        release_hash = release_entry["sha256"].casefold()

        # The release index is authoritative for bases it knows about. Remove a local duplicate/older entry identified
        # by name, Steam manifest ID, or root hash, while preserving unrelated locally added bases.
        for installed_name, installed_entry in list(merged.items()):
            if (
                installed_name.casefold() == release_name_folded
                or installed_entry["steam_manifest_id"] == release_manifest_id
                or installed_entry["sha256"].casefold() == release_hash
            ):
                del merged[installed_name]
        merged[release_name] = release_entry

    validate_index(merged)
    sorted_index = {name: merged[name] for name in sorted(merged, key=natural_sort_key)}
    output_path.write_text(json.dumps(sorted_index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")

def rollback_staged_release(changes: list[tuple[Path, Path | None]], backup: Path) -> None:
    rollback_errors: list[str] = []
    for destination, saved in reversed(changes):
        try:
            if destination.exists() or destination.is_symlink():
                _remove_path(destination)
            if saved is not None and saved.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(saved), str(destination))
        except Exception as exc:
            rollback_errors.append(f"{destination}: {exc}")

    if rollback_errors:
        raise RuntimeError(
            f"Rollback was incomplete. Backup retained at {backup}. Rollback errors: {'; '.join(rollback_errors)}"
        )
    shutil.rmtree(backup, ignore_errors=True)

def install_staged_release(stage: Path, install_dir: Path) -> tuple[Path, list[tuple[Path, Path | None]]]:
    if not stage.is_dir():
        raise RuntimeError(f"Staged update directory does not exist: {stage}")
    if not install_dir.is_dir():
        raise RuntimeError(f"Ninja Patch Tool directory does not exist: {install_dir}")

    backup = stage.parent / f"backup_{uuid.uuid4().hex}"
    backup.mkdir()
    changes: list[tuple[Path, Path | None]] = []

    def replace(source: Path, destination: Path, relative: Path) -> None:
        saved: Path | None = None
        if destination.exists() or destination.is_symlink():
            saved = backup / relative
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(destination), str(saved))
        changes.append((destination, saved))
        _copy_item(source, destination)

    try:
        for source in sorted(stage.iterdir(), key=lambda path: path.name.casefold()):
            if source.name.casefold() != "data":
                replace(source, install_dir / source.name, Path(source.name))
                continue

            destination_data = install_dir / "data"
            destination_data.mkdir(parents=True, exist_ok=True)
            for data_source in sorted(source.iterdir(), key=lambda path: path.name.casefold()):
                data_destination = destination_data / data_source.name
                data_name = data_source.name.casefold()
                if data_name == "update.json" and data_destination.exists():
                    continue
                if data_name == "index.json" and data_destination.exists():
                    merged_index = backup / "merged_index.json"
                    _write_merged_index(data_source, data_destination, merged_index)
                    replace(merged_index, data_destination, Path("data") / data_source.name)
                    continue
                replace(data_source, data_destination, Path("data") / data_source.name)
    except BaseException as install_error:
        try:
            rollback_staged_release(changes, backup)
        except Exception as rollback_error:
            raise RuntimeError(f"Update installation failed and {rollback_error}") from install_error
        raise

    return backup, changes

def _read_installed_version(executable: Path, cwd: Path) -> str:
    try:
        result = subprocess.run(
            [str(executable), "--version"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Updated executable did not respond to --version: {executable.name}") from exc
    except OSError as exc:
        raise RuntimeError(f"Updated executable could not be started: {executable.name}: {exc}") from exc

    output = result.stdout.strip()
    prefix = "Ninja Patch Tool v"
    if result.returncode != 0 or not output.startswith(prefix) or "\n" in output or "\r" in output:
        details = result.stderr.strip() or output or f"exit code {result.returncode}"
        raise RuntimeError(f"Updated executable failed validation: {executable.name}: {details}")
    version = output[len(prefix):]
    try:
        parse_version(version)
    except ValueError as exc:
        raise RuntimeError(f"Updated executable returned an invalid version: {executable.name}: {version!r}") from exc
    return version

def validate_installed_executable(executable: Path, target_version: str, cwd: Path) -> None:
    installed_version = _read_installed_version(executable, cwd)
    if installed_version != target_version:
        raise RuntimeError(
            f"Updated executable failed validation: {executable.name}: "
            f"expected v{target_version}, got v{installed_version}"
        )

def installed_executable_satisfies_target(executable: Path, target_version: str, cwd: Path) -> str | None:
    try:
        installed_version = _read_installed_version(executable, cwd)
        if compare_versions(installed_version, target_version) >= 0:
            return installed_version
    except Exception:
        pass
    return None

def relaunch(executable: Path, argv: list[str], cwd: Path, cleanup_work: Path | None = None) -> subprocess.Popen:
    environment = os.environ.copy()
    # Skip exactly one update check after a handoff. Injecting --no-auto-update would conflict with an original
    # --auto-update argument, so the user's command line is left unchanged.
    environment["NPT_SKIP_UPDATE_CHECK_ONCE"] = "1"
    if cleanup_work is not None:
        environment["NPT_UPDATE_WORK_CLEANUP"] = str(cleanup_work)
    return subprocess.Popen([str(executable), *argv], cwd=cwd, env=environment)

def run_update_installer(argv: list[str] | None = None) -> int:
    if sys.platform != "win32":
        print("ERROR: Ninja Patch Tool updater is Windows-only.", file=sys.stderr)
        return 1

    ignore_interrupts()

    parser = ErrorArgumentParser(description="Internal Ninja Patch Tool update installer.")
    parser.add_argument("--install-dir", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--stage-dir", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--parent-pid", type=int, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--target-version", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--relaunch-executable", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--relaunch-cwd", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("relaunch_args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    parser.add_version_argument()
    parser.add_help_argument()
    args = parser.parse_args(argv)

    install_dir = args.install_dir.resolve()
    stage = args.stage_dir.resolve()
    work = stage.parent
    executable = args.relaunch_executable.resolve()
    relaunch_cwd = args.relaunch_cwd.resolve()
    relaunch_args = args.relaunch_args
    if relaunch_args[:1] == ["--"]:
        relaunch_args = relaunch_args[1:]

    transaction: tuple[Path, list[tuple[Path, Path | None]]] | None = None
    try:
        write_update_session(work)
        wait_for_process_exit(args.parent_pid)
        with updater_install_lock(install_dir):
            # Another updater may have completed while this updater was waiting for the installation mutex. Never let
            # an older queued updater replace a version that is equal to or newer than its own target.
            installed_version = installed_executable_satisfies_target(executable, args.target_version, install_dir)
            if installed_version is not None:
                relaunch(executable, relaunch_args, relaunch_cwd, work)
                if compare_versions(installed_version, args.target_version) > 0:
                    print(f'[Update] Ninja Patch Tool v{installed_version} is already installed; skipping queued update to v{args.target_version}.')
                else:
                    print(f"[Update] Ninja Patch Tool v{args.target_version} was already installed by another updater.")
                return 0

            try:
                transaction = install_staged_release(stage, install_dir)
                validate_installed_executable(executable, args.target_version, install_dir)
                relaunch(executable, relaunch_args, relaunch_cwd, work)
            except Exception as exc:
                if transaction is not None:
                    backup, changes = transaction
                    try:
                        rollback_staged_release(changes, backup)
                    except Exception as rollback_error:
                        print(f'ERROR: Ninja Patch Tool update failed and rollback was incomplete: {rollback_error}', file=sys.stderr)
                        return 1

                print(f'ERROR: Ninja Patch Tool update failed; the previous installation was restored when possible: {exc}', file=sys.stderr)
                try:
                    relaunch(executable, relaunch_args, relaunch_cwd, work)
                except Exception as relaunch_error:
                    print(f"ERROR: Could not restart Ninja Patch Tool after the failed update: {relaunch_error}", file=sys.stderr)
                return 1

            backup, _ = transaction
            shutil.rmtree(backup, ignore_errors=True)
            print(f"[Update] Ninja Patch Tool updated successfully to v{args.target_version}.")
            return 0
    except Exception as exc:
        print(f"ERROR: Ninja Patch Tool updater could not start the installation: {exc}", file=sys.stderr)
        try:
            relaunch(executable, relaunch_args, relaunch_cwd, work)
        except Exception as relaunch_error:
            print(f"ERROR: Could not restart Ninja Patch Tool after the failed update: {relaunch_error}", file=sys.stderr)
        return 1
