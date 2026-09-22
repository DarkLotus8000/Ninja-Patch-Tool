#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

# Keep the release builder itself from creating __pycache__ in the source tree.
sys.dont_write_bytecode = True

from packaging.requirements import Requirement

from common import (
    ActiveOperationError,
    ENTRY_SCRIPTS,
    PRESERVED_RELEASE_FILES,
    RELEASE_MANIFEST_FILE,
    RELEASE_MANIFEST_VERSION,
    STEAM_CLIENT_VERSION,
    VERSION,
    STEAM_QUERY_RESULT_PREFIX,
    STEAM_QUERY_WORKER_SMOKE_ARGUMENT,
    exclusive_operation_activity_lock,
    console_title,
    display_version,
    format_bytes,
    format_duration,
    operation_lock,
    parse_json,
    print_error,
    sha256_file,
    validate_index,
)

COMPANY_NAME = "DarkLotus"
DISPLAY_VERSION = display_version()
ROOT = Path(__file__).resolve().parent
RELEASE_DIR = ROOT / "release"
RELEASE_TEMP_DIR = ROOT / "release_temp"
DATA_DIR = ROOT / "data"
FAVICON = DATA_DIR / "favicon.ico"
LICENSES_DIR = DATA_DIR / "licenses"
RELEASE_DATA_FILES = ("index.json", "update.json", "hdiffz.exe", "hpatchz.exe")
THIRD_PARTY_LICENSE_FILES = ("Python-LICENSE.txt", "HDiffPatch-LICENSE.txt")
VERSIONED_FALLBACK_STEAM_LICENSE_FILES = {
    ("gevent-eventemitter", "2.1"): LICENSES_DIR / "gevent_eventemitter_LICENSE.txt",
}
MIN_PYINSTALLER_VERSION = (6, 15, 0)
_ACTIVE_BUILD_PROCESS: subprocess.Popen | None = None
KNOWN_RUNTIME_LOCK_FILES = {
    "data/.index.lock",
    "data/.operation.lock",
    "data/.update.lock",
}
RELEASE_SOURCE_FILES = (
    *ENTRY_SCRIPTS,
    "build_release.py",
    "common.py",
    "update.py",
    "README.md",
    "requirements.txt",
    "data/favicon.ico",
    *(f"data/{name}" for name in RELEASE_DATA_FILES),
    *(f"data/licenses/{name}" for name in THIRD_PARTY_LICENSE_FILES),
    "data/licenses/gevent_eventemitter_LICENSE.txt",
    "tests/test_ninja_patch_tool.py",
)

def source_tree_artifacts(root: Path = ROOT) -> list[str]:
    artifacts: list[str] = []
    for current_root, directories, filenames in os.walk(root):
        current = Path(current_root)
        for directory in list(directories):
            if directory == ".git":
                directories.remove(directory)
                continue
            if directory in {".pytest_cache", ".mypy_cache", ".ruff_cache", "htmlcov", "__pycache__"}:
                path = current / directory
                artifacts.append(path.relative_to(root).as_posix() + "/")
                directories.remove(directory)
        for filename in filenames:
            path = current / filename
            relative = path.relative_to(root).as_posix()
            if filename.endswith(".lock") and relative in KNOWN_RUNTIME_LOCK_FILES:
                continue
            if filename in {".coverage", "coverage.xml"} or filename.endswith((".part", ".pyc", ".pyo", ".lock")):
                artifacts.append(relative)
    return sorted(artifacts, key=str.casefold)

def validate_source_tree_cleanliness(root: Path = ROOT) -> None:
    artifacts = source_tree_artifacts(root)
    if not artifacts:
        return
    details = "\n".join(f"- {path}" for path in artifacts)
    raise RuntimeError(f"Generated/cache artifacts must be removed before building a release:\n{details}")

def release_source_fingerprint(project_licenses: list[Path], root: Path = ROOT) -> str:
    candidates = [root / relative for relative in RELEASE_SOURCE_FILES]
    candidates.extend(project_licenses)
    unique = {path.resolve(): path for path in candidates}
    digest = hashlib.sha256()
    for resolved, path in sorted(unique.items(), key=lambda item: str(item[0]).casefold()):
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"Could not read release source file while checking build consistency: {path}") from exc
        try:
            label = resolved.relative_to(root.resolve()).as_posix()
        except ValueError:
            label = str(resolved)
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()

@contextlib.contextmanager
def runtime_build_barrier(root: Path = ROOT):
    try:
        with exclusive_operation_activity_lock(root):
            yield
    except ActiveOperationError as exc:
        raise RuntimeError(
            "Ninja Patch Tool is currently running or updating. Close it before building a release."
        ) from exc

def sanitize_staged_runtime_locks(stage: Path) -> None:
    for relative in KNOWN_RUNTIME_LOCK_FILES:
        path = stage / relative
        if path.is_dir():
            raise RuntimeError(f"Expected a runtime lock file but found a directory in release staging: {relative}")
        path.unlink(missing_ok=True)

    leftovers = sorted(
        path.relative_to(stage).as_posix()
        for path in stage.rglob("*.lock")
        if path.is_file()
    )
    if leftovers:
        details = "\n".join(f"- {path}" for path in leftovers)
        raise RuntimeError(f"Release staging contains unexpected runtime lock files:\n{details}")

def clean_markdown_inline(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    return text.replace("***", "").replace("**", "").replace("`", "")

def create_release_readme(markdown: str) -> str:
    lines: list[str] = []
    in_code = False
    skip_source_install = False

    for line in markdown.splitlines():
        if line == "## Build a release":
            break
        if line == "Install the source dependency with:":
            skip_source_install = True
            lines.append("No additional packages need to be installed for the release executables.")
            continue
        if skip_source_install:
            if line == "Building a release additionally requires PyInstaller.":
                skip_source_install = False
            continue
        if line.startswith("```"):
            in_code = not in_code
            continue
        if line == "The commands below use the release executables. When running from source, prefix the corresponding `.py` script with `py -3.14`; for example, `py -3.14 add_base.py ...`.":
            continue

        if line.startswith("# "):
            heading = clean_markdown_inline(line[2:])
            lines.extend([heading, "=" * len(heading), f"Version {DISPLAY_VERSION}"])
            continue
        if line.startswith("## "):
            heading = clean_markdown_inline(line[3:])
            lines.extend([heading, "-" * len(heading)])
            continue

        line = clean_markdown_inline(line)
        for script in ENTRY_SCRIPTS:
            command = Path(script).stem
            line = line.replace(f"py {script}", command).replace(script, command)
        if line == "- Python 3.14 (not required for release executables)":
            continue
        if line == "No packages need to be installed to run the tool from source. Building a release additionally requires PyInstaller.":
            line = "No additional packages need to be installed."
        if in_code and line:
            line = "    " + line
        lines.append(line)

    return "\n".join(lines).rstrip()

def version_tuple() -> tuple[int, int, int, int]:
    parts = VERSION.split(".")
    if len(parts) not in {2, 3, 4} or any(not part.isdigit() for part in parts):
        raise RuntimeError("VERSION must contain two to four numeric components, for example 1.4, 1.4.0, or 1.4.0.0.")
    numbers = [int(part) for part in parts]
    if any(number > 65535 for number in numbers):
        raise RuntimeError("Every VERSION component must be between 0 and 65535 for Windows version resources.")
    numbers.extend([0] * (4 - len(numbers)))
    return numbers[0], numbers[1], numbers[2], numbers[3]

def validate_pyinstaller_version(value: str) -> None:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        raise RuntimeError(f"Could not parse the installed PyInstaller version: {value!r}")
    installed = tuple(int(part) for part in match.groups())
    if installed < MIN_PYINSTALLER_VERSION:
        required = ".".join(str(part) for part in MIN_PYINSTALLER_VERSION)
        raise RuntimeError(f"PyInstaller {required} or newer is required for Python 3.14. Installed version: {value}")

def release_archive_path() -> Path:
    return RELEASE_DIR / f"NinjaPatchTool-v{VERSION}-Windows-x64.zip"

def release_checksum_path() -> Path:
    archive = release_archive_path()
    return archive.with_name(archive.name + ".sha256")

def release_extract_path() -> Path:
    return RELEASE_DIR / f"NinjaPatchTool-v{VERSION}"

def release_extract_temp_path() -> Path:
    return RELEASE_DIR / f".NinjaPatchTool-v{VERSION}.extract.tmp"

def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)

def _remove_path_with_retry(path: Path, attempts: int = 20, delay_seconds: float = 0.1) -> None:
    for attempt in range(attempts):
        try:
            _remove_path(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay_seconds)

def _replace_path_with_retry(source: Path, destination: Path, attempts: int = 20, delay_seconds: float = 0.1) -> None:
    for attempt in range(attempts):
        try:
            source.replace(destination)
            return
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay_seconds)

def extract_release_archive(archive: Path) -> Path:
    destination = release_extract_path()
    temporary_root = release_extract_temp_path()
    backup = destination.with_name(destination.name + ".extract.backup")

    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    _remove_path_with_retry(temporary_root)
    if backup.exists() or backup.is_symlink():
        if destination.exists() or destination.is_symlink():
            _remove_path_with_retry(backup)
        else:
            _replace_path_with_retry(backup, destination)

    try:
        with zipfile.ZipFile(archive, "r") as zip_file:
            zip_file.extractall(temporary_root)
        extracted = temporary_root / destination.name
        children = list(temporary_root.iterdir())
        if children != [extracted] or not extracted.is_dir() or extracted.is_symlink():
            raise RuntimeError("Release archive did not extract to the expected top-level directory.")

        had_destination = destination.exists() or destination.is_symlink()
        if had_destination:
            _replace_path_with_retry(destination, backup)
        try:
            _replace_path_with_retry(extracted, destination)
        except BaseException:
            if had_destination and backup.exists() and not destination.exists():
                _replace_path_with_retry(backup, destination)
            raise
        if backup.exists() or backup.is_symlink():
            _remove_path_with_retry(backup)
        return destination
    finally:
        _remove_path_with_retry(temporary_root)

class ReleaseArgumentParser(argparse.ArgumentParser):
    """Keep release-builder argument errors consistent with the tool's severity format."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        if message[:1].islower():
            message = message[0].upper() + message[1:]
        print_error(message)
        self.exit(2)

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = ReleaseArgumentParser(description="Build the Ninja Patch Tool Windows release.")
    parser.add_argument(
        "-e",
        "--extract",
        action="store_true",
        help="Also extract the completed release ZIP beside the archive.",
    )
    return parser.parse_args(argv)

def remove_release_temp() -> None:
    for attempt in range(20):
        try:
            shutil.rmtree(RELEASE_TEMP_DIR)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt == 19:
                raise
            time.sleep(0.1)

def clean_stale_release_temp() -> None:
    if not RELEASE_TEMP_DIR.exists():
        return
    print("[Cleaning] Previous temporary build files")
    try:
        remove_release_temp()
    except OSError as exc:
        raise RuntimeError(f"Could not remove previous temporary build files: {RELEASE_TEMP_DIR}") from exc

def remove_release_output_temps() -> None:
    archive = release_archive_path()
    checksum = release_checksum_path()
    for path in (archive.with_name(archive.name + ".tmp"), checksum.with_name(checksum.name + ".tmp")):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    _remove_path_with_retry(release_extract_temp_path())

def _terminate_active_build_process() -> None:
    process = _ACTIVE_BUILD_PROCESS
    if process is None or process.poll() is not None:
        return
    try:
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=0.5)
    except (OSError, subprocess.TimeoutExpired):
        pass

def _release_console_control_handler(control_type: int) -> bool:
    # Ctrl+C follows Python's normal KeyboardInterrupt path. Window close, logoff,
    # and shutdown events may terminate the process without unwinding finally blocks.
    if control_type not in {2, 5, 6}:
        return False
    _terminate_active_build_process()
    for cleanup in (remove_release_temp, remove_release_output_temps):
        try:
            cleanup()
        except OSError:
            pass
    return False

@contextlib.contextmanager
def release_temp_console_cleanup():
    if sys.platform != "win32":
        yield
        return

    handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
    handler = handler_type(_release_console_control_handler)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetConsoleCtrlHandler.argtypes = [handler_type, ctypes.c_bool]
    kernel32.SetConsoleCtrlHandler.restype = ctypes.c_bool
    if not kernel32.SetConsoleCtrlHandler(handler, True):
        raise OSError(ctypes.get_last_error(), "Could not install release build console cleanup handler.")
    try:
        yield
    finally:
        kernel32.SetConsoleCtrlHandler(handler, False)

def find_project_licenses() -> list[Path]:
    licenses: set[Path] = set()
    for pattern in ("LICENSE*", "COPYING*"):
        licenses.update(path for path in ROOT.glob(pattern) if path.is_file())
    return sorted(licenses, key=lambda path: path.name.casefold())

def validate_pe_x64(path: Path) -> None:
    try:
        with path.open("rb") as file:
            header = file.read(64)
            if len(header) < 64 or header[:2] != b"MZ":
                raise RuntimeError(f"Not a valid Windows PE executable: {path}")
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            file.seek(pe_offset)
            pe_header = file.read(6)
    except OSError as exc:
        raise RuntimeError(f"Could not inspect Windows executable: {path}") from exc
    if len(pe_header) != 6 or pe_header[:4] != b"PE\0\0":
        raise RuntimeError(f"Not a valid Windows PE executable: {path}")
    machine = struct.unpack_from("<H", pe_header, 4)[0]
    if machine != 0x8664:
        raise RuntimeError(f"Release dependency is not an x86-64 Windows executable: {path}")

ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)

def validate_ico(path: Path) -> None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Could not read icon file: {path}") from exc
    if len(data) < 6:
        raise RuntimeError(f"Invalid ICO file: {path}")
    reserved, icon_type, count = struct.unpack_from("<HHH", data, 0)
    directory_end = 6 + count * 16
    if reserved != 0 or icon_type != 1 or count == 0 or len(data) < directory_end:
        raise RuntimeError(f"Invalid ICO file: {path}")
    if count != len(ICO_SIZES):
        raise RuntimeError(
            f"ICO must contain exactly these resolutions: {', '.join(f'{size}x{size}' for size in ICO_SIZES)}: {path}"
        )

    found_sizes: set[int] = set()
    for index in range(count):
        entry_offset = 6 + index * 16
        width = data[entry_offset] or 256
        height = data[entry_offset + 1] or 256
        planes, bit_count = struct.unpack_from("<HH", data, entry_offset + 4)
        size, offset = struct.unpack_from("<II", data, entry_offset + 8)
        if (
            width != height
            or width not in ICO_SIZES
            or width in found_sizes
            or planes not in {0, 1}
            or bit_count != 32
            or size == 0
            or offset < directory_end
            or offset + size > len(data)
        ):
            raise RuntimeError(f"Invalid ICO entry in {path}")

        payload = data[offset:offset + size]
        if (
            len(payload) < 26
            or not payload.startswith(b"\x89PNG\r\n\x1a\n")
            or payload[12:16] != b"IHDR"
        ):
            raise RuntimeError(f"ICO entry {width}x{height} must be PNG-compressed: {path}")
        png_width, png_height = struct.unpack_from(">II", payload, 16)
        if png_width != width or png_height != height:
            raise RuntimeError(f"ICO entry dimensions do not match its PNG payload: {path}")
        # PNG color types 4 and 6 contain an alpha channel.
        if payload[25] not in {4, 6}:
            raise RuntimeError(f"ICO entry {width}x{height} must contain transparency: {path}")
        found_sizes.add(width)

    if found_sizes != set(ICO_SIZES):
        raise RuntimeError(
            f"ICO must contain exactly these resolutions: {', '.join(f'{size}x{size}' for size in ICO_SIZES)}: {path}"
        )

def validate_build_environment() -> list[Path]:
    if sys.platform != "win32":
        raise RuntimeError("Releases must be built on Windows.")
    if struct.calcsize("P") != 8:
        raise RuntimeError("A 64-bit Python installation is required to build the Windows x64 release.")
    if sys.version_info[:2] != (3, 14):
        raise RuntimeError("Python 3.14 is required to build releases. Run: py -3.14 build_release.py")
    version_tuple()
    try:
        pyinstaller_version = importlib.metadata.version("pyinstaller")
    except importlib.metadata.PackageNotFoundError:
        raise RuntimeError("PyInstaller is not installed for Python 3.14. Run: py -3.14 -m pip install pyinstaller") from None
    validate_pyinstaller_version(pyinstaller_version)
    try:
        steam_client_version = importlib.metadata.version("pysteam-client")
    except importlib.metadata.PackageNotFoundError:
        raise RuntimeError(f"pysteam-client[client] {STEAM_CLIENT_VERSION} is required. Run: py -3.14 -m pip install -r requirements.txt") from None
    if steam_client_version != STEAM_CLIENT_VERSION:
        raise RuntimeError(f"pysteam-client {STEAM_CLIENT_VERSION} is required. Installed version: {steam_client_version}")
    validate_source_tree_cleanliness()

    required = [ROOT / script for script in ENTRY_SCRIPTS]
    required.extend([ROOT / "common.py", ROOT / "update.py", ROOT / "README.md", ROOT / "requirements.txt", FAVICON])
    required.extend(DATA_DIR / name for name in RELEASE_DATA_FILES)
    required.extend(LICENSES_DIR / name for name in THIRD_PARTY_LICENSE_FILES)
    required.extend(VERSIONED_FALLBACK_STEAM_LICENSE_FILES.values())
    missing = [path for path in required if not path.is_file()]
    if missing:
        details = "\n".join(f"- {path}" for path in missing)
        raise RuntimeError(f"Required release files are missing:\n{details}")

    try:
        index = parse_json((DATA_DIR / "index.json").read_text(encoding="utf-8"))
        validate_index(index)
    except Exception as exc:
        raise RuntimeError(f"data/index.json is invalid: {exc}") from exc
    try:
        update_config = parse_json((DATA_DIR / "update.json").read_text(encoding="utf-8"))
        if not isinstance(update_config, dict) or not isinstance(update_config.get("auto_update"), bool):
            raise ValueError('Expected a JSON object containing boolean "auto_update".')
    except Exception as exc:
        raise RuntimeError(f"data/update.json is invalid: {exc}") from exc
    validate_pe_x64(DATA_DIR / "hdiffz.exe")
    validate_pe_x64(DATA_DIR / "hpatchz.exe")
    validate_ico(FAVICON)

    project_licenses = find_project_licenses()
    if not project_licenses:
        raise RuntimeError("No project license file was found. Add LICENSE, LICENSE.txt, COPYING, or a similarly named license file before building a release.")
    return project_licenses

def create_version_file(script: Path, destination: Path) -> Path:
    version = version_tuple()
    version_file = destination / f"{script.stem}_version.txt"
    text = f"""VSVersionInfo(
    ffi=FixedFileInfo(
        filevers={version!r},
        prodvers={version!r},
        mask=0x3f,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0)
    ),
    kids=[
        StringFileInfo([
            StringTable(
                '040904B0',
                [
                    StringStruct('CompanyName', '{COMPANY_NAME}'),
                    StringStruct('FileDescription', '{ENTRY_SCRIPTS[script.name]}'),
                    StringStruct('FileVersion', '{DISPLAY_VERSION}'),
                    StringStruct('InternalName', '{script.stem}'),
                    StringStruct('LegalCopyright', '{COMPANY_NAME}'),
                    StringStruct('ProductName', 'Ninja Patch Tool'),
                    StringStruct('ProductVersion', '{DISPLAY_VERSION}')
                ]
            )
        ]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])])
    ]
)
"""
    version_file.write_text(text, encoding="utf-8", newline="\n")
    return version_file

def build_environment(workspace: Path) -> dict[str, str]:
    config = workspace / "pyinstaller_config"
    config.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["TEMP"] = str(workspace)
    environment["TMP"] = str(workspace)
    environment["PYINSTALLER_CONFIG_DIR"] = str(config)
    return environment

def _run_tracked_build_process(
    command: list[str],
    *,
    timeout: float | None = None,
    capture_output: bool = False,
    **kwargs,
) -> subprocess.CompletedProcess:
    global _ACTIVE_BUILD_PROCESS
    if capture_output:
        if "stdout" in kwargs or "stderr" in kwargs:
            raise ValueError("capture_output cannot be combined with stdout or stderr")
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    process = subprocess.Popen(command, **kwargs)
    _ACTIVE_BUILD_PROCESS = process
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        _terminate_active_build_process()
        raise
    finally:
        if _ACTIVE_BUILD_PROCESS is process:
            _ACTIVE_BUILD_PROCESS = None
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

def build_executable(script: Path, dist: Path, work: Path, specs: Path) -> Path:
    name = script.stem
    print(f"[Compiling] {name}.exe")
    version_file = create_version_file(script, specs)
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--log-level",
        "WARN",
        "--onefile",
        "--console",
        "--noupx",
        "--icon",
        str(FAVICON),
        "--version-file",
        str(version_file),
        "--name",
        name,
        "--distpath",
        str(dist),
        "--workpath",
        str(work / name),
        "--specpath",
        str(specs),
        "--collect-all",
        "steam",
        "--recursive-copy-metadata",
        "pysteam-client",
        str(script),
    ]
    global _ACTIVE_BUILD_PROCESS
    process = subprocess.Popen(command, cwd=ROOT, env=build_environment(dist.parent))
    _ACTIVE_BUILD_PROCESS = process
    try:
        returncode = process.wait()
    except BaseException:
        _terminate_active_build_process()
        raise
    finally:
        if _ACTIVE_BUILD_PROCESS is process:
            _ACTIVE_BUILD_PROCESS = None
    if returncode != 0:
        raise RuntimeError(f"PyInstaller failed for {name}.exe with exit code {returncode}.")
    executable = dist / f"{name}.exe"
    if not executable.is_file():
        raise RuntimeError(f"PyInstaller did not create the expected executable: {executable}")
    return executable

def run_source_tests() -> None:
    print("[Testing] Source test suite")
    try:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [
                sys.executable,
                "-W", "error::DeprecationWarning",
                "-W", "error::RuntimeWarning",
                "-W", "error::ResourceWarning",
                "-m", "unittest", "discover", "-s", "tests",
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Source test suite timed out.") from exc
    if result.returncode != 0:
        details = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip()) or "No output was produced."
        raise RuntimeError(f"Source test suite failed:\n{details}")

def smoke_test_steam_worker_import(executable: Path, environment: dict[str, str]) -> None:
    result = _run_tracked_build_process(
        [str(executable), STEAM_QUERY_WORKER_SMOKE_ARGUMENT],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        timeout=30,
    )
    tagged = [
        line[len(STEAM_QUERY_RESULT_PREFIX):].strip()
        for line in result.stdout.splitlines()
        if line.startswith(STEAM_QUERY_RESULT_PREFIX)
    ]
    try:
        payload = json.loads(tagged[-1]) if tagged else None
    except json.JSONDecodeError:
        payload = None
    if result.returncode != 0 or payload != {"ok": True, "smoke": "steam-import"}:
        details = result.stderr.strip() or result.stdout.strip() or "No tagged Steam worker result was produced."
        raise RuntimeError(f"Standalone Steam worker smoke test failed for {executable.name}:\n{details}")

def smoke_test_executables(dist: Path) -> None:
    print("[Testing] Standalone executables")
    environment = build_environment(dist.parent)
    for script in ENTRY_SCRIPTS:
        executable = dist / f"{Path(script).stem}.exe"
        try:
            help_result = _run_tracked_build_process(
                [str(executable), "-h"], cwd=ROOT, env=environment, capture_output=True, text=True, errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=120
            )
            short_version_result = _run_tracked_build_process(
                [str(executable), "-v"], cwd=ROOT, env=environment, capture_output=True, text=True, errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=120
            )
            version_result = _run_tracked_build_process(
                [str(executable), "--version"], cwd=ROOT, env=environment, capture_output=True, text=True, errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=120
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Standalone executable smoke test timed out: {executable.name}") from exc
        if help_result.returncode != 0 or "Shows this help message" not in help_result.stdout:
            details = help_result.stderr.strip() or help_result.stdout.strip() or "No output was produced."
            raise RuntimeError(f"Standalone executable smoke test failed for {executable.name}:\n{details}")
        if short_version_result.returncode != 0 or short_version_result.stdout.strip() != f"Ninja Patch Tool v{DISPLAY_VERSION}":
            details = short_version_result.stderr.strip() or short_version_result.stdout.strip() or "No output was produced."
            raise RuntimeError(f"Standalone executable short version test failed for {executable.name}:\n{details}")
        if version_result.returncode != 0 or version_result.stdout.strip() != f"Ninja Patch Tool v{DISPLAY_VERSION}":
            details = version_result.stderr.strip() or version_result.stdout.strip() or "No output was produced."
            raise RuntimeError(f"Standalone executable version test failed for {executable.name}:\n{details}")

        try:
            updater_result = _run_tracked_build_process(
                [str(executable), "--update-installer", "--version"],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Internal updater smoke test timed out: {executable.name}") from exc
        if updater_result.returncode != 0 or updater_result.stdout.strip() != f"Ninja Patch Tool v{DISPLAY_VERSION}":
            details = updater_result.stderr.strip() or updater_result.stdout.strip() or "No output was produced."
            raise RuntimeError(f"Internal updater smoke test failed for {executable.name}:\n{details}")

    smoke_test_steam_worker_import(dist / "add_base.exe", environment)

def run_release_workflow_command(
    executable: Path,
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> None:
    command = [str(executable), *arguments]
    try:
        result = _run_tracked_build_process(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=180,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Release round-trip smoke test timed out: {executable.name}") from exc
    if result.returncode != 0:
        details = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip()) or "No output was produced."
        raise RuntimeError(f"Release round-trip smoke test failed for {executable.name}:\n{details}")

def release_smoke_tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }

def smoke_test_release_round_trip(stage: Path, workspace: Path) -> None:
    print("[Testing] Release patch round trip")
    workspace.mkdir(parents=True)
    tool = workspace / "tool"
    shutil.copytree(stage, tool)

    base = workspace / "base"
    new = workspace / "new"
    for root in (base, new):
        (root / "Cache.Windows").mkdir(parents=True)
        (root / "Tools").mkdir()

    base_executable = b"NPT release smoke base executable\n" * 1024
    new_executable = base_executable[:-64] + b"NPT release smoke updated executable\n" * 2
    base_cache = bytes(range(256)) * 256
    new_cache = base_cache[:32768] + (b"updated-cache-block" * 512) + base_cache[43008:]

    (base / "Warframe.x64.exe").write_bytes(base_executable)
    (new / "Warframe.x64.exe").write_bytes(new_executable)
    (base / "Cache.Windows" / "F.TextureDx9.cache").write_bytes(base_cache)
    (new / "Cache.Windows" / "F.TextureDx9.cache").write_bytes(new_cache)
    (base / "Tools" / "build-smoke-tool.bin").write_bytes(b"unchanged-tool-data" * 256)
    (new / "Tools" / "build-smoke-tool.bin").write_bytes(b"unchanged-tool-data" * 256)
    (base / "Cache.Windows" / "removed.cache").write_bytes(b"removed by smoke patch")
    (new / "Cache.Windows" / "added.cache").write_bytes(b"added by smoke patch")

    base_before = release_smoke_tree_hashes(base)
    expected = release_smoke_tree_hashes(new)
    patch = workspace / "roundtrip.patch"
    applied = workspace / "applied"
    base_name = "NPT-BUILD-SMOKE-BASE"
    environment = build_environment(workspace / "runtime")
    environment["NO_COLOR"] = "1"

    run_release_workflow_command(
        tool / "add_base.exe",
        [str(base), base_name, "18446744073709551615", "-n"],
        cwd=tool,
        environment=environment,
    )
    run_release_workflow_command(
        tool / "verify_base.exe",
        [str(base), base_name, "-n"],
        cwd=tool,
        environment=environment,
    )
    run_release_workflow_command(
        tool / "make_patch.exe",
        [str(base), str(new), str(patch), base_name, "-c", "normal", "-n"],
        cwd=tool,
        environment=environment,
    )
    if not patch.is_file():
        raise RuntimeError("Release round-trip smoke test did not create the expected patch file.")
    run_release_workflow_command(
        tool / "apply_patch.exe",
        [str(base), str(patch), "-o", str(applied), "-n"],
        cwd=tool,
        environment=environment,
    )
    if not applied.is_dir():
        raise RuntimeError("Release round-trip smoke test did not create the expected patched installation.")
    if release_smoke_tree_hashes(applied) != expected:
        raise RuntimeError("Release round-trip smoke test produced files that do not match the expected installation.")
    if release_smoke_tree_hashes(base) != base_before:
        raise RuntimeError("Release round-trip smoke test unexpectedly modified the base installation.")

    # Exercise the riskier in-place path separately on a disposable base copy.
    # This covers backup creation/verification, replacement, final verification,
    # and successful recovery-work cleanup in the actual packaged executable.
    in_place = workspace / "in-place"
    shutil.copytree(base, in_place)
    run_release_workflow_command(
        tool / "apply_patch.exe",
        [str(in_place), str(patch), "-i", "-n"],
        cwd=tool,
        environment=environment,
    )
    if release_smoke_tree_hashes(in_place) != expected:
        raise RuntimeError("Release in-place smoke test produced files that do not match the expected installation.")
    if release_smoke_tree_hashes(base) != base_before:
        raise RuntimeError("Release in-place smoke test unexpectedly modified the original base installation.")
    if (tool / "temp").exists():
        raise RuntimeError("Release in-place smoke test left temporary recovery data behind after successful completion.")

def normalized_distribution_name(name: str) -> str:
    return name.casefold().replace("_", "-").replace(".", "-")

def dependency_closure(root_name: str, *, extras: frozenset[str] = frozenset()) -> list[importlib.metadata.Distribution]:
    pending: list[tuple[str, frozenset[str]]] = [(root_name, extras)]
    processed_extras: dict[str, set[str]] = {}
    result: dict[str, importlib.metadata.Distribution] = {}
    while pending:
        name, active_extras = pending.pop()
        key = normalized_distribution_name(name)
        seen = processed_extras.setdefault(key, set())
        marker_extras = set(active_extras) or {""}
        if marker_extras.issubset(seen):
            continue
        seen.update(marker_extras)
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError(f"Could not inspect bundled dependency metadata: {name}") from exc
        result.setdefault(key, distribution)
        for raw_requirement in distribution.requires or []:
            requirement = Requirement(raw_requirement)
            if requirement.marker is not None:
                applies_without_extra = requirement.marker.evaluate({"extra": ""})
                applies_with_extra = any(requirement.marker.evaluate({"extra": extra}) for extra in active_extras)
                if not applies_without_extra and not applies_with_extra:
                    continue
            pending.append((requirement.name, frozenset(requirement.extras)))
    return sorted(result.values(), key=lambda item: normalized_distribution_name(item.metadata["Name"] or ""))

def is_license_or_notice_name(name: str) -> bool:
    lowered = name.casefold()
    return lowered.startswith(("license", "copying", "notice")) or lowered.endswith((".license", ".copying", ".notice"))

def distribution_license_files(distribution: importlib.metadata.Distribution) -> list[Path]:
    result: list[Path] = []
    for item in distribution.files or []:
        if is_license_or_notice_name(Path(str(item)).name):
            path = Path(distribution.locate_file(item))
            if path.is_file():
                result.append(path)
    return result

def fallback_steam_license_files(distribution: importlib.metadata.Distribution) -> list[Path]:
    name = normalized_distribution_name(distribution.metadata["Name"] or "")
    fallback = VERSIONED_FALLBACK_STEAM_LICENSE_FILES.get((name, distribution.version))
    if fallback is None:
        return []
    if not fallback.is_file():
        raise RuntimeError(f"Bundled fallback license file is missing: {fallback}")
    return [fallback]

def normalized_license_output_name(prefix: str, source: Path, index: int, total: int) -> str:
    name = source.name
    lowered = name.casefold()
    for suffix in (".txt", ".rst", ".md"):
        if lowered.endswith(suffix):
            name = name[:-len(suffix)]
            break
    ordinal = f"{index}-" if total > 1 else ""
    return f"{prefix}-{ordinal}{name}.txt"

def collect_steam_dependency_licenses(destination: Path) -> None:
    missing: list[str] = []
    for distribution in dependency_closure("pysteam-client", extras=frozenset({"client"})):
        name = distribution.metadata["Name"] or "unknown"
        version = distribution.version
        licenses = distribution_license_files(distribution) or fallback_steam_license_files(distribution)
        if not licenses:
            missing.append(f"{name} {version}")
            continue
        prefix = f"{normalized_distribution_name(name)}-{version}"
        for index, source in enumerate(licenses, 1):
            target = destination / normalized_license_output_name(prefix, source, index, len(licenses))
            if target.exists():
                raise RuntimeError(f"Duplicate flattened license filename: {target.name}")
            shutil.copy2(source, target)
    if missing:
        raise RuntimeError(
            "Could not locate license/notice files for bundled Steam dependencies:\n"
            + "\n".join(f"- {item}" for item in missing)
        )

def populate_release(stage: Path, dist: Path, project_licenses: list[Path]) -> None:
    stage.mkdir(parents=True)
    for script in ENTRY_SCRIPTS:
        executable = dist / f"{Path(script).stem}.exe"
        shutil.copy2(executable, stage / executable.name)

    release_data = stage / "data"
    release_data.mkdir()
    for name in RELEASE_DATA_FILES:
        if name == "update.json":
            # Runtime cooldown timestamps are installation state and must never be shipped in a fresh release.
            (release_data / name).write_text('{\n  "auto_update": true\n}\n', encoding="utf-8", newline="\n")
        else:
            shutil.copy2(DATA_DIR / name, release_data / name)

    release_licenses = release_data / "licenses"
    release_licenses.mkdir()
    for name in THIRD_PARTY_LICENSE_FILES:
        shutil.copy2(LICENSES_DIR / name, release_licenses / name)
    collect_steam_dependency_licenses(release_licenses)
    for index, license_file in enumerate(project_licenses):
        destination_name = "Ninja-Patch-Tool-LICENSE.txt" if index == 0 else f"Ninja-Patch-Tool-{license_file.name}.txt"
        destination = release_licenses / destination_name
        if destination.exists():
            raise RuntimeError(f"License filename collision while staging release: {destination_name}")
        shutil.copy2(license_file, destination)

    readme = create_release_readme((ROOT / "README.md").read_text(encoding="utf-8"))
    (stage / "README.txt").write_text(readme, encoding="utf-8", newline="\r\n")

def release_managed_file_hashes(stage: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(stage.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(stage).as_posix()
        if relative == RELEASE_MANIFEST_FILE or relative in PRESERVED_RELEASE_FILES:
            continue
        files[relative] = sha256_file(path)
    return files

def write_release_manifest(stage: Path) -> None:
    manifest = {
        "format_version": RELEASE_MANIFEST_VERSION,
        "application_version": VERSION,
        "files": release_managed_file_hashes(stage),
    }
    path = stage / RELEASE_MANIFEST_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

def validate_release_manifest(stage: Path) -> None:
    path = stage / RELEASE_MANIFEST_FILE
    try:
        value = parse_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Release manifest is invalid: {exc}") from exc
    if not isinstance(value, dict) or value.get("format_version") != RELEASE_MANIFEST_VERSION:
        raise RuntimeError("Release manifest has an unsupported format version.")
    if value.get("application_version") != VERSION:
        raise RuntimeError("Release manifest application version does not match the build version.")
    files = value.get("files")
    if not isinstance(files, dict) or any(not isinstance(name, str) or not isinstance(digest, str) for name, digest in files.items()):
        raise RuntimeError("Release manifest contains invalid file metadata.")
    if files != release_managed_file_hashes(stage):
        raise RuntimeError("Release manifest does not match the staged release files.")

def validate_release_archive(archive: Path, stage: Path) -> None:
    prefix = stage.name + "/"
    expected_names = {
        prefix + path.relative_to(stage).as_posix()
        for path in stage.rglob("*")
        if path.is_file()
    }
    with zipfile.ZipFile(archive, "r") as zip_file:
        bad_member = zip_file.testzip()
        if bad_member is not None:
            raise RuntimeError(f"Release archive CRC validation failed: {bad_member}")
        names = zip_file.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("Release archive contains duplicate members.")
        actual_names = set(names)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names, key=str.casefold)
            extra = sorted(actual_names - expected_names, key=str.casefold)
            details = []
            if missing:
                details.append("Missing: " + ", ".join(missing))
            if extra:
                details.append("Unexpected: " + ", ".join(extra))
            raise RuntimeError("Release archive member set does not match the staged release. " + " ".join(details))

        manifest_name = prefix + RELEASE_MANIFEST_FILE
        try:
            archived_manifest = parse_json(zip_file.read(manifest_name).decode("utf-8"))
            staged_manifest = parse_json((stage / RELEASE_MANIFEST_FILE).read_text(encoding="utf-8"))
        except (KeyError, UnicodeDecodeError, OSError, ValueError) as exc:
            raise RuntimeError(f"Release archive manifest is invalid: {exc}") from exc
        if archived_manifest != staged_manifest:
            raise RuntimeError("Release archive manifest does not match the staged release manifest.")
        files = archived_manifest.get("files") if isinstance(archived_manifest, dict) else None
        if not isinstance(files, dict):
            raise RuntimeError("Release archive manifest contains invalid file metadata.")
        for relative, expected_digest in files.items():
            try:
                with zip_file.open(prefix + relative, "r") as member:
                    actual_digest = hashlib.file_digest(member, "sha256").hexdigest()
            except KeyError as exc:
                raise RuntimeError(f"Release archive is missing managed file: {relative}") from exc
            if actual_digest != expected_digest:
                raise RuntimeError(f"Release archive hash mismatch: {relative}")

def _publish_release_outputs(temporary_archive: Path, archive: Path, temporary_checksum: Path, checksum: Path) -> None:
    backup_root = Path(tempfile.mkdtemp(prefix=".release-rollback-", dir=archive.parent))
    outputs = ((temporary_archive, archive), (temporary_checksum, checksum))
    existed = {target: target.exists() for _, target in outputs}
    backups = {target: backup_root / target.name for _, target in outputs}
    preserve_backups = False
    try:
        for temporary, target in outputs:
            if existed[target]:
                target.replace(backups[target])
            temporary.replace(target)
    except BaseException as exc:
        rollback_errors: list[str] = []
        for target in (checksum, archive):
            try:
                if backups[target].exists():
                    backups[target].replace(target)
                elif not existed[target]:
                    target.unlink(missing_ok=True)
            except OSError as rollback_exc:
                rollback_errors.append(f"{target.name}: {rollback_exc}")
        if rollback_errors:
            preserve_backups = True
            raise RuntimeError(
                f"Release publication failed ({exc}); rollback was incomplete: "
                + "; ".join(rollback_errors)
                + f". Previous release files were retained at {backup_root}."
            ) from exc
        raise
    finally:
        if not preserve_backups:
            shutil.rmtree(backup_root, ignore_errors=True)

@contextlib.contextmanager
def release_output_rollback_guard(enabled: bool):
    if not enabled:
        yield
        return

    archive = release_archive_path()
    checksum = release_checksum_path()
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    backup_root = Path(tempfile.mkdtemp(prefix=".release-finalize-rollback-", dir=RELEASE_DIR))
    outputs = (archive, checksum)
    existed = {path: path.is_file() for path in outputs}
    backups = {path: backup_root / path.name for path in outputs}
    preserve_backups = False
    try:
        for path in outputs:
            if path.exists() and not path.is_file():
                raise RuntimeError(f"Release output path is not a file: {path}")
            if existed[path]:
                shutil.copy2(path, backups[path])
        try:
            yield
        except BaseException as exc:
            rollback_errors: list[str] = []
            for path in outputs:
                try:
                    if existed[path]:
                        backups[path].replace(path)
                    else:
                        path.unlink(missing_ok=True)
                except OSError as rollback_exc:
                    rollback_errors.append(f"{path.name}: {rollback_exc}")
            if rollback_errors:
                preserve_backups = True
                raise RuntimeError(
                    f"Release finalization failed ({exc}); output rollback was incomplete: "
                    + "; ".join(rollback_errors)
                    + f". Previous release files were retained at {backup_root}."
                ) from exc
            raise
    finally:
        if not preserve_backups:
            shutil.rmtree(backup_root, ignore_errors=True)

def create_release_outputs(stage: Path) -> tuple[Path, Path, str, str]:
    validate_release_manifest(stage)
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    archive = release_archive_path()
    checksum = release_checksum_path()
    temporary_archive = archive.with_name(archive.name + ".tmp")
    temporary_checksum = checksum.with_name(checksum.name + ".tmp")

    temporary_archive.unlink(missing_ok=True)
    temporary_checksum.unlink(missing_ok=True)
    try:
        with zipfile.ZipFile(temporary_archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True) as output:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    output.write(path, f"{stage.name}/{path.relative_to(stage).as_posix()}")
        validate_release_archive(temporary_archive, stage)
        digest = sha256_file(temporary_archive)
        checksum_text = f"{digest}  {archive.name}\n"
        temporary_checksum.write_text(checksum_text, encoding="ascii", newline="\n")

        if archive.exists() and not archive.is_file():
            raise RuntimeError(f"Release archive path is not a file: {archive}")
        if checksum.exists() and not checksum.is_file():
            raise RuntimeError(f"Release checksum path is not a file: {checksum}")

        archive_existed = archive.is_file()
        if archive_existed and sha256_file(archive) == digest:
            temporary_archive.unlink()
            try:
                checksum_matches = checksum.read_text(encoding="ascii") == checksum_text
            except (OSError, UnicodeError):
                checksum_matches = False
            if checksum_matches:
                temporary_checksum.unlink()
            else:
                temporary_checksum.replace(checksum)
            return archive, checksum, digest, "unchanged"

        _publish_release_outputs(temporary_archive, archive, temporary_checksum, checksum)
        return archive, checksum, digest, "replaced" if archive_existed else "created"
    except BaseException:
        temporary_archive.unlink(missing_ok=True)
        temporary_checksum.unlink(missing_ok=True)
        raise

def main(argv: list[str] | None = None) -> int:
    started = time.perf_counter()
    args = parse_args([] if argv is None else argv)
    extracted: Path | None = None
    try:
        project_licenses = validate_build_environment()
        archive = release_archive_path()
        with operation_lock("release", archive, "release build for this version"):
            with release_temp_console_cleanup():
                clean_stale_release_temp()
                remove_release_output_temps()
                # Snapshot the tested release inputs while normal Ninja Patch Tool operations are excluded, then release
                # the activity gate while the source tests run. Windows tests intentionally exercise the same
                # operation gate. Reacquiring it and comparing the snapshot guarantees that the exact source
                # that passed tests is the source that is compiled and archived.
                with runtime_build_barrier():
                    tested_source_fingerprint = release_source_fingerprint(project_licenses)
                run_source_tests()
                with runtime_build_barrier():
                    validate_source_tree_cleanliness()
                    if release_source_fingerprint(project_licenses) != tested_source_fingerprint:
                        raise RuntimeError(
                            "Release source changed while the source test suite was running. "
                            "Retry the build after all Ninja Patch Tool/update activity has stopped."
                        )
                    RELEASE_TEMP_DIR.mkdir(parents=True, exist_ok=True)
                    try:
                        with tempfile.TemporaryDirectory(prefix="npt_release_", dir=RELEASE_TEMP_DIR) as temporary_dir:
                            temporary = Path(temporary_dir)
                            dist = temporary / "dist"
                            work = temporary / "build"
                            specs = temporary / "spec"
                            stage = temporary / f"NinjaPatchTool-v{VERSION}"
                            dist.mkdir()
                            work.mkdir()
                            specs.mkdir()

                            for script in ENTRY_SCRIPTS:
                                build_executable(ROOT / script, dist, work, specs)
                            smoke_test_executables(dist)
                            populate_release(stage, dist, project_licenses)
                            sanitize_staged_runtime_locks(stage)
                            smoke_test_release_round_trip(stage, temporary / "roundtrip")
                            write_release_manifest(stage)
                            with release_output_rollback_guard(args.extract):
                                archive, checksum, digest, result = create_release_outputs(stage)
                                if args.extract:
                                    extracted = extract_release_archive(archive)
                    except BaseException:
                        try:
                            remove_release_temp()
                        except OSError as cleanup_exc:
                            print(
                                f"WARNING: Could not remove temporary build files after the build failed: {RELEASE_TEMP_DIR}: {cleanup_exc}",
                                file=sys.stderr,
                            )
                        raise
                    else:
                        try:
                            remove_release_temp()
                        except OSError as exc:
                            raise RuntimeError(f"Could not remove temporary build files: {RELEASE_TEMP_DIR}") from exc

        duration = format_duration(time.perf_counter() - started)
        print(
            f"\n[{result.capitalize()}] Release completed successfully.\n"
            f"Version: {DISPLAY_VERSION}\n"
            f"Duration: {duration}\n"
            f"Size: {format_bytes(archive.stat().st_size)}\n"
            f"Archive: {archive}\n"
            f"SHA-256: {digest}\n"
            f"Checksum: {checksum}"
            + (f"\nExtracted: {extracted}" if extracted is not None else "")
        )
        return 0
    except KeyboardInterrupt:
        print("\nRelease creation interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print_error(f"{exc}")
        return 1

def run_main_with_console_title(argv: list[str]) -> int:
    with console_title("Building latest release... - Ninja Patch Tool"):
        return main(argv)

if __name__ == "__main__":
    raise SystemExit(run_main_with_console_title(sys.argv[1:]))
