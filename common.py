#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

TOOL_DIR = Path(__file__).resolve().parent
INDEX_FILE = TOOL_DIR / "index.json"
TEMP_ROOT = TOOL_DIR / "temp"
HASH_CHUNK = 8 * 1024 * 1024

# We don't need this garbage.
IGNORED_FILENAMES = {"launcher.zip", "launcher.exe", "remotecrashsender.exe"}

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()

def is_ignored_file(path: Path) -> bool:
    return path.name.casefold() in IGNORED_FILENAMES

def is_warframe_installation(path: Path) -> bool:
    return (path / "Cache.Windows").is_dir() and (path / "Tools").is_dir() and (path / "Warframe.x64.exe").is_file()

def validate_warframe_installation(path: Path, label: str) -> bool:
    if is_warframe_installation(path):
        return True
    print(f"ERROR: {label} directory is not a Warframe installation root:\n{path}\nExpected at least Cache.Windows, Tools, and Warframe.x64.exe directly inside it.", file=sys.stderr)
    return False

def natural_sort_key(value: str):
    return tuple(int(part) if part.isdigit() else part.casefold() for part in re.split(r"(\d+)", value) if part)

def scan_tree(root: Path) -> tuple[dict[str, dict[str, Any]], str]:
    # The root hash uses each relative path, size, and file SHA-256. Filesystem enumeration order is not guaranteed, so only the in-memory path list is sorted before hashing; no files are moved or modified.
    paths = sorted((path for path in root.rglob("*") if path.is_file() and not is_ignored_file(path)), key=lambda path: path.relative_to(root).as_posix())
    relative_paths = [path.relative_to(root).as_posix() for path in paths]
    files: dict[str, dict[str, Any]] = {}
    root_hash = hashlib.sha256()

    for path, relative in zip(paths, relative_paths):
        before = path.stat()
        digest = sha256_file(path)
        after = path.stat()
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise RuntimeError(f"Installation changed while it was being scanned:\n{path}\nClose Warframe and the Warframe Launcher and try again.")

        size = after.st_size
        files[relative] = {"path": path, "size": size, "sha256": digest}
        root_hash.update(relative.encode("utf-8") + b"\0" + str(size).encode("ascii") + b"\0" + digest.encode("ascii") + b"\n")

    current_paths = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() and not is_ignored_file(path))
    if current_paths != relative_paths:
        raise RuntimeError(f"Installation changed while it was being scanned:\n{root}\nClose Warframe and the Warframe Launcher and try again.")

    return files, root_hash.hexdigest()

def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate JSON key "{key}".')
        result[key] = value
    return result

def parse_json(data: str | bytes):
    return json.loads(data, object_pairs_hook=_no_duplicate_keys)

def is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None

def is_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0

def is_steam_manifest_id(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 18446744073709551615

def validate_index(index: dict[str, Any]) -> None:
    if not isinstance(index, dict):
        raise ValueError("index.json must contain a JSON object.")

    seen_names: dict[str, str] = {}
    seen_hashes: dict[str, str] = {}
    seen_manifest_ids: dict[int, str] = {}

    for name, entry in index.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Every base name must be a non-empty string.")

        folded = name.casefold()
        if folded in seen_names:
            raise ValueError(f'Duplicate base names "{seen_names[folded]}" and "{name}" differ only by capitalization.')
        seen_names[folded] = name

        if not isinstance(entry, dict):
            raise ValueError(f'Index entry "{name}" must be an object.')

        manifest_id = entry.get("steam_manifest_id")
        digest = entry.get("sha256")
        file_count = entry.get("file_count")
        if not is_steam_manifest_id(manifest_id):
            raise ValueError(f'Index entry "{name}" has an invalid or missing steam_manifest_id.')
        if not is_sha256(digest):
            raise ValueError(f'Index entry "{name}" has an invalid SHA-256 value.')
        if not is_nonnegative_int(file_count):
            raise ValueError(f'Index entry "{name}" has an invalid file_count.')

        if manifest_id in seen_manifest_ids:
            raise ValueError(f'Bases "{seen_manifest_ids[manifest_id]}" and "{name}" have the same Steam manifest ID and appear to be duplicates.')
        seen_manifest_ids[manifest_id] = name

        digest_lower = digest.lower()
        if digest_lower in seen_hashes:
            raise ValueError(f'Bases "{seen_hashes[digest_lower]}" and "{name}" have the same root SHA-256 and appear to be duplicates.')
        seen_hashes[digest_lower] = name

def load_index() -> dict[str, Any]:
    if not INDEX_FILE.exists():
        return {}
    index = parse_json(INDEX_FILE.read_text(encoding="utf-8"))
    validate_index(index)
    return index

def write_index(index: dict[str, Any]) -> None:
    validate_index(index)
    sorted_index = {name: index[name] for name in sorted(index, key=natural_sort_key)}

    # Write beside the real index and replace it only after serialization succeeds, so an interrupted write does not leave a half-written index.
    temporary = INDEX_FILE.with_name(INDEX_FILE.name + ".tmp")
    temporary.write_text(json.dumps(sorted_index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(INDEX_FILE)

def resolve_base_name(index: dict[str, Any], requested: str) -> str:
    requested_folded = requested.casefold()
    for name in index:
        if name.casefold() == requested_folded:
            return name
    raise KeyError(requested)

def make_work_dir(prefix: str) -> Path:
    TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    work = TEMP_ROOT / f"{prefix}_{uuid.uuid4().hex}"
    work.mkdir()
    return work

def cleanup_work_dir(work: Path) -> None:
    shutil.rmtree(work, ignore_errors=True)
    try:
        TEMP_ROOT.rmdir()
    except OSError:
        # Leave it alone if another operation is still using it, cleanup failed, or anything else remains inside it.
        pass

def install_termination_handlers() -> None:
    # Route SIGTERM through the same KeyboardInterrupt cleanup path where Python receives it normally. Forced Windows termination and console-window closure can bypass Python cleanup, so persistent/stale recovery still handles those cases.
    if hasattr(signal, "SIGTERM"):
        def handle_sigterm(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, handle_sigterm)

def run_child(command: list[str]) -> int:
    # Ensure an interrupted parent does not leave hdiffz/hpatchz running on its own.
    process = subprocess.Popen(command)
    try:
        return process.wait()
    except BaseException:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        raise

def process_is_running(pid: int) -> bool:
    # Recovery/cleanup state stores the creator PID so one tool instance does not delete another live instance's working directory.
    if pid <= 0:
        return False

    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return ctypes.get_last_error() == 5

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True

def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False

def relative_path_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative or "\0" in relative:
        raise ValueError(f"Unsafe relative path: {relative!r}")

    posix = PurePosixPath(relative.replace("\\", "/"))
    windows = PureWindowsPath(relative)
    if not posix.parts or posix.is_absolute() or windows.is_absolute() or windows.drive or ".." in posix.parts:
        raise ValueError(f"Unsafe relative path: {relative!r}")

    # Ninja Patches target Warframe on Windows. Reject names that Windows normalizes specially or interprets as devices/alternate data streams, even when validation runs on another OS.
    for part in posix.parts:
        stem = part.split(".", 1)[0].rstrip(" ").casefold()
        if (
            ":" in part
            or any(character in part for character in '<>"|?*')
            or any(ord(character) < 32 for character in part)
            or part.endswith((" ", "."))
            or stem in {"con", "prn", "aux", "nul", "conin$", "conout$"}
            or re.fullmatch(r"(?:com|lpt)(?:[1-9]|[¹²³])", stem)
        ):
            raise ValueError(f"Unsafe relative path: {relative!r}")
    return posix.parts

def safe_join(root: Path, relative: str) -> Path:
    result = root.joinpath(*relative_path_parts(relative))
    if not is_within(result, root):
        raise ValueError(f"Unsafe relative path: {relative!r}")
    return result

def ensure_patch_extension(path: Path) -> Path:
    return path if path.name.lower().endswith(".patch") else path.with_name(path.name + ".patch")

def format_bytes(size: int) -> str:
    value = float(max(0, size))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")

def warn_if_low_disk_space(path: Path, required_bytes: int, purpose: str) -> None:
    if required_bytes <= 0:
        return
    probe = path.resolve()
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        free = shutil.disk_usage(probe).free
    except OSError:
        return
    if free < required_bytes:
        print(f"WARNING: Disk space may be insufficient for {purpose}.\nAvailable: {format_bytes(free)}\nEstimated required: {format_bytes(required_bytes)}", file=sys.stderr)

def format_duration(seconds: float) -> str:
    total_seconds = max(0, round(seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"

class CompactHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=32)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        metavar = self._format_args(action, self._get_default_metavar_for_optional(action))
        return f"{', '.join(action.option_strings)} {metavar}"

class ErrorArgumentParser(argparse.ArgumentParser):
    """Keep argparse errors and built-in help text consistent with the tool's CLI style."""

    def __init__(self, *args, **kwargs) -> None:
        kwargs["add_help"] = False
        kwargs.setdefault("formatter_class", CompactHelpFormatter)
        super().__init__(*args, **kwargs)

    def add_help_argument(self) -> None:
        self.add_argument("-h", "--help", action="help", help="Shows this help message")

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"ERROR: {message}\n")

class SingleUseStoreAction(argparse.Action):
    """Store an option value, but reject repeated use of either alias."""

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values, option_string: str | None = None) -> None:
        marker = f"_single_use_seen_{self.dest}"
        if getattr(namespace, marker, False):
            parser.error(f"{option_string} cannot be used more than once (including its short/long alias)")
        setattr(namespace, marker, True)
        setattr(namespace, self.dest, values)

class SingleUseStoreTrueAction(argparse.Action):
    """Store True, but reject repeated use of either alias."""

    def __init__(self, option_strings, dest, default=False, required=False, help=None):
        super().__init__(option_strings=option_strings, dest=dest, nargs=0, default=default, required=required, help=help)

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values, option_string: str | None = None) -> None:
        marker = f"_single_use_seen_{self.dest}"
        if getattr(namespace, marker, False):
            parser.error(f"{option_string} cannot be used more than once (including its short/long alias)")
        setattr(namespace, marker, True)
        setattr(namespace, self.dest, True)

def resolve_patch_output(path: Path) -> Path:
    """Resolve a patch output path without creating directories; bare filenames go to <tool>/output/."""
    path = ensure_patch_extension(path)
    return TOOL_DIR / "output" / path.name if path.parent == Path(".") else path.resolve()

def resolve_patch_input(path: Path) -> Path:
    """Resolve a patch input path; bare filenames are looked up in <tool>/output/."""
    path = ensure_patch_extension(path)
    return TOOL_DIR / "output" / path.name if path.parent == Path(".") else path.resolve()

def display_relative_path(relative: str) -> str:
    return relative.replace("/", os.sep)
