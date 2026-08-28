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
import uuid
from contextlib import contextmanager
from pathlib import Path

from common import (
    ErrorArgumentParser,
    compare_versions,
    natural_sort_key,
    parse_json,
    parse_version,
    process_identity,
    validate_index,
)

UPDATER_LOCK_TIMEOUT_SECONDS = 120
UPDATE_INSTALLER_ARGUMENT = "--update-installer"
UPDATE_SESSION_FILE = "update_session.json"


def ignore_interrupts() -> None:
    # Once the updater handoff has started, interruption must not stop file replacement or rollback halfway through.
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            signal.signal(sig, signal.SIG_IGN)


@contextmanager
def updater_install_lock(install_dir: Path, timeout_seconds: int = UPDATER_LOCK_TIMEOUT_SECONDS):
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
            if destination.exists():
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
        if destination.exists():
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


def main(argv: list[str] | None = None) -> int:
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
                    print(
                        f"[Update] Ninja Patch Tool v{installed_version} is already installed; "
                        f"skipping queued update to v{args.target_version}."
                    )
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
                        print(
                            f"ERROR: Ninja Patch Tool update failed and rollback was incomplete: {rollback_error}",
                            file=sys.stderr,
                        )
                        return 1

                print(
                    f"ERROR: Ninja Patch Tool update failed; the previous installation was restored when possible: {exc}",
                    file=sys.stderr,
                )
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


if __name__ == "__main__":
    raise SystemExit(main())
