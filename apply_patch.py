#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import sys
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

from common import (
    ENTRY_SCRIPTS,
    ByteProgress,
    ErrorArgumentParser,
    SingleUseStoreAction,
    SingleUseStoreTrueAction,
    DATA_DIR,
    TEMP_ROOT,
    cleanup_work_dir,
    display_relative_path,
    format_duration,
    console_title,
    install_termination_handlers,
    is_ignored_file,
    is_nonnegative_int,
    is_sha256,
    is_steam_manifest_id,
    is_within,
    make_work_dir,
    operation_activity_lock,
    operation_lock,
    parse_json,
    process_identity,
    process_matches_identity,
    relative_path_parts,
    resolve_patch_path,
    root_sha256_from_files,
    run_child,
    safe_join,
    scan_tree,
    sha256_file,
    validate_installation_root_entry,
    validate_warframe_installation,
    validated_tree_paths,
    verify_scanned_file,
    verify_scanned_tree,
    warn_if_low_disk_space_groups,
)
from update import add_update_arguments, handle_automatic_update, handle_early_update_request

HPATCHZ = DATA_DIR / "hpatchz.exe"
SUPPORTED_VERSIONS = {1, 2}
RECOVERY_VERSION = 2
SUPPORTED_RECOVERY_VERSIONS = {1, 2}
RECOVERY_FILE = "recovery.json"
MAX_MANIFEST_SIZE = 64 * 1024 * 1024
SUPPORTED_ZIP_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_LZMA}
COPY_BUFFER_SIZE = 8 * 1024 * 1024

def read_archive_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    # Duplicate ZIP names are ambiguous, so reject them before reading the manifest or any payload.
    members: dict[str, zipfile.ZipInfo] = {}
    for member in archive.infolist():
        if member.is_dir():
            continue
        if member.filename in members:
            raise RuntimeError(f"Patch contains duplicate archive entry: {member.filename}")
        if member.compress_type not in SUPPORTED_ZIP_COMPRESSION:
            raise RuntimeError(f"Patch archive entry uses unsupported ZIP compression: {member.filename}")
        members[member.filename] = member
    return members

def normalized_relative_path(relative_path: str) -> str:
    return "/".join(relative_path_parts(relative_path))

def casefold_relative_path(relative_path: str) -> str:
    return normalized_relative_path(relative_path).casefold()

def validate_manifest(manifest: object, members: dict[str, zipfile.ZipInfo]) -> dict:
    if not isinstance(manifest, dict):
        raise RuntimeError("Invalid patch manifest.")
    version = manifest.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version not in SUPPORTED_VERSIONS:
        raise RuntimeError(f"Unsupported patch version: {version!r}")

    required = {
        "base",
        "base_steam_manifest_id",
        "old_root_sha256",
        "new_root_sha256",
        "old_file_count",
        "new_file_count",
        "operations",
    }
    missing = required - set(manifest)
    if missing:
        raise RuntimeError("Patch manifest is missing: " + ", ".join(sorted(missing)))
    if not isinstance(manifest["base"], str) or not manifest["base"].strip():
        raise RuntimeError("Patch manifest has an invalid base name.")
    if not is_steam_manifest_id(manifest["base_steam_manifest_id"]):
        raise RuntimeError("Patch manifest has an invalid base Steam manifest ID.")
    if not is_sha256(manifest["old_root_sha256"]) or not is_sha256(manifest["new_root_sha256"]):
        raise RuntimeError("Patch manifest contains an invalid root SHA-256.")
    if not is_nonnegative_int(manifest["old_file_count"]) or not is_nonnegative_int(manifest["new_file_count"]):
        raise RuntimeError("Patch manifest contains an invalid file count.")
    if not isinstance(manifest["operations"], list):
        raise RuntimeError("Patch manifest operations must be a list.")

    seen_paths: dict[str, list[tuple[str, str]]] = {}
    seen_payloads: set[str] = set()
    added = 0
    removed = 0

    for index, operation in enumerate(manifest["operations"], start=1):
        if not isinstance(operation, dict):
            raise RuntimeError(f"Patch operation {index} is invalid.")

        operation_type = operation.get("type")
        relative_path = operation.get("path")
        if operation_type not in {"patch", "replace", "add", "remove"} or not isinstance(relative_path, str):
            raise RuntimeError(f"Patch operation {index} has an invalid type or path.")

        try:
            canonical_path = normalized_relative_path(relative_path)
        except ValueError as exc:
            raise RuntimeError(f"Patch operation {index} has an unsafe path: {relative_path!r}") from exc

        if is_ignored_file(Path(canonical_path)):
            raise RuntimeError(f"Patch operation {index} targets a file Ninja Patch Tool intentionally ignores: {relative_path}")

        path_key = canonical_path.casefold()
        path_group = seen_paths.setdefault(path_key, [])
        if path_group:
            candidate_group = path_group + [(operation_type, canonical_path)]
            candidate_types = {kind for kind, _ in candidate_group}
            candidate_paths = {path for _, path in candidate_group}
            if len(candidate_group) != 2 or candidate_types != {"remove", "add"} or len(candidate_paths) != 2:
                raise RuntimeError(f"Patch contains more than one operation for: {relative_path}")
        path_group.append((operation_type, canonical_path))

        requires_old = operation_type in {"patch", "replace", "remove"}
        requires_new = operation_type in {"patch", "replace", "add"}
        if requires_old and (
            not is_nonnegative_int(operation.get("old_size")) or not is_sha256(operation.get("old_sha256"))
        ):
            raise RuntimeError(f"Patch operation {index} has invalid old-file metadata.")
        if requires_new and (
            not is_nonnegative_int(operation.get("new_size")) or not is_sha256(operation.get("new_sha256"))
        ):
            raise RuntimeError(f"Patch operation {index} has invalid new-file metadata.")

        if requires_new:
            payload = operation.get("payload")
            if not isinstance(payload, str) or "\\" in payload:
                raise RuntimeError(f"Patch operation {index} has an invalid payload path.")
            try:
                relative_path_parts(payload)
            except ValueError as exc:
                raise RuntimeError(f"Patch operation {index} has an unsafe payload path.") from exc
            if payload in seen_payloads:
                raise RuntimeError(f"Patch payload is referenced more than once: {payload}")
            seen_payloads.add(payload)

            if operation_type == "patch":
                expected_prefix = "diffs/"
            else:
                expected_prefix = "files/"
            if not payload.startswith(expected_prefix):
                raise RuntimeError(f"Patch operation {index} has an unexpected payload location: {payload}")

            member = members.get(payload)
            if member is None:
                raise RuntimeError(f"Patch payload is missing: {payload}")
            if operation_type == "patch" and member.file_size >= operation["new_size"]:
                raise RuntimeError(f"Patch delta is not smaller than its target file: {relative_path}")
            if operation_type in {"replace", "add"} and member.file_size != operation["new_size"]:
                raise RuntimeError(f"Patch payload size does not match the manifest: {relative_path}")

        added += operation_type == "add"
        removed += operation_type == "remove"

    if manifest["old_file_count"] + added - removed != manifest["new_file_count"]:
        raise RuntimeError("Patch manifest file counts do not match its operations.")

    return manifest

def read_manifest(archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo]) -> dict:
    info = members.get("manifest.json")
    if info is None:
        raise RuntimeError("Patch does not contain manifest.json.")
    if info.file_size > MAX_MANIFEST_SIZE:
        raise RuntimeError(f"Patch manifest is too large: {info.file_size:,} bytes (maximum {MAX_MANIFEST_SIZE:,} bytes).")
    with archive.open(info, "r") as source:
        return validate_manifest(parse_json(source.read()), members)

def copy_archive_member(archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo], name: str, destination: Path) -> None:
    member = members.get(name)
    if member is None:
        raise RuntimeError(f"Patch payload is missing: {name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with archive.open(member, "r") as source, destination.open("wb") as output:
        shutil.copyfileobj(source, output, length=8 * 1024 * 1024)

def verify_file(path: Path, expected_size: int, expected_hash: str) -> None:
    if not path.is_file():
        raise RuntimeError(f"Expected file does not exist: {path}")
    if path.stat().st_size != expected_size:
        raise RuntimeError(f"Size verification failed: {path}")
    if sha256_file(path).lower() != expected_hash.lower():
        raise RuntimeError(f"SHA-256 verification failed: {path}")

def installation_size(root: Path) -> int:
    _, source_files = validated_tree_paths(root)
    return sum(path.stat().st_size for path in source_files)

def copy_verified_base(base: Path, destination: Path, total_size: int | None = None) -> tuple[dict[str, dict], str]:
    # Validate the complete tree before copying so symlinks, junctions, and other reparse points are never followed
    # into data outside the selected Warframe installation. Each tracked file is hashed while it is copied.
    directories, source_files = validated_tree_paths(base)
    initial_directories = [path.relative_to(base).as_posix() for path in directories]
    initial_files = [path.relative_to(base).as_posix() for path in source_files]
    files: dict[str, dict] = {}
    estimated_size = sum(path.stat().st_size for path in source_files) if total_size is None else total_size
    progress = ByteProgress("Copying and verifying base", estimated_size)

    destination.mkdir(parents=True)
    for source_directory in directories:
        target_directory = destination / source_directory.relative_to(base)
        target_directory.mkdir(parents=True, exist_ok=True)

    for source in source_files:
        target = destination / source.relative_to(base)
        target.parent.mkdir(parents=True, exist_ok=True)
        if is_ignored_file(source):
            before = source.lstat()
            if source.is_symlink():
                raise RuntimeError(f"Installation changed while it was being copied:\n{source}")
            shutil.copy2(source, target)
            after = source.lstat()
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                raise RuntimeError(f"Installation changed while it was being copied:\n{source}\nClose Warframe and the Warframe Launcher and try again.")
            progress.update(after.st_size)
            continue

        before = source.lstat()
        if source.is_symlink():
            raise RuntimeError(f"Installation changed while it was being copied:\n{source}")
        digest = hashlib.sha256()
        with source.open("rb") as input_file, target.open("wb") as output_file:
            while chunk := input_file.read(COPY_BUFFER_SIZE):
                digest.update(chunk)
                if output_file.write(chunk) != len(chunk):
                    raise RuntimeError(f"Could not completely copy base file: {source}")
                progress.update(len(chunk))
        shutil.copystat(source, target)
        after = source.lstat()
        if source.is_symlink() or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise RuntimeError(f"Installation changed while it was being copied:\n{source}\nClose Warframe and the Warframe Launcher and try again.")

        target_stat = target.stat()
        if target_stat.st_size != after.st_size:
            raise RuntimeError(f"Base copy size verification failed: {target}")
        relative = source.relative_to(base).as_posix()
        files[relative] = {"path": target, "size": target_stat.st_size, "sha256": digest.hexdigest(), "mtime_ns": target_stat.st_mtime_ns}

    final_directories, final_files = validated_tree_paths(base)
    if (
        [path.relative_to(base).as_posix() for path in final_directories] != initial_directories
        or [path.relative_to(base).as_posix() for path in final_files] != initial_files
    ):
        raise RuntimeError(
            "Installation changed while it was being copied.\n"
            "Close Warframe and the Warframe Launcher and try again."
        )

    for source_directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        shutil.copystat(source_directory, destination / source_directory.relative_to(base))
    shutil.copystat(base, destination)
    progress.finish()
    verify_scanned_tree(destination, files)
    return files, root_sha256_from_files(files)

def verify_operation_old_file(target: Path, operation: dict, tracked_files: dict[str, dict] | None) -> None:
    if tracked_files is None:
        verify_file(target, operation["old_size"], operation["old_sha256"])
        return

    relative = normalized_relative_path(operation["path"])
    info = tracked_files.get(relative)
    if info is None or info["size"] != operation["old_size"] or info["sha256"].lower() != operation["old_sha256"].lower():
        raise RuntimeError(f"Patch old-file metadata does not match the verified base: {operation['path']}")
    verify_scanned_file(info)

def track_new_file(tracked_files: dict[str, dict] | None, operation: dict, target: Path) -> None:
    if tracked_files is None:
        return
    current = target.stat()
    if current.st_size != operation["new_size"]:
        raise RuntimeError(f"Size verification failed after publishing patched file: {target}")
    tracked_files[normalized_relative_path(operation["path"])] = {
        "path": target,
        "size": operation["new_size"],
        "sha256": operation["new_sha256"],
        "mtime_ns": current.st_mtime_ns,
    }

def prune_empty_parents(path: Path, root: Path) -> None:
    # This lets an update safely change a path from file -> directory or directory -> file without leaving empty old directories in the way.
    root = root.resolve()
    path = path.resolve()
    while path != root and is_within(path, root):
        try:
            path.rmdir()
        except OSError:
            break
        path = path.parent

def temporary_output(target: Path, token: str | None) -> Path:
    if token is None:
        # Recovery compatibility with NPT versions that used predictable <target>.tmp files.
        return target.with_name(target.name + ".tmp")
    return target.with_name(f".{target.name}.npt-{token}.tmp")

def check_temporary_paths(destination: Path, operations: list[dict], token: str | None = None) -> None:
    # New apply operations only touch session-owned temporary names. Refuse the vanishingly unlikely collision instead
    # of deleting a file that existed before this operation.
    targets = {
        str(safe_join(destination, operation["path"]).resolve()).casefold()
        for operation in operations
    }
    for operation in operations:
        if operation["type"] not in {"patch", "replace", "add"}:
            continue
        temporary = temporary_output(safe_join(destination, operation["path"]), token)
        if str(temporary.resolve()).casefold() in targets:
            raise RuntimeError(f"Temporary output path conflicts with a patch target: {temporary}")
        if temporary.exists():
            raise RuntimeError(f"Temporary output path already exists: {temporary}")

def ordered_operations(operations: list[dict]) -> list[dict]:
    # Remove old paths first so file/directory topology changes can be created afterward. Stable sorting preserves manifest order inside each phase.
    order = {"remove": 0, "patch": 1, "replace": 1, "add": 2}
    return sorted(operations, key=lambda operation: order[operation["type"]])

def apply_operations(
    destination: Path,
    archive: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    scratch: Path,
    operations: list[dict],
    tracked_files: dict[str, dict] | None = None,
    temporary_token: str | None = None,
) -> None:
    payload_file = scratch / "payload.hdiff"
    ordered = ordered_operations(operations)
    total_operations = len(ordered)

    for operation_number, operation in enumerate(ordered, start=1):
        operation_type = operation["type"]
        relative_path = operation["path"]
        normalized_path = normalized_relative_path(relative_path)
        target = safe_join(destination, relative_path)

        if operation_type == "remove":
            verify_operation_old_file(target, operation, tracked_files)
            target.unlink()
            if tracked_files is not None:
                tracked_files.pop(normalized_path, None)
            prune_empty_parents(target.parent, destination)
            print(f"[Removed {operation_number}/{total_operations}] {display_relative_path(relative_path)}")
            continue

        temporary = temporary_output(target, temporary_token)
        if temporary.exists():
            raise RuntimeError(f"Temporary output path unexpectedly exists: {temporary}")

        if operation_type == "patch":
            verify_operation_old_file(target, operation, tracked_files)
            payload_file.unlink(missing_ok=True)
            copy_archive_member(archive, members, operation["payload"], payload_file)

            try:
                result = run_child([str(HPATCHZ), str(target), str(payload_file), str(temporary)])
                if result != 0:
                    raise RuntimeError(f"hpatchz failed with exit code {result}: {relative_path}")
                verify_file(temporary, operation["new_size"], operation["new_sha256"])
                os.replace(temporary, target)
                track_new_file(tracked_files, operation, target)
            finally:
                payload_file.unlink(missing_ok=True)
                temporary.unlink(missing_ok=True)

            print(f"[Patched {operation_number}/{total_operations}] {display_relative_path(relative_path)}")
            continue

        if operation_type == "replace":
            verify_operation_old_file(target, operation, tracked_files)
        elif target.exists():
            raise RuntimeError(f"Patch expects a new file, but it already exists: {relative_path}")

        try:
            copy_archive_member(archive, members, operation["payload"], temporary)
            verify_file(temporary, operation["new_size"], operation["new_sha256"])
            os.replace(temporary, target)
            track_new_file(tracked_files, operation, target)
        finally:
            temporary.unlink(missing_ok=True)

        if operation_type == "replace":
            action = "Patched"
        else:
            action = "Added"
        print(f"[{action} {operation_number}/{total_operations}] {display_relative_path(relative_path)}")

def case_only_additions(operations: list[dict]) -> set[str]:
    removed = {}
    for operation in operations:
        if operation["type"] != "remove":
            continue
        removed.setdefault(casefold_relative_path(operation["path"]), set()).add(operation["path"])

    additions: set[str] = set()
    for operation in operations:
        if operation["type"] != "add":
            continue
        for removed_path in removed.get(casefold_relative_path(operation["path"]), set()):
            if removed_path != operation["path"]:
                additions.add(operation["path"])
                break
    return additions

def backup_in_place(base: Path, backup: Path, operations: list[dict]) -> dict[str, bool]:
    existed: dict[str, bool] = {}
    rename_additions = case_only_additions(operations)
    progress = ByteProgress("Creating recovery backup", sum(operation.get("old_size", 0) for operation in operations))
    for operation in operations:
        relative = operation["path"]
        target = safe_join(base, relative)
        existed_now = target.is_file()
        if operation["type"] == "add" and relative in rename_additions:
            existed[relative] = False
            continue
        existed[relative] = existed_now
        if existed_now:
            if "old_size" not in operation or "old_sha256" not in operation:
                raise RuntimeError(f"Patch expects a new file, but an original file exists: {relative}")
            backup_path = safe_join(backup, relative)
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            before = target.stat()
            digest = hashlib.sha256()
            with target.open("rb") as input_file, backup_path.open("wb") as output_file:
                while chunk := input_file.read(COPY_BUFFER_SIZE):
                    digest.update(chunk)
                    if output_file.write(chunk) != len(chunk):
                        raise RuntimeError(f"Could not completely copy recovery file: {target}")
                    progress.update(len(chunk))
            shutil.copystat(target, backup_path)
            after = target.stat()
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                raise RuntimeError(f"Installation changed while the recovery backup was being created:\n{target}")
            if after.st_size != operation["old_size"] or digest.hexdigest().lower() != operation["old_sha256"].lower():
                raise RuntimeError(f"Recovery backup source verification failed: {target}")
            backup_stat = backup_path.stat()
            if backup_stat.st_size != operation["old_size"]:
                raise RuntimeError(f"Recovery backup size verification failed: {backup_path}")
            verify_file(backup_path, operation["old_size"], operation["old_sha256"])
    progress.finish()
    return existed

def rollback_in_place(
    base: Path,
    backup: Path,
    operations: list[dict],
    existed: dict[str, bool],
    temporary_token: str | None = None,
) -> None:
    # Remove every path created by the patch first, then restore original files. This ordering is required when a
    # patch changes a path between file and directory topology.
    for operation in operations:
        relative = operation["path"]
        if existed.get(relative):
            continue
        target = safe_join(base, relative)
        try:
            temporary_output(target, temporary_token).unlink(missing_ok=True)
        except NotADirectoryError:
            pass
        if target.is_file():
            target.unlink()
            prune_empty_parents(target.parent, base)

    for operation in operations:
        relative = operation["path"]
        if not existed.get(relative):
            continue
        target = safe_join(base, relative)
        temporary_output(target, temporary_token).unlink(missing_ok=True)
        if target.exists() and not target.is_file():
            try:
                target.rmdir()
            except OSError as exc:
                raise RuntimeError(f"Rollback cannot replace non-empty directory with file: {relative}") from exc
        source = safe_join(backup, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

def write_recovery_state(work: Path, state: dict) -> None:
    # Apply recovery is persistent because user files may already have changed. The state is fsynced before atomic
    # replacement so abrupt termination can be repaired on the next run.
    recovery = work / RECOVERY_FILE
    temporary = recovery.with_name(recovery.name + ".tmp")
    state = {"recovery_version": RECOVERY_VERSION, "pid": os.getpid(), "process_identity": process_identity(os.getpid()), **state}

    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(state, output, indent=2, ensure_ascii=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, recovery)

def make_recovery_state(
    mode: str,
    base: Path,
    destination: Path,
    patch: Path,
    manifest: dict,
    phase: str,
    existed: dict[str, bool] | None = None,
    working_destination: Path | None = None,
    temporary_token: str | None = None,
) -> dict:
    state = {
        "mode": mode,
        "phase": phase,
        "base": str(base),
        "destination": str(destination),
        "patch": str(patch),
        "old_root_sha256": manifest["old_root_sha256"],
        "new_root_sha256": manifest["new_root_sha256"],
        "old_file_count": manifest["old_file_count"],
        "new_file_count": manifest["new_file_count"],
    }
    if temporary_token is not None:
        state["temporary_token"] = temporary_token
    if mode == "in_place":
        state["operations"] = manifest["operations"]
        state["existed"] = existed or {}
    elif working_destination is not None:
        state["working_destination"] = str(working_destination)
    return state

def recovery_matches_manifest(state: dict, manifest: dict) -> bool:
    return all(
        state.get(key) == manifest.get(key)
        for key in ("old_root_sha256", "new_root_sha256", "old_file_count", "new_file_count")
    )

def tree_matches(root: Path, expected_hash: str, expected_count: int, progress_label: str | None = None) -> bool:
    files, root_hash = scan_tree(root, progress_label)
    return root_hash.lower() == expected_hash.lower() and len(files) == expected_count

@contextmanager
def protected_cleanup():
    # Once recovery/cleanup starts, repeated Ctrl+C or SIGTERM should not interrupt it halfway through.
    previous = {}
    for name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, name, None)
        if sig is not None:
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, signal.SIG_IGN)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)

def restore_in_place(
    base: Path,
    backup: Path,
    operations: list[dict],
    existed: dict[str, bool],
    old_root_sha256: str,
    old_file_count: int,
    temporary_token: str | None = None,
) -> None:
    with protected_cleanup():
        rollback_in_place(base, backup, operations, existed, temporary_token)
        if not tree_matches(base, old_root_sha256, old_file_count, "Verifying restored base"):
            raise RuntimeError("Rollback failed: the original base could not be fully restored.")

def remove_incomplete_output(destination: Path) -> bool:
    with protected_cleanup():
        shutil.rmtree(destination, ignore_errors=True)
    return not destination.exists()

def separate_working_destination(destination: Path, work: Path) -> Path:
    token = work.name.removeprefix("apply_patch_")
    return destination.with_name(f".{destination.name}.npt-{token}.tmp")

def publish_output_directory(working_destination: Path, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError(f"Output path appeared while the patch was being applied:\n{destination}")
    try:
        # Windows directory rename is atomic on the same volume and refuses to replace an existing destination.
        working_destination.rename(destination)
    except OSError as exc:
        if destination.exists():
            raise FileExistsError(f"Output path appeared while the patch was being applied:\n{destination}") from exc
        raise

def recover_interrupted_operations(base: Path, destination: Path) -> dict | None:
    # Recovery runs before normal patch prerequisites so missing tools or a temporarily incomplete installation cannot
    # block restoration. Abandoned work without a finished recovery file is also cleaned when it is safe to do so.
    if not TEMP_ROOT.is_dir():
        return None

    completed_state: dict | None = None
    for work in sorted(TEMP_ROOT.glob("apply_patch_*")):
        recovery = work / RECOVERY_FILE
        if not recovery.is_file():
            temporary_recovery = recovery.with_name(recovery.name + ".tmp")
            if temporary_recovery.is_file():
                try:
                    temporary_state = parse_json(temporary_recovery.read_text(encoding="utf-8"))
                except Exception:
                    temporary_state = None
                if isinstance(temporary_state, dict):
                    pid = temporary_state.get("pid")
                    if isinstance(pid, int) and pid != os.getpid() and process_matches_identity(pid, temporary_state.get("process_identity")):
                        continue
                    try:
                        os.replace(temporary_recovery, recovery)
                    except OSError:
                        pass
        if not recovery.is_file():
            backup = work / "backup"
            try:
                backup_has_data = backup.is_symlink() or (backup.exists() and (not backup.is_dir() or next(backup.iterdir(), None) is not None))
            except OSError:
                backup_has_data = True
            if backup_has_data:
                print(f"WARNING: Abandoned Apply Patch work has recovery backup data but no usable recovery state and was left untouched:\n{work}", file=sys.stderr)
                continue
            token = work.name.removeprefix("apply_patch_")
            pid_text, separator, _ = token.partition("_")
            if separator and pid_text.isdecimal():
                pid = int(pid_text)
                if pid != os.getpid() and process_matches_identity(pid, None):
                    continue
            else:
                try:
                    if time.time() - work.stat().st_mtime < 2:
                        continue
                except OSError:
                    continue
            cleanup_work_dir(work)
            continue

        try:
            state = parse_json(recovery.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"WARNING: Could not read recovery state:\n{recovery}\n{exc}\nThe folder was left untouched.", file=sys.stderr)
            continue

        recovery_version = state.get("recovery_version") if isinstance(state, dict) else None
        if not isinstance(recovery_version, int) or isinstance(recovery_version, bool) or recovery_version not in SUPPORTED_RECOVERY_VERSIONS:
            print(f"WARNING: Unsupported recovery state:\n{recovery}\nThe folder was left untouched.", file=sys.stderr)
            continue

        try:
            recovery_base = Path(state["base"]).resolve()
            recovery_destination = Path(state.get("destination", state["base"])).resolve()
        except Exception:
            print(f"WARNING: Invalid recovery state:\n{recovery}\nThe folder was left untouched.", file=sys.stderr)
            continue

        if recovery_base != base:
            continue
        mode = state.get("mode")
        if mode == "separate" and recovery_destination != destination:
            continue

        pid = state.get("pid")
        if isinstance(pid, int) and pid != os.getpid() and process_matches_identity(pid, state.get("process_identity")):
            raise RuntimeError("Another Apply Patch operation appears to still be running for this base/output.\n" f"Recovery state: {recovery}")

        old_hash, new_hash = state.get("old_root_sha256"), state.get("new_root_sha256")
        old_count, new_count = state.get("old_file_count"), state.get("new_file_count")
        if not is_sha256(old_hash) or not is_sha256(new_hash) or not is_nonnegative_int(old_count) or not is_nonnegative_int(new_count):
            raise RuntimeError(f"Interrupted patch recovery data is invalid.\nRecovery state: {recovery}")

        phase = state.get("phase") if recovery_version >= 2 else "applying"
        print("\n[Recovery] Interrupted patch application detected.")

        if mode == "in_place":
            if phase not in {"preparing", "prepared", "applying"}:
                raise RuntimeError(f"Interrupted patch recovery data contains an unknown phase: {phase!r}\nRecovery state: {recovery}")
            print("Checking the current base before recovery...")
            if tree_matches(base, old_hash, old_count):
                print("[Recovery] The original base is already intact.")
                cleanup_work_dir(work)
                continue

            if phase in {"preparing", "prepared"}:
                backup_description = "partial recovery data" if phase == "preparing" else "the verified recovery backup"
                raise RuntimeError(
                    "The base changed before Ninja Patch Tool started modifying it, so automatic rollback was intentionally skipped.\n"
                    f"{backup_description.capitalize()} was kept at:\n{work}\n"
                    "Do not delete this folder if the base was changed or deleted unexpectedly."
                )

            if tree_matches(base, new_hash, new_count):
                print("[Recovery] The in-place patch had already completed successfully.")
                cleanup_work_dir(work)
                if completed_state is not None and not recovery_matches_manifest(completed_state, state):
                    raise RuntimeError("More than one completed recovery state with different patch identities was found for this base.")
                completed_state = state
                continue

            operations, existed = state.get("operations"), state.get("existed")
            backup = work / "backup"
            if not isinstance(operations, list) or not isinstance(existed, dict) or not backup.is_dir():
                raise RuntimeError(
                    "Interrupted in-place patch requires recovery, but its backup data is incomplete.\n"
                    f"Recovery folder: {work}\nDo not delete this folder."
                )

            print("Restoring the original base from the recovery backup...")
            temporary_token = state.get("temporary_token")
            if temporary_token is not None and (not isinstance(temporary_token, str) or not temporary_token.isalnum()):
                raise RuntimeError(f"Interrupted patch recovery data contains an invalid temporary token.\nRecovery state: {recovery}")
            restore_in_place(base, backup, operations, existed, old_hash, old_count, temporary_token)
            print("[Recovery] Original base restored successfully.")
            cleanup_work_dir(work)
            continue

        if mode == "separate":
            if recovery_version == 1:
                # Compatibility with recovery state written by Ninja Patch Tool <=1.1.0, which built directly at the final destination.
                if not recovery_destination.exists():
                    print("[Recovery] The interrupted output no longer exists.")
                    cleanup_work_dir(work)
                    continue
                print("Checking the interrupted output installation...")
                if tree_matches(recovery_destination, new_hash, new_count):
                    print("[Recovery] The previous output had already completed successfully.")
                    cleanup_work_dir(work)
                    if completed_state is not None and not recovery_matches_manifest(completed_state, state):
                        raise RuntimeError("More than one completed recovery state with different patch identities was found for this base/output.")
                    completed_state = state
                    continue
                print("Removing the incomplete output installation...")
                if not remove_incomplete_output(recovery_destination):
                    raise RuntimeError(f"Could not remove the incomplete output installation.\nOutput: {recovery_destination}\nRecovery folder: {work}")
                print("[Recovery] Incomplete output removed successfully.")
                cleanup_work_dir(work)
                continue

            raw_working = state.get("working_destination")
            if not isinstance(raw_working, str):
                raise RuntimeError(f"Interrupted separate-output recovery data is invalid.\nRecovery state: {recovery}")
            working_destination = Path(raw_working).resolve()
            if working_destination != separate_working_destination(recovery_destination, work).resolve():
                raise RuntimeError(f"Interrupted separate-output recovery data contains an unexpected temporary output path.\nRecovery state: {recovery}")

            if recovery_destination.exists():
                if tree_matches(recovery_destination, new_hash, new_count):
                    print("[Recovery] The previous output had already completed successfully.")
                    if working_destination.exists():
                        remove_incomplete_output(working_destination)
                    cleanup_work_dir(work)
                    if completed_state is not None and not recovery_matches_manifest(completed_state, state):
                        raise RuntimeError("More than one completed recovery state with different patch identities was found for this base/output.")
                    completed_state = state
                    continue
                raise RuntimeError(
                    "The final output path exists but cannot be identified as Ninja Patch Tool's completed output, so it was left untouched.\n"
                    f"Output: {recovery_destination}\nRecovery folder: {work}"
                )

            if not working_destination.exists():
                print("[Recovery] The interrupted temporary output no longer exists.")
                cleanup_work_dir(work)
                continue

            print("Checking the interrupted temporary output installation...")
            if tree_matches(working_destination, new_hash, new_count):
                print("Publishing the already completed temporary output...")
                publish_output_directory(working_destination, recovery_destination)
                print("[Recovery] Previous output published successfully.")
                cleanup_work_dir(work)
                if completed_state is not None and not recovery_matches_manifest(completed_state, state):
                    raise RuntimeError("More than one completed recovery state with different patch identities was found for this base/output.")
                completed_state = state
                continue

            print("Removing the incomplete temporary output installation...")
            if not remove_incomplete_output(working_destination):
                raise RuntimeError(f"Could not remove the incomplete temporary output.\nOutput: {working_destination}\nRecovery folder: {work}")
            print("[Recovery] Incomplete temporary output removed successfully.")
            cleanup_work_dir(work)
            continue

        raise RuntimeError(f"Interrupted patch recovery data contains an unknown mode: {mode!r}\nRecovery state: {recovery}")

    return completed_state

def apply_and_verify(
    destination: Path,
    archive: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    scratch: Path,
    manifest: dict,
    tracked_files: dict[str, dict] | None = None,
    temporary_token: str | None = None,
) -> float:
    print("\nApplying patch...")
    patch_started = time.perf_counter()
    apply_operations(destination, archive, members, scratch, manifest["operations"], tracked_files, temporary_token)
    patch_duration = time.perf_counter() - patch_started

    print("\nVerifying final installation...")
    if tracked_files is None:
        valid = tree_matches(destination, manifest["new_root_sha256"], manifest["new_file_count"], "Hashing final installation")
    else:
        verify_scanned_tree(destination, tracked_files)
        valid = len(tracked_files) == manifest["new_file_count"] and root_sha256_from_files(tracked_files).lower() == manifest["new_root_sha256"].lower()
    if not valid:
        raise RuntimeError("Final installation verification failed.")
    print(f"Patch operations: {format_duration(patch_duration)}")
    return patch_duration

def run_locked_apply(
    base: Path,
    patch: Path,
    destination: Path,
    in_place: bool,
) -> int:
    try:
        completed_state = recover_interrupted_operations(base, destination)
    except KeyboardInterrupt:
        print("\nPatch application cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not validate_warframe_installation(base, "Base"):
        return 1
    if not patch.is_file():
        print(f"ERROR: Patch file does not exist: {patch}", file=sys.stderr)
        return 1

    if completed_state is not None:
        try:
            with zipfile.ZipFile(patch, "r") as archive:
                members = read_archive_members(archive)
                completed_manifest = read_manifest(archive, members)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        if recovery_matches_manifest(completed_state, completed_manifest):
            print(f"\n[Patched] The previous patch application had already completed successfully.\nBase: {base}\nOutput: {destination}")
            return 0
        if not in_place and destination.exists():
            print(f"ERROR: Output path already exists and belongs to a previously completed different patch:\n{destination}", file=sys.stderr)
            return 1

    if not in_place and destination.exists():
        print(f"ERROR: Output path already exists:\n{destination}", file=sys.stderr)
        return 1
    if not HPATCHZ.is_file():
        print(f"ERROR: hpatchz.exe was not found in the data folder:\n{HPATCHZ}", file=sys.stderr)
        return 1

    work = None
    keep_work = False
    started = time.perf_counter()

    try:
        print("Reading patch manifest...")
        with zipfile.ZipFile(patch, "r") as archive:
            members = read_archive_members(archive)
            manifest = read_manifest(archive, members)
            print(f"Patch base: {manifest['base']}\nSteam manifest ID: {manifest['base_steam_manifest_id']}")

            if in_place:
                print("Verifying current base installation...")
                base_files, base_hash = scan_tree(base, "Hashing base")
                if base_hash.lower() != manifest["old_root_sha256"].lower() or len(base_files) != manifest["old_file_count"]:
                    raise RuntimeError(
                        "The supplied installation does not match the exact base required by this patch.\n"
                        f"Expected files: {manifest['old_file_count']:,}\n"
                        f"Actual files:   {len(base_files):,}\n"
                        f"Expected SHA-256: {manifest['old_root_sha256']}\n"
                        f"Actual SHA-256:   {base_hash}\n"
                        "No files were changed."
                    )
                print(f'[Verified] Base "{manifest["base"]}" is valid.')
            else:
                base_files = None
                print("Base verification will be performed while copying the installation.")

            largest_payload = max(
                (members[operation["payload"]].file_size for operation in manifest["operations"] if "payload" in operation),
                default=0,
            )
            largest_temporary = max((operation.get("new_size", 0) for operation in manifest["operations"]), default=0)
            if in_place:
                backup_estimate = sum(
                    operation.get("old_size", 0)
                    for operation in manifest["operations"]
                    if operation["type"] in {"patch", "replace", "remove"}
                )
                warn_if_low_disk_space_groups([
                    (TEMP_ROOT, backup_estimate + largest_payload, "the in-place recovery backup and patch payload"),
                    (base, largest_temporary, "temporary in-place patch output"),
                ])
            else:
                base_estimate = installation_size(base)
                warn_if_low_disk_space_groups([
                    (destination.parent, base_estimate + largest_temporary, "the separate patched installation"),
                    (TEMP_ROOT, largest_payload, "temporary patch payload data"),
                ])

            work = make_work_dir(f"apply_patch_{os.getpid()}")
            temporary_token = work.name.rsplit("_", 1)[-1]

            if in_place:
                check_temporary_paths(base, manifest["operations"], temporary_token)

            if in_place:
                write_recovery_state(work, make_recovery_state("in_place", base, base, patch, manifest, "preparing", temporary_token=temporary_token))
                keep_work = True
                scratch = work / "payload"
                scratch.mkdir()
                backup = work / "backup"
                backup.mkdir()
                print("\n--in-place was specified.\nCreating and verifying a temporary backup before modifying the base...")
                try:
                    existed = backup_in_place(base, backup, manifest["operations"])
                    write_recovery_state(work, make_recovery_state("in_place", base, base, patch, manifest, "prepared", existed, temporary_token=temporary_token))
                except BaseException as exc:
                    raise RuntimeError(
                        "In-place recovery preparation failed before any patch changes were made. Recovery data was kept at:\n"
                        f"{work}"
                    ) from exc
                try:
                    verify_scanned_tree(base, base_files)
                    write_recovery_state(work, make_recovery_state("in_place", base, base, patch, manifest, "applying", existed, temporary_token=temporary_token))
                except BaseException as exc:
                    raise RuntimeError(
                        "The base changed or recovery metadata could not be finalized after the in-place backup was created.\n"
                        "No patch changes were made. The verified recovery backup was kept at:\n"
                        f"{work}\n"
                        "Do not delete this folder if the base was changed or deleted unexpectedly."
                    ) from exc

                try:
                    apply_and_verify(base, archive, members, scratch, manifest, temporary_token=temporary_token)
                    keep_work = False
                except BaseException as patch_error:
                    if isinstance(patch_error, KeyboardInterrupt):
                        message = "\nPatch application interrupted.\nRolling back changes..."
                    else:
                        message = f"\nERROR: {patch_error}\nRolling back changes..."
                    print(message, file=sys.stderr)
                    try:
                        restore_in_place(base, backup, manifest["operations"], existed, manifest["old_root_sha256"], manifest["old_file_count"], temporary_token)
                    except BaseException as rollback_error:
                        raise RuntimeError(
                            "Rollback could not be completed. The persistent recovery backup was kept at:\n"
                            f"{work}\n"
                            "Run Apply Patch again with the same base to retry recovery."
                        ) from rollback_error
                    keep_work = False
                    print("Rollback completed successfully.\nThe original base installation has been restored.", file=sys.stderr)
                    raise

            else:
                working_destination = separate_working_destination(destination, work)
                if working_destination.exists():
                    raise RuntimeError(f"Temporary output path unexpectedly exists:\n{working_destination}")
                write_recovery_state(work, make_recovery_state("separate", base, destination, patch, manifest, "copying", working_destination=working_destination, temporary_token=temporary_token))
                keep_work = True
                scratch = work / "payload"
                scratch.mkdir()
                try:
                    print(f"\nCreating separate installation:\n{destination}\nCopying and verifying base installation...")
                    copy_started = time.perf_counter()
                    copied_files, copied_hash = copy_verified_base(base, working_destination, base_estimate)
                    copy_duration = time.perf_counter() - copy_started
                    print(f"Copy and base verification: {format_duration(copy_duration)}")
                    if copied_hash.lower() != manifest["old_root_sha256"].lower() or len(copied_files) != manifest["old_file_count"]:
                        raise RuntimeError(
                            "The supplied installation does not match the exact base required by this patch.\n"
                            f"Expected files: {manifest['old_file_count']:,}\n"
                            f"Actual files:   {len(copied_files):,}\n"
                            f"Expected SHA-256: {manifest['old_root_sha256']}\n"
                            f"Actual SHA-256:   {copied_hash}\n"
                            "The original base was not modified."
                        )
                    print(f'[Verified] Base "{manifest["base"]}" is valid.')
                    check_temporary_paths(working_destination, manifest["operations"], temporary_token)
                    write_recovery_state(work, make_recovery_state("separate", base, destination, patch, manifest, "applying", working_destination=working_destination, temporary_token=temporary_token))
                    apply_and_verify(working_destination, archive, members, scratch, manifest, copied_files, temporary_token=temporary_token)
                    write_recovery_state(work, make_recovery_state("separate", base, destination, patch, manifest, "publishing", working_destination=working_destination, temporary_token=temporary_token))
                    publish_output_directory(working_destination, destination)
                    keep_work = False
                except BaseException:
                    print("\nPatch interrupted or failed. Removing Ninja Patch Tool's incomplete temporary output...\nThe original base and any unrelated final output were not modified.", file=sys.stderr)
                    if remove_incomplete_output(working_destination):
                        keep_work = False
                    else:
                        print(f'WARNING: The incomplete temporary output could not be removed completely. Recovery data was kept at:\n{work}', file=sys.stderr)
                    raise

            duration = format_duration(time.perf_counter() - started)
            print(f"\n[Patched] Patch applied successfully.\nBase: {base}\nDuration: {duration}\nOutput: {destination}")
            return 0

    except KeyboardInterrupt:
        print("\nPatch application cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if work is not None and not keep_work:
            cleanup_work_dir(work)

def _run_operation(args, argv: list[str]) -> int:
    update_result = handle_automatic_update(args, argv)
    if update_result is not None:
        return update_result

    if not args.base.is_dir():
        print(f"ERROR: Base directory does not exist: {args.base}", file=sys.stderr)
        return 1
    validate_installation_root_entry(args.base)
    base = args.base.resolve()
    patch = resolve_patch_path(args.patch)


    if args.in_place:
        destination = base
    elif args.output is not None:
        destination = args.output.resolve()
    else:
        destination = base.parent / patch.stem

    if not args.in_place and (
        destination == base or is_within(destination, base) or is_within(base, destination)
    ):
        print("ERROR: Output and base directories must not overlap.", file=sys.stderr)
        return 1

    try:
        with operation_lock("installation", base, "operation using this installation"):
            if destination == base:
                return run_locked_apply(base, patch, destination, args.in_place)
            with operation_lock("installation", destination, "operation using this installation"):
                return run_locked_apply(base, patch, destination, args.in_place)
    except KeyboardInterrupt:
        print("\nPatch application cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    install_termination_handlers()
    argv = sys.argv[1:]
    early_update_result = handle_early_update_request(argv)
    if early_update_result is not None:
        return early_update_result
    parser = ErrorArgumentParser(
        description=(
            "Apply a Ninja Patch (Diff Patch) from a file. By default, the base is left untouched and a separate "
            "installation is created next to the base, named after the patch."
        )
    )
    parser.add_argument("base", type=Path, help="Base installation")
    parser.add_argument(
        "patch",
        type=Path,
        help="Patch filename or path; .patch is appended automatically. A bare filename is looked up in the tool's output folder.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "-o",
        "--output",
        type=Path,
        action=SingleUseStoreAction,
        help="Create a separate installation at OUTPUT; if omitted, creates one next to the base named after the patch (cannot be used with --in-place)",
    )
    mode.add_argument(
        "-i",
        "--in-place",
        action=SingleUseStoreTrueAction,
        help="Modify the base installation instead (cannot be used with --output)",
    )
    add_update_arguments(parser)
    parser.add_version_argument()
    parser.add_help_argument()
    args = parser.parse_args(argv)

    try:
        with operation_activity_lock():
            return _run_operation(args, argv)
    except KeyboardInterrupt:
        print("\nPatch application cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    with console_title(ENTRY_SCRIPTS["apply_patch.py"]):
        raise SystemExit(main())
