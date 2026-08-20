#!/usr/bin/env python3
from __future__ import annotations

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
    ErrorArgumentParser,
    SingleUseStoreAction,
    SingleUseStoreTrueAction,
    TEMP_ROOT,
    cleanup_work_dir,
    display_relative_path,
    format_duration,
    install_termination_handlers,
    is_nonnegative_int,
    is_sha256,
    is_steam_manifest_id,
    is_within,
    make_work_dir,
    parse_json,
    process_is_running,
    relative_path_parts,
    resolve_patch_input,
    run_child,
    safe_join,
    scan_tree,
    sha256_file,
    validate_warframe_installation,
    warn_if_low_disk_space,
)

TOOL_DIR = Path(__file__).resolve().parent
HPATCHZ = TOOL_DIR / "tools" / "hpatchz.exe"
SUPPORTED_VERSIONS = {1}
RECOVERY_VERSION = 1
RECOVERY_FILE = "recovery.json"

def read_archive_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    # Duplicate ZIP names are ambiguous, so reject them before reading the manifest or any payload.
    members: dict[str, zipfile.ZipInfo] = {}
    for member in archive.infolist():
        if member.is_dir():
            continue
        if member.filename in members:
            raise RuntimeError(f"Patch contains duplicate archive entry: {member.filename}")
        members[member.filename] = member
    return members

def validate_manifest(manifest: object, members: dict[str, zipfile.ZipInfo]) -> dict:
    if not isinstance(manifest, dict):
        raise RuntimeError("Invalid patch manifest.")
    if manifest.get("version") not in SUPPORTED_VERSIONS:
        raise RuntimeError(f"Unsupported patch version: {manifest.get('version')!r}")

    required = {"base", "base_steam_manifest_id", "old_root_sha256", "new_root_sha256", "old_file_count", "new_file_count", "operations"}
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

    seen_paths: set[str] = set()
    seen_payloads: set[str] = set()
    added = removed = 0

    for index, operation in enumerate(manifest["operations"], start=1):
        if not isinstance(operation, dict):
            raise RuntimeError(f"Patch operation {index} is invalid.")

        kind = operation.get("type")
        relative = operation.get("path")
        if kind not in {"patch", "replace", "add", "remove"} or not isinstance(relative, str):
            raise RuntimeError(f"Patch operation {index} has an invalid type or path.")

        try:
            canonical = "/".join(relative_path_parts(relative))
        except ValueError as exc:
            raise RuntimeError(f"Patch operation {index} has an unsafe path: {relative!r}") from exc

        path_key = canonical.casefold()
        if path_key in seen_paths:
            raise RuntimeError(f"Patch contains more than one operation for: {relative}")
        seen_paths.add(path_key)

        old_required = kind in {"patch", "replace", "remove"}
        new_required = kind in {"patch", "replace", "add"}
        if old_required and (not is_nonnegative_int(operation.get("old_size")) or not is_sha256(operation.get("old_sha256"))):
            raise RuntimeError(f"Patch operation {index} has invalid old-file metadata.")
        if new_required and (not is_nonnegative_int(operation.get("new_size")) or not is_sha256(operation.get("new_sha256"))):
            raise RuntimeError(f"Patch operation {index} has invalid new-file metadata.")

        if new_required:
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

            expected_prefix = "diffs/" if kind == "patch" else "files/"
            if not payload.startswith(expected_prefix):
                raise RuntimeError(f"Patch operation {index} has an unexpected payload location: {payload}")

            member = members.get(payload)
            if member is None:
                raise RuntimeError(f"Patch payload is missing: {payload}")
            if kind == "patch" and member.file_size >= operation["new_size"]:
                raise RuntimeError(f"Patch delta is not smaller than its target file: {relative}")
            if kind in {"replace", "add"} and member.file_size != operation["new_size"]:
                raise RuntimeError(f"Patch payload size does not match the manifest: {relative}")

        added += kind == "add"
        removed += kind == "remove"

    if manifest["old_file_count"] + added - removed != manifest["new_file_count"]:
        raise RuntimeError("Patch manifest file counts do not match its operations.")

    return manifest

def read_manifest(archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo]) -> dict:
    info = members.get("manifest.json")
    if info is None:
        raise RuntimeError("Patch does not contain manifest.json.")
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

def temporary_output(target: Path) -> Path:
    return target.with_name(target.name + ".tmp")

def check_temporary_paths(destination: Path, operations: list[dict]) -> None:
    # .tmp files are written beside targets for atomic replacement. Refuse any pre-existing or manifest-target collision instead of deleting a possibly legitimate file.
    targets = {str(safe_join(destination, operation["path"]).resolve()).casefold() for operation in operations}
    for operation in operations:
        if operation["type"] not in {"patch", "replace", "add"}:
            continue
        temporary = temporary_output(safe_join(destination, operation["path"]))
        if str(temporary.resolve()).casefold() in targets:
            raise RuntimeError(f"Temporary output path conflicts with a patch target: {temporary}")
        if temporary.exists():
            raise RuntimeError(f"Temporary output path already exists: {temporary}")

def ordered_operations(operations: list[dict]) -> list[dict]:
    # Remove old paths first so file/directory topology changes can be created afterward. Stable sorting preserves manifest order inside each phase.
    order = {"remove": 0, "patch": 1, "replace": 1, "add": 2}
    return sorted(operations, key=lambda operation: order[operation["type"]])

def apply_operations(destination: Path, archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo], scratch: Path, operations: list[dict]) -> None:
    payload_file = scratch / "payload.hdiff"

    for operation in ordered_operations(operations):
        kind = operation["type"]
        relative = operation["path"]
        target = safe_join(destination, relative)

        if kind == "remove":
            verify_file(target, operation["old_size"], operation["old_sha256"])
            target.unlink()
            prune_empty_parents(target.parent, destination)
            print(f"[Removed] {display_relative_path(relative)}")
            continue

        temporary = temporary_output(target)
        if temporary.exists():
            raise RuntimeError(f"Temporary output path unexpectedly exists: {temporary}")

        if kind == "patch":
            verify_file(target, operation["old_size"], operation["old_sha256"])
            payload_file.unlink(missing_ok=True)
            copy_archive_member(archive, members, operation["payload"], payload_file)

            try:
                result = run_child([str(HPATCHZ), str(target), str(payload_file), str(temporary)])
                if result != 0:
                    raise RuntimeError(f"hpatchz failed with exit code {result}: {relative}")
                verify_file(temporary, operation["new_size"], operation["new_sha256"])
                os.replace(temporary, target)
            finally:
                payload_file.unlink(missing_ok=True)
                temporary.unlink(missing_ok=True)

            print(f"[Patched] {display_relative_path(relative)}")
            continue

        if kind == "replace":
            verify_file(target, operation["old_size"], operation["old_sha256"])
        elif target.exists():
            raise RuntimeError(f"Patch expects a new file, but it already exists: {relative}")

        try:
            copy_archive_member(archive, members, operation["payload"], temporary)
            verify_file(temporary, operation["new_size"], operation["new_sha256"])
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

        print(f"[{'Patched' if kind == 'replace' else 'Added'}] {display_relative_path(relative)}")

def backup_in_place(base: Path, backup: Path, operations: list[dict]) -> dict[str, bool]:
    existed: dict[str, bool] = {}
    for operation in operations:
        relative = operation["path"]
        target = safe_join(base, relative)
        existed[relative] = target.is_file()
        if existed[relative]:
            if "old_size" not in operation or "old_sha256" not in operation:
                raise RuntimeError(f"Patch expects a new file, but an original file exists: {relative}")
            backup_path = safe_join(backup, relative)
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup_path)
            verify_file(backup_path, operation["old_size"], operation["old_sha256"])
    return existed

def rollback_in_place(base: Path, backup: Path, operations: list[dict], existed: dict[str, bool]) -> None:
    # Remove every path created by the patch first, then restore original files. This ordering is required when a patch changes a path between file and directory topology.
    for operation in operations:
        relative = operation["path"]
        if existed.get(relative):
            continue
        target = safe_join(base, relative)
        try:
            temporary_output(target).unlink(missing_ok=True)
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
        temporary_output(target).unlink(missing_ok=True)
        if target.exists() and not target.is_file():
            try:
                target.rmdir()
            except OSError as exc:
                raise RuntimeError(f"Rollback cannot replace non-empty directory with file: {relative}") from exc
        source = safe_join(backup, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

def write_recovery_state(work: Path, state: dict) -> None:
    # Apply recovery is persistent because user files may already have changed. The state is fsynced before atomic replacement so abrupt termination can be repaired on the next run.
    recovery = work / RECOVERY_FILE
    temporary = recovery.with_name(recovery.name + ".tmp")
    state = {"recovery_version": RECOVERY_VERSION, "pid": os.getpid(), **state}

    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(state, output, indent=2, ensure_ascii=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, recovery)

def make_recovery_state(mode: str, base: Path, destination: Path, patch: Path, manifest: dict, existed: dict[str, bool] | None = None) -> dict:
    state = {
        "mode": mode,
        "base": str(base),
        "destination": str(destination),
        "patch": str(patch),
        "old_root_sha256": manifest["old_root_sha256"],
        "new_root_sha256": manifest["new_root_sha256"],
        "old_file_count": manifest["old_file_count"],
        "new_file_count": manifest["new_file_count"],
    }
    if mode == "in_place":
        state["operations"] = manifest["operations"]
        state["existed"] = existed or {}
    return state

def recovery_matches_manifest(state: dict, manifest: dict) -> bool:
    return all(state.get(key) == manifest.get(key) for key in ("old_root_sha256", "new_root_sha256", "old_file_count", "new_file_count"))

def tree_matches(root: Path, expected_hash: str, expected_count: int) -> bool:
    files, root_hash = scan_tree(root)
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

def restore_in_place(base: Path, backup: Path, operations: list[dict], existed: dict[str, bool], old_root_sha256: str, old_file_count: int) -> None:
    with protected_cleanup():
        rollback_in_place(base, backup, operations, existed)
        if not tree_matches(base, old_root_sha256, old_file_count):
            raise RuntimeError("Rollback failed: the original base could not be fully restored.")

def remove_incomplete_output(destination: Path) -> bool:
    with protected_cleanup():
        shutil.rmtree(destination, ignore_errors=True)
    return not destination.exists()

def recover_interrupted_operations(base: Path, destination: Path) -> dict | None:
    # Recovery records exist only when an apply operation may need cleanup. Recovery runs before normal patch prerequisites so missing tools or a temporarily incomplete installation cannot block restoration.
    if not TEMP_ROOT.is_dir():
        return None

    completed_state: dict | None = None
    for work in sorted(TEMP_ROOT.glob("apply_patch_*")):
        recovery = work / RECOVERY_FILE
        if not recovery.is_file():
            continue

        try:
            state = parse_json(recovery.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"WARNING: Could not read recovery state:\n{recovery}\n{exc}\nThe folder was left untouched.", file=sys.stderr)
            continue

        if not isinstance(state, dict) or state.get("recovery_version") != RECOVERY_VERSION:
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
        if isinstance(pid, int) and pid != os.getpid() and process_is_running(pid):
            raise RuntimeError(f"Another apply_patch operation appears to still be running for this base/output.\nRecovery state: {recovery}")

        old_hash, new_hash = state.get("old_root_sha256"), state.get("new_root_sha256")
        old_count, new_count = state.get("old_file_count"), state.get("new_file_count")
        if not is_sha256(old_hash) or not is_sha256(new_hash) or not is_nonnegative_int(old_count) or not is_nonnegative_int(new_count):
            raise RuntimeError(f"Interrupted patch recovery data is invalid.\nRecovery state: {recovery}")

        print("\n[Recovery] Interrupted patch application detected.")

        if mode == "in_place":
            print("Checking the current base before recovery...")
            if tree_matches(base, new_hash, new_count):
                print("[Recovery] The in-place patch had already completed successfully.")
                cleanup_work_dir(work)
                if completed_state is not None and not recovery_matches_manifest(completed_state, state):
                    raise RuntimeError("More than one completed recovery state with different patch identities was found for this base.")
                completed_state = state
                continue
            if tree_matches(base, old_hash, old_count):
                print("[Recovery] The original base is already intact.")
                cleanup_work_dir(work)
                continue

            operations, existed = state.get("operations"), state.get("existed")
            backup = work / "backup"
            if not isinstance(operations, list) or not isinstance(existed, dict) or not backup.is_dir():
                raise RuntimeError(f"Interrupted in-place patch requires recovery, but its backup data is incomplete.\nRecovery folder: {work}\nDo not delete this folder.")

            print("Restoring the original base from the recovery backup...")
            restore_in_place(base, backup, operations, existed, old_hash, old_count)
            print("[Recovery] Original base restored successfully.")
            cleanup_work_dir(work)
            continue

        if mode == "separate":
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

        raise RuntimeError(f"Interrupted patch recovery data contains an unknown mode: {mode!r}\nRecovery state: {recovery}")

    return completed_state

def apply_and_verify(destination: Path, archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo], scratch: Path, manifest: dict) -> None:
    print("\nApplying patch...")
    apply_operations(destination, archive, members, scratch, manifest["operations"])
    print("\nVerifying final installation...")
    if not tree_matches(destination, manifest["new_root_sha256"], manifest["new_file_count"]):
        raise RuntimeError("Final installation verification failed.")

def main() -> int:
    install_termination_handlers()
    parser = ErrorArgumentParser(description="Apply a Ninja Patch (Diff Patch) from a file. By default, the base is left untouched and a separate installation named after the patch is created.")
    parser.add_argument("base", type=Path, help="Base installation")
    parser.add_argument("patch", type=Path, help="Patch filename or path; .patch is appended automatically. A bare filename is looked up in the tool's output folder.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-o", "--output", type=Path, action=SingleUseStoreAction, help="Create a separate installation at OUTPUT; if omitted, defaults to the patch filename (cannot be used with --in-place)")
    mode.add_argument("-i", "--in-place", action=SingleUseStoreTrueAction, help="Modify the base installation instead (cannot be used with --output)")
    parser.add_help_argument()
    args = parser.parse_args()

    base = args.base.resolve()
    patch = resolve_patch_input(args.patch)

    if not base.is_dir():
        print(f"ERROR: Base directory does not exist: {base}", file=sys.stderr)
        return 1

    destination = base if args.in_place else args.output.resolve() if args.output is not None else base.parent / patch.stem
    if not args.in_place and (destination == base or is_within(destination, base) or is_within(base, destination)):
        print("ERROR: Output and base directories must not overlap.", file=sys.stderr)
        return 1

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
        if not args.in_place and destination.exists():
            print(f"ERROR: Output path already exists and belongs to a previously completed different patch:\n{destination}", file=sys.stderr)
            return 1

    if not args.in_place and destination.exists():
        print(f"ERROR: Output path already exists:\n{destination}", file=sys.stderr)
        return 1
    if not HPATCHZ.is_file():
        print(f"ERROR: hpatchz.exe was not found in the tools folder:\n{HPATCHZ}", file=sys.stderr)
        return 1

    work = None
    keep_work = False
    started = time.perf_counter()

    try:
        print("Reading patch manifest...")
        with zipfile.ZipFile(patch, "r") as archive:
            members = read_archive_members(archive)
            manifest = read_manifest(archive, members)
            print(f"Patch base: {manifest['base']}\nSteam manifest ID: {manifest['base_steam_manifest_id']}\nVerifying current base installation...")
            base_files, base_hash = scan_tree(base)

            if base_hash.lower() != manifest["old_root_sha256"].lower() or len(base_files) != manifest["old_file_count"]:
                raise RuntimeError(
                    f"The supplied installation does not match the exact base required by this patch.\nExpected files: {manifest['old_file_count']:,}\nActual files:   {len(base_files):,}\n"
                    f"Expected SHA-256: {manifest['old_root_sha256']}\nActual SHA-256:   {base_hash}\nNo files were changed."
                )

            print(f'[Verified] Base "{manifest["base"]}" is valid.')
            largest_payload = max((members[operation["payload"]].file_size for operation in manifest["operations"] if "payload" in operation), default=0)
            largest_temporary = max((operation.get("new_size", 0) for operation in manifest["operations"]), default=0)
            if args.in_place:
                backup_estimate = sum(operation.get("old_size", 0) for operation in manifest["operations"] if operation["type"] in {"patch", "replace", "remove"})
                warn_if_low_disk_space(TEMP_ROOT, backup_estimate + largest_payload, "the in-place recovery backup and patch payload")
                warn_if_low_disk_space(base, largest_temporary, "temporary in-place patch output")
            else:
                base_estimate = sum(info["size"] for info in base_files.values())
                warn_if_low_disk_space(destination.parent, base_estimate + largest_temporary, "the separate patched installation")
                warn_if_low_disk_space(TEMP_ROOT, largest_payload, "temporary patch payload data")

            work = make_work_dir("apply_patch")
            scratch = work / "payload"
            scratch.mkdir()

            if args.in_place:
                check_temporary_paths(base, manifest["operations"])
                backup = work / "backup"
                backup.mkdir()
                print("\n--in-place was specified.\nCreating and verifying a temporary backup before modifying the base...")

                # Write recovery before the potentially long backup. If the process is killed during backup the base is still unchanged, so the next run can safely discard the partial backup.
                keep_work = True
                write_recovery_state(work, make_recovery_state("in_place", base, base, patch, manifest))
                try:
                    existed = backup_in_place(base, backup, manifest["operations"])
                    write_recovery_state(work, make_recovery_state("in_place", base, base, patch, manifest, existed))
                except BaseException:
                    keep_work = False
                    raise

                try:
                    apply_and_verify(base, archive, members, scratch, manifest)
                    keep_work = False
                except BaseException as patch_error:
                    message = "\nPatch application interrupted.\nRolling back changes..." if isinstance(patch_error, KeyboardInterrupt) else f"\nERROR: {patch_error}\nRolling back changes..."
                    print(message, file=sys.stderr)
                    try:
                        restore_in_place(base, backup, manifest["operations"], existed, manifest["old_root_sha256"], manifest["old_file_count"])
                    except BaseException as rollback_error:
                        raise RuntimeError(f"Rollback could not be completed. The persistent recovery backup was kept at:\n{work}\nRun apply_patch.py again with the same base to retry recovery.") from rollback_error
                    keep_work = False
                    print("Rollback completed successfully.\nThe original base installation has been restored.", file=sys.stderr)
                    raise

            else:
                keep_work = True
                write_recovery_state(work, make_recovery_state("separate", base, destination, patch, manifest))
                try:
                    print(f"\nCreating separate installation:\n{destination}\nCopying base installation...")
                    shutil.copytree(base, destination)
                    check_temporary_paths(destination, manifest["operations"])
                    apply_and_verify(destination, archive, members, scratch, manifest)
                    keep_work = False
                except BaseException:
                    print("\nPatch interrupted or failed. Removing the incomplete output installation...\nThe original base was not modified.", file=sys.stderr)
                    if remove_incomplete_output(destination):
                        keep_work = False
                    else:
                        print(f"WARNING: The incomplete output could not be removed completely. Recovery data was kept at:\n{work}", file=sys.stderr)
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

if __name__ == "__main__":
    raise SystemExit(main())
