#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import time
import zipfile
from pathlib import Path

from common import (
    ErrorArgumentParser,
    SingleUseStoreAction,
    TEMP_ROOT,
    cleanup_work_dir,
    display_relative_path,
    format_duration,
    install_termination_handlers,
    is_within,
    load_index,
    make_work_dir,
    parse_json,
    process_is_running,
    resolve_base_name,
    resolve_patch_output,
    run_child,
    scan_tree,
)

TOOL_DIR = Path(__file__).resolve().parent
HDIFFZ = TOOL_DIR / "tools" / "hdiffz.exe"
PATCH_VERSION = 1
MAKE_SESSION_FILE = "session.json"
MAKE_SESSION_GRACE_SECONDS = 10

# The regular presets map to one HDiffPatch strategy. "maximum" uses the same common compression as "higher", but tries several matching strategies below and keeps the smallest delta.
COMPRESSION_PRESETS = {
    "normal": {"memory": ["-m-3"], "stream": ["-s-64k"], "common": ["-SD", "-d", "-f", "-p-1", "-c-lzma2-9-64m"]},
    "high": {"memory": ["-m-2", "-cache"], "stream": ["-s-16k"], "common": ["-SD", "-d", "-f", "-p-1", "-c-lzma2-9-256m"]},
    "higher": {"memory": ["-m-1", "-cache", "-block-0"], "stream": ["-s-4k"], "common": ["-SD", "-d", "-f", "-p-1", "-c-lzma2-9-1024m"]},
    "maximum": {"memory": ["-m-1", "-cache", "-block-0"], "stream": ["-s-4k"], "common": ["-SD", "-d", "-f", "-p-1", "-c-lzma2-9-1024m"]},
}

# HDiffPatch matching has no single setting that always gives the smallest result. "maximum" therefore tries several candidates per modified file; the "higher" strategy is included as a known-good candidate.
MAXIMUM_MEMORY_CANDIDATES = [["-m-0", "-cache", "-block-0"], ["-m-1", "-cache", "-block-0"]]
MAXIMUM_STREAM_CANDIDATES = [["-s-1k"], ["-s-2k"], ["-s-4k"], ["-s-8k"], ["-s-16k"]]

# Aggressive -m matching can require enormous allocations on large game files. High/higher/maximum switch to streaming at 1 GiB; normal intentionally keeps its proven -m-3 behavior.
STREAM_MODE_THRESHOLD = 1024 * 1024 * 1024

def temporary_patch_path(output: Path) -> Path:
    return output.with_name(output.name + ".tmp")

def uses_stream(old: Path, new: Path, compression: str) -> bool:
    return compression != "normal" and max(old.stat().st_size, new.stat().st_size) >= STREAM_MODE_THRESHOLD

def write_make_session(work: Path, output: Path) -> None:
    # Creation is intentionally not resumable. This marker only lets a later run distinguish abandoned work from another make_patch process that is still active.
    session = work / MAKE_SESSION_FILE
    temporary = session.with_name(session.name + ".tmp")
    data = {"pid": os.getpid(), "output": str(output)}

    with temporary.open("w", encoding="utf-8", newline="\n") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, session)

def cleanup_stale_make_patch_work(output: Path) -> None:
    # Reusing old HDiff candidates would require proving every source hash and setting still matches, so interrupted creation data is discarded instead.
    active_for_output = False

    if TEMP_ROOT.is_dir():
        for work in sorted(TEMP_ROOT.glob("make_patch_*")):
            session = work / MAKE_SESSION_FILE
            session_output = None
            pid = None

            if session.is_file():
                try:
                    state = parse_json(session.read_text(encoding="utf-8"))
                    pid = state.get("pid") if isinstance(state, dict) else None
                    raw_output = state.get("output") if isinstance(state, dict) else None
                    if isinstance(raw_output, str):
                        session_output = Path(raw_output).resolve()
                except Exception:
                    pass

            if isinstance(pid, int) and process_is_running(pid):
                active_for_output |= session_output == output
                continue

            if not session.is_file():
                # Give a just-created folder a moment to receive its atomically written session marker before considering it stale.
                try:
                    if time.time() - work.stat().st_mtime < MAKE_SESSION_GRACE_SECONDS:
                        continue
                except OSError:
                    continue

            if session_output is not None:
                try:
                    temporary_patch_path(session_output).unlink(missing_ok=True)
                except OSError:
                    pass
            cleanup_work_dir(work)

    if active_for_output:
        raise RuntimeError(f"Another make_patch operation appears to still be creating this output:\n{output}")

    partial = temporary_patch_path(output)
    if partial.exists():
        print("Removing leftover temporary patch from an interrupted creation...")
        partial.unlink()

def payload_id(relative: str) -> str:
    return hashlib.sha256(relative.encode("utf-8")).hexdigest()

def run_hdiff_command(old: Path, new: Path, output: Path, mode_options: list[str], common_options: list[str]) -> None:
    result = run_child([str(HDIFFZ), *mode_options, *common_options, str(old), str(new), str(output)])
    if result != 0:
        raise RuntimeError(f"hdiffz failed with exit code {result}: {new}")

def run_hdiff(old: Path, new: Path, output: Path, compression: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    preset = COMPRESSION_PRESETS[compression]
    stream = uses_stream(old, new, compression)

    if compression != "maximum":
        run_hdiff_command(old, new, output, preset["stream" if stream else "memory"], preset["common"])
        return

    # Maximum is a best-of search. Only the winning candidate remains in the patch, so this extra work affects creation time but not application time.
    candidates = MAXIMUM_STREAM_CANDIDATES if stream else MAXIMUM_MEMORY_CANDIDATES
    best_path: Path | None = None
    best_size: int | None = None
    best_options: list[str] | None = None

    try:
        for index, mode_options in enumerate(candidates, start=1):
            candidate = output.with_name(f"{output.name}.candidate-{index}")
            candidate.unlink(missing_ok=True)
            print(f" [Maximum] Candidate {index}/{len(candidates)}: {' '.join(mode_options)}")
            run_hdiff_command(old, new, candidate, mode_options, preset["common"])
            candidate_size = candidate.stat().st_size

            if best_size is None or candidate_size < best_size:
                if best_path is not None:
                    best_path.unlink()
                best_path, best_size, best_options = candidate, candidate_size, mode_options
            else:
                candidate.unlink()

        if best_path is None or best_size is None or best_options is None:
            raise RuntimeError(f"No maximum-compression candidate was created: {new}")

        best_path.replace(output)
        print(f" [Maximum] Selected: {' '.join(best_options)} ({best_size:,} bytes)")
    except BaseException:
        for candidate in output.parent.glob(f"{output.name}.candidate-*"):
            candidate.unlink(missing_ok=True)
        raise

def create_patch_archive(work: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"Patch output already exists: {output}")

    temporary = temporary_patch_path(output)
    temporary.unlink(missing_ok=True)

    try:
        # Only patch-format files belong in the archive. In particular, session.json is local recovery metadata and must never leak into a distributed patch.
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            archive.write(work / "manifest.json", "manifest.json")
            for folder in ("diffs", "files"):
                for path in sorted((work / folder).rglob("*")):
                    if path.is_file():
                        archive.write(path, path.relative_to(work).as_posix())

        if output.exists():
            raise FileExistsError(f"Patch output appeared while the patch was being created: {output}")

        # Publish only after the complete archive is written; an interruption before this point can leave only the disposable .tmp file.
        temporary.replace(output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise

def main() -> int:
    install_termination_handlers()
    parser = ErrorArgumentParser(
        description="Create one self-contained Ninja Patch (Diff Patch) from a clean indexed base.",
        epilog="Compression presets: normal is the default. High and higher trade more time and memory for potentially smaller patches. Maximum tries several matching strategies per modified file and can take much longer.",
    )
    parser.add_argument("base", type=Path, help="Clean indexed base installation")
    parser.add_argument("new", type=Path, help="Newer installation")
    parser.add_argument("output", type=Path, help="Patch filename or output path; .patch is appended automatically. A bare filename is saved in the tool's output folder.")
    parser.add_argument("-b", "--base-name", metavar="NAME", required=True, action=SingleUseStoreAction, help="Base name from index.json, for example U43.5.1")
    parser.add_argument("-c", "--compression", metavar="PRESET", choices=COMPRESSION_PRESETS, default="normal", action=SingleUseStoreAction, help="Compression preset (default: normal): normal, high, higher, maximum")
    parser.add_help_argument()
    args = parser.parse_args()

    base = args.base.resolve()
    new = args.new.resolve()
    output = resolve_patch_output(args.output)

    if not base.is_dir():
        print(f"ERROR: Base directory does not exist: {base}", file=sys.stderr)
        return 1
    if not new.is_dir():
        print(f"ERROR: New directory does not exist: {new}", file=sys.stderr)
        return 1
    if base == new:
        print("ERROR: Base and new directories are the same.", file=sys.stderr)
        return 1
    if is_within(output, base) or is_within(output, new):
        print(f"ERROR: Patch output must not be inside the base or new installation:\n{output}", file=sys.stderr)
        return 1
    if output.exists():
        print(f"ERROR: Patch output already exists:\n{output}\nChoose a different output name or remove the existing patch first.\nNo patch was generated.", file=sys.stderr)
        return 1
    if not HDIFFZ.is_file():
        print(f"ERROR: hdiffz.exe was not found in the tools folder:\n{HDIFFZ}", file=sys.stderr)
        return 1

    try:
        cleanup_stale_make_patch_work(output)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    work = None
    started = time.perf_counter()

    try:
        index = load_index()
        canonical_name = resolve_base_name(index, args.base_name)
        indexed_base = index[canonical_name]

        print(f'Verifying base "{canonical_name}" before patch creation...\nScanning and hashing base files...')
        old_files, old_root_hash = scan_tree(base)

        if old_root_hash.lower() != indexed_base["sha256"].lower() or len(old_files) != indexed_base["file_count"]:
            raise RuntimeError(
                f"Base integrity verification failed.\nExpected files: {indexed_base['file_count']:,}\nActual files:   {len(old_files):,}\n"
                f"Expected SHA-256: {indexed_base['sha256']}\nActual SHA-256:   {old_root_hash}\nPatch creation was aborted."
            )

        print(f'[Verified] Base "{canonical_name}" is unmodified.\nCompression: {args.compression}\nScanning and hashing the new installation...')
        new_files, new_root_hash = scan_tree(new)
        old_names, new_names = set(old_files), set(new_files)
        common_names = old_names & new_names
        added = sorted(new_names - old_names)
        removed = sorted(old_names - new_names)
        modified = sorted(relative for relative in common_names if old_files[relative]["sha256"] != new_files[relative]["sha256"])

        print(f"\nUnchanged: {len(common_names) - len(modified):,}\nModified: {len(modified):,}\nAdded: {len(added):,}\nRemoved: {len(removed):,}\n\nCreating patch payload...")

        work = make_work_dir("make_patch")
        write_make_session(work, output)
        diffs_dir, files_dir = work / "diffs", work / "files"
        diffs_dir.mkdir()
        files_dir.mkdir()
        operations = []

        for relative in modified:
            old_info, new_info = old_files[relative], new_files[relative]
            item_id = payload_id(relative)
            diff_path = diffs_dir / f"{item_id}.hdiff"
            mode = "stream" if uses_stream(old_info["path"], new_info["path"], args.compression) else "memory"
            print(f"[Diffing] {display_relative_path(relative)} ({mode} mode)")
            run_hdiff(old_info["path"], new_info["path"], diff_path, args.compression)

            if diff_path.stat().st_size >= new_info["size"]:
                # A delta that is no smaller than the new file is pointless; store the complete replacement instead.
                diff_path.unlink()
                payload_path = files_dir / f"{item_id}.bin"
                shutil.copy2(new_info["path"], payload_path)
                operations.append({"type": "replace", "path": relative, "payload": f"files/{payload_path.name}", "old_size": old_info["size"], "old_sha256": old_info["sha256"],
                    "new_size": new_info["size"], "new_sha256": new_info["sha256"]})
                print(f"[Stored full file] {display_relative_path(relative)}")
            else:
                operations.append({"type": "patch", "path": relative, "payload": f"diffs/{diff_path.name}", "old_size": old_info["size"], "old_sha256": old_info["sha256"], "new_size": new_info["size"], "new_sha256": new_info["sha256"]})

        for relative in added:
            info = new_files[relative]
            payload_path = files_dir / f"{payload_id(relative)}.bin"
            shutil.copy2(info["path"], payload_path)
            operations.append({"type": "add", "path": relative, "payload": f"files/{payload_path.name}", "new_size": info["size"], "new_sha256": info["sha256"]})
            print(f"[Added] {display_relative_path(relative)}")

        for relative in removed:
            info = old_files[relative]
            operations.append({"type": "remove", "path": relative, "old_size": info["size"], "old_sha256": info["sha256"]})
            print(f"[Removed] {display_relative_path(relative)}")

        manifest = {"version": PATCH_VERSION, "base": canonical_name, "old_root_sha256": old_root_hash, "new_root_sha256": new_root_hash, "old_file_count": len(old_files), "new_file_count": len(new_files), "operations": operations}
        (work / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        print(f"\nCreating single patch file:\n{output}")
        create_patch_archive(work, output)
        duration = format_duration(time.perf_counter() - started)
        print(f"\n[Created] Patch completed successfully.\nBase: {canonical_name}\nDuration: {duration}\nPatch size: {output.stat().st_size:,} bytes")
        return 0

    except KeyError:
        print(f'ERROR: Base "{args.base_name}" is not present in index.json.', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nPatch creation cancelled.\nCleaning up temporary patch data...", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if work is not None:
            cleanup_work_dir(work)

if __name__ == "__main__":
    raise SystemExit(main())
