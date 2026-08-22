#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import zipfile
from contextlib import ExitStack
from pathlib import Path

from common import (
    ByteProgress,
    ErrorArgumentParser,
    SingleUseStoreAction,
    DATA_DIR,
    TEMP_ROOT,
    cleanup_work_dir,
    display_relative_path,
    format_duration,
    install_termination_handlers,
    is_within,
    load_index,
    make_work_dir,
    operation_lock,
    parse_json,
    process_identity,
    process_matches_identity,
    resolve_base_name,
    resolve_patch_output,
    run_child,
    scan_tree,
    validate_warframe_installation,
    verify_scanned_file,
    verify_scanned_tree,
    warn_if_low_disk_space_groups,
)

HDIFFZ = DATA_DIR / "hdiffz.exe"
PATCH_VERSION = 2
MAKE_SESSION_FILE = "session.json"
MAKE_SESSION_GRACE_SECONDS = 10

# The regular presets map to one HDiffPatch strategy. "maximum" uses the same common compression as "higher",
# but tries several matching strategies below and keeps the smallest delta.
COMPRESSION_PRESETS = {
    "normal": {"memory": ["-m-3"], "stream": ["-s-64k"], "common": ["-SD", "-d", "-f", "-p-1", "-c-lzma2-9-64m"]},
    "high": {"memory": ["-m-2", "-cache"], "stream": ["-s-16k"], "common": ["-SD", "-d", "-f", "-p-1", "-c-lzma2-9-256m"]},
    "higher": {"memory": ["-m-1", "-cache", "-block-0"], "stream": ["-s-4k"], "common": ["-SD", "-d", "-f", "-p-1", "-c-lzma2-9-1024m"]},
    "maximum": {"memory": ["-m-1", "-cache", "-block-0"], "stream": ["-s-4k"], "common": ["-SD", "-d", "-f", "-p-1", "-c-lzma2-9-1024m"]},
}

# HDiffPatch matching has no single setting that always gives the smallest result. "maximum" therefore tries several
# candidates per modified file; the "higher" strategy is included as a known-good candidate.
MAXIMUM_MEMORY_CANDIDATES = [["-m-0", "-cache", "-block-0"], ["-m-1", "-cache", "-block-0"]]
MAXIMUM_STREAM_CANDIDATES = [["-s-1k"], ["-s-2k"], ["-s-4k"], ["-s-8k"], ["-s-16k"]]

# Aggressive -m matching can require enormous allocations on large game files. High/higher/maximum switch to streaming
# at 1 GiB; normal intentionally keeps its proven -m-3 behavior.
STREAM_MODE_THRESHOLD = 1024 * 1024 * 1024

# The outer .patch ZIP container does not recompress .hdiff payloads because HDiffPatch already compresses them with LZMA2.
# Full-file payloads use progressively stronger ZIP compression with higher presets.
FULL_FILE_ZIP_COMPRESSION = {
    "normal": (zipfile.ZIP_STORED, None),
    "high": (zipfile.ZIP_DEFLATED, 9),
    "higher": (zipfile.ZIP_LZMA, None),
    "maximum": (zipfile.ZIP_LZMA, None),
}

def temporary_patch_path(output: Path) -> Path:
    return output.with_name(output.name + ".tmp")

def publish_patch_archive(temporary: Path, output: Path) -> None:
    try:
        if os.name == "nt":
            # Unlike os.replace(), Windows os.rename() fails if the destination already exists, so another process
            # cannot have its file overwritten during publication.
            temporary.rename(output)
        else:
            # Keep the same no-overwrite guarantee on non-Windows systems used by the test suite, where os.rename()
            # may replace an existing destination.
            os.link(temporary, output)
            temporary.unlink()
    except FileExistsError:
        raise FileExistsError(f"Patch output appeared while the patch was being created: {output}") from None

def uses_stream(old: Path, new: Path, compression: str) -> bool:
    return compression != "normal" and max(old.stat().st_size, new.stat().st_size) >= STREAM_MODE_THRESHOLD

def write_make_session(work: Path, output: Path) -> None:
    # Creation is intentionally not resumable. This marker only lets a later run distinguish abandoned work from
    # another make_patch process that is still active.
    session = work / MAKE_SESSION_FILE
    temporary = session.with_name(session.name + ".tmp")
    data = {"pid": os.getpid(), "process_identity": process_identity(os.getpid()), "output": str(output)}

    with temporary.open("w", encoding="utf-8", newline="\n") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, session)

def cleanup_stale_make_patch_work(output: Path) -> None:
    # Reusing old HDiff candidates would require proving every source hash and setting still matches, so interrupted
    # creation data is discarded instead.
    active_for_output = False

    if TEMP_ROOT.is_dir():
        for work in sorted(TEMP_ROOT.glob("make_patch_*")):
            session = work / MAKE_SESSION_FILE
            session_output = None
            pid = None
            state = None

            if session.is_file():
                try:
                    state = parse_json(session.read_text(encoding="utf-8"))
                    if isinstance(state, dict):
                        pid = state.get("pid")
                        raw_output = state.get("output")
                    else:
                        raw_output = None
                    if isinstance(raw_output, str):
                        session_output = Path(raw_output).resolve()
                except Exception:
                    pass

            if isinstance(pid, int) and process_matches_identity(pid, state.get("process_identity") if isinstance(state, dict) else None):
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
        raise RuntimeError(
            "Temporary patch path already exists and was not removed because Ninja Patch Tool cannot prove that it owns the file:\n"
            f"{partial}"
        )

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
        if stream:
            mode_options = preset["stream"]
        else:
            mode_options = preset["memory"]
        run_hdiff_command(old, new, output, mode_options, preset["common"])
        return

    # Maximum is a best-of search. Individual strategies may fail because of memory or HDiffPatch limits; keep trying
    # and fail only if every candidate fails.
    if stream:
        candidates = MAXIMUM_STREAM_CANDIDATES
    else:
        candidates = MAXIMUM_MEMORY_CANDIDATES
    best_path: Path | None = None
    best_size: int | None = None
    best_options: list[str] | None = None
    failures: list[str] = []

    try:
        for index, mode_options in enumerate(candidates, start=1):
            candidate = output.with_name(f"{output.name}.candidate-{index}")
            candidate.unlink(missing_ok=True)
            print(f" [Maximum] Candidate {index}/{len(candidates)}: {' '.join(mode_options)}")
            try:
                run_hdiff_command(old, new, candidate, mode_options, preset["common"])
                candidate_size = candidate.stat().st_size
            except Exception as exc:
                candidate.unlink(missing_ok=True)
                failures.append(f"{' '.join(mode_options)}: {exc}")
                print(f" [Maximum] Candidate failed: {exc}", file=sys.stderr)
                continue

            if best_size is None or candidate_size < best_size:
                if best_path is not None:
                    best_path.unlink()
                best_path, best_size, best_options = candidate, candidate_size, mode_options
            else:
                candidate.unlink()

        if best_path is None or best_size is None or best_options is None:
            details = "\n".join(f"- {failure}" for failure in failures)
            message = f"All maximum-compression candidates failed for: {new}"
            if details:
                message += f"\n{details}"
            raise RuntimeError(message)

        best_path.replace(output)
        print(f" [Maximum] Selected: {' '.join(best_options)} ({best_size:,} bytes)")
    except BaseException:
        for candidate in output.parent.glob(f"{output.name}.candidate-*"):
            candidate.unlink(missing_ok=True)
        raise

def reproducible_zip_info(name: str, compression: int, compresslevel: int | None = None) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = compression
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info._compresslevel = compresslevel
    return info

def write_reproducible_member(
    archive: zipfile.ZipFile,
    source: Path,
    name: str,
    compression: int,
    compresslevel: int | None = None,
    progress: ByteProgress | None = None,
) -> None:
    info = reproducible_zip_info(name, compression, compresslevel)
    with source.open("rb") as input_file, archive.open(info, "w", force_zip64=True) as output_file:
        while chunk := input_file.read(8 * 1024 * 1024):
            output_file.write(chunk)
            if progress is not None:
                progress.update(len(chunk))

def measure_full_file_compressed_size(file_info: dict, compression: str, work: Path, item_id: str) -> int | None:
    compress_type, compresslevel = FULL_FILE_ZIP_COMPRESSION[compression]
    candidate = work / f"full_candidate_{item_id}.zip"
    candidate.unlink(missing_ok=True)
    try:
        verify_scanned_file(file_info)
        with zipfile.ZipFile(candidate, "x", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            write_reproducible_member(archive, file_info["path"], "candidate.bin", compress_type, compresslevel)
        verify_scanned_file(file_info)
        with zipfile.ZipFile(candidate, "r") as archive:
            return archive.getinfo("candidate.bin").compress_size
    except Exception as exc:
        print(f"WARNING: Could not test compressed full-file candidate for {file_info['path']}: {exc}", file=sys.stderr)
        return None
    finally:
        candidate.unlink(missing_ok=True)

def should_store_full_file(diff_path: Path, new_info: dict, compression: str, work: Path, item_id: str) -> bool:
    diff_size = diff_path.stat().st_size
    if diff_size >= new_info["size"]:
        return True
    if compression not in {"higher", "maximum"}:
        return False
    compressed_size = measure_full_file_compressed_size(new_info, compression, work, item_id)
    return compressed_size is not None and compressed_size < diff_size

def create_patch_archive(work: Path, output: Path, compression: str, full_file_sources: dict[str, dict]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"Patch output already exists: {output}")

    temporary = temporary_patch_path(output)
    if temporary.exists():
        raise FileExistsError(f"Temporary patch path already exists: {temporary}")

    try:
        try:
            full_file_compression, full_file_compresslevel = FULL_FILE_ZIP_COMPRESSION[compression]
        except KeyError:
            raise ValueError(f"Unknown compression preset: {compression}") from None

        full_progress = ByteProgress("Archiving full-file payloads", sum(info["size"] for info in full_file_sources.values())) if full_file_sources else None
        with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            write_reproducible_member(archive, work / "manifest.json", "manifest.json", zipfile.ZIP_DEFLATED, 9)
            for path in sorted((work / "diffs").rglob("*")):
                if path.is_file():
                    write_reproducible_member(archive, path, path.relative_to(work).as_posix(), zipfile.ZIP_STORED)
            for payload in sorted(full_file_sources):
                file_info = full_file_sources[payload]
                verify_scanned_file(file_info)
                write_reproducible_member(archive, file_info["path"], payload, full_file_compression, full_file_compresslevel, full_progress)
                verify_scanned_file(file_info)
        if full_progress is not None:
            full_progress.finish()

        if output.exists():
            raise FileExistsError(f"Patch output appeared while the patch was being created: {output}")
        publish_patch_archive(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise

def main() -> int:
    install_termination_handlers()
    parser = ErrorArgumentParser(description="Create one self-contained Ninja Patch (Diff Patch) from a clean indexed Steam manifest base.")
    parser.add_argument("base", type=Path, help="Clean indexed Steam manifest base")
    parser.add_argument("new", type=Path, help="Newer installation")
    parser.add_argument(
        "output",
        type=Path,
        help="Patch filename or output path; .patch is appended automatically. A bare filename is saved in the tool's output folder.",
    )
    parser.add_argument("base_name", help="Base name from data/index.json, for example U43.5.1")
    parser.add_argument(
        "-c",
        "--compression",
        metavar="PRESET",
        choices=COMPRESSION_PRESETS,
        default="normal",
        action=SingleUseStoreAction,
        help="Compression preset (default: normal): normal, high, higher, maximum",
    )
    parser.add_version_argument()
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
    if not validate_warframe_installation(base, "Base"):
        return 1
    if not validate_warframe_installation(new, "New"):
        return 1
    if base == new:
        print("ERROR: Base and new directories are the same.", file=sys.stderr)
        return 1
    if is_within(output, base) or is_within(output, new):
        print(f"ERROR: Patch output must not be inside the base or new installation:\n{output}", file=sys.stderr)
        return 1
    if not HDIFFZ.is_file():
        print(f"ERROR: hdiffz.exe was not found in the data folder:\n{HDIFFZ}", file=sys.stderr)
        return 1

    work = None
    locks = ExitStack()
    started = time.perf_counter()

    try:
        locks.enter_context(operation_lock("patch_output", output, "patch creation using this output"))
        for installation in sorted((base, new), key=lambda path: str(path).casefold()):
            locks.enter_context(operation_lock("installation", installation, "operation using this installation"))

        cleanup_stale_make_patch_work(output)
        if output.exists():
            raise FileExistsError(
                f"Patch output already exists:\n{output}\n"
                "Choose a different output name or remove the existing patch first.\n"
                "No patch was generated."
            )

        index = load_index()
        canonical_name = resolve_base_name(index, args.base_name)
        indexed_base = index[canonical_name]

        print(f'Verifying base "{canonical_name}" before patch creation...\nScanning and hashing base files...')
        old_files, old_root_hash = scan_tree(base, "Hashing base")

        if old_root_hash.lower() != indexed_base["sha256"].lower() or len(old_files) != indexed_base["file_count"]:
            raise RuntimeError(
                f"Base integrity verification failed.\nExpected files: {indexed_base['file_count']:,}\nActual files:   {len(old_files):,}\n"
                f"Expected SHA-256: {indexed_base['sha256']}\nActual SHA-256:   {old_root_hash}\nPatch creation was aborted."
            )

        print(f'[Verified] Base "{canonical_name}" is unmodified.\nCompression: {args.compression}\nScanning and hashing the new installation...')
        new_files, new_root_hash = scan_tree(new, "Hashing new installation")
        old_names, new_names = set(old_files), set(new_files)
        common_names = old_names & new_names
        added = sorted(new_names - old_names)
        removed = sorted(old_names - new_names)
        modified = sorted(
            relative for relative in common_names if old_files[relative]["sha256"] != new_files[relative]["sha256"]
        )

        print(
            f"\nUnchanged: {len(common_names) - len(modified):,}\n"
            f"Modified: {len(modified):,}\n"
            f"Added: {len(added):,}\n"
            f"Removed: {len(removed):,}\n\n"
            "Creating patch payload..."
        )

        final_payload_estimate = sum(new_files[relative]["size"] for relative in modified + added)
        temporary_payload_estimate = sum(new_files[relative]["size"] for relative in modified)
        largest_modified = max((new_files[relative]["size"] for relative in modified), default=0)
        candidate_overhead = largest_modified * (2 if args.compression == "maximum" else 1)
        warn_if_low_disk_space_groups([
            (TEMP_ROOT, temporary_payload_estimate + candidate_overhead, "temporary patch creation data"),
            (output.parent, final_payload_estimate, "the final patch archive"),
        ])

        work = make_work_dir("make_patch")
        write_make_session(work, output)
        diffs_dir = work / "diffs"
        diffs_dir.mkdir()
        operations = []
        full_file_sources: dict[str, dict] = {}

        for relative in modified:
            old_info, new_info = old_files[relative], new_files[relative]
            item_id = payload_id(relative)
            diff_path = diffs_dir / f"{item_id}.hdiff"
            if uses_stream(old_info["path"], new_info["path"], args.compression):
                mode = "stream"
            else:
                mode = "memory"
            print(f"[Diffing] {display_relative_path(relative)} ({mode} mode)")
            verify_scanned_file(old_info)
            verify_scanned_file(new_info)
            run_hdiff(old_info["path"], new_info["path"], diff_path, args.compression)
            verify_scanned_file(old_info)
            verify_scanned_file(new_info)

            if should_store_full_file(diff_path, new_info, args.compression, work, item_id):
                diff_path.unlink()
                payload = f"files/{item_id}.bin"
                full_file_sources[payload] = new_info
                operations.append({
                    "type": "replace",
                    "path": relative,
                    "payload": payload,
                    "old_size": old_info["size"],
                    "old_sha256": old_info["sha256"],
                    "new_size": new_info["size"],
                    "new_sha256": new_info["sha256"],
                })
                print(f"[Stored full file] {display_relative_path(relative)}")
            else:
                operations.append({
                    "type": "patch",
                    "path": relative,
                    "payload": f"diffs/{diff_path.name}",
                    "old_size": old_info["size"],
                    "old_sha256": old_info["sha256"],
                    "new_size": new_info["size"],
                    "new_sha256": new_info["sha256"],
                })

        for relative in added:
            info = new_files[relative]
            payload = f"files/{payload_id(relative)}.bin"
            full_file_sources[payload] = info
            operations.append({
                "type": "add",
                "path": relative,
                "payload": payload,
                "new_size": info["size"],
                "new_sha256": info["sha256"],
            })
            print(f"[Added] {display_relative_path(relative)}")

        for relative in removed:
            info = old_files[relative]
            operations.append({
                "type": "remove",
                "path": relative,
                "old_size": info["size"],
                "old_sha256": info["sha256"],
            })
            print(f"[Removed] {display_relative_path(relative)}")

        verify_scanned_tree(base, old_files)
        verify_scanned_tree(new, new_files)

        manifest = {
            "version": PATCH_VERSION,
            "base": canonical_name,
            "base_steam_manifest_id": indexed_base["steam_manifest_id"],
            "old_root_sha256": old_root_hash,
            "new_root_sha256": new_root_hash,
            "old_file_count": len(old_files),
            "new_file_count": len(new_files),
            "operations": operations,
        }
        (work / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        print(f"\nCreating single patch file:\n{output}")
        create_patch_archive(work, output, args.compression, full_file_sources)
        try:
            verify_scanned_tree(base, old_files)
            verify_scanned_tree(new, new_files)
        except BaseException:
            output.unlink(missing_ok=True)
            raise
        duration = format_duration(time.perf_counter() - started)
        print(
            "\n[Created] Patch completed successfully.\n"
            f"Base: {canonical_name}\n"
            f"Steam manifest ID: {indexed_base['steam_manifest_id']}\n"
            f"Duration: {duration}\n"
            f"Patch size: {output.stat().st_size:,} bytes"
        )
        return 0

    except KeyError:
        print(f'ERROR: Base "{args.base_name}" is not present in data/index.json.', file=sys.stderr)
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
        locks.close()

if __name__ == "__main__":
    raise SystemExit(main())
