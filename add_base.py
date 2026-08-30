#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from common import (
    ErrorArgumentParser,
    INDEX_FILE,
    install_termination_handlers,
    is_steam_manifest_id,
    load_index,
    operation_lock,
    resolve_base_name,
    scan_tree,
    validate_warframe_installation,
    write_index,
)
from update import add_update_arguments, handle_automatic_update, handle_early_update_request

def _existing_base_conflict(index: dict, name: str, manifest_id: int) -> str | None:
    try:
        existing_name = resolve_base_name(index, name)
    except KeyError:
        existing_name = None

    if existing_name is not None:
        return f'Base "{existing_name}" already exists in the index.'

    for existing_name, entry in index.items():
        if entry["steam_manifest_id"] == manifest_id:
            return f'Steam manifest ID {manifest_id} is already indexed as "{existing_name}".'
    return None

def main() -> int:
    install_termination_handlers()
    argv = sys.argv[1:]
    early_update_result = handle_early_update_request(argv)
    if early_update_result is not None:
        return early_update_result
    parser = ErrorArgumentParser(description="Add a clean, unmodified Steam manifest base to data/index.json.")
    parser.add_argument("path", type=Path, help="Path to the clean Steam manifest base")
    parser.add_argument("name", help="Warframe version, for example U43.5.1")
    parser.add_argument("manifest_id", type=int, help="Steam manifest ID of the base")
    add_update_arguments(parser)
    parser.add_version_argument()
    parser.add_help_argument()
    args = parser.parse_args(argv)

    try:
        update_result = handle_automatic_update(args, argv)
        if update_result is not None:
            return update_result

        base = args.path.resolve()
        name = args.name.strip()
        manifest_id = args.manifest_id

        if not base.is_dir():
            print(f"ERROR: Base directory does not exist: {base}", file=sys.stderr)
            return 1
        if not validate_warframe_installation(base, "Base"):
            return 1

        if not name:
            print("ERROR: Base name cannot be empty.", file=sys.stderr)
            return 1
        if not is_steam_manifest_id(manifest_id):
            print("ERROR: Steam manifest ID must be a valid unsigned 64-bit integer.", file=sys.stderr)
            return 1

        # Reject conflicts that can be determined from the index before doing a potentially very expensive full-tree hash.
        # The same checks are repeated after hashing because another add_base process may update the index meanwhile.
        with operation_lock("index", INDEX_FILE, "base index update"):
            conflict = _existing_base_conflict(load_index(), name, manifest_id)
        if conflict is not None:
            print(f"ERROR: {conflict}\nNo changes were made.", file=sys.stderr)
            return 1

        with operation_lock("installation", base, "operation using this installation"):
            print(f'Hashing base "{name}"...\n' "This may take a while for large installations.")
            files, root_hash = scan_tree(base, "Hashing base")

            # Keep the installation locked until its verified identity is committed to the index.
            with operation_lock("index", INDEX_FILE, "base index update"):
                index = load_index()
                conflict = _existing_base_conflict(index, name, manifest_id)
                if conflict is not None:
                    print(f"ERROR: {conflict}\nNo changes were made.", file=sys.stderr)
                    return 1

                for existing_name, entry in index.items():
                    if entry["sha256"].lower() == root_hash.lower():
                        print(f'ERROR: This exact base is already indexed as "{existing_name}".\nNo changes were made.', file=sys.stderr)
                        return 1

                index[name] = {"steam_manifest_id": manifest_id, "sha256": root_hash, "file_count": len(files)}
                write_index(index)

        print(f'\n[Added] Base "{name}"\nSteam manifest ID: {manifest_id}\nFiles: {len(files):,}\nSHA-256: {root_hash}\nIndex: {INDEX_FILE}')
        return 0
    except KeyboardInterrupt:
        print("\nBase addition cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
