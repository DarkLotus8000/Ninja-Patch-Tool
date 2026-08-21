#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from common import (
    ErrorArgumentParser,
    is_steam_manifest_id,
    load_index,
    resolve_base_name,
    scan_tree,
    validate_warframe_installation,
    write_index,
)

def main() -> int:
    parser = ErrorArgumentParser(description="Add a clean, unmodified Steam manifest base to index.json.")
    parser.add_argument("path", type=Path, help="Path to the clean Steam manifest base")
    parser.add_argument("name", help="Warframe version, for example U43.5.1")
    parser.add_argument("manifest_id", type=int, help="Steam manifest ID of the base")
    parser.add_help_argument()
    args = parser.parse_args()

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

    try:
        index = load_index()

        try:
            existing_name = resolve_base_name(index, name)
        except KeyError:
            existing_name = None

        if existing_name is not None:
            print(f'ERROR: Base "{existing_name}" already exists in the index.\n' "No changes were made.", file=sys.stderr)
            return 1

        for existing_name, entry in index.items():
            if entry["steam_manifest_id"] == manifest_id:
                print(
                    f'ERROR: Steam manifest ID {manifest_id} is already indexed as "{existing_name}".\n'
                    "No changes were made.",
                    file=sys.stderr,
                )
                return 1

        print(f'Hashing base "{name}"...\n' "This may take a while for large installations.")

        files, root_hash = scan_tree(base)

        for existing_name, entry in index.items():
            if entry["sha256"].lower() == root_hash.lower():
                print(f'ERROR: This exact base is already indexed as ' f'"{existing_name}".\n' "No changes were made.", file=sys.stderr)
                return 1

        index[name] = {"steam_manifest_id": manifest_id, "sha256": root_hash, "file_count": len(files)}

        write_index(index)

        print(
            f'\n[Added] Base "{name}"\n'
            f"Steam manifest ID: {manifest_id}\n"
            f"Files: {len(files):,}\n"
            f"SHA-256: {root_hash}\n"
            f"Index: {Path(__file__).resolve().parent / 'index.json'}"
        )
        return 0

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
