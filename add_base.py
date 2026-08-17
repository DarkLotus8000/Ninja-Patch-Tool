#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from common import ErrorArgumentParser, load_index, resolve_base_name, scan_tree, write_index

def main() -> int:
    parser = ErrorArgumentParser(description="Add a clean, unmodified game base to index.json.")
    parser.add_argument("path", type=Path, help="Path to the clean base installation")
    parser.add_argument("name", help="Base name, for example U43.5.1")
    parser.add_help_argument()
    args = parser.parse_args()

    base = args.path.resolve()
    name = args.name.strip()

    if not base.is_dir():
        print(f"ERROR: Base directory does not exist: {base}", file=sys.stderr)
        return 1

    if not name:
        print("ERROR: Base name cannot be empty.", file=sys.stderr)
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

        print(f'Hashing base "{name}"...\n' "This may take a while for large installations.")

        files, root_hash = scan_tree(base)

        for existing_name, entry in index.items():
            if entry["sha256"].lower() == root_hash.lower():
                print(f'ERROR: This exact base is already indexed as ' f'"{existing_name}".\n' "No changes were made.", file=sys.stderr)
                return 1

        index[name] = {"sha256": root_hash, "file_count": len(files)}

        write_index(index)

        print(f'\n[Added] Base "{name}"\n' f"Files: {len(files):,}\n" f"SHA-256: {root_hash}\n" f"Index: {Path(__file__).resolve().parent / 'index.json'}")
        return 0

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
