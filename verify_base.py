#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from common import ErrorArgumentParser, load_index, resolve_base_name, scan_tree

def main() -> int:
    parser = ErrorArgumentParser(description="Verify a game base against its entry in index.json.")
    parser.add_argument("path", type=Path, help="Path to the base installation")
    parser.add_argument("name", help="Indexed base name, for example U43.5.1")
    parser.add_help_argument()
    args = parser.parse_args()

    base = args.path.resolve()

    if not base.is_dir():
        print(f"ERROR: Base directory does not exist: {base}", file=sys.stderr)
        return 1

    try:
        index = load_index()
        canonical_name = resolve_base_name(index, args.name)
        expected = index[canonical_name]

        print(f'Verifying base "{canonical_name}"...\n' "Calculating installation SHA-256...")

        files, actual_hash = scan_tree(base)

        if (actual_hash.lower() != expected["sha256"].lower() or len(files) != expected["file_count"]):
            print(f"ERROR: Base verification failed.\n" f"Expected files: {expected['file_count']:,}\n" f"Actual files: {len(files):,}\n" f"Expected SHA-256: {expected['sha256']}\n" f"Actual SHA-256: {actual_hash}", file=sys.stderr)
            return 1

        print(f'\n[Verified] Base "{canonical_name}" is valid and unmodified.\n' f"Files: {len(files):,}\n" f"SHA-256: {actual_hash}")
        return 0

    except KeyError:
        print(f'ERROR: Base "{args.name}" is not present in index.json.', file=sys.stderr)
        return 1

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
