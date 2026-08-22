#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from common import (
    ErrorArgumentParser,
    install_termination_handlers,
    load_index,
    operation_lock,
    resolve_base_name,
    scan_tree,
    validate_warframe_installation,
)

def main() -> int:
    install_termination_handlers()
    parser = ErrorArgumentParser(description="Verify a Steam manifest base against its entry in data/index.json.")
    parser.add_argument("path", type=Path, help="Path to the Steam manifest base")
    parser.add_argument("name", help="Indexed Warframe version, for example U43.5.1")
    parser.add_version_argument()
    parser.add_help_argument()
    args = parser.parse_args()

    base = args.path.resolve()

    if not base.is_dir():
        print(f"ERROR: Base directory does not exist: {base}", file=sys.stderr)
        return 1
    if not validate_warframe_installation(base, "Base"):
        return 1

    try:
        index = load_index()
        canonical_name = resolve_base_name(index, args.name)
        expected = index[canonical_name]

        print(f'Verifying base "{canonical_name}"...\nCalculating installation SHA-256...')
        with operation_lock("installation", base, "operation using this installation"):
            files, actual_hash = scan_tree(base)

        if actual_hash.lower() != expected["sha256"].lower() or len(files) != expected["file_count"]:
            print(
                "ERROR: Base verification failed.\n"
                f"Expected files: {expected['file_count']:,}\n"
                f"Actual files: {len(files):,}\n"
                f"Expected SHA-256: {expected['sha256']}\n"
                f"Actual SHA-256: {actual_hash}",
                file=sys.stderr,
            )
            return 1

        print(
            f'\n[Verified] Base "{canonical_name}" is valid and unmodified.\n'
            f"Steam manifest ID: {expected['steam_manifest_id']}\n"
            f"Files: {len(files):,}\n"
            f"SHA-256: {actual_hash}"
        )
        return 0
    except KeyError:
        print(f'ERROR: Base "{args.name}" is not present in data/index.json.', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nBase verification cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
