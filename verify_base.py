#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from common import (
    ENTRY_SCRIPTS,
    ErrorArgumentParser,
    console_title,
    install_termination_handlers,
    load_index,
    operation_activity_lock,
    operation_lock,
    resolve_base_name,
    scan_tree,
    validate_warframe_installation,
)
from update import add_update_arguments, handle_automatic_update, handle_early_update_request

def main() -> int:
    install_termination_handlers()
    argv = sys.argv[1:]
    early_update_result = handle_early_update_request(argv)
    if early_update_result is not None:
        return early_update_result
    parser = ErrorArgumentParser(description="Verify a Steam manifest base against its entry in data/index.json.")
    parser.add_argument("path", type=Path, help="Path to the Steam manifest base")
    parser.add_argument("name", help="Indexed Warframe version, for example U43.5.1")
    add_update_arguments(parser)
    parser.add_version_argument()
    parser.add_help_argument()
    args = parser.parse_args(argv)

    try:
        with operation_activity_lock():
            update_result = handle_automatic_update(args, argv)
            if update_result is not None:
                return update_result

            base = args.path.resolve()

            if not base.is_dir():
                print(f"ERROR: Base directory does not exist: {base}", file=sys.stderr)
                return 1
            if not validate_warframe_installation(base, "Base"):
                return 1

            index = load_index()
            canonical_name = resolve_base_name(index, args.name)
            expected = index[canonical_name]

            print(f'Verifying base "{canonical_name}"...\n' "Calculating installation SHA-256...")

            with operation_lock("installation", base, "operation using this installation"):
                files, actual_hash = scan_tree(base, "Hashing base")

            if actual_hash.lower() != expected["sha256"].lower() or len(files) != expected["file_count"]:
                print(f"ERROR: Base verification failed.\nExpected files: {expected['file_count']:,}\nActual files: {len(files):,}\nExpected SHA-256: {expected['sha256']}\nActual SHA-256: {actual_hash}", file=sys.stderr)
                return 1

            print(f'\n[Verified] Base "{canonical_name}" is valid and unmodified.\nSteam manifest ID: {expected["steam_manifest_id"]}\nFiles: {len(files):,}\nSHA-256: {actual_hash}')
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
    with console_title(ENTRY_SCRIPTS["verify_base.py"]):
        raise SystemExit(main())
