# Run from the project root with: py -m unittest discover -s tests
from __future__ import annotations

import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import add_base
import apply_patch
import build_release
import common
import make_patch
import update
import updater
import verify_base

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def make_warframe_root(root: Path) -> None:
    (root / "Cache.Windows").mkdir(parents=True, exist_ok=True)
    (root / "Tools").mkdir(exist_ok=True)
    (root / "Warframe.x64.exe").write_bytes(b"exe")

def tree_identity(root: Path) -> tuple[str, int]:
    files, digest = common.scan_tree(root)
    return digest, len(files)

def tracked_info(path: Path) -> dict:
    stat = path.stat()
    return {"path": path, "size": stat.st_size, "sha256": common.sha256_file(path), "mtime_ns": stat.st_mtime_ns}

def write_recovery(work: Path, state: dict, recovery_version: int | None = None) -> None:
    work.mkdir(parents=True, exist_ok=True)
    version = apply_patch.RECOVERY_VERSION if recovery_version is None else recovery_version
    data = {"recovery_version": version, "pid": -1, **state}
    if version >= 2 and "phase" not in data:
        data["phase"] = "applying"
    (work / apply_patch.RECOVERY_FILE).write_text(json.dumps(data), encoding="utf-8")

class CommonTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            common.parse_json('{"a": 1, "a": 2}')

    def test_nonstandard_json_constants_are_rejected(self) -> None:
        for payload in ('{"value": NaN}', '{"value": Infinity}', '{"value": -Infinity}'):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ValueError, "Non-standard JSON constant"):
                    common.parse_json(payload)

    def test_sha256_file_matches_hashlib(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.bin"
            data = b"Ninja Patch Tool\x00" * 4096
            path.write_bytes(data)
            self.assertEqual(common.sha256_file(path), hashlib.sha256(data).hexdigest())

    def test_root_hash_helper_matches_scan_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "b.bin").write_bytes(b"b")
            (root / "folder").mkdir()
            (root / "folder" / "a.bin").write_bytes(b"a")
            files, digest = common.scan_tree(root)
            self.assertEqual(common.root_sha256_from_files(files), digest)

    def test_root_hash_helper_normalizes_sha256_case(self) -> None:
        files = {"a.bin": {"size": 1, "sha256": sha256_bytes(b"a")}}
        expected = common.root_sha256_from_files(files)
        files["a.bin"]["sha256"] = files["a.bin"]["sha256"].upper()
        self.assertEqual(common.root_sha256_from_files(files), expected)

    def test_sha256_validation_is_strict(self) -> None:
        self.assertTrue(common.is_sha256("a" * 64))
        self.assertTrue(common.is_sha256("ABCDEF0123456789" * 4))
        for value in ("+" + "a" * 63, "-" + "a" * 63, " " + "a" * 63, "g" * 64, "a" * 63, True, None):
            self.assertFalse(common.is_sha256(value))

    def test_format_bytes_supports_pib(self) -> None:
        self.assertEqual(common.format_bytes(0), "0 B")
        self.assertEqual(common.format_bytes(1024**4), "1.0 TiB")
        self.assertEqual(common.format_bytes(1024**5), "1.0 PiB")

    def test_natural_sort_key_handles_mixed_base_name_shapes(self) -> None:
        self.assertEqual(sorted(["U10", "43.5", "U2", "Alpha1"], key=common.natural_sort_key), ["43.5", "Alpha1", "U2", "U10"])

    def test_version_has_single_source(self) -> None:
        self.assertEqual(build_release.VERSION, common.VERSION)

    def test_process_identity_prevents_pid_reuse_false_positive(self) -> None:
        with mock.patch.object(common, "process_is_running", return_value=True), mock.patch.object(common, "process_identity", return_value="123:new"):
            self.assertFalse(common.process_matches_identity(123, "123:old"))
            self.assertTrue(common.process_matches_identity(123, "123:new"))
            self.assertTrue(common.process_matches_identity(123, None))

    def test_argument_parser_uses_python_314_cli_improvements(self) -> None:
        parser = common.ErrorArgumentParser()
        self.assertTrue(parser.suggest_on_error)
        self.assertFalse(parser.color)

    def test_version_argument_includes_v_prefix(self) -> None:
        parser = common.ErrorArgumentParser()
        parser.add_version_argument()
        stdout = io.StringIO()
        with mock.patch("sys.stdout", stdout), self.assertRaises(SystemExit) as raised:
            parser.parse_args(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(stdout.getvalue().strip(), f"Ninja Patch Tool v{common.VERSION}")

    def test_steam_manifest_id_range(self) -> None:
        self.assertTrue(common.is_steam_manifest_id(1))
        self.assertTrue(common.is_steam_manifest_id(18446744073709551615))
        for value in (0, -1, 18446744073709551616, True, "1"):
            self.assertFalse(common.is_steam_manifest_id(value))

    def test_wrong_warframe_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with mock.patch("sys.stderr", stderr):
                self.assertFalse(common.validate_warframe_installation(Path(tmp), "Base"))
            self.assertIn("Expected at least Cache.Windows, Tools, and Warframe.x64.exe", stderr.getvalue())

    def test_warframe_root_allows_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_warframe_root(root)
            (root / "installscript.vdf").write_text("extra", encoding="utf-8")
            self.assertTrue(common.validate_warframe_installation(root, "Base"))
            with mock.patch("sys.stderr", io.StringIO()):
                self.assertFalse(common.validate_warframe_installation(root.parent, "Base"))

    def test_windows_unsafe_paths_are_rejected_on_every_os(self) -> None:
        unsafe_paths = (
            "../x", "/x", "C:/x", "file:stream", "CON", "con.txt", "CON .txt",
            "COM1.bin", "COM¹.bin", "LPT9", "name. ", "name.", "bad?.txt",
        )
        for path in unsafe_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    common.relative_path_parts(path)
        self.assertEqual(common.relative_path_parts("Cache.Windows/B.Misc.cache"), ("Cache.Windows", "B.Misc.cache"))

    def test_write_index_refuses_preexisting_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            index_file = Path(tmp) / "index.json"
            temporary = index_file.with_name(index_file.name + ".tmp")
            temporary.write_text("keep", encoding="utf-8")
            with mock.patch.object(common, "INDEX_FILE", index_file):
                with self.assertRaises(FileExistsError):
                    common.write_index({})
            self.assertEqual(temporary.read_text(encoding="utf-8"), "keep")
            self.assertFalse(index_file.exists())

    def test_add_base_keeps_installation_locked_until_index_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            active: list[str] = []

            from contextlib import contextmanager
            @contextmanager
            def fake_lock(kind: str, target: Path, description: str):
                active.append(kind)
                try:
                    yield
                finally:
                    active.remove(kind)

            def write_index(index: dict) -> None:
                self.assertIn("installation", active)
                self.assertIn("index", active)

            argv = ["add_base.py", str(base), "U43.5.1", "4895911296145320793"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(add_base, "operation_lock", side_effect=fake_lock),
                mock.patch.object(add_base, "validate_warframe_installation", return_value=True),
                mock.patch.object(add_base, "scan_tree", return_value=({}, "a" * 64)),
                mock.patch.object(add_base, "load_index", return_value={}),
                mock.patch.object(add_base, "write_index", side_effect=write_index),
            ):
                self.assertEqual(add_base.main(), 0)

    def test_frozen_tool_dir_uses_executable_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "NinjaPatchTool" / "make_patch.exe"
            with mock.patch.object(common.sys, "frozen", True, create=True), mock.patch.object(common.sys, "executable", str(executable)):
                self.assertEqual(common.get_tool_dir(), executable.resolve().parent)

    def test_release_readme_uses_executable_commands(self) -> None:
        markdown = """# Ninja Patch Tool

## Requirements

- Python 3.14 (not required for release executables)

## Add a base

```text
py add_base.py path name manifest_id
```

## Build a release

This should not be included.
"""
        readme = build_release.create_release_readme(markdown)
        self.assertIn(f"Version {build_release.VERSION}", readme)
        self.assertIn("add_base path name manifest_id", readme)
        self.assertNotIn("py add_base.py", readme)
        self.assertNotIn("add_base.exe", readme)
        self.assertNotIn("Python installation", readme)
        self.assertNotIn("Build a release", readme)
        self.assertNotIn("PyInstaller", readme)
        self.assertNotIn("build_release.py", readme)
        self.assertFalse(readme.endswith("\n"))

    def test_project_readme_uses_release_executable_commands(self) -> None:
        readme = (build_release.ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("add_base path name manifest_id [-a | -n]", readme)
        self.assertIn("verify_base path name [-a | -n]", readme)
        self.assertIn("make_patch base new output base_name [-c PRESET] [-a | -n]", readme)
        self.assertIn("apply_patch base patch [-o OUTPUT | -i] [-a | -n]", readme)
        self.assertIn("When running from source, use the corresponding `.py` script with Python 3.14 instead.", readme)
        self.assertNotIn("py add_base.py path name manifest_id", readme)
        self.assertNotIn("py verify_base.py path name", readme)
        self.assertNotIn("py make_patch.py base new output base_name [-c PRESET]", readme)
        self.assertNotIn("py apply_patch.py base patch [-o OUTPUT | -i]", readme)
        self.assertIn("-a, --auto-update", readme)
        self.assertIn("-n, --no-auto-update", readme)
        self.assertIn("-u, --check-update", readme)
        self.assertNotIn("## Automatic updates", readme)
        self.assertIn(".sha256", readme)
        for technical in ("HDiff payloads", "DEFLATE", "LZMA", "ZIP compression"):
            self.assertNotIn(technical, readme)
        self.assertIn("Ninja Capture Tool", readme)
        self.assertNotIn("Ninja Reverse Proxy", readme)
        self.assertIn("through Wine", readme)
        self.assertIn("native Linux/macOS source execution is not supported", readme)

        release_readme = build_release.create_release_readme(readme)
        for technical in ("HDiff payloads", "DEFLATE", "LZMA", "ZIP compression"):
            self.assertNotIn(technical, release_readme)

    def test_runtime_data_paths_are_centralized(self) -> None:
        self.assertEqual(common.DATA_DIR, common.TOOL_DIR / "data")
        self.assertEqual(common.INDEX_FILE, common.DATA_DIR / "index.json")
        self.assertEqual(make_patch.HDIFFZ, common.DATA_DIR / "hdiffz.exe")
        self.assertEqual(apply_patch.HPATCHZ, common.DATA_DIR / "hpatchz.exe")
        self.assertEqual(build_release.DATA_DIR, build_release.ROOT / "data")
        self.assertEqual(build_release.FAVICON, build_release.DATA_DIR / "favicon.ico")
        self.assertEqual(build_release.LICENSES_DIR, build_release.DATA_DIR / "licenses")
        self.assertEqual(update.UPDATE_CONFIG_FILE, common.DATA_DIR / "update.json")

    def test_release_temp_directory_is_separate_from_patch_temp(self) -> None:
        self.assertEqual(build_release.RELEASE_TEMP_DIR, build_release.ROOT / "release_temp")
        self.assertNotEqual(build_release.RELEASE_TEMP_DIR, common.TEMP_ROOT)

    def test_stale_release_temp_is_removed_before_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_temp = Path(tmp) / "release_temp"
            nested = release_temp / "old_build" / "build"
            nested.mkdir(parents=True)
            (nested / "leftover.bin").write_bytes(b"leftover")
            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", release_temp),
                mock.patch("builtins.print") as print_mock,
            ):
                build_release.clean_stale_release_temp()
            self.assertFalse(release_temp.exists())
            print_mock.assert_called_once_with("[Cleaning] Previous temporary build files")

    def test_stale_release_temp_cleanup_is_silent_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_temp = Path(tmp) / "release_temp"
            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", release_temp),
                mock.patch("builtins.print") as print_mock,
            ):
                build_release.clean_stale_release_temp()
            print_mock.assert_not_called()

    def test_release_data_is_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            stage = root / "stage"
            dist = root / "dist"
            data.mkdir()
            dist.mkdir()

            expected_data = {"index.json", "update.json", "hdiffz.exe", "hpatchz.exe"}
            expected_licenses = {"Python_LICENSE.txt", "HDiffPatch_LICENSE.txt", "LICENSE"}
            self.assertEqual(set(build_release.RELEASE_DATA_FILES), expected_data)
            self.assertEqual(set(build_release.THIRD_PARTY_LICENSE_FILES), {"Python_LICENSE.txt", "HDiffPatch_LICENSE.txt"})
            self.assertIn("updater.py", build_release.ENTRY_SCRIPTS)
            for name in expected_data:
                (data / name).write_bytes(b"{}" if name in {"index.json", "update.json"} else name.encode("ascii"))

            licenses = data / "licenses"
            licenses.mkdir()
            for name in build_release.THIRD_PARTY_LICENSE_FILES:
                (licenses / name).write_text(name, encoding="ascii")

            project_license = root / "LICENSE"
            project_license.write_text("project license", encoding="ascii")
            (data / "favicon.ico").write_bytes(b"icon")
            (data / "notes.txt").write_text("do not ship", encoding="utf-8")
            (data / "README.md").write_text("source-only data notes", encoding="utf-8")
            (root / "README.md").write_text("# Ninja Patch Tool\n", encoding="utf-8")

            with (
                mock.patch.object(build_release, "ROOT", root),
                mock.patch.object(build_release, "DATA_DIR", data),
                mock.patch.object(build_release, "LICENSES_DIR", licenses),
                mock.patch.object(build_release, "ENTRY_SCRIPTS", ()),
            ):
                build_release.populate_release(stage, dist, [project_license])

            self.assertEqual({path.name for path in (stage / "data").iterdir()}, {*expected_data, "licenses"})
            self.assertEqual({path.name for path in (stage / "data" / "licenses").iterdir()}, expected_licenses)

    def test_release_preflight_validates_x64_pe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "tool.exe"
            data = bytearray(0x86)
            data[:2] = b"MZ"
            data[0x3C:0x40] = (0x80).to_bytes(4, "little")
            data[0x80:0x84] = b"PE\0\0"
            data[0x84:0x86] = (0x8664).to_bytes(2, "little")
            executable.write_bytes(data)
            build_release.validate_pe_x64(executable)
            data[0x84:0x86] = (0x14C).to_bytes(2, "little")
            executable.write_bytes(data)
            with self.assertRaisesRegex(RuntimeError, "not an x86-64"):
                build_release.validate_pe_x64(executable)

    def test_release_preflight_validates_ico_structure(self) -> None:
        build_release.validate_ico(build_release.FAVICON)
        with tempfile.TemporaryDirectory() as tmp:
            icon = Path(tmp) / "bad.ico"
            icon.write_bytes(b"not an icon")
            with self.assertRaisesRegex(RuntimeError, "Invalid ICO"):
                build_release.validate_ico(icon)

            old_style = Path(tmp) / "old-style.ico"
            payload = b"not-png"
            old_style.write_bytes(
                b"\x00\x00\x01\x00\x01\x00"
                + b"\x00\x00\x00\x00\x01\x00\x20\x00"
                + len(payload).to_bytes(4, "little")
                + (22).to_bytes(4, "little")
                + payload
            )
            with self.assertRaisesRegex(RuntimeError, "transparent 256x256 PNG-compressed"):
                build_release.validate_ico(old_style)

    def test_release_checksum_is_generated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_dir = Path(tmp)
            with mock.patch.object(build_release, "RELEASE_DIR", release_dir):
                archive = build_release.release_archive_path()
                archive.write_bytes(b"release")
                checksum, digest = build_release.create_release_checksum(archive)
                self.assertEqual(digest, hashlib.sha256(b"release").hexdigest())
                self.assertEqual(checksum.read_text(encoding="ascii"), f"{digest}  {archive.name}\n")

    def test_release_output_archive_is_removed_if_checksum_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "release.zip"
            archive.write_bytes(b"release")
            with (
                mock.patch.object(build_release, "create_release_archive", return_value=archive),
                mock.patch.object(build_release, "create_release_checksum", side_effect=RuntimeError("checksum failed")),
            ):
                with self.assertRaisesRegex(RuntimeError, "checksum failed"):
                    build_release.create_release_outputs(Path(tmp) / "stage")
            self.assertFalse(archive.exists())

    def test_pyinstaller_minimum_version_for_python_314(self) -> None:
        build_release.validate_pyinstaller_version("6.15.0")
        build_release.validate_pyinstaller_version("6.22.2")
        with self.assertRaisesRegex(RuntimeError, "6.15.0 or newer"):
            build_release.validate_pyinstaller_version("6.14.2")

    def test_release_builder_requires_python_314(self) -> None:
        for version in ((3, 13, 9), (3, 15, 0)):
            with self.subTest(version=version):
                with (
                    mock.patch.object(build_release.sys, "platform", "win32"),
                    mock.patch.object(build_release.struct, "calcsize", return_value=8),
                    mock.patch.object(build_release.sys, "version_info", version),
                ):
                    with self.assertRaisesRegex(RuntimeError, "Python 3.14 is required to build releases"):
                        build_release.validate_build_environment()

    def test_release_executable_uses_icon_version_info_and_local_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "add_base.py"
            dist = root / "dist"
            work = root / "work"
            specs = root / "spec"
            script.write_text("print('test')", encoding="utf-8")
            dist.mkdir()
            work.mkdir()
            specs.mkdir()
            commands: list[list[str]] = []
            environments: list[dict[str, str]] = []

            def run(command, cwd, env):
                commands.append(command)
                environments.append(env)
                (dist / "add_base.exe").write_bytes(b"exe")
                return SimpleNamespace(returncode=0)

            with mock.patch.object(build_release.subprocess, "run", side_effect=run):
                build_release.build_executable(script, dist, work, specs)

            self.assertEqual(len(commands), 1)
            icon_index = commands[0].index("--icon")
            version_index = commands[0].index("--version-file")
            self.assertEqual(commands[0][icon_index + 1], str(build_release.FAVICON))
            self.assertTrue(Path(commands[0][version_index + 1]).is_file())
            log_level_index = commands[0].index("--log-level")
            self.assertEqual(commands[0][log_level_index + 1], "WARN")
            self.assertNotIn("--clean", commands[0])
            self.assertEqual(environments[0]["TEMP"], str(dist.parent))
            self.assertEqual(environments[0]["TMP"], str(dist.parent))
            self.assertEqual(environments[0]["PYINSTALLER_CONFIG_DIR"], str(dist.parent / "pyinstaller_config"))

    def test_release_builder_runs_source_tests_with_deprecation_warnings_as_errors(self) -> None:
        result = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(build_release.subprocess, "run", return_value=result) as run:
            build_release.run_source_tests()
        command = run.call_args.args[0]
        self.assertEqual(command[:3], [sys.executable, "-W", "error::DeprecationWarning"])
        self.assertEqual(command[3:], ["-m", "unittest", "discover", "-s", "tests"])

    def test_release_builder_stops_when_source_tests_fail(self) -> None:
        result = SimpleNamespace(returncode=1, stdout="failure", stderr="")
        with mock.patch.object(build_release.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "Source test suite failed"):
                build_release.run_source_tests()

    def test_release_smoke_tests_all_executables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            dist.mkdir()
            for script in build_release.ENTRY_SCRIPTS:
                (dist / f"{Path(script).stem}.exe").write_bytes(b"exe")

            calls: list[list[str]] = []
            def run(command, cwd, env, capture_output, text, timeout):
                calls.append(command)
                if command[1:] == ["-h"]:
                    return SimpleNamespace(returncode=0, stdout="Shows this help message", stderr="")
                return SimpleNamespace(returncode=0, stdout=f"Ninja Patch Tool v{build_release.VERSION}\n", stderr="")

            with mock.patch.object(build_release.subprocess, "run", side_effect=run):
                build_release.smoke_test_executables(dist)
            expected = []
            for script in build_release.ENTRY_SCRIPTS:
                expected.append([f"{Path(script).stem}.exe", "-h"])
                expected.append([f"{Path(script).stem}.exe", "--version"])
            self.assertEqual([[Path(command[0]).name, *command[1:]] for command in calls], expected)

    def test_release_version_info_contains_explorer_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for script, description in build_release.ENTRY_SCRIPTS.items():
                version_file = build_release.create_version_file(Path(script), Path(tmp))
                text = version_file.read_text(encoding="utf-8")
                compile(text, str(version_file), "eval")
                expected = {
                    "CompanyName": "DarkLotus",
                    "FileDescription": description,
                    "FileVersion": build_release.VERSION,
                    "InternalName": Path(script).stem,
                    "LegalCopyright": "DarkLotus",
                    "ProductName": "Ninja Patch Tool",
                    "ProductVersion": build_release.VERSION,
                }
                for key, value in expected.items():
                    self.assertIn(f"StringStruct('{key}', '{value}')", text)
                self.assertNotIn("StringStruct('OriginalFilename'", text)
                self.assertIn("VarStruct('Translation', [1033, 1200])", text)

    def test_release_output_is_checked_before_building(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_dir = Path(tmp)
            with mock.patch.object(build_release, "RELEASE_DIR", release_dir):
                archive = build_release.release_archive_path()
                archive.write_bytes(b"existing")
                with self.assertRaisesRegex(FileExistsError, "already exists"):
                    build_release.validate_release_output_available()
                archive.unlink()
                build_release.release_checksum_path().write_text("existing", encoding="ascii")
                with self.assertRaisesRegex(FileExistsError, "already exists"):
                    build_release.validate_release_output_available()

    def test_version_14_maps_to_windows_four_part_version(self) -> None:
        self.assertEqual(common.VERSION, "1.4")
        self.assertEqual(build_release.version_tuple(), (1, 4, 0, 0))

    def test_update_arguments_reject_duplicate_aliases_and_conflicts(self) -> None:
        invalid = (
            ["-a", "--auto-update"],
            ["-n", "--no-auto-update"],
            ["-u", "--check-update"],
            ["-a", "-a"],
            ["-a", "-n"],
            ["--auto-update", "--check-update"],
            ["--no-auto-update", "-u"],
        )
        for argv in invalid:
            with self.subTest(argv=argv):
                parser = common.ErrorArgumentParser()
                update.add_update_arguments(parser)
                with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as raised:
                    parser.parse_args(argv)
                self.assertEqual(raised.exception.code, 2)

    def test_check_update_is_standalone_and_does_not_read_config(self) -> None:
        with (
            mock.patch.object(update, "check_update_only", return_value=0) as check,
            mock.patch.object(update, "load_auto_update_setting") as load_config,
            mock.patch.object(update, "automatic_update_check_due") as cooldown,
            mock.patch.object(update, "cleanup_temporary_updater"),
        ):
            self.assertEqual(update.handle_early_update_request(["-u"]), 0)
        check.assert_called_once_with()
        load_config.assert_not_called()
        cooldown.assert_not_called()

        with mock.patch.object(update, "cleanup_temporary_updater"), mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                update.handle_early_update_request(["--check-update", "base"])
        self.assertEqual(raised.exception.code, 2)

    def test_check_update_reports_local_version_newer_than_latest_release(self) -> None:
        stdout = io.StringIO()
        release = {"version": "1.3.1", "url": "https://example.test/release"}
        with (
            mock.patch.object(update, "latest_release", return_value=release),
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stdout", stdout),
        ):
            self.assertEqual(update.check_update_only(), 0)
        record.assert_called_once_with("success")
        self.assertEqual(
            stdout.getvalue(),
            "[Update] Local Ninja Patch Tool v1.4 is newer than the latest release v1.3.1.\n",
        )

    def test_check_update_reports_equal_version_as_up_to_date(self) -> None:
        stdout = io.StringIO()
        release = {"version": "1.4", "url": "https://example.test/release"}
        with (
            mock.patch.object(update, "latest_release", return_value=release),
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stdout", stdout),
        ):
            self.assertEqual(update.check_update_only(), 0)
        record.assert_called_once_with("success")
        self.assertEqual(stdout.getvalue(), "[Update] Ninja Patch Tool v1.4 is up to date.\n")

    def test_check_update_reports_newer_release(self) -> None:
        stdout = io.StringIO()
        release = {"version": "1.5", "url": "https://example.test/release"}
        with (
            mock.patch.object(update, "latest_release", return_value=release),
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stdout", stdout),
        ):
            self.assertEqual(update.check_update_only(), 0)
        record.assert_called_once_with("update_available")
        self.assertEqual(
            stdout.getvalue(),
            "[Update] Ninja Patch Tool v1.5 is available.\n"
            "Current version: v1.4\n"
            "Release: https://example.test/release\n",
        )

    def test_update_check_interrupt_exits_cleanly(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(update, "latest_release", side_effect=KeyboardInterrupt),
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stderr", stderr),
        ):
            self.assertEqual(update.check_update_only(), 130)
        record.assert_not_called()
        self.assertIn("Update check cancelled", stderr.getvalue())

    def test_failed_explicit_update_check_records_retry_cooldown(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(update, "latest_release", side_effect=OSError("offline")),
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stderr", stderr),
        ):
            self.assertEqual(update.check_update_only(), 1)
        record.assert_called_once_with("failure")
        self.assertIn("Update check failed", stderr.getvalue())

    def test_startup_cleanup_interrupt_exits_cleanly(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(update, "cleanup_temporary_updater", side_effect=KeyboardInterrupt), mock.patch("sys.stderr", stderr):
            self.assertEqual(update.handle_early_update_request([]), 130)
        self.assertIn("Startup cancelled", stderr.getvalue())

    def test_missing_update_config_is_created_with_auto_update_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "data" / "update.json"
            with mock.patch.object(update, "UPDATE_CONFIG_FILE", config):
                self.assertTrue(update.load_auto_update_setting())
            self.assertEqual(json.loads(config.read_text(encoding="utf-8")), {"auto_update": True})

    def test_simultaneous_update_config_creation_uses_existing_winner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "data" / "update.json"

            def competing_create(source, destination) -> None:
                Path(destination).write_text('{"auto_update": false}\n', encoding="utf-8")
                raise FileExistsError("another process created the config first")

            with (
                mock.patch.object(update, "UPDATE_CONFIG_FILE", config),
                mock.patch.object(update.os, "link", side_effect=competing_create),
            ):
                self.assertFalse(update.load_auto_update_setting())
            self.assertEqual(json.loads(config.read_text(encoding="utf-8")), {"auto_update": False})
            self.assertEqual(list(config.parent.glob("update.json.*.tmp")), [])

    def test_update_config_creation_falls_back_when_hard_links_are_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "data" / "update.json"

            def fake_move(source: Path, destination: Path) -> None:
                source.rename(destination)

            with (
                mock.patch.object(update, "UPDATE_CONFIG_FILE", config),
                mock.patch.object(update.os, "link", side_effect=OSError("hard links unsupported")),
                mock.patch.object(update, "_move_file_if_absent_windows", side_effect=fake_move) as move_fallback,
            ):
                update._create_default_update_config()

            self.assertEqual(json.loads(config.read_text(encoding="utf-8")), {"auto_update": True})
            move_fallback.assert_called_once()
            self.assertEqual(list(config.parent.glob("update.json.*.tmp")), [])

    def test_invalid_update_config_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "update.json"
            original = '{"auto_update": "invalid"}\n'
            config.write_text(original, encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch.object(update, "UPDATE_CONFIG_FILE", config), mock.patch("sys.stderr", stderr):
                self.assertFalse(update.load_auto_update_setting())
            self.assertEqual(config.read_text(encoding="utf-8"), original)
            self.assertIn("automatic updating is disabled for this run", stderr.getvalue())

    def test_update_config_creation_failure_disables_auto_update_for_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "data" / "update.json"
            stderr = io.StringIO()
            with (
                mock.patch.object(update, "UPDATE_CONFIG_FILE", config),
                mock.patch.object(update, "_create_default_update_config", side_effect=OSError("read-only")),
                mock.patch("sys.stderr", stderr),
            ):
                self.assertFalse(update.load_auto_update_setting())
            self.assertIn("automatic updating is disabled for this run", stderr.getvalue())

    def test_successful_update_check_cooldown_is_24_hours(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "update.json"
            config.write_text('{"auto_update": true, "last_successful_check": 1000}\n', encoding="utf-8")
            with mock.patch.object(update, "UPDATE_CONFIG_FILE", config):
                self.assertFalse(update.automatic_update_check_due(1000 + 24 * 60 * 60 - 1))
                self.assertTrue(update.automatic_update_check_due(1000 + 24 * 60 * 60))

    def test_failed_update_check_cooldown_is_15_minutes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "update.json"
            config.write_text('{"auto_update": true, "last_failed_check": 1000}\n', encoding="utf-8")
            with mock.patch.object(update, "UPDATE_CONFIG_FILE", config):
                self.assertFalse(update.automatic_update_check_due(1000 + 15 * 60 - 1))
                self.assertTrue(update.automatic_update_check_due(1000 + 15 * 60))

    def test_future_update_check_timestamp_does_not_suppress_checks_indefinitely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "update.json"
            config.write_text('{"auto_update": true, "last_successful_check": 2000}\n', encoding="utf-8")
            with mock.patch.object(update, "UPDATE_CONFIG_FILE", config):
                self.assertTrue(update.automatic_update_check_due(1000))

    def test_recording_update_available_clears_existing_cooldowns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "update.json"
            config.write_text(
                '{"auto_update": true, "last_successful_check": 1000, "last_failed_check": 2000}\n',
                encoding="utf-8",
            )
            with mock.patch.object(update, "UPDATE_CONFIG_FILE", config):
                update._record_update_check_result("update_available", now=3000)
            self.assertEqual(json.loads(config.read_text(encoding="utf-8")), {"auto_update": True})

    def test_automatic_update_skips_github_during_success_cooldown(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "automatic_update_check_due", return_value=False),
            mock.patch.object(update, "check_for_update") as check,
        ):
            self.assertIsNone(update.handle_automatic_update(args, []))
        check.assert_not_called()

    def test_automatic_no_update_records_successful_check(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "automatic_update_check_due", return_value=True),
            mock.patch.object(update, "check_for_update", return_value=None),
            mock.patch.object(update, "_record_update_check_result") as record,
        ):
            self.assertIsNone(update.handle_automatic_update(args, []))
        record.assert_called_once_with("success")

    def test_automatic_update_failure_records_short_retry_cooldown(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "automatic_update_check_due", return_value=True),
            mock.patch.object(update, "check_for_update", side_effect=OSError("offline")),
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stderr", io.StringIO()),
        ):
            self.assertIsNone(update.handle_automatic_update(args, []))
        record.assert_called_once_with("failure")

    def test_explicit_auto_update_options_bypass_config(self) -> None:
        with (
            mock.patch.object(update.sys, "frozen", False, create=True),
            mock.patch.object(update, "load_auto_update_setting") as load_config,
            mock.patch("sys.stderr", io.StringIO()),
        ):
            args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
            self.assertIsNone(update.handle_automatic_update(args, []))
            load_config.assert_not_called()

        with mock.patch.object(update, "load_auto_update_setting") as load_config:
            args = SimpleNamespace(auto_update=False, no_auto_update=True, check_update=False)
            self.assertIsNone(update.handle_automatic_update(args, []))
            load_config.assert_not_called()

    def test_missing_updater_is_rejected_before_update_download(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        release = {"version": "1.5", "assets": [], "url": "https://example.test/release"}
        missing = Path("missing-updater.exe")
        stderr = io.StringIO()
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "automatic_update_check_due", return_value=True),
            mock.patch.object(update, "check_for_update", return_value=release),
            mock.patch.object(
                update,
                "_installed_updater_path",
                side_effect=RuntimeError(f"Updater executable is missing: {missing}"),
            ),
            mock.patch.object(update, "download_release") as download,
            mock.patch.object(update, "extract_release_archive") as extract,
            mock.patch.object(update, "launch_updater") as launch,
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stderr", stderr),
        ):
            self.assertIsNone(update.handle_automatic_update(args, []))

        download.assert_not_called()
        extract.assert_not_called()
        launch.assert_not_called()
        record.assert_called_once_with("failure")
        self.assertIn("Updater executable is missing", stderr.getvalue())

    def test_installed_updater_version_check_accepts_matching_version(self) -> None:
        updater_path = Path("updater.exe")
        result = SimpleNamespace(returncode=0, stdout="Ninja Patch Tool v1.4\n", stderr="")
        with (
            mock.patch.object(update, "_installed_updater_path", return_value=updater_path),
            mock.patch.object(update.subprocess, "run", return_value=result) as run,
        ):
            self.assertEqual(update._validate_installed_updater(), updater_path)
        run.assert_called_once_with(
            [str(updater_path), "--version"],
            cwd=update.TOOL_DIR,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    def test_wrong_updater_version_is_rejected_before_update_download(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        release = {"version": "1.5", "assets": [], "url": "https://example.test/release"}
        updater_path = Path("updater.exe")
        result = SimpleNamespace(returncode=0, stdout="Ninja Patch Tool v1.3.1\n", stderr="")
        stderr = io.StringIO()
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "automatic_update_check_due", return_value=True),
            mock.patch.object(update, "check_for_update", return_value=release),
            mock.patch.object(update, "_installed_updater_path", return_value=updater_path),
            mock.patch.object(update.subprocess, "run", return_value=result),
            mock.patch.object(update, "download_release") as download,
            mock.patch.object(update, "extract_release_archive") as extract,
            mock.patch.object(update, "launch_updater") as launch,
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stderr", stderr),
        ):
            self.assertIsNone(update.handle_automatic_update(args, []))

        download.assert_not_called()
        extract.assert_not_called()
        launch.assert_not_called()
        record.assert_called_once_with("failure")
        self.assertIn("Updater executable version does not match", stderr.getvalue())

    def test_automatic_update_interrupt_exits_cleanly(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        stderr = io.StringIO()
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "automatic_update_check_due", return_value=True),
            mock.patch.object(update, "check_for_update", side_effect=KeyboardInterrupt),
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stderr", stderr),
        ):
            self.assertEqual(update.handle_automatic_update(args, []), 130)
        record.assert_not_called()
        self.assertIn("Update cancelled", stderr.getvalue())

    def test_automatic_update_interrupt_cleans_partial_work(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        release = {"version": "1.5", "assets": [], "url": "https://example.test/release"}
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            with (
                mock.patch.object(update.sys, "frozen", True, create=True),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update, "automatic_update_check_due", return_value=True),
                mock.patch.object(update, "check_for_update", return_value=release),
                mock.patch.object(update, "_validate_installed_updater", return_value=Path("updater.exe")),
                mock.patch.object(update, "_record_update_check_result"),
                mock.patch.object(update, "download_release", side_effect=KeyboardInterrupt),
                mock.patch("sys.stderr", io.StringIO()),
            ):
                self.assertEqual(update.handle_automatic_update(args, []), 130)
            self.assertTrue(temp_root.is_dir())
            self.assertEqual(list(temp_root.iterdir()), [])

    def test_restarted_update_session_skips_exactly_one_update_check(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        with (
            mock.patch.dict(update.os.environ, {"NPT_SKIP_UPDATE_CHECK_ONCE": "1"}, clear=False),
            mock.patch.object(update, "check_for_update") as check,
        ):
            self.assertIsNone(update.handle_automatic_update(args, ["-a"]))
            self.assertNotIn("NPT_SKIP_UPDATE_CHECK_ONCE", update.os.environ)
        check.assert_not_called()

    def test_update_handoff_happens_after_cheap_add_base_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            make_warframe_root(base)
            argv = ["add_base.py", str(base), "U1", "1", "-a"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(add_base, "install_termination_handlers"),
                mock.patch.object(add_base, "handle_early_update_request", return_value=None),
                mock.patch.object(add_base, "operation_lock", return_value=nullcontext()),
                mock.patch.object(add_base, "load_index", return_value={}),
                mock.patch.object(add_base, "handle_automatic_update", return_value=0) as auto_update,
                mock.patch.object(add_base, "scan_tree") as scan,
            ):
                self.assertEqual(add_base.main(), 0)
            auto_update.assert_called_once()
            scan.assert_not_called()

    def test_add_base_existing_name_is_rejected_before_hash_or_update_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            make_warframe_root(base)
            entry = {"steam_manifest_id": 123, "sha256": "a" * 64, "file_count": 1}
            argv = ["add_base.py", str(base), "U43.5.1", "456"]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(add_base, "install_termination_handlers"),
                mock.patch.object(add_base, "handle_early_update_request", return_value=None),
                mock.patch.object(add_base, "operation_lock", return_value=nullcontext()),
                mock.patch.object(add_base, "load_index", return_value={"U43.5.1": entry}),
                mock.patch.object(add_base, "handle_automatic_update") as auto_update,
                mock.patch.object(add_base, "scan_tree") as scan,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(add_base.main(), 1)
            auto_update.assert_not_called()
            scan.assert_not_called()
            self.assertIn('Base "U43.5.1" already exists', stderr.getvalue())

    def test_add_base_existing_manifest_is_rejected_before_hash_or_update_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            make_warframe_root(base)
            entry = {"steam_manifest_id": 456, "sha256": "a" * 64, "file_count": 1}
            argv = ["add_base.py", str(base), "U43.5.2", "456"]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(add_base, "install_termination_handlers"),
                mock.patch.object(add_base, "handle_early_update_request", return_value=None),
                mock.patch.object(add_base, "operation_lock", return_value=nullcontext()),
                mock.patch.object(add_base, "load_index", return_value={"U43.5.1": entry}),
                mock.patch.object(add_base, "handle_automatic_update") as auto_update,
                mock.patch.object(add_base, "scan_tree") as scan,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(add_base.main(), 1)
            auto_update.assert_not_called()
            scan.assert_not_called()
            self.assertIn('Steam manifest ID 456 is already indexed as "U43.5.1"', stderr.getvalue())

    def test_add_base_rechecks_index_after_hash_to_close_race(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            make_warframe_root(base)
            entry = {"steam_manifest_id": 999, "sha256": "b" * 64, "file_count": 1}
            argv = ["add_base.py", str(base), "U43.5.2", "456"]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(add_base, "install_termination_handlers"),
                mock.patch.object(add_base, "handle_early_update_request", return_value=None),
                mock.patch.object(add_base, "operation_lock", return_value=nullcontext()),
                mock.patch.object(add_base, "load_index", side_effect=[{}, {"U43.5.2": entry}]),
                mock.patch.object(add_base, "handle_automatic_update", return_value=None),
                mock.patch.object(add_base, "scan_tree", return_value=({}, "a" * 64)) as scan,
                mock.patch.object(add_base, "write_index") as write,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(add_base.main(), 1)
            scan.assert_called_once()
            write.assert_not_called()
            self.assertIn('Base "U43.5.2" already exists', stderr.getvalue())

    def test_update_handoff_happens_after_cheap_verify_base_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            make_warframe_root(base)
            entry = {"steam_manifest_id": 123, "sha256": "a" * 64, "file_count": 1}
            argv = ["verify_base.py", str(base), "U43.5.1", "-a"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(verify_base, "install_termination_handlers"),
                mock.patch.object(verify_base, "handle_early_update_request", return_value=None),
                mock.patch.object(verify_base, "load_index", return_value={"U43.5.1": entry}),
                mock.patch.object(verify_base, "handle_automatic_update", return_value=0) as auto_update,
                mock.patch.object(verify_base, "scan_tree") as scan,
            ):
                self.assertEqual(verify_base.main(), 0)
            auto_update.assert_called_once()
            scan.assert_not_called()

    def test_verify_base_missing_index_entry_is_rejected_before_update_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            make_warframe_root(base)
            argv = ["verify_base.py", str(base), "U43.5.1"]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(verify_base, "install_termination_handlers"),
                mock.patch.object(verify_base, "handle_early_update_request", return_value=None),
                mock.patch.object(verify_base, "load_index", return_value={}),
                mock.patch.object(verify_base, "handle_automatic_update") as auto_update,
                mock.patch.object(verify_base, "scan_tree") as scan,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(verify_base.main(), 1)
            auto_update.assert_not_called()
            scan.assert_not_called()
            self.assertIn('Base "U43.5.1" is not present', stderr.getvalue())

    def test_shared_version_comparison_handles_short_feature_versions(self) -> None:
        self.assertGreater(common.compare_versions("1.4", "1.3.1.2"), 0)
        self.assertEqual(common.compare_versions("1.4", "1.4.0.0"), 0)
        self.assertLess(common.compare_versions("1.4", "1.4.1"), 0)
        self.assertEqual(common.parse_version("v1.4"), (1, 4))
        with self.assertRaises(ValueError):
            common.compare_versions("1.4-beta", "1.4")

    def test_update_download_retries_and_verifies_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            payload = b"release archive"
            digest = hashlib.sha256(payload).hexdigest()
            version = "1.5"
            archive_name = f"NinjaPatchTool-v{version}-Windows-x64.zip"
            checksum_name = archive_name + ".sha256"
            release = {
                "version": version,
                "assets": [
                    {"name": archive_name, "browser_download_url": "https://example.test/release.zip", "size": len(payload)},
                    {"name": checksum_name, "browser_download_url": "https://example.test/release.sha256", "size": len(f"{digest}  {archive_name}\n")},
                ],
            }
            calls = 0

            def fake_download(url: str, destination: Path, expected_size=None, progress_label=None) -> None:
                nonlocal calls
                calls += 1
                if calls <= 2:
                    raise OSError("temporary failure")
                if destination.name.endswith(".sha256"):
                    destination.write_text(f"{digest}  {archive_name}\n", encoding="ascii")
                else:
                    destination.write_bytes(payload)

            with mock.patch.object(update, "_download_file", side_effect=fake_download), mock.patch.object(update.time, "sleep"):
                archive = update.download_release(release, work)
            self.assertEqual(archive.read_bytes(), payload)
            self.assertEqual(calls, 4)

    def test_update_archive_validation_and_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "release.zip"
            release_root = "NinjaPatchTool-v1.5"
            files = {
                "add_base.exe": b"exe",
                "verify_base.exe": b"exe",
                "make_patch.exe": b"exe",
                "apply_patch.exe": b"exe",
                "updater.exe": b"exe",
                "README.txt": b"readme",
                "data/index.json": b"{}",
                "data/update.json": b'{"auto_update": true}',
                "data/hdiffz.exe": b"exe",
                "data/hpatchz.exe": b"exe",
                "data/licenses/LICENSE": b"license",
            }
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name, payload in files.items():
                    archive.writestr(f"{release_root}/{name}", payload)
            stage = update.extract_release_archive(archive_path, root / "stage", "1.5")
            self.assertEqual((stage / "README.txt").read_bytes(), b"readme")
            self.assertTrue((stage / "data" / "licenses" / "LICENSE").is_file())

    def test_update_archive_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("NinjaPatchTool-v1.5/../outside.txt", b"bad")
            with self.assertRaisesRegex(RuntimeError, "Unsafe update archive path"):
                update.extract_release_archive(archive_path, root / "stage", "1.5")

    def test_update_archive_rejects_windows_unsafe_paths(self) -> None:
        unsafe = (
            "NinjaPatchTool-v1.5/CON",
            "NinjaPatchTool-v1.5/data/COM1.txt",
            "NinjaPatchTool-v1.5/data/file.txt:stream",
            "NinjaPatchTool-v1.5/data/trailing.",
            "NinjaPatchTool-v1.5/data/trailing ",
            "NinjaPatchTool-v1.5/data/bad?.txt",
        )
        for name in unsafe:
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "Unsafe update archive path"):
                update._safe_archive_parts(name)

    def test_updater_preserves_mutable_data_and_replaces_release_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            (install / "data" / "licenses").mkdir(parents=True)
            (stage / "data" / "licenses").mkdir(parents=True)
            (install / "make_patch.exe").write_bytes(b"old")
            (stage / "make_patch.exe").write_bytes(b"new")
            (install / "data" / "index.json").write_text('{"custom": 1}', encoding="utf-8")
            (stage / "data" / "index.json").write_text('{"new": 1}', encoding="utf-8")
            (install / "data" / "update.json").write_text('{"auto_update": false}', encoding="utf-8")
            (stage / "data" / "update.json").write_text('{"auto_update": true}', encoding="utf-8")
            (install / "data" / "licenses" / "old.txt").write_text("old", encoding="utf-8")
            (stage / "data" / "licenses" / "new.txt").write_text("new", encoding="utf-8")
            (stage / "data" / "hdiffz.exe").write_bytes(b"new hdiff")

            backup, _ = updater.install_staged_release(stage, install)
            self.assertTrue(backup.is_dir())
            self.assertEqual((install / "make_patch.exe").read_bytes(), b"new")
            self.assertEqual((install / "data" / "index.json").read_text(encoding="utf-8"), '{"custom": 1}')
            self.assertEqual((install / "data" / "update.json").read_text(encoding="utf-8"), '{"auto_update": false}')
            self.assertEqual({path.name for path in (install / "data" / "licenses").iterdir()}, {"new.txt"})
            self.assertEqual((install / "data" / "hdiffz.exe").read_bytes(), b"new hdiff")

    def test_updater_rolls_back_replaced_files_on_install_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            (install / "a.exe").write_bytes(b"old a")
            (install / "b.exe").write_bytes(b"old b")
            (stage / "a.exe").write_bytes(b"new a")
            (stage / "b.exe").write_bytes(b"new b")
            original_copy = updater._copy_item

            def fail_on_b(source: Path, destination: Path) -> None:
                if source.name == "b.exe":
                    raise OSError("copy failed")
                original_copy(source, destination)

            with mock.patch.object(updater, "_copy_item", side_effect=fail_on_b):
                with self.assertRaisesRegex(OSError, "copy failed"):
                    updater.install_staged_release(stage, install)
            self.assertEqual((install / "a.exe").read_bytes(), b"old a")
            self.assertEqual((install / "b.exe").read_bytes(), b"old b")

    def test_updater_can_roll_back_after_post_install_validation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            (install / "make_patch.exe").write_bytes(b"old")
            (stage / "make_patch.exe").write_bytes(b"new")

            backup, changes = updater.install_staged_release(stage, install)
            self.assertEqual((install / "make_patch.exe").read_bytes(), b"new")
            updater.rollback_staged_release(changes, backup)
            self.assertEqual((install / "make_patch.exe").read_bytes(), b"old")

    def test_updater_failed_work_cleanup_removes_work_after_successful_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "update_work"
            (work / "stage").mkdir(parents=True)
            (work / "release.zip").write_bytes(b"zip")
            updater.cleanup_update_work(work)
            self.assertFalse(work.exists())

    def test_updater_failed_work_cleanup_preserves_incomplete_rollback_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "update_work"
            (work / "stage").mkdir(parents=True)
            backup = work / "backup_deadbeef"
            backup.mkdir()
            (backup / "make_patch.exe").write_bytes(b"old")
            updater.cleanup_update_work(work)
            self.assertTrue(work.is_dir())
            self.assertTrue((backup / "make_patch.exe").is_file())

    def test_updater_install_lock_times_out_instead_of_waiting_forever(self) -> None:
        import ctypes

        kernel32 = SimpleNamespace(
            CreateMutexW=mock.MagicMock(return_value=123),
            WaitForSingleObject=mock.MagicMock(return_value=0x102),
            ReleaseMutex=mock.MagicMock(),
            CloseHandle=mock.MagicMock(),
        )
        with mock.patch.object(ctypes, "WinDLL", create=True, return_value=kernel32):
            with self.assertRaisesRegex(RuntimeError, "Timed out waiting for another Ninja Patch Tool update"):
                with updater.updater_install_lock(Path("C:/NPT"), timeout_seconds=2):
                    pass

        kernel32.WaitForSingleObject.assert_called_once_with(123, 2000)
        kernel32.ReleaseMutex.assert_not_called()
        kernel32.CloseHandle.assert_called_once_with(123)

    def test_updater_queued_target_is_satisfied_by_equal_or_newer_installation(self) -> None:
        executable = Path("tool.exe")
        cwd = Path(".")
        with mock.patch.object(updater, "_read_installed_version", return_value="1.5"):
            self.assertEqual(updater.installed_executable_satisfies_target(executable, "1.5", cwd), "1.5")
        with mock.patch.object(updater, "_read_installed_version", return_value="1.6"):
            self.assertEqual(updater.installed_executable_satisfies_target(executable, "1.5", cwd), "1.6")
        with mock.patch.object(updater, "_read_installed_version", return_value="1.5.0"):
            self.assertEqual(updater.installed_executable_satisfies_target(executable, "1.5", cwd), "1.5.0")
        with mock.patch.object(updater, "_read_installed_version", return_value="1.4.9"):
            self.assertIsNone(updater.installed_executable_satisfies_target(executable, "1.5", cwd))
        with mock.patch.object(updater, "_read_installed_version", side_effect=RuntimeError("not runnable")):
            self.assertIsNone(updater.installed_executable_satisfies_target(executable, "1.5", cwd))

    def test_updater_post_install_validation_still_requires_exact_target_text(self) -> None:
        with mock.patch.object(updater, "_read_installed_version", return_value="1.6"):
            with self.assertRaisesRegex(RuntimeError, "expected v1.5, got v1.6"):
                updater.validate_installed_executable(Path("tool.exe"), "1.5", Path("."))

    def test_stale_update_work_cleanup_removes_only_safe_old_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            temp_root.mkdir()
            old = temp_root / "update_old"
            old.mkdir()
            (old / "stage").mkdir()
            protected = temp_root / "update_protected"
            protected.mkdir()
            (protected / "backup_deadbeef").mkdir()
            recent = temp_root / "update_recent"
            recent.mkdir()
            unrelated = temp_root / "other_old"
            unrelated.mkdir()

            now = 2_000_000.0
            old_time = now - update.STALE_UPDATE_AGE_SECONDS - 1
            recent_time = now - update.STALE_UPDATE_AGE_SECONDS + 1
            for path in (old, protected, unrelated):
                update.os.utime(path, (old_time, old_time))
            update.os.utime(recent, (recent_time, recent_time))

            with mock.patch.object(update, "TEMP_ROOT", temp_root), mock.patch.object(update.time, "time", return_value=now):
                update.cleanup_stale_update_work()

            self.assertFalse(old.exists())
            self.assertTrue(protected.exists())
            self.assertTrue(recent.exists())
            self.assertTrue(unrelated.exists())

    def test_stale_temporary_updater_cleanup_removes_old_executables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_dir = Path(tmp)
            old = temp_dir / "NinjaPatchToolUpdater_old.exe"
            recent = temp_dir / "NinjaPatchToolUpdater_recent.exe"
            unrelated = temp_dir / "OtherUpdater_old.exe"
            for path in (old, recent, unrelated):
                path.write_bytes(b"exe")

            now = 2_000_000.0
            old_time = now - update.STALE_UPDATE_AGE_SECONDS - 1
            recent_time = now - update.STALE_UPDATE_AGE_SECONDS + 1
            update.os.utime(old, (old_time, old_time))
            update.os.utime(unrelated, (old_time, old_time))
            update.os.utime(recent, (recent_time, recent_time))

            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update.tempfile, "gettempdir", return_value=tmp),
                mock.patch.object(update.time, "time", return_value=now),
            ):
                update.cleanup_stale_temporary_updaters()

            self.assertFalse(old.exists())
            self.assertTrue(recent.exists())
            self.assertTrue(unrelated.exists())

    def test_temporary_updater_cleanup_falls_back_to_delete_on_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            updater_path = Path(tmp) / "NinjaPatchToolUpdater_deadbeef.exe"
            updater_path.write_bytes(b"exe")
            environment = {"NPT_UPDATER_CLEANUP": str(updater_path)}
            with (
                mock.patch.object(update.tempfile, "gettempdir", return_value=tmp),
                mock.patch.dict(update.os.environ, environment, clear=True),
                mock.patch.object(Path, "unlink", side_effect=OSError("busy")),
                mock.patch.object(update.time, "sleep"),
                mock.patch.object(update, "_schedule_delete_on_reboot") as schedule_delete,
            ):
                update.cleanup_temporary_updater()
            schedule_delete.assert_called_once_with(updater_path.resolve())

    def test_updater_relaunch_uses_internal_one_shot_skip_without_changing_args(self) -> None:
        captured = {}

        def fake_popen(command, cwd=None, env=None):
            captured["command"] = command
            captured["cwd"] = cwd
            captured["env"] = env
            return SimpleNamespace()

        with mock.patch.object(updater.subprocess, "Popen", side_effect=fake_popen):
            updater.relaunch(Path("C:/NPT/make_patch.exe"), ["-a", "base", "new", "out", "U1"], Path("C:/work"))

        self.assertEqual(captured["command"][1:], ["-a", "base", "new", "out", "U1"])
        self.assertEqual(captured["env"]["NPT_SKIP_UPDATE_CHECK_ONCE"], "1")
        self.assertNotIn("--no-auto-update", captured["command"])

    @unittest.skipUnless(sys.platform == "win32", "Windows mutex test")
    def test_operation_lock_rejects_same_target_concurrently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            with mock.patch.object(common, "TEMP_ROOT", root / "temp"):
                with common.operation_lock("test", target, "test operation"):
                    with self.assertRaisesRegex(RuntimeError, "Another test operation"):
                        with common.operation_lock("test", target, "test operation"):
                            pass

    @unittest.skipUnless(sys.platform == "win32", "Windows mutex test")
    def test_operation_lock_can_be_reacquired_after_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            with mock.patch.object(common, "TEMP_ROOT", root / "temp"):
                with common.operation_lock("test", target, "test operation"):
                    pass
                with common.operation_lock("test", target, "test operation"):
                    pass

    def test_apply_main_locks_base_and_separate_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            base.mkdir()
            output = root / "out"
            patch = root / "test.patch"
            locks: list[tuple[str, Path]] = []

            from contextlib import contextmanager
            @contextmanager
            def fake_lock(kind: str, target: Path, description: str):
                locks.append((kind, target))
                yield

            argv = ["apply_patch.py", str(base), str(patch), "--output", str(output)]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(apply_patch, "operation_lock", side_effect=fake_lock),
                mock.patch.object(apply_patch, "run_locked_apply", return_value=0),
                mock.patch.object(apply_patch, "install_termination_handlers"),
            ):
                self.assertEqual(apply_patch.main(), 0)
            self.assertEqual(locks, [("installation", base.resolve()), ("installation", output.resolve())])

    def test_scan_tree_detects_file_changes_during_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "file.bin"
            target.write_bytes(b"old")
            original = common.sha256_file

            def changing_hash(path: Path) -> str:
                digest = original(path)
                path.write_bytes(b"changed and longer")
                return digest

            with mock.patch.object(common, "sha256_file", side_effect=changing_hash):
                with self.assertRaisesRegex(RuntimeError, "Installation changed while it was being scanned"):
                    common.scan_tree(root)

    def test_scanned_file_change_after_hashing_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "file.bin"
            target.write_bytes(b"old")
            files, _ = common.scan_tree(root)
            target.write_bytes(b"changed and longer")
            with self.assertRaisesRegex(RuntimeError, "Installation changed after it was scanned"):
                common.verify_scanned_file(files["file.bin"])

    def test_scanned_tree_structure_change_after_hashing_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "old.bin").write_bytes(b"old")
            files, _ = common.scan_tree(root)
            (root / "new.bin").write_bytes(b"new")
            with self.assertRaisesRegex(RuntimeError, "Installation changed after it was scanned"):
                common.verify_scanned_tree(root, files)

    def test_low_disk_space_is_only_a_warning(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(common.shutil, "disk_usage", return_value=SimpleNamespace(free=100)), mock.patch("sys.stderr", stderr):
            common.warn_if_low_disk_space(Path.cwd(), 200, "testing")
        self.assertIn("WARNING: Disk space may be insufficient", stderr.getvalue())

class MakePatchTests(unittest.TestCase):
    def test_unowned_patch_tmp_is_never_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            output = Path(tmp) / "output.patch"
            partial = make_patch.temporary_patch_path(output)
            partial.write_bytes(b"unrelated")
            with mock.patch.object(make_patch, "TEMP_ROOT", temp_root):
                with self.assertRaisesRegex(RuntimeError, "cannot prove that it owns"):
                    make_patch.cleanup_stale_make_patch_work(output)
            self.assertEqual(partial.read_bytes(), b"unrelated")

    def test_known_stale_patch_tmp_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "make_patch_old"
            work.mkdir(parents=True)
            output = Path(tmp) / "output.patch"
            partial = make_patch.temporary_patch_path(output)
            partial.write_bytes(b"partial")
            (work / make_patch.MAKE_SESSION_FILE).write_text(json.dumps({"pid": 123, "output": str(output)}), encoding="utf-8")
            with mock.patch.object(make_patch, "TEMP_ROOT", temp_root), mock.patch.object(make_patch, "process_matches_identity", return_value=False):
                make_patch.cleanup_stale_make_patch_work(output)
            self.assertFalse(partial.exists())
            self.assertFalse(work.exists())

    def test_archive_contains_only_patch_format_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            (work / "diffs").mkdir(parents=True)
            (work / "manifest.json").write_text("{}", encoding="utf-8")
            (work / "session.json").write_text("secret", encoding="utf-8")
            (work / "diffs" / "a.hdiff").write_bytes(b"diff")
            source = root / "full.bin"
            source.write_bytes(b"file")
            output = root / "test.patch"
            make_patch.create_patch_archive(work, output, "normal", {"files/b.bin": tracked_info(source)})
            with zipfile.ZipFile(output, "r") as archive:
                self.assertEqual(set(archive.namelist()), {"manifest.json", "diffs/a.hdiff", "files/b.bin"})

    def test_patch_archive_member_compression_follows_preset(self) -> None:
        expected = {
            "normal": zipfile.ZIP_STORED,
            "high": zipfile.ZIP_DEFLATED,
            "higher": zipfile.ZIP_LZMA,
            "maximum": zipfile.ZIP_LZMA,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            (work / "diffs").mkdir(parents=True)
            (work / "manifest.json").write_text("{}", encoding="utf-8")
            (work / "diffs" / "a.hdiff").write_bytes(b"already compressed delta")
            source = root / "full.bin"
            source.write_bytes(b"full file payload" * 1024)
            source_info = tracked_info(source)

            for preset, full_file_compression in expected.items():
                with self.subTest(preset=preset):
                    output = root / f"{preset}.patch"
                    make_patch.create_patch_archive(work, output, preset, {"files/b.bin": source_info})
                    with zipfile.ZipFile(output, "r") as archive:
                        members = {member.filename: member for member in archive.infolist()}
                    self.assertEqual(members["manifest.json"].compress_type, zipfile.ZIP_DEFLATED)
                    self.assertEqual(members["diffs/a.hdiff"].compress_type, zipfile.ZIP_STORED)
                    self.assertEqual(members["files/b.bin"].compress_type, full_file_compression)

    def test_patch_archive_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            (work / "diffs").mkdir(parents=True)
            (work / "manifest.json").write_text('{"version": 2}\n', encoding="utf-8")
            (work / "diffs" / "a.hdiff").write_bytes(b"same delta")
            source = root / "full.bin"
            source.write_bytes(b"same full payload" * 100)
            for preset in make_patch.COMPRESSION_PRESETS:
                with self.subTest(preset=preset):
                    source_info = tracked_info(source)
                    first, second = root / f"{preset}-first.patch", root / f"{preset}-second.patch"
                    make_patch.create_patch_archive(work, first, preset, {"files/b.bin": source_info})
                    source.touch()
                    (work / "manifest.json").touch()
                    (work / "diffs" / "a.hdiff").touch()
                    source_info = tracked_info(source)
                    make_patch.create_patch_archive(work, second, preset, {"files/b.bin": source_info})
                    self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_create_archive_refuses_unknown_compression_preset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            (work / "diffs").mkdir(parents=True)
            (work / "manifest.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unknown compression preset"):
                make_patch.create_patch_archive(work, root / "test.patch", "impossible", {})

    def test_create_archive_refuses_preexisting_tmp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            (work / "diffs").mkdir(parents=True)
            (work / "manifest.json").write_text("{}", encoding="utf-8")
            output = root / "test.patch"
            partial = make_patch.temporary_patch_path(output)
            partial.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                make_patch.create_patch_archive(work, output, "normal", {})
            self.assertEqual(partial.read_bytes(), b"keep")

    def test_create_archive_never_overwrites_output_created_during_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            (work / "diffs").mkdir(parents=True)
            (work / "manifest.json").write_text("{}", encoding="utf-8")
            output = root / "test.patch"
            original_publish = make_patch.publish_patch_archive

            def race(temporary: Path, destination: Path) -> None:
                destination.write_bytes(b"unrelated")
                with mock.patch.object(Path, "rename", side_effect=FileExistsError):
                    original_publish(temporary, destination)

            with mock.patch.object(make_patch, "publish_patch_archive", side_effect=race):
                with self.assertRaisesRegex(FileExistsError, "appeared while the patch was being created"):
                    make_patch.create_patch_archive(work, output, "normal", {})

            self.assertEqual(output.read_bytes(), b"unrelated")
            self.assertFalse(make_patch.temporary_patch_path(output).exists())

    def test_higher_and_maximum_compare_compressed_full_file_against_delta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diff = root / "delta.hdiff"
            source = root / "new.bin"
            diff.write_bytes(b"d" * 50)
            source.write_bytes(b"n" * 100)
            info = tracked_info(source)
            for preset in ("higher", "maximum"):
                with self.subTest(preset=preset):
                    with mock.patch.object(make_patch, "measure_full_file_compressed_size", return_value=20) as measure:
                        self.assertTrue(make_patch.should_store_full_file(diff, info, preset, root, "x"))
                        measure.assert_called_once()
            with mock.patch.object(make_patch, "measure_full_file_compressed_size") as measure:
                self.assertFalse(make_patch.should_store_full_file(diff, info, "high", root, "x"))
                measure.assert_not_called()

    def test_update_handoff_happens_after_cheap_make_patch_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, new = root / "base", root / "new"
            make_warframe_root(base)
            make_warframe_root(new)
            output = root / "out.patch"
            hdiffz = root / "hdiffz.exe"
            hdiffz.write_bytes(b"fake")
            entry = {"steam_manifest_id": 1, "sha256": "a" * 64, "file_count": 1}
            argv = ["make_patch.py", str(base), str(new), str(output), "U43.5.1", "-a"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(make_patch, "HDIFFZ", hdiffz),
                mock.patch.object(make_patch, "install_termination_handlers"),
                mock.patch.object(make_patch, "handle_early_update_request", return_value=None),
                mock.patch.object(make_patch, "load_index", return_value={"U43.5.1": entry}),
                mock.patch.object(make_patch, "handle_automatic_update", return_value=0) as auto_update,
                mock.patch.object(make_patch, "operation_lock") as operation_lock,
                mock.patch.object(make_patch, "scan_tree") as scan,
            ):
                self.assertEqual(make_patch.main(), 0)
            auto_update.assert_called_once()
            operation_lock.assert_not_called()
            scan.assert_not_called()

    def test_make_main_locks_output_and_installations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, new = root / "base", root / "new"
            make_warframe_root(base)
            make_warframe_root(new)
            output = root / "out.patch"
            hdiffz = root / "hdiffz.exe"
            hdiffz.write_bytes(b"fake")
            locks: list[tuple[str, Path]] = []

            from contextlib import contextmanager
            @contextmanager
            def fake_lock(kind: str, target: Path, description: str):
                locks.append((kind, target))
                yield

            argv = ["make_patch.py", str(base), str(new), str(output), "U43.5.1"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(make_patch, "HDIFFZ", hdiffz),
                mock.patch.object(make_patch, "operation_lock", side_effect=fake_lock),
                mock.patch.object(make_patch, "cleanup_stale_make_patch_work"),
                mock.patch.object(
                    make_patch,
                    "load_index",
                    side_effect=[
                        {"U43.5.1": {"steam_manifest_id": 1, "sha256": "a" * 64, "file_count": 1}},
                        RuntimeError("stop"),
                    ],
                ),
                mock.patch.object(make_patch, "install_termination_handlers"),
            ):
                self.assertEqual(make_patch.main(), 1)
            expected_installations = sorted((base.resolve(), new.resolve()), key=lambda path: str(path).casefold())
            expected_locks = [("patch_output", output.resolve())]
            expected_locks.extend(("installation", path) for path in expected_installations)
            self.assertEqual(locks, expected_locks)

    def test_maximum_continues_after_candidate_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old, new, output = root / "old", root / "new", root / "out.hdiff"
            old.write_bytes(b"old")
            new.write_bytes(b"new")
            calls = 0

            def fake_run(old_path: Path, new_path: Path, candidate: Path, mode: list[str], common_options: list[str]) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise RuntimeError("candidate failed")
                candidate.write_bytes(b"ok")

            with mock.patch.object(make_patch, "run_hdiff_command", side_effect=fake_run):
                make_patch.run_hdiff(old, new, output, "maximum")
            self.assertEqual(output.read_bytes(), b"ok")
            self.assertEqual(calls, len(make_patch.MAXIMUM_MEMORY_CANDIDATES))

    def test_patch_output_inside_installation_is_rejected_by_main(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, new = root / "base", root / "new"
            make_warframe_root(base)
            make_warframe_root(new)
            output = base / "bad.patch"
            stderr = io.StringIO()
            argv = ["make_patch.py", str(base), str(new), str(output), "U43.5.1"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(make_patch, "install_termination_handlers"),
                mock.patch.object(make_patch, "handle_automatic_update") as auto_update,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(make_patch.main(), 1)
            auto_update.assert_not_called()
            self.assertIn("Patch output must not be inside", stderr.getvalue())

    def test_make_rejects_different_paths_with_identical_contents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, new = root / "base", root / "new"
            make_warframe_root(base)
            (base / "Cache.Windows" / "data.bin").write_bytes(b"same")
            shutil.copytree(base, new)

            base_files, base_hash = common.scan_tree(base)
            index_path = root / "index.json"
            index_path.write_text(json.dumps({
                "U43.5.1": {
                    "steam_manifest_id": 4895911296145320793,
                    "sha256": base_hash,
                    "file_count": len(base_files),
                }
            }), encoding="utf-8")

            hdiffz = root / "hdiffz.exe"
            hdiffz.write_bytes(b"fake")
            output = root / "out.patch"
            temp_root = root / "temp"
            argv = ["make_patch.py", str(base), str(new), str(output), "U43.5.1"]
            stderr = io.StringIO()

            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(common, "INDEX_FILE", index_path),
                mock.patch.object(common, "TEMP_ROOT", temp_root),
                mock.patch.object(make_patch, "TEMP_ROOT", temp_root),
                mock.patch.object(make_patch, "HDIFFZ", hdiffz),
                mock.patch.object(make_patch, "operation_lock", side_effect=lambda *args: nullcontext()),
                mock.patch.object(make_patch, "make_work_dir") as make_work_dir,
                mock.patch.object(make_patch, "run_hdiff") as run_hdiff,
                mock.patch.object(make_patch, "install_termination_handlers"),
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(make_patch.main(), 1)

            self.assertIn("Base and new installations are identical.", stderr.getvalue())
            self.assertIn("There are no changes to include in a patch.", stderr.getvalue())
            self.assertFalse(output.exists())
            make_work_dir.assert_not_called()
            run_hdiff.assert_not_called()

    def test_make_aborts_if_source_changes_after_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, new = root / "base", root / "new"
            make_warframe_root(base)
            shutil.copytree(base, new)
            (base / "Cache.Windows" / "data.bin").write_bytes(b"old")
            target = new / "Cache.Windows" / "data.bin"
            target.write_bytes(b"new")
            base_files, base_hash = common.scan_tree(base)
            index_path = root / "index.json"
            index_path.write_text(json.dumps({
                "U43.5.1": {
                    "steam_manifest_id": 4895911296145320793,
                    "sha256": base_hash,
                    "file_count": len(base_files),
                }
            }), encoding="utf-8")
            hdiffz = root / "hdiffz.exe"
            hdiffz.write_bytes(b"fake")
            output = root / "out.patch"
            temp_root = root / "temp"

            def changing_hdiff(old_path: Path, new_path: Path, diff_path: Path, compression: str) -> None:
                diff_path.parent.mkdir(parents=True, exist_ok=True)
                diff_path.write_bytes(b"d")
                target.write_bytes(b"changed after scan")

            argv = ["make_patch.py", str(base), str(new), str(output), "U43.5.1"]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(common, "INDEX_FILE", index_path),
                mock.patch.object(common, "TEMP_ROOT", temp_root),
                mock.patch.object(make_patch, "TEMP_ROOT", temp_root),
                mock.patch.object(make_patch, "HDIFFZ", hdiffz),
                mock.patch.object(make_patch, "operation_lock", side_effect=lambda *args: nullcontext()),
                mock.patch.object(make_patch, "process_identity", return_value="test-process"),
                mock.patch.object(make_patch, "run_hdiff", side_effect=changing_hdiff),
                mock.patch.object(make_patch, "install_termination_handlers"),
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(make_patch.main(), 1)
            self.assertIn("Installation changed after it was scanned", stderr.getvalue())
            self.assertFalse(output.exists())

    def test_maximum_fails_only_when_every_candidate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old, new, output = root / "old", root / "new", root / "out.hdiff"
            old.write_bytes(b"old")
            new.write_bytes(b"new")
            with mock.patch.object(make_patch, "run_hdiff_command", side_effect=RuntimeError("nope")):
                with self.assertRaisesRegex(RuntimeError, "All maximum-compression candidates failed"):
                    make_patch.run_hdiff(old, new, output, "maximum")
            self.assertFalse(output.exists())

class ApplyPatchTests(unittest.TestCase):
    def test_update_handoff_happens_after_cheap_apply_patch_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            make_warframe_root(base)
            patch = root / "test.patch"
            patch.write_bytes(b"not read before update handoff")
            hpatchz = root / "hpatchz.exe"
            hpatchz.write_bytes(b"fake")
            argv = ["apply_patch.py", str(base), str(patch), "-a"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(apply_patch, "HPATCHZ", hpatchz),
                mock.patch.object(apply_patch, "install_termination_handlers"),
                mock.patch.object(apply_patch, "handle_early_update_request", return_value=None),
                mock.patch.object(apply_patch, "operation_lock", side_effect=lambda *args: nullcontext()),
                mock.patch.object(apply_patch, "recover_interrupted_operations", return_value=None),
                mock.patch.object(apply_patch, "handle_automatic_update", return_value=0) as auto_update,
                mock.patch.object(apply_patch.zipfile, "ZipFile") as zip_file,
            ):
                self.assertEqual(apply_patch.main(), 0)
            auto_update.assert_called_once()
            zip_file.assert_not_called()

    def test_apply_missing_patch_is_rejected_before_update_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            make_warframe_root(base)
            patch = root / "missing.patch"
            argv = ["apply_patch.py", str(base), str(patch)]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(apply_patch, "install_termination_handlers"),
                mock.patch.object(apply_patch, "handle_early_update_request", return_value=None),
                mock.patch.object(apply_patch, "operation_lock", side_effect=lambda *args: nullcontext()),
                mock.patch.object(apply_patch, "recover_interrupted_operations", return_value=None),
                mock.patch.object(apply_patch, "handle_automatic_update") as auto_update,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(apply_patch.main(), 1)
            auto_update.assert_not_called()
            self.assertIn("Patch file does not exist", stderr.getvalue())

    def minimal_manifest(self, operation: dict, old_count: int = 0, new_count: int = 1) -> dict:
        return {
            "version": 1,
            "base": "U43.5.1",
            "base_steam_manifest_id": 4895911296145320793,
            "old_root_sha256": "1" * 64,
            "new_root_sha256": "2" * 64,
            "old_file_count": old_count,
            "new_file_count": new_count,
            "operations": [operation],
        }

    def test_applier_supports_v1_and_v2_patch_manifests(self) -> None:
        operation = {"type": "remove", "path": "a.bin", "old_size": 1, "old_sha256": "a" * 64}
        for version in (1, 2):
            with self.subTest(version=version):
                manifest = self.minimal_manifest(operation, old_count=1, new_count=0)
                manifest["version"] = version
                self.assertEqual(apply_patch.validate_manifest(manifest, {"manifest.json": zipfile.ZipInfo("manifest.json")})["version"], version)
        self.assertEqual(make_patch.PATCH_VERSION, 2)
        self.assertEqual(apply_patch.SUPPORTED_VERSIONS, {1, 2})

    def test_manifest_rejects_boolean_patch_version(self) -> None:
        operation = {"type": "remove", "path": "a.bin", "old_size": 1, "old_sha256": "a" * 64}
        manifest = self.minimal_manifest(operation, old_count=1, new_count=0)
        manifest["version"] = True
        with self.assertRaisesRegex(RuntimeError, "Unsupported patch version"):
            apply_patch.validate_manifest(manifest, {"manifest.json": zipfile.ZipInfo("manifest.json")})

    def test_patch_archive_accepts_deflated_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            patch = Path(tmp) / "compressed.patch"
            with zipfile.ZipFile(patch, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", b"{}")
            with zipfile.ZipFile(patch, "r") as archive:
                members = apply_patch.read_archive_members(archive)
                self.assertEqual(members["manifest.json"].compress_type, zipfile.ZIP_DEFLATED)

    def test_patch_archive_accepts_lzma_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            patch = Path(tmp) / "compressed.patch"
            with zipfile.ZipFile(patch, "w", compression=zipfile.ZIP_LZMA) as archive:
                archive.writestr("manifest.json", b"{}")
            with zipfile.ZipFile(patch, "r") as archive:
                members = apply_patch.read_archive_members(archive)
                self.assertEqual(members["manifest.json"].compress_type, zipfile.ZIP_LZMA)

    def test_patch_archive_rejects_unsupported_bzip2_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            patch = Path(tmp) / "unsupported.patch"
            with zipfile.ZipFile(patch, "w", compression=zipfile.ZIP_BZIP2) as archive:
                archive.writestr("manifest.json", b"{}")
            with zipfile.ZipFile(patch, "r") as archive:
                with self.assertRaisesRegex(RuntimeError, "unsupported ZIP compression"):
                    apply_patch.read_archive_members(archive)

    def test_manifest_size_is_limited_before_reading(self) -> None:
        info = zipfile.ZipInfo("manifest.json")
        info.file_size = apply_patch.MAX_MANIFEST_SIZE + 1
        with self.assertRaisesRegex(RuntimeError, "Patch manifest is too large"):
            apply_patch.read_manifest(None, {"manifest.json": info})

    def test_manifest_rejects_duplicate_operation_paths(self) -> None:
        operation = {"type": "remove", "path": "a.bin", "old_size": 1, "old_sha256": "a" * 64}
        manifest = self.minimal_manifest(operation, old_count=2, new_count=0)
        manifest["operations"] = [operation, dict(operation)]
        with self.assertRaisesRegex(RuntimeError, "more than one operation"):
            apply_patch.validate_manifest(manifest, {"manifest.json": zipfile.ZipInfo("manifest.json")})

    def test_manifest_allows_case_only_rename_pair(self) -> None:
        remove = {"type": "remove", "path": "Folder/File.bin", "old_size": 1, "old_sha256": "a" * 64}
        add = {"type": "add", "path": "folder/file.bin", "payload": "files/payload.bin", "new_size": 1, "new_sha256": "b" * 64}
        member = zipfile.ZipInfo("files/payload.bin")
        member.file_size = 1
        manifest = self.minimal_manifest(remove, old_count=1, new_count=1)
        manifest["operations"] = [remove, add]
        validated = apply_patch.validate_manifest(manifest, {"manifest.json": zipfile.ZipInfo("manifest.json"), "files/payload.bin": member})
        self.assertEqual(validated["operations"], [remove, add])

    def test_manifest_rejects_operations_targeting_ignored_files(self) -> None:
        operation = {"type": "remove", "path": "Tools/Launcher.exe", "old_size": 1, "old_sha256": "a" * 64}
        manifest = self.minimal_manifest(operation, old_count=1, new_count=0)
        with self.assertRaisesRegex(RuntimeError, "intentionally ignores"):
            apply_patch.validate_manifest(manifest, {"manifest.json": zipfile.ZipInfo("manifest.json")})

    def test_manifest_rejects_windows_reserved_target(self) -> None:
        operation = {"type": "remove", "path": "CON.txt", "old_size": 1, "old_sha256": "a" * 64}
        manifest = self.minimal_manifest(operation, old_count=1, new_count=0)
        with self.assertRaisesRegex(RuntimeError, "unsafe path"):
            apply_patch.validate_manifest(manifest, {"manifest.json": zipfile.ZipInfo("manifest.json")})

    def test_temporary_path_collision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "a.bin"
            target.write_bytes(b"old")
            (root / "a.bin.tmp").write_bytes(b"mine")
            operation = {"type": "replace", "path": "a.bin"}
            with self.assertRaisesRegex(RuntimeError, "Temporary output path already exists"):
                apply_patch.check_temporary_paths(root, [operation])

    def test_file_to_directory_and_directory_to_file_topology(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "game"
            scratch = root / "scratch"
            destination.mkdir()
            scratch.mkdir()
            (destination / "Node").write_bytes(b"old")
            archive_path = root / "payload.patch"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("files/child.bin", b"child")
                archive.writestr("files/node.bin", b"new-node")

            remove_node = {"type": "remove", "path": "Node", "old_size": 3, "old_sha256": sha256_bytes(b"old")}
            add_child = {"type": "add", "path": "Node/child.txt", "payload": "files/child.bin", "new_size": 5, "new_sha256": sha256_bytes(b"child")}
            first_stdout = io.StringIO()
            with zipfile.ZipFile(archive_path, "r") as archive, mock.patch("sys.stdout", first_stdout):
                members = apply_patch.read_archive_members(archive)
                apply_patch.apply_operations(destination, archive, members, scratch, [add_child, remove_node])
            self.assertEqual((destination / "Node" / "child.txt").read_bytes(), b"child")
            self.assertEqual(
                first_stdout.getvalue().strip().splitlines(),
                ["[Removed 1/2] Node", f"[Added 2/2] {common.display_relative_path('Node/child.txt')}"],
            )

            remove_child = {"type": "remove", "path": "Node/child.txt", "old_size": 5, "old_sha256": sha256_bytes(b"child")}
            add_node = {"type": "add", "path": "Node", "payload": "files/node.bin", "new_size": 8, "new_sha256": sha256_bytes(b"new-node")}
            second_stdout = io.StringIO()
            with zipfile.ZipFile(archive_path, "r") as archive, mock.patch("sys.stdout", second_stdout):
                members = apply_patch.read_archive_members(archive)
                apply_patch.apply_operations(destination, archive, members, scratch, [add_node, remove_child])
            self.assertEqual((destination / "Node").read_bytes(), b"new-node")
            self.assertEqual(
                second_stdout.getvalue().strip().splitlines(),
                [f"[Removed 1/2] {common.display_relative_path('Node/child.txt')}", "[Added 2/2] Node"],
            )

    def test_backup_is_verified_before_modification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, backup = root / "base", root / "backup"
            base.mkdir()
            backup.mkdir()
            (base / "a.bin").write_bytes(b"old")
            operation = {"type": "replace", "path": "a.bin", "old_size": 3, "old_sha256": sha256_bytes(b"wrong")}
            with self.assertRaisesRegex(RuntimeError, "Recovery backup source verification failed"):
                apply_patch.backup_in_place(base, backup, [operation])

    def test_separate_copy_verifies_base_while_copying(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, destination = root / "base", root / "destination"
            make_warframe_root(base)
            (base / "Cache.Windows" / "data.bin").write_bytes(b"A" * 1024)
            (base / "Launcher.exe").write_bytes(b"ignored but copied")
            expected_files, expected_hash = common.scan_tree(base)

            copied_files, copied_hash = apply_patch.copy_verified_base(base, destination)

            self.assertEqual(copied_hash, expected_hash)
            self.assertEqual(set(copied_files), set(expected_files))
            self.assertEqual((destination / "Cache.Windows" / "data.bin").read_bytes(), b"A" * 1024)
            self.assertEqual((destination / "Launcher.exe").read_bytes(), b"ignored but copied")
            self.assertNotIn("Launcher.exe", copied_files)

    def test_tracked_old_file_avoids_rehashing_copied_base(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination, scratch = root / "destination", root / "scratch"
            destination.mkdir()
            scratch.mkdir()
            target = destination / "a.bin"
            target.write_bytes(b"old")
            stat = target.stat()
            tracked = {
                "a.bin": {"path": target, "size": 3, "sha256": sha256_bytes(b"old"), "mtime_ns": stat.st_mtime_ns}
            }
            operation = {
                "type": "replace", "path": "a.bin", "payload": "files/new.bin",
                "old_size": 3, "old_sha256": sha256_bytes(b"old"), "new_size": 3, "new_sha256": sha256_bytes(b"new"),
            }
            archive_path = root / "patch.zip"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as output:
                output.writestr("files/new.bin", b"new")
            with zipfile.ZipFile(archive_path, "r") as archive:
                members = apply_patch.read_archive_members(archive)
                original_verify = apply_patch.verify_file
                verified_paths: list[Path] = []

                def record_verify(path: Path, expected_size: int, expected_hash: str) -> None:
                    verified_paths.append(path)
                    original_verify(path, expected_size, expected_hash)

                with mock.patch.object(apply_patch, "verify_file", side_effect=record_verify):
                    apply_patch.apply_operations(destination, archive, members, scratch, [operation], tracked)

            self.assertEqual(target.read_bytes(), b"new")
            self.assertNotIn(target, verified_paths)
            self.assertEqual(tracked["a.bin"]["sha256"], sha256_bytes(b"new"))

    def test_tracked_final_verification_does_not_rehash_full_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination, scratch = root / "destination", root / "scratch"
            destination.mkdir()
            scratch.mkdir()
            target = destination / "unchanged.bin"
            target.write_bytes(b"unchanged")
            stat = target.stat()
            tracked = {
                "unchanged.bin": {"path": target, "size": 9, "sha256": sha256_bytes(b"unchanged"), "mtime_ns": stat.st_mtime_ns}
            }
            manifest = {"operations": [], "new_root_sha256": common.root_sha256_from_files(tracked), "new_file_count": 1}
            stdout = io.StringIO()
            with (
                mock.patch.object(apply_patch, "tree_matches", side_effect=AssertionError("full rehash should not run")),
                mock.patch("sys.stdout", stdout),
            ):
                duration = apply_patch.apply_and_verify(destination, mock.MagicMock(), {}, scratch, manifest, tracked)

            self.assertIsInstance(duration, float)
            self.assertIn("Patch operations:", stdout.getvalue())
            self.assertNotIn("Final verification:", stdout.getvalue())

    def test_in_place_backup_is_kept_if_base_changes_before_modification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            base.mkdir()
            patch = root / "test.patch"
            patch.write_bytes(b"patch")
            hpatchz = root / "hpatchz.exe"
            hpatchz.write_bytes(b"fake")
            work = root / "temp" / "apply_patch_test"
            work.mkdir(parents=True)
            base_files = {"a.bin": {"size": 3}}
            manifest = {
                "version": 1,
                "base": "U43.5.1",
                "base_steam_manifest_id": 4895911296145320793,
                "old_root_sha256": "a" * 64,
                "new_root_sha256": "b" * 64,
                "old_file_count": 1,
                "new_file_count": 0,
                "operations": [{"type": "remove", "path": "a.bin", "old_size": 3, "old_sha256": "c" * 64}],
            }
            archive = mock.MagicMock()
            archive.__enter__.return_value = archive
            archive.__exit__.return_value = False
            cleanup = mock.Mock()
            stderr = io.StringIO()

            with (
                mock.patch.object(apply_patch, "recover_interrupted_operations", return_value=None),
                mock.patch.object(apply_patch, "validate_warframe_installation", return_value=True),
                mock.patch.object(apply_patch, "HPATCHZ", hpatchz),
                mock.patch.object(apply_patch.zipfile, "ZipFile", return_value=archive),
                mock.patch.object(apply_patch, "read_archive_members", return_value={}),
                mock.patch.object(apply_patch, "read_manifest", return_value=manifest),
                mock.patch.object(apply_patch, "scan_tree", return_value=(base_files, "a" * 64)),
                mock.patch.object(apply_patch, "warn_if_low_disk_space_groups"),
                mock.patch.object(apply_patch, "make_work_dir", return_value=work),
                mock.patch.object(apply_patch, "check_temporary_paths"),
                mock.patch.object(apply_patch, "write_recovery_state"),
                mock.patch.object(apply_patch, "backup_in_place", return_value={"a.bin": True}),
                mock.patch.object(apply_patch, "verify_scanned_tree", side_effect=RuntimeError("changed")),
                mock.patch.object(apply_patch, "cleanup_work_dir", cleanup),
                mock.patch.object(apply_patch, "apply_and_verify") as apply_and_verify,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(apply_patch.run_locked_apply(base, patch, base, True), 1)

            cleanup.assert_not_called()
            apply_and_verify.assert_not_called()
            self.assertTrue((work / "backup").is_dir())
            self.assertIn("verified recovery backup was kept", stderr.getvalue())
            self.assertIn(str(work), stderr.getvalue())

    def test_separate_output_publication_refuses_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            working, destination = root / "working", root / "final"
            working.mkdir()
            destination.mkdir()
            (working / "ours.bin").write_bytes(b"ours")
            (destination / "theirs.bin").write_bytes(b"theirs")
            with self.assertRaisesRegex(FileExistsError, "Output path appeared"):
                apply_patch.publish_output_directory(working, destination)
            self.assertTrue((working / "ours.bin").is_file())
            self.assertEqual((destination / "theirs.bin").read_bytes(), b"theirs")

    def test_prepared_in_place_recovery_never_rolls_back_external_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            base.mkdir()
            (base / "changed.bin").write_bytes(b"external")
            work = root / "temp" / "apply_patch_test"
            backup = work / "backup"
            backup.mkdir(parents=True)
            (backup / "changed.bin").write_bytes(b"old")
            state = {
                "mode": "in_place", "phase": "prepared", "base": str(base), "destination": str(base), "patch": str(root / "test.patch"),
                "old_root_sha256": "a" * 64, "new_root_sha256": "b" * 64, "old_file_count": 1, "new_file_count": 1,
                "operations": [{"type": "replace", "path": "changed.bin"}], "existed": {"changed.bin": True},
            }
            write_recovery(work, state)
            with mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"), mock.patch.object(apply_patch, "tree_matches", return_value=False), mock.patch.object(apply_patch, "restore_in_place") as restore:
                with self.assertRaisesRegex(RuntimeError, "automatic rollback was intentionally skipped"):
                    apply_patch.recover_interrupted_operations(base, base)
            restore.assert_not_called()
            self.assertTrue(backup.is_dir())

    def test_v2_separate_recovery_publishes_completed_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, destination = root / "base", root / "final"
            make_warframe_root(base)
            work = root / "temp" / "apply_patch_test"
            working = apply_patch.separate_working_destination(destination, work)
            shutil.copytree(base, working)
            (working / "new.bin").write_bytes(b"new")
            old_hash, old_count = tree_identity(base)
            new_hash, new_count = tree_identity(working)
            state = {
                "mode": "separate", "phase": "publishing", "base": str(base), "destination": str(destination), "working_destination": str(working), "patch": str(root / "one.patch"),
                "old_root_sha256": old_hash, "new_root_sha256": new_hash, "old_file_count": old_count, "new_file_count": new_count,
            }
            write_recovery(work, state)
            with mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"), mock.patch.object(common, "TEMP_ROOT", root / "temp"):
                completed = apply_patch.recover_interrupted_operations(base, destination)
            self.assertIsNotNone(completed)
            self.assertFalse(working.exists())
            self.assertEqual((destination / "new.bin").read_bytes(), b"new")

    def test_rollback_restores_original_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, backup = root / "base", root / "backup"
            base.mkdir()
            backup.mkdir()
            (backup / "old.bin").write_bytes(b"original")
            (base / "old.bin").write_bytes(b"modified")
            (base / "added.bin").write_bytes(b"added")
            operations = [{"type": "replace", "path": "old.bin"}, {"type": "add", "path": "added.bin"}]
            apply_patch.rollback_in_place(base, backup, operations, {"old.bin": True, "added.bin": False})
            self.assertEqual((base / "old.bin").read_bytes(), b"original")
            self.assertFalse((base / "added.bin").exists())

    def test_recovery_rejects_boolean_recovery_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            base.mkdir()
            work = root / "temp" / "apply_patch_test"
            work.mkdir(parents=True)
            (work / apply_patch.RECOVERY_FILE).write_text(json.dumps({"recovery_version": True}), encoding="utf-8")
            stderr = io.StringIO()
            with (
                mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"),
                mock.patch("sys.stderr", stderr),
            ):
                self.assertIsNone(apply_patch.recover_interrupted_operations(base, base))
            self.assertIn("Unsupported recovery state", stderr.getvalue())
            self.assertTrue(work.exists())

    def test_recovery_restores_broken_warframe_root_before_normal_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            make_warframe_root(base)
            (base / "Tools" / "tool.bin").write_bytes(b"tool")
            old_hash, old_count = tree_identity(base)
            work = root / "temp" / "apply_patch_test"
            backup = work / "backup"
            (backup / "Tools").mkdir(parents=True)
            (backup / "Tools" / "tool.bin").write_bytes(b"tool")
            shutil.rmtree(base / "Tools")
            (base / "Tools").write_bytes(b"bad topology")
            new_hash, new_count = "f" * 64, 999
            operations = [
                {"type": "remove", "path": "Tools/tool.bin", "old_size": 4, "old_sha256": sha256_bytes(b"tool")},
                {"type": "add", "path": "Tools", "new_size": 12, "new_sha256": sha256_bytes(b"bad topology")},
            ]
            state = {
                "mode": "in_place", "base": str(base), "destination": str(base), "patch": str(root / "missing.patch"),
                "old_root_sha256": old_hash, "new_root_sha256": new_hash, "old_file_count": old_count, "new_file_count": new_count,
                "operations": operations, "existed": {"Tools/tool.bin": True, "Tools": False},
            }
            write_recovery(work, state, recovery_version=1)
            with mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"), mock.patch.object(common, "TEMP_ROOT", root / "temp"):
                recovered = apply_patch.recover_interrupted_operations(base, base)
            self.assertIsNone(recovered)
            self.assertTrue(common.validate_warframe_installation(base, "Base"))
            self.assertEqual((base / "Tools" / "tool.bin").read_bytes(), b"tool")

    def test_main_recovers_before_warframe_root_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            make_warframe_root(base)
            (base / "Tools" / "tool.bin").write_bytes(b"tool")
            old_hash, old_count = tree_identity(base)
            work = root / "temp" / "apply_patch_test"
            backup = work / "backup"
            (backup / "Tools").mkdir(parents=True)
            (backup / "Tools" / "tool.bin").write_bytes(b"tool")
            shutil.rmtree(base / "Tools")
            (base / "Tools").write_bytes(b"bad topology")
            operations = [
                {"type": "remove", "path": "Tools/tool.bin", "old_size": 4, "old_sha256": sha256_bytes(b"tool")},
                {"type": "add", "path": "Tools", "new_size": 12, "new_sha256": sha256_bytes(b"bad topology")},
            ]
            state = {
                "mode": "in_place", "base": str(base), "destination": str(base), "patch": str(root / "missing.patch"),
                "old_root_sha256": old_hash, "new_root_sha256": "f" * 64, "old_file_count": old_count, "new_file_count": 999,
                "operations": operations, "existed": {"Tools/tool.bin": True, "Tools": False},
            }
            write_recovery(work, state, recovery_version=1)
            stderr = io.StringIO()
            argv = ["apply_patch.py", str(base), str(root / "missing.patch"), "--in-place"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"),
                mock.patch.object(common, "TEMP_ROOT", root / "temp"),
                mock.patch.object(apply_patch, "operation_lock", side_effect=lambda *args: nullcontext()),
                mock.patch.object(apply_patch, "install_termination_handlers"),
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(apply_patch.main(), 1)
            self.assertTrue(common.validate_warframe_installation(base, "Base"))
            self.assertIn("Patch file does not exist", stderr.getvalue())
            self.assertNotIn("not a Warframe installation root", stderr.getvalue())

    def test_end_to_end_create_and_apply_keeps_current_patch_format_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, new, destination = root / "base", root / "new", root / "applied"
            make_warframe_root(base)
            shutil.copytree(base, new)
            old_data = b"A" * 256
            new_data = b"B" * 256
            (base / "Cache.Windows" / "data.bin").write_bytes(old_data)
            (new / "Cache.Windows" / "data.bin").write_bytes(new_data)
            base_files, base_hash = common.scan_tree(base)
            index_path = root / "index.json"
            index_path.write_text(
                json.dumps({
                    "U43.5.1": {
                        "steam_manifest_id": 4895911296145320793,
                        "sha256": base_hash,
                        "file_count": len(base_files),
                    }
                }),
                encoding="utf-8",
            )
            hdiffz, hpatchz = root / "hdiffz.exe", root / "hpatchz.exe"
            hdiffz.write_bytes(b"fake")
            hpatchz.write_bytes(b"fake")
            patch_path = root / "U43.5.2.patch"
            temp_root = root / "temp"

            def fake_hdiff(
                old_path: Path,
                new_path: Path,
                output: Path,
                mode_options: list[str],
                common_options: list[str],
            ) -> None:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"d")

            make_argv = ["make_patch.py", str(base), str(new), str(patch_path), "U43.5.1"]
            make_stdout = io.StringIO()
            with (
                mock.patch.object(sys, "argv", make_argv),
                mock.patch.object(common, "INDEX_FILE", index_path),
                mock.patch.object(common, "TEMP_ROOT", temp_root),
                mock.patch.object(make_patch, "TEMP_ROOT", temp_root),
                mock.patch.object(make_patch, "HDIFFZ", hdiffz),
                mock.patch.object(make_patch, "operation_lock", side_effect=lambda *args: nullcontext()),
                mock.patch.object(make_patch, "process_identity", return_value="test-process"),
                mock.patch.object(make_patch, "run_hdiff_command", side_effect=fake_hdiff),
                mock.patch.object(make_patch, "install_termination_handlers"),
                mock.patch("sys.stdout", make_stdout),
            ):
                self.assertEqual(make_patch.main(), 0)
            self.assertIn(f"[Diffing 1/1] {common.display_relative_path('Cache.Windows/data.bin')} (memory mode)", make_stdout.getvalue())
            self.assertIn(f"[Finished 1/1] {common.display_relative_path('Cache.Windows/data.bin')}", make_stdout.getvalue())
            self.assertIn(f"Patch size: {common.format_bytes(patch_path.stat().st_size)}", make_stdout.getvalue())

            with zipfile.ZipFile(patch_path, "r") as archive:
                manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest["version"], 2)
            self.assertEqual(manifest["base_steam_manifest_id"], 4895911296145320793)

            def fake_hpatch(command: list[str]) -> int:
                Path(command[-1]).write_bytes(new_data)
                return 0

            apply_argv = ["apply_patch.py", str(base), str(patch_path), "--output", str(destination)]
            apply_stdout = io.StringIO()
            with (
                mock.patch.object(sys, "argv", apply_argv),
                mock.patch.object(common, "TEMP_ROOT", temp_root),
                mock.patch.object(apply_patch, "TEMP_ROOT", temp_root),
                mock.patch.object(apply_patch, "HPATCHZ", hpatchz),
                mock.patch.object(apply_patch, "operation_lock", side_effect=lambda *args: nullcontext()),
                mock.patch.object(apply_patch, "process_identity", return_value="test-process"),
                mock.patch.object(apply_patch, "scan_tree", side_effect=AssertionError("separate mode should not pre-hash the base")),
                mock.patch.object(apply_patch, "run_child", side_effect=fake_hpatch),
                mock.patch.object(apply_patch, "install_termination_handlers"),
                mock.patch("sys.stdout", apply_stdout),
            ):
                self.assertEqual(apply_patch.main(), 0)
            self.assertIn(f"[Patched 1/1] {common.display_relative_path('Cache.Windows/data.bin')}", apply_stdout.getvalue())

            expected_hash, expected_count = tree_identity(new)
            actual_hash, actual_count = tree_identity(destination)
            self.assertEqual((actual_hash, actual_count), (expected_hash, expected_count))

    def test_completed_separate_recovery_keeps_patch_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, destination = root / "base", root / "out"
            make_warframe_root(base)
            shutil.copytree(base, destination)
            (destination / "new.bin").write_bytes(b"new")
            old_hash, old_count = tree_identity(base)
            new_hash, new_count = tree_identity(destination)
            work = root / "temp" / "apply_patch_test"
            state = {
                "mode": "separate", "base": str(base), "destination": str(destination), "patch": str(root / "one.patch"),
                "old_root_sha256": old_hash, "new_root_sha256": new_hash, "old_file_count": old_count, "new_file_count": new_count,
            }
            write_recovery(work, state, recovery_version=1)
            with mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"), mock.patch.object(common, "TEMP_ROOT", root / "temp"):
                completed = apply_patch.recover_interrupted_operations(base, destination)
            self.assertIsNotNone(completed)
            matching = {"old_root_sha256": old_hash, "new_root_sha256": new_hash, "old_file_count": old_count, "new_file_count": new_count}
            different = dict(matching, new_root_sha256="0" * 64)
            self.assertTrue(apply_patch.recovery_matches_manifest(completed, matching))
            self.assertFalse(apply_patch.recovery_matches_manifest(completed, different))
            self.assertTrue(destination.exists())

if __name__ == "__main__":
    unittest.main()
