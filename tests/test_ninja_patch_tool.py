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
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import apply_patch
import common
import make_patch

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def make_warframe_root(root: Path) -> None:
    (root / "Cache.Windows").mkdir(parents=True, exist_ok=True)
    (root / "Tools").mkdir(exist_ok=True)
    (root / "Warframe.x64.exe").write_bytes(b"exe")

def tree_identity(root: Path) -> tuple[str, int]:
    files, digest = common.scan_tree(root)
    return digest, len(files)

def write_recovery(work: Path, state: dict) -> None:
    work.mkdir(parents=True, exist_ok=True)
    (work / apply_patch.RECOVERY_FILE).write_text(
        json.dumps({"recovery_version": apply_patch.RECOVERY_VERSION, "pid": -1, **state}),
        encoding="utf-8",
    )

class CommonTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            common.parse_json('{"a": 1, "a": 2}')

    def test_sha256_validation_is_strict(self) -> None:
        self.assertTrue(common.is_sha256("a" * 64))
        self.assertTrue(common.is_sha256("ABCDEF0123456789" * 4))
        for value in ("+" + "a" * 63, "-" + "a" * 63, " " + "a" * 63, "g" * 64, "a" * 63, True, None):
            self.assertFalse(common.is_sha256(value))

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
            self.assertTrue(common.is_warframe_installation(root))
            self.assertFalse(common.is_warframe_installation(root.parent))

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
            with mock.patch.object(make_patch, "TEMP_ROOT", temp_root), mock.patch.object(make_patch, "process_is_running", return_value=False):
                make_patch.cleanup_stale_make_patch_work(output)
            self.assertFalse(partial.exists())
            self.assertFalse(work.exists())

    def test_archive_contains_only_patch_format_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            (work / "diffs").mkdir(parents=True)
            (work / "files").mkdir()
            (work / "manifest.json").write_text("{}", encoding="utf-8")
            (work / "session.json").write_text("secret", encoding="utf-8")
            (work / "diffs" / "a.hdiff").write_bytes(b"diff")
            (work / "files" / "b.bin").write_bytes(b"file")
            output = root / "test.patch"
            make_patch.create_patch_archive(work, output)
            with zipfile.ZipFile(output, "r") as archive:
                self.assertEqual(set(archive.namelist()), {"manifest.json", "diffs/a.hdiff", "files/b.bin"})

    def test_create_archive_refuses_preexisting_tmp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            (work / "diffs").mkdir(parents=True)
            (work / "files").mkdir()
            (work / "manifest.json").write_text("{}", encoding="utf-8")
            output = root / "test.patch"
            partial = make_patch.temporary_patch_path(output)
            partial.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                make_patch.create_patch_archive(work, output)
            self.assertEqual(partial.read_bytes(), b"keep")

    def test_create_archive_never_overwrites_output_created_during_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            (work / "diffs").mkdir(parents=True)
            (work / "files").mkdir()
            (work / "manifest.json").write_text("{}", encoding="utf-8")
            output = root / "test.patch"
            original_publish = make_patch.publish_patch_archive

            def race(temporary: Path, destination: Path) -> None:
                destination.write_bytes(b"unrelated")
                original_publish(temporary, destination)

            with mock.patch.object(make_patch, "publish_patch_archive", side_effect=race):
                with self.assertRaisesRegex(FileExistsError, "appeared while the patch was being created"):
                    make_patch.create_patch_archive(work, output)

            self.assertEqual(output.read_bytes(), b"unrelated")
            self.assertFalse(make_patch.temporary_patch_path(output).exists())

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
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(make_patch.main(), 1)
            self.assertIn("Patch output must not be inside", stderr.getvalue())

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

    def test_manifest_rejects_duplicate_operation_paths(self) -> None:
        operation = {"type": "remove", "path": "a.bin", "old_size": 1, "old_sha256": "a" * 64}
        manifest = self.minimal_manifest(operation, old_count=2, new_count=0)
        manifest["operations"] = [operation, dict(operation)]
        with self.assertRaisesRegex(RuntimeError, "more than one operation"):
            apply_patch.validate_manifest(manifest, {"manifest.json": zipfile.ZipInfo("manifest.json")})

    def test_manifest_rejects_case_only_duplicate_paths(self) -> None:
        first = {"type": "remove", "path": "Folder/File.bin", "old_size": 1, "old_sha256": "a" * 64}
        second = {"type": "remove", "path": "folder/file.bin", "old_size": 1, "old_sha256": "b" * 64}
        manifest = self.minimal_manifest(first, old_count=2, new_count=0)
        manifest["operations"] = [first, second]
        with self.assertRaisesRegex(RuntimeError, "more than one operation"):
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
            with zipfile.ZipFile(archive_path, "r") as archive:
                members = apply_patch.read_archive_members(archive)
                apply_patch.apply_operations(destination, archive, members, scratch, [add_child, remove_node])
            self.assertEqual((destination / "Node" / "child.txt").read_bytes(), b"child")

            remove_child = {"type": "remove", "path": "Node/child.txt", "old_size": 5, "old_sha256": sha256_bytes(b"child")}
            add_node = {"type": "add", "path": "Node", "payload": "files/node.bin", "new_size": 8, "new_sha256": sha256_bytes(b"new-node")}
            with zipfile.ZipFile(archive_path, "r") as archive:
                members = apply_patch.read_archive_members(archive)
                apply_patch.apply_operations(destination, archive, members, scratch, [add_node, remove_child])
            self.assertEqual((destination / "Node").read_bytes(), b"new-node")

    def test_backup_is_verified_before_modification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, backup = root / "base", root / "backup"
            base.mkdir()
            backup.mkdir()
            (base / "a.bin").write_bytes(b"old")
            operation = {"type": "replace", "path": "a.bin", "old_size": 3, "old_sha256": sha256_bytes(b"old")}

            def corrupt_copy(source: Path, destination: Path) -> None:
                Path(destination).write_bytes(b"bad")

            with mock.patch.object(apply_patch.shutil, "copy2", side_effect=corrupt_copy):
                with self.assertRaisesRegex(RuntimeError, "SHA-256 verification failed|Size verification failed"):
                    apply_patch.backup_in_place(base, backup, [operation])

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
            write_recovery(work, state)
            with mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"), mock.patch.object(common, "TEMP_ROOT", root / "temp"):
                recovered = apply_patch.recover_interrupted_operations(base, base)
            self.assertIsNone(recovered)
            self.assertTrue(common.is_warframe_installation(base))
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
            write_recovery(work, state)
            stderr = io.StringIO()
            argv = ["apply_patch.py", str(base), str(root / "missing.patch"), "--in-place"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"),
                mock.patch.object(common, "TEMP_ROOT", root / "temp"),
                mock.patch.object(apply_patch, "install_termination_handlers"),
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(apply_patch.main(), 1)
            self.assertTrue(common.is_warframe_installation(base))
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
            with (
                mock.patch.object(sys, "argv", make_argv),
                mock.patch.object(common, "INDEX_FILE", index_path),
                mock.patch.object(common, "TEMP_ROOT", temp_root),
                mock.patch.object(make_patch, "TEMP_ROOT", temp_root),
                mock.patch.object(make_patch, "HDIFFZ", hdiffz),
                mock.patch.object(make_patch, "run_hdiff_command", side_effect=fake_hdiff),
                mock.patch.object(make_patch, "install_termination_handlers"),
            ):
                self.assertEqual(make_patch.main(), 0)

            with zipfile.ZipFile(patch_path, "r") as archive:
                manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest["version"], 1)
            self.assertEqual(manifest["base_steam_manifest_id"], 4895911296145320793)

            def fake_hpatch(command: list[str]) -> int:
                Path(command[-1]).write_bytes(new_data)
                return 0

            apply_argv = ["apply_patch.py", str(base), str(patch_path), "--output", str(destination)]
            with (
                mock.patch.object(sys, "argv", apply_argv),
                mock.patch.object(common, "TEMP_ROOT", temp_root),
                mock.patch.object(apply_patch, "TEMP_ROOT", temp_root),
                mock.patch.object(apply_patch, "HPATCHZ", hpatchz),
                mock.patch.object(apply_patch, "run_child", side_effect=fake_hpatch),
                mock.patch.object(apply_patch, "install_termination_handlers"),
            ):
                self.assertEqual(apply_patch.main(), 0)

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
            write_recovery(work, state)
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
