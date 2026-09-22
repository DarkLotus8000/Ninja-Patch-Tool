# Run from the project root with: py -m unittest discover -s tests
from __future__ import annotations

import ast
import contextlib
import errno
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import ModuleType, SimpleNamespace
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
import verify_base

_LIVE_STATUS_PATCHES: list[object] = []

class FakeSteamQueryProcess:
    def __init__(self, *, running: bool = False, returncode: int = 0):
        self.running = running
        self.returncode = None if running else returncode

    def poll(self):
        return None if self.running else self.returncode

    def wait(self, timeout=None):
        if self.running:
            raise subprocess.TimeoutExpired("steam-worker", timeout)
        return self.returncode

    def terminate(self):
        self.running = False
        self.returncode = -15

    def kill(self):
        self.running = False
        self.returncode = -9

    def communicate(self, timeout=None):
        return "", None

def setUpModule() -> None:
    for module in (add_base, apply_patch, make_patch, verify_base):
        patcher = mock.patch.object(module, "print_live_status_once")
        patcher.start()
        _LIVE_STATUS_PATCHES.append(patcher)

def tearDownModule() -> None:
    while _LIVE_STATUS_PATCHES:
        _LIVE_STATUS_PATCHES.pop().stop()

def make_steam_appinfo_v41(manifest_id: int, size: int, download: int = 1) -> bytes:
    keys = ["appinfo", "depots", "230411", "manifests", "public", "gid", "size", "download"]
    indexes = {key: index for index, key in enumerate(keys)}

    def obj(key: str, content: bytes) -> bytes:
        return b"\x00" + indexes[key].to_bytes(4, "little") + content + b"\x08"

    def string(key: str, value: object) -> bytes:
        return b"\x01" + indexes[key].to_bytes(4, "little") + str(value).encode("ascii") + b"\0"

    public = string("gid", manifest_id) + string("size", size) + string("download", download)
    payload = obj("appinfo", obj("depots", obj("230411", obj("manifests", obj("public", public))))) + b"\x08"
    fixed_header = (
        (1).to_bytes(4, "little")
        + (123).to_bytes(4, "little")
        + (456).to_bytes(8, "little")
        + b"0" * 20
        + (789).to_bytes(4, "little")
        + b"1" * 20
    )
    entry_size = 60 + len(payload)
    entry = (230410).to_bytes(4, "little") + entry_size.to_bytes(4, "little") + fixed_header + payload
    string_table_offset = 16 + len(entry) + 4
    header = (
        (0x07564429).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + string_table_offset.to_bytes(8, "little")
    )
    string_table = len(keys).to_bytes(4, "little") + b"".join(key.encode("utf-8") + b"\0" for key in keys)
    return header + entry + b"\0" * 4 + string_table

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def add_release_manifest(files: dict[str, bytes], version: str) -> None:
    managed = {
        name: sha256_bytes(payload)
        for name, payload in files.items()
        if name not in common.PRESERVED_RELEASE_FILES and name != common.RELEASE_MANIFEST_FILE
    }
    files[common.RELEASE_MANIFEST_FILE] = (
        json.dumps(
            {
                "format_version": common.RELEASE_MANIFEST_VERSION,
                "application_version": version,
                "files": managed,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

def write_stage_release_manifest(stage: Path, version: str = common.VERSION) -> None:
    files: dict[str, str] = {}
    for path in stage.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(stage).as_posix()
        if relative == common.RELEASE_MANIFEST_FILE or relative in common.PRESERVED_RELEASE_FILES:
            continue
        files[relative] = common.sha256_file(path)
    (stage / common.RELEASE_MANIFEST_FILE).parent.mkdir(parents=True, exist_ok=True)
    (stage / common.RELEASE_MANIFEST_FILE).write_text(
        json.dumps(
            {
                "format_version": common.RELEASE_MANIFEST_VERSION,
                "application_version": version,
                "files": files,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

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
    def test_display_version_hides_zero_patch_component(self) -> None:
        self.assertEqual(common.display_version("1.0.0"), "1.0")
        self.assertEqual(common.display_version("1.5.0"), "1.5")
        self.assertEqual(common.display_version("1.5.1"), "1.5.1")
        self.assertEqual(common.display_version("1.5"), "1.5")

    def test_steam_appinfo_v41_reports_valid_and_empty_manifest_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "appinfo.vdf"
            path.write_bytes(make_steam_appinfo_v41(4895911296145320793, 52 * 1024**3, 30 * 1024**3))
            valid = common.read_steam_cached_public_manifest(path)
            self.assertEqual(valid["manifest_id"], 4895911296145320793)
            self.assertEqual(valid["status"], "valid")

            path.write_bytes(make_steam_appinfo_v41(5112463999164762556, 0, 0))
            empty = common.read_steam_cached_public_manifest(path)
            self.assertEqual(empty["manifest_id"], 5112463999164762556)
            self.assertEqual(empty["status"], "invalid")

    def test_steam_manifest_zero_download_is_invalid_even_with_nonzero_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "appinfo.vdf"
            path.write_bytes(make_steam_appinfo_v41(5112463999164762556, 52 * 1024**3, 0))
            info = common.read_steam_cached_public_manifest(path)
        self.assertEqual(info["status"], "invalid")

    def test_steam_manifest_smaller_than_ten_gib_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "appinfo.vdf"
            path.write_bytes(make_steam_appinfo_v41(123456789, 10 * 1024**3 - 1, 5 * 1024**3))
            info = common.read_steam_cached_public_manifest(path)
        self.assertEqual(info["status"], "invalid")

    def test_direct_steam_live_query_does_not_require_desktop_client(self) -> None:
        token_modes: list[bool] = []

        class FakeSteamClient:
            logged_on = False

            def anonymous_login(self):
                self.logged_on = True
                return 1

            def get_product_info(self, apps, timeout, auto_access_tokens=True):
                token_modes.append(auto_access_tokens)
                return {
                    "apps": {
                        common.WARFRAME_STEAM_APP_ID: {
                            "depots": {
                                str(common.WARFRAME_STEAM_DEPOT_ID): {
                                    "manifests": {"public": {"gid": "123", "size": str(52 * 1024**3), "download": str(30 * 1024**3)}}
                                }
                            },
                            "_missing_token": False,
                        }
                    }
                }

            def logout(self):
                self.logged_on = False

            def disconnect(self):
                pass

        steam_package = ModuleType("steam")
        steam_package.__path__ = []
        steam_client = ModuleType("steam.client")
        steam_client.SteamClient = FakeSteamClient
        with mock.patch.dict(sys.modules, {"steam": steam_package, "steam.client": steam_client}):
            info = common.query_steam_public_manifest(timeout=4)
        self.assertEqual(info["manifest_id"], 123)
        self.assertEqual(info["status"], "valid")
        self.assertEqual(info["source_kind"], "live")
        self.assertEqual(set(info), {"manifest_id", "size", "status", "source_kind"})
        self.assertEqual(token_modes, [False])

    def test_direct_steam_live_query_requests_access_token_only_when_required(self) -> None:
        token_modes: list[bool] = []

        class FakeSteamClient:
            logged_on = False

            def anonymous_login(self):
                self.logged_on = True
                return 1

            def get_product_info(self, apps, timeout, auto_access_tokens=True):
                token_modes.append(auto_access_tokens)
                if not auto_access_tokens:
                    return {"apps": {common.WARFRAME_STEAM_APP_ID: {"_missing_token": True}}}
                return {
                    "apps": {
                        common.WARFRAME_STEAM_APP_ID: {
                            "depots": {
                                str(common.WARFRAME_STEAM_DEPOT_ID): {
                                    "manifests": {"public": {"gid": "123", "size": str(52 * 1024**3), "download": str(30 * 1024**3)}}
                                }
                            },
                            "_missing_token": False,
                        }
                    }
                }

            def logout(self):
                self.logged_on = False

            def disconnect(self):
                pass

        steam_package = ModuleType("steam")
        steam_package.__path__ = []
        steam_client = ModuleType("steam.client")
        steam_client.SteamClient = FakeSteamClient
        with mock.patch.dict(sys.modules, {"steam": steam_package, "steam.client": steam_client}):
            info = common.query_steam_public_manifest(timeout=4)
        self.assertEqual(info["manifest_id"], 123)
        self.assertEqual(token_modes, [False, True])

    def test_start_steam_query_subprocess_attaches_parent_death_job(self) -> None:
        process = mock.Mock()
        with (
            mock.patch.object(subprocess, "Popen", return_value=process),
            mock.patch.object(common, "_attach_steam_worker_kill_job") as attach,
        ):
            result = common.start_steam_query_subprocess(timeout=4, entry_script=Path(common.__file__))
        self.assertIs(result, process)
        attach.assert_called_once_with(process)

    def test_start_steam_query_subprocess_continues_when_parent_death_job_is_unavailable(self) -> None:
        process = mock.Mock()
        with (
            mock.patch.object(subprocess, "Popen", return_value=process),
            mock.patch.object(common, "_attach_steam_worker_kill_job", side_effect=OSError(5, "job denied")),
        ):
            result = common.start_steam_query_subprocess(timeout=4, entry_script=Path(common.__file__))
        self.assertIs(result, process)
        process.kill.assert_not_called()

    def test_hidden_steam_query_worker_rejects_malformed_internal_arguments(self) -> None:
        for arguments in (
            ["--internal-steam-query-worker"],
            ["--internal-steam-query-worker", "not-a-number"],
            ["--internal-steam-query-worker", "0"],
            ["--internal-steam-query-worker", "61"],
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = common.handle_steam_query_worker_request(arguments)
            self.assertEqual(result, 2)
            line = output.getvalue().strip()
            self.assertTrue(line.startswith(common.STEAM_QUERY_RESULT_PREFIX))
            payload = json.loads(line[len(common.STEAM_QUERY_RESULT_PREFIX):])
            self.assertFalse(payload["ok"])

    def test_hidden_steam_query_worker_smoke_mode_imports_dependency_without_network(self) -> None:
        steam_package = ModuleType("steam")
        steam_package.__path__ = []
        steam_client = ModuleType("steam.client")
        steam_client.SteamClient = object
        output = io.StringIO()
        with (
            mock.patch.dict(sys.modules, {"steam": steam_package, "steam.client": steam_client}),
            contextlib.redirect_stdout(output),
        ):
            result = common.handle_steam_query_worker_request([common.STEAM_QUERY_WORKER_SMOKE_ARGUMENT])
        self.assertEqual(result, 0)
        line = output.getvalue().strip()
        payload = json.loads(line[len(common.STEAM_QUERY_RESULT_PREFIX):])
        self.assertEqual(payload, {"ok": True, "smoke": "steam-import"})

    def test_hidden_steam_query_worker_returns_json_result(self) -> None:
        info = {
            "manifest_id": 123,
            "size": 52 * 1024**3,
            "status": "valid",
            "source_kind": "live",
        }
        output = io.StringIO()
        with (
            mock.patch.object(common, "query_steam_public_manifest", return_value=info),
            contextlib.redirect_stdout(output),
        ):
            result = common.handle_steam_query_worker_request(["--internal-steam-query-worker", "4"])
        self.assertEqual(result, 0)
        line = output.getvalue().strip()
        self.assertTrue(line.startswith(common.STEAM_QUERY_RESULT_PREFIX))
        payload = json.loads(line[len(common.STEAM_QUERY_RESULT_PREFIX):])
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["info"]["manifest_id"], 123)

    def test_steam_worker_collector_ignores_noise_and_validates_tagged_schema(self) -> None:
        info = {
            "manifest_id": 123,
            "size": 52 * 1024**3,
            "status": "valid",
            "source_kind": "live",
        }

        class Process:
            returncode = 0
            def poll(self):
                return 0
            def communicate(self, timeout=None):
                payload = json.dumps({"ok": True, "info": info}, separators=(",", ":"))
                return f"noise\n{common.STEAM_QUERY_RESULT_PREFIX}{payload}\n", None

        result, error = common.collect_steam_query_subprocess(Process())
        self.assertIsNone(error)
        self.assertEqual(result["manifest_id"], 123)

    def test_steam_worker_collector_rejects_inconsistent_status(self) -> None:
        info = {
            "manifest_id": 123,
            "size": 1024,
            "status": "valid",
            "source_kind": "live",
        }

        class Process:
            returncode = 0
            def poll(self):
                return 0
            def communicate(self, timeout=None):
                payload = json.dumps({"ok": True, "info": info}, separators=(",", ":"))
                return common.STEAM_QUERY_RESULT_PREFIX + payload + "\n", None

        result, error = common.collect_steam_query_subprocess(Process())
        self.assertIsNone(result)
        self.assertIn("inconsistent manifest status", error)

    def test_steam_worker_collector_rejects_extra_info_fields_and_non_live_source(self) -> None:
        base = {
            "manifest_id": 123,
            "size": 52 * 1024**3,
            "status": "valid",
            "source_kind": "live",
        }

        class Process:
            returncode = 0
            def __init__(self, info):
                self.info = info
            def poll(self):
                return 0
            def communicate(self, timeout=None):
                payload = json.dumps({"ok": True, "info": self.info}, separators=(",", ":"))
                return common.STEAM_QUERY_RESULT_PREFIX + payload + "\n", None

        result, error = common.collect_steam_query_subprocess(Process(dict(base, extra=True)))
        self.assertIsNone(result)
        self.assertIn("invalid info schema", error)

        result, error = common.collect_steam_query_subprocess(Process(dict(base, source_kind="cache")))
        self.assertIsNone(result)
        self.assertIn("unexpected source kind", error)

    def test_live_status_snapshot_uses_warframe_and_steam_labels(self) -> None:
        process = FakeSteamQueryProcess()
        with (
            mock.patch.object(common, "fetch_current_warframe_version", return_value="44.0"),
            mock.patch.object(common, "start_steam_query_subprocess", return_value=process),
            mock.patch.object(
                common,
                "collect_steam_query_subprocess",
                return_value=({"manifest_id": 123, "size": 52 * 1024**3, "status": "valid", "source_kind": "live"}, None),
            ),
        ):
            self.assertEqual(
                common.live_status_lines(),
                ["[Warframe] Live version: U44.0", "[Steam] Live manifest: 123 (52.0 GiB)"],
            )

    def test_live_status_missing_provenance_is_not_treated_as_live(self) -> None:
        process = FakeSteamQueryProcess()
        with (
            mock.patch.object(common, "fetch_current_warframe_version", return_value="44.0"),
            mock.patch.object(common, "start_steam_query_subprocess", return_value=process),
            mock.patch.object(
                common,
                "collect_steam_query_subprocess",
                return_value=({"manifest_id": 123, "size": 52 * 1024**3, "status": "valid"}, None),
            ),
        ):
            lines = common.live_status_lines()
        self.assertEqual(lines[0], "[Warframe] Live version: U44.0")
        self.assertEqual(lines[1], "[Steam] Live manifest unavailable (invalid Steam manifest source).")

    def test_live_status_snapshot_has_hard_overall_deadline(self) -> None:
        process = FakeSteamQueryProcess(running=True)
        with (
            mock.patch.object(common, "fetch_current_warframe_version", return_value="44.0"),
            mock.patch.object(common, "start_steam_query_subprocess", return_value=process),
            mock.patch.object(common, "terminate_steam_query_subprocess") as terminate,
            mock.patch.object(common, "steam_manifest_with_cache_fallback", return_value=(None, "live status check timed out after 0.05 seconds")),
        ):
            lines = common.live_status_lines(timeout=0.05)
        terminate.assert_called_once_with(process)
        self.assertEqual(lines[0], "[Warframe] Live version: U44.0")
        self.assertEqual(lines[1], "[Steam] Live manifest unavailable (query timed out).")

    def test_steam_appinfo_cache_reuses_unchanged_file_and_refreshes_after_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "appinfo.vdf"
            path.write_bytes(make_steam_appinfo_v41(111, 1024, 512))
            first = common.read_steam_cached_public_manifest(path)
            with mock.patch.object(Path, "read_bytes", wraps=Path.read_bytes) as read_bytes:
                second = common.read_steam_cached_public_manifest(path)
                self.assertEqual(read_bytes.call_count, 0)
            self.assertEqual(first["manifest_id"], second["manifest_id"])

            path.write_bytes(make_steam_appinfo_v41(222, 2048, 1024))
            stat = path.stat()
            os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
            refreshed = common.read_steam_cached_public_manifest(path)
            self.assertEqual(refreshed["manifest_id"], 222)

    def test_console_severity_colors_are_restrained(self) -> None:
        stream = io.StringIO()
        message = "WARNING: warning\nERROR: error\n[Verified] stays plain"
        with mock.patch.object(common, "console_supports_color", return_value=True):
            styled = common.style_console_text(message, stream)
        self.assertIn("\x1b[33mWARNING:\x1b[0m", styled)
        self.assertIn("\x1b[31mERROR:\x1b[0m", styled)
        self.assertIn("[Verified]", styled)
        self.assertNotIn("\x1b[31m[Verified]", styled)
        self.assertNotIn("\x1b[33m[Verified]", styled)

    def test_console_title_includes_tool_version_and_restores_previous_title(self) -> None:
        calls: list[str] = []

        class Function:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                return self.callback(*args)

        class Kernel32:
            def __init__(self):
                self.GetConsoleTitleW = Function(self.get_console_title)
                self.SetConsoleTitleW = Function(self.set_console_title)

            @staticmethod
            def get_console_title(buffer, size):
                buffer.value = "Original Title"
                return len(buffer.value)

            @staticmethod
            def set_console_title(title):
                calls.append(title)
                return 1

        expected = {
            "add_base.py": "Add Base",
            "verify_base.py": "Verify Base",
            "make_patch.py": "Make Patch",
            "apply_patch.py": "Apply Patch",
        }
        for script, operation in expected.items():
            with self.subTest(script=script):
                calls.clear()
                with (
                    mock.patch.object(common.sys, "platform", "win32"),
                    mock.patch("ctypes.WinDLL", return_value=Kernel32(), create=True),
                    common.console_title(common.ENTRY_SCRIPTS[script]),
                ):
                    pass
                self.assertEqual(calls[0], f"{operation} - Ninja Patch Tool (v{common.display_version()})")
                self.assertEqual(calls[-1], "Original Title")

    def test_console_title_temporarily_disables_quick_edit_and_restores_input_mode(self) -> None:
        modes: list[int] = []
        original_mode = 0x0001 | 0x0040

        class Function:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                return self.callback(*args)

        class Kernel32:
            def __init__(self):
                self.GetStdHandle = Function(lambda which: 123)
                self.GetConsoleMode = Function(self.get_console_mode)
                self.SetConsoleMode = Function(self.set_console_mode)
                self.GetConsoleTitleW = Function(self.get_console_title)
                self.SetConsoleTitleW = Function(lambda title: 1)

            @staticmethod
            def get_console_mode(handle, pointer):
                pointer._obj.value = original_mode
                return 1

            @staticmethod
            def set_console_mode(handle, mode):
                modes.append(int(mode))
                return 1

            @staticmethod
            def get_console_title(buffer, size):
                buffer.value = "Original Title"
                return len(buffer.value)

        with (
            mock.patch.object(common.sys, "platform", "win32"),
            mock.patch("ctypes.WinDLL", return_value=Kernel32(), create=True),
            common.console_title("Add Base - Ninja Patch Tool"),
        ):
            self.assertEqual(modes, [0x0081])
        self.assertEqual(modes, [0x0081, original_mode])

    def test_update_progress_uses_capture_style_cyan_transfer_segment(self) -> None:
        stream = io.StringIO()
        message = (
            "[Update] 30.0 MiB / 60.0 MiB (50.0%) | 6.0 MiB/s | "
            "NinjaPatchTool-v1.4.11-Windows-x64.zip"
        )
        with mock.patch.object(common, "console_supports_color", return_value=True):
            styled = common.style_console_text(message, stream, status_tokens=True)
        self.assertEqual(
            styled,
            "[Update] \x1b[36m30.0 MiB / 60.0 MiB (50.0%)\x1b[0m | 6.0 MiB/s | "
            "NinjaPatchTool-v1.4.11-Windows-x64.zip",
        )
        self.assertNotIn("\x1b[36m[Update]", styled)

    def test_update_progress_matches_capture_progress_layout(self) -> None:
        progress = update._UpdateProgress(
            "[Update]",
            60 * 1024 * 1024,
            "NinjaPatchTool-v1.4.11-Windows-x64.zip",
        )
        progress.completed = 30 * 1024 * 1024
        progress.speed_samples.clear()
        progress.speed_samples.append((100.0, 24 * 1024 * 1024))
        stdout = io.StringIO()
        with (
            mock.patch.object(common, "console_supports_color", return_value=True),
            mock.patch.object(update.shutil, "get_terminal_size", return_value=os.terminal_size((160, 24))),
            contextlib.redirect_stdout(stdout),
        ):
            progress._render_interactive(101.0)
        self.assertEqual(
            stdout.getvalue(),
            "\r[Update] \x1b[36m30.0 MiB / 60.0 MiB (50.0%)\x1b[0m | 6.0 MiB/s | "
            "NinjaPatchTool-v1.4.11-Windows-x64.zip",
        )

    def test_console_colors_are_disabled_for_non_tty_output(self) -> None:
        message = "ERROR: failure"
        self.assertEqual(common.style_console_text(message, io.StringIO()), message)

    def test_argument_parser_colors_startup_error_prefix_on_tty(self) -> None:
        stderr = io.StringIO()
        parser = common.ErrorArgumentParser()
        parser.add_argument("--known")
        with (
            mock.patch.object(common, "console_supports_color", return_value=True),
            contextlib.redirect_stderr(stderr),
            self.assertRaises(SystemExit),
        ):
            parser.parse_args(["--definitely-invalid"])
        self.assertIn("\x1b[31mERROR:\x1b[0m", stderr.getvalue())

    def test_argument_parser_capitalizes_generated_error_message(self) -> None:
        stderr = io.StringIO()
        parser = common.ErrorArgumentParser()
        parser.add_argument("--known")
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            parser.parse_args(["--definitely-invalid"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("ERROR: Unrecognized arguments: --definitely-invalid", stderr.getvalue())

    def test_argument_parser_help_uses_compact_consistent_layout(self) -> None:
        parser = common.ErrorArgumentParser(prog="make_patch.exe", description="Create a Ninja Patch.")
        parser.add_argument("base")
        parser.add_argument("new")
        parser.add_argument("output")
        parser.add_argument("base_name")
        parser.add_argument("-c", "--compression", metavar="PRESET", help="Compression preset")
        update.add_update_arguments(parser)
        parser.add_version_argument()
        parser.add_help_argument()
        usage_lines = parser.format_usage().splitlines()
        self.assertGreater(len(usage_lines), 1)
        self.assertTrue(all(line == line.lstrip() for line in usage_lines[1:] if line))
        help_text = parser.format_help()
        lines = help_text.splitlines()
        normalized_help = " ".join(line.strip() for line in lines)
        self.assertIn("Shows the Ninja Patch Tool version", normalized_help)
        self.assertIn("Shows this help message", normalized_help)
        self.assertNotIn("NPT", normalized_help)
        option_lines = [line.strip() for line in lines if line.startswith("  -")]
        option_index = lambda prefix: next(index for index, line in enumerate(option_lines) if line.startswith(prefix))
        self.assertLess(option_index("-u, --check-update"), option_index("-v, --version"))
        self.assertLess(option_index("-v, --version"), option_index("-h, --help"))
        self.assertNotIn("\n\n\n", help_text)

    def test_argument_parser_preserves_option_leading_error_message(self) -> None:
        stderr = io.StringIO()
        parser = common.ErrorArgumentParser()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            parser.error("--check-update must be used without operation arguments")
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("ERROR: --check-update must be used without operation arguments", stderr.getvalue())

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

    def test_base_name_sort_key_places_pre_release_before_matching_release(self) -> None:
        names = ["U43.0.0", "Pre-U42.0.0", "U42.0.1", "U41.9.9", "U42.0.0", "Alpha1"]
        self.assertEqual(
            sorted(names, key=common.base_name_sort_key),
            ["Alpha1", "U41.9.9", "Pre-U42.0.0", "U42.0.0", "U42.0.1", "U43.0.0"],
        )

    def test_four_component_base_versions_validate_and_sort_numerically(self) -> None:
        names = ["U43.5.4.10", "U43.5.4.1", "Pre-U43.5.4.1", "U43.5.4", "U43.5.5", "U43.5.4.2"]
        index = {
            name: {"steam_manifest_id": i + 1, "sha256": f"{i + 1:064x}", "file_count": i}
            for i, name in enumerate(names)
        }
        common.validate_index(index)
        with tempfile.TemporaryDirectory() as tmp:
            index_file = Path(tmp) / "index.json"
            with mock.patch.object(common, "INDEX_FILE", index_file):
                common.write_index(index)
                self.assertEqual(common.load_index(), index)
            self.assertEqual(
                list(json.loads(index_file.read_text(encoding="utf-8"))),
                ["U43.5.4", "Pre-U43.5.4.1", "U43.5.4.1", "U43.5.4.2", "U43.5.4.10", "U43.5.5"],
            )

    def test_process_identity_prevents_pid_reuse_false_positive(self) -> None:
        with mock.patch.object(common, "process_is_running", return_value=True), mock.patch.object(common, "process_identity", return_value="123:new"):
            self.assertFalse(common.process_matches_identity(123, "123:old"))
            self.assertTrue(common.process_matches_identity(123, "123:new"))
            self.assertTrue(common.process_matches_identity(123, None))

    def test_operation_activity_gate_allows_parallel_operations_but_blocks_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            held: list[tuple[int, int, int]] = []
            fake_msvcrt = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2)

            def locking(fd: int, mode: int, length: int) -> None:
                offset = os.lseek(fd, 0, os.SEEK_CUR)
                if mode == fake_msvcrt.LK_NBLCK:
                    end = offset + length
                    if any(not (end <= start or offset >= stop) for _, start, stop in held):
                        raise OSError(errno.EACCES, "locked")
                    held.append((fd, offset, end))
                    return
                for index, item in enumerate(held):
                    if item == (fd, offset, offset + length):
                        held.pop(index)
                        return
                raise OSError(errno.EINVAL, "unlock of unowned range")

            fake_msvcrt.locking = locking
            with mock.patch.object(common.sys, "platform", "win32"), mock.patch.dict(sys.modules, {"msvcrt": fake_msvcrt}):
                with common.operation_activity_lock(root):
                    with common.operation_activity_lock(root):
                        with self.assertRaisesRegex(common.ActiveOperationError, "operation is active"):
                            with common.exclusive_operation_activity_lock(root):
                                pass
                with common.exclusive_operation_activity_lock(root):
                    with self.assertRaisesRegex(RuntimeError, "currently being updated"):
                        with common.operation_activity_lock(root):
                            pass

    @unittest.skipUnless(sys.platform == "win32", "Windows file-lock test")
    def test_operation_activity_gate_blocks_update_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = (
                "import sys, time\n"
                "from pathlib import Path\n"
                "import common\n"
                "with common.operation_activity_lock(Path(sys.argv[1])):\n"
                "    print('ready', flush=True)\n"
                "    time.sleep(30)\n"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", code, str(root)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(process.stdout.readline().strip(), "ready")
                with self.assertRaisesRegex(common.ActiveOperationError, "operation is active"):
                    with common.exclusive_operation_activity_lock(root):
                        pass
            finally:
                process.terminate()
                process.wait(timeout=10)
            with common.exclusive_operation_activity_lock(root):
                pass

    def test_all_entrypoints_hold_activity_gate_before_automatic_update(self) -> None:
        cases = (
            (add_base, ["add_base.py", "base", "U1", "1"]),
            (verify_base, ["verify_base.py", "base", "U1"]),
            (make_patch, ["make_patch.py", "base", "new", "out", "U1"]),
            (apply_patch, ["apply_patch.py", "base", "patch"]),
        )
        for module, argv in cases:
            with self.subTest(module=module.__name__):
                events: list[str] = []

                @contextmanager
                def activity():
                    events.append("activity-enter")
                    try:
                        yield
                    finally:
                        events.append("activity-exit")

                def automatic(*args, **kwargs):
                    events.append("update")
                    return 0

                with (
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(module, "install_termination_handlers"),
                    mock.patch.object(module, "handle_early_update_request", return_value=None),
                    mock.patch.object(module, "operation_activity_lock", side_effect=activity),
                    mock.patch.object(module, "handle_automatic_update", side_effect=automatic),
                ):
                    self.assertEqual(module.main(), 0)
                self.assertEqual(events, ["activity-enter", "update", "activity-exit"])

    def test_version_argument_supports_short_and_long_forms(self) -> None:
        for option in ("-v", "--version"):
            with self.subTest(option=option):
                parser = common.ErrorArgumentParser()
                parser.add_version_argument()
                stdout = io.StringIO()
                with mock.patch("sys.stdout", stdout), self.assertRaises(SystemExit) as raised:
                    parser.parse_args([option])
                self.assertEqual(raised.exception.code, 0)
                self.assertEqual(stdout.getvalue().strip(), f"Ninja Patch Tool v{common.display_version()}")

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

    def test_openwf_client_files_are_ignored_at_installation_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_warframe_root(root)
            (root / "OpenWF" / "config").mkdir(parents=True)
            (root / "OpenWF" / "config" / "client.json").write_text("ignored", encoding="utf-8")
            for name in (
                "Bootstrapper Setup.exe",
                "dwmapi.dll",
                "Launch with OpenWF.bat",
                "sideloadify-cli.exe",
                "sideloadify.exe",
                "version.dll",
                "wtsapi32.dll",
            ):
                (root / name).write_bytes(b"ignored")
            (root / "Tools" / "sideloadify.exe").write_bytes(b"tracked")
            (root / "Tools" / "version.dll").write_bytes(b"tracked")
            (root / "Cache.Windows" / "OpenWF").mkdir()
            (root / "Cache.Windows" / "OpenWF" / "nested.bin").write_bytes(b"tracked")

            files, _ = common.scan_tree(root)

            self.assertNotIn("OpenWF/config/client.json", files)
            for name in (
                "Bootstrapper Setup.exe",
                "dwmapi.dll",
                "Launch with OpenWF.bat",
                "sideloadify-cli.exe",
                "sideloadify.exe",
                "version.dll",
                "wtsapi32.dll",
            ):
                self.assertNotIn(name, files)
            self.assertIn("Tools/sideloadify.exe", files)
            self.assertIn("Tools/version.dll", files)
            self.assertIn("Cache.Windows/OpenWF/nested.bin", files)

    def test_tracked_scan_prunes_root_openwf_without_descending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_warframe_root(root)
            openwf = root / "OpenWF"
            (openwf / "nested").mkdir(parents=True)
            (openwf / "nested" / "client.bin").write_bytes(b"ignored")
            original_scandir = common.os.scandir

            def guarded_scandir(path):
                if Path(path) == openwf:
                    raise AssertionError("tracked scan descended into ignored root OpenWF directory")
                return original_scandir(path)

            with mock.patch.object(common.os, "scandir", side_effect=guarded_scandir):
                files, _ = common.scan_tree(root)
            self.assertNotIn("OpenWF/nested/client.bin", files)

    def test_write_index_uses_unique_owned_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            index_file = Path(tmp) / "index.json"
            legacy_temporary = index_file.with_name(index_file.name + ".tmp")
            legacy_temporary.write_text("keep", encoding="utf-8")
            with mock.patch.object(common, "INDEX_FILE", index_file):
                common.write_index({})
            self.assertEqual(legacy_temporary.read_text(encoding="utf-8"), "keep")
            self.assertEqual(json.loads(index_file.read_text(encoding="utf-8")), {})
            self.assertEqual(list(index_file.parent.glob(".index.json.*.tmp")), [])

            with (
                mock.patch.object(common, "INDEX_FILE", index_file),
                mock.patch.object(Path, "replace", side_effect=RuntimeError("primary index failure")),
                mock.patch.object(Path, "unlink", side_effect=OSError("cleanup failure")),
            ):
                with self.assertRaisesRegex(RuntimeError, "primary index failure"):
                    common.write_index({})

    def test_write_index_sorts_pre_release_before_matching_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            index_file = Path(tmp) / "index.json"
            names = ["U42.0.1", "U42.0.0", "Pre-U42.0.0", "U41.9.9"]
            index = {
                name: {"steam_manifest_id": i + 1, "sha256": f"{i + 1:064x}", "file_count": i}
                for i, name in enumerate(names)
            }
            with mock.patch.object(common, "INDEX_FILE", index_file):
                common.write_index(index)
            self.assertEqual(
                list(json.loads(index_file.read_text(encoding="utf-8"))),
                ["U41.9.9", "Pre-U42.0.0", "U42.0.0", "U42.0.1"],
            )

    def test_add_base_uses_live_common_index_path_for_index_locking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            make_warframe_root(base)
            index_file = Path(tmp) / "custom-index.json"
            index_file.write_text("{}\n", encoding="utf-8")
            observed: list[Path] = []

            @contextmanager
            def fake_index_lock(path: Path, timeout_seconds: int = 0):
                observed.append(path)
                yield

            argv = ["add_base.py", str(base), "U43.5.1", "4895911296145320793"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(common, "INDEX_FILE", index_file),
                mock.patch.object(add_base, "install_termination_handlers"),
                mock.patch.object(add_base, "handle_early_update_request", return_value=None),
                mock.patch.object(add_base, "handle_automatic_update", return_value=None),
                mock.patch.object(add_base, "operation_lock", return_value=nullcontext()),
                mock.patch.object(add_base, "index_update_lock", side_effect=fake_index_lock),
                mock.patch.object(add_base, "validate_warframe_installation", return_value=True),
                mock.patch.object(add_base, "print_live_status_once"),
                mock.patch.object(add_base, "scan_tree", return_value=({}, "a" * 64)),
            ):
                self.assertEqual(add_base.main(), 0)
            self.assertEqual(observed, [index_file, index_file])
            self.assertIn("U43.5.1", json.loads(index_file.read_text(encoding="utf-8")))

    def test_add_base_keeps_installation_locked_until_index_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            active: list[str] = []
            index_lock_timeouts: list[int] = []

            from contextlib import contextmanager
            @contextmanager
            def fake_lock(kind: str, target: Path, description: str):
                active.append(kind)
                try:
                    yield
                finally:
                    active.remove(kind)

            @contextmanager
            def fake_index_lock(index_file: Path, timeout_seconds: int = 0):
                index_lock_timeouts.append(timeout_seconds)
                active.append("index")
                try:
                    yield
                finally:
                    active.remove("index")

            def write_index(index: dict) -> None:
                self.assertIn("installation", active)
                self.assertIn("index", active)

            argv = ["add_base.py", str(base), "U43.5.1", "4895911296145320793"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(add_base, "operation_lock", side_effect=fake_lock),
                mock.patch.object(add_base, "index_update_lock", side_effect=fake_index_lock),
                mock.patch.object(add_base, "validate_warframe_installation", return_value=True),
                mock.patch.object(add_base, "scan_tree", return_value=({}, "a" * 64)),
                mock.patch.object(add_base, "load_index", return_value={}),
                mock.patch.object(add_base, "write_index", side_effect=write_index),
            ):
                self.assertEqual(add_base.main(), 0)
            self.assertEqual(index_lock_timeouts, [0, 5])

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

    def test_stale_release_temp_is_removed_before_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_temp = Path(tmp) / "release_temp"
            nested = release_temp / "old_build" / "build"
            nested.mkdir(parents=True)
            (nested / "leftover.bin").write_bytes(b"leftover")
            with mock.patch.object(build_release, "RELEASE_TEMP_DIR", release_temp):
                build_release.clean_stale_release_temp()
            self.assertFalse(release_temp.exists())

    def test_release_builder_uses_common_console_lifecycle(self) -> None:
        with (
            mock.patch.object(build_release, "console_title", return_value=nullcontext()) as console_context,
            mock.patch.object(build_release, "main", return_value=0) as main,
        ):
            self.assertEqual(build_release.run_main_with_console_title(["--extract"]), 0)
        console_context.assert_called_once_with("Building latest release... - Ninja Patch Tool")
        main.assert_called_once_with(["--extract"])

    def test_release_console_close_event_cleans_all_temporary_outputs(self) -> None:
        events: list[str] = []
        with (
            mock.patch.object(build_release, "_terminate_active_build_process", side_effect=lambda: events.append("terminate")),
            mock.patch.object(build_release, "remove_release_temp", side_effect=lambda: events.append("temp")),
            mock.patch.object(build_release, "remove_release_output_temps", side_effect=lambda: events.append("outputs")),
        ):
            self.assertFalse(build_release._release_console_control_handler(2))
            self.assertFalse(build_release._release_console_control_handler(0))
        self.assertEqual(events, ["terminate", "temp", "outputs"])

    def test_release_data_is_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            stage = root / "stage"
            dist = root / "dist"
            data.mkdir()
            dist.mkdir()

            expected_data = {"index.json", "update.json", "hdiffz.exe", "hpatchz.exe"}
            expected_licenses = {"Python-LICENSE.txt", "HDiffPatch-LICENSE.txt", "Ninja-Patch-Tool-LICENSE.txt"}
            for name in expected_data:
                if name == "index.json":
                    (data / name).write_bytes(b"{}")
                elif name == "update.json":
                    (data / name).write_text(
                        '{"auto_update": false, "last_successful_check": 123, "last_failed_check": 456}\n',
                        encoding="utf-8",
                    )
                else:
                    (data / name).write_bytes(name.encode("ascii"))

            licenses = data / "licenses"
            licenses.mkdir()
            for name in ("Python-LICENSE.txt", "HDiffPatch-LICENSE.txt"):
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
                mock.patch.object(build_release, "collect_steam_dependency_licenses"),
            ):
                build_release.populate_release(stage, dist, [project_license])

            self.assertEqual({path.name for path in (stage / "data").iterdir()}, {*expected_data, "licenses"})
            self.assertEqual({path.name for path in (stage / "data" / "licenses").iterdir()}, expected_licenses)
            self.assertEqual(
                json.loads((stage / "data" / "update.json").read_text(encoding="utf-8")),
                {"auto_update": True},
            )

    def test_gevent_eventemitter_fallback_license_is_tracked(self) -> None:
        expected = build_release.LICENSES_DIR / "gevent_eventemitter_LICENSE.txt"
        self.assertEqual(
            build_release.VERSIONED_FALLBACK_STEAM_LICENSE_FILES,
            {("gevent-eventemitter", "2.1"): expected},
        )
        self.assertTrue(expected.is_file())

    def test_steam_license_collection_uses_gevent_eventemitter_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "licenses"
            destination.mkdir()

            distribution = mock.Mock()
            distribution.metadata = {"Name": "gevent-eventemitter"}
            distribution.version = "2.1"
            distribution.files = []

            with mock.patch.object(build_release, "dependency_closure", return_value=[distribution]):
                build_release.collect_steam_dependency_licenses(destination)

            fallback_copy = destination / "gevent-eventemitter-2.1-gevent_eventemitter_LICENSE.txt"
            self.assertEqual(
                fallback_copy.read_bytes(),
                build_release.VERSIONED_FALLBACK_STEAM_LICENSE_FILES[("gevent-eventemitter", "2.1")].read_bytes(),
            )

    def test_gevent_eventemitter_fallback_is_version_specific(self) -> None:
        distribution = mock.Mock()
        distribution.metadata = {"Name": "gevent-eventemitter"}
        distribution.version = "2.2"
        distribution.files = []
        self.assertEqual(build_release.fallback_steam_license_files(distribution), [])

    def test_release_manifest_tracks_managed_files_but_not_mutable_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            (stage / "data").mkdir(parents=True)
            (stage / "make_patch.exe").write_bytes(b"exe")
            (stage / "data" / "index.json").write_text("{}", encoding="utf-8")
            (stage / "data" / "update.json").write_text('{"auto_update": true}', encoding="utf-8")
            (stage / "data" / "hdiffz.exe").write_bytes(b"hdiff")

            build_release.write_release_manifest(stage)
            build_release.validate_release_manifest(stage)
            self.assertTrue((stage / "data" / "release_manifest.json").is_file())
            self.assertFalse((stage / "release_manifest.json").exists())
            manifest = json.loads((stage / common.RELEASE_MANIFEST_FILE).read_text(encoding="utf-8"))
            self.assertEqual(manifest["application_version"], common.VERSION)
            self.assertEqual(
                set(manifest["files"]),
                {"make_patch.exe", "data/hdiffz.exe"},
            )
            self.assertEqual(manifest["files"]["make_patch.exe"], sha256_bytes(b"exe"))

    def test_release_archive_validates_exact_members_and_manifest_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root / f"NinjaPatchTool-v{common.VERSION}"
            (stage / "data").mkdir(parents=True)
            (stage / "make_patch.exe").write_bytes(b"expected-exe")
            (stage / "data" / "index.json").write_text("{}", encoding="utf-8")
            build_release.write_release_manifest(stage)
            prefix = stage.name + "/"

            valid = root / "valid.zip"
            with zipfile.ZipFile(valid, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in stage.rglob("*"):
                    if path.is_file():
                        archive.write(path, prefix + path.relative_to(stage).as_posix())
            build_release.validate_release_archive(valid, stage)

            extra = root / "extra.zip"
            with zipfile.ZipFile(extra, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in stage.rglob("*"):
                    if path.is_file():
                        archive.write(path, prefix + path.relative_to(stage).as_posix())
                archive.writestr(prefix + "unexpected.bin", b"extra")
            with self.assertRaisesRegex(RuntimeError, "member set"):
                build_release.validate_release_archive(extra, stage)

            tampered = root / "tampered.zip"
            with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in stage.rglob("*"):
                    if not path.is_file():
                        continue
                    relative = path.relative_to(stage).as_posix()
                    payload = b"tampered" if relative == "make_patch.exe" else path.read_bytes()
                    archive.writestr(prefix + relative, payload)
            with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                build_release.validate_release_archive(tampered, stage)

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
            with self.assertRaisesRegex(RuntimeError, "exactly these resolutions"):
                build_release.validate_ico(old_style)

    def test_release_outputs_keep_identical_archive_repair_checksum_and_replace_changed_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release_dir = root / "release"
            stage = root / f"NinjaPatchTool-v{common.VERSION}"
            stage.mkdir()
            (stage / "NinjaPatchTool.exe").write_bytes(b"exe")
            build_release.write_release_manifest(stage)

            with mock.patch.object(build_release, "RELEASE_DIR", release_dir):
                archive, checksum, digest, result = build_release.create_release_outputs(stage)
                self.assertEqual(result, "created")
                original_archive = archive.read_bytes()
                self.assertEqual(checksum.read_text(encoding="ascii"), f"{digest}  {archive.name}\n")

                checksum.write_text("wrong\n", encoding="ascii")
                same_archive, same_checksum, same_digest, result = build_release.create_release_outputs(stage)
                self.assertEqual(result, "unchanged")
                self.assertEqual(same_archive.read_bytes(), original_archive)
                self.assertEqual(same_digest, digest)
                self.assertEqual(same_checksum.read_text(encoding="ascii"), f"{digest}  {archive.name}\n")

                (stage / "NinjaPatchTool.exe").write_bytes(b"changed-exe")
                build_release.write_release_manifest(stage)
                _, checksum, changed_digest, result = build_release.create_release_outputs(stage)
                self.assertEqual(result, "replaced")
                self.assertNotEqual(changed_digest, digest)
                self.assertNotEqual(archive.read_bytes(), original_archive)
                self.assertEqual(checksum.read_text(encoding="ascii"), f"{changed_digest}  {archive.name}\n")

    def test_release_output_failure_preserves_existing_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release_dir = root / "release"
            stage = root / f"NinjaPatchTool-v{common.VERSION}"
            stage.mkdir()
            (stage / "NinjaPatchTool.exe").write_bytes(b"exe")
            build_release.write_release_manifest(stage)

            with mock.patch.object(build_release, "RELEASE_DIR", release_dir):
                archive, checksum, _, _ = build_release.create_release_outputs(stage)
                existing_archive = archive.read_bytes()
                existing_checksum = checksum.read_bytes()
                (stage / "NinjaPatchTool.exe").write_bytes(b"changed-exe")
                build_release.write_release_manifest(stage)

                with mock.patch.object(build_release, "validate_release_archive", side_effect=RuntimeError("validation failed")):
                    with self.assertRaisesRegex(RuntimeError, "validation failed"):
                        build_release.create_release_outputs(stage)

                self.assertEqual(archive.read_bytes(), existing_archive)
                self.assertEqual(checksum.read_bytes(), existing_checksum)
                self.assertFalse(archive.with_name(archive.name + ".tmp").exists())
                self.assertFalse(checksum.with_name(checksum.name + ".tmp").exists())

    def test_release_builder_extract_argument_aliases(self) -> None:
        self.assertTrue(build_release.parse_args(["-e"]).extract)
        self.assertTrue(build_release.parse_args(["--extract"]).extract)
        self.assertFalse(build_release.parse_args([]).extract)

    def test_release_builder_argument_errors_use_styled_error_prefix(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                build_release.parse_args(["-x"])
        self.assertEqual(raised.exception.code, 2)
        output = stderr.getvalue()
        self.assertIn("usage:", output)
        self.assertIn("ERROR: Unrecognized arguments: -x", output)
        self.assertNotIn("build_release.py: error:", output)

    def test_release_builder_extracts_archive_and_replaces_previous_extracted_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release_dir = root / "release"
            release_dir.mkdir()
            archive = release_dir / f"NinjaPatchTool-v{common.VERSION}-Windows-x64.zip"
            top_level = f"NinjaPatchTool-v{common.VERSION}"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr(f"{top_level}/NinjaPatchTool.exe", b"new-exe")

            previous = release_dir / top_level
            previous.mkdir()
            (previous / "old.txt").write_text("old", encoding="ascii")

            with mock.patch.object(build_release, "RELEASE_DIR", release_dir):
                extracted = build_release.extract_release_archive(archive)

            self.assertEqual(extracted, previous)
            self.assertEqual((extracted / "NinjaPatchTool.exe").read_bytes(), b"new-exe")
            self.assertFalse((extracted / "old.txt").exists())
            self.assertFalse((release_dir / f".{top_level}.extract.tmp").exists())
            self.assertFalse((release_dir / f"{top_level}.extract.backup").exists())

    def test_release_extract_remove_retry_recovers_from_transient_windows_lock(self) -> None:
        path = Path("locked")
        remove = mock.Mock(side_effect=[PermissionError("busy"), PermissionError("busy"), None])
        with (
            mock.patch.object(build_release, "_remove_path", remove),
            mock.patch.object(build_release.time, "sleep") as sleep,
        ):
            build_release._remove_path_with_retry(path, attempts=3, delay_seconds=0.01)
        self.assertEqual(remove.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_release_extract_replace_retry_recovers_from_transient_windows_lock(self) -> None:
        source = mock.Mock()
        source.replace.side_effect = [PermissionError("busy"), None]
        destination = Path("destination")
        with mock.patch.object(build_release.time, "sleep") as sleep:
            build_release._replace_path_with_retry(source, destination, attempts=2, delay_seconds=0.01)
        self.assertEqual(source.replace.call_count, 2)
        sleep.assert_called_once_with(0.01)

    def test_release_output_rollback_guard_removes_new_outputs_after_extract_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_dir = Path(tmp) / "release"
            with mock.patch.object(build_release, "RELEASE_DIR", release_dir):
                archive = build_release.release_archive_path()
                checksum = build_release.release_checksum_path()
                with self.assertRaisesRegex(PermissionError, "extract failed"):
                    with build_release.release_output_rollback_guard(True):
                        archive.write_bytes(b"new archive")
                        checksum.write_text("new checksum", encoding="ascii")
                        raise PermissionError("extract failed")
                self.assertFalse(archive.exists())
                self.assertFalse(checksum.exists())
                self.assertEqual(list(release_dir.glob(".release-finalize-rollback-*")), [])

    def test_release_output_rollback_guard_restores_previous_outputs_after_extract_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_dir = Path(tmp) / "release"
            release_dir.mkdir()
            with mock.patch.object(build_release, "RELEASE_DIR", release_dir):
                archive = build_release.release_archive_path()
                checksum = build_release.release_checksum_path()
                archive.write_bytes(b"old archive")
                checksum.write_text("old checksum", encoding="ascii")
                with self.assertRaisesRegex(RuntimeError, "extract failed"):
                    with build_release.release_output_rollback_guard(True):
                        archive.write_bytes(b"new archive")
                        checksum.write_text("new checksum", encoding="ascii")
                        raise RuntimeError("extract failed")
                self.assertEqual(archive.read_bytes(), b"old archive")
                self.assertEqual(checksum.read_text(encoding="ascii"), "old checksum")
                self.assertEqual(list(release_dir.glob(".release-finalize-rollback-*")), [])

    def test_release_checksum_publication_failure_restores_output_pair(self) -> None:
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                release_dir = root / "release"
                stage = root / f"NinjaPatchTool-v{common.VERSION}"
                stage.mkdir()
                (stage / "NinjaPatchTool.exe").write_bytes(b"exe")
                build_release.write_release_manifest(stage)
                with mock.patch.object(build_release, "RELEASE_DIR", release_dir):
                    archive = build_release.release_archive_path()
                    checksum = build_release.release_checksum_path()
                    if existing:
                        build_release.create_release_outputs(stage)
                        old_archive, old_checksum = archive.read_bytes(), checksum.read_bytes()
                        (stage / "NinjaPatchTool.exe").write_bytes(b"updated-exe")
                        build_release.write_release_manifest(stage)
                    original_replace = Path.replace

                    def fail_checksum(path, target):
                        if path == checksum.with_name(checksum.name + ".tmp"):
                            raise PermissionError("checksum is locked")
                        return original_replace(path, target)

                    with mock.patch.object(Path, "replace", fail_checksum):
                        with self.assertRaisesRegex(PermissionError, "checksum is locked"):
                            build_release.create_release_outputs(stage)
                    if existing:
                        self.assertEqual(archive.read_bytes(), old_archive)
                        self.assertEqual(checksum.read_bytes(), old_checksum)
                    else:
                        self.assertFalse(archive.exists())
                        self.assertFalse(checksum.exists())
                    self.assertFalse(list(release_dir.glob("*.tmp")))
                    self.assertFalse(list(release_dir.glob(".release-rollback-*")))

    def test_release_main_preserves_build_error_when_temp_cleanup_also_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release_temp = root / "release_temp"
            archive = root / "release.zip"
            stderr = io.StringIO()
            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", release_temp),
                mock.patch.object(build_release, "validate_build_environment", return_value=[]),
                mock.patch.object(build_release, "release_archive_path", return_value=archive),
                mock.patch.object(build_release, "operation_lock", return_value=nullcontext()),
                mock.patch.object(build_release, "run_source_tests"),
                mock.patch.object(build_release, "build_executable", side_effect=RuntimeError("build failed")),
                mock.patch.object(build_release, "remove_release_temp", side_effect=OSError("cleanup failed")),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(build_release.main(), 1)
            self.assertIn("build failed", stderr.getvalue())
            self.assertIn("cleanup failed", stderr.getvalue())

    def test_release_duration_uses_patch_summary_format(self) -> None:
        self.assertEqual(common.format_duration(0), "00:00")
        self.assertEqual(common.format_duration(65), "01:05")
        self.assertEqual(common.format_duration(3599), "59:59")
        self.assertEqual(common.format_duration(3600), "01:00:00")
        self.assertEqual(common.format_duration(3661), "01:01:01")

    def test_pyinstaller_minimum_version_for_python_314(self) -> None:
        build_release.validate_pyinstaller_version("6.15.0")
        build_release.validate_pyinstaller_version("6.22.2")
        with self.assertRaisesRegex(RuntimeError, "6.15.0 or newer"):
            build_release.validate_pyinstaller_version("6.14.2")

    def test_production_modules_do_not_redefine_top_level_functions_or_classes(self) -> None:
        root = Path(build_release.__file__).resolve().parent
        duplicates: list[str] = []

        for path in sorted(root.glob("*.py"), key=lambda item: item.name.casefold()):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            definitions: dict[str, int] = {}
            for node in tree.body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                previous = definitions.get(node.name)
                if previous is None:
                    definitions[node.name] = node.lineno
                    continue
                duplicates.append(f"{path.name}:{node.lineno}: {node.name} (first defined at line {previous})")

        self.assertEqual(duplicates, [], "Duplicate top-level definitions found:\n" + "\n".join(duplicates))

    def test_production_modules_do_not_reach_into_other_modules_private_api(self) -> None:
        root = Path(build_release.__file__).resolve().parent
        module_paths = tuple(sorted(root.glob("*.py"), key=lambda path: path.name.casefold()))
        project_modules = {path.stem for path in module_paths}
        violations: list[str] = []

        for path in module_paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            module_aliases: dict[str, str] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for imported in node.names:
                        if imported.name in project_modules:
                            module_aliases[imported.asname or imported.name] = imported.name
                elif isinstance(node, ast.ImportFrom) and node.module in project_modules:
                    for imported in node.names:
                        if imported.name.startswith("_") and not imported.name.startswith("__"):
                            violations.append(
                                f"{path.name}:{node.lineno}: from {node.module} import {imported.name}"
                            )

            for node in ast.walk(tree):
                if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Name):
                    continue
                owner = module_aliases.get(node.value.id)
                if owner is None or not node.attr.startswith("_") or node.attr.startswith("__"):
                    continue
                violations.append(f"{path.name}:{node.lineno}: {node.value.id}.{node.attr}")

        self.assertEqual(violations, [], "Cross-module private API access found:\n" + "\n".join(violations))

    def test_release_source_files_cover_all_python_source_and_tests(self) -> None:
        root = Path(build_release.__file__).resolve().parent
        expected = {path.name for path in root.glob("*.py") if path.is_file()}
        expected.update(
            path.relative_to(root).as_posix()
            for path in (root / "tests").glob("*.py")
            if path.is_file()
        )
        declared = set(build_release.RELEASE_SOURCE_FILES)
        missing = sorted(expected - declared, key=str.casefold)
        self.assertEqual(missing, [], "Python release inputs missing from RELEASE_SOURCE_FILES:\n" + "\n".join(missing))

    def test_source_tree_cleanliness_detects_generated_artifacts_and_runtime_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".pytest_cache").mkdir()
            (root / ".mypy_cache").mkdir()
            (root / ".ruff_cache").mkdir()
            (root / "htmlcov").mkdir()
            (root / ".coverage").write_text("coverage", encoding="ascii")
            (root / "coverage.xml").write_text("coverage", encoding="ascii")
            (root / ".git").mkdir()
            (root / ".git" / "index.lock").write_text("git index lock", encoding="ascii")
            (root / "nested").mkdir()
            (root / "nested" / "download.zip.part").write_bytes(b"partial")
            (root / "nested" / "__pycache__").mkdir()
            (root / "nested" / "module.pyc").write_bytes(b"bytecode")
            (root / "nested" / "module.pyo").write_bytes(b"optimized bytecode")
            (root / "data").mkdir()
            (root / "data" / ".index.lock").write_text("1", encoding="ascii")

            self.assertEqual(
                build_release.source_tree_artifacts(root),
                [
                    ".coverage",
                    ".mypy_cache/",
                    ".pytest_cache/",
                    ".ruff_cache/",
                    "coverage.xml",
                    "htmlcov/",
                    "nested/__pycache__/",
                    "nested/download.zip.part",
                    "nested/module.pyc",
                    "nested/module.pyo",
                ],
            )
            with self.assertRaisesRegex(RuntimeError, "Generated/cache artifacts must be removed"):
                build_release.validate_source_tree_cleanliness(root)

    def test_release_cleanliness_allows_known_runtime_locks_and_rejects_unknown_locks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            for relative in build_release.KNOWN_RUNTIME_LOCK_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("lock", encoding="utf-8")
            (data / ".runtime.lock").write_text("lock", encoding="utf-8")
            self.assertEqual(build_release.source_tree_artifacts(root), ["data/.runtime.lock"])
            with self.assertRaisesRegex(RuntimeError, "Generated/cache artifacts"):
                build_release.validate_source_tree_cleanliness(root)

    def test_release_runtime_build_barrier_uses_exclusive_operation_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            events: list[str] = []

            @contextmanager
            def activity_gate(install_dir: Path):
                self.assertEqual(install_dir, root)
                events.append("enter")
                try:
                    yield
                finally:
                    events.append("exit")

            with mock.patch.object(build_release, "exclusive_operation_activity_lock", side_effect=activity_gate):
                with build_release.runtime_build_barrier(root):
                    events.append("build")

            self.assertEqual(events, ["enter", "build", "exit"])

    def test_release_runtime_build_barrier_reports_active_operation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            @contextmanager
            def activity_gate(_install_dir: Path):
                raise build_release.ActiveOperationError("active")
                yield

            with mock.patch.object(build_release, "exclusive_operation_activity_lock", side_effect=activity_gate):
                with self.assertRaisesRegex(RuntimeError, "Close it before building a release"):
                    with build_release.runtime_build_barrier(root):
                        self.fail("busy runtime barrier unexpectedly entered")

    def test_release_staging_removes_known_locks_and_rejects_unknown_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            for relative in build_release.KNOWN_RUNTIME_LOCK_FILES:
                path = stage / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("lock", encoding="ascii")
            unexpected = stage / "data" / ".unexpected.lock"
            unexpected.write_text("lock", encoding="ascii")

            with self.assertRaisesRegex(RuntimeError, "unexpected runtime lock files"):
                build_release.sanitize_staged_runtime_locks(stage)
            self.assertTrue(unexpected.exists())
            self.assertTrue(all(not (stage / relative).exists() for relative in build_release.KNOWN_RUNTIME_LOCK_FILES))

            unexpected.unlink()
            build_release.sanitize_staged_runtime_locks(stage)

    def test_release_main_revalidates_cleanliness_after_source_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_temp = Path(tmp) / "release_temp"
            archive = Path(tmp) / "release.zip"
            events: list[str] = []

            def run_tests() -> None:
                events.append("tests")

            def validate_cleanliness() -> None:
                events.append("cleanliness")

            fingerprints = iter(("same", "same"))

            def source_fingerprint(_project_licenses: list[Path]) -> str:
                events.append("fingerprint")
                return next(fingerprints)

            @contextmanager
            def runtime_barrier():
                events.append("barrier-enter")
                try:
                    yield
                finally:
                    events.append("barrier-exit")

            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", release_temp),
                mock.patch.object(build_release, "validate_build_environment", return_value=[]),
                mock.patch.object(build_release, "release_archive_path", return_value=archive),
                mock.patch.object(build_release, "operation_lock", return_value=nullcontext()),
                mock.patch.object(build_release, "release_temp_console_cleanup", return_value=nullcontext()),
                mock.patch.object(build_release, "clean_stale_release_temp"),
                mock.patch.object(build_release, "remove_release_output_temps"),
                mock.patch.object(build_release, "runtime_build_barrier", side_effect=runtime_barrier),
                mock.patch.object(build_release, "release_source_fingerprint", side_effect=source_fingerprint),
                mock.patch.object(build_release, "run_source_tests", side_effect=run_tests),
                mock.patch.object(build_release, "validate_source_tree_cleanliness", side_effect=validate_cleanliness),
                mock.patch.object(build_release, "build_executable", side_effect=RuntimeError("stop after cleanliness")),
                mock.patch.object(build_release, "remove_release_temp"),
                mock.patch("sys.stderr", io.StringIO()),
            ):
                self.assertEqual(build_release.main([]), 1)
            self.assertEqual(
                events,
                [
                    "barrier-enter",
                    "fingerprint",
                    "barrier-exit",
                    "tests",
                    "barrier-enter",
                    "cleanliness",
                    "fingerprint",
                    "barrier-exit",
                ],
            )

    def test_release_main_rejects_source_change_during_source_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_temp = Path(tmp) / "release_temp"
            archive = Path(tmp) / "release.zip"
            build_executable = mock.Mock(side_effect=AssertionError("build must not start"))
            stderr = io.StringIO()
            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", release_temp),
                mock.patch.object(build_release, "validate_build_environment", return_value=[]),
                mock.patch.object(build_release, "release_archive_path", return_value=archive),
                mock.patch.object(build_release, "operation_lock", return_value=nullcontext()),
                mock.patch.object(build_release, "release_temp_console_cleanup", return_value=nullcontext()),
                mock.patch.object(build_release, "clean_stale_release_temp"),
                mock.patch.object(build_release, "remove_release_output_temps"),
                mock.patch.object(build_release, "runtime_build_barrier", return_value=nullcontext()),
                mock.patch.object(build_release, "release_source_fingerprint", side_effect=["before", "after"]),
                mock.patch.object(build_release, "run_source_tests"),
                mock.patch.object(build_release, "validate_source_tree_cleanliness"),
                mock.patch.object(build_release, "build_executable", build_executable),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(build_release.main([]), 1)
            build_executable.assert_not_called()
            self.assertIn("Release source changed while the source test suite was running", stderr.getvalue())

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

            process = mock.Mock()
            process.wait.side_effect = lambda: ((dist / "add_base.exe").write_bytes(b"exe"), 0)[1]

            with mock.patch.object(build_release.subprocess, "Popen", return_value=process) as popen:
                build_release.build_executable(script, dist, work, specs)

            commands.append(popen.call_args.args[0])
            environments.append(popen.call_args.kwargs["env"])
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
            pairs = list(zip(commands[0], commands[0][1:]))
            self.assertIn(("--collect-all", "steam"), pairs)
            self.assertIn(("--recursive-copy-metadata", "pysteam-client"), pairs)

    def test_requirements_pin_steam_client_version(self) -> None:
        text = (build_release.ROOT / "requirements.txt").read_text(encoding="utf-8").strip()
        self.assertEqual(text, f"pysteam-client[client]=={common.STEAM_CLIENT_VERSION}")

    def test_release_builder_runs_source_tests_with_deprecation_warnings_as_errors(self) -> None:
        result = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(build_release.subprocess, "run", return_value=result) as run:
            build_release.run_source_tests()
        command = run.call_args.args[0]
        self.assertEqual(command[0], sys.executable)
        self.assertIn("error::DeprecationWarning", command)
        self.assertIn("error::RuntimeWarning", command)
        self.assertIn("error::ResourceWarning", command)
        self.assertEqual(run.call_args.kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(run.call_args.kwargs["errors"], "replace")
        self.assertEqual(command[-5:], ["-m", "unittest", "discover", "-s", "tests"])

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
            timeouts: list[int] = []
            child_creationflags: list[int] = []
            def run(command, cwd, env, capture_output, text, errors, creationflags, timeout):
                calls.append(command)
                timeouts.append(timeout)
                child_creationflags.append(creationflags)
                if command[1:] == ["-h"]:
                    return SimpleNamespace(returncode=0, stdout="Shows this help message", stderr="")
                if command[1:] == [common.STEAM_QUERY_WORKER_SMOKE_ARGUMENT]:
                    payload = json.dumps({"ok": True, "smoke": "steam-import"})
                    return SimpleNamespace(returncode=0, stdout=common.STEAM_QUERY_RESULT_PREFIX + payload + "\n", stderr="")
                return SimpleNamespace(returncode=0, stdout=f"Ninja Patch Tool v{build_release.DISPLAY_VERSION}\n", stderr="")

            with mock.patch.object(build_release, "_run_tracked_build_process", side_effect=run):
                build_release.smoke_test_executables(dist)
            expected = []
            for script in build_release.ENTRY_SCRIPTS:
                expected.append([f"{Path(script).stem}.exe", "-h"])
                expected.append([f"{Path(script).stem}.exe", "-v"])
                expected.append([f"{Path(script).stem}.exe", "--version"])
                expected.append([f"{Path(script).stem}.exe", "--update-installer", "--version"])
            expected.append(["add_base.exe", common.STEAM_QUERY_WORKER_SMOKE_ARGUMENT])
            self.assertEqual([[Path(command[0]).name, *command[1:]] for command in calls], expected)
            self.assertEqual(timeouts, [120] * (len(expected) - 1) + [30])
            self.assertEqual(
                child_creationflags,
                [getattr(build_release.subprocess, "CREATE_NO_WINDOW", 0)] * len(expected),
            )

    def test_release_workflow_capture_tolerates_non_utf8_native_child_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            build_release.run_release_workflow_command(
                Path(sys.executable),
                ["-c", "import os; os.write(1, bytes([0x97]) + b'native-output\\n')"],
                cwd=Path(tmp),
                environment=os.environ.copy(),
            )

    def test_release_round_trip_smoke_runs_full_cli_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root / "stage"
            stage.mkdir()
            for script in build_release.ENTRY_SCRIPTS:
                (stage / f"{Path(script).stem}.exe").write_bytes(b"exe")

            calls: list[list[str]] = []
            environments: list[dict[str, str]] = []
            newer: Path | None = None

            def run(command, cwd, env, capture_output, text, errors, creationflags, timeout):
                nonlocal newer
                self.assertEqual(creationflags, getattr(build_release.subprocess, "CREATE_NO_WINDOW", 0))
                self.assertEqual(errors, "replace")
                calls.append(command)
                environments.append(env)
                name = Path(command[0]).name
                if name == "make_patch.exe":
                    newer = Path(command[2])
                    Path(command[3]).write_bytes(b"patch")
                elif name == "apply_patch.exe":
                    self.assertIsNotNone(newer)
                    if "-o" in command:
                        shutil.copytree(newer, Path(command[4]))
                    else:
                        target = Path(command[1])
                        shutil.rmtree(target)
                        shutil.copytree(newer, target)
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch.object(build_release, "_run_tracked_build_process", side_effect=run):
                build_release.smoke_test_release_round_trip(stage, root / "roundtrip")

            self.assertEqual(
                [Path(command[0]).name for command in calls],
                ["add_base.exe", "verify_base.exe", "make_patch.exe", "apply_patch.exe", "apply_patch.exe"],
            )
            self.assertTrue(all("-n" in command for command in calls))
            self.assertTrue(all(env.get("NO_COLOR") == "1" for env in environments))
            self.assertEqual([call[-1] for call in calls[:2]], ["-n", "-n"])
            self.assertEqual(calls[2][-3:], ["-c", "normal", "-n"])
            self.assertEqual(calls[3][-3], "-o")
            self.assertEqual(calls[4][-2:], ["-i", "-n"])

    def test_release_round_trip_smoke_rejects_incorrect_applied_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root / "stage"
            stage.mkdir()
            for script in build_release.ENTRY_SCRIPTS:
                (stage / f"{Path(script).stem}.exe").write_bytes(b"exe")

            def run(command, cwd, env, capture_output, text, errors, creationflags, timeout):
                self.assertEqual(creationflags, getattr(build_release.subprocess, "CREATE_NO_WINDOW", 0))
                self.assertEqual(errors, "replace")
                name = Path(command[0]).name
                if name == "make_patch.exe":
                    Path(command[3]).write_bytes(b"patch")
                elif name == "apply_patch.exe":
                    output = Path(command[4])
                    output.mkdir()
                    (output / "wrong.bin").write_bytes(b"wrong")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch.object(build_release, "_run_tracked_build_process", side_effect=run):
                with self.assertRaisesRegex(RuntimeError, "do not match the expected installation"):
                    build_release.smoke_test_release_round_trip(stage, root / "roundtrip")

    def test_windows_version_tuple_pads_to_four_components(self) -> None:
        with mock.patch.object(build_release, "VERSION", "1.4.5"):
            self.assertEqual(build_release.version_tuple(), (1, 4, 5, 0))

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
            mock.patch.object(update, "cleanup_relaunched_update_work"),
            mock.patch.object(update, "cleanup_stale_update_work"),
        ):
            self.assertEqual(update.handle_early_update_request(["-u"]), 0)
        check.assert_called_once_with()
        load_config.assert_not_called()
        cooldown.assert_not_called()

        with mock.patch.object(update, "cleanup_relaunched_update_work"), mock.patch.object(update, "cleanup_stale_update_work"), mock.patch("sys.stderr", io.StringIO()):
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
            f"[Update] Local Ninja Patch Tool v{common.display_version()} is newer than the latest release v1.3.1.\n",
        )

    def test_check_update_reports_equal_version_as_up_to_date(self) -> None:
        stdout = io.StringIO()
        release = {"version": common.VERSION, "url": "https://example.test/release"}
        with (
            mock.patch.object(update, "latest_release", return_value=release),
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stdout", stdout),
        ):
            self.assertEqual(update.check_update_only(), 0)
        record.assert_called_once_with("success")
        self.assertEqual(stdout.getvalue(), f"[Update] Ninja Patch Tool v{common.display_version()} is up to date.\n")

    def test_check_update_reports_newer_release(self) -> None:
        stdout = io.StringIO()
        release = {"version": "1.6", "url": "https://example.test/release"}
        with (
            mock.patch.object(update, "latest_release", return_value=release),
            mock.patch.object(update, "_record_update_check_result") as record,
            mock.patch("sys.stdout", stdout),
        ):
            self.assertEqual(update.check_update_only(), 0)
        record.assert_called_once_with("update_available")
        self.assertEqual(
            stdout.getvalue(),
            "[Update] Ninja Patch Tool v1.6 is available.\n"
            f"Current version: v{common.display_version()}\n"
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
        with mock.patch.object(update, "cleanup_relaunched_update_work", side_effect=KeyboardInterrupt), mock.patch("sys.stderr", stderr):
            self.assertEqual(update.handle_early_update_request([]), 130)
        self.assertIn("Startup cancelled", stderr.getvalue())

    def test_missing_update_config_is_created_with_auto_update_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "data" / "update.json"
            with mock.patch.object(update, "UPDATE_CONFIG_FILE", config):
                self.assertTrue(update.load_auto_update_setting())
            self.assertEqual(json.loads(config.read_text(encoding="utf-8")), {"auto_update": True})

    def test_malformed_update_config_reports_json_context_without_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "update.json"
            original = '{"auto_update":'
            config.write_text(original, encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch.object(update, "UPDATE_CONFIG_FILE", config), mock.patch("sys.stderr", stderr):
                self.assertFalse(update.load_auto_update_setting())
            self.assertIn("Invalid JSON:", stderr.getvalue())
            self.assertIn("automatic updating is disabled for this run", stderr.getvalue())
            self.assertEqual(config.read_text(encoding="utf-8"), original)

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
            with (
                mock.patch.object(update, "UPDATE_CONFIG_FILE", config),
                mock.patch.object(update.sys, "frozen", True, create=True),
            ):
                update._record_update_check_result("update_available", now=3000)
            self.assertEqual(json.loads(config.read_text(encoding="utf-8")), {"auto_update": True})

    def test_source_update_checks_do_not_persist_cooldown_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "update.json"
            original = {
                "auto_update": True,
                "last_successful_check": 1000,
                "last_failed_check": 2000,
            }
            for result in ("success", "failure", "update_available"):
                with self.subTest(result=result):
                    config.write_text(json.dumps(original) + "\n", encoding="utf-8")
                    with (
                        mock.patch.object(update, "UPDATE_CONFIG_FILE", config),
                        mock.patch.object(update.sys, "frozen", False, create=True),
                    ):
                        update._record_update_check_result(result, now=3000)
                    self.assertEqual(json.loads(config.read_text(encoding="utf-8")), original)

    def test_configured_auto_update_skips_github_during_success_cooldown(self) -> None:
        args = SimpleNamespace(auto_update=False, no_auto_update=False, check_update=False)
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "load_auto_update_setting", return_value=True),
            mock.patch.object(update, "automatic_update_check_due", return_value=False),
            mock.patch.object(update, "check_for_update") as check,
        ):
            self.assertIsNone(update.handle_automatic_update(args, []))
        check.assert_not_called()

    def test_explicit_auto_update_bypasses_check_cooldown(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "automatic_update_check_due") as cooldown,
            mock.patch.object(update, "check_for_update", return_value=None) as check,
            mock.patch.object(update, "_record_update_check_result") as record,
        ):
            self.assertIsNone(update.handle_automatic_update(args, []))
        cooldown.assert_not_called()
        check.assert_called_once_with()
        record.assert_called_once_with("success")

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

    def test_update_preparation_failure_retries_on_next_launch(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        release = {"version": "1.5", "assets": [], "url": "https://example.test/release"}
        stderr = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "TEMP_ROOT", Path(tmp) / "temp"),
            mock.patch.object(update, "automatic_update_check_due", return_value=True),
            mock.patch.object(update, "check_for_update", return_value=release),
            mock.patch.object(
                update,
                "_copy_application_for_update",
                side_effect=RuntimeError("Current Ninja Patch Tool executable is missing"),
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
        record.assert_called_once_with("update_available")
        self.assertIn("Current Ninja Patch Tool executable is missing", stderr.getvalue())

    def test_temporary_self_updater_version_check_accepts_matching_version(self) -> None:
        updater_path = Path("NinjaPatchToolUpdater.exe")
        result = SimpleNamespace(returncode=0, stdout=f"Ninja Patch Tool v{common.display_version()}\n", stderr="")
        with mock.patch.object(update.subprocess, "run", return_value=result) as run:
            update._validate_temporary_updater(updater_path)
        run.assert_called_once_with(
            [str(updater_path), "--update-installer", "--version"],
            cwd=update.TOOL_DIR,
            capture_output=True,
            text=True,
            timeout=150,
            check=False,
        )

    def test_installed_version_validation_allows_slow_onefile_startup(self) -> None:
        result = SimpleNamespace(returncode=0, stdout=f"Ninja Patch Tool v{common.display_version()}\n", stderr="")
        with mock.patch.object(update.subprocess, "run", return_value=result) as run:
            self.assertEqual(
                update._read_installed_version(Path("make_patch.exe"), Path(".")),
                common.display_version(),
            )
        self.assertEqual(run.call_args.kwargs["timeout"], 150)

    def test_copy_application_for_update_stays_inside_update_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "make_patch.exe"
            source.write_bytes(b"tool")
            work = root / "temp" / "update_deadbeef"
            work.mkdir(parents=True)
            with (
                mock.patch.object(update, "_current_application_path", return_value=source),
                mock.patch.object(update, "_validate_temporary_updater") as validate,
            ):
                copied = update._copy_application_for_update(work)
            validate.assert_called_once_with(copied)
            self.assertEqual(copied, work / "NinjaPatchToolUpdater.exe")
            self.assertEqual(copied.read_bytes(), b"tool")

    def test_wrong_temporary_updater_version_is_rejected(self) -> None:
        updater_path = Path("NinjaPatchToolUpdater.exe")
        result = SimpleNamespace(returncode=0, stdout="Ninja Patch Tool v1.3.1\n", stderr="")
        with mock.patch.object(update.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "version does not match"):
                update._validate_temporary_updater(updater_path)

    def test_launch_updater_revalidates_self_copy_immediately_before_handoff(self) -> None:
        updater_path = Path("C:/NPT/temp/update_deadbeef/NinjaPatchToolUpdater.exe")
        stage = Path("C:/NPT/temp/update_deadbeef/stage")
        with (
            mock.patch.object(update, "_validate_temporary_updater") as validate,
            mock.patch.object(update.subprocess, "Popen", return_value=SimpleNamespace()) as popen,
            mock.patch.object(update.sys, "executable", "C:/NPT/make_patch.exe"),
        ):
            update.launch_updater(updater_path, stage, ["base", "new"], "1.5")
        validate.assert_called_once_with(updater_path)
        command = popen.call_args.args[0]
        self.assertEqual(command[0], str(updater_path))
        self.assertEqual(command[1], "--update-installer")
        self.assertEqual(popen.call_args.kwargs["env"]["PYINSTALLER_RESET_ENVIRONMENT"], "1")

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
                mock.patch.object(update, "_copy_application_for_update", return_value=Path("NinjaPatchToolUpdater.exe")),
                mock.patch.object(update, "_record_update_check_result"),
                mock.patch.object(update, "download_release", side_effect=KeyboardInterrupt),
                mock.patch("sys.stderr", io.StringIO()),
            ):
                self.assertEqual(update.handle_automatic_update(args, []), 130)
            self.assertFalse(temp_root.exists())

    def test_restarted_update_session_skips_exactly_one_update_check(self) -> None:
        args = SimpleNamespace(auto_update=True, no_auto_update=False, check_update=False)
        with (
            mock.patch.dict(update.os.environ, {"NPT_SKIP_UPDATE_CHECK_ONCE": "1"}, clear=False),
            mock.patch.object(update, "check_for_update") as check,
        ):
            self.assertIsNone(update.handle_automatic_update(args, ["-a"]))
            self.assertNotIn("NPT_SKIP_UPDATE_CHECK_ONCE", update.os.environ)
        check.assert_not_called()

    def test_update_handoff_happens_before_add_base_operation(self) -> None:
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

    def test_add_base_existing_name_is_rejected_after_update_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            make_warframe_root(base)
            entry = {"steam_manifest_id": 123, "sha256": "a" * 64, "file_count": 1}
            index_file = Path(tmp) / "index.json"
            argv = ["add_base.py", str(base), "U43.5.1", "456"]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(common, "INDEX_FILE", index_file),
                mock.patch.object(add_base, "install_termination_handlers"),
                mock.patch.object(add_base, "handle_early_update_request", return_value=None),
                mock.patch.object(add_base, "operation_lock", return_value=nullcontext()),
                mock.patch.object(add_base, "load_index", return_value={"U43.5.1": entry}),
                mock.patch.object(add_base, "handle_automatic_update", return_value=None) as auto_update,
                mock.patch.object(add_base, "scan_tree") as scan,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(add_base.main(), 1)
            auto_update.assert_called_once()
            scan.assert_not_called()
            self.assertIn('Base "U43.5.1" already exists', stderr.getvalue())

    def test_add_base_existing_manifest_is_rejected_after_update_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            make_warframe_root(base)
            entry = {"steam_manifest_id": 456, "sha256": "a" * 64, "file_count": 1}
            index_file = Path(tmp) / "index.json"
            argv = ["add_base.py", str(base), "U43.5.2", "456"]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(common, "INDEX_FILE", index_file),
                mock.patch.object(add_base, "install_termination_handlers"),
                mock.patch.object(add_base, "handle_early_update_request", return_value=None),
                mock.patch.object(add_base, "operation_lock", return_value=nullcontext()),
                mock.patch.object(add_base, "load_index", return_value={"U43.5.1": entry}),
                mock.patch.object(add_base, "handle_automatic_update", return_value=None) as auto_update,
                mock.patch.object(add_base, "scan_tree") as scan,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(add_base.main(), 1)
            auto_update.assert_called_once()
            scan.assert_not_called()
            self.assertIn('[Steam] Manifest ID 456 is already indexed as "U43.5.1"', stderr.getvalue())

    def test_add_base_rechecks_index_after_hash_to_close_race(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            make_warframe_root(base)
            entry = {"steam_manifest_id": 999, "sha256": "b" * 64, "file_count": 1}
            index_file = Path(tmp) / "index.json"
            argv = ["add_base.py", str(base), "U43.5.2", "456"]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(common, "INDEX_FILE", index_file),
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

    def test_update_handoff_happens_before_verify_base_operation(self) -> None:
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

    def test_verify_base_missing_index_entry_is_rejected_after_update_check(self) -> None:
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
                mock.patch.object(verify_base, "handle_automatic_update", return_value=None) as auto_update,
                mock.patch.object(verify_base, "scan_tree") as scan,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(verify_base.main(), 1)
            auto_update.assert_called_once()
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

            def fake_download(url: str, destination: Path, expected_size=None, progress_label=None, max_size=None) -> None:
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

    def test_update_download_rejects_excess_bytes_before_writing_them(self) -> None:
        class Response(io.BytesIO):
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "release.zip"
            with mock.patch.object(update, "_request", return_value=Response(b"123456")):
                with self.assertRaisesRegex(RuntimeError, "exceeds the expected size"):
                    update._download_file("https://example.test/release.zip", destination, expected_size=5)
            self.assertFalse(destination.exists())
            self.assertFalse(destination.with_name(destination.name + ".part").exists())

    def test_release_assets_require_valid_sizes(self) -> None:
        for size in (None, -1, True, "123"):
            with self.subTest(size=size):
                release = {"assets": [{"name": "asset.zip", "browser_download_url": "https://example.test/asset.zip", "size": size}]}
                with self.assertRaisesRegex(RuntimeError, "invalid or missing size"):
                    update.find_release_asset(release, "asset.zip")

    def test_update_metadata_response_has_size_limit(self) -> None:
        class Response(io.BytesIO):
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()

        payload = b"{" + b" " * update.MAX_GITHUB_JSON_BYTES + b"}"
        with mock.patch.object(update, "_request", return_value=Response(payload)):
            with self.assertRaisesRegex(RuntimeError, "unexpectedly large"):
                update._request_json("https://example.test/latest")

    def test_malformed_update_metadata_reports_github_context(self) -> None:
        for payload in (b'{"tag_name":', b'\xff'):
            with self.subTest(payload=payload):
                with mock.patch.object(update, "_request", return_value=io.BytesIO(payload)):
                    with self.assertRaisesRegex(RuntimeError, "GitHub returned invalid JSON:"):
                        update._request_json("https://example.test/latest")

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
                "README.txt": b"readme",
                "data/index.json": b"{}",
                "data/update.json": b'{"auto_update": true}',
                "data/hdiffz.exe": b"exe",
                "data/hpatchz.exe": b"exe",
                "data/licenses/Ninja-Patch-Tool-LICENSE.txt": b"license",
            }
            add_release_manifest(files, "1.5")
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name, payload in files.items():
                    archive.writestr(f"{release_root}/{name}", payload)
            stage = update.extract_release_archive(archive_path, root / "stage", "1.5")
            self.assertEqual((stage / "README.txt").read_bytes(), b"readme")
            self.assertTrue((stage / "data" / "licenses" / "Ninja-Patch-Tool-LICENSE.txt").is_file())

    def test_update_archive_rejects_release_manifest_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "release.zip"
            release_root = "NinjaPatchTool-v1.5"
            files = {
                "add_base.exe": b"exe",
                "verify_base.exe": b"exe",
                "make_patch.exe": b"exe",
                "apply_patch.exe": b"exe",
                "README.txt": b"readme",
                "data/index.json": b"{}",
                "data/update.json": b'{"auto_update": true}',
                "data/hdiffz.exe": b"exe",
                "data/hpatchz.exe": b"exe",
                "data/licenses/Ninja-Patch-Tool-LICENSE.txt": b"license",
            }
            add_release_manifest(files, "1.5")
            files["make_patch.exe"] = b"tampered"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name, payload in files.items():
                    archive.writestr(f"{release_root}/{name}", payload)
            with self.assertRaisesRegex(RuntimeError, "SHA-256 does not match"):
                update.extract_release_archive(archive_path, root / "stage", "1.5")

    def test_update_archive_rejects_invalid_index_schema_before_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "release.zip"
            release_root = "NinjaPatchTool-v1.5"
            files = {
                "add_base.exe": b"exe",
                "verify_base.exe": b"exe",
                "make_patch.exe": b"exe",
                "apply_patch.exe": b"exe",
                "README.txt": b"readme",
                "data/index.json": b'{"U1": {}}',
                "data/update.json": b'{"auto_update": true}',
                "data/hdiffz.exe": b"exe",
                "data/hpatchz.exe": b"exe",
                "data/licenses/Ninja-Patch-Tool-LICENSE.txt": b"license",
            }
            add_release_manifest(files, "1.5")
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name, payload in files.items():
                    archive.writestr(f"{release_root}/{name}", payload)

            with self.assertRaisesRegex(RuntimeError, "invalid or missing steam_manifest_id"):
                update.extract_release_archive(archive_path, root / "stage", "1.5")

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

    def test_updater_merges_release_index_preserves_update_config_and_replaces_release_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            (install / "data" / "licenses").mkdir(parents=True)
            (stage / "data" / "licenses").mkdir(parents=True)
            (install / "make_patch.exe").write_bytes(b"old")
            (stage / "make_patch.exe").write_bytes(b"new")
            installed_index = {
                "LocalBase": {"steam_manifest_id": 1, "sha256": "1" * 64, "file_count": 10}
            }
            release_index = {
                "U44": {"steam_manifest_id": 2, "sha256": "2" * 64, "file_count": 20}
            }
            (install / "data" / "index.json").write_text(json.dumps(installed_index), encoding="utf-8")
            (stage / "data" / "index.json").write_text(json.dumps(release_index), encoding="utf-8")
            (install / "data" / "update.json").write_text('{"auto_update": false}', encoding="utf-8")
            (stage / "data" / "update.json").write_text('{"auto_update": true}', encoding="utf-8")
            (install / "data" / "licenses" / "old.txt").write_text("old", encoding="utf-8")
            (stage / "data" / "licenses" / "new.txt").write_text("new", encoding="utf-8")
            (stage / "data" / "hdiffz.exe").write_bytes(b"new hdiff")
            write_stage_release_manifest(stage)

            backup, _ = update.install_staged_release(stage, install, common.VERSION)
            self.assertTrue(backup.is_dir())
            self.assertEqual((install / "make_patch.exe").read_bytes(), b"new")
            self.assertEqual(
                json.loads((install / "data" / "index.json").read_text(encoding="utf-8")),
                {**installed_index, **release_index},
            )
            self.assertEqual((install / "data" / "update.json").read_text(encoding="utf-8"), '{"auto_update": false}')
            self.assertEqual({path.name for path in (install / "data" / "licenses").iterdir()}, {"new.txt"})
            self.assertEqual((install / "data" / "hdiffz.exe").read_bytes(), b"new hdiff")

    def test_updater_release_index_replaces_conflicting_local_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            (install / "data").mkdir(parents=True)
            (stage / "data").mkdir(parents=True)
            installed_index = {
                "CustomAlias": {"steam_manifest_id": 10, "sha256": "a" * 64, "file_count": 1},
                "KeepMe": {"steam_manifest_id": 11, "sha256": "b" * 64, "file_count": 2},
            }
            release_index = {
                "U44.1": {"steam_manifest_id": 10, "sha256": "a" * 64, "file_count": 3}
            }
            (install / "data" / "index.json").write_text(json.dumps(installed_index), encoding="utf-8")
            (stage / "data" / "index.json").write_text(json.dumps(release_index), encoding="utf-8")
            write_stage_release_manifest(stage)

            update.install_staged_release(stage, install, common.VERSION)
            merged = json.loads((install / "data" / "index.json").read_text(encoding="utf-8"))
            self.assertNotIn("CustomAlias", merged)
            self.assertEqual(merged["U44.1"], release_index["U44.1"])
            self.assertEqual(merged["KeepMe"], installed_index["KeepMe"])

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
            write_stage_release_manifest(stage)
            original_copy = update._copy_item

            def fail_on_b(source: Path, destination: Path) -> None:
                if source.name == "b.exe":
                    raise OSError("copy failed")
                original_copy(source, destination)

            with mock.patch.object(update, "_copy_item", side_effect=fail_on_b):
                with self.assertRaisesRegex(OSError, "copy failed"):
                    update.install_staged_release(stage, install, common.VERSION)
            self.assertEqual((install / "a.exe").read_bytes(), b"old a")
            self.assertEqual((install / "b.exe").read_bytes(), b"old b")

    def test_release_manifest_removes_only_unchanged_obsolete_release_files_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)

            unchanged = install / "obsolete.exe"
            modified = install / "modified.exe"
            unowned = install / "user-file.txt"
            unchanged.write_bytes(b"old unchanged")
            modified.write_bytes(b"locally modified")
            unowned.write_bytes(b"user")
            old_manifest = {
                "format_version": common.RELEASE_MANIFEST_VERSION,
                "application_version": "1.4.4",
                "files": {
                    "obsolete.exe": sha256_bytes(b"old unchanged"),
                    "modified.exe": sha256_bytes(b"original release bytes"),
                },
            }
            (install / common.RELEASE_MANIFEST_FILE).parent.mkdir(parents=True, exist_ok=True)
            (install / common.RELEASE_MANIFEST_FILE).write_text(json.dumps(old_manifest), encoding="utf-8")

            (stage / "new.exe").write_bytes(b"new")
            write_stage_release_manifest(stage, "1.4.5")
            backup, changes = update.install_staged_release(stage, install, "1.4.5")

            self.assertFalse(unchanged.exists())
            self.assertEqual(modified.read_bytes(), b"locally modified")
            self.assertEqual(unowned.read_bytes(), b"user")
            self.assertEqual((install / "new.exe").read_bytes(), b"new")

            update.rollback_staged_release(changes, backup)
            self.assertEqual(unchanged.read_bytes(), b"old unchanged")
            self.assertEqual(modified.read_bytes(), b"locally modified")
            self.assertEqual(unowned.read_bytes(), b"user")
            self.assertFalse((install / "new.exe").exists())
            self.assertEqual(
                json.loads((install / common.RELEASE_MANIFEST_FILE).read_text(encoding="utf-8")),
                old_manifest,
            )

    def test_updater_preserves_work_when_install_rollback_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "temp" / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" / "stage"
            backup = stage.parent / "backup_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            backup.mkdir()
            executable = install / "make_patch.exe"
            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "write_update_session"),
                mock.patch.object(update, "wait_for_process_exit"),
                mock.patch.object(update, "updater_install_lock", return_value=nullcontext()),
                mock.patch.object(update, "exclusive_operation_activity_lock", return_value=nullcontext()),
                mock.patch.object(update, "installed_executable_satisfies_target", return_value=None),
                mock.patch.object(update, "install_staged_release", side_effect=RuntimeError("rollback incomplete")),
                mock.patch.object(update, "relaunch") as relaunch,
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.5.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                ])
            self.assertEqual(result, 1)
            self.assertTrue(backup.is_dir())
            relaunch.assert_not_called()

    def test_updater_can_roll_back_after_post_install_validation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            (install / "make_patch.exe").write_bytes(b"old")
            (stage / "make_patch.exe").write_bytes(b"new")
            write_stage_release_manifest(stage)

            backup, changes = update.install_staged_release(stage, install, common.VERSION)
            self.assertEqual((install / "make_patch.exe").read_bytes(), b"new")
            update.rollback_staged_release(changes, backup)
            self.assertEqual((install / "make_patch.exe").read_bytes(), b"old")

    def test_updater_defers_when_another_operation_is_active_and_relaunches_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            executable = install / "make_patch.exe"
            stdout = io.StringIO()
            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "write_update_session"),
                mock.patch.object(update, "wait_for_process_exit"),
                mock.patch.object(update, "updater_install_lock", return_value=nullcontext()),
                mock.patch.object(
                    update,
                    "exclusive_operation_activity_lock",
                    side_effect=common.ActiveOperationError("active"),
                ),
                mock.patch.object(update, "install_staged_release") as install_release,
                mock.patch.object(update, "relaunch") as relaunch,
                mock.patch("sys.stdout", stdout),
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.5.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                    "--", "base", "patch",
                ])
            self.assertEqual(result, 0)
            install_release.assert_not_called()
            relaunch.assert_called_once_with(executable.resolve(), ["base", "patch"], root.resolve(), stage.parent)
            self.assertIn("Installation deferred", stdout.getvalue())

    def test_updater_releases_all_installation_locks_before_relaunch(self) -> None:
        events: list[str] = []

        @contextmanager
        def updater_lock(*args, **kwargs):
            events.append("updater-enter")
            try:
                yield
            finally:
                events.append("updater-exit")

        @contextmanager
        def activity_lock(*args, **kwargs):
            events.append("activity-enter")
            try:
                yield
            finally:
                events.append("activity-exit")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            backup = root / "work" / "backup"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            backup.mkdir()
            executable = install / "make_patch.exe"
            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "write_update_session"),
                mock.patch.object(update, "wait_for_process_exit"),
                mock.patch.object(update, "updater_install_lock", side_effect=updater_lock),
                mock.patch.object(update, "exclusive_operation_activity_lock", side_effect=activity_lock),
                mock.patch.object(update, "installed_executable_satisfies_target", return_value=None),
                mock.patch.object(update, "install_staged_release", side_effect=lambda *args, **kwargs: (events.append("install") or (backup, []))),
                mock.patch.object(update, "validate_installed_executable", side_effect=lambda *args: events.append("validate")),
                mock.patch.object(update, "mark_update_session_committed", side_effect=lambda *args: events.append("commit")),
                mock.patch.object(update, "relaunch", side_effect=lambda *args: events.append("relaunch")),
                mock.patch("sys.stdout", io.StringIO()),
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.5.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                ])
            self.assertEqual(result, 0)
        self.assertLess(events.index("validate"), events.index("activity-exit"))
        self.assertLess(events.index("activity-exit"), events.index("updater-exit"))
        self.assertLess(events.index("updater-exit"), events.index("relaunch"))

    def test_updater_does_not_relaunch_while_another_updater_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            executable = install / "make_patch.exe"
            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "write_update_session"),
                mock.patch.object(update, "wait_for_process_exit"),
                mock.patch.object(update, "updater_install_lock", side_effect=update.UpdaterBusyError("busy")),
                mock.patch.object(update, "cleanup_deferred_update_payload") as cleanup_deferred,
                mock.patch.object(update, "relaunch") as relaunch,
                mock.patch("sys.stdout", io.StringIO()),
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.5.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                ])
            self.assertEqual(result, 0)
            cleanup_deferred.assert_called_once_with(stage.parent)
            relaunch.assert_not_called()

    def test_updater_install_lock_defers_immediately_and_is_installation_scoped(self) -> None:
        fake_msvcrt = SimpleNamespace(
            LK_NBLCK=1,
            LK_UNLCK=2,
            locking=mock.MagicMock(side_effect=OSError(errno.EACCES, "busy")),
        )
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(sys.modules, {"msvcrt": fake_msvcrt}):
            install = Path(tmp)
            with self.assertRaisesRegex(update.UpdaterBusyError, "already in progress"):
                with update.updater_install_lock(install):
                    pass
            self.assertTrue(update.updater_install_lock_path(install).is_file())
        fake_msvcrt.locking.assert_called_once()
        self.assertEqual(fake_msvcrt.locking.call_args.args[1:], (fake_msvcrt.LK_NBLCK, 1))

    def test_updater_queued_target_is_satisfied_by_equal_or_newer_installation(self) -> None:
        executable = Path("tool.exe")
        cwd = Path(".")
        with mock.patch.object(update, "_read_installed_version", return_value="1.5"):
            self.assertEqual(update.installed_executable_satisfies_target(executable, "1.5", cwd), "1.5")
        with mock.patch.object(update, "_read_installed_version", return_value="1.6"):
            self.assertEqual(update.installed_executable_satisfies_target(executable, "1.5", cwd), "1.6")
        with mock.patch.object(update, "_read_installed_version", return_value="1.5.0"):
            self.assertEqual(update.installed_executable_satisfies_target(executable, "1.5", cwd), "1.5.0")
        with mock.patch.object(update, "_read_installed_version", return_value="1.4.9"):
            self.assertIsNone(update.installed_executable_satisfies_target(executable, "1.5", cwd))
        with mock.patch.object(update, "_read_installed_version", side_effect=RuntimeError("not runnable")):
            self.assertIsNone(update.installed_executable_satisfies_target(executable, "1.5", cwd))

    def test_updater_rejects_staged_version_mismatch_before_backup_or_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            installed = install / "make_patch.exe"
            installed.write_bytes(b"old")
            (stage / "make_patch.exe").write_bytes(b"unexpected-release")
            write_stage_release_manifest(stage, "9.9.9")

            with self.assertRaisesRegex(RuntimeError, "does not match the downloaded release"):
                update.install_staged_release(stage, install, "1.5")

            self.assertEqual(installed.read_bytes(), b"old")
            self.assertEqual((stage / "make_patch.exe").read_bytes(), b"unexpected-release")
            self.assertFalse(any(update._UPDATE_BACKUP_NAME_RE.fullmatch(path.name) for path in stage.parent.iterdir()))

    def test_release_manifest_rejects_preserved_paths_case_insensitively(self) -> None:
        for managed_path in (
            "Data/Index.JSON",
            "DATA/UPDATE.JSON",
            "DATA/RELEASE_MANIFEST.JSON",
        ):
            with self.subTest(managed_path=managed_path), tempfile.TemporaryDirectory() as tmp:
                manifest = Path(tmp) / "release_manifest.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "format_version": common.RELEASE_MANIFEST_VERSION,
                            "application_version": common.VERSION,
                            "files": {managed_path: "0" * 64},
                        }
                    ),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(RuntimeError, "invalid managed path"):
                    update._parse_release_manifest(manifest)

    def test_updater_rolls_back_when_installed_file_changes_before_post_install_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            (install / "make_patch.exe").write_bytes(b"old-exe")
            (install / "README.txt").write_text("old readme", encoding="utf-8")
            (stage / "make_patch.exe").write_bytes(b"new-exe")
            (stage / "README.txt").write_text("new readme", encoding="utf-8")
            write_stage_release_manifest(stage)
            original_copy = update._copy_item

            def copy_then_tamper(source: Path, destination: Path) -> None:
                original_copy(source, destination)
                if destination.name == "README.txt":
                    destination.write_text("tampered after staged validation", encoding="utf-8")

            with (
                mock.patch.object(update, "_copy_item", side_effect=copy_then_tamper),
                self.assertRaisesRegex(RuntimeError, "Installed release SHA-256 does not match 'README.txt'"),
            ):
                update.install_staged_release(stage, install, common.VERSION)

            self.assertEqual((install / "make_patch.exe").read_bytes(), b"old-exe")
            self.assertEqual((install / "README.txt").read_text(encoding="utf-8"), "old readme")
            self.assertFalse((install / common.RELEASE_MANIFEST_FILE).exists())

    def test_updater_post_install_validation_accepts_equivalent_version_text(self) -> None:
        with mock.patch.object(update, "_read_installed_version", return_value="1.5"):
            update.validate_installed_executable(Path("tool.exe"), "1.5.0", Path("."))

    def test_updater_post_install_validation_rejects_different_version(self) -> None:
        with mock.patch.object(update, "_read_installed_version", return_value="1.6"):
            with self.assertRaisesRegex(RuntimeError, "expected v1.5, got v1.6"):
                update.validate_installed_executable(Path("tool.exe"), "1.5.0", Path("."))

    def test_stale_update_work_cleanup_removes_only_safe_old_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            temp_root.mkdir()
            old = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            old.mkdir()
            (old / "stage").mkdir()
            protected = temp_root / "update_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            protected.mkdir()
            (protected / "backup_cccccccccccccccccccccccccccccccc").mkdir()
            recent = temp_root / "update_dddddddddddddddddddddddddddddddd"
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

    def test_stale_update_work_preserves_active_self_updater_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            work.mkdir(parents=True)
            (work / update.UPDATE_SESSION_FILE).write_text(
                json.dumps({"pid": 123, "process_identity": "123:456"}), encoding="utf-8"
            )
            now = 2_000_000.0
            old_time = now - update.STALE_UPDATE_AGE_SECONDS - 1
            update.os.utime(work, (old_time, old_time))

            with (
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update.time, "time", return_value=now),
                mock.patch.object(update, "process_matches_identity", return_value=True) as matches,
            ):
                update.cleanup_stale_update_work()

            self.assertTrue(work.is_dir())
            matches.assert_called_once_with(123, "123:456")

    def test_stale_update_work_removes_inactive_self_updater_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_ffffffffffffffffffffffffffffffff"
            work.mkdir(parents=True)
            (work / update.UPDATE_SESSION_FILE).write_text(
                json.dumps({"pid": 123, "process_identity": "123:456"}), encoding="utf-8"
            )
            now = 2_000_000.0
            old_time = now - update.STALE_UPDATE_AGE_SECONDS - 1
            update.os.utime(work, (old_time, old_time))

            with (
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update.time, "time", return_value=now),
                mock.patch.object(update, "process_matches_identity", return_value=False),
            ):
                update.cleanup_stale_update_work()

            self.assertFalse(work.exists())
            self.assertFalse(temp_root.exists())

    def test_stale_update_work_removes_malformed_session_without_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_55555555555555555555555555555555"
            work.mkdir(parents=True)
            (work / update.UPDATE_SESSION_FILE).write_text("{not-json", encoding="utf-8")
            now = 2_000_000.0
            old_time = now - update.STALE_UPDATE_AGE_SECONDS - 1
            update.os.utime(work, (old_time, old_time))

            with (
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update.time, "time", return_value=now),
            ):
                update.cleanup_stale_update_work()

            self.assertFalse(work.exists())

    def test_malformed_update_session_never_makes_backup_disposable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_66666666666666666666666666666666"
            backup = work / "backup_77777777777777777777777777777777"
            backup.mkdir(parents=True)
            (work / update.UPDATE_SESSION_FILE).write_text("{not-json", encoding="utf-8")
            now = 2_000_000.0
            old_time = now - update.STALE_UPDATE_AGE_SECONDS - 1
            update.os.utime(work, (old_time, old_time))

            with (
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update.time, "time", return_value=now),
            ):
                update.cleanup_stale_update_work()

            self.assertTrue(work.is_dir())
            self.assertTrue(backup.is_dir())

    def test_stale_update_cleanup_ignores_non_owned_update_prefix_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_notes"
            work.mkdir(parents=True)
            now = 2_000_000.0
            old_time = now - update.STALE_UPDATE_AGE_SECONDS - 1
            update.os.utime(work, (old_time, old_time))
            with mock.patch.object(update, "TEMP_ROOT", temp_root), mock.patch.object(update.time, "time", return_value=now):
                update.cleanup_stale_update_work()
            self.assertTrue(work.is_dir())

    def test_backup_prefix_without_owned_id_is_not_recovery_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "update_88888888888888888888888888888888"
            (work / "backup_notes").mkdir(parents=True)
            self.assertFalse(update._update_work_has_backup(work))

    def test_relaunched_tool_cleans_completed_update_work_inside_temp_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_11111111111111111111111111111111"
            work.mkdir(parents=True)
            (work / "NinjaPatchToolUpdater.exe").write_bytes(b"exe")
            with (
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.dict(update.os.environ, {"NPT_UPDATE_WORK_CLEANUP": str(work)}, clear=True),
            ):
                update.cleanup_relaunched_update_work()
            self.assertFalse(work.exists())
            self.assertFalse(temp_root.exists())

    def test_relaunched_tool_cleans_transient_success_backup_with_update_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_22222222222222222222222222222222"
            (work / "backup_33333333333333333333333333333333").mkdir(parents=True)
            (work / update.UPDATE_SESSION_FILE).write_text(
                json.dumps(
                    {
                        "pid": 123,
                        "process_identity": "123:456",
                        "transaction_state": "committed",
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.dict(update.os.environ, {"NPT_UPDATE_WORK_CLEANUP": str(work)}, clear=True),
            ):
                update.cleanup_relaunched_update_work()
            self.assertFalse(work.exists())

    def test_legacy_updater_cleanup_removes_only_identified_old_release_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tool_dir = Path(tmp)
            legacy_updater = tool_dir / "updater.exe"
            legacy_updater.write_bytes(b"legacy")
            with (
                mock.patch.object(update, "TOOL_DIR", tool_dir),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update.sys, "frozen", True, create=True),
                mock.patch.object(update.sys, "executable", str(tool_dir / "make_patch.exe")),
                mock.patch.object(update, "_is_known_legacy_updater", return_value=True),
            ):
                update.cleanup_legacy_updater_executable()
            self.assertFalse(legacy_updater.exists())

    def test_legacy_updater_cleanup_preserves_unrecognized_updater(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tool_dir = Path(tmp)
            legacy_updater = tool_dir / "updater.exe"
            legacy_updater.write_bytes(b"user file")
            with (
                mock.patch.object(update, "TOOL_DIR", tool_dir),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update.sys, "frozen", True, create=True),
                mock.patch.object(update.sys, "executable", str(tool_dir / "make_patch.exe")),
                mock.patch.object(update, "_is_known_legacy_updater", return_value=False),
            ):
                update.cleanup_legacy_updater_executable()
            self.assertTrue(legacy_updater.exists())

    def test_legacy_updater_identity_requires_old_npt_updater_metadata(self) -> None:
        valid = {
            "ProductName": "Ninja Patch Tool",
            "ProductVersion": "1.4.0.0",
            "FileDescription": "Ninja Patch Tool Updater",
            "InternalName": "updater",
        }
        wrong_product = {**valid, "ProductName": "Other Tool"}
        wrong_version = {**valid, "ProductVersion": "1.4.1"}
        not_updater = {**valid, "FileDescription": "Ninja Patch Tool", "InternalName": "make_patch"}
        for metadata, expected in ((valid, True), (wrong_product, False), (wrong_version, False), (not_updater, False), ({}, False)):
            with mock.patch.object(update, "_legacy_updater_version_info", return_value=metadata):
                self.assertEqual(update._is_known_legacy_updater(Path("updater.exe")), expected)

    def test_legacy_updater_cleanup_is_release_only_and_best_effort(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tool_dir = Path(tmp)
            legacy_updater = tool_dir / "updater.exe"
            legacy_updater.write_bytes(b"legacy")

            with (
                mock.patch.object(update, "TOOL_DIR", tool_dir),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update.sys, "frozen", False, create=True),
            ):
                update.cleanup_legacy_updater_executable()
            self.assertTrue(legacy_updater.exists())

            with (
                mock.patch.object(update, "TOOL_DIR", tool_dir),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update.sys, "frozen", True, create=True),
                mock.patch.object(update.sys, "executable", str(tool_dir / "make_patch.exe")),
                mock.patch.object(update, "_is_known_legacy_updater", return_value=True),
                mock.patch.object(Path, "unlink", side_effect=PermissionError("locked")),
            ):
                update.cleanup_legacy_updater_executable()

    def test_update_installer_internal_mode_dispatches_before_startup_cleanup(self) -> None:
        with (
            mock.patch.object(update, "run_update_installer", return_value=7) as installer,
            mock.patch.object(update, "cleanup_legacy_updater_executable") as legacy_cleanup,
            mock.patch.object(update, "cleanup_relaunched_update_work") as cleanup,
            mock.patch.object(update, "cleanup_stale_update_work") as stale,
        ):
            self.assertEqual(update.handle_early_update_request(["--update-installer", "--version"]), 7)
        installer.assert_called_once_with(["--version"])
        legacy_cleanup.assert_not_called()
        cleanup.assert_not_called()
        stale.assert_not_called()

    def test_updater_writes_active_session_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "update_44444444444444444444444444444444"
            work.mkdir()
            with mock.patch.object(update, "process_identity", return_value="123:456"):
                with mock.patch.object(update.os, "getpid", return_value=123):
                    update.write_update_session(work)
            state = json.loads((work / update.UPDATE_SESSION_FILE).read_text(encoding="utf-8"))
            self.assertEqual(state, {"pid": 123, "process_identity": "123:456", "transaction_state": "active"})

    def test_updater_session_terminal_states_preserve_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            session = work / update.UPDATE_SESSION_FILE
            session.write_text(
                json.dumps(
                    {
                        "pid": 123,
                        "process_identity": "123:456",
                        "transaction_state": "active",
                    }
                ),
                encoding="utf-8",
            )
            update.mark_update_session_committed(work)
            self.assertEqual(json.loads(session.read_text(encoding="utf-8"))["transaction_state"], "committed")
            update.mark_update_session_rolled_back(work)
            state = json.loads(session.read_text(encoding="utf-8"))
            self.assertEqual(state["transaction_state"], "rolled_back")
            self.assertEqual(state["pid"], 123)
            self.assertEqual(state["process_identity"], "123:456")

    def test_updater_relaunch_uses_internal_one_shot_skip_without_changing_args(self) -> None:
        captured = {}

        def fake_popen(command, cwd=None, env=None):
            captured["command"] = command
            captured["cwd"] = cwd
            captured["env"] = env
            return SimpleNamespace()

        with mock.patch.object(update.subprocess, "Popen", side_effect=fake_popen):
            update.relaunch(
                Path("C:/NPT/make_patch.exe"),
                ["-a", "base", "new", "out", "U1"],
                Path("C:/work"),
                Path("C:/NPT/temp/update_deadbeef"),
            )

        self.assertEqual(captured["command"][1:], ["-a", "base", "new", "out", "U1"])
        self.assertEqual(captured["env"]["PYINSTALLER_RESET_ENVIRONMENT"], "1")
        self.assertEqual(captured["env"]["NPT_SKIP_UPDATE_CHECK_ONCE"], "1")
        self.assertEqual(
            captured["env"]["NPT_UPDATE_WORK_CLEANUP"],
            str(Path("C:/NPT/temp/update_deadbeef")),
        )
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

    def test_operation_lock_uses_global_user_scoped_mutex_on_windows(self) -> None:
        import ctypes

        kernel32 = SimpleNamespace(
            CreateMutexW=mock.MagicMock(return_value=123),
            WaitForSingleObject=mock.MagicMock(return_value=0),
            ReleaseMutex=mock.MagicMock(),
            CloseHandle=mock.MagicMock(),
        )
        target = Path("C:/Warframe")
        with (
            mock.patch.object(common.sys, "platform", "win32"),
            mock.patch.object(common, "windows_user_sid", return_value="S-1-5-21-42"),
            mock.patch.object(ctypes, "WinDLL", create=True, return_value=kernel32),
        ):
            with common.operation_lock("installation", target, "test operation"):
                pass
        mutex_name = kernel32.CreateMutexW.call_args.args[2]
        self.assertTrue(
            mutex_name.startswith(r"Global\DarkLotus.NinjaPatchTool.operation.S-1-5-21-42.installation.")
        )

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

    def test_obvious_missing_paths_fail_before_live_status_snapshot(self) -> None:
        cases = (
            (add_base, ["add_base.py", "missing-base", "U44.0", "123"]),
            (verify_base, ["verify_base.py", "missing-base", "U44.0"]),
            (make_patch, ["make_patch.py", "missing-base", "missing-new", "out.patch", "U44.0"]),
            (apply_patch, ["apply_patch.py", "missing-base", "missing.patch"]),
        )
        for module, argv in cases:
            with self.subTest(module=module.__name__):
                status = mock.Mock()
                with (
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(module, "print_live_status_once", status),
                    mock.patch.object(module, "install_termination_handlers"),
                    mock.patch.object(module, "handle_automatic_update", return_value=None),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(module.main(), 1)
                status.assert_not_called()

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

    def test_scan_tree_rejects_windows_unsafe_source_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "CON").write_bytes(b"bad")
            with self.assertRaisesRegex(RuntimeError, "cannot be represented safely"):
                common.scan_tree(root)

    def test_scan_tree_rejects_symlink_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.bin"
            link = root / "linked.bin"
            target.write_bytes(b"target")
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"Symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "symlink, junction, or reparse point"):
                common.scan_tree(root)

    def test_installation_root_symlink_is_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.mkdir()
            link = root / "linked-root"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "root must not be a symlink, junction, or reparse point"):
                common.validate_installation_root_entry(link)

    def test_reparse_attribute_is_detected(self) -> None:
        self.assertTrue(common.is_reparse_stat(SimpleNamespace(st_file_attributes=0x400)))
        self.assertFalse(common.is_reparse_stat(SimpleNamespace(st_file_attributes=0)))

    def test_scan_tree_rejects_case_insensitive_path_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Windows filesystems normally cannot contain both spellings at once, so
            # simulate the enumeration result instead of relying on the host filesystem.
            collision_paths = [root / "Foo.bin", root / "foo.bin"]
            with mock.patch.object(common, "validated_tree_paths", return_value=([], collision_paths)):
                with self.assertRaisesRegex(RuntimeError, "collide on Windows"):
                    common.scan_tree(root)

    def test_scan_tree_detects_atomic_replacement_with_same_size_and_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "file.bin"
            target.write_bytes(b"same")
            original_mtime = target.stat().st_mtime_ns
            original_hash = common.sha256_file

            def replace_during_hash(path: Path) -> str:
                digest = original_hash(path)
                replacement = root / "replacement.tmp"
                replacement.write_bytes(b"same")
                os.utime(replacement, ns=(original_mtime, original_mtime))
                os.replace(replacement, path)
                return digest

            with mock.patch.object(common, "sha256_file", side_effect=replace_during_hash):
                with self.assertRaisesRegex(RuntimeError, "changed while it was being scanned"):
                    common.scan_tree(root)

    def test_low_disk_space_is_only_a_warning(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(common.shutil, "disk_usage", return_value=SimpleNamespace(free=100)), mock.patch("sys.stderr", stderr):
            common.warn_if_low_disk_space(Path.cwd(), 200, "testing")
        self.assertIn("WARNING: Disk space may be insufficient", stderr.getvalue())

class MakePatchTests(unittest.TestCase):
    def test_stale_make_patch_cleanup_removes_dead_owned_work_for_other_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "temp"
            work = temp_root / "make_patch_123_deadbeef"
            work.mkdir(parents=True)
            first_output = (root / "first.patch").resolve()
            second_output = (root / "second.patch").resolve()
            first_partial = make_patch.temporary_patch_path(first_output, "a" * 32)
            (work / make_patch.MAKE_SESSION_FILE).write_text(
                json.dumps({
                    "pid": 123,
                    "process_identity": "dead",
                    "output": str(first_output),
                    "temporary_patch": str(first_partial),
                }),
                encoding="utf-8",
            )
            first_partial.write_bytes(b"partial")
            with (
                mock.patch.object(make_patch, "TEMP_ROOT", temp_root),
                mock.patch.object(make_patch, "process_matches_identity", return_value=False),
            ):
                make_patch.cleanup_stale_make_patch_work(second_output)
            self.assertFalse(work.exists())
            self.assertFalse(first_partial.exists())

    def test_unowned_randomized_patch_tmp_is_never_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            output = Path(tmp) / "output.patch"
            partial = make_patch.temporary_patch_path(output, "a" * 32)
            partial.write_bytes(b"unrelated")
            with mock.patch.object(make_patch, "TEMP_ROOT", temp_root):
                make_patch.cleanup_stale_make_patch_work(output)
            self.assertEqual(partial.read_bytes(), b"unrelated")

    def test_predictable_legacy_patch_tmp_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            output = Path(tmp) / "output.patch"
            legacy = output.with_name(output.name + ".tmp")
            legacy.write_bytes(b"unrelated")
            with mock.patch.object(make_patch, "TEMP_ROOT", temp_root):
                make_patch.cleanup_stale_make_patch_work(output)
            self.assertEqual(legacy.read_bytes(), b"unrelated")

    def test_known_stale_randomized_patch_tmp_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "make_patch_old"
            work.mkdir(parents=True)
            output = Path(tmp) / "output.patch"
            partial = make_patch.temporary_patch_path(output, "b" * 32)
            partial.write_bytes(b"partial")
            (work / make_patch.MAKE_SESSION_FILE).write_text(
                json.dumps({"pid": 123, "output": str(output), "temporary_patch": str(partial)}),
                encoding="utf-8",
            )
            with mock.patch.object(make_patch, "TEMP_ROOT", temp_root), mock.patch.object(make_patch, "process_matches_identity", return_value=False):
                make_patch.cleanup_stale_make_patch_work(output)
            self.assertFalse(partial.exists())
            self.assertFalse(work.exists())

    def test_stale_make_patch_work_without_session_is_removed_when_owner_is_dead(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "make_patch_123_deadbeef"
            work.mkdir(parents=True)
            output = Path(tmp) / "output.patch"
            with mock.patch.object(make_patch, "TEMP_ROOT", temp_root), mock.patch.object(make_patch, "process_matches_identity", return_value=False):
                make_patch.cleanup_stale_make_patch_work(output)
            self.assertFalse(work.exists())

    def test_complete_temporary_make_session_is_used_for_stale_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "make_patch_123_deadbeef"
            work.mkdir(parents=True)
            output = Path(tmp) / "output.patch"
            partial = make_patch.temporary_patch_path(output, "c" * 32)
            partial.write_bytes(b"partial")
            (work / f"{make_patch.MAKE_SESSION_FILE}.tmp").write_text(
                json.dumps({
                    "pid": 123,
                    "process_identity": "123:1",
                    "output": str(output),
                    "temporary_patch": str(partial),
                }),
                encoding="utf-8",
            )
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
            partial = make_patch.temporary_patch_path(output, "d" * 32)
            partial.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                make_patch.create_patch_archive(work, output, "normal", {}, partial)
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

            partial = make_patch.temporary_patch_path(output, "e" * 32)
            with mock.patch.object(make_patch, "publish_patch_archive", side_effect=race):
                with self.assertRaisesRegex(FileExistsError, "appeared while the patch was being created"):
                    make_patch.create_patch_archive(work, output, "normal", {}, partial)

            self.assertEqual(output.read_bytes(), b"unrelated")
            self.assertFalse(partial.exists())

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

    def test_update_handoff_happens_before_make_patch_operation(self) -> None:
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

    def test_patch_output_inside_installation_is_rejected_after_update_check(self) -> None:
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
                mock.patch.object(make_patch, "handle_automatic_update", return_value=None) as auto_update,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(make_patch.main(), 1)
            auto_update.assert_called_once()
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
    def test_update_handoff_happens_before_apply_patch_operation(self) -> None:
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

    def test_apply_missing_patch_is_rejected_after_update_check(self) -> None:
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
                mock.patch.object(apply_patch, "handle_automatic_update", return_value=None) as auto_update,
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(apply_patch.main(), 1)
            auto_update.assert_called_once()
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
        for path in ("Tools/Launcher.exe", "OpenWF/config/client.json", "version.dll", "Launch with OpenWF.bat"):
            with self.subTest(path=path):
                operation = {"type": "remove", "path": path, "old_size": 1, "old_sha256": "a" * 64}
                manifest = self.minimal_manifest(operation, old_count=1, new_count=0)
                with self.assertRaisesRegex(RuntimeError, "intentionally ignores"):
                    apply_patch.validate_manifest(manifest, {"manifest.json": zipfile.ZipInfo("manifest.json")})

    def test_manifest_allows_root_only_ignore_names_below_other_directories(self) -> None:
        operation = {"type": "remove", "path": "Tools/version.dll", "old_size": 1, "old_sha256": "a" * 64}
        manifest = self.minimal_manifest(operation, old_count=1, new_count=0)
        validated = apply_patch.validate_manifest(manifest, {"manifest.json": zipfile.ZipInfo("manifest.json")})
        self.assertEqual(validated["operations"], [operation])

    def test_manifest_rejects_windows_reserved_target(self) -> None:
        operation = {"type": "remove", "path": "CON.txt", "old_size": 1, "old_sha256": "a" * 64}
        manifest = self.minimal_manifest(operation, old_count=1, new_count=0)
        with self.assertRaisesRegex(RuntimeError, "unsafe path"):
            apply_patch.validate_manifest(manifest, {"manifest.json": zipfile.ZipInfo("manifest.json")})

    def test_apply_temporary_paths_are_session_owned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "a.bin"
            target.write_bytes(b"old")
            (root / "a.bin.tmp").write_bytes(b"mine")
            operation = {"type": "replace", "path": "a.bin"}
            token = "abc123"
            apply_patch.check_temporary_paths(root, [operation], token)
            owned = apply_patch.temporary_output(target, token)
            owned.write_bytes(b"owned")
            with self.assertRaisesRegex(RuntimeError, "Temporary output path already exists"):
                apply_patch.check_temporary_paths(root, [operation], token)
            self.assertEqual((root / "a.bin.tmp").read_bytes(), b"mine")

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

    def test_separate_copy_rejects_symlink_in_base_without_copying_external_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, destination = root / "base", root / "destination"
            external = root / "external.bin"
            make_warframe_root(base)
            external.write_bytes(b"external")
            link = base / "Cache.Windows" / "linked.bin"
            try:
                link.symlink_to(external)
            except OSError as exc:
                self.skipTest(f"Symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "symlink, junction, or reparse point"):
                apply_patch.copy_verified_base(base, destination)
            self.assertFalse(destination.exists())

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

    def test_separate_output_publication_accepts_existing_truly_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            working, destination = root / "working", root / "final"
            working.mkdir()
            destination.mkdir()
            (working / "ours.bin").write_bytes(b"ours")

            apply_patch.publish_output_directory(working, destination)

            self.assertFalse(working.exists())
            self.assertEqual((destination / "ours.bin").read_bytes(), b"ours")

    def test_separate_output_publication_refuses_existing_nonempty_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            working, destination = root / "working", root / "final"
            working.mkdir()
            destination.mkdir()
            (working / "ours.bin").write_bytes(b"ours")
            (destination / "theirs.bin").write_bytes(b"theirs")
            with self.assertRaisesRegex(FileExistsError, "already exists and is not empty"):
                apply_patch.publish_output_directory(working, destination)
            self.assertTrue((working / "ours.bin").is_file())
            self.assertEqual((destination / "theirs.bin").read_bytes(), b"theirs")

    def test_separate_output_publication_rechecks_empty_directory_before_claiming_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            working, destination = root / "working", root / "final"
            working.mkdir()
            destination.mkdir()
            (working / "ours.bin").write_bytes(b"ours")

            original = apply_patch.require_output_missing_or_empty
            checked = False

            def race(path: Path) -> bool:
                nonlocal checked
                result = original(path)
                if result and not checked:
                    checked = True
                    (path / "appeared.bin").write_bytes(b"external")
                return result

            with mock.patch.object(apply_patch, "require_output_missing_or_empty", side_effect=race):
                with self.assertRaisesRegex(FileExistsError, "no longer an empty directory"):
                    apply_patch.publish_output_directory(working, destination)

            self.assertTrue((working / "ours.bin").is_file())
            self.assertEqual((destination / "appeared.bin").read_bytes(), b"external")

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

    def test_v2_separate_recovery_publishes_completed_working_directory_over_original_empty_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, destination = root / "base", root / "final"
            make_warframe_root(base)
            destination.mkdir()
            work = root / "temp" / "apply_patch_test"
            working = apply_patch.separate_working_destination(destination, work)
            shutil.copytree(base, working)
            (working / "new.bin").write_bytes(b"new")
            old_hash, old_count = tree_identity(base)
            new_hash, new_count = tree_identity(working)
            state = {
                "mode": "separate", "phase": "publishing", "base": str(base), "destination": str(destination),
                "working_destination": str(working), "patch": str(root / "one.patch"),
                "old_root_sha256": old_hash, "new_root_sha256": new_hash,
                "old_file_count": old_count, "new_file_count": new_count,
                "destination_preexisting_empty": True,
            }
            write_recovery(work, state)
            with mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"), mock.patch.object(common, "TEMP_ROOT", root / "temp"):
                completed = apply_patch.recover_interrupted_operations(base, destination)
            self.assertIsNotNone(completed)
            self.assertFalse(working.exists())
            self.assertEqual((destination / "new.bin").read_bytes(), b"new")

    def test_v2_separate_recovery_leaves_original_empty_output_when_working_directory_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, destination = root / "base", root / "final"
            make_warframe_root(base)
            destination.mkdir()
            work = root / "temp" / "apply_patch_test"
            working = apply_patch.separate_working_destination(destination, work)
            working.mkdir(parents=True)
            (working / "partial.bin").write_bytes(b"partial")
            old_hash, old_count = tree_identity(base)
            state = {
                "mode": "separate", "phase": "applying", "base": str(base), "destination": str(destination),
                "working_destination": str(working), "patch": str(root / "one.patch"),
                "old_root_sha256": old_hash, "new_root_sha256": "b" * 64,
                "old_file_count": old_count, "new_file_count": 99,
                "destination_preexisting_empty": True,
            }
            write_recovery(work, state)
            with mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"), mock.patch.object(common, "TEMP_ROOT", root / "temp"):
                completed = apply_patch.recover_interrupted_operations(base, destination)
            self.assertIsNone(completed)
            self.assertTrue(destination.is_dir())
            self.assertEqual(list(destination.iterdir()), [])
            self.assertFalse(working.exists())
            self.assertFalse(work.exists())

    def test_v2_separate_recovery_does_not_claim_unrecorded_empty_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, destination = root / "base", root / "final"
            make_warframe_root(base)
            destination.mkdir()
            work = root / "temp" / "apply_patch_test"
            working = apply_patch.separate_working_destination(destination, work)
            working.mkdir(parents=True)
            old_hash, old_count = tree_identity(base)
            state = {
                "mode": "separate", "phase": "applying", "base": str(base), "destination": str(destination),
                "working_destination": str(working), "patch": str(root / "one.patch"),
                "old_root_sha256": old_hash, "new_root_sha256": "b" * 64,
                "old_file_count": old_count, "new_file_count": 99,
                "destination_preexisting_empty": False,
            }
            write_recovery(work, state)
            with mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"), mock.patch.object(common, "TEMP_ROOT", root / "temp"):
                with self.assertRaisesRegex(RuntimeError, "cannot be identified"):
                    apply_patch.recover_interrupted_operations(base, destination)
            self.assertTrue(destination.is_dir())
            self.assertTrue(working.is_dir())
            self.assertTrue(work.is_dir())

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

    def test_recovery_cleans_abandoned_apply_work_without_recovery_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            base.mkdir()
            work = root / "temp" / "apply_patch_12345_deadbeef"
            (work / "payload").mkdir(parents=True)
            with mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"), mock.patch.object(common, "TEMP_ROOT", root / "temp"), mock.patch.object(apply_patch, "process_matches_identity", return_value=False):
                self.assertIsNone(apply_patch.recover_interrupted_operations(base, base))
            self.assertFalse(work.exists())

    def test_recovery_preserves_orphaned_apply_backup_without_recovery_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            base.mkdir()
            work = root / "temp" / "apply_patch_12345_deadbeef"
            backup = work / "backup"
            backup.mkdir(parents=True)
            (backup / "original.bin").write_bytes(b"original")
            stderr = io.StringIO()
            with mock.patch.object(apply_patch, "TEMP_ROOT", root / "temp"), mock.patch.object(common, "TEMP_ROOT", root / "temp"), mock.patch("sys.stderr", stderr):
                self.assertIsNone(apply_patch.recover_interrupted_operations(base, base))
            self.assertTrue(work.exists())
            self.assertIn("recovery backup data", stderr.getvalue())

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

    def test_index_update_lock_is_filesystem_scoped_and_non_recursive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            index_file = Path(tmp) / "data" / "index.json"
            with common.index_update_lock(index_file):
                self.assertTrue(common.index_update_lock_path(index_file).is_file())
                with self.assertRaisesRegex(RuntimeError, "Another base index update"):
                    with common.index_update_lock(index_file):
                        pass
            with common.index_update_lock(index_file):
                pass

    def test_separate_copy_rejects_file_added_during_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, destination = root / "base", root / "destination"
            make_warframe_root(base)
            (base / "Cache.Windows" / "data.bin").write_bytes(b"A" * 1024)
            original_validated_tree_paths = apply_patch.validated_tree_paths
            calls = 0

            def changing_tree_paths(tree: Path):
                nonlocal calls
                calls += 1
                if calls == 2:
                    (base / "Cache.Windows" / "appeared-during-copy.bin").write_bytes(b"late")
                return original_validated_tree_paths(tree)

            with mock.patch.object(apply_patch, "validated_tree_paths", side_effect=changing_tree_paths):
                with self.assertRaisesRegex(RuntimeError, "Installation changed while it was being copied"):
                    apply_patch.copy_verified_base(base, destination)

    def test_updater_rejects_reparse_destination_hierarchy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            external = root / "external"
            install.mkdir()
            stage.mkdir(parents=True)
            external.mkdir()
            try:
                (install / "data").symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "symlink, junction, or reparse point"):
                update.install_staged_release(stage, install, common.VERSION)
            self.assertEqual(list(external.iterdir()), [])

    def test_cached_live_status_reports_concise_dependency_failure_reason(self) -> None:
        cached = {
            "manifest_id": 4895911296145320793,
            "size": 52 * 1024**3,
            "status": "valid",
            "source_kind": "cache",
            "live_error": f"pysteam-client[client] {common.STEAM_CLIENT_VERSION} is required for live Steam manifest queries",
        }
        with (
            mock.patch.object(common, "start_steam_query_subprocess", side_effect=RuntimeError("worker failed")),
            mock.patch.object(common, "steam_manifest_with_cache_fallback", return_value=(cached, None)),
            mock.patch.object(common, "fetch_current_warframe_version", return_value="43.5.4"),
        ):
            lines = common.live_status_lines(timeout=0.1)
        self.assertEqual(lines[0], "[Warframe] Live version: U43.5.4")
        self.assertEqual(
            lines[1],
            "[Steam] Cached manifest: 4895911296145320793 (52.0 GiB) — live query unavailable (Steam client dependency missing).",
        )

    def test_steam_app_info_rejects_present_but_malformed_numeric_metadata(self) -> None:
        def app_data(size: object, download: object) -> dict[str, object]:
            return {
                "depots": {
                    "230411": {
                        "manifests": {
                            "public": {"gid": "123", "size": size, "download": download}
                        }
                    }
                }
            }
        with self.assertRaisesRegex(RuntimeError, "manifest size"):
            common._steam_manifest_from_app_data(app_data("broken", 1), source_kind="live")
        with self.assertRaisesRegex(RuntimeError, "download size"):
            common._steam_manifest_from_app_data(app_data(52 * 1024**3, -1), source_kind="live")

if __name__ == "__main__":
    unittest.main()
