#!/usr/bin/env python3
from __future__ import annotations

import importlib.metadata
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from common import (
    ENTRY_SCRIPTS,
    PRESERVED_RELEASE_FILES,
    RELEASE_MANIFEST_FILE,
    RELEASE_MANIFEST_VERSION,
    VERSION,
    format_bytes,
    operation_lock,
    parse_json,
    sha256_file,
    validate_index,
)

COMPANY_NAME = "DarkLotus"
ROOT = Path(__file__).resolve().parent
RELEASE_DIR = ROOT / "release"
RELEASE_TEMP_DIR = ROOT / "release_temp"
DATA_DIR = ROOT / "data"
FAVICON = DATA_DIR / "favicon.ico"
LICENSES_DIR = DATA_DIR / "licenses"
RELEASE_DATA_FILES = ("index.json", "update.json", "hdiffz.exe", "hpatchz.exe")
THIRD_PARTY_LICENSE_FILES = ("Python_LICENSE.txt", "HDiffPatch_LICENSE.txt")
MIN_PYINSTALLER_VERSION = (6, 15, 0)

def clean_markdown_inline(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    return text.replace("***", "").replace("**", "").replace("`", "")

def create_release_readme(markdown: str) -> str:
    lines: list[str] = []
    in_code = False

    for line in markdown.splitlines():
        if line == "## Build a release":
            break
        if line.startswith("```"):
            in_code = not in_code
            continue
        if line == "The commands below use the release executables. When running from source, use the corresponding `.py` script with Python 3.14 instead.":
            continue

        if line.startswith("# "):
            heading = clean_markdown_inline(line[2:])
            lines.extend([heading, "=" * len(heading), f"Version {VERSION}"])
            continue
        if line.startswith("## "):
            heading = clean_markdown_inline(line[3:])
            lines.extend([heading, "-" * len(heading)])
            continue

        line = clean_markdown_inline(line)
        for script in ENTRY_SCRIPTS:
            command = Path(script).stem
            line = line.replace(f"py {script}", command).replace(script, command)
        if line == "- Python 3.14 (not required for release executables)":
            continue
        if line == "No packages need to be installed to run the tool from source. Building a release additionally requires PyInstaller.":
            line = "No additional packages need to be installed."
        if in_code and line:
            line = "    " + line
        lines.append(line)

    return "\n".join(lines).rstrip()

def version_tuple() -> tuple[int, int, int, int]:
    parts = VERSION.split(".")
    if len(parts) not in {2, 3, 4} or any(not part.isdigit() for part in parts):
        raise RuntimeError("VERSION must contain two to four numeric components, for example 1.4, 1.4.0, or 1.4.0.0.")
    numbers = [int(part) for part in parts]
    if any(number > 65535 for number in numbers):
        raise RuntimeError("Every VERSION component must be between 0 and 65535 for Windows version resources.")
    numbers.extend([0] * (4 - len(numbers)))
    return numbers[0], numbers[1], numbers[2], numbers[3]

def validate_pyinstaller_version(value: str) -> None:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        raise RuntimeError(f"Could not parse the installed PyInstaller version: {value!r}")
    installed = tuple(int(part) for part in match.groups())
    if installed < MIN_PYINSTALLER_VERSION:
        required = ".".join(str(part) for part in MIN_PYINSTALLER_VERSION)
        raise RuntimeError(f"PyInstaller {required} or newer is required for Python 3.14. Installed version: {value}")

def release_archive_path() -> Path:
    return RELEASE_DIR / f"NinjaPatchTool-v{VERSION}-Windows-x64.zip"

def release_checksum_path() -> Path:
    archive = release_archive_path()
    return archive.with_name(archive.name + ".sha256")

def validate_release_output_available() -> Path:
    archive = release_archive_path()
    checksum = release_checksum_path()
    for output in (archive, checksum):
        temporary = output.with_name(output.name + ".tmp")
        if output.exists():
            raise FileExistsError(f"Release output already exists: {output}")
        if temporary.exists():
            raise FileExistsError(f"Release output temporary file already exists: {temporary}")
    return archive

def clean_stale_release_temp() -> None:
    if not RELEASE_TEMP_DIR.exists():
        return
    print("[Cleaning] Previous temporary build files")
    try:
        shutil.rmtree(RELEASE_TEMP_DIR)
    except OSError as exc:
        raise RuntimeError(f"Could not remove previous temporary build files: {RELEASE_TEMP_DIR}") from exc

def find_project_licenses() -> list[Path]:
    licenses: set[Path] = set()
    for pattern in ("LICENSE*", "COPYING*"):
        licenses.update(path for path in ROOT.glob(pattern) if path.is_file())
    return sorted(licenses, key=lambda path: path.name.casefold())

def validate_pe_x64(path: Path) -> None:
    try:
        with path.open("rb") as file:
            header = file.read(64)
            if len(header) < 64 or header[:2] != b"MZ":
                raise RuntimeError(f"Not a valid Windows PE executable: {path}")
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            file.seek(pe_offset)
            pe_header = file.read(6)
    except OSError as exc:
        raise RuntimeError(f"Could not inspect Windows executable: {path}") from exc
    if len(pe_header) != 6 or pe_header[:4] != b"PE\0\0":
        raise RuntimeError(f"Not a valid Windows PE executable: {path}")
    machine = struct.unpack_from("<H", pe_header, 4)[0]
    if machine != 0x8664:
        raise RuntimeError(f"Release dependency is not an x86-64 Windows executable: {path}")

def validate_ico(path: Path) -> None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Could not read icon file: {path}") from exc
    if len(data) < 6:
        raise RuntimeError(f"Invalid ICO file: {path}")
    reserved, icon_type, count = struct.unpack_from("<HHH", data, 0)
    directory_end = 6 + count * 16
    if reserved != 0 or icon_type != 1 or count == 0 or len(data) < directory_end:
        raise RuntimeError(f"Invalid ICO file: {path}")

    has_modern_256 = False
    for index in range(count):
        entry_offset = 6 + index * 16
        width = data[entry_offset] or 256
        height = data[entry_offset + 1] or 256
        size, offset = struct.unpack_from("<II", data, entry_offset + 8)
        if size == 0 or offset < directory_end or offset + size > len(data):
            raise RuntimeError(f"Invalid ICO file: {path}")

        payload = data[offset:offset + size]
        if width == 256 and height == 256 and payload.startswith(b"\x89PNG\r\n\x1a\n"):
            # PNG color types 4 and 6 contain an alpha channel.
            if len(payload) >= 26 and payload[12:16] == b"IHDR" and payload[25] in {4, 6}:
                has_modern_256 = True

    if not has_modern_256:
        raise RuntimeError(f"ICO must contain a transparent 256x256 PNG-compressed image: {path}")

def validate_build_environment() -> list[Path]:
    if sys.platform != "win32":
        raise RuntimeError("Releases must be built on Windows.")
    if struct.calcsize("P") != 8:
        raise RuntimeError("A 64-bit Python installation is required to build the Windows x64 release.")
    if sys.version_info[:2] != (3, 14):
        raise RuntimeError("Python 3.14 is required to build releases. Run the builder with: py -3.14 build_release.py")
    version_tuple()
    try:
        pyinstaller_version = importlib.metadata.version("pyinstaller")
    except importlib.metadata.PackageNotFoundError:
        raise RuntimeError("PyInstaller is not installed for Python 3.14. Run: py -3.14 -m pip install pyinstaller") from None
    validate_pyinstaller_version(pyinstaller_version)

    required = [ROOT / script for script in ENTRY_SCRIPTS]
    required.extend([ROOT / "common.py", ROOT / "update.py", ROOT / "README.md", FAVICON])
    required.extend(DATA_DIR / name for name in RELEASE_DATA_FILES)
    required.extend(LICENSES_DIR / name for name in THIRD_PARTY_LICENSE_FILES)
    missing = [path for path in required if not path.is_file()]
    if missing:
        details = "\n".join(f"- {path}" for path in missing)
        raise RuntimeError(f"Required release files are missing:\n{details}")

    try:
        index = parse_json((DATA_DIR / "index.json").read_text(encoding="utf-8"))
        validate_index(index)
    except Exception as exc:
        raise RuntimeError(f"data/index.json is invalid: {exc}") from exc
    try:
        update_config = parse_json((DATA_DIR / "update.json").read_text(encoding="utf-8"))
        if not isinstance(update_config, dict) or not isinstance(update_config.get("auto_update"), bool):
            raise ValueError('Expected a JSON object containing boolean "auto_update".')
    except Exception as exc:
        raise RuntimeError(f"data/update.json is invalid: {exc}") from exc
    validate_pe_x64(DATA_DIR / "hdiffz.exe")
    validate_pe_x64(DATA_DIR / "hpatchz.exe")
    validate_ico(FAVICON)

    project_licenses = find_project_licenses()
    if not project_licenses:
        raise RuntimeError("No project license file was found. Add LICENSE, LICENSE.txt, COPYING, or a similarly named license file before building a release.")
    return project_licenses

def create_version_file(script: Path, destination: Path) -> Path:
    version = version_tuple()
    version_file = destination / f"{script.stem}_version.txt"
    text = f"""VSVersionInfo(
    ffi=FixedFileInfo(
        filevers={version!r},
        prodvers={version!r},
        mask=0x3f,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0)
    ),
    kids=[
        StringFileInfo([
            StringTable(
                '040904B0',
                [
                    StringStruct('CompanyName', '{COMPANY_NAME}'),
                    StringStruct('FileDescription', '{ENTRY_SCRIPTS[script.name]}'),
                    StringStruct('FileVersion', '{VERSION}'),
                    StringStruct('InternalName', '{script.stem}'),
                    StringStruct('LegalCopyright', '{COMPANY_NAME}'),
                    StringStruct('ProductName', 'Ninja Patch Tool'),
                    StringStruct('ProductVersion', '{VERSION}')
                ]
            )
        ]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])])
    ]
)
"""
    version_file.write_text(text, encoding="utf-8", newline="\n")
    return version_file

def build_environment(workspace: Path) -> dict[str, str]:
    config = workspace / "pyinstaller_config"
    config.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["TEMP"] = str(workspace)
    environment["TMP"] = str(workspace)
    environment["PYINSTALLER_CONFIG_DIR"] = str(config)
    return environment

def build_executable(script: Path, dist: Path, work: Path, specs: Path) -> Path:
    name = script.stem
    print(f"[Compiling] {script.name}")
    version_file = create_version_file(script, specs)
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--log-level",
        "WARN",
        "--onefile",
        "--console",
        "--noupx",
        "--icon",
        str(FAVICON),
        "--version-file",
        str(version_file),
        "--name",
        name,
        "--distpath",
        str(dist),
        "--workpath",
        str(work / name),
        "--specpath",
        str(specs),
        str(script),
    ]
    result = subprocess.run(command, cwd=ROOT, env=build_environment(dist.parent))
    if result.returncode != 0:
        raise RuntimeError(f"PyInstaller failed for {script.name} with exit code {result.returncode}.")
    executable = dist / f"{name}.exe"
    if not executable.is_file():
        raise RuntimeError(f"PyInstaller did not create the expected executable: {executable}")
    return executable

def run_source_tests() -> None:
    print("[Testing] Source test suite")
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-W", "error::DeprecationWarning",
                "-W", "error::RuntimeWarning",
                "-W", "error::ResourceWarning",
                "-m", "unittest", "discover", "-s", "tests",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Source test suite timed out.") from exc
    if result.returncode != 0:
        details = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip()) or "No output was produced."
        raise RuntimeError(f"Source test suite failed:\n{details}")

def smoke_test_executables(dist: Path) -> None:
    print("[Testing] Standalone executables")
    environment = build_environment(dist.parent)
    for script in ENTRY_SCRIPTS:
        executable = dist / f"{Path(script).stem}.exe"
        try:
            help_result = subprocess.run(
                [str(executable), "-h"], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30
            )
            short_version_result = subprocess.run(
                [str(executable), "-v"], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30
            )
            version_result = subprocess.run(
                [str(executable), "--version"], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Standalone executable smoke test timed out: {executable.name}") from exc
        if help_result.returncode != 0 or "Shows this help message" not in help_result.stdout:
            details = help_result.stderr.strip() or help_result.stdout.strip() or "No output was produced."
            raise RuntimeError(f"Standalone executable smoke test failed for {executable.name}:\n{details}")
        if short_version_result.returncode != 0 or short_version_result.stdout.strip() != f"Ninja Patch Tool v{VERSION}":
            details = short_version_result.stderr.strip() or short_version_result.stdout.strip() or "No output was produced."
            raise RuntimeError(f"Standalone executable short version test failed for {executable.name}:\n{details}")
        if version_result.returncode != 0 or version_result.stdout.strip() != f"Ninja Patch Tool v{VERSION}":
            details = version_result.stderr.strip() or version_result.stdout.strip() or "No output was produced."
            raise RuntimeError(f"Standalone executable version test failed for {executable.name}:\n{details}")

        try:
            updater_result = subprocess.run(
                [str(executable), "--update-installer", "--version"],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Internal updater smoke test timed out: {executable.name}") from exc
        if updater_result.returncode != 0 or updater_result.stdout.strip() != f"Ninja Patch Tool v{VERSION}":
            details = updater_result.stderr.strip() or updater_result.stdout.strip() or "No output was produced."
            raise RuntimeError(f"Internal updater smoke test failed for {executable.name}:\n{details}")

def populate_release(stage: Path, dist: Path, project_licenses: list[Path]) -> None:
    stage.mkdir(parents=True)
    for script in ENTRY_SCRIPTS:
        executable = dist / f"{Path(script).stem}.exe"
        shutil.copy2(executable, stage / executable.name)

    release_data = stage / "data"
    release_data.mkdir()
    for name in RELEASE_DATA_FILES:
        if name == "update.json":
            # Runtime cooldown timestamps are installation state and must never be shipped in a fresh release.
            (release_data / name).write_text('{\n  "auto_update": true\n}\n', encoding="utf-8", newline="\n")
        else:
            shutil.copy2(DATA_DIR / name, release_data / name)

    release_licenses = release_data / "licenses"
    release_licenses.mkdir()
    for name in THIRD_PARTY_LICENSE_FILES:
        shutil.copy2(LICENSES_DIR / name, release_licenses / name)
    for license_file in project_licenses:
        destination = release_licenses / license_file.name
        if destination.exists():
            raise RuntimeError(f"License filename collision while staging release: {license_file.name}")
        shutil.copy2(license_file, destination)

    readme = create_release_readme((ROOT / "README.md").read_text(encoding="utf-8"))
    (stage / "README.txt").write_text(readme, encoding="utf-8", newline="\r\n")

def release_managed_file_hashes(stage: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(stage.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(stage).as_posix()
        if relative == RELEASE_MANIFEST_FILE or relative in PRESERVED_RELEASE_FILES:
            continue
        files[relative] = sha256_file(path)
    return files

def write_release_manifest(stage: Path) -> None:
    manifest = {
        "format_version": RELEASE_MANIFEST_VERSION,
        "application_version": VERSION,
        "files": release_managed_file_hashes(stage),
    }
    path = stage / RELEASE_MANIFEST_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

def validate_release_manifest(stage: Path) -> None:
    path = stage / RELEASE_MANIFEST_FILE
    try:
        value = parse_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Release manifest is invalid: {exc}") from exc
    if not isinstance(value, dict) or value.get("format_version") != RELEASE_MANIFEST_VERSION:
        raise RuntimeError("Release manifest has an unsupported format version.")
    if value.get("application_version") != VERSION:
        raise RuntimeError("Release manifest application version does not match the build version.")
    files = value.get("files")
    if not isinstance(files, dict) or any(not isinstance(name, str) or not isinstance(digest, str) for name, digest in files.items()):
        raise RuntimeError("Release manifest contains invalid file metadata.")
    if files != release_managed_file_hashes(stage):
        raise RuntimeError("Release manifest does not match the staged release files.")

def publish_without_overwrite(temporary: Path, output: Path) -> None:
    try:
        temporary.rename(output)
    except FileExistsError:
        raise FileExistsError(f"Release output appeared while the release was being created: {output}") from None

def create_release_archive(stage: Path) -> Path:
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    archive = validate_release_output_available()
    temporary = archive.with_name(archive.name + ".tmp")
    try:
        with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True) as output:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    output.write(path, f"{stage.name}/{path.relative_to(stage).as_posix()}")
        publish_without_overwrite(temporary, archive)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return archive

def create_release_checksum(archive: Path) -> tuple[Path, str]:
    checksum = release_checksum_path()
    temporary = checksum.with_name(checksum.name + ".tmp")
    if checksum.exists():
        raise FileExistsError(f"Release output already exists: {checksum}")
    if temporary.exists():
        raise FileExistsError(f"Release output temporary file already exists: {temporary}")
    digest = sha256_file(archive)
    try:
        with temporary.open("x", encoding="ascii", newline="\n") as file:
            file.write(f"{digest}  {archive.name}\n")
        publish_without_overwrite(temporary, checksum)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return checksum, digest

def create_release_outputs(stage: Path) -> tuple[Path, Path, str]:
    validate_release_manifest(stage)
    archive = create_release_archive(stage)
    try:
        checksum, digest = create_release_checksum(archive)
    except BaseException:
        archive.unlink(missing_ok=True)
        raise
    return archive, checksum, digest

def main() -> int:
    try:
        project_licenses = validate_build_environment()
        archive = release_archive_path()
        with operation_lock("release", archive, "release build for this version"):
            validate_release_output_available()
            clean_stale_release_temp()
            run_source_tests()
            RELEASE_TEMP_DIR.mkdir(parents=True, exist_ok=True)
            try:
                with tempfile.TemporaryDirectory(prefix="npt_release_", dir=RELEASE_TEMP_DIR) as temporary_dir:
                    temporary = Path(temporary_dir)
                    dist = temporary / "dist"
                    work = temporary / "build"
                    specs = temporary / "spec"
                    stage = temporary / f"NinjaPatchTool-v{VERSION}"
                    dist.mkdir()
                    work.mkdir()
                    specs.mkdir()

                    for script in ENTRY_SCRIPTS:
                        build_executable(ROOT / script, dist, work, specs)
                    smoke_test_executables(dist)
                    populate_release(stage, dist, project_licenses)
                    write_release_manifest(stage)
                    archive, checksum, digest = create_release_outputs(stage)
            finally:
                try:
                    RELEASE_TEMP_DIR.rmdir()
                except OSError:
                    pass

        print(f"\n[Created] {archive}")
        print(f'Version: {VERSION}\nSize: {format_bytes(archive.stat().st_size)}\nSHA-256: {digest}\nChecksum: {checksum}')
        return 0
    except KeyboardInterrupt:
        print("\nRelease creation interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
