# Ninja Patch Tool

Ninja Patch Tool creates and applies self-contained Ninja Patches (Diff Patches) using HDiffPatch. Use Ninja Reverse Proxy (not published yet) instead when a normal Update Patch can be created; Ninja Patch Tool is intended as a fallback.

A ***base*** is a clean, unmodified Warframe installation from a known Steam manifest. Select the Warframe installation root, where at least `Cache.Windows`, `Tools`, and `Warframe.x64.exe` are directly located. Warframe Content depot manifests can be found on [SteamDB](https://steamdb.info/depot/230411/manifests/).

## Requirements

- Windows 10 (64-bit) or newer
- Python 3.14 (not required for release executables)

No packages need to be installed to run the tool from source. Building a release additionally requires PyInstaller.

The commands below use the release executables. When running from source, use the corresponding `.py` script with Python 3.14 instead.

## Add a base

Add a clean, unmodified Steam manifest base to `data/index.json`.

```text
add_base.exe path name manifest_id
```

- `path` - Path to the clean Steam manifest base
- `name` - Warframe version, for example `U43.5.1`
- `manifest_id` - Steam manifest ID of the base

Example:

```bat
add_base.exe "D:\WF\U43.5.1" U43.5.1 4895911296145320793
```

## Verify a base

Verify a Steam manifest base against its entry in `data/index.json`. This is optional before creating a patch because `make_patch.exe` verifies the selected base automatically.

```text
verify_base.exe path name
```

- `path` - Path to the Steam manifest base
- `name` - Indexed Warframe version, for example `U43.5.1`

## Create a Ninja Patch (Diff Patch)

Create one self-contained Ninja Patch (Diff Patch) from a clean indexed Steam manifest base.

Before using an installation as `new`, fully download all language files and both DirectX 11 and DirectX 12 files in the Warframe Launcher, then open the launcher settings, click **Optimize**, and let the process finish. Close Warframe and the Warframe Launcher before creating the patch.

```text
make_patch.exe base new output base_name [-c PRESET]
```

- `base` - Clean indexed Steam manifest base
- `new` - Newer installation
- `output` - Patch filename or output path; `.patch` is appended automatically. A bare filename is saved in the tool's `output` folder.
- `base_name` - Base name from `data/index.json`, for example `U43.5.1`
- `-c, --compression PRESET` - Compression preset (default: `normal`): `normal`, `high`, `higher`, `maximum`

Compression presets: normal is the default. High and higher trade more time and memory for potentially smaller patches. Maximum tries several matching strategies per modified file and can take much longer.

Example:

```bat
make_patch.exe "D:\WF\U43.5.1" "D:\WF\U43.5.2" "U43.5.2.patch" U43.5.1
```

An existing patch is never overwritten automatically.

## Apply a Ninja Patch (Diff Patch)

Apply a Ninja Patch (Diff Patch) from a file. By default, the base is left untouched and a separate installation named after the patch is created.

```text
apply_patch.exe base patch [-o OUTPUT | -i]
```

- `base` - Base installation
- `patch` - Patch filename or path; `.patch` is appended automatically. A bare filename is looked up in the tool's `output` folder.
- `-o, --output OUTPUT` - Create a separate installation at `OUTPUT`; if omitted, defaults to the patch filename (cannot be used with `--in-place`)
- `-i, --in-place` - Modify the base installation instead (cannot be used with `--output`)

Example:

```bat
apply_patch.exe "D:\WF\U43.5.1" "U43.5.2.patch"
```

In-place mode creates a recovery backup before modifying the base. Interrupted operations are cleaned up or recovered automatically when possible.

## Build a release

Set `VERSION` in `common.py`, then run:

```text
py -3.14 -m pip install pyinstaller
py -3.14 build_release.py
```
