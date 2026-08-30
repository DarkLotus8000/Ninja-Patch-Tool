# Ninja Patch Tool

Ninja Patch Tool creates and applies self-contained Ninja Patches (Diff Patches) using HDiffPatch. Use Ninja Capture Tool (not published yet) instead when a normal Update Patch can be created; Ninja Patch Tool is intended as a fallback.

A ***base*** is a clean, unmodified Warframe installation from a known Steam manifest. Select the Warframe installation root, where at least `Cache.Windows`, `Tools`, and `Warframe.x64.exe` are directly located.
Warframe Content depot manifests can be found on [SteamDB](https://steamdb.info/depot/230411/manifests/).

## Requirements

- Windows 10 (64-bit) or newer
- Python 3.14 (not required for release executables)

Ninja Patch Tool targets Windows. On non-Windows systems, use the Windows release executables through Wine; native Linux/macOS source execution is not supported. Wine compatibility is not yet officially verified.

No packages need to be installed to run the tool from source. Building a release additionally requires PyInstaller.

The commands below use the release executables. When running from source, use the corresponding `.py` script with Python 3.14 instead.

Update options available on all main executables:

- `-a, --auto-update` - Enable automatic updating for this run, overriding `data/update.json`
- `-n, --no-auto-update` - Disable automatic updating for this run, overriding `data/update.json`
- `-u, --check-update` - Check GitHub Releases for a newer version without installing it; use this option without operation arguments
- `-v, --version` - Show the installed Ninja Patch Tool version and exit

## Add a base

Add a clean, unmodified Steam manifest base to `data/index.json`.

```text
add_base path name manifest_id [-a | -n]
```

- `path` - Path to the clean Steam manifest base
- `name` - Warframe version, for example `U43.5.1`
- `manifest_id` - Steam manifest ID of the base

Example:

```bat
add_base "D:\WF\U43.5.1" U43.5.1 4895911296145320793
```

## Verify a base

Verify a Steam manifest base against its entry in `data/index.json`. This is optional before creating a patch because `make_patch` verifies the selected base automatically.

```text
verify_base path name [-a | -n]
```

- `path` - Path to the Steam manifest base
- `name` - Indexed Warframe version, for example `U43.5.1`

## Create a Ninja Patch (Diff Patch)

Create one self-contained Ninja Patch (Diff Patch) from a clean indexed Steam manifest base.

Before using an installation as `new`, fully download all language files and both DirectX 11 and DirectX 12 files in the Warframe Launcher, then open the launcher settings, click **Optimize**, and let the process finish.
Close Warframe and the Warframe Launcher before creating the patch.

```text
make_patch base new output base_name [-c PRESET] [-a | -n]
```

- `base` - Clean indexed Steam manifest base
- `new` - Newer installation
- `output` - Patch filename or output path; `.patch` is appended automatically. A bare filename is saved in the tool's `output` folder.
- `base_name` - Base name from `data/index.json`, for example `U43.5.1`
- `-c, --compression PRESET` - Compression preset (default: `normal`): `normal`, `high`, `higher`, `maximum`

Example:

```bat
make_patch "D:\WF\U43.5.1" "D:\WF\U43.5.2" "U43.5.2.patch" U43.5.1
```

An existing patch is never overwritten automatically.

## Apply a Ninja Patch (Diff Patch)

Apply a Ninja Patch (Diff Patch) from a file. By default, the base is left untouched and a separate installation is created next to the base, named after the patch.

```text
apply_patch base patch [-o OUTPUT | -i] [-a | -n]
```

- `base` - Base installation
- `patch` - Patch filename or path; `.patch` is appended automatically. A bare filename is looked up in the tool's `output` folder.
- `-o, --output OUTPUT` - Create a separate installation at `OUTPUT`; if omitted, creates one next to the base named after the patch (cannot be used with `--in-place`)
- `-i, --in-place` - Modify the base installation instead (cannot be used with `--output`)

Example:

```bat
apply_patch "D:\WF\U43.5.1" "U43.5.2.patch"
```

Close Warframe and the Warframe Launcher before applying a patch, especially when using `--in-place`.

In-place mode creates a recovery backup of only the files the patch may modify or remove before changing the base. Interrupted operations are cleaned up or recovered automatically when possible.

## Build a release

Set `VERSION` in `common.py`, then run:

```bat
py -3.14 -m pip install pyinstaller
py -3.14 build_release.py
```

Upload both generated files to the matching GitHub Release (`vVERSION`):

```text
NinjaPatchTool-vVERSION-Windows-x64.zip
NinjaPatchTool-vVERSION-Windows-x64.zip.sha256
```

The updater requires both release assets.
