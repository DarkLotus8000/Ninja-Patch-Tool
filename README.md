# Ninja Patch Tool

Ninja Patch Tool creates and applies self-contained Ninja Patches (Diff Patches) using HDiffPatch. Use Ninja Reverse Proxy (not published yet) instead when a normal Update Patch can be created; Ninja Patch Tool is intended as a fallback.

A **base** is a clean, unmodified Warframe installation from a known Steam manifest. Warframe Content depot manifests can be found on [SteamDB](https://steamdb.info/depot/230411/manifests/).

## Requirements

- Python 3.10 or newer

No packages need to be installed.

## Add a base

Add a clean, unmodified Steam manifest base to `index.json`.

```text
py add_base.py path name -m ID
```

- `path` - Path to the clean Steam manifest base
- `name` - Warframe version, for example `U43.5.1`
- `-m, --manifest-id ID` - Steam manifest ID for the base

Example:

```bat
py add_base.py "D:\Warframe\U43.5.1" U43.5.1 -m 4895911296145320793
```

## Verify a base

Verify a Steam manifest base against its entry in `index.json`. This is optional before creating a patch because `make_patch.py` verifies the selected base automatically.

```text
py verify_base.py path name
```

- `path` - Path to the Steam manifest base
- `name` - Indexed Warframe version, for example `U43.5.1`

## Create a Ninja Patch (Diff Patch)

Create one self-contained Ninja Patch (Diff Patch) from a clean indexed Steam manifest base.

```text
py make_patch.py base new output -b NAME [-c PRESET]
```

- `base` - Clean indexed Steam manifest base
- `new` - Newer installation
- `output` - Patch filename or output path; `.patch` is appended automatically. A bare filename is saved in the tool's `output` folder.
- `-b, --base-name NAME` - Base name from `index.json`, for example `U43.5.1`
- `-c, --compression PRESET` - Compression preset (default: `normal`): `normal`, `high`, `higher`, `maximum`

Compression presets: normal is the default. High and higher trade more time and memory for potentially smaller patches. Maximum tries several matching strategies per modified file and can take much longer.

Example:

```bat
py make_patch.py "D:\Warframe\U43.5.1" "D:\Warframe\U43.5.2" "U43.5.2.patch" -b U43.5.1
```

An existing patch is never overwritten automatically.

## Apply a Ninja Patch (Diff Patch)

Apply a Ninja Patch (Diff Patch). By default, the base is left untouched and a separate installation named after the patch is created.

```text
py apply_patch.py base patch [-o OUTPUT | -i]
```

- `base` - Base installation
- `patch` - Patch filename or path; `.patch` is appended automatically. A bare filename is looked up in the tool's `output` folder.
- `-o, --output OUTPUT` - Create a separate installation at `OUTPUT`; if omitted, defaults to the patch filename (cannot be used with `--in-place`)
- `-i, --in-place` - Modify the base installation instead (cannot be used with `--output`)

Example:

```bat
py apply_patch.py "D:\Warframe\U43.5.1" "U43.5.2.patch"
```

In-place mode creates a recovery backup before modifying the base. Interrupted operations are cleaned up or recovered automatically when possible.
