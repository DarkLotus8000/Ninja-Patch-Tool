# Ninja Patch Tool

Ninja Patch Tool creates and applies self-contained Ninja Patches (Diff Patches) using HDiffPatch.

## Requirements

- Python 3.10 or newer

No packages need to be installed.

## Add a base

Add a clean, unmodified game base to `index.json`.

```text
python add_base.py path name
```

- `path` - Path to the clean base installation
- `name` - Base name, for example `U43.5.1`

Example:

```bat
python add_base.py "D:\Warframe\U43.5.1" U43.5.1
```

## Verify a base

Verify a game base against its entry in `index.json`. This is optional before creating a patch because `make_patch.py` verifies the selected base automatically.

```text
python verify_base.py path name
```

- `path` - Path to the base installation
- `name` - Indexed base name, for example `U43.5.1`

## Create a Ninja Patch (Diff Patch)

Create one self-contained Ninja Patch (Diff Patch) from a clean indexed base.

```text
python make_patch.py base new output -b NAME [-c PRESET]
```

- `base` - Clean indexed base installation
- `new` - Newer installation
- `output` - Patch filename or output path; `.patch` is appended automatically. A bare filename is saved in the tool's `output` folder.
- `-b, --base-name NAME` - Base name from `index.json`, for example `U43.5.1`
- `-c, --compression PRESET` - Compression preset (default: `normal`): `normal`, `high`, `higher`, `maximum`

Compression presets: normal is the default. High and higher trade more time and memory for potentially smaller patches. Maximum tries several matching strategies per modified file and can take much longer.

Example:

```bat
python make_patch.py "D:\Warframe\U43.5.1" "D:\Warframe\U43.5.2" "U43.5.2.patch" -b U43.5.1
```

An existing patch is never overwritten automatically.

## Apply a Ninja Patch (Diff Patch)

Apply a Ninja Patch (Diff Patch). By default, the base is left untouched and a separate installation named after the patch is created.

```text
python apply_patch.py base patch [-o OUTPUT | -i]
```

- `base` - Base installation
- `patch` - Patch filename or path; `.patch` is appended automatically. A bare filename is looked up in the tool's `output` folder.
- `-o, --output OUTPUT` - Create a separate installation at `OUTPUT`; if omitted, defaults to the patch filename (cannot be used with `--in-place`)
- `-i, --in-place` - Modify the base installation instead (cannot be used with `--output`)

Example:

```bat
python apply_patch.py "D:\Warframe\U43.5.1" "U43.5.2.patch"
```

In-place mode creates a recovery backup before modifying the base. Interrupted operations are cleaned up or recovered automatically when possible.
