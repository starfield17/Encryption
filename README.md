# Deniable Encryption Archiver

Python implementation of the `manual.md` v2 design.

The tool creates a fixed-size slot region that can hold independently encrypted ZIP payloads. New containers use a ZIP-compatible outer layer by default, so ordinary ZIP tools can list optional visible ZIP entries while this tool reads and writes the slot region. Extraction scans every slot with the supplied password and either extracts the first matching payload after the scan completes or writes a generic raw dump.

This project does not provide legal, coercion-resistant, or mathematically perfect deniability. Its deniability depends on the threat model, implementation quality, operational discipline, and what an adversary already knows.

## Install

```bash
python -m pip install -r requirements.txt
```

Dev tools (lint/format/tests):

```bash
python -m pip install -r requirements-dev.txt
```

Run tests:

```bash
python -m pytest
```

Lint and format with [Ruff](https://docs.astral.sh/ruff/) (config in `pyproject.toml`):

```bash
ruff check .
ruff format --check .
# apply formatting:
ruff format .
```

## CLI

Initialize a container:

```bash
python darc.py init vault.zip --size-mb 100 --slots 4
```

Custom slot sizes (layout secret; MiB values must sum to `--size-mb`). Layout is **not** stored in the file:

```bash
python darc.py init vault.zip --size-mb 100 --slot-sizes 10,40,30,20
python darc.py write vault.zip ./payload_files --slot 1 --slot-sizes 10,40,30,20
python darc.py extract vault.zip ./output --slot-sizes 10,40,30,20
```


Add optional ZIP-visible content at creation time:

```bash
python darc.py init vault.zip --size-mb 100 --slots 4 --visible-source ./visible_files --passworded-entry-source ./zip_entry_files
```

Passworded ZIP content has two modes:

- `archive` writes one encrypted archive entry such as `Documents.zip`. This keeps the source filenames out of the outer ZIP listing, but ZIP tools show a ZIP file entry inside the container.
- `files` writes each source file as an encrypted ZIP entry. This looks more like a common encrypted ZIP, but the source filenames and relative paths are listed by ZIP tools.

Select direct encrypted file entries when that presentation is preferred:

```bash
python darc.py init vault.zip --size-mb 100 --slots 4 --visible-source ./visible_files --passworded-entry-source ./zip_entry_files --passworded-entry-mode files
```

Create a raw random-looking container instead:

```bash
python darc.py init vault.darc --size-mb 100 --slots 4 --raw
```

Write a directory into a slot:

```bash
python darc.py write vault.zip ./payload_files --slot 0 --slots 4
```

Extract with a password:

```bash
python darc.py extract vault.zip ./output --slots 4
```

Passwords are requested with `getpass`; command-line password arguments are intentionally not provided.

### ZIP camouflage check (system zip/unzip)

For ZIP-compatible containers, system tools should only see the decoy layer:

```bash
zip -T vault.zip
unzip -l vault.zip
unzip -o vault.zip -d /tmp/vault-visible
```

`zip -T` should report OK. `unzip -l` lists only visible (and optional passworded ZIP) entries—not encrypted slot payloads. Passworded ZIP entries use WinZip AES and may require WinRAR, 7-Zip, or compatible tooling to extract.

## GUI

Launch the GUI:

```bash
python main.py --gui
```

Without arguments, `main.py` opens the GUI by default.

The GUI uses language and configuration packages under `config/`:

```text
config/
  i18n/
    en.json
    zh_cn.json
  presets/
    default_standard.json
```

Runtime settings are written to `workdir/app_config.json`.

## Packaging

Build an onedir PyInstaller package:

```bash
python scripts/build_pyinstaller.py --clean
```

Useful options:

```bash
python scripts/build_pyinstaller.py --clean --onefile --windowed
```

The PyInstaller configuration bundles `config/` so language packs and presets are available in packaged builds.

## Security Notes

- The encrypted slot region has no plaintext headers, slot tables, file names, timestamps, or algorithm metadata.
- ZIP-compatible containers intentionally expose ordinary ZIP metadata for the visible ZIP layer.
- Payloads use scrypt and ChaCha20-Poly1305.
- Slot writes overwrite the whole selected slot.
- Extraction does not print password-match, authentication, or slot-match details.
- ZIP extraction validates paths and file types before writing.
- Use strong, unrelated passwords for different slots. Prefer at least 6 random words or roughly 128 bits of entropy.
