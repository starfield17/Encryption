# Deniable Encryption Archiver

Python implementation of the `manual.md` v2 design.

The tool creates a fixed-size random-looking binary container split into generic fixed-size slots. Each slot can hold one independently encrypted ZIP payload. Extraction scans every slot with the supplied password and either extracts the first matching payload after the scan completes or writes a generic raw dump.

This project does not provide legal, coercion-resistant, or mathematically perfect deniability. Its deniability depends on the threat model, implementation quality, operational discipline, and what an adversary already knows.

## Install

```bash
python -m pip install -r requirements.txt
```

Run tests:

```bash
python -m pytest
```

## CLI

Initialize a container:

```bash
python darc.py init vault.darc --size-mb 100 --slots 4
```

Write a directory into a slot:

```bash
python darc.py write vault.darc ./cover_files --slot 0 --slots 4
```

Extract with a password:

```bash
python darc.py extract vault.darc ./output --slots 4
```

Passwords are requested with `getpass`; command-line password arguments are intentionally not provided.

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

- Container files have no plaintext headers, slot tables, file names, timestamps, algorithm metadata, or real/decoy labels.
- Payloads use scrypt and ChaCha20-Poly1305.
- Slot writes overwrite the whole selected slot.
- Extraction does not print password-match, authentication, or slot-match details.
- ZIP extraction validates paths and file types before writing.
- Use strong, unrelated passwords for different slots. Prefer at least 6 random words or roughly 128 bits of entropy.

