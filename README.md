# Deniable Encryption Archiver (DARC) v3

DARC creates a fixed-size region split into independently password-protected slots. A slot contains a streaming
tar+zstd archive encrypted as fixed-size ChaCha20-Poly1305 records; unused space in a written slot is random padding
covered by authentication. A raw, random-looking `.darc` file is the default. An optional ZIP-compatible suffix can
expose real visible files or real WinZip AES-256 passworded content.

The project name is not a security guarantee. DARC does not provide mathematical plausible deniability, protection
against coercion, or protection from a compromised endpoint. Its intended scope is ordinary offline inspection of
one final container snapshot. Read [the threat model](docs/threat-model.md) before relying on it, and see
[the v3 format](docs/format-v3.md) for the byte-level design.

> **v3 compatibility break:** v3 does not read, update, or migrate v2 containers. Keep the software needed to read
> existing v2 data until that data has been recovered and written to a new v3 container. A v2 file generally appears
> as `NO_MATCH` to the v3 reader.

## What changed in v3

- Raw `.darc` output is the default; ZIP wrapping is an explicit compatibility option.
- Wrong passwords, wrong layouts, and authenticated payload failures return a generic no-match result. DARC no
  longer creates the v2 fake/raw-dump artifact.
- The encrypted archive and all remaining padding in a written slot are authenticated record by record.
- Every written record authenticates a commitment to the complete ordered slot layout, so changing the slot count,
  any slot size, or their order invalidates matching control records.
- Payload creation and extraction stream data instead of holding a complete payload archive or slot in memory.
- Container creation and slot updates use same-directory temporary files and atomic publication. Extraction is
  staged in a temporary sibling directory and published only after verification.
- Slot count is limited to 16. The default layout is four equal slots.

## Requirements and installation

DARC requires Python 3.11 or newer.

The checked-in lock file is the reproducible application and build dependency set generated with Python 3.13:

```bash
python -m pip install --require-hashes -r requirements.lock
```

`requirements.txt` is the unpinned input set and is useful when intentionally resolving newer compatible versions;
it is not a reproducible installation:

```bash
python -m pip install -r requirements.txt
```

Install development tools separately when running checks:

```bash
python -m pip install -r requirements-dev.txt
ruff check .
ruff format --check .
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

The lock contains hashes for the distributions available when it was generated. If a target Python or platform is
not represented, regenerate and review the lock in that target environment instead of silently falling back to an
unhashed install.

## CLI quick start

Create a 100 MiB raw slot region with four equal slots:

```bash
python darc.py init vault.darc --size-mb 100 --slots 4
```

Write a directory to slot `0`, then extract the payload matching a password:

```bash
python darc.py write vault.darc ./payload_files --slot 0 --slots 4
python darc.py extract vault.darc ./output --slots 4
```

Passwords are read with `getpass`; there is intentionally no password command-line argument. Empty passwords are
rejected. The `.darc` extension is a convention and the GUI default, not an authenticated format marker.

### Slot numbering and layouts

The CLI and Python core use zero-based slot indexes: `0` through `slot_count - 1`. The GUI displays one-based slot
numbers: `1` through `slot_count`. This difference is intentional.

For a custom layout, provide the same comma-separated MiB sizes to every command. There must be 2 to 16 slots, and
the initialization sizes must sum exactly to `--size-mb`:

```bash
python darc.py init vault.darc --size-mb 100 --slot-sizes 10,40,30,20
python darc.py write vault.darc ./payload_files --slot 1 --slot-sizes 10,40,30,20
python darc.py extract vault.darc ./output --slot-sizes 10,40,30,20
```

The layout is not serialized in the slot region. Losing it can make a valid payload inaccessible. It is only an
additional concealed parameter, not a cryptographic key: defaults, file size, historical copies, user behavior, or
password testing can reveal or guess it. See [Layout is not a secret key](docs/threat-model.md#layout-is-not-a-secret-key).

v3 always writes a zstd-compressed PAX tar stream. The legacy `--no-compress` CLI flag is accepted for compatibility
but has no effect.

### Replacement and exit behavior

Creating over an existing regular file requires explicit replacement:

```bash
python darc.py init vault.darc --size-mb 100 --slots 4 --force
```

`write` is itself an explicit request to replace the selected slot. It copies and updates the whole container, then
atomically replaces the original after the new file has been synchronized. It does not authenticate or preserve the
previous contents of that selected slot.

Extraction requires a missing or empty output directory by default. `--force` replaces the complete existing output
directory; it does not merge files:

```bash
python darc.py extract vault.darc ./output --slots 4 --force
```

Existing destination symlinks are rejected even when replacement is requested.

| Exit code | Meaning |
| --- | --- |
| `0` | Command completed successfully. |
| `1` | Validation, I/O, capacity, or other operational error. |
| `2` | Command-line usage error reported by `argparse`. |
| `3` | Extraction completed its slot search but found no extractable payload. |

Exit code `3` deliberately does not distinguish a wrong password from a wrong layout or a supported authenticated
payload failure. It creates no output and no fake raw artifact. Arbitrarily malformed or unreadable container files
can still produce exit code `1`; this is not a constant-error oracle.

## Optional ZIP wrapper

ZIP wrapping is off by default and exists only for compatibility with tools that understand a ZIP archive after a
leading byte region. Enabling it requires at least one real regular file from a visible or passworded source; an
empty wrapper is rejected.

Create a container with ordinary visible entries:

```bash
python darc.py init vault.zip --size-mb 100 --slots 4 \
  --zip-wrapper --visible-source ./visible_files
```

Add passworded ZIP content as well:

```bash
python darc.py init vault.zip --size-mb 100 --slots 4 \
  --zip-wrapper \
  --visible-source ./visible_files \
  --passworded-entry-source ./zip_entry_files \
  --passworded-entry-mode archive
```

The ZIP entry password is prompted separately from all slot passwords. The two password domains are independent.

- `archive` is the default. It creates an inner ZIP and stores it as one AES-256 encrypted outer entry, named
  `Documents.zip` by default. Source names are absent from the outer listing but become visible after decryption.
- `files` writes each source file as an AES-256 encrypted outer entry. File names and relative paths remain visible
  in the ZIP central directory even without the password.

Visible entries use ordinary DEFLATE. Passworded entries use WinZip AES-256 and require a compatible tool such as
7-Zip, WinRAR, or another AES-capable ZIP implementation. Compatibility varies across ZIP tools. The wrapper uses
ZIP32 offsets and rejects inputs that would require ZIP64. Unlike slot payload processing, the current wrapper builder
assembles the ZIP suffix in memory; `archive` mode also materializes the inner ZIP, so do not assume bounded memory
use for very large wrapper sources.

> **Treat a wrapped container as read-only in external ZIP tools.** Listing or extracting visible content is the
> intended use. Editing, adding, deleting, repairing, or re-saving entries can rewrite or discard the leading slot
> region or its offsets. The ZIP suffix is not authenticated by any encrypted slot. DARC slot updates preserve the
> suffix by copying the whole container before replacement.

For read-only inspection, tools that support prefixed ZIP files should list only the wrapper entries:

```bash
unzip -l vault.zip
```

## GUI

Launch the GUI with:

```bash
python main.py
python main.py --gui --lang zh_cn
```

The main window has three task pages: Create, Update Slot, and Extract. Raw `.darc` creation is the default; layout
and ZIP settings are under advanced controls. The GUI displays slots as `1` to `N` and converts them to zero-based
core indexes internally. Update and nonempty-output replacement require explicit confirmation. Long operations show
progress and support cooperative cancellation.

Bundled language packs and presets under `config/` are read-only resources. User settings are written outside the
bundle as described below.

## Python API

The core API also uses zero-based indexes and byte-sized layouts:

```python
from pathlib import Path

from core.archiver import ContainerSpec, DeniableArchiver, ExtractionStatus, PayloadSpec
from core.layout import MIB

layout = (25 * MIB, 25 * MIB, 25 * MIB, 25 * MIB)
archiver = DeniableArchiver()

archiver.create_container(
    Path("vault.darc"),
    ContainerSpec(layout=layout),
    [
        PayloadSpec(
            slot_index=0,
            source_dir=Path("payload_files"),
            password="a strong unique passphrase",
        )
    ],
)

result = archiver.extract_payload(
    Path("vault.darc"),
    "a strong unique passphrase",
    Path("output"),
    layout=layout,
)
assert result.status is ExtractionStatus.EXTRACTED
```

For batch creation, payload slot indexes and passwords must be unique and source directories must not overlap. Avoid
embedding real passwords in source code; the literal above only demonstrates the API shape.

## Storage and atomicity

- New containers are built in a same-directory temporary file and synchronized. Without explicit replacement they
  are published with an atomic create-if-absent operation; with replacement they are published with `os.replace`.
- Slot updates make a same-directory full copy, modify that copy, synchronize it, and replace the original only on
  success. Capacity errors and cooperative cancellation before publication leave the original container unchanged.
- Extraction writes plaintext to a temporary sibling directory. The directory is published only after archive,
  record, digest, size, entry-count, and padding verification succeeds.
- Explicit output replacement first renames the old directory aside, publishes the verified directory, and removes
  the backup. On publication failure, the implementation attempts to restore the old directory.
- A path-derived cross-process file lock serializes cooperating DARC container writers. It does not lock out unrelated
  programs or remote writers.
- Container/source/output overlap and unsafe destination symlinks are rejected. Archive extraction rejects links,
  special files, traversal, unsafe cross-platform names, and case/Unicode path collisions.

These properties rely on the operating system and filesystem semantics. Directory synchronization is best effort on
platforms that do not expose it, and atomic replacement is not a substitute for backups or trusted rollback
detection. Plaintext extraction staging can also leave traces in filesystem journals, snapshots, backups, or storage
hardware even when the temporary directory is removed.

## Runtime data locations

Read-only resources come from the source or packaged bundle's `config/` and `fonts/` directories. Writable state uses
[`platformdirs`](https://platformdirs.readthedocs.io/) per-user locations:

| State | Location |
| --- | --- |
| Application settings | `user_config_dir() / "app_config.json"` |
| Data and log directory | `user_data_dir()` and `user_data_dir() / "logs"` |
| Temporary cache directory | `user_cache_dir() / "temp"` |

On a default Linux/XDG setup these are respectively
`~/.config/DeniableArchiver`, `~/.local/share/DeniableArchiver`, and `~/.cache/DeniableArchiver`. macOS, Windows, and
custom XDG environments use their normal `platformdirs` equivalents. Print the exact paths for the current runtime
with:

```bash
python - <<'PY'
from core.app_paths import user_cache_dir, user_config_dir, user_data_dir

print("config:", user_config_dir())
print("data:  ", user_data_dir())
print("cache: ", user_cache_dir())
PY
```

Set `DARC_PORTABLE=1` before launch to place all writable state in `workdir/` under the application root. In a source
checkout that is the repository root; in a frozen build it is the executable directory. Portable mode therefore
requires that directory to be writable.

## Packaging

Build the default onedir PyInstaller package:

```bash
python scripts/build_pyinstaller.py --clean
```

Inspect the generated command without building, or select a onefile/windowed build:

```bash
python scripts/build_pyinstaller.py --dry-run
python scripts/build_pyinstaller.py --clean --onefile --windowed
```

UPX is disabled by default. It is used only with explicit opt-in:

```bash
python scripts/build_pyinstaller.py --clean --upx
```

The package includes all application submodules, read-only configuration resources, and the bundled UI font. A
successful build does not establish the cryptographic correctness or trustworthiness of the build host.

## Security summary

Each written slot uses a fresh 16-byte salt, an 8-byte random nonce prefix, scrypt
(`N=2^18`, `r=8`, `p=1`, 32-byte key), and ChaCha20-Poly1305. The encrypted control record contains the format marker,
archive lengths, entry count, codec, record count, and SHA-256 digest. Record AAD binds the format domain, zero-based
slot index, slot size, record index, plaintext length, and a SHA-256 commitment to the complete ordered layout.

Use strong, unrelated passwords for different slots and for the optional ZIP layer. Weak passwords remain vulnerable
to offline guessing because the attacker has the complete salts, ciphertexts, and authentication tags. DARC has no
password recovery, key escrow, or trusted rollback log.

The concise security boundary is in [docs/threat-model.md](docs/threat-model.md); the precise construction and its
authentication limits are in [docs/format-v3.md](docs/format-v3.md).
