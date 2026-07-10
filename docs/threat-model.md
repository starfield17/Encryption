# DARC v3 Threat Model

This document states the security scope of the current v3 implementation. It is a boundary, not a claim that the
implementation has received an independent audit. When this document and an informal description disagree, rely on
the narrower statement here and verify it against the source.

## In-scope adversary

The intended adversary obtains one byte-for-byte snapshot of the final container and performs ordinary offline
analysis. The adversary may:

- know the source code, algorithms, format, defaults, and this document;
- inspect the complete file, its size, its optional ZIP metadata, and normal filesystem metadata;
- guess passwords and candidate layouts offline;
- corrupt, relocate, reorder, truncate, append to, or replace bytes and later provide the modified file to the user;
- possess unrelated public files or likely plaintext examples.

The confidentiality assumption is that slot passwords are strong and unknown, the operating system random generator
is sound, scrypt and ChaCha20-Poly1305 retain their expected security, and the endpoint performing encryption or
extraction is not compromised. A custom layout may be unknown to the adversary, but confidentiality must not depend
on it remaining unknown.

## Intended properties

### Payload confidentiality

For a written slot, relative names, file contents, archived mode and modification-time metadata, archive length,
uncompressed size, entry count, codec identifier, and internal format marker are inside authenticated encryption.
The slot exposes a random salt, random nonce prefix, ciphertext sizes fixed by the supplied slot size, and tags.

An unfilled slot is initialized from the operating system random generator. A filled slot is intended to be
computationally difficult to distinguish from random bytes without a matching password and layout. This is a
cryptographic engineering goal, not a proof of plausible deniability or a guarantee against environmental evidence.

### Integrity of a selected written slot

With the correct password and layout, extraction authenticates the encrypted control record and every encrypted data
record in the selected slot. This includes records containing bytes after the compressed archive, so random padding
to the end of that slot is checked before output is published. The authenticated archive digest, uncompressed size,
and entry count are checked as well.

Associated data binds each record to the v3 domain, a SHA-256 commitment to the complete ordered layout, zero-based
slot index, slot size, record index, and plaintext length. Changing the slot count, any slot size, or their order;
moving a slot to a different index; or reordering equal-sized records therefore fails authentication under the normal
cryptographic assumptions. Because the committed layout includes all slot sizes, it also commits to their summed
slot-region size.

This is password-based integrity, not a digital signature. Anyone who knows the password can construct a replacement
slot that authenticates. Anyone who can modify the file can destroy a slot, replace the whole file, or prevent
recovery; DARC provides detection for a matching written slot, not availability.

### Transactional publication

The implementation does not publish extracted plaintext until the archive and the entire matching slot have passed
verification. Container creation and updates operate on a same-directory temporary file and publish the destination
only after successful completion and synchronization. Creation without replacement uses an atomic create-if-absent
operation; explicit replacement and updates use atomic file replacement. Extraction stages into a temporary sibling
directory and then renames it into place.

These behaviors reduce partial results after ordinary failures and cooperative cancellation. They inherit the local
filesystem's rename and durability guarantees. They do not promise crash consistency on every filesystem, protect
against a hostile kernel, or erase data from journals, snapshots, backups, SSD remapping, and similar storage layers.

## Extraction outcomes

For supported, readable containers whose output preconditions are satisfied, v3 intentionally collapses several
conditions into the same no-match result:

| Condition | Core result | CLI result | New output published |
| --- | --- | --- | --- |
| Correct password, correct layout, valid matching slot | `EXTRACTED` | Exit `0` | Yes |
| Wrong password or no matching written slot | `NO_MATCH` | Exit `3` | No |
| Wrong layout that yields no valid control record | `NO_MATCH` | Exit `3` | No |
| Matching control but invalid AEAD record, digest, zstd stream, safe-extraction check, or padding | `NO_MATCH` | Exit `3` | No |
| Empty password, invalid layout, unsafe path, nonempty destination without replacement, or I/O error | Exception | Exit `1` | No |

The no-match message is `No extractable payload was found.` It does not identify a slot or explain whether the
password, layout, or authenticated payload was wrong. v3 never creates the v2 `decrypted_raw.bin` or another fake
raw-dump artifact; the no-match API result has `output_dir=None`.

This normalization is deliberately limited. Arbitrarily malformed files, ZIP detection failures, permission errors,
and invalid output state can still be observably different. Runtime and I/O timing is not constant. Do not treat the
interface as a general-purpose side-channel-resistant password oracle.

## Authentication boundaries

There is no global authenticator for a complete DARC file.

- A supplied password first attempts only each slot's control record. Slots that do not match that password are not
  fully decrypted or authenticated.
- A filled matching slot is fully checked, including its padding. Unfilled random slots have no authentication.
- The optional trailing ZIP suffix is outside every slot and is not authenticated by a slot password.
- The complete ordered layout, including its summed slot-region size, is bound into every written slot record. The
  file name, filesystem metadata, container path, total file length, and presence or contents of a ZIP suffix are not.
- Deleting, replacing, or rolling back the complete file cannot be distinguished from the user selecting another
  legitimate copy.

Consequently, "padding is authenticated" means all padding within the written slot selected by a matching password,
under the supplied layout. It does not mean every byte of the container or every other slot is globally authenticated.

## Layout is not a secret key

The raw slot region contains no plaintext slot table. Equal layouts are derived from a supplied slot count, and custom
layouts are supplied as an ordered list of byte sizes (MiB values in the CLI). The valid range is 2 to 16 slots; the
default is four equal slots.

This concealment has important limits:

- Default layouts and common size choices are easy to guess.
- The file size constrains possible layouts.
- Each guessed slot/password pair provides an offline AEAD control-record test.
- A user must reproduce the exact layout to read or update a custom-layout container.
- Historical copies reveal which byte range changed during a slot update, because the complete selected slot is
  re-encrypted while other slot bytes remain unchanged.
- The optional ZIP suffix reveals the slot-region boundary through its offsets.

Treat the layout as operational metadata that may reduce casual disclosure, not as password entropy. Store a needed
custom layout separately and securely; DARC has no layout recovery mechanism.

## Information that remains visible

Even for a raw container, an observer can learn or infer:

- total file size, path, timestamps, ownership, access patterns, and copy history provided by the filesystem or other
  systems;
- that the bytes appear high-entropy, and that their size or surrounding context may be consistent with DARC;
- updates, synchronization deltas, backups, and historical byte ranges if more than one snapshot exists;
- resource use, timing, process information, UI activity, or temporary plaintext when observing the endpoint.

A ZIP-wrapped container additionally exposes the fact that it is ZIP-compatible and all normal outer ZIP metadata.
Visible file contents and names are public. In `files` mode, AES-encrypted file names and relative paths are public as
central-directory metadata. In `archive` mode, the chosen outer entry name and its sizes are public; names inside the
encrypted inner ZIP are not in the outer listing.

The wrapper is compatibility content, not camouflage that makes DARC indistinguishable from every ordinary ZIP file.
Different ZIP tools can expose prefix size, unusual offsets, encryption metadata, or other structural clues.

## Offline password guessing

Each written slot carries its own 16-byte salt. Passwords are encoded as UTF-8 and processed with scrypt using
`N=2^18`, `r=8`, `p=1`, producing a 32-byte key. This deliberately makes each candidate more expensive, but it does
not make a weak password strong. An attacker can test guesses without interacting with the user.

Use strong, unrelated passwords for each slot and a separate password for passworded ZIP content. Reusing a password
links the user's operational choices and can expose multiple payloads if that password is recovered. Batch creation
rejects duplicate payload passwords, but separate slot updates cannot prevent deliberate reuse.

## Explicit non-goals

DARC v3 does not attempt to protect against:

- **Historical or cloud-diff analysis.** Multiple versions can reveal the updated slot range, operation frequency,
  growth decisions, and ZIP changes.
- **Endpoint, memory, or live-system forensics.** Password strings, derived keys, archive chunks, source files,
  extracted plaintext, GUI state, paging, crash dumps, and temporary directories may be observable. Memory is not
  locked or guaranteed to be zeroized.
- **Coercion resistance or legal deniability.** The tool cannot establish what an operator knows, prevent compelled
  disclosure, or provide legal assurances.
- **Trusted rollback detection.** There is no monotonic counter, remote transparency log, signed manifest, or trusted
  hardware state. An older valid container extracts normally.
- **Availability or recovery.** Authentication detects many changes but cannot repair them. There is no password,
  payload, or layout recovery feature.
- **Protection after password compromise.** A password holder can decrypt and forge its slot. ZIP entry passwords are
  independent and governed by WinZip AES behavior.
- **A hostile or concurrent endpoint.** Other processes can alter source content, replace files, observe operations,
  or bypass DARC's cooperative lock. Source identity, size, and timestamp checks run before and after streaming, and
  final components are opened without following symlinks where the OS supports it, but a hostile endpoint or kernel
  is not comprehensively controlled.
- **Traffic-analysis or constant-time UI/CLI behavior.** File access, CPU/memory use, progress, errors, and elapsed
  time may disclose what operation is running.

## Operational guidance

- Keep an independent, verified backup. Integrity without recovery does not protect availability.
- Preserve every custom layout exactly and use the same ordered values for create, update, and extract.
- Use high-entropy, unrelated passwords; do not rely on slot layout or ZIP appearance as the primary secret.
- Keep original source directories and extracted output on storage appropriate for plaintext. DARC cannot erase
  remnants, snapshots, indexing caches, or backups.
- Avoid versioned sync, deduplicating backups, and filesystem snapshots when historical-diff resistance matters. That
  scenario is outside this design.
- Treat external ZIP access as read-only. Listing or extracting wrapper entries is expected; editing, repairing, or
  re-saving the archive can discard the slot prefix or change its detected boundary.
- Do not run another writer against the same container. DARC's file lock coordinates DARC processes using the same
  canonical path, not arbitrary third-party programs or remote hosts.
- Keep the exact application version needed for old containers. v3 has no v2 reader or migration path.

## Version statement

This threat model applies to payload format version 3 as implemented by `core/format_v3.py`, `core/archiver.py`,
`core/archive_stream.py`, `core/storage.py`, and `core/zip_wrapper.py`. Format details are documented in
[format-v3.md](format-v3.md).
