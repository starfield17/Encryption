# DARC Payload Format v3

This document describes the v3 byte layout implemented in `core/format_v3.py` and its container framing. Integer
fields are unsigned big-endian unless stated otherwise. Constants in the implementation are authoritative.

v3 is intentionally incompatible with v2. There is no v2 auto-detection, reader, writer, or migration path in the
current application.

## Container framing

A raw container is only the concatenation of its fixed-size slots:

```text
+----------------+----------------+-----+----------------+
| slot 0         | slot 1         | ... | slot N - 1     |
+----------------+----------------+-----+----------------+
```

An optionally wrapped container appends a complete ZIP suffix after the same slot region:

```text
+---------------------------+----------------------------+
| slot region               | ZIP local data + directory |
+---------------------------+----------------------------+
0                           slot_region_size             end of file
```

The default is a raw file with a `.darc` extension. The extension is not parsed and is not authenticated. When a
valid supported trailing ZIP is detected, its prefix offset defines `slot_region_size`; otherwise the complete file
is treated as the slot region. There is no plaintext global DARC header or global version field.

This framing is an important security boundary: slot authentication does not cover the ZIP suffix or complete file
length. It does bind a commitment to the caller-supplied ordered layout, including the sum of all slot sizes, so a
different slot-region boundary cannot validate a written control record under an alternate layout.

## Layout

The caller supplies either an equal slot count or an ordered custom layout. A layout must:

- contain at least 2 and at most 16 slots;
- contain only positive, representable slot sizes;
- sum exactly to the detected slot-region size.

The default is four equal slots. An equal layout also requires the region size to be divisible by its slot count.
Custom CLI sizes are positive integer MiB values. The core API uses byte counts.

Slot indexes in the binary construction, CLI, and core API are zero-based. The GUI displays `index + 1`, so GUI slot
`1` is binary/core slot `0`.

No slot table is stored in the slot region. An extractor must be given the same layout used for writing. The layout is
part of record associated data, but it is not a cryptographic key; see [the threat model](threat-model.md).

## Slot structure

Every slot consumes exactly its declared size `S`:

| Relative offset | Length | Value |
| --- | ---: | --- |
| `0` | 16 | Random scrypt salt |
| `16` | 8 | Random AEAD nonce prefix |
| `24` | 144 | Encrypted 128-byte control record plus 16-byte tag |
| `168` | Remaining bytes | One or more encrypted data records, each followed by a 16-byte tag |

The salt and nonce prefix are public random values. Changing either prevents the existing control and data records
from authenticating. The format currently requires a slot to be at least 185 bytes: 168 prefix bytes, one plaintext
data byte, and one data-record tag. Normal CLI layouts are much larger.

### Data-record sizing

Let:

```text
C = 1,048,576                 maximum data-record plaintext bytes
R = S - 168                   bytes after the fixed slot prefix
n = ceil(R / (C + 16))        number of data records
P = R - 16*n                  total archive-plus-padding plaintext capacity
```

`R` must be greater than 16, and `P` must leave at least one plaintext byte for every record. The implementation
assigns each record length `L_i` in order, taking at most `C` bytes while reserving at least one byte for every
remaining record. Therefore:

```text
1 <= L_i <= C
sum(L_i) = P
sum(L_i + 16) = R
```

`P` is the maximum compressed tar+zstd archive length for the slot. It is not a limit on the restored logical size;
a highly compressible payload can restore to more bytes than `S`. The authenticated control record carries the
expected uncompressed size and entry count, and extraction enforces both.

## Key derivation and AEAD

The password must be a nonempty Python string and is encoded as UTF-8. Each written slot derives an independent key:

```text
KDF        = scrypt
salt       = 16 random bytes from os.urandom
N          = 2^18
r          = 8
p          = 1
key length = 32 bytes
```

Records use ChaCha20-Poly1305 with a 16-byte tag. A fresh 8-byte random nonce prefix is generated every time a slot is
written. The 12-byte nonce for record `j` is:

```text
nonce = nonce_prefix[8] || uint32_be(j)
```

Record index `0` is reserved for the control record. Data record indexes are `1` through `n`. The current maximum
container and slot-count limits keep `n` well below the 32-bit nonce counter limit.

First compute a commitment to the complete ordered layout:

```text
layout_commitment = SHA-256(
    b"DARCv3-layout\x00"
    || uint32_be(slot_count)
    || uint64_be(slot_0_size)
    || ...
    || uint64_be(slot_N_minus_1_size)
)
```

Every record's associated data is:

```text
b"DARCv3\x00" || layout_commitment[32]
                || uint32_be(slot_index)
                || uint64_be(slot_size)
                || uint32_be(record_index)
                || uint32_be(plaintext_length)
```

This binds ciphertext to the v3 domain, the complete slot count/sizes/order, their summed region size, the record's
zero-based slot index, declared slot size, record position, and expected plaintext size. It prevents silent
cross-index slot relocation, layout reinterpretation, removal of complete trailing slots under a smaller layout,
record reordering, and record truncation under the normal AEAD assumptions. It does not authenticate another slot's
contents, the container path, file metadata, total file length, or the optional ZIP suffix.

## Encrypted control record

The control plaintext is exactly 128 bytes. Its first 74 bytes use the following structure; the remaining 54 bytes
are fresh random padding:

| Offset | Type | Field | Required value or meaning |
| ---: | --- | --- | --- |
| 0 | `bytes[8]` | magic | `DARC3PAY` |
| 8 | `uint16` | version | `3` |
| 10 | `uint16` | header length | `74` |
| 12 | `uint16` | codec | `1` = PAX tar compressed with zstd |
| 14 | `uint32` | chunk count | Must equal `n` derived from slot size |
| 18 | `uint64` | archive length | Meaningful compressed bytes at the start of data plaintext |
| 26 | `uint64` | uncompressed size | Sum of restored regular-file byte lengths |
| 34 | `uint64` | entry count | Number of archived regular-file and directory entries |
| 42 | `bytes[32]` | archive SHA-256 | Digest of the `archive length` compressed bytes |
| 74 | `bytes[54]` | reserved padding | Random in v3; ignored after control authentication |

The entire 128-byte plaintext is encrypted and authenticated as record `0`, yielding 144 bytes. The magic and version
are therefore not visible without a matching password. The SHA-256 digest is not a substitute for AEAD; because it is
inside the authenticated control, it supplies an additional end-to-end check over the meaningful compressed stream.

`archive length` must not exceed `P`. The reader also rejects unsupported codec values and a chunk count inconsistent
with the supplied slot size. Higher-level extraction caps the authenticated entry count at 10,000.

## Archive and padding plaintext

The payload archive is produced as a streaming POSIX PAX tar and compressed by zstd at level 6. v3 always compresses;
the old `compress` API parameter and CLI `--no-compress` flag do not alter this codec.

The tar writer stores relative regular-file and directory entries. It normalizes owner identifiers to `0` and owner
names to empty strings, while retaining permission mode and integer modification time. Source symlinks and special
files are rejected. Cross-platform unsafe names and case-folded/NFC path collisions are also rejected.

The archive bytes are fed directly into the ordered data-record plaintext stream. After the compressed frame ends,
the writer fills every remaining plaintext byte through the end of the slot with `os.urandom` data. It then encrypts
every complete record. There is no unauthenticated gap between the control record and the slot boundary.

The control record is written last, after archive length, digest, uncompressed size, and entry count are known. Atomic
container publication prevents that temporary, incomplete slot from replacing the original on an ordinary failure.

## Read and verification sequence

For each candidate slot in the supplied layout, extraction:

1. Reads the 16-byte salt, 8-byte nonce prefix, and 144-byte encrypted control.
2. Derives a key from the supplied password and that slot's salt.
3. Computes the complete ordered-layout commitment and attempts control-record AEAD verification with that
   commitment plus the candidate index and size.
4. Validates the decrypted format fields and remembers the first valid match, while continuing the control scan.
5. Streams the matching archive bytes through zstd and the safe tar extractor into a temporary sibling directory.
6. Checks output paths and entry types, enforces authenticated file-size and entry-count totals, and rejects unsafe or
   duplicate cross-platform paths.
7. Decrypts all records through the slot boundary, including archive-tail padding, and compares the compressed-stream
   SHA-256 digest.
8. Publishes the temporary directory only after every check succeeds.

Wrong-password control authentication returns no match for that slot. An authentication or supported archive failure
after a control match discards the staged output and returns the same generic no-match result. The CLI maps that
result to exit code `3`. It does not write a raw fallback artifact.

Only the selected matching slot is fully authenticated. Other nonmatching slots are control-tested but their data
records are not decrypted, random unfilled slots have no tags, and the ZIP suffix is outside this sequence. DARC has
no whole-container signature or rollback counter.

## Optional ZIP suffix

ZIP mode appends a non-ZIP64 archive whose offsets account for the preceding slot region. It is disabled by default.
An enabled wrapper must contain at least one real regular file from either source category:

- **Visible source:** each file becomes an ordinary DEFLATE entry with public name, metadata, and content.
- **Passworded source, `archive` mode:** the files are first put in an inner DEFLATE ZIP. Those bytes become one outer
  WinZip AES-256 entry, `Documents.zip` by default.
- **Passworded source, `files` mode:** each file becomes a separate WinZip AES-256 outer entry. Names and paths remain
  visible without the password.

Empty sources cannot create an empty wrapper. Passworded content requires a nonempty separate ZIP entry password.
Unsafe names, symlinks, special files, duplicates (including case/NFC collisions), source identity/size/timestamp
changes observed before or after streaming, too many entries, and bounds requiring ZIP64 are rejected. Source files
are streamed from verified file descriptors rather than reopened by pathname during ZIP writing.

The current wrapper implementation constructs the complete outer suffix in memory. `archive` mode additionally
constructs the complete inner ZIP in memory before encrypting it. This differs from the streaming encrypted-slot
archive path and can materially increase peak memory use for large wrapper sources.

The ZIP suffix does not protect or authenticate slot data, and slot AEAD does not protect the ZIP suffix. External ZIP
programs should only list or extract entries. An editor or repair tool may rewrite the central directory, change the
detected prefix offset, or discard the leading slot region entirely.

## Limits and compatibility notes

- Maximum accepted complete container file size: 16,384 MiB.
- Maximum configured raw slot-region size: 16,384 MiB; a ZIP wrapper can impose a lower effective limit.
- Slot count: 2 through 16; default 4.
- Data plaintext chunk maximum: 1 MiB; each record adds a 16-byte tag.
- Archive entry count accepted by the higher-level writer/reader: 10,000.
- ZIP wrapper: ZIP32 only. Prefix and content sizes are preflighted, so the optional wrapper can impose a lower limit
  than the raw 16,384 MiB maximum.
- Password KDF parameters and archive codec are fixed for v3. There is no plaintext algorithm-negotiation header.
- v2 payloads are not accepted. Preserve an old compatible reader until all needed v2 data has been recovered.

For the security claims and non-goals surrounding this construction, read [threat-model.md](threat-model.md).
