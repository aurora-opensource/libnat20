# DICE handover format

The handover is the certificate chain a boot stage leaves in memory for the
next one. Each stage that issues a certificate appends it; the last stage
hands the whole chain on (e.g. to the OS, via a reserved-memory node).
Implemented by `nat20::handover`.

## Layout

A handover is a 16-byte header immediately followed by its content:

| Offset | Size | Field               | Value                                     |
|-------:|-----:|---------------------|-------------------------------------------|
|      0 |    4 | `magic`             | ASCII `"DICE"`                            |
|      4 |    4 | `version`           | 1                                         |
|      8 |    4 | `header_size`       | 16                                        |
|     12 |    4 | `terminator_offset` | offset of the array's break byte (`0xFF`) |

All integers are unsigned 32-bit **little-endian**, independent of the host.
Offsets are relative to the start of the header. The header is naturally
aligned (4 bytes).

The content, starting at offset `header_size`, is a CBOR indefinite-length
array (RFC 8949 §3.2.2):

```
0x9F  entry  entry  ...  0xFF
```

The break byte `0xFF` is at `terminator_offset`. Bytes after it are unused
and carry no meaning.

Each entry is one complete CBOR data item, in chain order (device identity
first, each later certificate signed by the key of the one before):

- `#6.18(COSE_Sign1)` — a CWT DICE certificate (tag byte `0xD2`), or
- a tagged byte string holding a DER X.509 certificate.

The library writes only the first kind today.

## Rules

A stage that **starts** a chain initializes the region: header as above,
content `0x9F 0xFF`, `terminator_offset = 17`.

A stage that **inherits** a chain must, before trusting or extending it,
check:

1. `magic`, `version` and `header_size` have exactly the values above;
2. `header_size < terminator_offset < region size`;
3. the first content byte is `0x9F` and the byte at `terminator_offset` is
   `0xFF`.

`HandoverStruct::used_size` (C: `n20r_handover_validate`) performs these
checks and returns `terminator_offset + 1`, the number of bytes in use. It
does not parse entries; certificate verification is the consumer's job.
Appending and reserving run the same checks first, so a malformed chain is
never extended.

**Appending** an entry writes it at `terminator_offset`, writes a new break
byte right after it, and advances `terminator_offset` by the entry size.
An entry fits only if its new break byte is still inside the region. An
append that fails, or an in-place reservation that is abandoned, leaves
the handover exactly as it was.

A version other than 1 must be rejected; a future version may change the
layout in incompatible ways.
