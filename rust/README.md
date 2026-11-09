# nat20 (Rust)

A minimal `no_std` Rust port of the libnat20 CWT path, for linking into early
boot firmware on Arm Cortex-A. It performs deterministic DICE key derivation
and issues CWT certificates (COSE_Sign1, Ed25519):

1. **Device identity**: from the root CDI, derive the device-identity
   Ed25519 key and start the chain with its public key, a COSE_Key.
2. **Next stage**: from the root CDI plus the open-DICE measurements of the
   next boot stage, derive the next CDI and a second key pair, and issue a
   CWT carrying the open-DICE claims and the second public key, signed by
   the device-identity key.

The key and the certificate go into a DICE handover (`HANDOVER.md`), the certificate
chain each boot stage leaves in memory for the next.

## Compatibility with C libnat20

Derivation and wire format are byte-compatible with the C library using the
BoringSSL crypto backend: HKDF-Expand-SHA512 with the same `ASYM_SALT`,
`ID_SALT`, `"CDI_Attest"`, `"Key Pair Attest"`, and `"ID"` constants, and an
identical COSE_Sign1/CWT CBOR layout (verified byte-for-byte by
`nat20/tests/differential.rs` against a certificate produced by
`n20_issue_certificate`; regenerate with `tools/c_diff_harness.c`).

One deliberate departure: the chain does not start with a self-signed
certificate (the C library rejects COSE for self-signed certificates) but
with the device-identity public key itself, an Ed25519 COSE_Key
(`{1: OKP, 3: EdDSA, 4: [verify], -1: Ed25519, -2: x}`) under CBOR tag
80152. A signature by the key over itself would add nothing a verifier
can check. The next-stage CWT names the key's CDI_ID as its issuer.

Profile-specific rules stay with the profile: the profile name is written
verbatim as a CBOR text string, as in C libnat20, and an inline
configuration descriptor is not size-checked (the Open Profile for DICE
requires 64 bytes; other profiles relax that).

## Layout

- `nat20/` — the library (`#![no_std]`, no alloc, no floating point, no
  panics; `unsafe` only in the stack scrub's register clearing). Crypto is
  pluggable via the `Digest` and `Crypto` traits (`src/crypto/mod.rs`): a
  backend provides SHA-512, the key derivation and Ed25519 on opaque key
  handles, as C libnat20's `crypto.h` does, so it may keep its keys in a
  hardware engine. The `soft-crypto` feature provides a software backend on
  `sha2`, `hmac` and `ed25519-dalek`, the best-audited option.

  `nat20::handover` maintains the DICE handover (format: `HANDOVER.md`).
- `nat20-ffi/` — `staticlib` (`libnat20_rust.a`) exposing the C API in
  `include/nat20_rust.h`. The integrator supplies the crypto backend as a
  table of C functions, `n20r_crypto_t`; with the `soft-crypto` feature the
  library also offers its software backend as such a table.
- `size-probe/` — bare-metal binary used only to measure code size
  (see `SIZE.md`).
- `firmware/` — build profiles for particular firmware environments
  (cargo configuration files; see Firmware profiles).
- `support/` — runtime pieces for build systems that invoke rustc without
  cargo (such as U-Boot's Kbuild): an empty `compiler_builtins` stand-in
  and the ARM RTABI memory helpers such environments usually lack.
- `tools/` — `gen_vectors.py` (KDF test vectors, stdlib-only Python),
  `decode_cwt.py` (independent CWT decode + signature verification),
  `c_diff_harness.c` (regenerates the C-library golden certificate),
  `build-firmware-lib.sh` (builds the static library for a firmware
  profile),
  `stack-probe.sh` (checks under QEMU that no secret survives a call, and
  measures stack depth; see Security notes).

## Building

Host tests (also runs the differential golden test):

```
cargo test -p nat20                       # without a crypto backend
cargo test -p nat20 --features soft-crypto
cargo test -p nat20-ffi --lib --no-default-features --features soft-crypto
```

Cross-build the static library (the toolchain and target are pinned by
`rust-toolchain.toml`):

```
cargo build --release --target armv7a-none-eabi -p nat20-ffi
# -> target/armv7a-none-eabi/release/libnat20_rust.a
```

`.cargo/config.toml` holds the defaults for each bare-metal target, such as
Thumb-2 code on armv7; they apply whatever firmware the library goes into.
`nat20-ffi` and `size-probe` are excluded from default host builds
(`default-members`); they are bare-metal artifacts.

## Firmware integration

- Link `libnat20_rust.a` and include `nat20-ffi/include/nat20_rust.h`. In a
  `-nostdinc` environment that provides `size_t` and the `uintN_t` types
  itself, define `N20R_TYPES_HEADER` to that header (U-Boot:
  `-DN20R_TYPES_HEADER='"linux/types.h"'`; quoted, because GNU C
  predefines `linux`, which would be expanded inside angle brackets). The
  target is soft-float AAPCS (`armv7a-none-eabi`), matching
  `-mfloat-abi=soft`; no FP/NEON instructions are emitted. The library
  code is compiled as Thumb-2 (see `SIZE.md`); symbols carry the Thumb bit
  and the linker inserts interworking veneers as needed, so ARM-mode
  firmware links against it without special flags.
- Supply the crypto backend: an `n20r_crypto_t` table (see "Writing a
  crypto backend" below), or the built-in one from a library built with
  `soft-crypto`.
- If the firmware executes in place and never processes relocations,
  discard `.rel*` and `.ARM.exidx*` in its linker script — otherwise a
  `-pie` link appends them to flash as orphan sections (~5 KB).
- The library needs no libc beyond `memcpy`/`memset`/`memmove` (provided by
  compiler-builtins inside the archive; the environment's own copies also
  satisfy them).
- Panic behavior: the library contains no reachable panic (see Security
  notes), but a staticlib must still name a handler. The default
  `panic-loop` feature spins forever;
  `panic-putc-hang` prints the message through `putc()` and calls `hang()`,
  both of which the environment must provide (U-Boot does).
- Stack: the library itself reaches about 1 KiB below its caller on top of
  what the crypto backend uses; with the built-in backend the deepest call,
  `n20r_issue_next_stage_cwt`, reaches 8 KiB (11 KiB with
  `verify-after-sign`), wipes included.
- Calling sequence per boot, with `crypto` the backend's table and `cdi`
  the root CDI as one of its keys:
  1. `n20r_issue_device_id_key(&crypto, cdi, ...)` — the device-identity
     COSE_Key; starts the handover.
  2. `n20r_ctx_init(ctx, ...)`, then `n20r_set_*` as the measurements of
     the next stage become known.
  3. `n20r_issue_next_stage_cwt(&crypto, ctx, cdi, &next_cdi, ...)` —
     next-stage certificate, appended to the handover; `next_cdi` is the
     next CDI, a key of the backend. Hand it to the next boot stage, then
     free both CDIs. `n20r_ctx_cleanup(ctx)` releases adopted buffers.

  A stage that inherits a handover checks it with `n20r_handover_validate`
  before extending it. `n20r_encode_cbor_map` encodes open-DICE code and
  configuration descriptors, so the caller needs no CBOR encoder.

## Writing a crypto backend

An `n20r_crypto_t` (`nat20_rust.h`) provides five functions: SHA-512 over
a gather list, the key derivation, the Ed25519 public key and signature,
and freeing a key. Keys are opaque handles (`n20r_key_t`), as in C
libnat20's `crypto.h`, and the derivation is the same as its BoringSSL
backend's (HKDF-Expand-SHA512, 32 bytes), so a correct backend yields the
same keys and certificate bytes as C libnat20.

- **Key slots**: the library holds at most 3 keys at a time, the caller's
  root CDI included (`nat20::MIN_KEY_SLOTS`): issuing the next-stage
  certificate derives the next CDI first, then one attestation key at a
  time, each freed before the next is derived. A backend without dynamic
  allocation reserves 3 slots and never runs out; everything the library
  derives it frees, except the next CDI, which it hands to the caller.
- **Secrets**: a function must not leave anything it computed from a key
  behind when it returns, on success and on error: not on the stack below
  its caller's frame, not in the registers it may clobber. A software
  backend runs each computation in a function of its own that is never
  inlined, then zeroes the stack that function reached (for example with a
  volatile write loop over a local array of that size, in a function that
  is itself never inlined) and the scratch registers (r0-r3 and r12 on
  32-bit Arm). It must not panic, trap or print in between. `key_free`
  wipes the key. The library does not wipe after the backend.
- **Fault attacks**: a signature should be verified before it is released;
  a faulty signature next to a correct one over the same message can give
  the key away.

`tools/stack-probe.sh` shows how to check a backend: it runs each
operation of the built-in backend on a painted stack under QEMU and checks
that nothing is left below its frame, then runs the library's calls and
searches the stack for every secret they derive, the key-equivalent HMAC
midstates included.

## Firmware profiles

What a particular firmware environment needs beyond the target defaults
(reserved registers, C ABI details, panic hooks) is a profile: a cargo
configuration file `firmware/<environment>-<arch>.toml` that names the
target and adds the environment's flags. `tools/build-firmware-lib.sh
<profile>` builds the library with it, adds the crate features the
environment calls for, and rebuilds `core` from source (`-Zbuild-std=core`
via `RUSTC_BOOTSTRAP=1` on the pinned *stable* toolchain). It refuses to
run with `RUSTFLAGS` set: cargo would then ignore the profile's rustflags,
`+reserve-r9` among them, without a word. A build system that sets
`RUSTFLAGS` (Yocto does), or that invokes rustc itself, applies the
profile's flags itself. `tools/stack-probe.sh <profile>` checks the
secrets contract with them.

**U-Boot on 32-bit Arm** (`u-boot-armv7`), for SPL or U-Boot proper:

- r9 is never allocated (`+reserve-r9`): U-Boot keeps its global data
  pointer there. Compile the crypto backend's C with U-Boot's flags, which
  include `-ffixed-r9`.
- `core` is rebuilt because U-Boot links with `-pie`, which rejects the
  movw/movt absolute relocations in rustup's prebuilt core.
- Features: `panic-putc-hang`, with U-Boot's `putc()` and `hang()`.
- Include the header with `-DN20R_TYPES_HEADER='"linux/types.h"'`.
  U-Boot's Kbuild invokes rustc without cargo; `support/` has the pieces
  that needs.

Adding a profile, for example U-Boot on arm64 (`u-boot-aarch64`): U-Boot
keeps the pointer in x18 there, so the profile adds `+reserve-x18` and
`-ffixed-x18` for the crypto backend's C, and `tools/build-firmware-lib.sh`
gets a line with its features. A new target such as `aarch64-unknown-none`
also needs its defaults in `.cargo/config.toml`, the register clearing of
`nat20::crypto::scrubbed` for its architecture, and an entry in
`rust-toolchain.toml`.

## Security notes

- **Constant time**: the nat20 code itself handles no secret, only key
  handles. In the built-in backend secrets flow only through HMAC-SHA-512
  and curve25519-dalek's serial backend (constant-time by construction via
  `subtle`). A disassembly spot-check of the secret-handling functions
  (`LookupTable::select`, `conditional_assign`, scalar/field multiplication,
  `ExpandedSecretKey::from`) on the pinned toolchain found conditional
  branches only on public loop counters. This is best-effort assurance, not
  proof: re-check when bumping the toolchain (which is why
  `rust-toolchain.toml` pins it), and consider on-target trace testing
  (e.g. dudect-style) as future work.
- **Secrets in memory**: secrets live only in the crypto backend, behind
  key handles; the library never sees one, for Rust and C callers alike.
  The backend must leave nothing behind when an operation returns, on the
  stack below its caller or in the registers a call may clobber (see
  "Writing a crypto backend"). The built-in backend runs each operation in
  a frame of its own and then zeroes the stack it reached and r0-r3 and r12
  (`nat20::crypto::scrubbed`); its keys sit in a fixed number of slots,
  wiped when freed. Every key the library derives it frees on every path,
  except the next CDI it hands to the caller.

  None of this would survive a panic (a wipe or a free would never run), so
  the library has none: linked against a crypto backend that does nothing
  and a panic handler that cannot be linked (`panic-never`, see `SIZE.md`),
  the whole C ABI links only if the optimizer proved every panic
  unreachable, which it does. The built-in backend is outside that proof:
  curve25519-dalek's bounds-checked scalar indexing keeps panic paths the
  compiler cannot remove, so there the guarantee rests on dalek.
  `tools/stack-probe.sh` checks the built-in backend under
  `qemu-system-arm`, built as for firmware, on a painted stack: after each
  backend operation nothing below its own frame may be left, and after each
  FFI entry point no secret, from a list that includes the HMAC midstates.
  It checks it can see a leak by also running without the backend's scrub.
- **Fault injection**: signing is deterministic (RFC 8032; early boot
  firmware usually has no RNG), so a fault attacker who can obtain two
  different signatures over the same message could recover the key. A
  backend should verify each signature before it releases it; the
  built-in one does with the `verify-after-sign` feature (of `nat20`,
  forwarded by `nat20-ffi`; about +3.3 KB with dalek, ~2x signing time).
  Enable it if the threat model includes physical glitching.

## Verifying certificates off-target

```
python3 tools/decode_cwt.py next_stage.cwt device_id.key # against the device-identity COSE_Key
python3 tools/decode_cwt.py next.cwt next_stage.cwt      # against the issuer certificate
```
