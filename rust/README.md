# nat20 (Rust)

A minimal `no_std` Rust port of the libnat20 CWT path, for linking into early
boot firmware on Arm Cortex-A. It performs deterministic DICE key derivation
and issues CWT certificates (COSE_Sign1, Ed25519):

1. **Device identity**: from the root CDI, derive the device-identity
   Ed25519 key and issue a *self-signed* CWT.
2. **Next stage**: from the root CDI plus the open-DICE measurements of the
   next boot stage, derive the next CDI and a second key pair, and issue a
   CWT carrying the open-DICE claims and the second public key, signed by
   the device-identity key.

Both certificates go into a DICE handover (`HANDOVER.md`), the certificate
chain each boot stage leaves in memory for the next.

## Compatibility with C libnat20

Derivation and wire format are byte-compatible with the C library using the
BoringSSL crypto backend: HKDF-Expand-SHA512 with the same `ASYM_SALT`,
`ID_SALT`, `"CDI_Attest"`, `"Key Pair Attest"`, and `"ID"` constants, and an
identical COSE_Sign1/CWT CBOR layout (verified byte-for-byte by
`nat20/tests/differential.rs` against a certificate produced by
`n20_issue_certificate`; regenerate with `tools/c_diff_harness.c`).

One deliberate extension: the C library currently rejects COSE for
self-signed certificates; this port issues the device-identity CWT
self-signed (issuer == subject == CDI_ID of the embedded key, mode claim
`0x00` "not configured", key usage keyCertSign).

Profile-specific rules stay with the profile: the profile name is written
verbatim as a CBOR text string, as in C libnat20, and an inline
configuration descriptor is not size-checked (the Open Profile for DICE
requires 64 bytes; other profiles relax that).

## Layout

- `nat20/` — the library (`#![no_std]`, no alloc, no floating point;
  `unsafe` is forbidden outside the optional Monocypher FFI module). Crypto
  is pluggable via the `Digest` and `Ed25519Signer` traits
  (`src/crypto/mod.rs`); HKDF is implemented generically on `Digest`, so a
  hardware SHA-512/HMAC engine only implements two functions. Two built-in
  backends:
  - `soft-crypto` (default): `sha2`, `hmac`, `ed25519-dalek` — the
    best-audited option.
  - `mono-crypto`: vendored Monocypher (C, `third_party/monocypher`), about
    8 KB smaller, for tight flash budgets. `nat20/tests/mono.rs` proves
    byte-identical output to `soft-crypto` and to C libnat20.

  `nat20::handover` maintains the DICE handover (format: `HANDOVER.md`).
- `nat20-ffi/` — `staticlib` (`libnat20_rust.a`) exposing the C API in
  `include/nat20_rust.h`.
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
  `stack-probe.sh` (checks under QEMU that no secret survives on the stack,
  and measures stack depth; see Security notes).

## Building

Host tests (also runs the differential golden test):

```
cargo test -p nat20 --features soft-crypto
cargo test -p nat20 --features soft-crypto,mono-crypto
cargo test -p nat20-ffi --lib --no-default-features --features soft-crypto
# FFI on Monocypher, checked against the soft-crypto reference:
cargo test -p nat20-ffi --lib --no-default-features --features mono-crypto,soft-crypto
```

The Monocypher backend needs a C compiler for the target (`cc` on the host,
`arm-none-eabi-gcc` for `armv7a-none-eabi`).

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
  `-mfloat-abi=soft`; no FP/NEON instructions are emitted. The library code is compiled as Thumb-2 (see `SIZE.md`);
  symbols carry the Thumb bit and the linker inserts interworking veneers as
  needed, so ARM-mode firmware links against it without special flags.
- Monocypher is compiled with `-mno-unaligned-access`, so the library runs
  with strict alignment checking (SCTLR.A) enabled.
- If the firmware executes in place and never processes relocations,
  discard `.rel*` and `.ARM.exidx*` in its linker script — otherwise a
  `-pie` link appends them to flash as orphan sections (~5 KB).
- The library needs no libc beyond `memcpy`/`memset`/`memmove` (provided by
  compiler-builtins inside the archive; the environment's own copies also
  satisfy them).
- Panic behavior: the default `panic-loop` feature spins forever;
  `panic-putc-hang` prints the message through `putc()` and calls `hang()`,
  both of which the environment must provide (U-Boot does).
- Stack: budget 3 KiB (Monocypher) or 8 KiB (soft backend) below the
  caller of each issue call. That is `N20R_STACK_SCRUB_SIZE`, the region
  the call zeroes before returning; the calls themselves reach 2.2 KiB and
  6.4 KiB.
- Calling sequence per boot:
  1. `n20r_issue_device_id_cwt(cdi, ...)` — self-signed device identity;
     starts the handover.
  2. `n20r_ctx_init(ctx, ...)`, then `n20r_set_*` as the measurements of
     the next stage become known.
  3. `n20r_issue_next_stage_cwt(ctx, cdi, next_cdi, ...)` — next-stage
     certificate, appended to the handover; hand `next_cdi` to the next
     boot stage, then scrub the root CDI. `n20r_ctx_cleanup(ctx)` releases
     adopted buffers.

  A stage that inherits a handover checks it with `n20r_handover_validate`
  before extending it. `n20r_encode_cbor_map` encodes open-DICE code and
  configuration descriptors, so the caller needs no CBOR encoder.

## Firmware profiles

What a particular firmware environment needs beyond the target defaults
(reserved registers, C ABI details, panic hooks) is a profile: a cargo
configuration file `firmware/<environment>-<arch>.toml` that names the
target and adds the environment's flags. `tools/build-firmware-lib.sh
<profile>` builds the library with it, adds the crate features the
environment calls for, and rebuilds `core` from source (`-Zbuild-std=core`
via `RUSTC_BOOTSTRAP=1` on the pinned *stable* toolchain); `SLIM=1` also
strips the panic-formatting machinery if the size budget demands it. A
build system that invokes rustc and the C compiler itself applies the
profile's flags the same way. `tools/stack-probe.sh <profile>` checks the
stack scrub with them.

**U-Boot on 32-bit Arm** (`u-boot-armv7`), for SPL or U-Boot proper:

- r9 is never allocated (`+reserve-r9`, and `-ffixed-r9` for Monocypher):
  U-Boot keeps its global data pointer there.
- `core` is rebuilt because U-Boot links with `-pie`, which rejects the
  movw/movt absolute relocations in rustup's prebuilt core.
- Monocypher is compiled with `-fshort-wchar -fno-short-enums`, matching
  the EABI attributes of U-Boot's objects.
- Features: `mono-crypto` and `panic-putc-hang`, with U-Boot's `putc()`
  and `hang()`.
- Include the header with `-DN20R_TYPES_HEADER='"linux/types.h"'`.
  U-Boot's Kbuild invokes rustc without cargo; `support/` has the pieces
  that needs.

Adding a profile, for example U-Boot on arm64 (`u-boot-aarch64`): U-Boot
keeps the pointer in x18 there, so the profile adds `+reserve-x18` and
`-ffixed-x18`, and `tools/build-firmware-lib.sh` gets a line with its
features. A new target such as `aarch64-unknown-none` also needs its
defaults in `.cargo/config.toml`, the C compiler for Monocypher in
`nat20/build.rs`, and an entry in `rust-toolchain.toml`.

## Security notes

- **Constant time**: the nat20 code itself has no secret-dependent branches
  or memory indexing; secrets flow only through HMAC-SHA-512 and
  curve25519-dalek's serial backend (constant-time by construction via
  `subtle`). A disassembly spot-check of the secret-handling functions
  (`LookupTable::select`, `conditional_assign`, scalar/field multiplication,
  `ExpandedSecretKey::from`) on the pinned toolchain found conditional
  branches only on public loop counters. This is best-effort assurance, not
  proof: re-check when bumping the toolchain (which is why
  `rust-toolchain.toml` pins it), and consider on-target trace testing
  (e.g. dudect-style) as future work.
- **Zeroization**: `CdiSecret` and `Seed32` are zeroized on drop, as are
  HKDF intermediates and ed25519-dalek's key material (its `zeroize`
  feature). The derivations fill caller-owned containers instead of
  returning secrets by value, since every move leaves a copy no destructor
  sees. That still leaves what the crypto backends' locals and spilled
  registers leave in dead frames: Monocypher's SHA-512 compression state
  (key-equivalent for an HMAC keyed with a CDI), dalek's expanded scalar.
  So each secret-handling FFI entry point runs its body in a frame of its
  own and then zeroes `N20R_STACK_SCRUB_SIZE` bytes of stack below its
  frame, on success and on error. `tools/stack-probe.sh` runs those entry
  points under `qemu-system-arm`, built as for firmware, on a painted
  stack: it fails if anything but the entry point's own frame (arguments,
  saved registers) is left, or if any derived secret is found, and it
  checks it can see a leak by also running without the scrub. Registers
  are not cleared, and the caller still owns wiping the root CDI it passed
  in and the next CDI it got back.
- **Fault injection**: signing is deterministic (RFC 8032; early boot
  firmware usually has no RNG), so a fault attacker who can obtain two
  different signatures over the same message could recover the key. The
  `verify-after-sign` feature of `nat20` re-verifies every signature before
  release (~+10 KB, ~2x signing time); enable it if the threat model
  includes physical glitching.

## Verifying certificates off-target

```
python3 tools/decode_cwt.py device_id.cwt                # self-signed
python3 tools/decode_cwt.py next_stage.cwt device_id.cwt # chained
```
