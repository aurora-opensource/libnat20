# Code size

Measured on `size-probe`, which links the full FFI surface
(`n20r_issue_device_id_cwt`, `n20r_issue_next_stage_cwt`,
`n20r_device_id_public_key`, the context setters, `n20r_handover_validate`
and `n20r_encode_cbor_map`), built with the pinned toolchain for
`armv7a-none-eabi`, release profile (`opt-level = "z"`, fat LTO,
`panic = "abort"`):

```
cargo build --release --target armv7a-none-eabi -p size-probe
cargo build --release --target armv7a-none-eabi -p size-probe \
    --no-default-features --features mono-crypto
llvm-size target/armv7a-none-eabi/release/size-probe
```

Budget: **40 KB .text**.

| backend                                   | .text   |
|-------------------------------------------|---------|
| `soft-crypto` (default)                   | 28800 B |
| `mono-crypto`                             | 19834 B |
| `mono-crypto`, `verify-after-sign`        | 22630 B |

## No reachable panic

The same build with the `panic-never` feature checks that the library
contains no panic the optimizer could not remove:

```
cargo build --release --target armv7a-none-eabi -p size-probe \
    --no-default-features --features mono-crypto,panic-never
```

`panic-never` installs a panic handler that calls a symbol nothing defines,
so the link fails if any panic is still reachable once fat LTO is done. It
succeeds for `mono-crypto` (with and without `verify-after-sign`, and with
the firmware profiles), which is what the secret invariants of
`nat20::crypto` rely on: a panic would never come back to wipe anything.
With `soft-crypto` it fails on bounds checks inside curve25519-dalek's
scalar arithmetic, which the compiler cannot prove away. The check depends
on the build (optimization level, LTO), so it is made on the build that
ships. A failing link names no culprit; looking for calls into
`core::panicking` and `core::slice::index` in the disassembly of the
ordinary build finds them.

What the numbers rest on:

- **Thumb-2** (`.cargo/config.toml`): about 15–20% smaller than ARM mode
  (Monocypher: 23882 B in ARM mode). The constant-time spot-check was done
  on the Thumb disassembly: the curve and scalar secret paths are
  branch-free, and all `it` blocks sit in public-data encoder and FFI code.
- **Compact SHA-512**: the `sha2` feature `force-soft-compact` selects the
  loop-based compression function, about 15 KB smaller than the default
  unrolled one on 32-bit Arm.
- **Backend choice**: Monocypher saves about 8 KB over ed25519-dalek and
  sha2, whose arithmetic is unrolled for speed. A pure-C build of the same
  feature set (libnat20's encoders plus Monocypher) measured within about
  1.1 KB of the Rust build with Monocypher, so the footprint is the crypto
  backend, not the language.
- **Panic formatting**: with `mono-crypto` no panic is reachable, so the
  panic handler and its message formatting (several KiB) are not linked
  at all. `-Cpanic=immediate-abort`, which would drop them with the soft
  backend, is deliberately not offered: panics then become trap
  instructions, and a firmware's exception handler (U-Boot's) dumps the
  registers, which can hold secrets, on its console.
- **Firmware profiles**: the numbers are for the target defaults. A
  profile's flags cost a little on top: reserving r9 for U-Boot
  (`firmware/u-boot-armv7.toml`) adds 44 B (soft) and 24 B (Monocypher).

Experiments that did **not** pay off (don't re-try without new evidence):
`#[inline(never)]` on the CBOR writers (±0 — they were already outlined);
a data-driven `CborType` enum + interpreter for the CWT/COSE maps (+364 B —
building the description array costs more than the direct call sequence);
`+hwdiv,+hwdiv-arm` for Cortex-A7 (+2 KB — unknown-to-rustc features block
inlining against prebuilt core, and the library has no runtime division).

## Per-crate attribution

From `llvm-nm --print-size` on an unstripped build
(`--config 'profile.release.strip="none"'`), .text symbols grouped by crate
namespace. Caveat: fat LTO attributes inlined callee code to the caller, so
e.g. "nat20 (lib)" includes hmac/sha2 code inlined into the HKDF and
`SoftCrypto::hmac_sha512` bodies; treat the split as approximate.

| bytes | share | crate |
|-------|-------|-------|
| 12066 | 46.3% | curve25519-dalek (serial u32 backend) |
|  5030 | 19.3% | nat20 (lib) |
|  2740 | 10.5% | compiler-builtins (memcpy/memmove/udiv...; prebuilt, stays ARM-mode) |
|  2152 |  8.3% | ed25519-dalek |
|   970 |  3.7% | sha2 (compact compress) |
|   966 |  3.7% | core (slice indexing, prebuilt) |
|   946 |  3.6% | hmac/digest/block-buffer |
|   942 |  3.6% | nat20-ffi |
|   148 |  0.6% | size-probe harness |
|    78 |  0.3% | zeroize + subtle |
| 26044 |  100% | attributed; remainder of the 28924 B .text is padding/literal pools |

(Measured on the soft backend's Thumb-2 build of an earlier revision,
28 924 B; the proportions are indicative, re-measure before relying on the
exact figures.)

Further squeezes if ever needed: nightly `-Zbuild-std=core` with
`-Zbuild-std-features=panic_immediate_abort` (drops residual `core::fmt`
panic machinery), `opt_size`-style trimming of the probe itself.
