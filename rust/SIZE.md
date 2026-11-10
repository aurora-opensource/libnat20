# Code size

Measured on `size-probe`, which links the full FFI surface
(`n20r_issue_device_id_key`, `n20r_issue_next_stage_cwt`,
`n20r_device_id_public_key`, the context setters, `n20r_handover_validate`
and `n20r_encode_cbor_map`), built with the pinned toolchain for
`armv7a-none-eabi`, release profile (`opt-level = "z"`, fat LTO,
`panic = "abort"`). Without features it hands the library a crypto table
that computes nothing, so the size is the library's own; the firmware adds
its crypto backend. `soft-crypto` adds the built-in backend instead:

```
cargo build --release --target armv7a-none-eabi -p size-probe
cargo build --release --target armv7a-none-eabi -p size-probe --features soft-crypto
llvm-size target/armv7a-none-eabi/release/size-probe
```

Budget: **40 KB .text**.

| build                                        | .text   |
|----------------------------------------------|---------|
| library only                                 |  8260 B |
| with the built-in backend (`soft-crypto`)    | 29742 B |
| `soft-crypto`, `verify-after-sign`           | 33006 B |

## No reachable panic

The library-only build with the `panic-never` feature checks that the
library contains no panic the optimizer could not remove:

```
cargo build --release --target armv7a-none-eabi -p size-probe --features panic-never
```

`panic-never` installs a panic handler that calls a symbol nothing defines,
so the link fails if any panic is still reachable once fat LTO is done. It
succeeds, with the target defaults and with each firmware profile, and
whatever crypto backend the firmware links: the backend is outside the
Rust code, behind function pointers. That is what the secrets contract of
`nat20::crypto` relies on: a panic would never come back to wipe or free
anything. With `soft-crypto` it fails on bounds checks inside
curve25519-dalek's scalar arithmetic, which the compiler cannot prove
away. The check depends on the build (optimization level, LTO), so it is
made on the build that ships. A failing link names no culprit; looking for
calls into `core::panicking` and `core::slice::index` in the disassembly of
the ordinary build finds them.

What the numbers rest on:

- **Thumb-2** (`.cargo/config.toml`): about 15–20% smaller than ARM mode.
  The constant-time spot-check was done on the Thumb disassembly: the
  curve and scalar secret paths are branch-free, and all `it` blocks sit in
  public-data encoder and FFI code.
- **Compact SHA-512**: the `sha2` feature `force-soft-compact` selects the
  loop-based compression function, about 15 KB smaller than the default
  unrolled one on 32-bit Arm.
- **The crypto backend**: most of the built-in backend's size is
  curve25519-dalek and sha2, unrolled for speed. A backend written for
  size is much smaller: one over Monocypher measured about 8 KB less.
- **Panic formatting**: no panic is reachable in the library, so the panic
  handler and its message formatting (several KiB) are not linked at all.
  `-Cpanic=immediate-abort`, which would drop them with the built-in
  backend, is deliberately not offered: panics then become trap
  instructions, and a firmware's exception handler (U-Boot's) dumps the
  registers, which can hold secrets, on its console.
- **Firmware profiles**: the numbers are for the target defaults. A
  profile's flags cost a little on top: reserving r9 for U-Boot
  (`firmware/u-boot-armv7.toml`) adds nothing to the library alone and
  56 B with the built-in backend.

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
e.g. "nat20 (lib)" includes hmac/sha2 code inlined into the backend's
bodies; treat the split as approximate.

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
