# Example crypto backend: Monocypher

`n20r_monocypher.c` implements `n20r_crypto_t` (`nat20_rust.h`) over
[Monocypher](https://monocypher.org) 4.0.3, vendored in
`third_party/monocypher` (BSD-2-Clause or CC0-1.0). It is an example of what
an integrator's crypto backend looks like; nothing in libnat20 builds or
depends on it.

What it shows:

- **Key handles without allocation**: keys live in a fixed array of
  `N20R_MONOCYPHER_KEY_SLOTS` (3) slots in caller-provided state, the most
  the library holds at once. A handle is a slot index plus one.
- **The derivation**: `kdf` is HKDF-Expand-SHA512 with 32 bytes of output,
  so the keys, CDIs and certificates are the same as with C libnat20 and the
  library's built-in backend.
- **Wiping**: each operation runs in a function of its own (`NOINLINE`);
  afterwards `wipe_stack()` zeroes `N20R_MONOCYPHER_STACK_WIPE` bytes below
  the caller's frame and `wipe_registers()` zeroes r0-r3 and r12 on 32-bit
  Arm. Monocypher wipes its own contexts, and the example wipes its copies
  of keys. A freed key is wiped. Under `qemu-system-arm` with the stack
  probe's checks, the deepest operation (signing) reaches about 1.9 KiB on
  armv7 Thumb-2 with `-Os`, and nothing derived is left after any of them;
  measure again for your target and flags.
- **Fault resistance**: a signature is verified with `crypto_ed25519_check`
  before it is released.
- **Size**: on armv7 Thumb-2 the backend is about 8 KB smaller than the
  library's built-in one (curve25519-dalek and sha2).

Run the host test, which issues the certificates with this backend and
checks them against C libnat20's golden certificate and, byte for byte,
against the built-in backend:

```
make test
```

For firmware, compile `n20r_monocypher.c` and the two Monocypher sources
with the firmware's own compiler and flags (for U-Boot on 32-bit Arm that
includes `-ffixed-r9`, and `-mno-unaligned-access` if the firmware runs with
strict alignment checking), and link them beside `libnat20_rust.a`.
