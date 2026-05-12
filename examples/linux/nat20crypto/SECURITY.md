# Security Assessment - nat20crypto

This module implements the libnat20 crypto interface in terms of
kernel-provided primitives. It attempts to provide a functionally correct
implementation and makes an effort to clean sensitive key material from
memory. But it is **not suitable for production**, specifically the ECC
signing operation is not constant-time and susceptible to leaking private
key information through timing side channels.

## Key Material Leak Analysis

### Addressed

- **`nat20crypto_sign`** — stack buffers `z`, `k`, `k_inv`, `rs` are wiped via
  `memzero_explicit` on all exit paths. This covers the nonce, the inverted
  nonce, the byte-swapped private key (in `k_inv` via the `key_bytes` alias),
  and intermediate signature values.
- **`nat20crypto_key_destroy`** — uses `memzero_explicit` before `kfree`.
- **`nat20crypto_make_secret`** — the input `secret_in` buffer is caller-owned;
  the output key is heap-allocated and properly zeroed on free.

### Outstanding issues

#### `n20_rfc6979_k_generation` internal state

This function (from nat20lib) uses HMAC internally with the private key as
input. Whether its internal buffers are zeroed depends on its implementation.
Out of scope for this module but noted as a dependency.

## Timing Side Channel Analysis

### Threat model

In a DICE boot-time context where signing happens once during module init with
no concurrent attacker (single-threaded init, no network, no user interaction),
timing side channels are not practically exploitable. For a general-purpose
signing oracle accessible from userspace, the issues below would be exploitable.

### High risk

#### `vli_mod_inv` — variable-time modular inverse

The kernel's `vli_mod_inv` computes the modular inverse of `k` using a binary
extended GCD with data-dependent branches and loop counts. The number of
iterations depends on the value of `k`, leaking nonce information through
timing. Partial nonce knowledge enables private key recovery via lattice
attacks.

#### `ecc_make_pub_key` — variable-time point multiplication

The kernel's ECC point multiplication uses a double-and-add algorithm. Older
kernels (pre-6.10) use a naive implementation with data-dependent
doublings/additions, leaking the scalar `k` through timing.

### Medium risk

#### `vli_mod_mult_slow` — conditional subtraction

The kernel's `vli_mod_mult_slow` is a shift-and-add modular multiplication.
The loop count is constant, but the conditional subtraction after each shift
(`if (result >= mod) result -= mod`) is data-dependent. This leaks
intermediate state of `d_A * r` and `k_inv * s`, exposing bits of the private
key and nonce inverse.

#### Conditional mod-n reduction branches

```c
if (vli_cmp(k, s, ndigits) <= 0) {
    vli_sub(s, s, k, ndigits);
} else {
    /* addition path */
}
```

The branch taken depends on `s` which embeds `d_A * r`, leaking information
about the private key.

### Low risk

#### RFC 6979 / HMAC-SHA

The kernel's SHA implementations are generally constant-time for the
compression function. HMAC processes fixed-size blocks. Low timing risk.

#### `ecc_swap_digits` / `memcpy` / simple copies

These process a fixed number of bytes regardless of value. Constant-time.

### Summary table

| Operation | Timing risk | Impact |
|---|---|---|
| `vli_mod_inv(k_inv, k, ...)` | Variable-time | Nonce leak, key recovery |
| `ecc_make_pub_key(k * G)` | Variable-time (pre-6.10) | Nonce leak, key recovery |
| `vli_mod_mult_slow(s, d_A, r)` | Conditional subtract | Private key leak |
| Conditional mod-n reduction | Branch on secret | Minor info leak |
| RFC 6979 / HMAC-SHA | Constant-time | Safe |
| `ecc_swap_digits` / copies | Constant-time | Safe |
