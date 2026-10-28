# nat20 (Rust)

A minimal `no_std` Rust port of the libnat20 CWT path, for linking into early
boot firmware: deterministic DICE key derivation and CWT certificate
issuance (COSE_Sign1, Ed25519), byte-compatible with the C library.

The port is added in steps; this file grows into the full documentation as
the pieces land. Run the tests from this directory:

```
cargo test -p nat20 --features soft-crypto
```
