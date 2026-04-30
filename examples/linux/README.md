# Linux DICE Example

This directory contains a set of Linux kernel modules and a userspace CLI tool
that together implement a software DICE node using libnat20.

## Architecture

The example is structured as four kernel modules with the following dependency
chain:

```
nat20sw  ──►  nat20crypto  ──►  nat20lib
               nat20device  ──►
```

### nat20lib

A kernel module wrapper around the core libnat20 C library. It compiles all
core library sources (CBOR, COSE, CWT, X.509, HKDF, service dispatch) into a
single `.ko` and re-exports their symbols via `EXPORT_SYMBOL()` so that other
kernel modules can use them.

### nat20crypto

Implements the libnat20 crypto interface (`n20_crypto_context_t`) using the
Linux kernel's crypto API. Provides ECDSA signing (P-256, P-384), HKDF key
derivation, and SHA-2 hashing — all in kernel space.

### nat20device

A generic character device framework for DICE services. On load it allocates
the `nat20` device class. Backend modules (like `nat20sw`) register via
`nat20device_register_driver()`, which creates:

- `/dev/nat20<N>` — a character device for DICE service requests (write a CBOR
  request, read the CBOR response).
- `/sys/kernel/security/nat20<N>/dice_chain` — a read-only securityfs file
  exposing the boot-time DICE certificate chain.

### nat20sw

A concrete software DICE node that wires `nat20lib`, `nat20crypto`, and
`nat20device` together. On load it derives a UDS from a hardcoded passphrase
(for demonstration purposes only), issues a self-signed X.509 certificate, and
registers itself with the `nat20device` framework.

### nat20cli

A userspace command-line tool that communicates with the DICE service via
`/dev/nat200`. It can issue CDI certificates, ECA certificates, and advance
the DICE layer via the `promote` command.

## The `dice_chain` securityfs interface

Each registered nat20device driver instance exposes a `dice_chain` file at
`/sys/kernel/security/nat20<N>/dice_chain`. This file contains the DICE
certificate chain constructed during bootup, encoded as a CBOR
indefinite-length array.

### Encoding

The file contains a single CBOR indefinite-length array (`0x9f ... 0xff`).
Each element in the array is one of the following CBOR-tagged values:

| CBOR tag | Content | Description |
|----------|---------|-------------|
| `#6.80150(bstr)` | DER-encoded X.509 certificate | An X.509 certificate, typically with the Open DICE Input extension (OID `1.3.6.1.4.1.11129.2.1.24`). |
| `#6.18(COSE_Sign1)` | COSE_Sign1 with CWT payload | A COSE certificate as specified by the Open DICE profile or a similar custom DICE profile. |
| `#8.80152(COSE_Key)` | COSE_Key | A public key. |

### Ordering and semantics

- The first element represents the root device identity key. It may be a
  self-signed certificate, a CA-signed certificate, or a bare public key
  (`#8.80152`).
- A benign implementation orders the remaining certificates from root to leaf.
- The chain only contains certificates generated during bootup. Userspace is
  responsible for managing additional CDI certificates issued via the
  `/dev/nat20<N>` character device.

## Building with Buildroot

The `br_external/` directory provides a Buildroot external tree for building
all components targeting a QEMU x86_64 virtual machine.

```sh
# Bootstrap the Buildroot environment (build directory must be outside the repo)
BUILDROOT_DIR=/path/to/buildroot.build
examples/linux/br_external/bootstrap.sh qemu $BUILDROOT_DIR

# Build everything
cd $BUILDROOT_DIR/buildroot
make
```

### Local development
The bootstrap script installs a file `envsetup.sh` in `$BUILDROOT_DIR`
which sets the `*_OVERRIDE_SRCDIR`s for all of the packages nat20* etc.,
and defines helper functions for rebuilding and running the result in
qemu.

```
# Source the environment
cd $BUILDROOT_DIR
. envsetup.sh

# Rebuild a package and the rootfs, this is equivalent to
# pushd $BUILDROOT_DIR/buildroot
# make nat20sw-rebuild all
# popd
brrebuild nat20sw

# Rebuild all packages and the rootfs
brrebuild all

# Run the resulting rootfs and kernel in qemu
run-qemu

# Run the nat20cli test in qemu and shut down the emulator
run-nat20cli-test

# Run the nat20test integration test in qemu and sht down the emulator
run-nat20test-test
```

### Caveat - `bootstrap.sh`
The bootstrap script is usefull for setting up the development environment
once, but it cannot keep the build root environment in sync with the upstream
repository. When pulling the upstream repository and changes where made to
`envsetup.sh`, `bootstrap.sh`, or the buildroot config, it may be necessary
to bootstrap a new environment. A savvy user may track the changes and manually
update the environment to save 30 minutes rebuilding the build root environment.