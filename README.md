# The libnat20 DICE library {#mainpage}

Libnat20 is a free standing DICE library implementing the protocols
for OpenDICE, the TCG DICE Attestation Architecture, and the TCG DICE
Layering architecture.

It is aimed at restricted runtime environments as can be found in secure
elements, boot loaders and operating system kernels.

The core library is written in C11 for ease of integration in a variety of code
bases. The code base shall be compliant with MISRA C++ 2023 and must be
accepted by a C++17 compiler. The core library delegates memory allocation
to the user and can operate entirely without heap allocation if necessary.
The core library also delegates cryptographic operations to the user by
means of an interface that users are expected to provide. A reference
implementation of this interface based on boring ssl is provided
and can be compiled optionally.

## Contributing!

The project is licensed under Apache 2 license and contributers are expected
to sign a CLA before contributions can be considered.
Please read [CONTRIBUTING.md](CONTRIBUTING.md) carefully for details on
the CLA and code style.

## Getting started

#### TLDR

```sh
cmake -B . -DNAT20_WITH_TESTS=ON -DNAT20_WITH_DOCS=ON
make -j
make nat20_docs
make test
```

This library uses cmake as primary build system. And it is set up to
generate a `compile_commands.json` for the benefit of `clangd` based IDE
extensions.

The preferred development platform is a linux distribution such as Ubuntu
or similar. The core library can be build with minimal dependencies:

```sh
sudo apt install build-essential cmake
```

For generating the documentation doxygen and the graphviz package need to
be installed.

```sh
sudo apt install doxygen graphviz
```

### Building

By default only the core library is built.

```sh
cmake --build .
make
```

### Testing

To enable the test suite set the cmake variable `NAT20_WITH_TESTS` to `ON`, then
build and run the test suite as follows:

```sh
cmake --build . -DNAT20_WITH_TESTS=ON
make
make test
```

### Documentation

Libnat20 uses doxygen for the generation of the API documentation. To enable
the documentation target `nat20_docs` set the cmake variable `NAT20_WITH_DOCS` to `ON`,
then build the documentation as follows:

```sh
cmake --build . -DNAT20_WITH_DOCS=ON
make nat20_docs
```

Open the documentation by pointing your browser to `html/index.html` in your
build directory.

## API Reference

The API references is generated from the main branch using doxygen and deployed
as [LibNat20 Github Pages](https://aurora-opensource.github.io/libnat20).
