# Contributing to libnat20

Thank you for your interest in libnat20: a C DICE library, by Aurora. We welcome your contributions!
Here are some guidelines to help.

## Contributor License Agreement (“CLA”)

Contributions to this project must be accompanied by a signed CLA. You (or your employer) retain the
copyright to your contribution; the CLA merely gives us permission to use and redistribute your
contribution as part of the project. You'll automatically be prompted to sign the CLA the first time
you create a pull request.  You only need to sign it once.

> NOTE: If you're planning to make contributions on behalf of your employer or another entity,
> please sign the [corporate
> CLA](https://docs.google.com/forms/d/e/1FAIpQLSdxFUhXe8cy5UMuu4cBQH_SPam0aQ5Yrxw0W8CHIpt0VhPV3g/viewform).
> Your employer's GitHub organization will be allowlisted after you do.

## Reporting Issues

We also have an [issues page](https://github.com/aurora-opensource/libnat20/issues) for tracking problems
and future work. If you have a bug report or feature request, check the existing issues to see if
it’s been posted, and file a new one if it hasn’t. While we can’t promise timely resolution, we will
do our best to respond quickly so you know you’ve been heard, and where we stand on the issue.

## License

By contributing to libnat20, you agree to be bound by the terms of the applicable CLA and that your
contributions will be licensed under the LICENSE file in the root directory of this source tree.

## Guidelines for Pull Requests

Pull requests (PRs) can involve a significant amount of work, both to
write and to review.  Follow these guidelines to minimize the chance of wasting that work, and
maximize the chance of delivering its value!

- First, **check the [issues](https://github.com/aurora-opensource/libnat20/issues)**.  If your change
  isn't covered by any existing issue, it's a good idea to file a new one, so you can make sure the
  change would be welcomed.

- Make **small PRs**.  Each PR should address **one idea only**.  This means some issues may take
  multiple PRs to resolve; this is normal and expected.

- Each PR becomes one single commit when it lands to main, so follow the rules for [good commit
  messages](https://cbea.ms/git-commit/)!  In particular, note that the PR title becomes the commit
  title, and the PR summary becomes the commit body.

- All remote builds must pass before any PR is landed.

See our [README](README.md) to get started with building and testing the code and documentation!

### Style guide

Libnat20 loosely follows the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html).
However, there are clear distinctions between the core library, which is written in pure C and
supporting code such as the test suite which may use C++ code and library dependencies that would
not be allowed in the core library.

In matters of formatting, readability and consistency takes precedence over all other considerations.
The `.clang-format` file is authoritative, but exceptions are permitted at the discretion of the
maintainers if readability is significantly impaired otherwise.

Also, prefix cv qualifiers are an abomination and are disallowed, no exceptions!

#### The core library

The core library is written in pure C11. However, it must comply with MISRA C++ 2023, and
it must be accepted by a C++17 compiler, so beware of using C++ key words of identifiers.

The following rules take precedence of the Google C++ Style Guide.

1. The `.clang-format` file in the repository supersedes the Google style guide in all matters of
   code formatting.
2. Prefix cv qualifiers are not allowed.
3. Use `#pragma once` instead of [`#define`
   guards](https://google.github.io/styleguide/cppguide.html#The__define_Guard).
4. All symbols use `lower_snake_case`.
5. All external symbols have the prefix `n20_`.
6. All macro names use `UPPER_SNAKE_CASE`.
7. All macro names that are part of the public API have the prefix `N20_`.
8. All type definitions follow the symbol rules and have the suffix `_t`.
9. All enum variants follow the symbol rules and have the suffix `_e`.
10. All struct and enum names follow the symbol rules and have the suffix `_s`.

#### The test suite

The test suite allows for using C++ and some library dependencies which would not be allowed in the
core library.

Coverage and best practice usage of the APIs takes precedence. Still, the code base
shall be kept readable and consistent in style. The `.clang-format` files is authoritative in
questions of formatting and the C++ Style Guide shall be used as a tie breaker if
discussions around style shall arise.

The following rules take precedence though:

1. The `.clang-format` file in the repository supersedes the Google style guide in all matters of
   code formatting.
2. Prefix cv qualifiers are not allowed.
3. Use `#pragma once` instead of [`#define`
   guards](https://google.github.io/styleguide/cppguide.html#The__define_Guard).
