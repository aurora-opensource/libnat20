#!/bin/sh
# Copyright 2026 Aurora Operations, Inc.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
#
# This work is dual licensed.
# You may use it under Apache-2.0 or GPL-2.0 at your option.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# OR
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see
# <https://www.gnu.org/licenses/>.
#
# Builds the nat20 static library for a firmware environment:
#
#     tools/build-firmware-lib.sh <profile>
#
# Profiles are the cargo configuration files in firmware/, named
# <environment>-<arch>: u-boot-armv7 is U-Boot on 32-bit Arm. A profile
# names the target and adds the environment's flags to the target
# defaults in .cargo/config.toml; this script adds the crate features the
# environment calls for. The result is
# target/<target>/release/libnat20_rust.a.
#
# All profiles use the Monocypher backend, the smaller one, for tight
# flash budgets.
#
# core is always rebuilt from source (-Zbuild-std=core): it applies the
# profile's flags to core too, and position-independent firmware needs it
# (see the profile). RUSTC_BOOTSTRAP=1 makes the *pinned stable* toolchain
# (rust-toolchain.toml) accept the unstable -Zbuild-std machinery — the
# same technique the Linux kernel uses. The usual caveat applies: these
# flags carry no stability guarantee, so their behavior is only locked by
# the toolchain pin; re-verify on every toolchain bump (along with the
# size measurement and the constant-time disassembly spot-check, see
# SIZE.md and README.md).
#
# Default build: plain `abort` panic strategy.
#
# SLIM=1 build: additionally strips the panic-message formatting
# machinery (several KiB) via -Cpanic=immediate-abort. Panic sites then
# compile to a trap instruction (udf) and nothing is printed — use only
# if the size budget forces it.
#
# Requires: rustup (for the pinned toolchain + rust-src), and the target's
# C cross compiler for the vendored Monocypher sources (arm-none-eabi-gcc
# for armv7).

set -eu

profile=${1:-}
case "$profile" in
u-boot-armv7)
	# U-Boot provides putc() and hang(), so panics print
	# "rust: panicked at <file>:<line>: <msg>" on its console.
	features=mono-crypto,panic-putc-hang
	;;
*)
	echo "usage: $0 <profile>   (profiles: u-boot-armv7)" >&2
	exit 2
	;;
esac

cd "$(dirname "$0")/.."

rustup component add rust-src >/dev/null 2>&1 || true

config="firmware/$profile.toml"
target=$(sed -n 's/^target = "\(.*\)"$/\1/p' "$config")

set -- --config "$config"
if [ "${SLIM:-0}" = "1" ]; then
	# Added to the target's rustflags from the configuration files.
	set -- "$@" --config "target.$target.rustflags = [\"-Zunstable-options\", \"-Cpanic=immediate-abort\"]"
fi

RUSTC_BOOTSTRAP=1 exec cargo build "$@" -Zbuild-std=core --release \
	--target "$target" -p nat20-ffi \
	--no-default-features --features "$features"
