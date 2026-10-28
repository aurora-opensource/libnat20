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
# Checks on the target that the secret-handling entry points leave no
# secrets on the stack, and measures how deep they go (to size
# N20R_STACK_SCRUB_SIZE in nat20-ffi).
#
#     tools/stack-probe.sh [profile]
#
# For each crypto backend, builds the static library for armv7 (Thumb-2,
# opt-level z, fat LTO), with the flags of the firmware profile from
# firmware/ if one is given, as tools/build-firmware-lib.sh does. Links it
# into tools/stack-probe/probe.c and runs that under qemu-system-arm. It runs
# twice: with the stack scrub, where nothing may survive below the entry
# point's own frame, and without it (--cfg nat20_no_stack_scrub), where
# something must -- otherwise the probe could not see a leak and its pass
# would mean nothing. The depths the second run prints are what the scrub
# has to cover.
#
# Needs qemu-system-arm, arm-none-eabi-gcc and python3.

set -eu

profile=${1:-}

cd "$(dirname "$0")/.."

set --
if [ -n "$profile" ]; then
	set -- --config "firmware/$profile.toml"
fi

rustup component add rust-src >/dev/null 2>&1 || true

out=target/stack-probe${profile:+-$profile}
mkdir -p "$out"
python3 tools/stack-probe/gen_secrets.py >"$out/probe_secrets.h"

CFLAGS='-mcpu=cortex-a7 -mthumb -mfloat-abi=soft -mno-unaligned-access -Os
	-ffreestanding -fno-builtin -fno-tree-loop-distribute-patterns -Wall'

status=0
for backend in mono-crypto soft-crypto; do
	for scrub in on off; do
		variant="$backend-scrub-$scrub"
		noscrub=
		# Added to the target's rustflags from the configuration files.
		[ "$scrub" = off ] && noscrub='target.armv7a-none-eabi.rustflags = ["--cfg", "nat20_no_stack_scrub"]'

		# RUSTC_BOOTSTRAP=1 for a profile's [unstable] build-std.
		RUSTC_BOOTSTRAP=1 CARGO_TARGET_DIR="$out/$variant" \
			cargo build -q "$@" ${noscrub:+--config "$noscrub"} --release \
			--target armv7a-none-eabi -p nat20-ffi \
			--no-default-features --features "$backend,panic-loop"

		# shellcheck disable=SC2086
		arm-none-eabi-gcc $CFLAGS -nostdlib -ffunction-sections -Wl,--gc-sections \
			-Wl,--no-enum-size-warning -Wl,--no-wchar-size-warning \
			-T tools/stack-probe/probe.ld \
			-I nat20-ffi/include -I "$out" \
			tools/stack-probe/start.S tools/stack-probe/probe.c \
			support/aeabi_mem.c \
			"$out/$variant/armv7a-none-eabi/release/libnat20_rust.a" \
			-lgcc -o "$out/$variant.elf"

		echo "== $variant"
		if timeout 120 qemu-system-arm -M virt -cpu cortex-a7 -m 64M \
			-nographic -monitor none -serial none \
			-semihosting-config enable=on,target=native \
			-kernel "$out/$variant.elf"; then
			result=pass
		else
			result=fail
		fi
		case "$scrub-$result" in
		on-fail)
			echo "FAIL: left on the stack despite the scrub"
			status=1
			;;
		off-pass)
			echo "FAIL: nothing left even without the scrub; the probe is blind"
			status=1
			;;
		esac
	done
done
exit $status
