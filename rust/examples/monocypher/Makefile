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

# Builds and runs the host test of the example backend (test.c) against a
# host build of libnat20_rust.a with the built-in backend, for comparison.
#
#     make test

RUST := ../..
LIB := $(RUST)/target/release/libnat20_rust.a
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS += -I$(RUST)/nat20-ffi/include -Ithird_party/monocypher -DWITH_SOFT_CRYPTO

SRCS := test.c n20r_monocypher.c third_party/monocypher/monocypher.c \
	third_party/monocypher/monocypher-ed25519.c

.PHONY: test lib clean

test: n20r_monocypher_test
	./n20r_monocypher_test

lib:
	cd $(RUST) && cargo build --release -p nat20-ffi --features soft-crypto

$(LIB): lib

n20r_monocypher_test: $(SRCS) n20r_monocypher.h $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRCS) $(LIB)

clean:
	rm -f n20r_monocypher_test
