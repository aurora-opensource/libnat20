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

cmake_minimum_required(VERSION 3.22)

project(NAT20CLI VERSION 0.0.1 LANGUAGES C)

# The C standard shall be C11.
set(CMAKE_C_STANDARD 11)

# CMake shall generate a compile_commands.json file for
# the benefit of clangd based IDE support.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

###################################################################################################
# The following section defines all the groups of source files.
# All files must be specified explicitly; no globbing or other generation is allowed.

set(NAT20CLI_SOURCES
    # Add the core library source files here.
    src/main.c
)

###################################################################################################

###################################################################################################
# The nat20_service library is also part of the product of this project.
# It will always be compiled.
add_executable(nat20cli)

find_package(LibNat20 REQUIRED)

target_sources(nat20cli
	PRIVATE ${NAT20CLI_SOURCES}
)

target_link_libraries(nat20cli PRIVATE LibNat20::nat20 LibNat20::nat20_service LibNat20::nat20_crypto_nat20)

target_compile_options(nat20cli
    PRIVATE -pedantic
    PRIVATE -Wall
    PRIVATE -Wextra
    PRIVATE -Werror
)

install(TARGETS nat20cli RUNTIME DESTINATION bin)
install(PROGRAMS nat20cli_test.sh DESTINATION bin)
install(PROGRAMS nat20cli_qemu_init.sh DESTINATION bin)
install(FILES openssl_dice.cnf DESTINATION bin)

###################################################################################################
