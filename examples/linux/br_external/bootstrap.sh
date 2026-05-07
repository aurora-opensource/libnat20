#!/bin/bash

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

PROJECT="$1"
LIBNAT20_BR_BUILD_DIR="$2"
LIBNAT20_ROOT="${3:-$(pwd)}"
LIBNAT20_ROOT="$(readlink -f "${LIBNAT20_ROOT}")"

usage() {
	echo "Usage: bootstrap.sh <project> <buildroot_build_dir> <libnat20_root>"
	echo
	echo "This script bootstraps the Buildroot environment for the Dice project."
	echo
	echo "This script may be run from any directory, as long as the libnat20 root"
	echo "directory is specified correctly. The first parameter specifies the project."
	echo "See valid options below."
	echo "The second parameter specifies the out of tree Buildroot build directory."
	echo "The third parameter specifies the libnat20 root directory."
	echo "It uses the current working directory by default."
	echo
	echo "Available projects:"
	echo "  qemu       - Setup Buildroot for the QEMU-based Dice emulator"
}

case "$PROJECT" in
	qemu)
		;;
	*)
		usage
		exit 0
		;;
esac

if [ -z "${LIBNAT20_BR_BUILD_DIR}" ]; then
	echo "Error: buildroot_build_dir must be specified."
	echo
	usage
	exit 1
fi

LIBNAT20_BR_BUILD_DIR="$(readlink -f "${LIBNAT20_BR_BUILD_DIR}")"

case "${LIBNAT20_BR_BUILD_DIR}" in
	"${LIBNAT20_ROOT}"|"${LIBNAT20_ROOT}"/*)
		echo "Error: buildroot_build_dir must not be inside libnat20_root."
		echo "  buildroot_build_dir: ${LIBNAT20_BR_BUILD_DIR}"
		echo "  libnat20_root:       ${LIBNAT20_ROOT}"
		exit 1
		;;
esac

if [ -e "${LIBNAT20_BR_BUILD_DIR}" ]; then
	echo "Buildroot build directory ${LIBNAT20_BR_BUILD_DIR} already exists."
	exit 1
fi

if [ ! -d "${LIBNAT20_ROOT}/examples/linux/br_external" ]; then
	echo "Directory ${LIBNAT20_ROOT}/examples/linux/br_external does not exist."
	echo "Please make sure \"${LIBNAT20_ROOT}\" points to the libnat20 root directory."
	exit 1
fi

mkdir -p "${LIBNAT20_BR_BUILD_DIR}"
pushd ${LIBNAT20_BR_BUILD_DIR}

echo "LIBNAT20_BR_BUILD_DIR=${LIBNAT20_BR_BUILD_DIR}" | tee .env
echo "LIBNAT20_ROOT=${LIBNAT20_ROOT}" | tee -a .env

cp ${LIBNAT20_ROOT}/examples/linux/br_external/utils/envsetup.sh ./

# Checkout buildroot
git clone --depth 1 --branch "2025.08.1" https://gitlab.com/buildroot.org/buildroot.git

# Install the buildroot config
case "$PROJECT" in
	qemu)
		cp ${LIBNAT20_ROOT}/examples/linux/br_external/configs/qemu_br_defconfig buildroot/.config
		cp ${LIBNAT20_ROOT}/examples/linux/br_external/run-qemu.sh ./
		;;
	esac

pushd buildroot

make BR2_EXTERNAL=${LIBNAT20_ROOT}/examples/linux/br_external oldconfig

popd
popd

echo
echo "Now enter buildroot and run make:"
echo "  $ cd ${LIBNAT20_BR_BUILD_DIR}/buildroot"
echo '  $ make'
