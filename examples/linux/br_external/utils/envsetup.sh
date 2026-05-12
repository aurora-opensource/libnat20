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

if [ ! -f ".env" ]; then
    echo ".env file not found. Please run bootstrap.sh first."
    if (return 0 2>/dev/null); then
        return 1
    else
        exit 1
    fi
fi

source .env

export NAT20CRYPTO_OVERRIDE_SRCDIR="$LIBNAT20_ROOT"
export NAT20SW_OVERRIDE_SRCDIR="$LIBNAT20_ROOT"
export NAT20DEVICE_OVERRIDE_SRCDIR="$LIBNAT20_ROOT"
export NAT20LIB_OVERRIDE_SRCDIR="$LIBNAT20_ROOT"
export LIBNAT20_OVERRIDE_SRCDIR="$LIBNAT20_ROOT"

function ensure_popd() {
    "$@"
    local rc=$?
    popd
    return $rc
}

function brbuild() {
    pushd "${LIBNAT20_BR_BUILD_DIR}/buildroot" || return 1
    ensure_popd make
}

function brrebuild() {
    pushd "${LIBNAT20_BR_BUILD_DIR}/buildroot" || return 1

    if [ "$#" -eq 0 ]; then
        echo "Usage: brrebuild <target> [<target> ...]"
        echo "Available targets:"
        echo "  all          - Rebuild all components"
        echo "  linux        - Rebuild the linux kernel"
        echo "  nat20crypto  - Rebuild the nat20crypto module"
        echo "  libnat20     - Rebuild the libnat20 library"
        echo "  nat20device  - Rebuild the nat20device module"
        echo "  nat20sw      - Rebuild the nat20sw module"
        echo "  nat20lib     - Rebuild the nat20lib library"
        popd
        return 1
    fi

    case "$1" in
        all)
            ensure_popd make linux-rebuild nat20crypto-rebuild libnat20-rebuild nat20device-rebuild nat20sw-rebuild nat20lib-rebuild all
            ;;
        *)
            ensure_popd make $1-rebuild all
            ;;
    esac
}
