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

# In CI NAT20SW_OVERRIDE_SRCDIR is set to the root of the repository,
# so that the source under test is always the current branch.
# Integrators who use this configuration should pin the version
# to a specific commit or branch to avoid breakages when the main branch changes.
NAT20SW_VERSION = origin/main
NAT20SW_SITE = https://github.com/aurora-opensource/libnat20.git
NAT20SW_SITE_METHOD = git
NAT20SW_LICENSE = Apache-2.0 OR GPL-2.0
NAT20SW_LICENSE_FILES = LICENSE-Apache-2.0.txt LICENSE-GPL-2.0.txt

NAT20SW_DEPENDENCIES += nat20lib
NAT20SW_DEPENDENCIES += nat20device
NAT20SW_DEPENDENCIES += nat20crypto
NAT20SW_MODULE_MAKE_OPTS += NAT20SW_NAT20LIB_DIR=$(NAT20LIB_DIR)/examples/linux/nat20lib
NAT20SW_MODULE_MAKE_OPTS += NAT20SW_NAT20DEVICE_DIR=$(NAT20DEVICE_DIR)/examples/linux/nat20device
NAT20SW_MODULE_MAKE_OPTS += NAT20SW_NAT20CRYPTO_DIR=$(NAT20CRYPTO_DIR)/examples/linux/nat20crypto

NAT20SW_MODULE_SUBDIRS = examples/linux/nat20sw

$(eval $(kernel-module))
$(eval $(generic-package))
