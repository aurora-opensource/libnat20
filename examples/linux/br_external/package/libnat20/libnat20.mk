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

# In CI LIBNAT20_OVERRIDE_SRCDIR is set to the root of the repository,
# so that the source under test is always the current branch.
# Integrators who use this configuration should pin the version
# to a specific commit or branch to avoid breakages when the main branch changes.
LIBNAT20_VERSION = origin/main
LIBNAT20_SITE = https://github.com/aurora-opensource/libnat20.git
LIBNAT20_SITE_METHOD = git
LIBNAT20_LICENSE = Apache-2.0 OR GPL-2.0
LIBNAT20_LICENSE_FILES = LICENSE-Apache-2.0.txt LICENSE-GPL-2.0.txt

LIBNAT20_INSTALL_STAGING = YES
LIBNAT20_INSTALL_TARGET = NO

$(eval $(cmake-package))
