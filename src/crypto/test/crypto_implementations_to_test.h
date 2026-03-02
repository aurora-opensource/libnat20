/*
 * Copyright 2025 Aurora Operations, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
 *
 * This work is dual licensed.
 * You may use it under Apache-2.0 or GPL-2.0 at your option.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * OR
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <gtest/gtest.h>

// To add a crypto implementation to the list of test
// create a class that implements the following static
// member functions.
// struct MyCryptoImplementation {
//     static n20_error_t open(n20_crypto_context_t** ctx);
//     static n20_error_t close(n20_crypto_context_t* ctx);
// };
// Include it here and then add the class name to the types list below.

#ifdef N20_CONFIG_ENABLE_CRYPTO_TEST_IMPL

#ifdef N20_CONFIG_WITH_BSSL
#include "crypto_boringssl.h"
#endif

#include "crypto_nat20.h"

using FullCryptoImplementationsToTest = testing::Types<
// Add crypto implementations to the list in order to run
// the crypto test against them.

#ifdef N20_CONFIG_WITH_BSSL
    CryptoImplBSSL
#endif

    // End of list.
    >;

using DigestOnlyCryptoImplementationsToTest = testing::Types<CryptoImplNat20>;

#endif

template <typename T, typename U>
struct ConcatenateTestLists {};

template <typename... T1, typename... T2>
struct ConcatenateTestLists<testing::Types<T1...>, testing::Types<T2...>> {
    using type = testing::Types<T1..., T2...>;
};
