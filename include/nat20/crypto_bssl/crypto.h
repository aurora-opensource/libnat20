/*
 * Copyright 2025 Aurora Operations, Inc.
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
 */

#pragma once

#include <nat20/crypto.h>
#include <nat20/error.h>

#ifdef __cplusplus
extern "C" {
#endif

n20_error_t n20_crypto_open_boringssl(n20_crypto_context_t** ctx, n20_slice_t const* cdi);

n20_error_t n20_crypto_close_boringssl(n20_crypto_context_t* ctx);

#ifdef __cplusplus
}
#endif
