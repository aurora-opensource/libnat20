/*
 * Copyright 2026 Aurora Operations, Inc.
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

/** @file Homogeneous Endian definitions for various environments. */

#pragma once

#ifdef __KERNEL__
#include <asm/byteorder.h>
#ifdef __LITTLE_ENDIAN
#define LITTLE_ENDIAN __LITTLE_ENDIAN
#define BIG_ENDIAN (~(__LITTLE_ENDIAN))
#define BYTE_ORDER __LITTLE_ENDIAN
#else
#define LITTLE_ENDIAN (~(__BIG_ENDIAN))
#define BIG_ENDIAN __BIG_ENDIAN
#define BYTE_ORDER __BIG_ENDIAN
#endif
#else
#include <endian.h>
#endif
