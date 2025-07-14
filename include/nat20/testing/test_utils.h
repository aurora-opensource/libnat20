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

/** @file */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Generate a hex dump from a byte vector.
 *
 * This function converts a byte vector into a human readable hexadecimal string representation.
 * It is provided for testing and debugging purposes only and should not be used in production code.
 * The output is formatted as two groups of 8 bytes per line.
 *
 * @param data The byte vector to convert.
 * @return std::string A string representation of the hex dump.
 */
std::string hexdump(std::vector<uint8_t> const& data);
/**
 * @brief Convert a byte vector to a hexadecimal string.
 *
 * This function converts a byte vector into a hexadecimal string representation.
 * It is provided for testing and debugging purposes only and should not be used in production code.
 * This function prints a continuous string of hexadecimal digits without any formatting or spaces.
 *
 * @param data The byte vector to convert.
 * @return std::string A string representation of the hexadecimal data.
 */
std::string hex(std::vector<uint8_t> const& data);
