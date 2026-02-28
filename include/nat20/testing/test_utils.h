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

/**
 * @brief Convert a byte vector to a C-style array string.
 *
 * This is a utility function for generating a C-style array representation of a byte vector.
 *
 * @param data The byte vector to convert.
 * @return std::string A string representation of the byte vector as a C-style array.
 */
std::string hex_as_c_array(std::vector<uint8_t> const& data);

/**
 * @brief Convert two byte vectors to a side-by-side hex dump string.
 *
 * This function generates a side-by-side hex dump comparison of two byte vectors.
 * It is useful for visually comparing the contents of two byte arrays in a human-readable format.
 * It writes the output in three columns: the first column contains the
 * offset in hexadecimal, the second column contains the hex dump of the first byte vector,
 * and the third column contains the hex dump of the second byte vector.
 * The second and third columns are labeled with the provided labels.
 *
 * @param label_a Label for the first byte vector.
 * @param a First byte vector to compare.
 * @param label_b Label for the second byte vector.
 * @param b Second byte vector to compare.
 * @return std::string A string representation of the side-by-side hex dump.
 */
std::string hexdump_side_by_side(std::string const& label_a,
                                 std::vector<uint8_t> const& a,
                                 std::string const& label_b,
                                 std::vector<uint8_t> const& b);
