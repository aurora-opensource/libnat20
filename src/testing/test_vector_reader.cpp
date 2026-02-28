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

#include <istream>
#include <optional>
#include <string>
#include <tuple>

std::optional<std::tuple<std::string, std::string>> trim_and_remove_comments(std::string str) {
    auto trim = [](std::string str) -> std::string {
        auto begin = str.find_first_not_of(" \t");  // Remove leading whitespace
        if (begin == std::string::npos) {
            return "";  // Empty line
        }
        auto end = str.find_last_not_of(" \t");  // Remove trailing whitespace
        if (end == std::string::npos) {
            return "";  // Empty line after trimming
        }
        return str.substr(begin, end - begin + 1);  // Trim leading and trailing whitespace
    };

    auto end = str.find_first_of("#");  // Remove comments
    if (end != std::string::npos) {
        str.erase(end);
    }
    auto colon_pos = str.find(':');  // Find the colon
    if (colon_pos == std::string::npos) {
        return std::nullopt;  // No colon found, invalid line
    }

    return std::make_tuple(trim(str.substr(0, colon_pos)), trim(str.substr(colon_pos + 1)));
};

std::optional<std::tuple<std::string, std::string>> n20_testing_next_pair(std::istream& file) {
    std::string line;
    while (std::getline(file, line)) {
        auto result = trim_and_remove_comments(line);
        if (result) {
            return result;
        }
    }
    return std::nullopt;  // End of file or no valid line found
}
