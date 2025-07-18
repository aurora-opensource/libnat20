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

#include <nat20/testing/test_utils.h>

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <vector>

std::string hexdump(std::vector<uint8_t> const& data) {
    if (data.empty()) {
        return "";
    }

    std::stringstream s;

    s << std::hex << std::setw(2) << std::setfill('0') << (int)data[0];

    for (size_t i = 1; i < data.size(); ++i) {
        if ((i & 0x0F) == 0) {
            s << "\n";
        } else if ((i & 0x07) == 0) {
            s << "  ";
        } else {
            s << " ";
        }
        s << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s.str();
}

std::string hex(std::vector<uint8_t> const& data) {
    std::stringstream s;
    s << std::hex;
    for (size_t i = 0; i < data.size(); ++i) {
        s << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s.str();
}
