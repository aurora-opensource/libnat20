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

#include <iomanip>
#include <sstream>
#include <vector>
#include <cstdint>

std::string hexdump(std::vector<uint8_t> const& data) {
    std::stringstream s;
    int i;
    for (i = 0; i < data.size() - 1; ++i) {
        s << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i % 16 == 15) {
            s << "\n";
        } else if (i % 16 == 7) {
            s << "  ";
        } else {
            s << " ";
        }
    }
    if (i < data.size()) {
        s << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s.str();
}

std::string hex(std::vector<uint8_t> const &data) {
    std::stringstream s;
    int i;
    for (i = 0; i < data.size(); ++i) {
        s << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s.str();
}
