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

#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

template <typename Field>
struct value_type {};

template <typename Field>
using value_type_t = typename value_type<Field>::type;

template <typename Field>
struct value_parser {};

template <typename Field>
using value_parser_t = typename value_parser<Field>::type;

template <typename Field>
struct field_key {};

template <typename Field>
constexpr char const* field_key_v = field_key<Field>::value;

#define DEFINE_FIELD(Name, Type, Parser, Key)                                                   \
    struct Name {};                                                                             \
    template <>                                                                                 \
    struct value_type<Name> {                                                                   \
        using type = Type;                                                                      \
    };                                                                                          \
                                                                                                \
    template <>                                                                                 \
    struct value_parser<Name> {                                                                 \
        using type = Parser;                                                                    \
        static std::optional<Type> parse(std::string const& str) { return Parser::parse(str); } \
    };                                                                                          \
                                                                                                \
    template <>                                                                                 \
    struct field_key<Name> {                                                                    \
        using type = std::string;                                                               \
        static constexpr char const* value = Key;                                               \
    };

std::optional<std::tuple<std::string, std::string>> n20_testing_next_pair(std::istream& file);

enum class ErrorCode : int {
    None,
    EndOfFile,
    UnexpectedKey,
    ParsingError,
};

constexpr char const* to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::None:
            return "None";
        case ErrorCode::EndOfFile:
            return "EndOfFile";
        case ErrorCode::UnexpectedKey:
            return "UnexpectedKey";
        case ErrorCode::ParsingError:
            return "ParsingError";
        default:
            return "UnknownError";
    }
}

template <typename... Fields>
class TestVectorReader {
   private:
    std::ifstream& file_;

   public:
    using tuple_type = std::tuple<value_type_t<Fields>...>;

    explicit TestVectorReader(std::ifstream& file) : file_(file) {}

    template <typename Field>
    value_type_t<Field> next_field(ErrorCode& errorcode) {
        if (errorcode != ErrorCode::None) {
            return {};
        }
        auto pair = n20_testing_next_pair(file_);
        if (!pair) {
            errorcode = ErrorCode::EndOfFile;  // No more pairs to read
            return {};
        }
        auto [key, value] = *pair;

        if (key != field_key_v<Field>) {
            errorcode = ErrorCode::UnexpectedKey;  // Unexpected key
            return {};
        }

        if (auto parsed = value_parser_t<Field>::parse(value)) {
            return *parsed;  // Return the parsed value
        } else {
            errorcode = ErrorCode::ParsingError;  // Parsing error
            return {};
        }
    }

    std::variant<ErrorCode, tuple_type> next_vector() {
        ErrorCode errorcode = ErrorCode::None;  // Start with a valid state

        if (sizeof...(Fields) == 0) {
            return tuple_type{};  // No fields to read
        }

        auto result = tuple_type{next_field<Fields>(errorcode)...};
        if (errorcode != ErrorCode::None) {
            return errorcode;  // Return the error code if it's not None
        }
        return result;  // Return the result of reading fields
    }

    static std::vector<tuple_type> read_all_vectors_from_file(std::string const& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open file: " + filename);
        }
        TestVectorReader reader(file);
        std::vector<tuple_type> vectors;
        while (true) {
            auto vector = reader.next_vector();
            // Check if we reached the end of the file or encountered an error
            if (auto error = std::get_if<ErrorCode>(&vector)) {
                if (*error == ErrorCode::EndOfFile) {
                    break;  // End of file
                } else if (*error != ErrorCode::None) {
                    throw std::runtime_error("Error reading vector: " +
                                             std::string(to_string(*error)));
                }
            }
            vectors.push_back(*std::get_if<tuple_type>(&vector));
        }
        return vectors;
    }
};