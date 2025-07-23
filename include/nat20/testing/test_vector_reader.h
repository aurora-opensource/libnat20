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

#include <charconv>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

/**
 * @brief Type trait to get the value type of a field.
 *
 * This trait extracts the value type from a field type.
 */
template <typename Field>
struct value_type {};

/**
 * @brief Alias for `value_type` that extracts the value type from a field type.
 */
template <typename Field>
using value_type_t = typename value_type<Field>::type;

/**
 * @brief Type trait to get the parser type of a field.
 *
 * This trait extracts the parser type from a field type.
 */
template <typename Field>
struct value_parser {};

/**
 * @brief Alias for `value_parser` that extracts the parser type from a field type.
 *
 * This alias provides a convenient way to access the parser type associated with a field.
 */
template <typename Field>
using value_parser_t = typename value_parser<Field>::type;

/**
 * @brief Type trait to get the key string of a field.
 *
 * This trait extracts the key associated with a field type.
 */
template <typename Field>
struct field_key {};

/**
 * @brief Alias for `field_key` that extracts the key string from a field type.
 */
template <typename Field>
constexpr char const* field_key_v = field_key<Field>::value;

/**
 * @brief Macro to define a field in the test vector reader.
 *
 * This macro simplifies the creation of field types by creating the necessary
 * specializations for `value_type`, `value_parser`, and `field_key` from the provided
 * parameters.
 */
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

/**
 * @brief Read the next key-value pair from the test vector file.
 *
 * This function reads a line from the input file stream, splits it into a key and a value,
 * and returns them as a tuple.
 *
 * @param file The input file stream to read from.
 * @return std::optional<std::tuple<std::string, std::string>> The next key-value pair, or
 * std::nullopt if reading fails.
 */
std::optional<std::tuple<std::string, std::string>> n20_testing_next_pair(std::istream& file);

/**
 * @brief Error codes for the test vector reader.
 *
 * These error codes represent various errors that can occur while reading test vectors.
 */
enum class ErrorCode : int {
    None,
    EndOfFile,
    UnexpectedKey,
    ParsingError,
};

/**
 * @brief Converts an ErrorCode to a string representation.
 *
 * This function provides a string representation for each error code.
 *
 * @param code The error code to convert.
 * @return A string representation of the error code.
 */
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

/**
 * @brief A parser for string values.
 *
 * This parser simply returns the input string as is.
 */
struct string_parser {
    /**
     * @brief Parses a string value.
     *
     * @param str The input string to parse.
     * @return std::optional<std::string> The parsed string, or std::nullopt if parsing fails.
     */
    static std::optional<std::string> parse(std::string const& str) {
        return str;  // Simply return the string as is
    }
};

/**
 * @brief A parser for hexadecimal strings.
 *
 * This parser converts a hexadecimal string into a vector of bytes.
 * The string must have an even length, and each pair of characters
 * represents a byte in hexadecimal format.
 */
struct hex_string_parser {
    /**
     * @brief Parses a hexadecimal string.
     *
     * @param str The input string to parse.
     * @return std::optional<std::vector<uint8_t>> The parsed bytes, or std::nullopt if parsing
     * fails.
     */
    static std::optional<std::vector<uint8_t>> parse(std::string const& str) {
        if (str.empty()) {
            return std::vector<uint8_t>{};  // Return empty vector for empty string
        }
        if (str.size() % 2 != 0) {
            return std::nullopt;  // Invalid hex string length
        }
        std::vector<uint8_t> bytes;
        bytes.reserve(str.size() / 2);
        for (size_t i = 0; i < str.size(); i += 2) {
            std::string byte_str = str.substr(i, 2);
            uint8_t byte_value;
            auto [ptr, ec] =
                std::from_chars(byte_str.data(), byte_str.data() + byte_str.size(), byte_value, 16);
            if (ec != std::errc()) {
                return std::nullopt;  // Invalid hex string
            }
            bytes.push_back(byte_value);
        }
        return bytes;  // Return the parsed bytes
    }
};

/**
 * @brief A reader for test vectors.
 *
 * This class reads test vectors from a file and provides methods to read specific fields.
 * The format of the file is given by the Fields template parameters, which define the expected
 * fields in each test vector. A field is formatted as a key-value pair of the form "key: value",
 * where the key is defined by `field_key_v<Field>`. The value is parsed using the
 * `value_parser_t<Field>` for each field type. Field types are defined using the `DEFINE_FIELD`
 * macro, which associates a field name with its type and parser.
 *
 * ## Example Usage
 * This example shows how to define fields and use the `TestVectorReader<Name, Vec>` to read test
 * vectors from a file with one or more test vectors of the form:
 * ```
 * Name: TestName
 * Vec: 0102030405060708090a0b0c0d0e0f
 * ```
 * Note that each field must appear in the order that they are defined in the parameter pack
 * `Fields` of the `TestVectorReader` class.
 *
 * ### Defining Fields
 * To define a field, use the `DEFINE_FIELD` macro:
 * ```cpp
 * DEFINE_FIELD(FieldName, FieldType, ParserType, Key)
 * ```
 * - `FieldName`: The name of the field (used as a type).
 * - `FieldType`: The C/C++ type of the field (e.g., `std::string`, `n20_crypto_digest_algorithm_t`,
 *    etc.).
 * - `ParserType`: A parser class that implements a static `parse` method to convert a string to the
 *   field type.
 * - `Key`: The key used in the test vector file to identify this field (e.g., "Name", "Alg", "Msg",
 * etc.).
 *
 * The `ParserType` should implement a static method `parse` that takes a string and returns an
 * `std::optional<FieldType>`. If the parsing fails, it should return `std::nullopt`.
 * Example parsers can be defined as follows:
 * ```cpp
 * struct string_parser {
 *     static std::optional<std::string> parse(std::string const& str) {
 *         return str;
 *     }
 * };
 * ```
 * A simple test vector parser with each test consisting of a test name and vector of bytes
 * can be defined as follows:
 * ```cpp
 * // Define the fields Name and Vec.
 * DEFINE_FIELD(Name, std::string, string_parser, "Name")
 * DEFINE_FIELD(Vec, std::vector<uint8_t>, hex_string_parser, "Vec")
 * ```
 *
 * The `string_parser` and `hex_string_parser` are provided by this implementation for convenience,
 * but more application-specific parsers can be defined as needed.
 *
 * ### Using the TestVectorReader
 * After defining the fields, you can use the `TestVectorReader` to read test vectors from a file.
 * The `TestVectorReader` is a template class that takes the defined fields as template parameters
 * and provides methods to read the test vectors.
 * Here is an example of how to use it:
 * ```cpp
 * #include <nat20/testing/test_vector_reader.h>
 * // Specialize and instantiate the TestVectorReader with the defined fields.
 * // The field names correspond to the first argument of the DEFINE_FIELD macro.
 * // The tuple_type will be a std::tuple<std::string, std::vector<uint8_t>>.
 * using TestVectorReader = TestVectorReader<Name, Vec>;
 * // Read all vectors from a file at static initialization time.
 * std::vector<TestVectorReader::tuple_type> test_vectors =
 * TestVectorReader::read_all_vectors_from_file("path/to/test_vectors.txt");
 * ```
 *
 * ### Using the test vectors in tests
 * The `test_vectors` variable can be exported in in a header file while hiding the reader
 * implementation.
 * ```cpp
 * extern std::vector<std::tuple<std::string, std::vector<uint8_t>>> test_vectors;
 * ```
 * A test can now iterate the test vectors directly or in parameterized gtests using
 * `testing::ValuesIn(test_vectors)`. See `TEST_P` and `INSTANTIATE_TEST_SUITE_P` in the Google Test
 * documentation for more details on parameterized tests.
 *
 * @tparam Fields The fields to read from the test vector.
 */
template <typename... Fields>
class TestVectorReader {
   private:
    std::ifstream& file_;

   public:
    /**
     * @brief The type of the tuple returned by the reader.
     *
     * This type is a std::tuple containing the values read from each test vector
     * in the test vector file.
     */
    using tuple_type = std::tuple<value_type_t<Fields>...>;

    /**
     * @brief Read all test vectors from a file.
     *
     * This function reads all test vectors from the specified file and returns
     * them as a vector of tuples.
     *
     * @param filename The name of the file to read the test vectors from.
     * @return std::vector<tuple_type> A vector of tuples, each containing the
     *         values read from a test vector in the file.
     * @throws std::runtime_error If the file cannot be opened or if there is an
     *         error reading a vector.
     * @throws std::runtime_error If an unexpected key is encountered or if there
     *         is a parsing error for any field.
     */
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

   private:
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
};