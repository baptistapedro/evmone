// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/hex.hpp>

using evmc::bytes;
using evmc::bytes_view;
using evmc::from_hex;
using evmc::hex;

/// Converts a string to bytes by casting individual characters.
inline bytes to_bytes(std::string_view s)
{
    return {s.begin(), s.end()};
}

/// Produces bytes out of string literal.
inline bytes operator""_b(const char* data, size_t size)
{
    return to_bytes({data, size});
}

/// Decodes the hexx encoded string.
///
/// The hexx encoding format is the hex format (base 16) with the extension
/// for run-length encoding. The parser replaces expressions like
///     `(` <num_repetitions> `x` <element> `)`
/// with `<element>` repeated `<num_repetitions>` times.
/// E.g. `(2x1d3)` is `1d31d3` in hex.
///
/// @param hexx  The hexx encoded string.
/// @return      The decoded bytes.
bytes from_hexx(const std::string& hexx);
