// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <cstring>

namespace evmone
{
using evmc::bytes;
using evmc::bytes_view;

/// Default type for 256-bit hash.
///
/// Better than ethash::hash256 because has some additional handy constructors.
using hash256 = evmc::bytes32;

/// Computes Keccak hash out of input bytes (wrapper of ethash::keccak256).
inline hash256 keccak256(bytes_view data) noexcept
{
    const auto eh = ethash::keccak256(data.data(), data.size());
    hash256 h;
    std::memcpy(h.bytes, eh.bytes, sizeof(h));  // TODO: Use std::bit_cast.
    return h;
}

using evmc::address;
using evmc::from_hex;
using evmc::hex;
using namespace evmc::literals;

inline bytes to_bytes(std::string_view s)
{
    bytes b;
    b.reserve(std::size(s));
    for (const auto c : s)
        b.push_back(static_cast<uint8_t>(c));
    return b;
}

constexpr evmc_revision from_string(std::string_view s) noexcept
{
    if (s == "Frontier")
        return EVMC_FRONTIER;
    if (s == "Homestead")
        return EVMC_HOMESTEAD;
    if (s == "EIP150")
        return EVMC_TANGERINE_WHISTLE;
    if (s == "EIP158")
        return EVMC_SPURIOUS_DRAGON;
    if (s == "Byzantium")
        return EVMC_BYZANTIUM;
    if (s == "Constantinople")
        return EVMC_CONSTANTINOPLE;
    if (s == "ConstantinopleFix")
        return EVMC_PETERSBURG;
    if (s == "Istanbul")
        return EVMC_ISTANBUL;
    if (s == "Berlin")
        return EVMC_BERLIN;
    if (s == "London")
        return EVMC_LONDON;
    assert(false && "unknown revision");
    __builtin_unreachable();
}
}  // namespace evmone
