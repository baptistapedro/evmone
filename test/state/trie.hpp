// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hash_utils.hpp"
#include <memory>

namespace evmone::state
{
constexpr auto emptyTrieHash =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

class Node;

/// Insert-only Merkle Patricia Trie implementation for getting the root hash
/// out of (key, value) pairs.
class MPT
{
    std::unique_ptr<Node> m_root;

public:
    MPT() noexcept;
    ~MPT() noexcept;

    void insert(bytes_view key, bytes&& value);

    [[nodiscard]] hash256 hash() const;
};

}  // namespace evmone::state
