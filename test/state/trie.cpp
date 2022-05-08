// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "trie.hpp"
#include "rlp.hpp"
#include <algorithm>
#include <cassert>
#include <cstring>

namespace evmone::state
{
namespace
{
/// The collection of nibbles (4-bit values) representing a path in a MPT.
struct Path
{
    size_t length;  // TODO: Can be converted to uint8_t.
    uint8_t nibbles[64];

    explicit Path(bytes_view k) noexcept : length(2 * std::size(k))
    {
        assert(length <= 64);
        size_t i = 0;
        for (const auto b : k)
        {
            nibbles[i++] = b >> 4;
            nibbles[i++] = b & 0x0f;
        }
    }

    [[nodiscard]] Path tail(size_t index) const
    {
        assert(index <= length);
        Path p{{}};
        p.length = length - index;
        std::memcpy(p.nibbles, &nibbles[index], p.length);
        return p;
    }

    [[nodiscard]] Path head(size_t size) const
    {
        assert(size < length);
        Path p{{}};
        p.length = size;
        std::memcpy(p.nibbles, nibbles, size);
        return p;
    }

    [[nodiscard]] bytes encode(bool extended) const
    {
        bytes bs;
        const auto is_even = length % 2 == 0;
        if (is_even)
            bs.push_back(0x00);
        else
            bs.push_back(0x10 | nibbles[0]);
        for (size_t i = is_even ? 0 : 1; i < length; ++i)
        {
            const auto h = nibbles[i++];
            const auto l = nibbles[i];
            assert(h <= 0x0f);
            assert(l <= 0x0f);
            bs.push_back(uint8_t((h << 4) | l));
        }
        if (!extended)
            bs[0] |= 0x20;
        return bs;
    }
};
}  // namespace

/// The MPT Node.
///
/// The implementation is based on StackTrie from go-ethereum.
class Node
{
    enum class Kind : uint8_t
    {
        leaf,
        ext,
        branch
    };

    static constexpr size_t num_children = 16;

    Kind m_kind;
    Path m_path{{}};
    bytes m_value;
    std::unique_ptr<Node> children[num_children];

    Node(Kind kind, const Path& path, bytes&& value = {}) noexcept
      : m_kind{kind}, m_path{path}, m_value{std::move(value)}
    {}

    /// Named constructor for an extended node.
    static Node ext(const Path& k, std::unique_ptr<Node> child) noexcept
    {
        Node node{Kind::ext, k};
        node.children[0] = std::move(child);
        return node;
    }

    static size_t diff_index(const Path& p1, const Path& p2) noexcept
    {
        assert(p1.length <= p2.length);
        return static_cast<size_t>(
            std::mismatch(p1.nibbles, p1.nibbles + p1.length, p2.nibbles).first - p1.nibbles);
    }

public:
    Node() = default;

    /// Named constructor for a leaf node.
    static Node leaf(const Path& k, bytes&& v) noexcept { return {Kind::leaf, k, std::move(v)}; }

    void insert(const Path& k, bytes&& v);

    [[nodiscard]] hash256 hash() const;
};

MPT::MPT() noexcept = default;
MPT::~MPT() noexcept = default;

void MPT::insert(bytes_view key, bytes&& value)
{
    if (m_root == nullptr)
        m_root = std::make_unique<Node>(Node::leaf(Path{key}, std::move(value)));
    else
        m_root->insert(Path{key}, std::move(value));
}

[[nodiscard]] hash256 MPT::hash() const
{
    if (m_root == nullptr)
        return emptyTrieHash;
    return m_root->hash();
}

void Node::insert(const Path& k, bytes&& v)
{
    switch (m_kind)
    {
    case Kind::branch:
    {
        assert(m_path.length == 0);
        const auto idx = k.nibbles[0];
        auto& child = children[idx];
        if (!child)
            child = std::make_unique<Node>(leaf(k.tail(1), std::move(v)));
        else
            child->insert(k.tail(1), std::move(v));
        break;
    }

    case Kind::ext:
    {
        const auto diffidx = diff_index(m_path, k);

        if (diffidx == m_path.length)
        {
            // Go into child.
            return children[0]->insert(k.tail(diffidx), std::move(v));
        }

        std::unique_ptr<Node> n;
        if (diffidx < m_path.length - 1)
            n = std::make_unique<Node>(ext(m_path.tail(diffidx + 1), std::move(children[0])));
        else
            n = std::move(children[0]);

        Node* branch = nullptr;
        if (diffidx == 0)
        {
            branch = this;
            branch->m_kind = Kind::branch;
        }
        else
        {
            branch = (children[0] = std::make_unique<Node>()).get();
            branch->m_kind = Kind::branch;
        }

        const auto origIdx = m_path.nibbles[diffidx];
        const auto newIdx = k.nibbles[diffidx];

        branch->children[origIdx] = std::move(n);
        branch->children[newIdx] = std::make_unique<Node>(leaf(k.tail(diffidx + 1), std::move(v)));
        m_path = m_path.head(diffidx);
        break;
    }

    case Kind::leaf:
    {
        // TODO: Add assert for k == key.
        const auto diffidx = diff_index(m_path, k);

        Node* branch = nullptr;
        if (diffidx == 0)  // Convert into a branch.
        {
            m_kind = Kind::branch;
            branch = this;
        }
        else
        {
            m_kind = Kind::ext;
            branch = (children[0] = std::make_unique<Node>()).get();
            branch->m_kind = Kind::branch;
        }

        const auto origIdx = m_path.nibbles[diffidx];
        branch->children[origIdx] =
            std::make_unique<Node>(leaf(m_path.tail(diffidx + 1), std::move(m_value)));

        const auto newIdx = k.nibbles[diffidx];
        assert(origIdx != newIdx);
        branch->children[newIdx] = std::make_unique<Node>(leaf(k.tail(diffidx + 1), std::move(v)));

        m_path = m_path.head(diffidx);
        break;
    }

    default:
        assert(false);
    }
}

hash256 Node::hash() const
{
    hash256 r{};
    switch (m_kind)
    {
    case Kind::leaf:
    {
        const auto node = rlp::tuple(m_path.encode(false), m_value);
        r = keccak256(node);
        break;
    }
    case Kind::branch:
    {
        assert(m_path.length == 0);

        // Temporary storage for children hashes.
        // The `bytes` type could be used instead, but this way dynamic allocation is avoided.
        hash256 children_hashes[num_children];

        // Views of children hash bytes. Additional item for hash list
        // terminator (always empty). Does not seem needed for correctness,
        // but this is what the spec says.
        bytes_view children_hash_bytes[num_children + 1];

        for (size_t i = 0; i < num_children; ++i)
        {
            if (children[i])
            {
                children_hashes[i] = children[i]->hash();
                children_hash_bytes[i] = children_hashes[i];
            }
        }

        r = keccak256(rlp::encode(children_hash_bytes));
        break;
    }
    case Kind::ext:
    {
        const auto branch = children[0].get();
        assert(branch != nullptr);
        assert(branch->m_kind == Kind::branch);
        r = keccak256(rlp::tuple(m_path.encode(true), branch->hash()));
        break;
    }
    default:
        assert(false);
    }

    return r;
}

}  // namespace evmone::state
