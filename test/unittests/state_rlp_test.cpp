// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/state/hash_utils.hpp>
#include <test/state/rlp.hpp>
#include <test/utils/utils.hpp>

using namespace evmone;
using namespace evmc::literals;
using namespace intx;

static constexpr auto emptyBytesHash =
    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;

static constexpr auto emptyMPTHash =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

TEST(state_rlp, empty_bytes_hash)
{
    EXPECT_EQ(keccak256({}), emptyBytesHash);
}

TEST(state_rlp, empty_mpt_hash)
{
    const auto rlp_null = rlp::encode(0);
    EXPECT_EQ(rlp_null, bytes{0x80});
    EXPECT_EQ(keccak256(rlp_null), emptyMPTHash);
}

TEST(state_rlp, encode_string_short)
{
    EXPECT_EQ(hex(rlp::encode(0x01)), "01");
    EXPECT_EQ(hex(rlp::encode(0x31)), "31");
    EXPECT_EQ(hex(rlp::encode(0x7f)), "7f");
}

TEST(state_rlp, encode_string_long)
{
    const auto buffer = std::make_unique<uint8_t[]>(0xffffff);

    const auto r1 = rlp::encode({buffer.get(), 0xaabb});
    EXPECT_EQ(r1.size(), 0xaabb + 3);
    EXPECT_EQ(hex({r1.data(), 10}), "b9aabb00000000000000");

    const auto r2 = rlp::encode({buffer.get(), 0xffff});
    EXPECT_EQ(r2.size(), 0xffff + 3);
    EXPECT_EQ(hex({r2.data(), 10}), "b9ffff00000000000000");

    const auto r3 = rlp::encode({buffer.get(), 0xaabbcc});
    EXPECT_EQ(r3.size(), 0xaabbcc + 4);
    EXPECT_EQ(hex({r3.data(), 10}), "baaabbcc000000000000");

    const auto r4 = rlp::encode({buffer.get(), 0xffffff});
    EXPECT_EQ(r4.size(), 0xffffff + 4);
    EXPECT_EQ(hex({r4.data(), 10}), "baffffff000000000000");
}

TEST(state_rlp, encode_c_array)
{
    uint64_t a[]{1, 2, 3};
    EXPECT_EQ(hex(rlp::encode(a)), "c3010203");
}

TEST(state_rlp, encode_vector)
{
    const auto x = 0xe1e2e3e4e5e6e7d0d1d2d3d4d5d6d7c0c1c2c3c4c5c6c7b0b1b2b3b4b5b6b7_u256;
    EXPECT_EQ(
        hex(rlp::encode(x)), "9fe1e2e3e4e5e6e7d0d1d2d3d4d5d6d7c0c1c2c3c4c5c6c7b0b1b2b3b4b5b6b7");
    std::vector<uint256> v(0xffffff / 32, x);
    const auto r = rlp::encode(v);
    EXPECT_EQ(r.size(), v.size() * 32 + 4);
}

TEST(state_rlp, encode_account_with_balance)
{
    const auto expected = from_hex(
        "f8 44"
        "80"
        "01"
        "a0 56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        "a0 c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    const auto r = rlp::tuple(uint64_t{0}, 1_u256, emptyMPTHash, emptyBytesHash);
    EXPECT_EQ(r, expected);
}

TEST(state_rlp, encode_storage_value)
{
    const auto value = 0x00000000000000000000000000000000000000000000000000000000000001ff_bytes32;
    const auto xvalue = rlp::encode(rlp::trim(value));
    EXPECT_EQ(xvalue, from_hex("8201ff"));
}

TEST(state_rlp, encode_mpt_node)
{
    const bytes path{0x20, 0x41};
    const bytes value{'v', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_',
        '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '1'};
    const auto node = rlp::tuple(path, value);
    EXPECT_EQ(hex(node), "e18220419d765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31");
}
