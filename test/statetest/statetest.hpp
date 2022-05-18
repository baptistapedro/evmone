// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "../state/state.hpp"
#include <filesystem>

namespace fs = std::filesystem;

namespace evmone::test
{
struct TestTxParams
{
    size_t data;
    size_t gas_limit;
    size_t value;
};

struct MultiTx : state::Tx
{
    std::vector<state::AccessList> access_lists;
    std::vector<bytes> datas;
    std::vector<int64_t> gas_limits;
    std::vector<intx::uint256> values;

    [[nodiscard]] Tx get(const TestTxParams& indexes) const noexcept
    {
        Tx tx{*this};
        if (!access_lists.empty())
            tx.access_list = access_lists.at(indexes.data);
        tx.data = datas.at(indexes.data);
        tx.gas_limit = gas_limits.at(indexes.gas_limit);
        tx.value = values.at(indexes.value);
        return tx;
    }
};

struct TestExpectations
{
    TestTxParams indexes;
    hash256 state_hash;
    hash256 logs_hash;
    bool exception;
};

struct TestPost
{
    evmc_revision rev;
    std::vector<TestExpectations> cases;
};

struct StateTransitionTest
{
    state::State pre_state;
    state::BlockInfo block;
    MultiTx multi_tx;
    std::vector<TestPost> posts;
};

StateTransitionTest load_state_test(const fs::path& test_file);

}  // namespace evmone::test
