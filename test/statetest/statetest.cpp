
#include "../state/state.hpp"
#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace json = nlohmann;

using namespace evmone;
using namespace evmone::state;
using namespace std::string_view_literals;

static constexpr evmc_revision from_string(std::string_view s) noexcept
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

struct TestTxParams
{
    size_t data;
    size_t gas_limit;
    size_t value;
};

struct TestExpectations
{
    TestTxParams indexes;
    hash256 state_hash;
    hash256 logs_hash;
    bool exception;
};

struct MultiTx : Tx
{
    std::vector<AccessList> access_lists;
    std::vector<bytes> datas;
    std::vector<int64_t> gas_limits;
    std::vector<intx::uint256> values;

    [[nodiscard]] Tx get(TestTxParams indexes) const noexcept
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

struct TestPost
{
    evmc_revision rev;
    std::vector<TestExpectations> cases;
};

struct StateTransitionTest
{
    State pre_state;
    MultiTx multi_tx;
    BlockInfo block;
    std::vector<TestPost> posts;
};

template <typename T>
T from_json(const json::json& j) = delete;

template <>
address from_json<address>(const json::json& j)
{
    const auto s = j.get<std::string>();
    if (s.empty())
        return {};
    assert(s.size() == 42);
    return evmc::literals::internal::from_hex<address>(s.c_str() + 2);
}

template <>
hash256 from_json<hash256>(const json::json& j)
{
    const auto bytes = from_hex(j.get<std::string>());
    assert(bytes.size() <= 32);
    hash256 h{};
    std::memcpy(&h.bytes[32 - bytes.size()], bytes.data(), bytes.size());
    return h;
}

template <>
intx::uint256 from_json<intx::uint256>(const json::json& j)
{
    const auto s = j.get<std::string>();
    std::string_view v = s;
    constexpr auto bigint_marker = "0x:bigint "sv;
    if (v.substr(0, bigint_marker.size()) == bigint_marker)
        return std::numeric_limits<intx::uint256>::max();  // Fake it
    return intx::from_string<intx::uint256>(s);
}

template <>
bytes from_json<bytes>(const json::json& j)
{
    return from_hex(j.get<std::string>());
}

template <>
int64_t from_json<int64_t>(const json::json& j)
{
    return static_cast<int64_t>(std::stoll(j.get<std::string>(), nullptr, 16));
}

template <>
uint64_t from_json<uint64_t>(const json::json& j)
{
    return static_cast<uint64_t>(std::stoull(j.get<std::string>(), nullptr, 16));
}

static void from_json(const json::json& j, TestTxParams& o)
{
    o.data = j["data"].get<size_t>();
    o.gas_limit = j["gas"].get<size_t>();
    o.value = j["value"].get<size_t>();
}

static void from_json(const json::json& j, TestExpectations& o)
{
    o.indexes = j["indexes"].get<TestTxParams>();
    o.state_hash = from_json<hash256>(j["hash"]);
    o.logs_hash = from_json<hash256>(j["logs"]);
    o.exception = j.contains("expectException");
}

static void from_json(const json::json& j, AccessList& o)
{
    for (const auto& a : j)
    {
        o.push_back({from_json<evmc::address>(a["address"]), {}});
        auto& storage_access_list = o.back().second;
        for (const auto& storage_key : a["storageKeys"])
            storage_access_list.emplace_back(from_json<hash256>(storage_key));
    }
}

static void from_json(const json::json& j, MultiTx& o)
{
    if (j.contains("gasPrice"))
    {
        o.kind = Tx::Kind::legacy;
        o.max_gas_price = from_json<intx::uint256>(j["gasPrice"]);
        o.max_priority_gas_price = o.max_gas_price;
    }
    else
    {
        o.kind = Tx::Kind::eip1559;
        o.max_gas_price = from_json<intx::uint256>(j["maxFeePerGas"]);
        o.max_priority_gas_price = from_json<intx::uint256>(j["maxPriorityFeePerGas"]);
    }
    o.nonce = from_json<uint64_t>(j["nonce"]);
    o.sender = from_json<evmc::address>(j["sender"]);
    if (!j["to"].get<std::string>().empty())
        o.to = from_json<evmc::address>(j["to"]);

    for (const auto& j_data : j.at("data"))
        o.datas.emplace_back(from_json<bytes>(j_data));

    if (j.contains("accessLists"))
    {
        for (const auto& j_access_list : j["accessLists"])
            o.access_lists.emplace_back(j_access_list.get<AccessList>());
    }

    for (const auto& j_gas_limit : j.at("gasLimit"))
        o.gas_limits.emplace_back(from_json<int64_t>(j_gas_limit));

    for (const auto& j_value : j.at("value"))
        o.values.emplace_back(from_json<intx::uint256>(j_value));
}

static void from_json(const json::json& j, StateTransitionTest& o)
{
    const auto& j_t = j.begin().value();  // Content is in a dict with the test name.

    for (const auto& [j_addr, j_acc] : j_t["pre"].items())
    {
        const auto addr = from_json<address>(j_addr);
        auto& acc = o.pre_state.get_or_create(addr);
        acc.balance = from_json<intx::uint256>(j_acc["balance"]);
        acc.nonce = from_json<uint64_t>(j_acc["nonce"]);
        acc.code = from_json<bytes>(j_acc["code"]);

        for (const auto& [j_key, j_value] : j_acc["storage"].items())
        {
            auto& slot = acc.storage[from_json<bytes32>(j_key)];
            const auto value = from_json<bytes32>(j_value);
            slot.orig = value;
            slot.current = value;
        }
    }

    o.multi_tx = j_t["transaction"].get<MultiTx>();

    const auto& env = j_t["env"];
    o.block.gas_limit = from_json<int64_t>(env["currentGasLimit"]);
    o.block.coinbase = from_json<evmc::address>(env["currentCoinbase"]);
    o.block.base_fee = from_json<uint64_t>(env["currentBaseFee"]);
    o.block.difficulty = from_json<evmc::uint256be>(env["currentDifficulty"]);
    o.block.number = from_json<int64_t>(env["currentNumber"]);
    o.block.timestamp = from_json<int64_t>(env["currentTimestamp"]);

    // TODO: Chain ID is expected to be 1.
    o.block.chain_id = {};
    o.block.chain_id.bytes[31] = 1;

    for (const auto& [rev_name, posts] : j_t["post"].items())
    {
        auto& p = o.posts.emplace_back();
        p.rev = from_string(rev_name);
        for (const auto& post : posts)
            p.cases.emplace_back(post.get<TestExpectations>());
    }
}

static void run_state_test(const json::json& j)
{
    SCOPED_TRACE(j.begin().key());

    auto test = j.get<StateTransitionTest>();

    evmc::VM vm{evmc_create_evmone(), {
                                          {"O", "0"},
                                          // {"trace", "1"},
                                      }};

    for (const auto& [rev, cases] : test.posts)
    {
        // if (rev_name != "London")
        //     continue;

        SCOPED_TRACE(rev);
        int i = 0;
        for (const auto& expected : cases)
        {
            // if (i != 0)
            // {
            //     ++i;
            //     continue;
            // }
            const auto tx = test.multi_tx.get(expected.indexes);
            auto state = test.pre_state;

            const auto tx_status = state::transition(state, test.block, tx, rev, vm);
            EXPECT_NE(tx_status.success, expected.exception);

            std::ostringstream state_dump;

            state_dump << "--- " << rev << " " << i << "\n";
            for (const auto& [addr, acc] : state.get_accounts())
            {
                state_dump << evmc::hex({addr.bytes, sizeof(addr.bytes)}) << " [" << acc.nonce
                           << "]: " << to_string(acc.balance) << "\n";
                for (const auto& [k, v] : acc.storage)
                {
                    if (is_zero(v.current))
                        continue;
                    state_dump << "- " << evmc::hex({k.bytes, sizeof(k)}) << ": "
                               << evmc::hex({v.current.bytes, sizeof(v.current)}) << "\n";
                }
            }

            EXPECT_EQ(state::trie_hash(state), expected.state_hash) << state_dump.str();

            const auto logs_hash =
                (tx_status.logs_hash != hash256{}) ? tx_status.logs_hash : keccak256(bytes{0xc0});
            EXPECT_EQ(logs_hash, expected.logs_hash);

            ++i;
        }
    }
}

namespace fs = std::filesystem;

class StateTest : public testing::Test
{
    fs::path m_json_test_file;

public:
    explicit StateTest(fs::path json_test_file) : m_json_test_file{std::move(json_test_file)} {}

    void TestBody() final { run_state_test(json::json::parse(std::ifstream{m_json_test_file})); }
};

int main(int argc, char* argv[])
{
    constexpr auto known_passing_tests =
        "*.*:"
        "-"
        // Slow tests.
        "stCreateTest.CreateOOGafterMaxCodesize:"      // pass
        "stQuadraticComplexityTest.Call50000_sha256:"  // pass
        "stTimeConsuming.static_Call50000_sha256:"     // pass
        "stTimeConsuming.CALLBlake2f_MaxRounds:"       // pass
        "VMTests/vmPerformance.*:"                     // pass
        /**/
        ;

    // constexpr auto single_test = "stLogTests.*:"sv;
    constexpr auto single_test = ""sv;

    std::string filter = "--gtest_filter=";
    const auto argv_end = argv + argc;
    if (const auto filter_arg = std::find(argv, argv_end, "--gtest_filter=builtin"sv);
        filter_arg != argv_end)
    {
        filter += (single_test.empty() ? known_passing_tests : single_test.data());
        *filter_arg = filter.data();
    }

    testing::InitGoogleTest(&argc, argv);

    if (argc != 2)
        return -1;

    const fs::path root_test_dir{argv[1]};
    for (const auto& dir_entry : fs::recursive_directory_iterator{root_test_dir})
    {
        const auto& p = dir_entry.path();
        if (dir_entry.is_regular_file() && p.extension() == ".json")
        {
            const auto d = fs::relative(p, root_test_dir);
            testing::RegisterTest(d.parent_path().c_str(), d.stem().c_str(), nullptr, nullptr,
                p.c_str(), 0, [p]() -> testing::Test* { return new StateTest(p); });
        }
    }

    return RUN_ALL_TESTS();
}
