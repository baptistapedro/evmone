
#include "statetest.hpp"
#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <iostream>

using namespace evmone;
using namespace evmone::state;
using namespace evmone::test;
using namespace std::string_view_literals;


static void run_state_test(const StateTransitionTest& test)
{
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

            const auto tx_logs = state::transition(state, test.block, tx, rev, vm);
            EXPECT_NE(tx_logs.has_value(), expected.exception);

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

            if (tx_logs.has_value())
            {
                EXPECT_EQ(keccak256(rlp::encode(*tx_logs)), expected.logs_hash);
            }

            ++i;
        }
    }
}


class StateTest : public testing::Test
{
    fs::path m_json_test_file;

public:
    explicit StateTest(fs::path json_test_file) : m_json_test_file{std::move(json_test_file)} {}

    void TestBody() final { run_state_test(load_state_test(m_json_test_file)); }
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

    std::vector<fs::path> test_files;
    const fs::path root_test_dir{argv[1]};
    std::copy_if(fs::recursive_directory_iterator{root_test_dir},
        fs::recursive_directory_iterator{}, std::back_inserter(test_files),
        [](const fs::directory_entry& entry) {
            return entry.is_regular_file() && entry.path().extension() == ".json";
        });
    std::sort(test_files.begin(), test_files.end());
    for (const auto& p : test_files)
    {
        const auto d = fs::relative(p, root_test_dir);
        testing::RegisterTest(d.parent_path().c_str(), d.stem().c_str(), nullptr, nullptr,
            p.c_str(), 0, [p]() -> testing::Test* { return new StateTest(p); });
    }

    return RUN_ALL_TESTS();
}
