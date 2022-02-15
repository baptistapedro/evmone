// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "baseline.hpp"
#include "execution_state.hpp"
#include "instructions_traits.hpp"
#include "instructions_xmacro.hpp"
#include <ethash/keccak.hpp>

namespace evmone
{
using code_iterator = const uint8_t*;

/// Represents the pointer to the stack top item
/// and allows retrieving stack items and manipulating the pointer.
class StackTop
{
    uint256* m_top;

public:
    StackTop(uint256* top) noexcept : m_top{top} {}

    /// Returns the reference to the stack item by index, where 0 means the top item
    /// and positive index values the items further down the stack.
    /// Using [-1] is also valid, but .push() should be used instead.
    [[nodiscard]] uint256& operator[](int index) noexcept { return m_top[-index]; }

    /// Returns the reference to the stack top item.
    [[nodiscard]] uint256& top() noexcept { return *m_top; }

    /// Returns the current top item and move the stack top pointer down.
    /// The value is returned by reference because the stack slot remains valid.
    [[nodiscard]] uint256& pop() noexcept { return *m_top--; }

    /// Assigns the value to the stack top and moves the stack top pointer up.
    void push(const uint256& value) noexcept { *++m_top = value; }
};

/// A wrapper for evmc_status_code to indicate that an instruction
/// unconditionally terminates execution.
struct StopToken
{
    const evmc_status_code status;  ///< The status code execution terminates with.
};

constexpr auto max_buffer_size = std::numeric_limits<uint32_t>::max();

/// The size of the EVM 256-bit word.
constexpr auto word_size = 32;

/// Returns number of words what would fit to provided number of bytes,
/// i.e. it rounds up the number bytes to number of words.
inline constexpr int64_t num_words(uint64_t size_in_bytes) noexcept
{
    return static_cast<int64_t>((size_in_bytes + (word_size - 1)) / word_size);
}

// Grows EVM memory and checks its cost.
//
// This function should not be inlined because this may affect other inlining decisions:
// - making check_memory() too costly to inline,
// - making mload()/mstore()/mstore8() too costly to inline.
//
// TODO: This function should be moved to Memory class.
[[gnu::noinline]] inline int64_t grow_memory(
    ExecutionState& state, int64_t gas_left, uint64_t new_size) noexcept
{
    // This implementation recomputes memory.size(). This value is already known to the caller
    // and can be passed as a parameter, but this make no difference to the performance.

    const auto new_words = num_words(new_size);
    const auto current_words = static_cast<int64_t>(state.memory.size() / word_size);
    const auto new_cost = 3 * new_words + new_words * new_words / 512;
    const auto current_cost = 3 * current_words + current_words * current_words / 512;
    const auto cost = new_cost - current_cost;

    gas_left -= cost;
    if (gas_left >= 0)
        state.memory.grow(static_cast<size_t>(new_words * word_size));
    return gas_left;
}

// Check memory requirements of a reasonable size.
inline int64_t check_memory(
    ExecutionState& state, int64_t gas_left, const uint256& offset, uint64_t size) noexcept
{
    // TODO: This should be done in intx.
    // There is "branchless" variant of this using | instead of ||, but benchmarks difference
    // is within noise. This should be decided when moving the implementation to intx.
    if (((offset[3] | offset[2] | offset[1]) != 0) || (offset[0] > max_buffer_size))
        return -1;

    const auto new_size = static_cast<uint64_t>(offset) + size;
    if (new_size > state.memory.size())
        gas_left = grow_memory(state, gas_left, new_size);

    return gas_left;
}

// Check memory requirements for "copy" instructions.
inline int64_t check_memory(
    ExecutionState& state, int64_t gas_left, const uint256& offset, const uint256& size) noexcept
{
    if (size == 0)  // Copy of size 0 is always valid (even if offset is huge).
        return gas_left;

    // This check has 3 same word checks with the check above.
    // However, compilers do decent although not perfect job unifying common instructions.
    // TODO: This should be done in intx.
    if (((size[3] | size[2] | size[1]) != 0) || (size[0] > max_buffer_size))
        return -1;

    return check_memory(state, gas_left, offset, static_cast<uint64_t>(size));
}

namespace instr::core
{

/// The "core" instruction implementations.
///
/// These are minimal EVM instruction implementations which assume:
/// - the stack requirements (overflow, underflow) have already been checked,
/// - the "base" gas const has already been charged,
/// - the `stack` pointer points to the EVM stack top element.
/// Moreover, these implementations _do not_ inform about new stack height
/// after execution. The adjustment must be performed by the caller.
inline void noop(StackTop /*stack*/) noexcept {}
inline constexpr auto pop = noop;
inline constexpr auto jumpdest = noop;

template <evmc_status_code Status>
inline StopToken stop_impl() noexcept
{
    return {Status};
}
inline constexpr auto stop = stop_impl<EVMC_SUCCESS>;
inline constexpr auto invalid = stop_impl<EVMC_INVALID_INSTRUCTION>;

inline void add(StackTop stack) noexcept
{
    stack.top() += stack.pop();
}

inline void mul(StackTop stack) noexcept
{
    stack.top() *= stack.pop();
}

inline void sub(StackTop stack) noexcept
{
    stack[1] = stack[0] - stack[1];
}

inline void div(StackTop stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? stack[0] / v : 0;
}

inline void sdiv(StackTop stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? intx::sdivrem(stack[0], v).quot : 0;
}

inline void mod(StackTop stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? stack[0] % v : 0;
}

inline void smod(StackTop stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? intx::sdivrem(stack[0], v).rem : 0;
}

inline void addmod(StackTop stack) noexcept
{
    const auto& x = stack.pop();
    const auto& y = stack.pop();
    auto& m = stack.top();
    m = m != 0 ? intx::addmod(x, y, m) : 0;
}

inline void mulmod(StackTop stack) noexcept
{
    const auto& x = stack[0];
    const auto& y = stack[1];
    auto& m = stack[2];
    m = m != 0 ? intx::mulmod(x, y, m) : 0;
}

inline int64_t exp(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    const auto& base = stack.pop();
    auto& exponent = stack.top();

    const auto exponent_significant_bytes =
        static_cast<int>(intx::count_significant_bytes(exponent));
    const auto exponent_cost = state.rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10;
    const auto additional_cost = exponent_significant_bytes * exponent_cost;
    gas_left -= additional_cost;
    if (gas_left < 0)
        return gas_left;

    exponent = intx::exp(base, exponent);
    return gas_left;
}

inline void signextend(StackTop stack) noexcept
{
    const auto& ext = stack.pop();
    auto& x = stack.top();

    if (ext < 31)  // For 31 we also don't need to do anything.
    {
        const auto e = ext[0];  // uint256 -> uint64.
        const auto sign_word_index =
            static_cast<size_t>(e / sizeof(e));      // Index of the word with the sign bit.
        const auto sign_byte_index = e % sizeof(e);  // Index of the sign byte in the sign word.
        auto& sign_word = x[sign_word_index];

        const auto sign_byte_offset = sign_byte_index * 8;
        const auto sign_byte = sign_word >> sign_byte_offset;  // Move sign byte to position 0.

        // Sign-extend the "sign" byte and move it to the right position. Value bits are zeros.
        const auto sext_byte = static_cast<uint64_t>(int64_t{static_cast<int8_t>(sign_byte)});
        const auto sext = sext_byte << sign_byte_offset;

        const auto sign_mask = ~uint64_t{0} << sign_byte_offset;
        const auto value = sign_word & ~sign_mask;  // Reset extended bytes.
        sign_word = sext | value;                   // Combine the result word.

        // Produce bits (all zeros or ones) for extended words. This is done by SAR of
        // the sign-extended byte. Shift by any value 7-63 would work.
        const auto sign_ex = static_cast<uint64_t>(static_cast<int64_t>(sext_byte) >> 8);

        for (size_t i = 3; i > sign_word_index; --i)
            x[i] = sign_ex;  // Clear extended words.
    }
}

inline void lt(StackTop stack) noexcept
{
    const auto& x = stack.pop();
    stack[0] = x < stack[0];
}

inline void gt(StackTop stack) noexcept
{
    const auto& x = stack.pop();
    stack[0] = stack[0] < x;  // Arguments are swapped and < is used.
}

inline void slt(StackTop stack) noexcept
{
    const auto& x = stack.pop();
    stack[0] = slt(x, stack[0]);
}

inline void sgt(StackTop stack) noexcept
{
    const auto& x = stack.pop();
    stack[0] = slt(stack[0], x);  // Arguments are swapped and SLT is used.
}

inline void eq(StackTop stack) noexcept
{
    stack[1] = stack[0] == stack[1];
}

inline void iszero(StackTop stack) noexcept
{
    stack.top() = stack.top() == 0;
}

inline void and_(StackTop stack) noexcept
{
    stack.top() &= stack.pop();
}

inline void or_(StackTop stack) noexcept
{
    stack.top() |= stack.pop();
}

inline void xor_(StackTop stack) noexcept
{
    stack.top() ^= stack.pop();
}

inline void not_(StackTop stack) noexcept
{
    stack.top() = ~stack.top();
}

inline void byte(StackTop stack) noexcept
{
    const auto& n = stack.pop();
    auto& x = stack.top();

    const bool n_valid = n < 32;
    const uint64_t byte_mask = (n_valid ? 0xff : 0);

    const auto index = 31 - static_cast<unsigned>(n[0] % 32);
    const auto word = x[index / 8];
    const auto byte_index = index % 8;
    const auto byte = (word >> (byte_index * 8)) & byte_mask;
    x = byte;
}

inline void shl(StackTop stack) noexcept
{
    stack.top() <<= stack.pop();
}

inline void shr(StackTop stack) noexcept
{
    stack.top() >>= stack.pop();
}

inline void sar(StackTop stack) noexcept
{
    const auto& y = stack.pop();
    auto& x = stack.top();

    const bool is_neg = static_cast<int64_t>(x[3]) < 0;  // Inspect the top bit (words are LE).
    const auto sign_mask = is_neg ? ~uint256{} : uint256{};

    const auto mask_shift = (y < 256) ? (256 - y[0]) : 0;
    x = (x >> y) | (sign_mask << mask_shift);
}

inline int64_t keccak256(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    const auto& index = stack.pop();
    auto& size = stack.top();

    if (gas_left = check_memory(state, gas_left, index, size); gas_left < 0)
        return gas_left;

    const auto i = static_cast<size_t>(index);
    const auto s = static_cast<size_t>(size);
    const auto w = num_words(s);
    const auto cost = w * 6;
    if ((gas_left -= cost) < 0)
        return gas_left;

    auto data = s != 0 ? &state.memory[i] : nullptr;
    size = intx::be::load<uint256>(ethash::keccak256(data, s));
    return gas_left;
}


inline void address(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.msg->recipient));
}

inline int64_t balance(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    auto& x = stack.top();
    const auto addr = intx::be::trunc<evmc::address>(x);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return gas_left;
    }

    x = intx::be::load<uint256>(state.host.get_balance(addr));
    return gas_left;
}

inline void origin(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.host.get_tx_context().tx_origin));
}

inline void caller(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.msg->sender));
}

inline void callvalue(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.msg->value));
}

inline void calldataload(StackTop stack, ExecutionState& state) noexcept
{
    auto& index = stack.top();

    if (state.msg->input_size < index)
        index = 0;
    else
    {
        const auto begin = static_cast<size_t>(index);
        const auto end = std::min(begin + 32, state.msg->input_size);

        uint8_t data[32] = {};
        for (size_t i = 0; i < (end - begin); ++i)
            data[i] = state.msg->input_data[begin + i];

        index = intx::be::load<uint256>(data);
    }
}

inline void calldatasize(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(state.msg->input_size);
}

inline int64_t calldatacopy(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    const auto& mem_index = stack.pop();
    const auto& input_index = stack.pop();
    const auto& size = stack.pop();

    if (gas_left = check_memory(state, gas_left, mem_index, size); gas_left < 0)
        return gas_left;

    auto dst = static_cast<size_t>(mem_index);
    auto src = state.msg->input_size < input_index ? state.msg->input_size :
                                                     static_cast<size_t>(input_index);
    auto s = static_cast<size_t>(size);
    auto copy_size = std::min(s, state.msg->input_size - src);

    const auto copy_cost = num_words(s) * 3;
    if ((gas_left -= copy_cost) < 0)
        return gas_left;

    if (copy_size > 0)
        std::memcpy(&state.memory[dst], &state.msg->input_data[src], copy_size);

    if (s - copy_size > 0)
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

    return gas_left;
}

inline void codesize(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(state.code.size());
}

inline int64_t codecopy(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    // TODO: Similar to calldatacopy().

    const auto& mem_index = stack.pop();
    const auto& input_index = stack.pop();
    const auto& size = stack.pop();

    if (gas_left = check_memory(state, gas_left, mem_index, size); gas_left < 0)
        return gas_left;

    const auto code_size = state.code.size();
    const auto dst = static_cast<size_t>(mem_index);
    const auto src = code_size < input_index ? code_size : static_cast<size_t>(input_index);
    const auto s = static_cast<size_t>(size);
    const auto copy_size = std::min(s, code_size - src);

    const auto copy_cost = num_words(s) * 3;
    if ((gas_left -= copy_cost) < 0)
        return gas_left;

    // TODO: Add unit tests for each combination of conditions.
    if (copy_size > 0)
        std::memcpy(&state.memory[dst], &state.code[src], copy_size);

    if (s - copy_size > 0)
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

    return gas_left;
}


inline void gasprice(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.host.get_tx_context().tx_gas_price));
}

inline void basefee(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_base_fee));
}

inline int64_t extcodesize(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    auto& x = stack.top();
    const auto addr = intx::be::trunc<evmc::address>(x);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return gas_left;
    }

    x = state.host.get_code_size(addr);
    return gas_left;
}

inline int64_t extcodecopy(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    const auto addr = intx::be::trunc<evmc::address>(stack.pop());
    const auto& mem_index = stack.pop();
    const auto& input_index = stack.pop();
    const auto& size = stack.pop();

    if (gas_left = check_memory(state, gas_left, mem_index, size); gas_left < 0)
        return gas_left;

    const auto s = static_cast<size_t>(size);
    const auto copy_cost = num_words(s) * 3;
    if ((gas_left -= copy_cost) < 0)
        return gas_left;

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return gas_left;
    }

    if (s > 0)
    {
        const auto src =
            (max_buffer_size < input_index) ? max_buffer_size : static_cast<size_t>(input_index);
        const auto dst = static_cast<size_t>(mem_index);
        const auto num_bytes_copied = state.host.copy_code(addr, src, &state.memory[dst], s);
        if (const auto num_bytes_to_clear = s - num_bytes_copied; num_bytes_to_clear > 0)
            std::memset(&state.memory[dst + num_bytes_copied], 0, num_bytes_to_clear);
    }

    return gas_left;
}

inline void returndatasize(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(state.return_data.size());
}

inline evmc_status_code returndatacopy(StackTop stack, ExecutionState& state) noexcept
{
    const auto& mem_index = stack.pop();
    const auto& input_index = stack.pop();
    const auto& size = stack.pop();

    if (state.gas_left = check_memory(state, state.gas_left, mem_index, size); state.gas_left < 0)
        return EVMC_OUT_OF_GAS;

    auto dst = static_cast<size_t>(mem_index);
    auto s = static_cast<size_t>(size);

    if (state.return_data.size() < input_index)
        return EVMC_INVALID_MEMORY_ACCESS;
    auto src = static_cast<size_t>(input_index);

    if (src + s > state.return_data.size())
        return EVMC_INVALID_MEMORY_ACCESS;

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return EVMC_OUT_OF_GAS;

    if (s > 0)
        std::memcpy(&state.memory[dst], &state.return_data[src], s);

    return EVMC_SUCCESS;
}

inline int64_t extcodehash(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    auto& x = stack.top();
    const auto addr = intx::be::trunc<evmc::address>(x);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return gas_left;
    }

    x = intx::be::load<uint256>(state.host.get_code_hash(addr));
    return gas_left;
}


inline void blockhash(StackTop stack, ExecutionState& state) noexcept
{
    auto& number = stack.top();

    const auto upper_bound = state.host.get_tx_context().block_number;
    const auto lower_bound = std::max(upper_bound - 256, decltype(upper_bound){0});
    const auto n = static_cast<int64_t>(number);
    const auto header =
        (number < upper_bound && n >= lower_bound) ? state.host.get_block_hash(n) : evmc::bytes32{};
    number = intx::be::load<uint256>(header);
}

inline void coinbase(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_coinbase));
}

inline void timestamp(StackTop stack, ExecutionState& state) noexcept
{
    // TODO: Add tests for negative timestamp?
    stack.push(static_cast<uint64_t>(state.host.get_tx_context().block_timestamp));
}

inline void number(StackTop stack, ExecutionState& state) noexcept
{
    // TODO: Add tests for negative block number?
    stack.push(static_cast<uint64_t>(state.host.get_tx_context().block_number));
}

inline void difficulty(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_difficulty));
}

inline void gaslimit(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(static_cast<uint64_t>(state.host.get_tx_context().block_gas_limit));
}

inline void chainid(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.host.get_tx_context().chain_id));
}

inline void selfbalance(StackTop stack, ExecutionState& state) noexcept
{
    // TODO: introduce selfbalance in EVMC?
    stack.push(intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)));
}

inline evmc_status_code mload(StackTop stack, ExecutionState& state) noexcept
{
    auto& index = stack.top();

    if (state.gas_left = check_memory(state, state.gas_left, index, 32); state.gas_left < 0)
        return EVMC_OUT_OF_GAS;

    index = intx::be::unsafe::load<uint256>(&state.memory[static_cast<size_t>(index)]);
    return EVMC_SUCCESS;
}

inline evmc_status_code mstore(StackTop stack, ExecutionState& state) noexcept
{
    const auto& index = stack.pop();
    const auto& value = stack.pop();

    if (state.gas_left = check_memory(state, state.gas_left, index, 32); state.gas_left < 0)
        return EVMC_OUT_OF_GAS;

    intx::be::unsafe::store(&state.memory[static_cast<size_t>(index)], value);
    return EVMC_SUCCESS;
}

inline evmc_status_code mstore8(StackTop stack, ExecutionState& state) noexcept
{
    const auto& index = stack.pop();
    const auto& value = stack.pop();

    if (state.gas_left = check_memory(state, state.gas_left, index, 1); state.gas_left < 0)
        return EVMC_OUT_OF_GAS;

    state.memory[static_cast<size_t>(index)] = static_cast<uint8_t>(value);
    return EVMC_SUCCESS;
}

inline evmc_status_code sload(StackTop stack, ExecutionState& state) noexcept
{
    auto& x = stack.top();
    const auto key = intx::be::store<evmc::bytes32>(x);

    if (state.rev >= EVMC_BERLIN &&
        state.host.access_storage(state.msg->recipient, key) == EVMC_ACCESS_COLD)
    {
        // The warm storage access cost is already applied (from the cost table).
        // Here we need to apply additional cold storage access cost.
        constexpr auto additional_cold_sload_cost =
            instr::cold_sload_cost - instr::warm_storage_read_cost;
        if ((state.gas_left -= additional_cold_sload_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    x = intx::be::load<uint256>(state.host.get_storage(state.msg->recipient, key));

    return EVMC_SUCCESS;
}

inline evmc_status_code sstore(StackTop stack, ExecutionState& state) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return EVMC_STATIC_MODE_VIOLATION;

    if (state.rev >= EVMC_ISTANBUL && state.gas_left <= 2300)
        return EVMC_OUT_OF_GAS;

    const auto key = intx::be::store<evmc::bytes32>(stack.pop());
    const auto value = intx::be::store<evmc::bytes32>(stack.pop());

    int cost = 0;
    if (state.rev >= EVMC_BERLIN &&
        state.host.access_storage(state.msg->recipient, key) == EVMC_ACCESS_COLD)
        cost = instr::cold_sload_cost;

    const auto status = state.host.set_storage(state.msg->recipient, key, value);

    switch (status)
    {
    case EVMC_STORAGE_UNCHANGED:
    case EVMC_STORAGE_MODIFIED_AGAIN:
        if (state.rev >= EVMC_BERLIN)
            cost += instr::warm_storage_read_cost;
        else if (state.rev == EVMC_ISTANBUL)
            cost = 800;
        else if (state.rev == EVMC_CONSTANTINOPLE)
            cost = 200;
        else
            cost = 5000;
        break;
    case EVMC_STORAGE_MODIFIED:
    case EVMC_STORAGE_DELETED:
        if (state.rev >= EVMC_BERLIN)
            cost += 5000 - instr::cold_sload_cost;
        else
            cost = 5000;
        break;
    case EVMC_STORAGE_ADDED:
        cost += 20000;
        break;
    }
    if ((state.gas_left -= cost) < 0)
        return EVMC_OUT_OF_GAS;
    return EVMC_SUCCESS;
}

/// Internal jump implementation for JUMP/JUMPI instructions.
inline code_iterator jump_impl(ExecutionState& state, const uint256& dst) noexcept
{
    const auto& jumpdest_map = state.analysis.baseline->jumpdest_map;
    if (dst >= jumpdest_map.size() || !jumpdest_map[static_cast<size_t>(dst)])
    {
        state.status = EVMC_BAD_JUMP_DESTINATION;
        return nullptr;
    }

    return state.code.data() + static_cast<size_t>(dst);
}

/// JUMP instruction implementation using baseline::CodeAnalysis.
inline code_iterator jump(StackTop stack, ExecutionState& state, code_iterator /*pos*/) noexcept
{
    return jump_impl(state, stack.pop());
}

/// JUMPI instruction implementation using baseline::CodeAnalysis.
inline code_iterator jumpi(StackTop stack, ExecutionState& state, code_iterator pos) noexcept
{
    const auto& dst = stack.pop();
    const auto& cond = stack.pop();
    return cond ? jump_impl(state, dst) : pos + 1;
}

inline code_iterator pc(StackTop stack, ExecutionState& state, code_iterator pos) noexcept
{
    stack.push(static_cast<uint64_t>(pos - state.code.data()));
    return pos + 1;
}

inline void msize(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(state.memory.size());
}

inline void gas(StackTop stack, ExecutionState& state) noexcept
{
    stack.push(state.gas_left);
}

/// PUSH instruction implementation.
/// @tparam Len The number of push data bytes, e.g. PUSH3 is push<3>.
///
/// It assumes that the whole data read is valid so code padding is required for some EVM bytecodes
/// having an "incomplete" PUSH instruction at the very end.
template <size_t Len>
inline code_iterator push(StackTop stack, ExecutionState& /*state*/, code_iterator pos) noexcept
{
    // TODO: state access not needed.
    const auto data_pos = pos + 1;
    uint8_t buffer[Len];
    std::memcpy(buffer, data_pos, Len);  // Valid by the assumption code is padded.
    stack.push(intx::be::load<uint256>(buffer));
    return pos + (Len + 1);
}

/// DUP instruction implementation.
/// @tparam N  The number as in the instruction definition, e.g. DUP3 is dup<3>.
template <int N>
inline void dup(StackTop stack) noexcept
{
    static_assert(N >= 1 && N <= 16);
    stack.push(stack[N - 1]);
}

/// SWAP instruction implementation.
/// @tparam N  The number as in the instruction definition, e.g. SWAP3 is swap<3>.
template <int N>
inline void swap(StackTop stack) noexcept
{
    static_assert(N >= 1 && N <= 16);
    std::swap(stack.top(), stack[N]);
}

template <size_t NumTopics>
inline evmc_status_code log(StackTop stack, ExecutionState& state) noexcept
{
    static_assert(NumTopics <= 4);

    if (state.msg->flags & EVMC_STATIC)
        return EVMC_STATIC_MODE_VIOLATION;

    const auto& offset = stack.pop();
    const auto& size = stack.pop();

    if (state.gas_left = check_memory(state, state.gas_left, offset, size); state.gas_left < 0)
        return EVMC_OUT_OF_GAS;

    const auto o = static_cast<size_t>(offset);
    const auto s = static_cast<size_t>(size);

    const auto cost = int64_t(s) * 8;
    if ((state.gas_left -= cost) < 0)
        return EVMC_OUT_OF_GAS;

    std::array<evmc::bytes32, NumTopics> topics;  // NOLINT(cppcoreguidelines-pro-type-member-init)
    for (auto& topic : topics)
        topic = intx::be::store<evmc::bytes32>(stack.pop());

    const auto data = s != 0 ? &state.memory[o] : nullptr;
    state.host.emit_log(state.msg->recipient, data, s, topics.data(), NumTopics);
    return EVMC_SUCCESS;
}


template <evmc_opcode Op>
evmc_status_code call_impl(StackTop stack, ExecutionState& state) noexcept;
inline constexpr auto call = call_impl<OP_CALL>;
inline constexpr auto callcode = call_impl<OP_CALLCODE>;
inline constexpr auto delegatecall = call_impl<OP_DELEGATECALL>;
inline constexpr auto staticcall = call_impl<OP_STATICCALL>;

template <evmc_opcode Op>
evmc_status_code create_impl(StackTop stack, ExecutionState& state) noexcept;
inline constexpr auto create = create_impl<OP_CREATE>;
inline constexpr auto create2 = create_impl<OP_CREATE2>;

template <evmc_status_code StatusCode>
inline StopToken return_impl(StackTop stack, ExecutionState& state) noexcept
{
    const auto& offset = stack[0];
    const auto& size = stack[1];

    if (state.gas_left = check_memory(state, state.gas_left, offset, size); state.gas_left < 0)
        return {EVMC_OUT_OF_GAS};

    state.output_size = static_cast<size_t>(size);
    if (state.output_size != 0)
        state.output_offset = static_cast<size_t>(offset);
    return {StatusCode};
}
inline constexpr auto return_ = return_impl<EVMC_SUCCESS>;
inline constexpr auto revert = return_impl<EVMC_REVERT>;

inline StopToken selfdestruct(StackTop stack, ExecutionState& state) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return {EVMC_STATIC_MODE_VIOLATION};

    const auto beneficiary = intx::be::trunc<evmc::address>(stack[0]);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(beneficiary) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::cold_account_access_cost) < 0)
            return {EVMC_OUT_OF_GAS};
    }

    if (state.rev >= EVMC_TANGERINE_WHISTLE)
    {
        if (state.rev == EVMC_TANGERINE_WHISTLE || state.host.get_balance(state.msg->recipient))
        {
            // After TANGERINE_WHISTLE apply additional cost of
            // sending value to a non-existing account.
            if (!state.host.account_exists(beneficiary))
            {
                if ((state.gas_left -= 25000) < 0)
                    return {EVMC_OUT_OF_GAS};
            }
        }
    }

    state.host.selfdestruct(state.msg->recipient, beneficiary);
    return {EVMC_SUCCESS};
}


/// Maps an opcode to the instruction implementation.
///
/// The set of template specializations which map opcodes `Op` to the function
/// implementing the instruction identified by the opcode.
///     instr::impl<OP_DUP1>(/*...*/);
/// The unspecialized template is invalid and should never to used.
template <evmc_opcode Op>
inline constexpr auto impl = nullptr;

#define X(OPCODE, IDENTIFIER) \
    template <>               \
    inline constexpr auto impl<OPCODE> = IDENTIFIER;  // opcode -> implementation
MAP_OPCODE_TO_IDENTIFIER
#undef X
}  // namespace instr::core
}  // namespace evmone
