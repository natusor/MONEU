// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "block_validation.h"
#include "reveal_validation.h"
#include "../consensus/pow.h"
#include <iostream>
#include <unordered_set>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace MONEU {
namespace validation {

bool BlockValidation::CheckBlockHeader(
    const BlockHeader& header,
    BlockValidationState& state)
{
    if (header.GetVersion() == 0) {
        state.SetInvalid(
            BlockValidationResult::INVALID_HEADER,
            "Block version is zero");
        return false;
    }
    if (header.GetTimestamp() < NetParams::GENESIS_TIMESTAMP) {
        state.SetInvalid(
            BlockValidationResult::INVALID_HEADER,
            "Block timestamp precedes the genesis block");
        return false;
    }

    if (header.GetTimestamp() == 0) {
        state.SetInvalid(
            BlockValidationResult::INVALID_TIMESTAMP,
            "Block timestamp is zero");
        return false;
    }
    uint64_t now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now()
            .time_since_epoch()).count());
    if (header.GetTimestamp() > now + 7200) {
        state.SetInvalid(
            BlockValidationResult::INVALID_TIMESTAMP,
            "Block timestamp too far in the future");
        return false;
    }
    bool allZeroMerkle = true;
    for (uint8_t b : header.GetMerkleRoot()) {
        if (b != 0) { allZeroMerkle = false; break; }
    }
    if (allZeroMerkle) {
        state.SetInvalid(
            BlockValidationResult::INVALID_MERKLE_ROOT,
            "Block merkle root is zero");
        return false;
    }
    if (!PNC::CheckProofOfWork(header.GetHash(), header.GetBits())) {
        state.SetInvalid(
            BlockValidationResult::INVALID_POW,
            "Proof of work does not satisfy the declared target");
        return false;
    }
    return true;
}

bool BlockValidation::CheckBlockSize(
    const Block& block,
    BlockValidationState& state)
{
    size_t blockSize = block.GetSerializedSize();
    if (blockSize > NetParams::MAX_BLOCK_SIZE) {
        state.SetInvalid(
            BlockValidationResult::INVALID_TOO_LARGE,
            "Block size " +
            std::to_string(blockSize) +
            " exceeds maximum " +
            std::to_string(NetParams::MAX_BLOCK_SIZE));
        return false;
    }
    return true;
}

bool BlockValidation::CheckMerkleRoot(
    const Block& block,
    BlockValidationState& state)
{
    bytes32 computedMerkle = block.ComputeMerkleRoot();
    if (computedMerkle !=
        block.GetHeader().GetMerkleRoot())
    {
        state.SetInvalid(
            BlockValidationResult::INVALID_MERKLE_ROOT,
            "Merkle root mismatch");
        return false;
    }
    return true;
}

bool BlockValidation::CheckBlockTransactions(
    const Block& block,
    BlockValidationState& state)
{
    if (block.GetTransactionCount() == 0) {
        state.SetInvalid(
            BlockValidationResult::INVALID_TRANSACTION,
            "Block has no transactions");
        return false;
    }
    if (!block.GetTransactions()[0].IsCoinbase()) {
        state.SetInvalid(
            BlockValidationResult::INVALID_COINBASE,
            "First transaction must be coinbase");
        return false;
    }
    for (size_t i = 1;
         i < block.GetTransactionCount(); ++i)
    {
        if (block.GetTransactions()[i].IsCoinbase()) {
            state.SetInvalid(
                BlockValidationResult::INVALID_COINBASE,
                "Only first transaction can be "
                "coinbase");
            return false;
        }
        TxValidationState txState;
        if (!TxValidation::CheckTransaction(
                block.GetTransactions()[i], txState))
        {
            state.SetInvalid(
                BlockValidationResult::INVALID_TRANSACTION,
                "Transaction " +
                std::to_string(i) +
                " invalid: " + txState.reason);
            return false;
        }
    }
    return true;
}

bool BlockValidation::CheckDuplicateTransactions(
    const Block& block,
    BlockValidationState& state)
{
    std::unordered_set<std::string> txHashes;
    for (size_t i = 0;
         i < block.GetTransactionCount(); ++i)
    {
        const bytes32& hash =
            block.GetTransactions()[i].GetHash();
        std::string hashStr(
            reinterpret_cast<const char*>(
                hash.data()), 32);
        if (!txHashes.insert(hashStr).second) {
            state.SetInvalid(
                BlockValidationResult::INVALID_DUPLICATE_TX,
                "Duplicate transaction at index " +
                std::to_string(i));
            return false;
        }
    }
    return true;
}

bool BlockValidation::CheckCoinbaseTransaction(
    const Block& block,
    uint32_t height,
    BlockValidationState& state)
{
    if (block.GetTransactionCount() == 0)
        return true;
    const Transaction& coinbase =
        block.GetTransactions()[0];
    if (!coinbase.IsCoinbase()) {
        state.SetInvalid(
            BlockValidationResult::INVALID_COINBASE,
            "First transaction is not coinbase");
        return false;
    }
    int64_t totalCoinbaseOut =
        coinbase.GetValueOut();
    if (totalCoinbaseOut < 0) {
        state.SetInvalid(
            BlockValidationResult::INVALID_COINBASE,
            "Coinbase output value is negative");
        return false;
    }

    (void)height;
    return true;
}

bool BlockValidation::CheckBlock(
    const Block& block,
    BlockValidationState& state)
{
    if (!CheckBlockHeader(
            block.GetHeader(), state)) return false;
    if (!CheckBlockSize(
            block, state))             return false;
    if (!CheckMerkleRoot(
            block, state))             return false;
    if (!CheckBlockTransactions(
            block, state))             return false;
    if (!CheckDuplicateTransactions(
            block, state))             return false;
    return true;
}

bool BlockValidation::CheckBlockTransactionsWithUTXO(
    const Block& block,
    const storage::UTXOSet& utxoSet,
    uint32_t currentHeight,
    BlockValidationState& state)
{
    std::set<std::pair<bytes32, uint32_t>> blockOutpoints;
    std::set<std::pair<bytes32, uint32_t>> blockLeaves;

    uint64_t totalFees = 0;

    for (size_t i = 1;
         i < block.GetTransactionCount(); ++i)
    {
        const Transaction& tx = block.GetTransactions()[i];
        for (size_t in = 0; in < tx.GetInputCount(); ++in) {
            const TxInput& input = tx.GetInputs()[in];
            auto outpoint = std::make_pair(input.GetPrevTxHash(),
                                           input.GetOutputIndex());
            if (!blockOutpoints.insert(outpoint).second) {
                state.SetInvalid(
                    BlockValidationResult::INVALID_TRANSACTION,
                    "Transaction " +
                    std::to_string(i) +
                    " spends an output already spent within this block");
                return false;
            }
        }
        TxValidationState txState;
        if (!TxValidation::CheckTransactionWithUTXO(
                tx,
                utxoSet,
                currentHeight,
                txState))
        {
            state.SetInvalid(
                BlockValidationResult::INVALID_TRANSACTION,
                "Transaction " +
                std::to_string(i) +
                " UTXO check failed: " +
                txState.reason);
            return false;
        }
        if (!TxValidation::VerifyTransactionSignatures(
                tx,
                utxoSet,
                txState,
                &blockLeaves))
        {
            state.SetInvalid(
                BlockValidationResult::INVALID_TRANSACTION,
                "Transaction " +
                std::to_string(i) +
                " signature verification failed: " +
                txState.reason);
            return false;
        }

        uint64_t txIn = 0;
        for (size_t in = 0; in < tx.GetInputCount(); ++in) {
            const TxInput& input = tx.GetInputs()[in];
            storage::OutPoint outpoint(
                input.GetPrevTxHash(),
                input.GetOutputIndex());
            storage::Coin coin;
            if (!utxoSet.GetCoin(outpoint, coin)) {
                state.SetInvalid(
                    BlockValidationResult::INVALID_TRANSACTION,
                    "Transaction " + std::to_string(i) +
                    " input missing during fee accounting");
                return false;
            }
            uint64_t newIn = txIn + static_cast<uint64_t>(coin.value);
            if (newIn < txIn) {
                state.SetInvalid(
                    BlockValidationResult::INVALID_TRANSACTION,
                    "Input value overflow during fee accounting");
                return false;
            }
            txIn = newIn;
        }
        uint64_t txOut = 0;
        for (size_t o = 0; o < tx.GetOutputCount(); ++o) {
            txOut += static_cast<uint64_t>(tx.GetOutputs()[o].GetValue());
        }
        if (txIn < txOut) {
            state.SetInvalid(
                BlockValidationResult::INVALID_TRANSACTION,
                "Transaction " + std::to_string(i) +
                " outputs exceed inputs");
            return false;
        }
    }

    for (size_t r = 0; r < block.GetReveals().size(); ++r) {
        storage::PendingSpend pending;
        if (!utxoSet.GetPendingSpend(block.GetReveals()[r].GetTxid(),
                                     pending)) {
            state.SetInvalid(
                BlockValidationResult::INVALID_TRANSACTION,
                "Reveal " + std::to_string(r) +
                " settles no held transaction");
            return false;
        }
        if (pending.fee < 0) {
            state.SetInvalid(
                BlockValidationResult::INVALID_TRANSACTION,
                "Reveal " + std::to_string(r) +
                " settles a transaction with a negative fee");
            return false;
        }
        const uint64_t fee = static_cast<uint64_t>(pending.fee);
        const uint64_t newTotal = totalFees + fee;
        if (newTotal < totalFees) {
            state.SetInvalid(
                BlockValidationResult::INVALID_TRANSACTION,
                "Accumulated block fees out of range");
            return false;
        }
        totalFees = newTotal;
    }

    const uint64_t subsidy = NetParams::GetBlockSubsidy(currentHeight);
    uint64_t allowed = subsidy + totalFees;
    if (allowed < subsidy) {
        state.SetInvalid(
            BlockValidationResult::INVALID_COINBASE,
            "Block reward overflow (subsidy + fees)");
        return false;
    }
    const Transaction& coinbase = block.GetTransactions()[0];
    int64_t coinbaseOut = coinbase.GetValueOut();
    if (coinbaseOut < 0) {
        state.SetInvalid(
            BlockValidationResult::INVALID_COINBASE,
            "Coinbase output value is negative");
        return false;
    }
    if (static_cast<uint64_t>(coinbaseOut) > allowed) {
        state.SetInvalid(
            BlockValidationResult::INVALID_COINBASE,
            "Coinbase output " + std::to_string(coinbaseOut) +
            " exceeds allowed subsidy plus fees " + std::to_string(allowed));
        return false;
    }

    return true;
}

bool BlockValidation::ValidateBlock(
    const Block& block,
    const storage::UTXOSet& utxoSet,
    uint32_t height,
    BlockValidationState& state)
{
    if (!CheckBlock(block, state)) return false;

    if (!CheckBlockReveals(block, utxoSet, height, state)) return false;

    if (!CheckBlockTransactionsWithUTXO(block, utxoSet, height, state)) {
        return false;
    }

    return true;
}

bool BlockValidation::CheckBlockReveals(
    const Block& block,
    const storage::UTXOSet& utxoSet,
    uint32_t currentHeight,
    BlockValidationState& state)
{
    const std::vector<LeafReveal>& reveals = block.GetReveals();

    if (reveals.size() > Block::MAX_REVEALS) {
        state.SetInvalid(
            BlockValidationResult::INVALID_TRANSACTION,
            "Block carries too many reveals");
        return false;
    }

    if (!(block.ComputeRevealRoot() == block.GetHeader().GetRevealRoot())) {
        state.SetInvalid(
            BlockValidationResult::INVALID_MERKLE_ROOT,
            "Reveal root does not match the reveal section");
        return false;
    }

    if (reveals.empty()) {
        return true;
    }

    std::string why;
    const validation::RevealValidation::BlockTxIndex blockTxs =
        validation::RevealValidation::IndexBlockTransactions(
            block.GetTransactions());

    if (!validation::RevealValidation::CheckBlockReveals(
            reveals, currentHeight, utxoSet, why, &blockTxs)) {
        state.SetInvalid(
            BlockValidationResult::INVALID_TRANSACTION,
            "Reveal section rejected: " + why);
        return false;
    }
    return true;
}

bool BlockValidation::CheckGenesisBlock(
    const Block& block,
    BlockValidationState& state)
{
    if (block.GetTransactionCount() == 0) {
        state.SetInvalid(
            BlockValidationResult::INVALID_GENESIS,
            "Genesis block has no transactions");
        return false;
    }
    if (!block.GetTransactions()[0].IsCoinbase()) {
        state.SetInvalid(
            BlockValidationResult::INVALID_GENESIS,
            "Genesis block first transaction is "
            "not coinbase");
        return false;
    }
    if (block.GetHeader().GetHeight() != 0) {
        state.SetInvalid(
            BlockValidationResult::INVALID_GENESIS,
            "Genesis block height must be zero");
        return false;
    }
    bool allZeroPrev = true;
    for (uint8_t b :
         block.GetHeader().GetPrevBlockHash()) {
        if (b != 0) {
            allZeroPrev = false; break;
        }
    }
    if (!allZeroPrev) {
        state.SetInvalid(
            BlockValidationResult::INVALID_GENESIS,
            "Genesis block prev hash must be zero");
        return false;
    }
    if (block.GetHeader().GetTimestamp() !=
        NetParams::GENESIS_TIMESTAMP)
    {
        state.SetInvalid(
            BlockValidationResult::INVALID_GENESIS,
            "Genesis block timestamp mismatch");
        return false;
    }
    return true;
}

std::string BlockValidation::ResultToString(
    BlockValidationResult result)
{
    switch (result) {
        case BlockValidationResult::VALID:
            return "VALID";
        case BlockValidationResult::INVALID_HEADER:
            return "INVALID_HEADER";
        case BlockValidationResult::INVALID_MERKLE_ROOT:
            return "INVALID_MERKLE_ROOT";
        case BlockValidationResult::INVALID_TIMESTAMP:
            return "INVALID_TIMESTAMP";
        case BlockValidationResult::INVALID_HEIGHT:
            return "INVALID_HEIGHT";
        case BlockValidationResult::INVALID_PREV_HASH:
            return "INVALID_PREV_HASH";
        case BlockValidationResult::INVALID_POW:
            return "INVALID_POW";
        case BlockValidationResult::INVALID_COINBASE:
            return "INVALID_COINBASE";
        case BlockValidationResult::INVALID_TRANSACTION:
            return "INVALID_TRANSACTION";
        case BlockValidationResult::INVALID_TOO_LARGE:
            return "INVALID_TOO_LARGE";
        case BlockValidationResult::INVALID_DUPLICATE_TX:
            return "INVALID_DUPLICATE_TX";
        case BlockValidationResult::INVALID_GENESIS:
            return "INVALID_GENESIS";
        default:
            return "UNKNOWN";
    }
}

} // namespace validation
} // namespace MONEU
