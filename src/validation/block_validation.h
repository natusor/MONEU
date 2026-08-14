// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_VALIDATION_BLOCK_VALIDATION_H
#define MONEU_VALIDATION_BLOCK_VALIDATION_H

#include "tx_validation.h"
#include "../primitives/block.h"
#include "../primitives/transaction.h"
#include "../storage/chain_state.h"
#include "../consensus/pow.h"
#include "../chainparams.h"

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace MONEU {
namespace validation {

enum class BlockValidationResult {
    VALID,
    INVALID_HEADER,
    INVALID_MERKLE_ROOT,
    INVALID_TIMESTAMP,
    INVALID_HEIGHT,
    INVALID_PREV_HASH,
    INVALID_POW,
    INVALID_COINBASE,
    INVALID_TRANSACTION,
    INVALID_TOO_LARGE,
    INVALID_DUPLICATE_TX,
    INVALID_GENESIS
};

struct BlockValidationState {
    BlockValidationResult result;
    std::string           reason;
    bool                  valid;

    BlockValidationState()
        : result(BlockValidationResult::VALID)
        , valid(true)
    {}

    void SetInvalid(BlockValidationResult r, const std::string& msg) {
        result = r;
        reason = msg;
        valid  = false;
    }

    bool IsValid() const { return valid; }
};

class BlockValidation {
private:
    static bool CheckBlockHeader(
        const BlockHeader& header,
        BlockValidationState& state);

    static bool CheckBlockSize(
        const Block& block,
        BlockValidationState& state);

    static bool CheckMerkleRoot(
        const Block& block,
        BlockValidationState& state);

    static bool CheckBlockTransactions(
        const Block& block,
        BlockValidationState& state);

    static bool CheckDuplicateTransactions(
        const Block& block,
        BlockValidationState& state);

public:
    static bool ValidateBlock(
        const Block& block,
        const storage::UTXOSet& utxoSet,
        uint32_t height,
        BlockValidationState& state);

    static bool CheckBlock(
        const Block& block,
        BlockValidationState& state);

    static bool CheckCoinbaseTransaction(
        const Block& block,
        uint32_t height,
        BlockValidationState& state);

    static bool CheckBlockTransactionsWithUTXO(
        const Block& block,
        const storage::UTXOSet& utxoSet,
        uint32_t currentHeight,
        BlockValidationState& state);

    static bool CheckBlockReveals(
        const Block& block,
        const storage::UTXOSet& utxoSet,
        uint32_t currentHeight,
        BlockValidationState& state);

    static bool CheckGenesisBlock(
        const Block& block,
        BlockValidationState& state);

    static std::string ResultToString(BlockValidationResult result);
};

} // namespace validation
} // namespace MONEU

#endif // MONEU_VALIDATION_BLOCK_VALIDATION_H
