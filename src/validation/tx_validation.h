// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_VALIDATION_TX_VALIDATION_H
#define MONEU_VALIDATION_TX_VALIDATION_H

#include "../primitives/transaction.h"
#include "../primitives/keys.h"
#include "../storage/utxo_set.h"
#include "../chainparams.h"

#include <string>
#include <vector>
#include <set>
#include <utility>
#include <cstdint>
#include <stdexcept>

namespace MONEU {
namespace validation {

enum class TxValidationResult {
    VALID,
    INVALID_EMPTY_INPUTS,
    INVALID_EMPTY_OUTPUTS,
    INVALID_TOO_LARGE,
    INVALID_DUST_OUTPUT,
    INVALID_NEGATIVE_VALUE,
    INVALID_VALUE_OVERFLOW,
    INVALID_COINBASE_SIZE,
    INVALID_DOUBLE_SPEND,
    INVALID_MISSING_INPUT,
    INVALID_INSUFFICIENT_FEE,
    INVALID_BAD_SIGNATURE,
    INVALID_COINBASE_MATURITY,
    INVALID_MONEY_RANGE,
    INVALID_NOISE_PROOF,
    INVALID_SCRIPT
};

struct TxValidationState {
    TxValidationResult result;
    std::string        reason;
    bool               valid;

    TxValidationState()
        : result(TxValidationResult::VALID)
        , valid(true)
    {}

    void SetInvalid(TxValidationResult r, const std::string& msg) {
        result = r;
        reason = msg;
        valid  = false;
    }

    bool IsValid() const { return valid; }
};

class TxValidation {
private:
    static bool CheckTxOutputs(const Transaction& tx,
                                TxValidationState& state);

    static bool CheckTxInputs(const Transaction& tx,
                               TxValidationState& state);

    static bool CheckTxSize(const Transaction& tx,
                             TxValidationState& state);

    static bool CheckCoinbase(const Transaction& tx,
                               TxValidationState& state);

    static bool CheckMoneyRange(int64_t value,
                                TxValidationState& state);

public:
    static bool CheckTransaction(const Transaction& tx,
                                  TxValidationState& state);

    static bool CheckTransactionWithUTXO(
        const Transaction& tx,
        const storage::UTXOSet& utxoSet,
        uint32_t currentHeight,
        TxValidationState& state);

    static bool VerifyTransactionSignatures(
        const Transaction& tx,
        const storage::UTXOSet& utxoSet,
        TxValidationState& state,
        std::set<std::pair<bytes32, uint32_t>>* usedLeaves = nullptr);

    static bool CheckFee(const Transaction& tx,
                          const storage::UTXOSet& utxoSet,
                          int64_t minFee,
                          TxValidationState& state);

    static int64_t GetMinimumFee(const Transaction& tx);

    static std::string ResultToString(TxValidationResult result);
};

} // namespace validation
} // namespace MONEU

#endif // MONEU_VALIDATION_TX_VALIDATION_H
