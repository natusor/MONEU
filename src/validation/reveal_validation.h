// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_VALIDATION_REVEAL_VALIDATION_H
#define MONEU_VALIDATION_REVEAL_VALIDATION_H

#include "../primitives/leaf_reveal.h"
#include "../primitives/transaction.h"
#include "../storage/utxo_set.h"
#include "../chainparams.h"

#include <map>
#include <string>
#include <vector>

namespace MONEU {
namespace validation {

enum class RevealResult {
    VALID = 0,
    MALFORMED,
    UNKNOWN_TRANSACTION,
    HEIGHT_MISMATCH,
    NOT_YET_ELIGIBLE,
    WINDOW_EXPIRED,
    PROOF_COUNT_MISMATCH,
    INVALID_PROOF,
    LEAF_ALREADY_SPENT,
    DUPLICATE_IN_BLOCK
};

class RevealValidation {
public:
    typedef std::map<std::string, const Transaction*> BlockTxIndex;

    static RevealResult CheckReveal(const LeafReveal& reveal,
                                    uint32_t currentHeight,
                                    const storage::UTXOSet& utxoSet,
                                    std::string& reasonOut,
                                    const BlockTxIndex* blockTxs = NULL);

    static bool CheckBlockReveals(const std::vector<LeafReveal>& reveals,
                                  uint32_t currentHeight,
                                  const storage::UTXOSet& utxoSet,
                                  std::string& reasonOut,
                                  const BlockTxIndex* blockTxs = NULL);

    static BlockTxIndex IndexBlockTransactions(
        const std::vector<Transaction>& txs);

    static bool IsWithinWindow(uint32_t pendingHeight,
                               uint32_t currentHeight);

    static uint32_t ExpiryHeight(uint32_t pendingHeight);

    static const char* ResultToString(RevealResult result);
};

} // namespace validation
} // namespace MONEU

#endif // MONEU_VALIDATION_REVEAL_VALIDATION_H
