// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "reveal_validation.h"
#include "../wallet/noise_otp.h"

#include <set>
#include <sstream>
#include <string>

namespace MONEU {
namespace validation {

namespace {

std::string LeafKey(const bytes32& kps, uint32_t leafIndex) {
    std::string key;
    key.reserve(32 + 4);
    key.append(reinterpret_cast<const char*>(kps.data()), kps.size());
    for (int b = 0; b < 4; ++b) {
        key.push_back(static_cast<char>((leafIndex >> (8 * b)) & 0xFF));
    }
    return key;
}

std::string TxidKey(const bytes32& txid) {
    return std::string(reinterpret_cast<const char*>(txid.data()),
                       txid.size());
}

} // namespace

bool RevealValidation::IsWithinWindow(uint32_t pendingHeight,
                                      uint32_t currentHeight) {
    if (pendingHeight >= currentHeight) return false;
    return (currentHeight - pendingHeight) <= NetParams::REVEAL_WINDOW_BLOCKS;
}

uint32_t RevealValidation::ExpiryHeight(uint32_t pendingHeight) {
    return pendingHeight + NetParams::REVEAL_WINDOW_BLOCKS + 1;
}

RevealValidation::BlockTxIndex RevealValidation::IndexBlockTransactions(
    const std::vector<Transaction>& txs)
{
    BlockTxIndex index;
    for (size_t i = 0; i < txs.size(); ++i) {
        if (txs[i].IsCoinbase()) continue;
        const bytes32 h = txs[i].GetHash();
        index[std::string(reinterpret_cast<const char*>(h.data()), 32)] =
            &txs[i];
    }
    return index;
}

RevealResult RevealValidation::CheckReveal(const LeafReveal& reveal,
                                           uint32_t currentHeight,
                                           const storage::UTXOSet& utxoSet,
                                           std::string& reasonOut,
                                           const BlockTxIndex* blockTxs) {
    if (!reveal.IsWellFormed()) {
        reasonOut = "reveal is malformed";
        return RevealResult::MALFORMED;
    }

    storage::PendingSpend pending;
    bool fromThisBlock = false;

    if (!utxoSet.GetPendingSpend(reveal.GetTxid(), pending)) {
        const Transaction* inBlock = NULL;
        if (blockTxs != NULL) {
            const std::string key(
                reinterpret_cast<const char*>(reveal.GetTxid().data()), 32);
            BlockTxIndex::const_iterator it = blockTxs->find(key);
            if (it != blockTxs->end()) inBlock = it->second;
        }
        if (inBlock == NULL) {
            reasonOut = "no transaction is awaiting leaves under this id, "
                        "and none in this block carries it";
            return RevealResult::UNKNOWN_TRANSACTION;
        }
        pending.tx     = *inBlock;
        pending.height = currentHeight;
        fromThisBlock  = true;
    }

    if (fromThisBlock && reveal.GetHeight() == 0) {
    } else if (reveal.GetHeight() != pending.height) {
        std::ostringstream oss;
        oss << "reveal names height " << reveal.GetHeight()
            << " but the transaction is held at " << pending.height;
        reasonOut = oss.str();
        return RevealResult::HEIGHT_MISMATCH;
    }

    if (pending.height > currentHeight) {
        std::ostringstream oss;
        oss << "a reveal cannot authorise a transaction from a later block: "
            << "names height " << pending.height
            << ", carried at " << currentHeight;
        reasonOut = oss.str();
        return RevealResult::NOT_YET_ELIGIBLE;
    }

    (void)fromThisBlock;
    if (pending.height != currentHeight &&
        !IsWithinWindow(pending.height, currentHeight)) {
        std::ostringstream oss;
        oss << "reveal window closed: transaction held at "
            << pending.height << ", current height " << currentHeight
            << ", window " << NetParams::REVEAL_WINDOW_BLOCKS << " blocks";
        reasonOut = oss.str();
        return RevealResult::WINDOW_EXPIRED;
    }

    const std::vector<TxInput>& inputs = pending.tx.GetInputs();
    if (reveal.GetProofCount() != inputs.size()) {
        std::ostringstream oss;
        oss << "reveal carries " << reveal.GetProofCount()
            << " proofs for " << inputs.size() << " inputs";
        reasonOut = oss.str();
        return RevealResult::PROOF_COUNT_MISMATCH;
    }

    const std::vector<NoiseProof>& proofs = reveal.GetProofs();
    std::set<std::string> seenHere;
    for (size_t i = 0; i < inputs.size(); ++i) {
        const bytes32& kps = inputs[i].GetKps();

        if (!NoiseFile::VerifyProof(kps, reveal.GetTxid(), proofs[i],
                                    NetParams::NOISE_LEAF_COUNT)) {
            std::ostringstream oss;
            oss << "proof for input " << i << " does not verify";
            reasonOut = oss.str();
            return RevealResult::INVALID_PROOF;
        }

        if (utxoSet.IsNoiseLeafSpent(kps, proofs[i].leafIndex)) {
            std::ostringstream oss;
            oss << "leaf " << proofs[i].leafIndex
                << " for input " << i << " is already consumed";
            reasonOut = oss.str();
            return RevealResult::LEAF_ALREADY_SPENT;
        }

        if (!seenHere.insert(LeafKey(kps, proofs[i].leafIndex)).second) {
            std::ostringstream oss;
            oss << "leaf " << proofs[i].leafIndex
                << " is used by more than one input";
            reasonOut = oss.str();
            return RevealResult::DUPLICATE_IN_BLOCK;
        }
    }

    return RevealResult::VALID;
}

bool RevealValidation::CheckBlockReveals(
    const std::vector<LeafReveal>& reveals,
    uint32_t currentHeight,
    const storage::UTXOSet& utxoSet,
    std::string& reasonOut,
    const BlockTxIndex* blockTxs) {

    std::set<std::string> seenTxids;
    std::set<std::string> seenLeaves;

    for (size_t r = 0; r < reveals.size(); ++r) {
        const LeafReveal& reveal = reveals[r];

        const RevealResult result =
            CheckReveal(reveal, currentHeight, utxoSet, reasonOut, blockTxs);
        if (result != RevealResult::VALID) {
            std::ostringstream oss;
            oss << "reveal " << r << ": " << reasonOut
                << " (" << ResultToString(result) << ")";
            reasonOut = oss.str();
            return false;
        }

        if (!seenTxids.insert(TxidKey(reveal.GetTxid())).second) {
            std::ostringstream oss;
            oss << "reveal " << r
                << ": the block already settles this transaction";
            reasonOut = oss.str();
            return false;
        }

        storage::PendingSpend pending;
        const Transaction* txPtr = NULL;
        if (utxoSet.GetPendingSpend(reveal.GetTxid(), pending)) {
            txPtr = &pending.tx;
        } else if (blockTxs != NULL) {
            const std::string key(
                reinterpret_cast<const char*>(reveal.GetTxid().data()), 32);
            BlockTxIndex::const_iterator it = blockTxs->find(key);
            if (it != blockTxs->end()) txPtr = it->second;
        }
        if (txPtr == NULL) {
            std::ostringstream oss;
            oss << "reveal " << r << ": transaction vanished mid-check";
            reasonOut = oss.str();
            return false;
        }
        const std::vector<TxInput>& inputs = txPtr->GetInputs();
        const std::vector<NoiseProof>& proofs = reveal.GetProofs();
        for (size_t i = 0; i < inputs.size() && i < proofs.size(); ++i) {
            const std::string key =
                LeafKey(inputs[i].GetKps(), proofs[i].leafIndex);
            if (!seenLeaves.insert(key).second) {
                std::ostringstream oss;
                oss << "reveal " << r << ": leaf " << proofs[i].leafIndex
                    << " is already consumed earlier in this block";
                reasonOut = oss.str();
                return false;
            }
        }
    }
    return true;
}

const char* RevealValidation::ResultToString(RevealResult result) {
    switch (result) {
        case RevealResult::VALID:                return "VALID";
        case RevealResult::MALFORMED:            return "MALFORMED";
        case RevealResult::UNKNOWN_TRANSACTION:  return "UNKNOWN_TRANSACTION";
        case RevealResult::HEIGHT_MISMATCH:      return "HEIGHT_MISMATCH";
        case RevealResult::NOT_YET_ELIGIBLE:     return "NOT_YET_ELIGIBLE";
        case RevealResult::WINDOW_EXPIRED:       return "WINDOW_EXPIRED";
        case RevealResult::PROOF_COUNT_MISMATCH: return "PROOF_COUNT_MISMATCH";
        case RevealResult::INVALID_PROOF:        return "INVALID_PROOF";
        case RevealResult::LEAF_ALREADY_SPENT:   return "LEAF_ALREADY_SPENT";
        case RevealResult::DUPLICATE_IN_BLOCK:   return "DUPLICATE_IN_BLOCK";
    }
    return "UNKNOWN";
}

} // namespace validation
} // namespace MONEU
