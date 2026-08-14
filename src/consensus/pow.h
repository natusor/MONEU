// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MONEU_CONSENSUS_POW_H
#define MONEU_CONSENSUS_POW_H

#include "../chainparams.h"
#include <cstdint>

namespace PNC {

bool CheckProofOfWork(const bytes32& hash, uint32_t bits);

uint32_t CalculateNextWorkRequired(uint32_t lastBits,
                                   uint64_t lastBlockTime,
                                   uint64_t firstBlockTime);

bool IsRetargetHeight(uint64_t height);

bytes32 CompactToTarget(uint32_t bits);

bytes32 GetBlockProof(uint32_t bits);

bytes32 AddChainWork(const bytes32& parentWork, uint32_t bits);

int CompareWork(const bytes32& a, const bytes32& b);

} // namespace PNC

#endif // MONEU_CONSENSUS_POW_H
