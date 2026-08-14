// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"
#include "../crypto/arith_uint256.h"
#include <cstring>

namespace PNC {

bool CheckProofOfWork(const bytes32& hash, uint32_t bits)
{
    bool fNegative = false;
    bool fOverflow = false;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(bits, &fNegative, &fOverflow);

    arith_uint256 bnPowLimit;
    bnPowLimit.SetCompact(NetParams::POW_LIMIT_COMPACT);

    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > bnPowLimit)
        return false;

    if (ArithFromBytes32(hash) > bnTarget)
        return false;

    return true;
}

uint32_t CalculateNextWorkRequired(uint32_t lastBits,
                                   uint64_t lastBlockTime,
                                   uint64_t firstBlockTime)
{
    const uint64_t idealTimespan = NetParams::POW_TARGET_TIMESPAN;

    int64_t actualTimespan =
        (int64_t)lastBlockTime - (int64_t)firstBlockTime;

    const int64_t minTimespan =
        (int64_t)(idealTimespan * NetParams::POW_MIN_TIMESPAN_PERCENT) / 100;
    const int64_t maxTimespan =
        (int64_t)(idealTimespan * NetParams::POW_MAX_TIMESPAN_PERCENT) / 100;

    if (actualTimespan < minTimespan) actualTimespan = minTimespan;
    if (actualTimespan > maxTimespan) actualTimespan = maxTimespan;

    arith_uint256 bnPowLimit;
    bnPowLimit.SetCompact(NetParams::POW_LIMIT_COMPACT);

    bool negative = false;
    bool overflow = false;
    arith_uint256 bnNew;
    bnNew.SetCompact(lastBits, &negative, &overflow);
    if (negative || overflow || bnNew == 0) {
        return NetParams::POW_LIMIT_COMPACT;
    }

    bnNew *= (uint32_t)actualTimespan;
    bnNew /= arith_uint256((uint64_t)idealTimespan);

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool IsRetargetHeight(uint64_t height)
{
    if (height == 0) return false;
    return (height % NetParams::DIFFICULTY_ADJUSTMENT_INTERVAL) == 0;
}

bytes32 GetBlockProof(uint32_t bits)
{
    bool fNegative = false;
    bool fOverflow = false;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(bits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0) {
        bytes32 zero{};
        return zero;
    }
    arith_uint256 work = (~bnTarget / (bnTarget + 1)) + 1;
    return ArithToBytes32(work);
}

bytes32 AddChainWork(const bytes32& parentWork, uint32_t bits)
{
    arith_uint256 total = ArithFromBytes32(parentWork);
    total += ArithFromBytes32(GetBlockProof(bits));
    return ArithToBytes32(total);
}

int CompareWork(const bytes32& a, const bytes32& b)
{
    return std::memcmp(a.data(), b.data(), 32);
}

bytes32 CompactToTarget(uint32_t bits)
{
    bool fNegative = false;
    bool fOverflow = false;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(bits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0) {
        bytes32 zero{};
        return zero;
    }
    return ArithToBytes32(bnTarget);
}

} // namespace PNC
