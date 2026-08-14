// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_PRIMITIVES_LEAF_REVEAL_H
#define MONEU_PRIMITIVES_LEAF_REVEAL_H

#include "keys.h"
#include "transaction.h"
#include "../wallet/noise_otp.h"

#include <cstdint>
#include <vector>

namespace MONEU {

class LeafReveal {
private:
    bytes32                 mTxid;
    uint32_t                mHeight;
    std::vector<NoiseProof> mProofs;

    mutable bytes32 mHash;
    mutable bool    mHashComputed;

    void ComputeHash() const;

public:
    static const size_t MAX_PROOFS = Transaction::MAX_INPUTS;

    LeafReveal();
    LeafReveal(const bytes32& txid, uint32_t height);

    const bytes32& GetTxid() const { return mTxid; }
    uint32_t GetHeight() const { return mHeight; }
    const std::vector<NoiseProof>& GetProofs() const { return mProofs; }
    size_t GetProofCount() const { return mProofs.size(); }

    void SetTxid(const bytes32& txid);
    void SetHeight(uint32_t height);
    void AddProof(const NoiseProof& proof);
    void ClearProofs();

    const bytes32& GetHash() const;

    size_t GetSerializedSize() const;
    std::vector<uint8_t> Serialize() const;

    static LeafReveal Deserialize(const uint8_t* data,
                                  size_t len,
                                  size_t& offset);

    bool IsWellFormed() const;
};

bytes32 ComputeRevealRoot(const std::vector<LeafReveal>& reveals);

} // namespace MONEU

#endif // MONEU_PRIMITIVES_LEAF_REVEAL_H
