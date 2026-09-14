// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_WALLET_NOISE_OTP_H
#define MONEU_WALLET_NOISE_OTP_H

#include "../chainparams.h"
#include "../primitives/keys.h"
#include <cstdint>
#include <vector>
#include <string>

namespace MONEU {

using PNC::bytes32;

static const size_t NOISE_OTP_LEAF_SIZE = 32;

static const uint32_t NOISE_OTP_LEAF_COUNT =
    NetParams::NOISE_LEAF_COUNT_VALUE;

struct NoiseProof {
    uint32_t leafIndex;
    bytes32  leaf;
    bytes32  boundProof;
    std::vector<bytes32> merklePath;
    std::vector<uint8_t> pathDirs;

    size_t GetSerializedSize() const;
    std::vector<uint8_t> Serialize() const;
    static NoiseProof Deserialize(const uint8_t* data, size_t len, size_t& offset);
};

class NoiseFile {
private:
    std::vector<bytes32> mLeaves;
    std::vector<std::vector<bytes32> > mLevels;
    bytes32 mRoot;
    uint32_t mNextLeaf;
    std::vector<uint8_t> mUsed;

    void BuildTree();
    void Wipe();

public:
    NoiseFile();
    ~NoiseFile();
    NoiseFile(const NoiseFile& other);
    NoiseFile& operator=(const NoiseFile& other);

    NoiseFile(NoiseFile&& other);
    NoiseFile& operator=(NoiseFile&& other);

    static NoiseFile Generate(const std::vector<uint8_t>& rawNoise,
                              uint32_t leafCount);

    const bytes32& GetRoot() const { return mRoot; }
    uint32_t GetLeafCount() const { return (uint32_t)mLeaves.size(); }
    uint32_t GetNextLeaf() const { return mNextLeaf; }

    void SetNextLeaf(uint32_t next);
    uint32_t GetRemaining() const { return (uint32_t)mLeaves.size() - mNextLeaf; }

    NoiseProof CreateProof(const bytes32& txHash);
    NoiseProof CreateProofAt(uint32_t index, const bytes32& txHash) const;

    bool IsLeafUsed(uint32_t index) const;
    void MarkLeafUsed(uint32_t index);
    uint32_t CountUsed() const;
    const std::vector<uint8_t>& GetUsedMap() const { return mUsed; }
    void SetUsedMap(const std::vector<uint8_t>& map);

    static bool VerifyProof(const bytes32& root,
                            const bytes32& txHash,
                            const NoiseProof& proof,
                            uint32_t leafCount);
};

bytes32 BindLeafToTx(const bytes32& leaf, const bytes32& txHash);

std::vector<uint32_t> DeriveLeafIndices(const bytes32& txHash,
                                        const bytes32& kps,
                                        uint32_t count,
                                        uint32_t leafCount);

} // namespace MONEU

#endif // MONEU_WALLET_NOISE_OTP_H
