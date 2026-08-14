// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "noise_otp.h"
#include <cstring>
#include <stdexcept>
#include <utility>

extern "C" {
    #include "../crypto/sha2.h"
    #include "../crypto/memzero.h"
}

namespace MONEU {

static bytes32 Sha256(const uint8_t* data, size_t len) {
    bytes32 out;
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, data, len);
    sha256_Final(&ctx, out.data());
    memzero(&ctx, sizeof(ctx));
    return out;
}

static bytes32 Sha256Pair(const bytes32& a, const bytes32& b) {
    uint8_t buf[64];
    std::memcpy(buf, a.data(), 32);
    std::memcpy(buf + 32, b.data(), 32);
    bytes32 out = Sha256(buf, 64);
    memzero(buf, sizeof(buf));
    return out;
}

static void WriteLE32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back((uint8_t)(v & 0xFF));
    out.push_back((uint8_t)((v >> 8) & 0xFF));
    out.push_back((uint8_t)((v >> 16) & 0xFF));
    out.push_back((uint8_t)((v >> 24) & 0xFF));
}

static uint32_t ReadLE32(const uint8_t* data, size_t& offset) {
    uint32_t v = (uint32_t)data[offset] |
                 ((uint32_t)data[offset + 1] << 8) |
                 ((uint32_t)data[offset + 2] << 16) |
                 ((uint32_t)data[offset + 3] << 24);
    offset += 4;
    return v;
}

bytes32 BindLeafToTx(const bytes32& leaf, const bytes32& txHash) {
    uint8_t buf[64];
    std::memcpy(buf, leaf.data(), 32);
    std::memcpy(buf + 32, txHash.data(), 32);
    bytes32 out = Sha256(buf, 64);
    memzero(buf, sizeof(buf));
    return out;
}

static bytes32 RootFromPath(const bytes32& commitment,
                            const std::vector<bytes32>& path,
                            const std::vector<uint8_t>& dirs) {
    bytes32 acc = commitment;
    for (size_t i = 0; i < path.size(); ++i) {
        if (dirs[i] == 0) {
            acc = Sha256Pair(acc, path[i]);
        } else {
            acc = Sha256Pair(path[i], acc);
        }
    }
    return acc;
}

size_t NoiseProof::GetSerializedSize() const {
    return 4 + 32 + 32 + 4 +
           merklePath.size() * 32 +
           pathDirs.size();
}

std::vector<uint8_t> NoiseProof::Serialize() const {
    std::vector<uint8_t> data;
    data.reserve(GetSerializedSize());
    WriteLE32(data, leafIndex);
    data.insert(data.end(), leaf.begin(), leaf.end());
    data.insert(data.end(), boundProof.begin(), boundProof.end());
    WriteLE32(data, (uint32_t)merklePath.size());
    for (size_t i = 0; i < merklePath.size(); ++i) {
        data.insert(data.end(), merklePath[i].begin(), merklePath[i].end());
    }
    for (size_t i = 0; i < pathDirs.size(); ++i) {
        data.push_back(pathDirs[i]);
    }
    return data;
}

NoiseProof NoiseProof::Deserialize(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 4 + 32 + 32 + 4 > len) {
        throw CryptoError("NoiseProof: data too short");
    }
    NoiseProof p;
    p.leafIndex = ReadLE32(data, offset);
    std::memcpy(p.leaf.data(), data + offset, 32);
    offset += 32;
    std::memcpy(p.boundProof.data(), data + offset, 32);
    offset += 32;
    uint32_t pathLen = ReadLE32(data, offset);
    if (pathLen > 64) {
        throw CryptoError("NoiseProof: implausible path length");
    }
    if (offset + (size_t)pathLen * 32 + pathLen > len) {
        throw CryptoError("NoiseProof: insufficient data for path");
    }
    p.merklePath.resize(pathLen);
    for (uint32_t i = 0; i < pathLen; ++i) {
        std::memcpy(p.merklePath[i].data(), data + offset, 32);
        offset += 32;
    }
    p.pathDirs.resize(pathLen);
    for (uint32_t i = 0; i < pathLen; ++i) {
        p.pathDirs[i] = data[offset++];
    }
    return p;
}

NoiseFile::NoiseFile() : mNextLeaf(0) {
    mRoot.fill(0);
}

NoiseFile::~NoiseFile() {
    Wipe();
}

NoiseFile::NoiseFile(const NoiseFile& other)
    : mLeaves(other.mLeaves)
    , mLevels(other.mLevels)
    , mRoot(other.mRoot)
    , mNextLeaf(other.mNextLeaf)
{}

NoiseFile::NoiseFile(NoiseFile&& other)
    : mLeaves(std::move(other.mLeaves))
    , mLevels(std::move(other.mLevels))
    , mRoot(other.mRoot)
    , mNextLeaf(other.mNextLeaf)
{
    other.mLeaves.clear();
    other.mLevels.clear();
    other.mRoot.fill(0);
    other.mNextLeaf = 0;
}

NoiseFile& NoiseFile::operator=(NoiseFile&& other) {
    if (this != &other) {
        Wipe();
        mLeaves   = std::move(other.mLeaves);
        mLevels   = std::move(other.mLevels);
        mRoot     = other.mRoot;
        mNextLeaf = other.mNextLeaf;
        other.mLeaves.clear();
        other.mLevels.clear();
        other.mRoot.fill(0);
        other.mNextLeaf = 0;
    }
    return *this;
}

NoiseFile& NoiseFile::operator=(const NoiseFile& other) {
    if (this != &other) {
        Wipe();
        mLeaves   = other.mLeaves;
        mLevels   = other.mLevels;
        mRoot     = other.mRoot;
        mNextLeaf = other.mNextLeaf;
    }
    return *this;
}

void NoiseFile::Wipe() {
    if (!mLeaves.empty()) {
        memzero(mLeaves.data(), mLeaves.size() * sizeof(bytes32));
    }
    for (size_t i = 0; i < mLevels.size(); ++i) {
        if (!mLevels[i].empty()) {
            memzero(mLevels[i].data(), mLevels[i].size() * sizeof(bytes32));
        }
    }
    mLeaves.clear();
    mLevels.clear();
    mRoot.fill(0);
    mNextLeaf = 0;
}

void NoiseFile::BuildTree() {
    mLevels.clear();
    if (mLeaves.empty()) {
        mRoot.fill(0);
        return;
    }

    std::vector<bytes32> level(mLeaves.size());
    for (size_t i = 0; i < mLeaves.size(); ++i) {
        level[i] = Sha256(mLeaves[i].data(), 32);
    }
    mLevels.push_back(std::move(level));

    while (mLevels.back().size() > 1) {
        const std::vector<bytes32>& cur = mLevels.back();
        std::vector<bytes32> next;
        next.reserve((cur.size() + 1) / 2);
        for (size_t i = 0; i < cur.size(); i += 2) {
            const bytes32& left = cur[i];
            const bytes32& right = (i + 1 < cur.size()) ? cur[i + 1] : cur[i];
            next.push_back(Sha256Pair(left, right));
        }
        mLevels.push_back(std::move(next));
    }

    mRoot = mLevels.back()[0];
}

NoiseFile NoiseFile::Generate(const std::vector<uint8_t>& rawNoise, uint32_t leafCount) {
    if (leafCount == 0) {
        throw CryptoError("NoiseFile: leaf count must be positive");
    }
    if (rawNoise.size() < (size_t)leafCount * NOISE_OTP_LEAF_SIZE) {
        throw CryptoError("NoiseFile: not enough physical noise for requested leaves");
    }
    NoiseFile nf;
    nf.mLeaves.resize(leafCount);
    uint8_t buf[36];
    for (uint32_t i = 0; i < leafCount; ++i) {
        std::memcpy(buf, rawNoise.data() + (size_t)i * NOISE_OTP_LEAF_SIZE, 32);
        buf[32] = (uint8_t)(i & 0xFF);
        buf[33] = (uint8_t)((i >> 8) & 0xFF);
        buf[34] = (uint8_t)((i >> 16) & 0xFF);
        buf[35] = (uint8_t)((i >> 24) & 0xFF);
        nf.mLeaves[i] = Sha256(buf, 36);
    }
    memzero(buf, sizeof(buf));
    nf.BuildTree();
    nf.mNextLeaf = 0;
    return nf;
}

void NoiseFile::SetNextLeaf(uint32_t next) {
    if (next > mLeaves.size()) {
        next = (uint32_t)mLeaves.size();
    }
    if (next > mNextLeaf) {
        mNextLeaf = next;
    }
}

NoiseProof NoiseFile::CreateProof(const bytes32& txHash) {
    if (mNextLeaf >= mLeaves.size()) {
        throw CryptoError("NoiseFile: pool exhausted, no leaves left");
    }
    if (mLevels.empty()) {
        throw CryptoError("NoiseFile: tree not built");
    }

    const uint32_t index = mNextLeaf;
    NoiseProof p;
    p.leafIndex = index;
    p.leaf = mLeaves[index];
    p.boundProof = BindLeafToTx(mLeaves[index], txHash);

    p.merklePath.reserve(mLevels.size() - 1);
    p.pathDirs.reserve(mLevels.size() - 1);
    size_t idx = index;
    for (size_t lvl = 0; lvl + 1 < mLevels.size(); ++lvl) {
        const std::vector<bytes32>& cur = mLevels[lvl];
        size_t sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
        if (sibling >= cur.size()) sibling = idx;
        p.merklePath.push_back(cur[sibling]);
        p.pathDirs.push_back((idx % 2 == 0) ? 0 : 1);
        idx /= 2;
    }

    mNextLeaf++;
    return p;
}

bool NoiseFile::VerifyProof(const bytes32& root,
                            const bytes32& txHash,
                            const NoiseProof& proof,
                            uint32_t leafCount) {
    if (leafCount == 0) return false;
    if (proof.leafIndex >= leafCount) return false;
    if (proof.merklePath.size() != proof.pathDirs.size()) return false;

    size_t expectedDepth = 0;
    for (size_t width = leafCount; width > 1; width = (width + 1) / 2) {
        ++expectedDepth;
    }
    if (proof.merklePath.size() != expectedDepth) return false;

    for (size_t i = 0; i < proof.pathDirs.size(); ++i) {
        if (proof.pathDirs[i] > 1) return false;
    }

    bytes32 expectedBound = BindLeafToTx(proof.leaf, txHash);
    if (std::memcmp(expectedBound.data(), proof.boundProof.data(), 32) != 0) {
        return false;
    }

    bytes32 commitment = Sha256(proof.leaf.data(), 32);
    bytes32 computed = RootFromPath(commitment, proof.merklePath, proof.pathDirs);
    return std::memcmp(computed.data(), root.data(), 32) == 0;
}

} // namespace MONEU
