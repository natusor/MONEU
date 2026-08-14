// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "leaf_reveal.h"

#include <cstring>
#include <set>
#include <string>

extern "C" {
    #include "../crypto/sha2.h"
    #include "../crypto/memzero.h"
}

namespace MONEU {

namespace {

void WriteLE32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

uint32_t ReadLE32(const uint8_t* data, size_t& offset) {
    uint32_t v = static_cast<uint32_t>(data[offset]) |
                 (static_cast<uint32_t>(data[offset + 1]) << 8) |
                 (static_cast<uint32_t>(data[offset + 2]) << 16) |
                 (static_cast<uint32_t>(data[offset + 3]) << 24);
    offset += 4;
    return v;
}

bytes32 Sha256Pair(const bytes32& a, const bytes32& b) {
    uint8_t buf[64];
    std::memcpy(buf, a.data(), 32);
    std::memcpy(buf + 32, b.data(), 32);
    bytes32 out;
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, buf, 64);
    sha256_Final(&ctx, out.data());
    memzero(&ctx, sizeof(ctx));
    memzero(buf, sizeof(buf));
    return out;
}

// Key identifying one consumed leaf: the KPS the proof belongs to is not
// carried by the proof itself, so within a single reveal the leaf index is
// enough to spot a repeat. All proofs in one reveal authorise inputs of the
// same transaction and a wallet has one KPS.
std::string LeafKey(const NoiseProof& p) {
    std::string key;
    key.reserve(32 + 4);
    key.append(reinterpret_cast<const char*>(p.leaf.data()), p.leaf.size());
    for (int b = 0; b < 4; ++b) {
        key.push_back(static_cast<char>((p.leafIndex >> (8 * b)) & 0xFF));
    }
    return key;
}

} // namespace

LeafReveal::LeafReveal()
    : mHeight(0)
    , mHashComputed(false)
{
    mTxid.fill(0);
    mHash.fill(0);
}

LeafReveal::LeafReveal(const bytes32& txid, uint32_t height)
    : mTxid(txid)
    , mHeight(height)
    , mHashComputed(false)
{
    mHash.fill(0);
}

void LeafReveal::SetTxid(const bytes32& txid) {
    mTxid = txid;
    mHashComputed = false;
}

void LeafReveal::SetHeight(uint32_t height) {
    mHeight = height;
    mHashComputed = false;
}

void LeafReveal::AddProof(const NoiseProof& proof) {
    mProofs.push_back(proof);
    mHashComputed = false;
}

void LeafReveal::ClearProofs() {
    mProofs.clear();
    mHashComputed = false;
}

void LeafReveal::ComputeHash() const {
    std::vector<uint8_t> data = Serialize();
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, data.data(), static_cast<uint32_t>(data.size()));
    sha256_Final(&ctx, mHash.data());
    memzero(&ctx, sizeof(ctx));
    mHashComputed = true;
}

const bytes32& LeafReveal::GetHash() const {
    if (!mHashComputed) {
        ComputeHash();
    }
    return mHash;
}

size_t LeafReveal::GetSerializedSize() const {
    size_t size = 32 + 4 + 4;   // txid, height, proof count
    for (size_t i = 0; i < mProofs.size(); ++i) {
        size += 4;                                  // per-proof length
        size += mProofs[i].GetSerializedSize();
    }
    return size;
}

std::vector<uint8_t> LeafReveal::Serialize() const {
    std::vector<uint8_t> data;
    data.reserve(GetSerializedSize());

    data.insert(data.end(), mTxid.begin(), mTxid.end());
    WriteLE32(data, mHeight);
    WriteLE32(data, static_cast<uint32_t>(mProofs.size()));

    // Each proof is length-prefixed so the record can be walked without
    // parsing every proof, and so a malformed proof cannot run past the
    // end of the record into the next one.
    for (size_t i = 0; i < mProofs.size(); ++i) {
        std::vector<uint8_t> proofData = mProofs[i].Serialize();
        WriteLE32(data, static_cast<uint32_t>(proofData.size()));
        data.insert(data.end(), proofData.begin(), proofData.end());
    }
    return data;
}

LeafReveal LeafReveal::Deserialize(const uint8_t* data,
                                   size_t len,
                                   size_t& offset) {
    if (data == NULL) {
        throw CryptoError("LeafReveal: no data");
    }
    // Fixed part: txid, height, proof count.
    if (offset > len || len - offset < 32 + 4 + 4) {
        throw CryptoError("LeafReveal: data too short");
    }

    LeafReveal reveal;
    std::memcpy(reveal.mTxid.data(), data + offset, 32);
    offset += 32;
    reveal.mHeight = ReadLE32(data, offset);

    const uint32_t proofCount = ReadLE32(data, offset);
    // Checked before reserving, so a forged count cannot make this
    // allocate on the strength of a number a peer chose.
    if (proofCount == 0) {
        throw CryptoError("LeafReveal: no proofs");
    }
    if (proofCount > MAX_PROOFS) {
        throw CryptoError("LeafReveal: too many proofs");
    }

    reveal.mProofs.reserve(proofCount);
    for (uint32_t i = 0; i < proofCount; ++i) {
        if (offset > len || len - offset < 4) {
            throw CryptoError("LeafReveal: truncated proof length");
        }
        const uint32_t proofLen = ReadLE32(data, offset);
        if (offset > len || len - offset < proofLen) {
            throw CryptoError("LeafReveal: truncated proof");
        }
        // Parse inside the declared span only, then step over exactly that
        // span. A proof claiming a shorter or longer body than it uses
        // cannot shift the position of the proofs that follow.
        size_t inner = 0;
        NoiseProof proof =
            NoiseProof::Deserialize(data + offset, proofLen, inner);
        if (inner != proofLen) {
            throw CryptoError("LeafReveal: proof length mismatch");
        }
        offset += proofLen;
        reveal.mProofs.push_back(proof);
    }

    reveal.mHashComputed = false;
    return reveal;
}

bool LeafReveal::IsWellFormed() const {
    if (mProofs.empty()) return false;
    if (mProofs.size() > MAX_PROOFS) return false;

    // A transaction hash is never all zeroes, so this catches an empty or
    // uninitialised record before it reaches validation.
    bool allZero = true;
    for (size_t i = 0; i < mTxid.size(); ++i) {
        if (mTxid[i] != 0) { allZero = false; break; }
    }
    if (allZero) return false;

    // One leaf may authorise one input. A record listing the same leaf
    // twice would consume a single-use value twice over.
    std::set<std::string> seen;
    for (size_t i = 0; i < mProofs.size(); ++i) {
        const NoiseProof& p = mProofs[i];
        if (p.merklePath.size() != p.pathDirs.size()) return false;
        for (size_t d = 0; d < p.pathDirs.size(); ++d) {
            if (p.pathDirs[d] > 1) return false;
        }
        if (!seen.insert(LeafKey(p)).second) return false;
    }
    return true;
}

bytes32 ComputeRevealRoot(const std::vector<LeafReveal>& reveals) {
    bytes32 root;
    root.fill(0);
    if (reveals.empty()) {
        return root;   // a block with no reveals commits to zero
    }

    std::vector<bytes32> level;
    level.reserve(reveals.size());
    for (size_t i = 0; i < reveals.size(); ++i) {
        level.push_back(reveals[i].GetHash());
    }

    while (level.size() > 1) {
        std::vector<bytes32> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const bytes32& left = level[i];
            const bytes32& right =
                (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(Sha256Pair(left, right));
        }
        level.swap(next);
    }
    return level[0];
}

}
