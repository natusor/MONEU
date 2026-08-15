// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "block.h"
#include "../crypto/sha2.h"
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace MONEU {

static void WriteLE32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(value & 0xFF);
    out.push_back((value >> 8) & 0xFF);
    out.push_back((value >> 16) & 0xFF);
    out.push_back((value >> 24) & 0xFF);
}

static void WriteLE64(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        out.push_back((value >> (8 * i)) & 0xFF);
    }
}

static uint32_t ReadLE32(const uint8_t* data, size_t& offset) {
    uint32_t value = (uint32_t)data[offset] |
                     ((uint32_t)data[offset + 1] << 8) |
                     ((uint32_t)data[offset + 2] << 16) |
                     ((uint32_t)data[offset + 3] << 24);
    offset += 4;
    return value;
}

static uint64_t ReadLE64(const uint8_t* data, size_t& offset) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value |= ((uint64_t)data[offset + i]) << (8 * i);
    }
    offset += 8;
    return value;
}

BlockHeader::BlockHeader()
    : mVersion(CURRENT_VERSION)
    , mTimestamp(0)
    , mHeight(0)
    , mBits(0)
    , mNonce(0)
    , mHashCached(false)
{
    mPrevBlockHash.fill(0);
    mMerkleRoot.fill(0);
    mLeafRoot.fill(0);
    mBlockHash.fill(0);
}

BlockHeader::BlockHeader(uint32_t version)
    : mVersion(version)
    , mTimestamp(0)
    , mHeight(0)
    , mBits(0)
    , mNonce(0)
    , mHashCached(false)
{
    mPrevBlockHash.fill(0);
    mMerkleRoot.fill(0);
    mLeafRoot.fill(0);
    mBlockHash.fill(0);
}

void BlockHeader::ComputeHash() const {
    std::vector<uint8_t> data = Serialize();
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, data.data(), data.size());
    sha256_Final(&ctx, const_cast<uint8_t*>(mBlockHash.data()));
    mHashCached = true;
}

const bytes32& BlockHeader::GetHash() const {
    if (!mHashCached) {
        ComputeHash();
    }
    return mBlockHash;
}

bool BlockHeader::IsValid() const {
    if (mVersion == 0) return false;
    if (mTimestamp == 0) return false;
    if (mBits == 0) return false;
    bool allZeroMerkle = true;
    for (uint8_t byte : mMerkleRoot) {
        if (byte != 0) {
            allZeroMerkle = false;
            break;
        }
    }
    if (allZeroMerkle) return false;
    return true;
}

size_t BlockHeader::GetSerializedSize() const {
    return SERIALIZED_SIZE;
}

std::vector<uint8_t> BlockHeader::Serialize() const {
    std::vector<uint8_t> data;
    data.reserve(SERIALIZED_SIZE);
    WriteLE32(data, mVersion);
    data.insert(data.end(), mPrevBlockHash.begin(), mPrevBlockHash.end());
    data.insert(data.end(), mMerkleRoot.begin(), mMerkleRoot.end());
    data.insert(data.end(), mLeafRoot.begin(), mLeafRoot.end());
    WriteLE64(data, mTimestamp);
    WriteLE32(data, mHeight);
    WriteLE32(data, mBits);
    WriteLE32(data, mNonce);
    return data;
}

bool BlockHeader::SerializeTo(uint8_t* out, size_t outLen) const {
    if (out == NULL || outLen < SERIALIZED_SIZE) return false;

    size_t o = 0;
    auto put32 = [&](uint32_t v) {
        out[o++] = (uint8_t)(v      ); out[o++] = (uint8_t)(v >>  8);
        out[o++] = (uint8_t)(v >> 16); out[o++] = (uint8_t)(v >> 24);
    };
    auto put64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) out[o++] = (uint8_t)(v >> (i * 8));
    };
    auto put32b = [&](const bytes32& h) {
        std::memcpy(out + o, h.data(), 32); o += 32;
    };

    put32(mVersion);
    put32b(mPrevBlockHash);
    put32b(mMerkleRoot);
    put32b(mLeafRoot);
    put64(mTimestamp);
    put32(mHeight);
    put32(mBits);
    put32(mNonce);

    return o == SERIALIZED_SIZE;
}

BlockHeader BlockHeader::Deserialize(const uint8_t* data, size_t len) {
    if (len < SERIALIZED_SIZE) {
        throw CryptoError("BlockHeader data too short");
    }
    size_t offset = 0;
    BlockHeader header;
    header.mVersion = ReadLE32(data, offset);
    std::memcpy(header.mPrevBlockHash.data(), data + offset, 32);
    offset += 32;
    std::memcpy(header.mMerkleRoot.data(), data + offset, 32);
    offset += 32;
    std::memcpy(header.mLeafRoot.data(), data + offset, 32);
    offset += 32;
    header.mTimestamp = ReadLE64(data, offset);
    header.mHeight = ReadLE32(data, offset);
    header.mBits = ReadLE32(data, offset);
    header.mNonce = ReadLE32(data, offset);
    header.mHashCached = false;
    return header;
}

BlockHeader BlockHeader::Deserialize(const std::vector<uint8_t>& data) {
    return Deserialize(data.data(), data.size());
}

std::string BlockHeader::ToHex() const {
    std::vector<uint8_t> data = Serialize();
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    return oss.str();
}

BlockHeader BlockHeader::FromHex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw CryptoError("Invalid hex string length");
    }
    std::vector<uint8_t> data;
    data.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        data.push_back(static_cast<uint8_t>(
            std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return Deserialize(data);
}

Block::Block() {}

Block::Block(const BlockHeader& header) : mHeader(header) {}

void Block::AddTransaction(const Transaction& tx) {
    if (mTransactions.size() >= MAX_TRANSACTIONS) {
        throw CryptoError("Block transaction limit exceeded");
    }
    mTransactions.push_back(tx);
}

void Block::ClearTransactions() {
    mTransactions.clear();
}

bytes32 ComputeMerkleRoot(const std::vector<bytes32>& hashes) {
    if (hashes.empty()) {
        bytes32 zero;
        zero.fill(0);
        return zero;
    }
    if (hashes.size() == 1) {
        return hashes[0];
    }
    std::vector<bytes32> level = hashes;
    while (level.size() > 1) {
        std::vector<bytes32> nextLevel;
        for (size_t i = 0; i < level.size(); i += 2) {
            SHA256_CTX ctx;
            sha256_Init(&ctx);
            sha256_Update(&ctx, level[i].data(), level[i].size());
            if (i + 1 < level.size()) {
                sha256_Update(&ctx, level[i + 1].data(), level[i + 1].size());
            } else {
                sha256_Update(&ctx, level[i].data(), level[i].size());
            }
            bytes32 hash;
            sha256_Final(&ctx, hash.data());
            nextLevel.push_back(hash);
        }
        level = nextLevel;
    }
    return level[0];
}

bytes32 Block::ComputeMerkleRoot() const {
    std::vector<bytes32> txHashes;
    txHashes.reserve(mTransactions.size());
    for (const auto& tx : mTransactions) {
        txHashes.push_back(tx.GetHash());
    }
    return MONEU::ComputeMerkleRoot(txHashes);
}

void Block::UpdateMerkleRoot() {
    mHeader.SetMerkleRoot(ComputeMerkleRoot());
}

bytes32 Block::ComputeLeafRoot() const {
    std::vector<bytes32> leafCommitments;
    for (const auto& tx : mTransactions) {
        if (tx.IsCoinbase()) continue;
        for (const auto& input : tx.GetInputs()) {
            const std::vector<uint8_t>& proof = input.GetNoiseProof();
            if (proof.empty()) continue;
            SHA256_CTX ctx;
            sha256_Init(&ctx);
            sha256_Update(&ctx, input.GetKps().data(), 32);
            sha256_Update(&ctx, proof.data(), proof.size());
            bytes32 h;
            sha256_Final(&ctx, h.data());
            leafCommitments.push_back(h);
        }
    }
    return MONEU::ComputeMerkleRoot(leafCommitments);
}

void Block::UpdateLeafRoot() {
    mHeader.SetLeafRoot(ComputeLeafRoot());
}

void Block::UpdateRoots() {
    UpdateMerkleRoot();
    UpdateLeafRoot();
}

bool Block::IsCoinbaseValid() const {
    if (mTransactions.empty()) return false;
    if (!mTransactions[0].IsCoinbase()) return false;
    for (size_t i = 1; i < mTransactions.size(); ++i) {
        if (mTransactions[i].IsCoinbase()) return false;
    }
    return true;
}

bool Block::IsValid() const {
    if (!mHeader.IsValid()) return false;
    if (mTransactions.empty()) return false;
    if (!IsCoinbaseValid()) return false;
    if (!(ComputeMerkleRoot() == mHeader.GetMerkleRoot())) return false;
    if (!(ComputeLeafRoot() == mHeader.GetLeafRoot())) return false;
    if (GetSerializedSize() > NetParams::MAX_BLOCK_SIZE) return false;
    bytes32 computedMerkle = ComputeMerkleRoot();
    if (computedMerkle != mHeader.GetMerkleRoot()) return false;
    for (const auto& tx : mTransactions) {
        if (!tx.IsValid()) return false;
    }
    return true;
}

size_t Block::GetSerializedSize() const {
    size_t size = mHeader.GetSerializedSize();
    size += 4;
    for (const auto& tx : mTransactions) {
        size += 4;
        size += tx.GetSerializedSize();
    }
    return size;
}

std::vector<uint8_t> Block::Serialize() const {
    std::vector<uint8_t> data;
    data.reserve(GetSerializedSize());
    std::vector<uint8_t> headerData = mHeader.Serialize();
    data.insert(data.end(), headerData.begin(), headerData.end());
    WriteLE32(data, static_cast<uint32_t>(mTransactions.size()));
    for (const auto& tx : mTransactions) {
        std::vector<uint8_t> txData = tx.Serialize();
        WriteLE32(data, static_cast<uint32_t>(txData.size()));
        data.insert(data.end(), txData.begin(), txData.end());
    }
    return data;
}

Block Block::Deserialize(const uint8_t* data, size_t len) {
    if (len < BlockHeader::SERIALIZED_SIZE + 4) {
        throw CryptoError("Block data too short");
    }
    Block block;
    block.mHeader = BlockHeader::Deserialize(data, len);
    size_t offset = BlockHeader::SERIALIZED_SIZE;

    uint32_t txCount = ReadLE32(data, offset);
    if (txCount > MAX_TRANSACTIONS) {
        throw CryptoError("Block transaction count implausible");
    }
    block.mTransactions.reserve(txCount);
    for (uint32_t i = 0; i < txCount; i++) {
        if (offset + 4 > len) {
            throw CryptoError("Block truncated at transaction length");
        }
        uint32_t txLen = ReadLE32(data, offset);
        if (txLen == 0 || offset + txLen > len) {
            throw CryptoError("Block truncated inside transaction");
        }
        block.mTransactions.push_back(
            Transaction::Deserialize(data + offset, txLen));
        offset += txLen;
    }

    return block;
}

Block Block::Deserialize(const std::vector<uint8_t>& data) {
    return Deserialize(data.data(), data.size());
}

std::string Block::ToHex() const {
    std::vector<uint8_t> data = Serialize();
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    return oss.str();
}

Block Block::FromHex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw CryptoError("Invalid hex string length");
    }
    std::vector<uint8_t> data;
    data.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        data.push_back(static_cast<uint8_t>(
            std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return Deserialize(data);
}

BlockBuilder::BlockBuilder() : mBlock(Block()) {
}

BlockBuilder::BlockBuilder(uint32_t version) : mBlock(Block()) {
    mBlock.GetMutableHeader().SetVersion(version);
}

BlockBuilder& BlockBuilder::SetPrevBlockHash(const bytes32& hash) {
    mBlock.GetMutableHeader().SetPrevBlockHash(hash);
    return *this;
}

BlockBuilder& BlockBuilder::SetTimestamp(uint64_t timestamp) {
    mBlock.GetMutableHeader().SetTimestamp(timestamp);
    return *this;
}

BlockBuilder& BlockBuilder::SetHeight(uint32_t height) {
    mBlock.GetMutableHeader().SetHeight(height);
    return *this;
}

BlockBuilder& BlockBuilder::SetBits(uint32_t bits) {
    mBlock.GetMutableHeader().SetBits(bits);
    return *this;
}

BlockBuilder& BlockBuilder::SetNonce(uint32_t nonce) {
    mBlock.GetMutableHeader().SetNonce(nonce);
    return *this;
}

BlockBuilder& BlockBuilder::AddTransaction(const Transaction& tx) {
    mBlock.AddTransaction(tx);
    return *this;
}

BlockBuilder& BlockBuilder::AddCoinbase(const Transaction& coinbase) {
    if (!coinbase.IsCoinbase()) {
        throw CryptoError("AddCoinbase called with non-coinbase transaction");
    }
    if (mBlock.GetTransactionCount() != 0) {
        throw CryptoError("Coinbase must be the first transaction");
    }
    mBlock.AddTransaction(coinbase);
    return *this;
}

Block BlockBuilder::Build() {
    mBlock.UpdateRoots();
    return mBlock;
}

Block BlockBuilder::BuildAndFinalize() {
    mBlock.UpdateRoots();
    mBlock.GetHash();
    return mBlock;
}

} // namespace MONEU
