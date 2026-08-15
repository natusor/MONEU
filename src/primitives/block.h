// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_PRIMITIVES_BLOCK_H
#define MONEU_PRIMITIVES_BLOCK_H

#include "transaction.h"
#include "keys.h"
#include "../chainparams.h"
#include <vector>
#include <memory>
#include <ctime>

namespace MONEU {

class BlockHeader;
class Block;
using BlockPtr = std::shared_ptr<Block>;

class BlockHeader {
private:
    uint32_t mVersion;
    bytes32 mPrevBlockHash;
    bytes32 mMerkleRoot;
    bytes32 mLeafRoot;
    uint64_t mTimestamp;
    uint32_t mHeight;
    uint32_t mBits;
    uint32_t mNonce;

    mutable bytes32 mBlockHash;
    mutable bool mHashCached;

    void ComputeHash() const;

public:
    static constexpr uint32_t CURRENT_VERSION = 1;
    static constexpr size_t SERIALIZED_SIZE = 4 + 32 + 32 + 32 + 8 + 4 + 4 + 4;

    static constexpr size_t NONCE_OFFSET = 4 + 32 + 32 + 32 + 8 + 4 + 4;

    BlockHeader();
    explicit BlockHeader(uint32_t version);

    uint32_t GetVersion() const { return mVersion; }
    const bytes32& GetPrevBlockHash() const { return mPrevBlockHash; }
    const bytes32& GetMerkleRoot() const { return mMerkleRoot; }
    const bytes32& GetLeafRoot() const { return mLeafRoot; }
    uint64_t GetTimestamp() const { return mTimestamp; }
    uint32_t GetHeight() const { return mHeight; }
    uint32_t GetBits() const { return mBits; }
    uint32_t GetNonce() const { return mNonce; }
    const bytes32& GetHash() const;

    void SetVersion(uint32_t version) { mVersion = version; mHashCached = false; }
    void SetPrevBlockHash(const bytes32& hash) { mPrevBlockHash = hash; mHashCached = false; }
    void SetMerkleRoot(const bytes32& root) { mMerkleRoot = root; mHashCached = false; }
    void SetLeafRoot(const bytes32& root) { mLeafRoot = root; mHashCached = false; }
    void SetTimestamp(uint64_t timestamp) { mTimestamp = timestamp; mHashCached = false; }
    void SetHeight(uint32_t height) { mHeight = height; mHashCached = false; }
    void SetBits(uint32_t bits) { mBits = bits; mHashCached = false; }
    void SetNonce(uint32_t nonce) { mNonce = nonce; mHashCached = false; }

    bool IsValid() const;

    size_t GetSerializedSize() const;
    std::vector<uint8_t> Serialize() const;

    bool SerializeTo(uint8_t* out, size_t outLen) const;
    static BlockHeader Deserialize(const uint8_t* data, size_t len);
    static BlockHeader Deserialize(const std::vector<uint8_t>& data);

    std::string ToHex() const;
    static BlockHeader FromHex(const std::string& hex);
};

class Block {
private:
    BlockHeader mHeader;
    std::vector<Transaction> mTransactions;

public:
    static constexpr size_t MAX_TRANSACTIONS = 10000;

    Block();
    explicit Block(const BlockHeader& header);

    const BlockHeader& GetHeader() const { return mHeader; }
    BlockHeader& GetMutableHeader() { return mHeader; }
    const std::vector<Transaction>& GetTransactions() const { return mTransactions; }

    void SetHeader(const BlockHeader& header) { mHeader = header; }
    void AddTransaction(const Transaction& tx);
    void ClearTransactions();

    size_t GetTransactionCount() const { return mTransactions.size(); }

    bytes32 ComputeMerkleRoot() const;
    void UpdateMerkleRoot();

    bytes32 ComputeLeafRoot() const;
    void UpdateLeafRoot();

    void UpdateRoots();

    bool IsCoinbaseValid() const;
    bool IsValid() const;

    size_t GetSerializedSize() const;
    std::vector<uint8_t> Serialize() const;

    bool SerializeTo(uint8_t* out, size_t outLen) const;
    static Block Deserialize(const uint8_t* data, size_t len);
    static Block Deserialize(const std::vector<uint8_t>& data);

    std::string ToHex() const;
    static Block FromHex(const std::string& hex);

    const bytes32& GetHash() const { return mHeader.GetHash(); }
};

class BlockBuilder {
private:
    Block mBlock;

public:
    BlockBuilder();
    explicit BlockBuilder(uint32_t version);

    BlockBuilder& SetPrevBlockHash(const bytes32& hash);
    BlockBuilder& SetTimestamp(uint64_t timestamp);
    BlockBuilder& SetHeight(uint32_t height);
    BlockBuilder& SetBits(uint32_t bits);
    BlockBuilder& SetNonce(uint32_t nonce);

    BlockBuilder& AddTransaction(const Transaction& tx);
    BlockBuilder& AddCoinbase(const Transaction& coinbase);

    Block Build();
    Block BuildAndFinalize();
};

bytes32 ComputeMerkleRoot(const std::vector<bytes32>& hashes);

} // namespace MONEU

#endif // MONEU_PRIMITIVES_BLOCK_H
