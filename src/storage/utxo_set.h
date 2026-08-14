// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_STORAGE_UTXO_SET_H
#define MONEU_STORAGE_UTXO_SET_H

#include "db_wrapper.h"
#include "../primitives/transaction.h"
#include "../chainparams.h"

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <map>
#include <set>
#include <cstdint>
#include <functional>

#include <boost/filesystem.hpp>

namespace MONEU {
namespace storage {

namespace fs = boost::filesystem;

static const char DB_UTXO      = 'U';
static const char DB_UTXO_BEST = 'u';
static const char DB_UTXO_HEAD = 'h';

static const char DB_NOISE_LEAF = 'N';

static const char DB_PENDING = 'P';

struct OutPoint {
    bytes32  txHash;
    uint32_t index;

    OutPoint() : index(0) { txHash.fill(0); }
    OutPoint(const bytes32& hash, uint32_t idx)
        : txHash(hash), index(idx) {}

    bool operator==(const OutPoint& other) const {
        return txHash == other.txHash && index == other.index;
    }
    bool operator!=(const OutPoint& other) const {
        return !(*this == other);
    }
    bool operator<(const OutPoint& other) const {
        if (txHash != other.txHash) return txHash < other.txHash;
        return index < other.index;
    }
};

struct OutPointHasher {
    size_t operator()(const OutPoint& op) const {
        size_t h1 = 0;
        const uint8_t* data = op.txHash.data();
        for (size_t i = 0; i < 32; i += 8) {
            uint64_t word = 0;
            std::memcpy(&word, data + i, sizeof(word));
            h1 ^= std::hash<uint64_t>{}(word) + 0x9e3779b9 + (h1 << 6) + (h1 >> 2);
        }
        h1 ^= std::hash<uint32_t>{}(op.index) + 0x9e3779b9 + (h1 << 6) + (h1 >> 2);
        return h1;
    }
};

struct NoiseLeafKey {
    bytes32  kps;
    uint32_t leafIndex;

    NoiseLeafKey() : leafIndex(0) { kps.fill(0); }
    NoiseLeafKey(const bytes32& k, uint32_t idx)
        : kps(k), leafIndex(idx) {}

    bool operator==(const NoiseLeafKey& other) const {
        return kps == other.kps && leafIndex == other.leafIndex;
    }
    bool operator<(const NoiseLeafKey& other) const {
        if (kps != other.kps) return kps < other.kps;
        return leafIndex < other.leafIndex;
    }
};

struct Coin {
    int64_t  value;
    bytes32  pubkeyHash;
    uint32_t height;
    bool     isCoinbase;
    bool     isSpent;

    Coin()
        : value(0)
        , height(0)
        , isCoinbase(false)
        , isSpent(false)
    {
        pubkeyHash.fill(0);
    }

    Coin(int64_t val,
         const bytes32& pkHash,
         uint32_t h,
         bool coinbase)
        : value(val)
        , pubkeyHash(pkHash)
        , height(h)
        , isCoinbase(coinbase)
        , isSpent(false)
    {
    }

    bool IsValid() const {
        return !isSpent && value > 0;
    }
};

struct UTXOEntry {
    Coin coin;
    bool isDirty;
    bool isNew;

    UTXOEntry() : isDirty(false), isNew(false) {}
    explicit UTXOEntry(const Coin& c, bool dirty = false, bool isnew = false)
        : coin(c), isDirty(dirty), isNew(isnew) {}
};

using UTXOMap = std::unordered_map<OutPoint, UTXOEntry, OutPointHasher>;

struct PendingSpend {
    Transaction       tx;
    uint32_t          height;
    std::vector<Coin> spentCoins;
    int64_t           fee;

    PendingSpend() : height(0), fee(0) {}

    std::vector<uint8_t> Serialize() const;
    static PendingSpend Deserialize(const uint8_t* data, size_t len);
};

class UTXOSet {
private:
    std::unique_ptr<DBWrapper> mDB;
    mutable std::mutex         mMutex;
    UTXOMap                    mCache;
    size_t                     mCacheSize;
    bytes32                    mBestBlock;

    std::set<NoiseLeafKey>     mSpentLeafCache;
    std::set<NoiseLeafKey>     mSpentLeafDirty;
    std::set<NoiseLeafKey>     mErasedLeafDirty;

    std::map<bytes32, PendingSpend> mPendingCache;
    std::map<OutPoint, bytes32>     mPendingByOutpoint;
    std::set<bytes32>               mPendingDirty;
    std::set<bytes32>               mErasedPendingDirty;

    bool GetCoinLocked(const OutPoint& outpoint, Coin& coin) const;
    bool SpendCoinLocked(const OutPoint& outpoint);
    bool AddCoinLocked(const OutPoint& outpoint, const Coin& coin);

    void IndexPendingLocked(const PendingSpend& pending);
    void UnindexPendingLocked(const PendingSpend& pending);
    bool LoadPendingLocked(const bytes32& txid, PendingSpend& out) const;

    static const size_t DEFAULT_CACHE_ENTRIES = 100000;
    static const size_t MAX_BATCH_SIZE        = 16 * 1024 * 1024;

    bool FlushCache(const bytes32& bestBlock);

    bool IsNoiseLeafSpentLocked(const bytes32& kps, uint32_t leafIndex) const;
    void MarkNoiseLeafSpentLocked(const bytes32& kps, uint32_t leafIndex);
    void UnmarkNoiseLeafSpentLocked(const bytes32& kps, uint32_t leafIndex);

public:
    explicit UTXOSet(const fs::path& dataDir,
                     size_t nCacheSize = DB_DEFAULT_CACHE_SIZE);

    ~UTXOSet();

    UTXOSet(const UTXOSet&) = delete;
    UTXOSet& operator=(const UTXOSet&) = delete;

    bool GetCoin(const OutPoint& outpoint, Coin& coin) const;
    bool HaveCoin(const OutPoint& outpoint) const;
    bool SpendCoin(const OutPoint& outpoint);
    bool AddCoin(const OutPoint& outpoint, const Coin& coin);

    bool ApplyTransaction(const Transaction& tx,
                          uint32_t height,
                          bool isCoinbase,
                          std::vector<Coin>* spentCoinsOut = nullptr);

    bool UndoTransaction(const Transaction& tx,
                         const std::vector<Coin>& spentCoins);

    int64_t GetBalance(const bytes32& pubkeyHash) const;

    std::vector<std::pair<OutPoint, Coin>> GetUTXOsForAddress(
        const bytes32& pubkeyHash) const;

    bool IsNoiseLeafSpent(const bytes32& kps, uint32_t leafIndex) const;
    bool MarkNoiseLeafSpent(const bytes32& kps, uint32_t leafIndex);
    bool UnmarkNoiseLeafSpent(const bytes32& kps, uint32_t leafIndex);

    bool GetHighestSpentNoiseLeaf(const bytes32& kps,
                                  uint32_t& highestOut) const;

    bool AddPendingSpend(const Transaction& tx,
                         uint32_t height,
                         const std::vector<Coin>& spentCoins,
                         int64_t fee);

    bool GetPendingSpend(const bytes32& txid, PendingSpend& out) const;
    bool HasPendingSpend(const bytes32& txid) const;

    bool IsOutpointPending(const OutPoint& outpoint,
                           bytes32* holderTxid = NULL) const;

    bool FinalizePendingSpend(const bytes32& txid);

    bool ReleasePendingSpend(const bytes32& txid);

    bool UnfinalizePendingSpend(const Transaction& tx,
                                uint32_t pendingHeight,
                                const std::vector<Coin>& spentCoins,
                                int64_t fee);

    bool RestorePendingSpend(const Transaction& tx,
                             uint32_t pendingHeight,
                             const std::vector<Coin>& spentCoins,
                             int64_t fee);

    std::vector<bytes32> GetPendingSpendsAtHeight(uint32_t height) const;

    size_t PendingSpendCount() const;

    bytes32 GetBestBlock() const;
    bool SetBestBlock(const bytes32& blockHash);

    bool Flush();
    bool Sync();

    size_t GetCacheSize() const;
    size_t EstimateSize() const;

    void Clear();

#ifdef DEBUG
    bool CheckIntegrity() const;
#endif
};

} // namespace storage
} // namespace MONEU

#endif // MONEU_STORAGE_UTXO_SET_H
