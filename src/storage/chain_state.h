// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_STORAGE_CHAIN_STATE_H
#define MONEU_STORAGE_CHAIN_STATE_H

#include "db_wrapper.h"
#include "block_data.h"
#include "block_undo.h"
#include "utxo_set.h"
#include "../primitives/block.h"
#include "../primitives/transaction.h"
#include "../chainparams.h"

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <cstdint>

#include <boost/filesystem.hpp>

namespace MONEU {
namespace storage {

namespace fs = boost::filesystem;

static const char DB_CHAIN_HEIGHT   = 'H';
static const char DB_CHAIN_BEST     = 'B';
static const char DB_CHAIN_GENESIS  = 'G';

struct ChainTip {
    bytes32  blockHash;
    uint32_t height;
    uint64_t timestamp;
    uint32_t bits;
    bytes32  chainWork;

    ChainTip()
        : height(0)
        , timestamp(0)
        , bits(0)
    {
        blockHash.fill(0);
        chainWork.fill(0);
    }
};

class ChainState {
private:
    std::unique_ptr<DBWrapper> mDB;
    std::unique_ptr<BlockData> mBlockData;
    std::unique_ptr<UTXOSet>   mUTXOSet;

    mutable std::mutex         mMutex;

    ChainTip                   mBestChain;
    bool                       mInitialized;

    bool LoadBestChain();
    bool VerifyGenesisBlock() const;

    bool InitializeGenesisLocked();

    bool GetBlockHashByHeightLocked(uint32_t height, bytes32& hashOut) const;

    bool ReplayBlocksLocked();
    bool RollforwardBlockLocked(const bytes32& blockHash, uint32_t height);
    bool RollbackBlockLocked(const bytes32& blockHash, uint32_t height);
    bool LastCommonAncestorLocked(const bytes32& a, const bytes32& b,
                                  bytes32& out) const;
    bool AncestorPathLocked(const bytes32& from, const bytes32& to,
                            std::vector<bytes32>& out) const;

    bool ApplyBlockTwoPhase(const Block& block,
                            uint32_t height,
                            BlockUndo* undoOut);
    bool UndoBlockTwoPhase(const Block& block,
                           const BlockUndo& undo);

    bool ApplyBlockTransactions(const Block& block,
                                BlockUndo* undoOut = nullptr);

    bool UndoBlockTransactions(
        const Block& block,
        const BlockUndo& undo);

    bool ConnectBlockLocked(const Block& block);
    bool DisconnectTipLocked();
    bool ActivateBestChainLocked(const bytes32& newTipHash);
    void RollbackConnectedLocked(const std::vector<bytes32>& connected);
    bool IsOnActiveChainLocked(const bytes32& blockHash) const;

    std::vector<Transaction> mSyncConnected;
    std::vector<Transaction> mSyncDisconnected;
    size_t                   mSyncDisconnectedBytes;

    static const size_t MAX_DISCONNECTED_TX_BYTES = 20u * 1000u * 1000u;

    void QueueConnectedLocked(const Block& block);
    void QueueDisconnectedLocked(const Block& block);

    uint64_t GetMedianTimePastLocked(const bytes32& blockHash) const;

    static const size_t MEDIAN_TIME_SPAN = 11;

    uint32_t GetExpectedBitsLocked(uint32_t height) const;

public:
    explicit ChainState(
        const fs::path& dataDir,
        size_t nCacheSize = DB_DEFAULT_CACHE_SIZE);

    ~ChainState() = default;

    ChainState(const ChainState&) = delete;
    ChainState& operator=(const ChainState&) = delete;

    bool Initialize();
    bool IsInitialized() const { return mInitialized; }

    bool ConnectBlock(const Block& block);

    bool DisconnectBlock(const bytes32& blockHash);

    bool AcceptBlock(const Block& block);

    void TakeMempoolSync(std::vector<Transaction>& connectedOut,
                         std::vector<Transaction>& disconnectedOut);

    bool HasBlock(const bytes32& blockHash) const;
    bool GetBlock(Block& block,
                  const bytes32& blockHash) const;

    bool GetTransaction(const bytes32& txid,
                        Transaction& txOut,
                        bytes32* blockHashOut = nullptr,
                        uint32_t* heightOut = nullptr) const;

    ChainTip GetBestChain() const;
    uint32_t GetHeight() const;
    bytes32  GetBestBlockHash() const;

    uint32_t GetNextBits() const;

    uint64_t GetMedianTimePast() const;

    bool GetBlockIndexEntry(const bytes32& blockHash,
                            BlockIndexEntry& entry) const;

    bool GetBlockHashByHeight(uint32_t height, bytes32& hashOut) const;

    double EstimateNetworkHashPS(uint32_t lookback = 120) const;

    std::vector<bytes32> GetBlockHashesAfter(const bytes32& after,
                                             size_t max) const;

    std::vector<bytes32> GetBlockLocator() const;

    bool FindForkPoint(const std::vector<bytes32>& locator,
                       uint32_t& heightOut) const;

    bool GetCoin(const OutPoint& outpoint,
                 Coin& coin) const;
    bool HaveCoin(const OutPoint& outpoint) const;
    int64_t GetBalance(const bytes32& pubkeyHash) const;

    std::vector<std::pair<OutPoint, Coin>>
    GetUTXOsForAddress(
        const bytes32& pubkeyHash) const;

    bool IsGenesisBlock(const bytes32& blockHash) const;

    bool Flush();
    bool Sync();

    BlockData& GetBlockData() { return *mBlockData; }
    UTXOSet&   GetUTXOSet()   { return *mUTXOSet; }
};

} // namespace storage
} // namespace MONEU

#endif
