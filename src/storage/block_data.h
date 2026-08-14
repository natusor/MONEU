// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_STORAGE_BLOCK_DATA_H
#define MONEU_STORAGE_BLOCK_DATA_H

#include "db_wrapper.h"
#include "../primitives/block.h"
#include "../primitives/transaction.h"
#include "../chainparams.h"
#include "block_undo.h"

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <cstdint>

#include <boost/filesystem.hpp>

namespace MONEU {
namespace storage {

namespace fs = boost::filesystem;

static const char DB_BLOCK_INDEX  = 'b';
static const char DB_BLOCK_FILES  = 'f';
static const char DB_LAST_BLOCK   = 'l';
static const char DB_BEST_BLOCK   = 'B';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_FLAG         = 'F';
static const char DB_BLOCK_UNDO   = 'u';
static const char DB_TX_INDEX     = 't';

static const uint32_t MAX_BLOCK_FILE_SIZE = 128 * 1024 * 1024;
static const uint32_t BLOCK_FILE_CHUNK    = 0x1000000;

struct BlockFileInfo {
    uint32_t nBlocks;
    uint32_t nSize;
    uint32_t nHeightFirst;
    uint32_t nHeightLast;
    uint64_t nTimeFirst;
    uint64_t nTimeLast;

    BlockFileInfo()
        : nBlocks(0)
        , nSize(0)
        , nHeightFirst(0)
        , nHeightLast(0)
        , nTimeFirst(0)
        , nTimeLast(0)
    {}
};

struct DiskBlockPos {
    int32_t  nFile;
    uint32_t nPos;

    DiskBlockPos() : nFile(-1), nPos(0) {}
    DiskBlockPos(int32_t file, uint32_t pos) : nFile(file), nPos(pos) {}

    bool IsNull() const { return nFile == -1; }

    bool operator==(const DiskBlockPos& other) const {
        return nFile == other.nFile && nPos == other.nPos;
    }
    bool operator!=(const DiskBlockPos& other) const {
        return !(*this == other);
    }
};

struct BlockIndexEntry {
    uint32_t nVersion;
    bytes32  hashPrev;
    bytes32  hashMerkleRoot;

    uint64_t nTime;

    uint32_t nHeight;

    uint32_t nBits;
    uint32_t nNonce;

    bytes32  nChainWork;

    DiskBlockPos blockPos;
    uint32_t nTx;
    bool     hasData;

    BlockIndexEntry()
        : nVersion(0)
        , nTime(0)
        , nHeight(0)
        , nBits(0)
        , nNonce(0)
        , nTx(0)
        , hasData(false)
    {
        hashPrev.fill(0);
        hashMerkleRoot.fill(0);
        nChainWork.fill(0);
    }
};

class BlockData {
private:
    std::unique_ptr<DBWrapper> mBlockIndex;
    fs::path                   mBlocksDir;
    mutable std::mutex         mMutex;
    int32_t                    mLastBlockFile;

    fs::path GetBlockFilePath(int32_t nFile) const;
    bool WriteBlockToDisk(const Block& block, DiskBlockPos& pos);
    bool ReadBlockFromDisk(Block& block, const DiskBlockPos& pos) const;

public:
    explicit BlockData(const fs::path& dataDir,
                       size_t nCacheSize = DB_DEFAULT_CACHE_SIZE);

    ~BlockData() = default;

    BlockData(const BlockData&) = delete;
    BlockData& operator=(const BlockData&) = delete;

    bool WriteBlock(const Block& block,
                    uint32_t height,
                    const bytes32& chainWork,
                    DiskBlockPos& posOut);

    bool WriteBlockConnected(const Block& block,
                             uint32_t height,
                             const bytes32& chainWork,
                             const BlockUndo& undo,
                             DiskBlockPos& posOut);

    bool ReadBlock(Block& block,
                   const DiskBlockPos& pos) const;

    bool HasBlock(const bytes32& blockHash) const;

    bool WriteBlockIndex(const bytes32& blockHash,
                         const BlockIndexEntry& entry);

    bool ReadBlockIndex(const bytes32& blockHash,
                        BlockIndexEntry& entry) const;

    bool WriteBlockUndo(const bytes32& blockHash,
                        const BlockUndo& undo);

    bool WriteTxIndex(const bytes32& txid, const bytes32& blockHash);
    bool ReadTxIndex(const bytes32& txid, bytes32& blockHashOut) const;

private:
    bool WriteTxIndexLocked(const bytes32& txid, const bytes32& blockHash);
public:
    bool ReadBlockUndo(const bytes32& blockHash,
                       BlockUndo& undo) const;
    bool HasBlockUndo(const bytes32& blockHash) const;

    bool WriteBestBlock(const bytes32& blockHash);

    bool ReadBestBlock(bytes32& blockHash) const;

    bool WriteLastBlockFile(int32_t nFile);

    bool ReadLastBlockFile(int32_t& nFile) const;

    bool WriteFlag(const std::string& name, bool value);

    bool ReadFlag(const std::string& name, bool& value) const;

    bool WriteBlockFileInfo(int32_t nFile,
                            const BlockFileInfo& info);

    bool ReadBlockFileInfo(int32_t nFile,
                           BlockFileInfo& info) const;

    bool WriteReindexing(bool fReindexing);

    bool ReadReindexing(bool& fReindexing) const;

    uint64_t EstimateSize() const;

    void Flush();
};

} // namespace storage
} // namespace MONEU

#endif // MONEU_STORAGE_BLOCK_DATA_H
