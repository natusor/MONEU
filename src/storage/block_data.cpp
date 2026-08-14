// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "block_data.h"

#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace MONEU {
namespace storage {

namespace {
bool WriteAll(int fd, const void* buf, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t left = len;
    while (left > 0) {
        const ssize_t n = ::write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p    += static_cast<size_t>(n);
        left -= static_cast<size_t>(n);
    }
    return true;
}
} // namespace

BlockData::BlockData(const fs::path& dataDir, size_t nCacheSize)
    : mLastBlockFile(0)
{
    mBlocksDir = dataDir / "blocks";
    try {
        fs::create_directories(mBlocksDir);
        fs::create_directories(mBlocksDir / "index");
    } catch (const fs::filesystem_error& e) {
        throw DBError("Failed to create blocks directory: " + std::string(e.what()));
    }
    mBlockIndex = std::unique_ptr<DBWrapper>(
        new DBWrapper(mBlocksDir / "index", nCacheSize, false, false, false)
    );
    ReadLastBlockFile(mLastBlockFile);
}

fs::path BlockData::GetBlockFilePath(int32_t nFile) const {
    std::ostringstream oss;
    oss << "blk" << std::setw(5) << std::setfill('0') << nFile << ".dat";
    return mBlocksDir / oss.str();
}

bool BlockData::WriteBlockToDisk(const Block& block, DiskBlockPos& pos) {
    std::vector<uint8_t> data = block.Serialize();
    uint32_t dataSize = static_cast<uint32_t>(data.size());
    fs::path filePath = GetBlockFilePath(mLastBlockFile);
    uint32_t currentSize = 0;
    if (fs::exists(filePath)) {
        currentSize = static_cast<uint32_t>(fs::file_size(filePath));
    }
    if (currentSize + dataSize + 8 > MAX_BLOCK_FILE_SIZE) {
        mLastBlockFile++;
        WriteLastBlockFile(mLastBlockFile);
        filePath = GetBlockFilePath(mLastBlockFile);
        currentSize = 0;
    }
    const int fd = ::open(filePath.string().c_str(),
                          O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        throw DBError("Failed to open block file: " + filePath.string());
    }

    uint8_t header[8];
    std::memcpy(header, NetParams::MAINNET_MAGIC, 4);
    header[4] = static_cast<uint8_t>( dataSize        & 0xFF);
    header[5] = static_cast<uint8_t>((dataSize >>  8) & 0xFF);
    header[6] = static_cast<uint8_t>((dataSize >> 16) & 0xFF);
    header[7] = static_cast<uint8_t>((dataSize >> 24) & 0xFF);

    bool ok = WriteAll(fd, header, sizeof(header));
    if (ok) ok = WriteAll(fd, data.data(), data.size());
    if (ok && ::fsync(fd) != 0) ok = false;
    if (::close(fd) != 0) ok = false;

    if (!ok) {
        throw DBError("Failed to write block to disk");
    }
    pos.nFile = mLastBlockFile;
    pos.nPos  = currentSize;
    return true;
}

bool BlockData::ReadBlockFromDisk(Block& block, const DiskBlockPos& pos) const {
    if (pos.IsNull()) return false;
    fs::path filePath = GetBlockFilePath(pos.nFile);
    std::ifstream file(filePath.string(), std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "BlockData: cannot open block file " << filePath.string() << "\n";
        return false;
    }
    file.seekg(pos.nPos, std::ios::beg);
    uint8_t header[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    file.read(reinterpret_cast<char*>(header), sizeof(header));
    if (!file.good()) return false;
    if (!NetParams::VerifyNetworkMagic(header)) {
        std::cerr << "BlockData: invalid magic in block file\n";
        return false;
    }
    const uint32_t dataSize =
        static_cast<uint32_t>(header[4]) |
        (static_cast<uint32_t>(header[5]) << 8) |
        (static_cast<uint32_t>(header[6]) << 16) |
        (static_cast<uint32_t>(header[7]) << 24);
    if (dataSize == 0 || dataSize > NetParams::MAX_BLOCK_SIZE) {
        std::cerr << "BlockData: invalid block size " << dataSize << "\n";
        return false;
    }
    std::vector<uint8_t> data(dataSize);
    file.read(reinterpret_cast<char*>(data.data()), dataSize);
    if (!file.good()) return false;
    try {
        block = Block::Deserialize(data);
    } catch (const std::exception& e) {
        std::cerr << "BlockData: failed to deserialize block: " << e.what() << "\n";
        return false;
    }
    return true;
}

bool BlockData::WriteBlock(const Block& block,
                           uint32_t height,
                           const bytes32& chainWork,
                           DiskBlockPos& posOut)
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (!WriteBlockToDisk(block, posOut)) return false;
    BlockIndexEntry entry;
    const BlockHeader& hdr = block.GetHeader();
    entry.nVersion          = hdr.GetVersion();
    entry.hashPrev          = hdr.GetPrevBlockHash();
    entry.hashMerkleRoot    = hdr.GetMerkleRoot();
    entry.nTime             = hdr.GetTimestamp();
    entry.nHeight           = height;
    entry.nBits             = hdr.GetBits();
    entry.nNonce            = hdr.GetNonce();
    entry.nChainWork        = chainWork;
    entry.blockPos          = posOut;
    entry.nTx               = static_cast<uint32_t>(block.GetTransactionCount());
    entry.hasData           = true;
    bytes32 blockHash = hdr.GetHash();
    if (!WriteBlockIndex(blockHash, entry)) return false;
    for (const auto& tx : block.GetTransactions()) {
        if (!WriteTxIndexLocked(tx.GetHash(), blockHash)) return false;
    }
    BlockFileInfo fileInfo;
    ReadBlockFileInfo(posOut.nFile, fileInfo);
    fileInfo.nBlocks++;
    fileInfo.nSize = posOut.nPos;
    if (fileInfo.nBlocks == 1 || height < fileInfo.nHeightFirst)
        fileInfo.nHeightFirst = height;
    if (fileInfo.nBlocks == 1 || height > fileInfo.nHeightLast)
        fileInfo.nHeightLast = height;
    if (fileInfo.nBlocks == 1 || entry.nTime < fileInfo.nTimeFirst)
        fileInfo.nTimeFirst = entry.nTime;
    if (fileInfo.nBlocks == 1 || entry.nTime > fileInfo.nTimeLast)
        fileInfo.nTimeLast = entry.nTime;
    WriteBlockFileInfo(posOut.nFile, fileInfo);
    return true;
}

bool BlockData::WriteTxIndex(const bytes32& txid, const bytes32& blockHash) {
    std::lock_guard<std::mutex> lock(mMutex);
    return WriteTxIndexLocked(txid, blockHash);
}

bool BlockData::WriteTxIndexLocked(const bytes32& txid,
                                   const bytes32& blockHash) {
    return mBlockIndex->Write(std::make_pair(DB_TX_INDEX, txid), blockHash);
}

bool BlockData::ReadTxIndex(const bytes32& txid, bytes32& blockHashOut) const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mBlockIndex->Read(std::make_pair(DB_TX_INDEX, txid), blockHashOut);
}

bool BlockData::WriteBlockConnected(const Block& block,
                                    uint32_t height,
                                    const bytes32& chainWork,
                                    const BlockUndo& undo,
                                    DiskBlockPos& posOut)
{
    std::lock_guard<std::mutex> lock(mMutex);

    if (!WriteBlockToDisk(block, posOut)) return false;

    const BlockHeader& hdr = block.GetHeader();
    const bytes32 blockHash = hdr.GetHash();

    BlockIndexEntry entry;
    entry.nVersion       = hdr.GetVersion();
    entry.hashPrev       = hdr.GetPrevBlockHash();
    entry.hashMerkleRoot = hdr.GetMerkleRoot();
    entry.nTime          = hdr.GetTimestamp();
    entry.nHeight        = height;
    entry.nBits          = hdr.GetBits();
    entry.nNonce         = hdr.GetNonce();
    entry.nChainWork     = chainWork;
    entry.blockPos       = posOut;
    entry.nTx            = static_cast<uint32_t>(block.GetTransactionCount());
    entry.hasData        = true;

    BlockFileInfo fileInfo;
    ReadBlockFileInfo(posOut.nFile, fileInfo);
    fileInfo.nBlocks++;
    fileInfo.nSize = posOut.nPos;
    if (fileInfo.nBlocks == 1 || height < fileInfo.nHeightFirst)
        fileInfo.nHeightFirst = height;
    if (fileInfo.nBlocks == 1 || height > fileInfo.nHeightLast)
        fileInfo.nHeightLast = height;
    if (fileInfo.nBlocks == 1 || entry.nTime < fileInfo.nTimeFirst)
        fileInfo.nTimeFirst = entry.nTime;
    if (fileInfo.nBlocks == 1 || entry.nTime > fileInfo.nTimeLast)
        fileInfo.nTimeLast = entry.nTime;

    DBBatch batch(*mBlockIndex);
    batch.Write(std::make_pair(DB_BLOCK_INDEX, blockHash), entry);

    const std::vector<uint8_t> undoBlob = undo.Serialize();
    batch.Write(std::make_pair(DB_BLOCK_UNDO, blockHash), undoBlob);

    for (const auto& tx : block.GetTransactions()) {
        batch.Write(std::make_pair(DB_TX_INDEX, tx.GetHash()), blockHash);
    }

    batch.Write(std::make_pair(DB_BLOCK_FILES, posOut.nFile), fileInfo);

    return mBlockIndex->WriteBatch(batch, true);
}

bool BlockData::ReadBlock(Block& block, const DiskBlockPos& pos) const {
    std::lock_guard<std::mutex> lock(mMutex);
    return ReadBlockFromDisk(block, pos);
}

bool BlockData::HasBlock(const bytes32& blockHash) const {
    std::lock_guard<std::mutex> lock(mMutex);
    BlockIndexEntry entry;
    return ReadBlockIndex(blockHash, entry);
}

bool BlockData::WriteBlockIndex(const bytes32& blockHash, const BlockIndexEntry& entry) {
    return mBlockIndex->Write(std::make_pair(DB_BLOCK_INDEX, blockHash), entry);
}

bool BlockData::ReadBlockIndex(const bytes32& blockHash, BlockIndexEntry& entry) const {
    return mBlockIndex->Read(std::make_pair(DB_BLOCK_INDEX, blockHash), entry);
}

bool BlockData::WriteBlockUndo(const bytes32& blockHash, const BlockUndo& undo) {
    std::vector<uint8_t> blob = undo.Serialize();
    return mBlockIndex->Write(std::make_pair(DB_BLOCK_UNDO, blockHash), blob);
}

bool BlockData::ReadBlockUndo(const bytes32& blockHash, BlockUndo& undo) const {
    std::vector<uint8_t> blob;
    if (!mBlockIndex->Read(std::make_pair(DB_BLOCK_UNDO, blockHash), blob)) {
        return false;
    }
    try {
        undo = BlockUndo::Deserialize(blob.data(), blob.size());
    } catch (const std::exception& e) {
        std::cerr << "BlockData: corrupt undo record: " << e.what() << "\n";
        return false;
    }
    return true;
}

bool BlockData::HasBlockUndo(const bytes32& blockHash) const {
    return mBlockIndex->Exists(std::make_pair(DB_BLOCK_UNDO, blockHash));
}

bool BlockData::WriteBestBlock(const bytes32& blockHash) {
    return mBlockIndex->Write(DB_BEST_BLOCK, blockHash);
}

bool BlockData::ReadBestBlock(bytes32& blockHash) const {
    return mBlockIndex->Read(DB_BEST_BLOCK, blockHash);
}

bool BlockData::WriteLastBlockFile(int32_t nFile) {
    mLastBlockFile = nFile;
    return mBlockIndex->Write(DB_LAST_BLOCK, nFile);
}

bool BlockData::ReadLastBlockFile(int32_t& nFile) const {
    return mBlockIndex->Read(DB_LAST_BLOCK, nFile);
}

bool BlockData::WriteFlag(const std::string& name, bool value) {
    return mBlockIndex->Write(
        std::make_pair(DB_FLAG, name),
        value ? '1' : '0'
    );
}

bool BlockData::ReadFlag(const std::string& name, bool& value) const {
    char ch;
    if (!mBlockIndex->Read(std::make_pair(DB_FLAG, name), ch)) return false;
    value = (ch == '1');
    return true;
}

bool BlockData::WriteBlockFileInfo(int32_t nFile, const BlockFileInfo& info) {
    return mBlockIndex->Write(std::make_pair(DB_BLOCK_FILES, nFile), info);
}

bool BlockData::ReadBlockFileInfo(int32_t nFile, BlockFileInfo& info) const {
    return mBlockIndex->Read(std::make_pair(DB_BLOCK_FILES, nFile), info);
}

bool BlockData::WriteReindexing(bool fReindexing) {
    if (fReindexing) return mBlockIndex->Write(DB_REINDEX_FLAG, '1');
    return mBlockIndex->Erase(DB_REINDEX_FLAG);
}

bool BlockData::ReadReindexing(bool& fReindexing) const {
    fReindexing = mBlockIndex->Exists(DB_REINDEX_FLAG);
    return true;
}

uint64_t BlockData::EstimateSize() const {
    bytes32 keyBegin, keyEnd;
    keyBegin.fill(0x00);
    keyEnd.fill(0xFF);
    return mBlockIndex->EstimateSize(
        std::make_pair(DB_BLOCK_INDEX, keyBegin),
        std::make_pair(DB_BLOCK_INDEX, keyEnd)
    );
}

void BlockData::Flush() {
    mBlockIndex->Sync();
}

} // namespace storage
} // namespace MONEU
