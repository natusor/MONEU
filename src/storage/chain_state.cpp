// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "chain_state.h"
#include "log/log.h"
#include "../crypto/arith_uint256.h"
#include "../validation/block_validation.h"
#include "../consensus/pow.h"
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <vector>
#include <utility>

namespace MONEU {
namespace storage {

namespace {

std::string HexOf(const bytes32& h) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (size_t i = 0; i < h.size(); ++i) {
        out.push_back(d[(h[i] >> 4) & 0x0F]);
        out.push_back(d[h[i] & 0x0F]);
    }
    return out;
}

std::string TimeOf(uint64_t unixTime) {
    const std::time_t t = static_cast<std::time_t>(unixTime);
    std::tm tmUtc;
    gmtime_r(&t, &tmUtc);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmUtc);
    return std::string(buf);
}

// Height of the highest checkpoint this node actually holds.
//
// The list is walked from the newest entry backwards and the first one
// found in the block index wins, so a node that has only synchronised part
// of the chain is bounded by what it has rather than by what the list
// claims. The height is taken from the index entry, not from the list, so
// the answer describes a block this node has really seen.
//
// False when no checkpointed block is in the index yet, which leaves the
// caller with nothing to enforce.
bool LastCheckpointHeight(const BlockData& blockData, uint32_t& heightOut) {
    for (size_t i = NetParams::CHECKPOINT_COUNT; i-- > 0; ) {
        const bytes32 hash = NetParams::HexToBytes32(
            NetParams::MAINNET_CHECKPOINTS[i].block_hash);
        BlockIndexEntry entry;
        if (blockData.ReadBlockIndex(hash, entry)) {
            heightOut = entry.nHeight;
            return true;
        }
    }
    return false;
}

}

ChainState::ChainState(const fs::path& dataDir,
                        size_t nCacheSize)
    : mInitialized(false)
    , mSyncDisconnectedBytes(0)
{
    fs::path chainDir = dataDir / "chain";
    try {
        fs::create_directories(chainDir);
    } catch (const fs::filesystem_error& e) {
        throw DBError(
            "Failed to create chain directory: " +
            std::string(e.what()));
    }
    mDB = std::unique_ptr<DBWrapper>(
        new DBWrapper(chainDir, nCacheSize,
                      false, false, false));
    mBlockData = std::unique_ptr<BlockData>(
        new BlockData(dataDir, nCacheSize));
    mUTXOSet = std::unique_ptr<UTXOSet>(
        new UTXOSet(dataDir, nCacheSize));
}

bool ChainState::LoadBestChain() {
    if (!mDB->Read(DB_CHAIN_BEST, mBestChain)) {
        mBestChain = ChainTip();
        return false;
    }
    return true;
}

bool ChainState::VerifyGenesisBlock() const {
    bytes32 genesisHash = NetParams::GetGenesisHash();
    bool allZero = true;
    for (uint8_t b : genesisHash) {
        if (b != 0) { allZero = false; break; }
    }
    if (allZero) return true;

    bytes32 storedGenesis;
    if (!mDB->Read(DB_CHAIN_GENESIS, storedGenesis)) {
        return true;
    }
    if (storedGenesis != genesisHash) {
        std::cerr << "ChainState: genesis hash does not match the "
                     "stored one\n";
        std::cerr << "ChainState: refusing to start\n";
        return false;
    }
    return true;
}

bool ChainState::Initialize() {
    std::lock_guard<std::mutex> lock(mMutex);

    if (!VerifyGenesisBlock()) {
        throw DBError(
            "Genesis block mismatch - chain data does not belong to "
            "this network");
    }

    if (!LoadBestChain()) {
        if (!InitializeGenesisLocked()) {
            throw DBError(
                "Failed to initialize genesis block - "
                "chainparams do not reproduce the genesis hash?");
        }
    }

    bytes32 pendingNew, pendingOld;
    const bool interrupted = mUTXOSet->GetHeadBlocks(pendingNew, pendingOld);
    const bytes32 utxoBest = mUTXOSet->GetBestBlock();

    if (interrupted || !(utxoBest == mBestChain.blockHash)) {
        MONEU_LOG_INFO("ChainState: the UTXO set is at " + HexOf(utxoBest) +
                       " while the tip is " + HexOf(mBestChain.blockHash) +
                       " - the node was stopped without committing; "
                       "replaying the blocks in between");
        if (!ReplayBlocksLocked()) {
            MONEU_LOG_ERROR("Chain state is inconsistent: the tip is " +
                            HexOf(mBestChain.blockHash) +
                            " but the UTXO set belongs to " +
                            HexOf(mUTXOSet->GetBestBlock()) +
                            ", which is not a block on the way to it. The "
                            "chain data cannot be reconciled by replaying.");
            throw DBError("Chain tip and UTXO set disagree - the recorded "
                          "block is not an ancestor of the tip");
        }
        MONEU_LOG_INFO("ChainState: replay finished, the UTXO set now "
                       "matches the tip");
    }

    mInitialized = true;
    MONEU_LOG_INFO("ChainState: initialized at height " +
                   std::to_string(mBestChain.height) +
                   " tip=" + HexOf(mBestChain.blockHash));
    return true;
}

bool ChainState::InitializeGenesisLocked() {
    const bytes32 genesisHash = NetParams::GetGenesisHash();

    bool allZero = true;
    for (uint8_t b : genesisHash) {
        if (b != 0) { allZero = false; break; }
    }
    if (allZero) {
        return true;
    }

    const Block genesis = NetParams::BuildGenesisBlock();
    const BlockHeader& hdr = genesis.GetHeader();

    if (hdr.GetHash() != genesisHash) {
        std::cerr << "ChainState: BuildGenesisBlock() hash "
                     "does not match GetGenesisHash()!\n"
                     "ChainState: check GENESIS_* constants "
                     "in chainparams.cpp\n";
        return false;
    }

    const auto& txs = genesis.GetTransactions();
    for (size_t i = 0; i < txs.size(); ++i) {
        const bool isCoinbase = (i == 0 && txs[i].IsCoinbase());
        if (!mUTXOSet->ApplyTransaction(txs[i], 0, isCoinbase, nullptr)) {
            std::cerr << "ChainState: failed to apply "
                         "genesis transactions\n";
            return false;
        }
    }

    bytes32 zeroWork;
    zeroWork.fill(0);
    const bytes32 chainWork =
        PNC::AddChainWork(zeroWork, hdr.GetBits());

    DiskBlockPos blockPos;
    if (!mBlockData->WriteBlock(genesis, 0, chainWork, blockPos)) {
        std::cerr << "ChainState: failed to write "
                     "genesis block\n";
        return false;
    }

    mBestChain.blockHash = genesisHash;
    mBestChain.height    = 0;
    mBestChain.timestamp = hdr.GetTimestamp();
    mBestChain.bits      = hdr.GetBits();
    mBestChain.chainWork = chainWork;

    mDB->Write(DB_CHAIN_BEST, mBestChain);
    mDB->Write(DB_CHAIN_GENESIS, genesisHash);
    mUTXOSet->SetBestBlock(genesisHash);

    if (!mUTXOSet->Flush()) {
        std::cerr << "ChainState: failed to commit the genesis "
                     "UTXO set\n";
        return false;
    }

    std::cerr << "ChainState: genesis block materialized "
                 "at height 0\n";
    return true;
}

bool ChainState::AncestorPathLocked(const bytes32& from,
                                    const bytes32& to,
                                    std::vector<bytes32>& out) const
{
    out.clear();
    if (from == to) return true;

    bytes32 cursor = from;
    const size_t maxSteps = static_cast<size_t>(mBestChain.height) + 2;

    for (size_t step = 0; step < maxSteps; ++step) {
        out.push_back(cursor);
        BlockIndexEntry entry;
        if (!mBlockData->ReadBlockIndex(cursor, entry)) return false;
        if (entry.hashPrev == to) return true;
        if (entry.nHeight == 0) return false;
        cursor = entry.hashPrev;
    }
    return false;
}

bool ChainState::LastCommonAncestorLocked(const bytes32& a,
                                          const bytes32& b,
                                          bytes32& out) const
{
    BlockIndexEntry ea, eb;
    if (!mBlockData->ReadBlockIndex(a, ea)) return false;
    if (!mBlockData->ReadBlockIndex(b, eb)) return false;

    bytes32 ca = a, cb = b;
    const size_t maxSteps = static_cast<size_t>(mBestChain.height) + 2;

    for (size_t step = 0; step < maxSteps && ea.nHeight > eb.nHeight; ++step) {
        ca = ea.hashPrev;
        if (!mBlockData->ReadBlockIndex(ca, ea)) return false;
    }
    for (size_t step = 0; step < maxSteps && eb.nHeight > ea.nHeight; ++step) {
        cb = eb.hashPrev;
        if (!mBlockData->ReadBlockIndex(cb, eb)) return false;
    }
    for (size_t step = 0; step < maxSteps; ++step) {
        if (ca == cb) { out = ca; return true; }
        if (ea.nHeight == 0 || eb.nHeight == 0) return false;
        ca = ea.hashPrev;
        cb = eb.hashPrev;
        if (!mBlockData->ReadBlockIndex(ca, ea)) return false;
        if (!mBlockData->ReadBlockIndex(cb, eb)) return false;
    }
    return false;
}

bool ChainState::RollforwardBlockLocked(const bytes32& blockHash,
                                        uint32_t height)
{
    BlockIndexEntry entry;
    if (!mBlockData->ReadBlockIndex(blockHash, entry)) {
        MONEU_LOG_ERROR("ChainState: replay cannot read the index entry for " +
                        HexOf(blockHash));
        return false;
    }

    Block block;
    if (!mBlockData->ReadBlock(block, entry.blockPos)) {
        MONEU_LOG_ERROR("ChainState: replay cannot read block " +
                        HexOf(blockHash) + " from disk");
        return false;
    }

    if (block.GetHeader().GetHash() != blockHash) {
        MONEU_LOG_ERROR("ChainState: replay read a block whose hash is not " +
                        HexOf(blockHash));
        return false;
    }

    const std::vector<Transaction>& txs = block.GetTransactions();
    for (size_t i = 0; i < txs.size(); ++i) {
        const bool isCoinbase = (i == 0 && txs[i].IsCoinbase());
        if (!mUTXOSet->ApplyTransactionForReplay(txs[i], height, isCoinbase)) {
            MONEU_LOG_ERROR("ChainState: replay failed on transaction " +
                            std::to_string(i) + " of the block at height " +
                            std::to_string(height));
            return false;
        }
    }
    return true;
}

bool ChainState::RollbackBlockLocked(const bytes32& blockHash,
                                     uint32_t height)
{
    if (height == 0) return true;

    BlockIndexEntry entry;
    if (!mBlockData->ReadBlockIndex(blockHash, entry)) {
        MONEU_LOG_ERROR("ChainState: rollback cannot read the index entry "
                        "for " + HexOf(blockHash));
        return false;
    }

    Block block;
    if (!mBlockData->ReadBlock(block, entry.blockPos)) {
        MONEU_LOG_ERROR("ChainState: rollback cannot read block " +
                        HexOf(blockHash) + " from disk");
        return false;
    }

    BlockUndo undo;
    if (!mBlockData->ReadBlockUndo(blockHash, undo)) {
        MONEU_LOG_ERROR("ChainState: rollback has no undo data for block " +
                        HexOf(blockHash));
        return false;
    }

    if (!UndoBlockTwoPhase(block, undo)) {
        MONEU_LOG_ERROR("ChainState: rollback failed for the block at "
                        "height " + std::to_string(height));
        return false;
    }
    return true;
}

bool ChainState::ReplayBlocksLocked()
{
    bytes32 markedNew, markedOld;
    const bool haveMarker = mUTXOSet->GetHeadBlocks(markedNew, markedOld);

    bytes32 target = mBestChain.blockHash;
    bytes32 source = mUTXOSet->GetBestBlock();

    if (haveMarker) {
        source = markedOld;
        MONEU_LOG_INFO("ChainState: an interrupted commit was recorded, "
                       "from " + HexOf(markedOld) + " to " +
                       HexOf(markedNew));
    }

    bool sourceUnset = true;
    for (size_t i = 0; i < source.size(); ++i) {
        if (source[i] != 0) { sourceUnset = false; break; }
    }

    if (!sourceUnset && source == target) {
        if (haveMarker && !mUTXOSet->Flush()) return false;
        return true;
    }

    const bytes32 genesisHash = NetParams::GetGenesisHash();
    bytes32 fork = genesisHash;
    std::vector<bytes32> rollback;

    if (!sourceUnset) {
        if (!LastCommonAncestorLocked(source, target, fork)) {
            MONEU_LOG_ERROR("ChainState: replay found no common block "
                            "between " + HexOf(source) + " and " +
                            HexOf(target));
            return false;
        }
        if (!AncestorPathLocked(source, fork, rollback)) {
            MONEU_LOG_ERROR("ChainState: replay cannot walk back from " +
                            HexOf(source) + " to " + HexOf(fork));
            return false;
        }
    }

    std::vector<bytes32> rollforward;
    if (sourceUnset) {
        bytes32 cursor = target;
        const size_t maxSteps = static_cast<size_t>(mBestChain.height) + 2;
        bool reached = false;
        for (size_t step = 0; step < maxSteps; ++step) {
            rollforward.push_back(cursor);
            if (cursor == genesisHash) { reached = true; break; }
            BlockIndexEntry entry;
            if (!mBlockData->ReadBlockIndex(cursor, entry)) return false;
            cursor = entry.hashPrev;
        }
        if (!reached) {
            MONEU_LOG_ERROR("ChainState: replay cannot walk back from " +
                            HexOf(target) + " to genesis");
            return false;
        }
    } else if (!AncestorPathLocked(target, fork, rollforward)) {
        MONEU_LOG_ERROR("ChainState: replay cannot walk back from " +
                        HexOf(target) + " to " + HexOf(fork));
        return false;
    }

    std::reverse(rollforward.begin(), rollforward.end());

    MONEU_LOG_INFO("ChainState: replaying - " +
                   std::to_string(rollback.size()) + " block(s) back, " +
                   std::to_string(rollforward.size()) + " block(s) forward");

    for (size_t i = 0; i < rollback.size(); ++i) {
        BlockIndexEntry entry;
        if (!mBlockData->ReadBlockIndex(rollback[i], entry)) return false;
        if (!RollbackBlockLocked(rollback[i], entry.nHeight)) return false;
    }

    for (size_t i = 0; i < rollforward.size(); ++i) {
        BlockIndexEntry entry;
        if (!mBlockData->ReadBlockIndex(rollforward[i], entry)) return false;
        if (!RollforwardBlockLocked(rollforward[i], entry.nHeight)) {
            return false;
        }
    }

    mUTXOSet->SetBestBlock(target);

    if (!mUTXOSet->Flush()) {
        MONEU_LOG_ERROR("ChainState: replay could not commit the UTXO set");
        return false;
    }

    if (!(mUTXOSet->GetBestBlock() == target)) {
        MONEU_LOG_ERROR("ChainState: replay ended at " +
                        HexOf(mUTXOSet->GetBestBlock()) +
                        " instead of the tip " + HexOf(target));
        return false;
    }

    return true;
}

bool ChainState::ApplyBlockTwoPhase(const Block& block,
                                    uint32_t height,
                                    BlockUndo* undoOut)
{
    const auto& txs = block.GetTransactions();

    BlockUndo local;
    BlockUndo& undo = undoOut ? *undoOut : local;
    undo.txUndo.clear();

    bool coinbaseApplied = false;
    std::vector<std::pair<size_t, std::vector<Coin> > > appliedHere;

    auto rollback = [&]() {
        for (size_t i = appliedHere.size(); i-- > 0; ) {
            mUTXOSet->UndoTransaction(txs[appliedHere[i].first],
                                      appliedHere[i].second);
        }
        if (coinbaseApplied && !txs.empty()) {
            std::vector<Coin> none;
            mUTXOSet->UndoTransaction(txs[0], none);
        }
    };

    if (!txs.empty() && txs[0].IsCoinbase()) {
        std::vector<Coin> spent;
        if (!mUTXOSet->ApplyTransaction(txs[0], height, true, &spent)) {
            std::cerr << "ChainState: coinbase failed to apply\n";
            return false;
        }
        coinbaseApplied = true;
    }

    for (size_t i = 0; i < txs.size(); ++i) {
        if (i == 0 && txs[i].IsCoinbase()) continue;

        const std::vector<TxInput>& ins = txs[i].GetInputs();
        std::vector<Coin> coins;
        coins.reserve(ins.size());
        bool ok = true;
        for (size_t k = 0; k < ins.size(); ++k) {
            Coin c;
            if (!mUTXOSet->GetCoin(OutPoint(ins[k].GetPrevTxHash(),
                                            ins[k].GetOutputIndex()), c)) {
                ok = false;
                break;
            }
            coins.push_back(c);
        }
        if (!ok) {
            std::cerr << "ChainState: tx " << i
                      << " names an output that is gone\n";
            rollback();
            return false;
        }

        int64_t valueIn = 0;
        for (size_t k = 0; k < coins.size(); ++k) {
            if (coins[k].value < 0 ||
                !NetParams::CheckMoneyRange(
                    static_cast<uint64_t>(coins[k].value))) {
                std::cerr << "ChainState: tx " << i
                          << " input value out of range\n";
                rollback();
                return false;
            }
            const int64_t next = valueIn + coins[k].value;
            if (next < valueIn ||
                !NetParams::CheckMoneyRange(static_cast<uint64_t>(next))) {
                std::cerr << "ChainState: tx " << i
                          << " total input value out of range\n";
                rollback();
                return false;
            }
            valueIn = next;
        }

        const int64_t valueOut = txs[i].GetValueOut();

        if (valueOut < 0 || valueIn < valueOut) {
            std::cerr << "ChainState: tx " << i
                      << " spends more than it takes in\n";
            rollback();
            return false;
        }

        const int64_t fee = valueIn - valueOut;

        std::vector<Coin> spentHere;
        if (!mUTXOSet->ApplyTransaction(txs[i], height, false,
                                        &spentHere)) {
            std::cerr << "ChainState: tx " << i
                      << " could not be applied\n";
            rollback();
            return false;
        }

        (void)fee;

        TxUndo tu;
        tu.spentCoins = spentHere;
        undo.txUndo.push_back(tu);
        appliedHere.push_back(std::make_pair(i, spentHere));
    }

    return true;
}

bool ChainState::UndoBlockTwoPhase(const Block& block,
                                   const BlockUndo& undo)
{
    const auto& txs = block.GetTransactions();

    size_t nonCoinbaseCount = 0;
    for (size_t i = 0; i < txs.size(); ++i) {
        if (i == 0 && txs[i].IsCoinbase()) continue;
        ++nonCoinbaseCount;
    }
    if (undo.txUndo.size() != nonCoinbaseCount) {
        std::cerr << "ChainState: undo record holds "
                  << undo.txUndo.size()
                  << " entries for " << nonCoinbaseCount
                  << " non-coinbase transactions\n";
        return false;
    }

    size_t undoIndex = undo.txUndo.size();
    for (size_t i = txs.size(); i-- > 0; ) {
        if (i == 0 && txs[i].IsCoinbase()) continue;
        --undoIndex;
        if (!mUTXOSet->UndoTransaction(txs[i],
                                       undo.txUndo[undoIndex].spentCoins)) {
            std::cerr << "ChainState: could not undo transaction "
                      << i << "\n";
            return false;
        }
    }

    if (!txs.empty() && txs[0].IsCoinbase()) {
        std::vector<Coin> none;
        if (!mUTXOSet->UndoTransaction(txs[0], none)) {
            std::cerr << "ChainState: could not undo the coinbase\n";
            return false;
        }
    }

    return true;
}

bool ChainState::ApplyBlockTransactions(const Block& block,
                                        BlockUndo* undoOut)
{
    const auto& txs = block.GetTransactions();

    if (undoOut) undoOut->txUndo.clear();

    std::vector<std::vector<Coin>> applied;
    applied.reserve(txs.size());

    for (size_t i = 0; i < txs.size(); ++i) {
        bool isCoinbase =
            (i == 0 && txs[i].IsCoinbase());
        std::vector<Coin> spent;
        if (!mUTXOSet->ApplyTransaction(
                txs[i],
                mBestChain.height + 1,
                isCoinbase,
                &spent))
        {
            std::cerr << "ChainState: ApplyTransaction"
                         " failed for tx "
                      << i << ", rolling back "
                      << i << " applied\n";
            for (size_t j = i; j-- > 0; ) {
                if (!mUTXOSet->UndoTransaction(txs[j], applied[j])) {
                    std::cerr << "ChainState: rollback failed for tx "
                              << j << "\n";
                }
            }
            return false;
        }
        applied.push_back(std::move(spent));
    }

    if (undoOut) {
        for (size_t i = 0; i < txs.size(); ++i) {
            if (i == 0 && txs[i].IsCoinbase()) continue;
            TxUndo tu;
            tu.spentCoins = std::move(applied[i]);
            undoOut->txUndo.push_back(std::move(tu));
        }
    }

    return true;
}

bool ChainState::UndoBlockTransactions(
    const Block& block,
    const BlockUndo& undo)
{
    const auto& txs = block.GetTransactions();

    size_t nonCoinbase = 0;
    for (const auto& t : txs) {
        if (!t.IsCoinbase()) nonCoinbase++;
    }
    if (undo.txUndo.size() != nonCoinbase) {
        std::cerr << "ChainState: undo record count "
                  << undo.txUndo.size()
                  << " does not match non-coinbase tx count "
                  << nonCoinbase << "\n";
        return false;
    }

    size_t undoIdx = undo.txUndo.size();
    for (int i = static_cast<int>(txs.size()) - 1; i >= 0; --i) {
        if (txs[i].IsCoinbase()) {
            std::vector<Coin> none;
            if (!mUTXOSet->UndoTransaction(txs[i], none)) {
                std::cerr << "ChainState: UndoTransaction"
                             " failed for coinbase\n";
                return false;
            }
            continue;
        }
        undoIdx--;
        if (!mUTXOSet->UndoTransaction(
                txs[i], undo.txUndo[undoIdx].spentCoins))
        {
            std::cerr << "ChainState: UndoTransaction"
                         " failed for tx " << i << "\n";
            return false;
        }
    }
    return true;
}

uint32_t ChainState::GetExpectedBitsLocked(uint32_t height) const
{
    if (mBestChain.height == 0 || mBestChain.bits == 0) {
        return NetParams::POW_LIMIT_COMPACT;
    }

    if (!PNC::IsRetargetHeight(height)) {
        return mBestChain.bits;
    }

    const uint32_t lastHeight = mBestChain.height;
    if (lastHeight + 1 < NetParams::DIFFICULTY_ADJUSTMENT_INTERVAL) {
        return mBestChain.bits;
    }
    const uint32_t firstHeight =
        lastHeight - (NetParams::DIFFICULTY_ADJUSTMENT_INTERVAL - 1);

    bytes32 firstHash;
    if (!GetBlockHashByHeightLocked(firstHeight, firstHash)) {
        std::cerr << "ChainState: retarget at height " << height
                  << " cannot reach the block at " << firstHeight
                  << "; keeping the current target\n";
        return mBestChain.bits;
    }

    BlockIndexEntry firstEntry;
    if (!mBlockData->ReadBlockIndex(firstHash, firstEntry)) {
        std::cerr << "ChainState: retarget at height " << height
                  << " cannot read the index entry at " << firstHeight
                  << "; keeping the current target\n";
        return mBestChain.bits;
    }

    return PNC::CalculateNextWorkRequired(
        mBestChain.bits, mBestChain.timestamp, firstEntry.nTime);
}

bool ChainState::ConnectBlock(const Block& block)
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mInitialized) {
        std::cerr << "ChainState: not initialized\n";
        return false;
    }
    return ConnectBlockLocked(block);
}

bool ChainState::ConnectBlockLocked(const Block& block)
{
    const BlockHeader& hdr = block.GetHeader();
    const uint32_t newHeight = mBestChain.height + 1;

    if (hdr.GetHeight() != newHeight) {
        std::cerr << "ChainState: ConnectBlock "
                     "rejected - header height "
                  << hdr.GetHeight()
                  << " does not extend tip height "
                  << mBestChain.height << "\n";
        return false;
    }

    if (mBestChain.height == 0) {
        if (hdr.GetPrevBlockHash() != NetParams::GetGenesisHash()) {
            std::cerr << "ChainState: ConnectBlock "
                         "rejected - first block does not "
                         "reference the genesis hash\n";
            return false;
        }
    } else if (hdr.GetPrevBlockHash() != mBestChain.blockHash) {
        std::cerr << "ChainState: ConnectBlock "
                     "rejected - prevHash mismatch\n";
        return false;
    }

    if (mBestChain.height != 0) {
        uint64_t mtp = GetMedianTimePastLocked(mBestChain.blockHash);
        if (hdr.GetTimestamp() <= mtp) {
            std::cerr << "ChainState: ConnectBlock "
                         "rejected - timestamp "
                      << hdr.GetTimestamp()
                      << " not past median-time-past "
                      << mtp << "\n";
            return false;
        }
    }

    const uint32_t expectedBits = GetExpectedBitsLocked(newHeight);
    if (hdr.GetBits() != expectedBits) {
        std::cerr << "ChainState: ConnectBlock "
                     "rejected - header bits "
                  << hdr.GetBits()
                  << " do not match expected "
                  << expectedBits
                  << " at height " << newHeight << "\n";
        return false;
    }

    if (!PNC::CheckProofOfWork(hdr.GetHash(), hdr.GetBits())) {
        std::cerr << "ChainState: ConnectBlock "
                     "rejected - proof of work invalid "
                     "at height " << newHeight << "\n";
        return false;
    }

    BlockUndo undo;
    if (!ApplyBlockTwoPhase(block, static_cast<uint32_t>(newHeight), &undo))
    {
        std::cerr << "ChainState: ApplyBlockTwoPhase"
                     " failed\n";
        return false;
    }

    const bytes32 chainWork =
        PNC::AddChainWork(mBestChain.chainWork, hdr.GetBits());

    DiskBlockPos blockPos;
    bytes32 blockHash = hdr.GetHash();
    if (!mBlockData->WriteBlockConnected(
            block, newHeight, chainWork, undo, blockPos))
    {
        MONEU_LOG_ERROR("ChainState: could not record block at height " +
                        std::to_string(newHeight) +
                        " - chain state left unchanged");
        return false;
    }

    mBestChain.blockHash = blockHash;
    mBestChain.height    = newHeight;
    mBestChain.timestamp = hdr.GetTimestamp();
    mBestChain.bits      = hdr.GetBits();
    mBestChain.chainWork = chainWork;

    if (!mDB->Write(DB_CHAIN_BEST, mBestChain, true)) {
        MONEU_LOG_ERROR("ChainState: could not record the new tip at "
                        "height " + std::to_string(newHeight) +
                        " - the block is stored but the chain still points "
                        "at its parent; it will be connected again on the "
                        "next attempt");
        return false;
    }
    mUTXOSet->SetBestBlock(blockHash);

    if (!mUTXOSet->Flush()) {
        MONEU_LOG_ERROR("ChainState: the block at height " +
                        std::to_string(newHeight) + " is connected but the "
                        "UTXO set could not be committed; it will be "
                        "replayed at the next start");
    }

    MONEU_LOG_INFO("UpdateTip: new best=" + HexOf(blockHash) +
                   " height=" + std::to_string(newHeight) +
                   " tx=" + std::to_string(block.GetTransactionCount()) +
                   " date='" + TimeOf(hdr.GetTimestamp()) + "'" +
                   " work=" + HexOf(chainWork).substr(40));

    if (mBestChain.height == 1) {
        bytes32 genesisHash = hdr.GetPrevBlockHash();
        mDB->Write(DB_CHAIN_GENESIS, genesisHash);
    }

    QueueConnectedLocked(block);
    return true;
}

bool ChainState::DisconnectBlock(
    const bytes32& blockHash)
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mInitialized) return false;

    if (blockHash != mBestChain.blockHash) {
        std::cerr << "ChainState: DisconnectBlock - "
                     "not the current tip\n";
        return false;
    }
    return DisconnectTipLocked();
}

bool ChainState::DisconnectTipLocked()
{
    const bytes32 blockHash = mBestChain.blockHash;

    if (mBestChain.height == 0) {
        std::cerr << "ChainState: DisconnectTip - "
                     "cannot disconnect genesis\n";
        return false;
    }

    BlockIndexEntry entry;
    if (!mBlockData->ReadBlockIndex(blockHash, entry)) {
        std::cerr << "ChainState: DisconnectTip - "
                     "block not found\n";
        return false;
    }

    Block block;
    if (!mBlockData->ReadBlock(block, entry.blockPos)) {
        std::cerr << "ChainState: DisconnectBlock - "
                     "cannot read block\n";
        return false;
    }

    BlockUndo undo;
    if (!mBlockData->ReadBlockUndo(blockHash, undo)) {
        std::cerr << "ChainState: DisconnectBlock - "
                     "missing or corrupt undo data\n";
        return false;
    }

    if (!UndoBlockTwoPhase(block, undo)) {
        std::cerr << "ChainState: UndoBlockTwoPhase"
                     " failed\n";
        return false;
    }

    BlockIndexEntry parent;
    if (mBlockData->ReadBlockIndex(entry.hashPrev, parent)) {
        mBestChain.blockHash = entry.hashPrev;
        mBestChain.height    = parent.nHeight;
        mBestChain.timestamp = parent.nTime;
        mBestChain.bits      = parent.nBits;
        mBestChain.chainWork = parent.nChainWork;
    } else {
        std::cerr << "ChainState: DisconnectBlock - parent "
                     "missing from the block index, chain state is "
                     "inconsistent\n";
        return false;
    }

    mDB->Write(DB_CHAIN_BEST, mBestChain);
    mUTXOSet->SetBestBlock(mBestChain.blockHash);

    if (!mUTXOSet->Flush()) {
        MONEU_LOG_ERROR("ChainState: the tip was disconnected but the UTXO "
                        "set could not be committed at height " +
                        std::to_string(mBestChain.height));
    }

    QueueDisconnectedLocked(block);
    return true;
}

void ChainState::QueueConnectedLocked(const Block& block)
{
    const auto& txs = block.GetTransactions();
    for (const auto& tx : txs) {
        if (tx.IsCoinbase()) continue;
        mSyncConnected.push_back(tx);
    }
}

void ChainState::QueueDisconnectedLocked(const Block& block)
{
    const auto& txs = block.GetTransactions();
    for (auto it = txs.rbegin(); it != txs.rend(); ++it) {
        if (it->IsCoinbase()) continue;
        mSyncDisconnectedBytes += it->GetSerializedSize();
        mSyncDisconnected.push_back(*it);
    }

    size_t evict = 0;
    while (evict < mSyncDisconnected.size() &&
           mSyncDisconnectedBytes > MAX_DISCONNECTED_TX_BYTES) {
        mSyncDisconnectedBytes -=
            mSyncDisconnected[evict].GetSerializedSize();
        ++evict;
    }
    if (evict > 0) {
        std::cerr << "ChainState: disconnected-transaction buffer over "
                  << MAX_DISCONNECTED_TX_BYTES << " bytes, dropped "
                  << evict << " transaction(s)\n";
        mSyncDisconnected.erase(mSyncDisconnected.begin(),
                                mSyncDisconnected.begin() +
                                static_cast<long>(evict));
    }
}

void ChainState::TakeMempoolSync(std::vector<Transaction>& connectedOut,
                                 std::vector<Transaction>& disconnectedOut)
{
    std::lock_guard<std::mutex> lock(mMutex);
    connectedOut.clear();
    disconnectedOut.clear();
    connectedOut.swap(mSyncConnected);
    disconnectedOut.swap(mSyncDisconnected);
    mSyncDisconnectedBytes = 0;
    std::reverse(disconnectedOut.begin(), disconnectedOut.end());
}

bool ChainState::AcceptBlock(const Block& block)
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mInitialized) {
        std::cerr << "ChainState: not initialized\n";
        return false;
    }

    const BlockHeader& hdr = block.GetHeader();
    const bytes32 blockHash = hdr.GetHash();

    if (mBlockData->HasBlock(blockHash)) {
        return true;
    }

    const bytes32 prevHash = hdr.GetPrevBlockHash();
    bytes32 parentWork;
    parentWork.fill(0);
    uint32_t parentHeight = 0;

    bool parentIsGenesis = (prevHash == NetParams::GetGenesisHash());
    if (!parentIsGenesis) {
        BlockIndexEntry parent;
        if (!mBlockData->ReadBlockIndex(prevHash, parent)) {
            std::cerr << "ChainState: AcceptBlock - unknown parent\n";
            return false;
        }
        parentWork = parent.nChainWork;
        parentHeight = parent.nHeight;
    } else {
        BlockIndexEntry genesisEntry;
        if (!mBlockData->ReadBlockIndex(prevHash, genesisEntry)) {
            std::cerr << "ChainState: AcceptBlock - genesis missing from "
                         "the block index\n";
            return false;
        }
        parentWork = genesisEntry.nChainWork;
        parentHeight = genesisEntry.nHeight;
    }

    const uint32_t blockHeight = parentHeight + 1;

    if (hdr.GetHeight() != blockHeight) {
        std::cerr << "ChainState: AcceptBlock - header height "
                  << hdr.GetHeight() << " != branch height "
                  << blockHeight << "\n";
        return false;
    }

    if (!PNC::CheckProofOfWork(blockHash, hdr.GetBits())) {
        MONEU_LOG_WARN("Block rejected at height " +
                       std::to_string(blockHeight) +
                       ": invalid proof of work");
        return false;
    }

    // History below the highest checkpoint this node holds is settled, and
    // nothing that would branch from it is stored.
    //
    // Cumulative work decides between two chains, and where the target sits
    // at the network floor a competing history is cheap to produce: a
    // branch started far enough back can be rebuilt faster than it was
    // originally mined, then win on work alone. Refusing every block that
    // would sit below the checkpoint denies that branch a place to grow
    // from, so it can never be assembled, let alone overtake.
    //
    // Whether the block agrees with a checkpoint at its own height is not
    // the question and is not asked; the height bound alone leaves the
    // checkpointed block as the only one that can hold its position, since
    // any rival there would have to descend from a parent below it.
    uint32_t lastCheckpointHeight = 0;
    if (LastCheckpointHeight(*mBlockData, lastCheckpointHeight) &&
        blockHeight < lastCheckpointHeight) {
        MONEU_LOG_WARN("Block rejected at height " +
                       std::to_string(blockHeight) +
                       ": forked chain older than the last checkpoint at "
                       "height " + std::to_string(lastCheckpointHeight));
        return false;
    }

    {
        validation::BlockValidationState vstate;
        if (!validation::BlockValidation::ValidateBlock(
                block, *mUTXOSet, blockHeight, vstate)) {
            MONEU_LOG_WARN("Block rejected at height " +
                           std::to_string(blockHeight) + ": " +
                           vstate.reason);
            return false;
        }
    }

    const bytes32 blockWork =
        PNC::AddChainWork(parentWork, hdr.GetBits());

    DiskBlockPos pos;
    if (!mBlockData->WriteBlock(block, blockHeight, blockWork, pos)) {
        std::cerr << "ChainState: AcceptBlock - WriteBlock failed\n";
        return false;
    }

    if (PNC::CompareWork(blockWork, mBestChain.chainWork) <= 0) {
        return true;
    }

    return ActivateBestChainLocked(blockHash);
}

bool ChainState::ActivateBestChainLocked(const bytes32& newTipHash)
{
    std::vector<bytes32> newBranch;
    bytes32 cursor = newTipHash;
    bytes32 forkHash;
    forkHash.fill(0);
    bool forkIsGenesis = false;

    while (true) {
        BlockIndexEntry e;
        if (!mBlockData->ReadBlockIndex(cursor, e)) {
            std::cerr << "ChainState: reorg - missing block in new branch\n";
            return false;
        }
        if (IsOnActiveChainLocked(cursor)) {
            forkHash = cursor;
            break;
        }
        if (e.hashPrev == NetParams::GetGenesisHash()) {
            newBranch.push_back(cursor);
            forkIsGenesis = true;
            break;
        }
        newBranch.push_back(cursor);
        cursor = e.hashPrev;
    }

    while (true) {
        if (forkIsGenesis) {
            if (mBestChain.height == 0) break;
        } else {
            if (mBestChain.blockHash == forkHash) break;
        }
        if (mBestChain.height == 0) {
            std::cerr << "ChainState: reorg - underflowed to genesis "
                         "without reaching fork\n";
            return false;
        }
        if (!DisconnectTipLocked()) {
            std::cerr << "ChainState: reorg - disconnect failed\n";
            return false;
        }
    }

    std::vector<bytes32> connected;
    for (auto it = newBranch.rbegin(); it != newBranch.rend(); ++it) {
        BlockIndexEntry e;
        if (!mBlockData->ReadBlockIndex(*it, e)) {
            std::cerr << "ChainState: reorg - missing branch block on "
                         "connect\n";
            RollbackConnectedLocked(connected);
            return false;
        }
        Block blk;
        if (!mBlockData->ReadBlock(blk, e.blockPos)) {
            std::cerr << "ChainState: reorg - cannot read branch block\n";
            RollbackConnectedLocked(connected);
            return false;
        }
        if (!ConnectBlockLocked(blk)) {
            std::cerr << "ChainState: reorg - branch block rejected on "
                         "connect; rolling back\n";
            RollbackConnectedLocked(connected);
            return false;
        }
        connected.push_back(*it);
    }

    return true;
}

void ChainState::RollbackConnectedLocked(
    const std::vector<bytes32>& connected)
{
    for (auto it = connected.rbegin(); it != connected.rend(); ++it) {
        if (mBestChain.blockHash != *it) {
            std::cerr << "ChainState: rollback - tip is not the block "
                         "expected to be undone\n";
        }
        if (!DisconnectTipLocked()) {
            std::cerr << "ChainState: rollback - failed to disconnect a "
                         "block; chain state may be inconsistent\n";
            return;
        }
    }
}

uint64_t ChainState::GetMedianTimePastLocked(const bytes32& blockHash) const
{
    std::vector<uint64_t> times;
    times.reserve(MEDIAN_TIME_SPAN);

    bytes32 cursor = blockHash;
    for (size_t i = 0; i < MEDIAN_TIME_SPAN; ++i) {
        BlockIndexEntry entry;
        if (!mBlockData->ReadBlockIndex(cursor, entry)) {
            break;
        }
        times.push_back(entry.nTime);

        bool parentIsNull = true;
        for (size_t b = 0; b < entry.hashPrev.size(); ++b) {
            if (entry.hashPrev[b] != 0) { parentIsNull = false; break; }
        }
        if (parentIsNull) break;
        cursor = entry.hashPrev;
    }

    if (times.empty()) {
        return NetParams::GENESIS_TIMESTAMP;
    }

    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}

bool ChainState::IsOnActiveChainLocked(const bytes32& blockHash) const
{
    bytes32 cursor = mBestChain.blockHash;
    uint32_t height = mBestChain.height;
    while (height > 0) {
        if (cursor == blockHash) return true;
        BlockIndexEntry e;
        if (!mBlockData->ReadBlockIndex(cursor, e)) return false;
        cursor = e.hashPrev;
        height--;
    }
    return false;
}

bool ChainState::HasBlock(
    const bytes32& blockHash) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return mBlockData->HasBlock(blockHash);
}

bool ChainState::GetBlock(
    Block& block,
    const bytes32& blockHash) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    BlockIndexEntry entry;
    if (!mBlockData->ReadBlockIndex(blockHash, entry))
        return false;
    return mBlockData->ReadBlock(block, entry.blockPos);
}

std::vector<bytes32> ChainState::GetBlockLocator() const {
    std::lock_guard<std::mutex> lock(mMutex);
    std::vector<bytes32> locator;
    if (!mInitialized) return locator;

    locator.reserve(32);
    uint32_t step = 1;
    int64_t height = static_cast<int64_t>(mBestChain.height);

    while (height >= 0) {
        bytes32 hash;
        if (!GetBlockHashByHeightLocked(static_cast<uint32_t>(height), hash)) {
            break;
        }
        locator.push_back(hash);
        if (height == 0) break;
        if (locator.size() > 10) step *= 2;
        height -= static_cast<int64_t>(step);
        if (height < 0) height = 0;
    }
    return locator;
}

bool ChainState::FindForkPoint(const std::vector<bytes32>& locator,
                               uint32_t& heightOut) const {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mInitialized) return false;

    for (size_t i = 0; i < locator.size(); ++i) {
        BlockIndexEntry entry;
        if (!mBlockData->ReadBlockIndex(locator[i], entry)) continue;
        bytes32 onChain;
        if (!GetBlockHashByHeightLocked(entry.nHeight, onChain)) continue;
        if (!(onChain == locator[i])) continue;
        heightOut = entry.nHeight;
        return true;
    }
    return false;
}

std::vector<bytes32> ChainState::GetBlockHashesAfter(const bytes32& after,
                                                    size_t max) const {
    std::lock_guard<std::mutex> lock(mMutex);
    std::vector<bytes32> out;
    if (!mInitialized || max == 0) return out;

    uint32_t fromHeight = 0;
    if (after == mBestChain.blockHash) {
        return out;
    }

    BlockIndexEntry entry;
    if (!mBlockData->ReadBlockIndex(after, entry)) {
        return out;
    }
    fromHeight = entry.nHeight;

    bytes32 atSameHeight;
    if (!GetBlockHashByHeightLocked(fromHeight, atSameHeight)) return out;
    if (!(atSameHeight == after)) return out;

    for (uint32_t h = fromHeight + 1;
         h <= mBestChain.height && out.size() < max; ++h) {
        bytes32 hash;
        if (!GetBlockHashByHeightLocked(h, hash)) break;
        out.push_back(hash);
    }
    return out;
}

double ChainState::EstimateNetworkHashPS(uint32_t lookback) const {
    std::lock_guard<std::mutex> lock(mMutex);

    const uint32_t tipHeight = mBestChain.height;
    if (tipHeight == 0) return 0.0;

    if (lookback == 0 || lookback > tipHeight) lookback = tipHeight;
    const uint32_t fromHeight = tipHeight - lookback;

    bytes32 fromHash;
    if (!GetBlockHashByHeightLocked(fromHeight, fromHash)) return 0.0;

    BlockIndexEntry fromEntry;
    if (!mBlockData->ReadBlockIndex(fromHash, fromEntry)) return 0.0;

    const PNC::arith_uint256 tipWork = PNC::ArithFromBytes32(mBestChain.chainWork);
    const PNC::arith_uint256 oldWork = PNC::ArithFromBytes32(fromEntry.nChainWork);
    if (tipWork <= oldWork) return 0.0;

    const PNC::arith_uint256 workDiff = tipWork - oldWork;

    const int64_t timeDiff =
        static_cast<int64_t>(mBestChain.timestamp) -
        static_cast<int64_t>(fromEntry.nTime);
    if (timeDiff <= 0) return 0.0;

    return workDiff.ToDouble() / static_cast<double>(timeDiff);
}

bool ChainState::GetBlockHashByHeight(uint32_t height, bytes32& hashOut) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return GetBlockHashByHeightLocked(height, hashOut);
}

bool ChainState::GetBlockHashByHeightLocked(uint32_t height,
                                            bytes32& hashOut) const
{
    if (!mInitialized) return false;
    if (height > mBestChain.height) return false;

    if (height == mBestChain.height) {
        hashOut = mBestChain.blockHash;
        return true;
    }

    bytes32 cursor = mBestChain.blockHash;
    uint32_t h = mBestChain.height;
    while (h > height) {
        BlockIndexEntry entry;
        if (!mBlockData->ReadBlockIndex(cursor, entry)) return false;
        cursor = entry.hashPrev;
        h--;
    }
    hashOut = cursor;
    return true;
}

bool ChainState::GetTransaction(
    const bytes32& txid,
    Transaction& txOut,
    bytes32* blockHashOut,
    uint32_t* heightOut) const
{
    std::lock_guard<std::mutex> lock(mMutex);

    bytes32 blockHash;
    if (!mBlockData->ReadTxIndex(txid, blockHash))
        return false;

    BlockIndexEntry entry;
    if (!mBlockData->ReadBlockIndex(blockHash, entry))
        return false;

    Block block;
    if (!mBlockData->ReadBlock(block, entry.blockPos))
        return false;

    for (const auto& tx : block.GetTransactions()) {
        if (tx.GetHash() == txid) {
            txOut = tx;
            if (blockHashOut) *blockHashOut = blockHash;
            if (heightOut) *heightOut = entry.nHeight;
            return true;
        }
    }
    return false;
}

ChainTip ChainState::GetBestChain() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mBestChain;
}

uint32_t ChainState::GetHeight() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mBestChain.height;
}

bytes32 ChainState::GetBestBlockHash() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mBestChain.blockHash;
}

uint32_t ChainState::GetNextBits() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return GetExpectedBitsLocked(mBestChain.height + 1);
}

uint64_t ChainState::GetMedianTimePast() const
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mInitialized || mBestChain.height == 0) return 0;
    return GetMedianTimePastLocked(mBestChain.blockHash);
}

bool ChainState::GetBlockIndexEntry(
    const bytes32& blockHash,
    BlockIndexEntry& entry) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return mBlockData->ReadBlockIndex(blockHash, entry);
}

bool ChainState::GetCoin(
    const OutPoint& outpoint,
    Coin& coin) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return mUTXOSet->GetCoin(outpoint, coin);
}

bool ChainState::HaveCoin(
    const OutPoint& outpoint) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return mUTXOSet->HaveCoin(outpoint);
}

int64_t ChainState::GetBalance(
    const bytes32& pubkeyHash) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return mUTXOSet->GetBalance(pubkeyHash);
}

std::vector<std::pair<OutPoint, Coin>>
ChainState::GetUTXOsForAddress(
    const bytes32& pubkeyHash) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return mUTXOSet->GetUTXOsForAddress(pubkeyHash);
}

bool ChainState::IsGenesisBlock(
    const bytes32& blockHash) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    bytes32 storedGenesis;
    if (!mDB->Read(DB_CHAIN_GENESIS, storedGenesis))
        return false;
    return storedGenesis == blockHash;
}

bool ChainState::Flush() {
    std::lock_guard<std::mutex> lock(mMutex);
    mBlockData->Flush();
    mUTXOSet->Flush();
    return mDB->Sync();
}

bool ChainState::Sync() {
    std::lock_guard<std::mutex> lock(mMutex);
    mBlockData->Flush();
    mUTXOSet->Sync();
    return mDB->Sync();
}

} // namespace storage
} // namespace MONEU
