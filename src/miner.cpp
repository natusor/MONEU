// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "miner.h"
#include <unistd.h>
#include "log/log.h"
#include "validation/block_validation.h"
#include "storage/chain_state.h"
#include "consensus/pow.h"
#include "crypto/arith_uint256.h"

#include <chrono>
#include <cstring>
#include <iostream>
#include <algorithm>

namespace MONEU {
namespace node {

namespace {
std::string HashToHex(const bytes32& h) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (size_t i = 0; i < h.size(); ++i) {
        out.push_back(d[(h[i] >> 4) & 0x0F]);
        out.push_back(d[h[i] & 0x0F]);
    }
    return out;
}
}

static uint64_t NowSeconds() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static uint64_t NowMillis() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

Miner::Miner(storage::ChainState* chainState,
             Mempool* mempool,
             net::ConnManager* connManager)
    : mChainState(chainState)
    , mMempool(mempool)
    , mConnManager(connManager)
    , mChainSync()
    , mMining(false)
    , mStop(false)
    , mHashCount(0)
    , mBlockCount(0)

    , mThreadCount(0)
{
    mCoinbaseOutputHash.fill(0);
}

Miner::~Miner() {
    Stop();
}

Transaction Miner::BuildCoinbase(uint32_t height,
                                 uint64_t value,
                                 const bytes32& coinbaseOutputHash,
                                 uint64_t extraNonce)
{
    Transaction tx;

    TxInput in;
    bytes32 nullPrev;
    nullPrev.fill(0);
    in.SetPrevTxHash(nullPrev);
    in.SetOutputIndex(0xFFFFFFFF);

    bytes32 marker;
    marker.fill(0);
    marker[0] = (uint8_t)(height & 0xFF);
    marker[1] = (uint8_t)((height >> 8) & 0xFF);
    marker[2] = (uint8_t)((height >> 16) & 0xFF);
    marker[3] = (uint8_t)((height >> 24) & 0xFF);
    for (int i = 0; i < 8; i++) {
        marker[4 + i] = (uint8_t)((extraNonce >> (8 * i)) & 0xFF);
    }
    in.SetPubkey(marker);
    tx.AddInput(in);

    TxOutput out((int64_t)value, coinbaseOutputHash);
    tx.AddOutput(out);

    return tx;
}

bool Miner::ComputeTxFee(const Transaction& tx, uint64_t& feeOut) const
{
    if (tx.IsCoinbase()) {
        feeOut = 0;
        return true;
    }

    uint64_t totalIn = 0;
    for (size_t i = 0; i < tx.GetInputCount(); ++i) {
        const TxInput& input = tx.GetInputs()[i];
        storage::OutPoint outpoint(
            input.GetPrevTxHash(),
            input.GetOutputIndex());
        storage::Coin coin;
        if (!mChainState->GetCoin(outpoint, coin)) {
            return false;
        }
        uint64_t newIn = totalIn + static_cast<uint64_t>(coin.value);
        if (newIn < totalIn) {
            return false;
        }
        totalIn = newIn;
    }

    uint64_t totalOut = 0;
    for (size_t i = 0; i < tx.GetOutputCount(); ++i) {
        uint64_t newOut =
            totalOut + static_cast<uint64_t>(tx.GetOutputs()[i].GetValue());
        if (newOut < totalOut) {
            return false;
        }
        totalOut = newOut;
    }

    if (totalIn < totalOut) {
        return false;
    }

    feeOut = totalIn - totalOut;
    return true;
}

Block Miner::BuildBlockTemplate(const bytes32& coinbaseOutputHash)
{
    const uint32_t height = mChainState->GetHeight() + 1;
    const uint32_t bits   = mChainState->GetNextBits();
    const bytes32  prev   = mChainState->GetBestBlockHash();
    const uint64_t subsidy = NetParams::GetBlockSubsidy(height);

    const uint64_t extraNonce = NowMillis();

    Block block;
    BlockHeader& hdr = block.GetMutableHeader();
    hdr.SetVersion(BlockHeader::CURRENT_VERSION);
    hdr.SetPrevBlockHash(prev);
    hdr.SetHeight(height);
    hdr.SetBits(bits);
    hdr.SetNonce(0);

    uint64_t now = NowSeconds();
    uint64_t mtp = mChainState->GetMedianTimePast();
    if (mtp < NetParams::GENESIS_TIMESTAMP) mtp = NetParams::GENESIS_TIMESTAMP;
    if (now <= mtp) now = mtp + 1;
    hdr.SetTimestamp(now);

    std::vector<Transaction> body;
    uint64_t totalFees = 0;

    if (mMempool) {
        std::vector<Transaction> pending =
            mMempool->GetTransactions(Block::MAX_TRANSACTIONS);

        Block sizeProbe;
        sizeProbe.GetMutableHeader() = hdr;
        sizeProbe.AddTransaction(
            BuildCoinbase(height, subsidy, coinbaseOutputHash, extraNonce));

        for (const auto& tx : pending) {
            uint64_t fee = 0;
            if (!ComputeTxFee(tx, fee)) {
                continue;
            }

            sizeProbe.AddTransaction(tx);
            if (sizeProbe.GetSerializedSize() > NetParams::MAX_BLOCK_SIZE) {
                sizeProbe.ClearTransactions();
                sizeProbe.AddTransaction(
                    BuildCoinbase(height, subsidy, coinbaseOutputHash,
                                  extraNonce));
                for (const auto& included : body) {
                    sizeProbe.AddTransaction(included);
                }
                break;
            }

            (void)fee;
            body.push_back(tx);
        }
    }

    std::vector<LeafReveal> chosenReveals;
    if (mMempool && mChainState) {
        const storage::UTXOSet& utxoSet = mChainState->GetUTXOSet();
        std::vector<LeafReveal> reveals =
            mMempool->GetReveals(Block::MAX_REVEALS);

        Block roomProbe;
        roomProbe.GetMutableHeader() = hdr;
        roomProbe.AddTransaction(
            BuildCoinbase(height, subsidy, coinbaseOutputHash, extraNonce));
        for (const auto& tx : body) {
            roomProbe.AddTransaction(tx);
        }
        size_t used = roomProbe.GetSerializedSize() + 4;

        std::map<std::string, const Transaction*> hereNow;
        for (size_t i = 0; i < body.size(); ++i) {
            const bytes32 h = body[i].GetHash();
            hereNow[std::string(reinterpret_cast<const char*>(h.data()), 32)]
                = &body[i];
        }

        for (size_t i = 0; i < reveals.size(); ++i) {
            storage::PendingSpend pending;
            bool settlesHere = false;

            if (!utxoSet.GetPendingSpend(reveals[i].GetTxid(), pending)) {
                const std::string key(
                    reinterpret_cast<const char*>(
                        reveals[i].GetTxid().data()), 32);
                std::map<std::string, const Transaction*>::const_iterator it =
                    hereNow.find(key);
                if (it == hereNow.end()) {
                    continue;
                }
                uint64_t txFee = 0;
                if (!ComputeTxFee(*it->second, txFee)) continue;
                pending.tx     = *it->second;
                pending.height = height;
                pending.fee    = static_cast<int64_t>(txFee);
                settlesHere    = true;
            }
            (void)settlesHere;
            if (pending.fee < 0) continue;

            const size_t projected =
                used + 4 + reveals[i].GetSerializedSize();
            if (projected > NetParams::MAX_BLOCK_SIZE) break;

            const uint64_t fee = static_cast<uint64_t>(pending.fee);
            const uint64_t newTotal = totalFees + fee;
            if (newTotal < totalFees) break;

            totalFees = newTotal;
            used = projected;
            chosenReveals.push_back(reveals[i]);
        }
    }

    block.AddTransaction(
        BuildCoinbase(height, subsidy + totalFees,
                      coinbaseOutputHash, extraNonce));
    for (const auto& tx : body) {
        block.AddTransaction(tx);
    }
    for (const auto& reveal : chosenReveals) {
        block.AddReveal(reveal);
    }

    block.UpdateRoots();
    return block;
}

void Miner::ReportRate(int workerId, double rate) {
    if (workerId >= 0 &&
        static_cast<size_t>(workerId) < mWorkerRates.size()) {
        mWorkerRates[workerId].store(rate);
    }
}

bool Miner::RunNonceLoop(Block& block, int workerId)
{
    BlockHeader& hdr = block.GetMutableHeader();
    const uint32_t bits = hdr.GetBits();

    PNC::arith_uint256 target;
    bool neg = false, over = false;
    target.SetCompact(bits, &neg, &over);
    if (neg || over || target == 0) {
        return false;
    }

    uint32_t nonce = hdr.GetNonce();
    uint64_t startMs = NowMillis();
    uint64_t localHashes = 0;

    const bytes32 builtOn = hdr.GetPrevBlockHash();

    uint32_t targetTop = 0;
    {
        const bytes32 tb = PNC::ArithToBytes32(target);
        targetTop = ((uint32_t)tb[0] << 24) | ((uint32_t)tb[1] << 16) |
                    ((uint32_t)tb[2] << 8)  | ((uint32_t)tb[3]);
    }

    uint8_t  buf[BlockHeader::SERIALIZED_SIZE];
    uint32_t midstate[8];
    uint32_t block2[16];
    uint32_t block3[16];

    auto prepare = [&]() {
        if (!hdr.SerializeTo(buf, sizeof(buf))) {
            return;
        }
        uint32_t block1[16];
        for (int i = 0; i < 16; ++i) {
            block1[i] = ((uint32_t)buf[i*4]     << 24) |
                        ((uint32_t)buf[i*4 + 1] << 16) |
                        ((uint32_t)buf[i*4 + 2] << 8)  |
                        ((uint32_t)buf[i*4 + 3]);
        }
        static const uint32_t iv[8] = {
            0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
            0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL };
        sha256_Transform(iv, block1, midstate);

        for (int i = 0; i < 14; ++i) {
            const size_t o = 64 + i*4;
            block2[i] = ((uint32_t)buf[o]     << 24) |
                        ((uint32_t)buf[o + 1] << 16) |
                        ((uint32_t)buf[o + 2] << 8)  |
                        ((uint32_t)buf[o + 3]);
        }
        block2[14] = 0x80000000UL;
        block2[15] = 0;

        for (int i = 0; i < 15; ++i) block3[i] = 0;
        block3[15] = BlockHeader::SERIALIZED_SIZE * 8;
    };

    prepare();

    while (mMining.load() && !mStop.load()) {
        localHashes++;
        mHashCount.fetch_add(1, std::memory_order_relaxed);

        if ((localHashes & 0xFFFF) == 0) {
            if (mChainState &&
                !(mChainState->GetBestBlockHash() == builtOn)) {
                const uint64_t elapsed = NowMillis() - startMs;
                if (elapsed > 0) {
                    ReportRate(workerId, (double)localHashes * 1000.0 /
                                         (double)elapsed);
                }
                return false;
            }

            if (NowMillis() - startMs > TEMPLATE_REFRESH_MS) {
                const uint64_t elapsed = NowMillis() - startMs;
                if (elapsed > 0) {
                    ReportRate(workerId, (double)localHashes * 1000.0 /
                                         (double)elapsed);
                }
                return false;
            }
            const uint64_t now = NowSeconds();
            if (now > hdr.GetTimestamp() + 60) {
                hdr.SetTimestamp(now);
                prepare();
            }
        }

        block2[13] = ((nonce & 0x000000FFu) << 24) |
                     ((nonce & 0x0000FF00u) << 8)  |
                     ((nonce & 0x00FF0000u) >> 8)  |
                     ((nonce & 0xFF000000u) >> 24);

        uint32_t state[8], hw[8];
        sha256_Transform(midstate, block2, state);
        sha256_Transform(state, block3, hw);

        if (hw[0] <= targetTop) {
            bytes32 hash;
            for (int i = 0; i < 8; ++i) {
                hash[i*4]     = (uint8_t)(hw[i] >> 24);
                hash[i*4 + 1] = (uint8_t)(hw[i] >> 16);
                hash[i*4 + 2] = (uint8_t)(hw[i] >> 8);
                hash[i*4 + 3] = (uint8_t)(hw[i]);
            }
            if (PNC::ArithFromBytes32(hash) <= target) {
                hdr.SetNonce(nonce);
                const uint64_t elapsed = NowMillis() - startMs;
                if (elapsed > 0) {
                    ReportRate(workerId, (double)localHashes * 1000.0 /
                                         (double)elapsed);
                }
                return true;
            }
        }

        if (nonce == 0xFFFFFFFFu) {
            hdr.SetTimestamp(NowSeconds());
            prepare();
            nonce = 0;
        } else {
            nonce++;
        }

        if ((localHashes & 0xFFFFF) == 0) {
            const uint64_t sinceStart = NowMillis() - startMs;
            if (sinceStart > 0) {
                ReportRate(workerId, (double)localHashes * 1000.0 /
                                     (double)sinceStart);
            }
        }
    }

    {
        const uint64_t elapsed = NowMillis() - startMs;
        if (elapsed > 0 && localHashes > 0) {
            ReportRate(workerId, (double)localHashes * 1000.0 / (double)elapsed);
        }
    }
    return false;
}

void Miner::WorkerLoop(int workerId)
{
    (void)!nice(10);

    const int loaded = mThreadCount.load();
    const uint32_t threadCount = loaded > 0 ? (uint32_t)loaded : 1;
    const uint32_t nonceStart =
        (uint32_t)((0xFFFFFFFFull / threadCount) * (uint32_t)workerId);
    while (mMining.load() && !mStop.load()) {
        Block block;
        try {
            block = BuildBlockTemplate(mCoinbaseOutputHash);
            block.GetMutableHeader().SetNonce(nonceStart);
        } catch (const std::exception& e) {
            MONEU_LOG_WARN(std::string("Miner: could not build a block "
                                       "template: ") + e.what());
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        const bytes32 builtOn = block.GetHeader().GetPrevBlockHash();

        if (RunNonceLoop(block, workerId)) {
            {
                std::lock_guard<std::mutex> lock(mFoundMutex);
                mFound.push(block);
            }
            mFoundCv.notify_one();
            mBlockCount.fetch_add(1, std::memory_order_relaxed);
        } else if (mMining.load() && !mStop.load()) {
            if (mChainState &&
                !(mChainState->GetBestBlockHash() == builtOn)) {
                MONEU_LOG_DEBUG("Miner: tip moved, starting a new template");
            } else {
                MONEU_LOG_DEBUG("Miner: refreshing the template");
            }
            continue;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void Miner::SubmitLoop()
{
    while (mMining.load() || !mFound.empty()) {
        std::unique_lock<std::mutex> lock(mFoundMutex);
        mFoundCv.wait_for(lock, std::chrono::seconds(1));

        while (!mFound.empty()) {
            Block block = mFound.front();
            mFound.pop();
            lock.unlock();

            SubmitBlock(block);

            lock.lock();
        }
        if (mStop.load() && mFound.empty()) break;
    }
}

void Miner::SetChainSyncCallback(std::function<void()> cb)
{
    mChainSync = std::move(cb);
}

bool Miner::SubmitBlock(const Block& block)
{
    if (!mChainState) return false;

    if (!mChainState->AcceptBlock(block)) {
        MONEU_LOG_WARN("Miner: chain rejected the block just mined at "
                       "height " +
                       std::to_string(block.GetHeader().GetHeight()) +
                       " - the tip moved, or the block is invalid");
        return false;
    }

    if (mChainSync) {
        mChainSync();
    } else if (mMempool) {
        mMempool->RemoveForBlock(block.GetTransactions());
    }

    MONEU_LOG_INFO("Miner: found block at height " +
                   std::to_string(block.GetHeader().GetHeight()) +
                   " hash=" + HashToHex(block.GetHeader().GetHash()) +
                   " tx=" + std::to_string(block.GetTransactionCount()) +
                   " reveals=" + std::to_string(block.GetRevealCount()));

    if (mConnManager) {
        mConnManager->BroadcastBlock(block);
    }
    return true;
}

bool Miner::Start(const bytes32& coinbaseOutputHash, int threads)
{
    if (mMining.load()) {
        MONEU_LOG_WARN("Miner: already running");
        return false;
    }
    bool allZero = true;
    for (uint8_t b : coinbaseOutputHash) {
        if (b != 0) { allZero = false; break; }
    }
    if (allZero) {
        MONEU_LOG_ERROR("Miner: refusing to start - the reward address "
                        "is all zeroes, so the reward would be unspendable");
        return false;
    }
    if (threads < 1) threads = 1;
    if (threads > MAX_THREADS) threads = MAX_THREADS;

    mCoinbaseOutputHash = coinbaseOutputHash;
    mStop.store(false);
    mMining.store(true);
    mHashCount.store(0);
    mWorkerRates = std::vector<std::atomic<double> >(threads);
    for (int i = 0; i < threads; ++i) mWorkerRates[i].store(0.0);

    mThreadCount.store(threads);

    for (int i = 0; i < threads; i++) {
        mWorkers.emplace_back(&Miner::WorkerLoop, this, i);
    }
    mSubmitter = std::thread(&Miner::SubmitLoop, this);

    MONEU_LOG_INFO("Miner: started on " + std::to_string(threads) +
                   " thread(s)");
    return true;
}

void Miner::Stop()
{
    if (!mMining.load()) return;
    mStop.store(true);
    mMining.store(false);
    mFoundCv.notify_all();

    for (auto& t : mWorkers) {
        if (t.joinable()) t.join();
    }
    mWorkers.clear();
    if (mSubmitter.joinable()) mSubmitter.join();

    MONEU_LOG_INFO("Miner: stopped");
}

void Miner::GetStats(uint64_t& hashes, uint64_t& blocks, double& hashRate) const
{
    hashes   = mHashCount.load();
    blocks   = mBlockCount.load();
    hashRate = 0.0;
    for (size_t i = 0; i < mWorkerRates.size(); ++i) {
        hashRate += mWorkerRates[i].load();
    }
}

} // namespace node
} // namespace MONEU
