// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_NODE_MINER_H
#define MONEU_NODE_MINER_H

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/chain_state.h"
#include "consensus/mempool.h"
#include "net/net.h"

#include <atomic>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <string>
#include <cstdint>

namespace MONEU {
namespace node {

class Miner {
public:
    Miner(storage::ChainState* chainState,
          Mempool* mempool,
          net::ConnManager* connManager);
    ~Miner();

    Miner(const Miner&) = delete;
    Miner& operator=(const Miner&) = delete;

    bool Start(const bytes32& coinbaseOutputHash, int threads);

    void Stop();

    void SetChainSyncCallback(std::function<void()> cb);

    bool IsMining() const { return mMining.load(); }

    void GetStats(uint64_t& hashes, uint64_t& blocks, double& hashRate) const;

    static const int MAX_THREADS = 32;

    static const uint64_t TEMPLATE_REFRESH_MS = 15000;

    Block BuildBlockTemplate(const bytes32& coinbaseOutputHash);

    bool SubmitBlock(const Block& block);

private:
    storage::ChainState* mChainState;
    Mempool*             mMempool;
    net::ConnManager*    mConnManager;
    std::function<void()> mChainSync;

    std::atomic<bool> mMining;
    std::atomic<bool> mStop;

    std::vector<std::thread> mWorkers;
    std::thread              mSubmitter;

    mutable std::atomic<uint64_t> mHashCount;
    mutable std::atomic<uint64_t> mBlockCount;
    mutable std::vector<std::atomic<double> > mWorkerRates;

    std::atomic<int>              mThreadCount;

    bytes32 mCoinbaseOutputHash;

    std::queue<Block>       mFound;
    mutable std::mutex      mFoundMutex;
    std::condition_variable mFoundCv;

    Transaction BuildCoinbase(uint32_t height,
                              uint64_t value,
                              const bytes32& coinbaseOutputHash,
                              uint64_t extraNonce);

    bool ComputeTxFee(const Transaction& tx, uint64_t& feeOut) const;

    bool RunNonceLoop(Block& block, int workerId);

    void ReportRate(int workerId, double rate);

    void WorkerLoop(int workerId);
    void SubmitLoop();

};

} // namespace node
} // namespace MONEU

#endif // MONEU_NODE_MINER_H
