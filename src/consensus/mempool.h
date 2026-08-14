// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_CONSENSUS_MEMPOOL_H
#define MONEU_CONSENSUS_MEMPOOL_H

#include "../primitives/transaction.h"
#include "../primitives/leaf_reveal.h"
#include "../chainparams.h"
#include <map>
#include <unordered_map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <boost/filesystem.hpp>
#include <cstdint>

namespace MONEU {

// Transaction memory pool for a proof-of-work node.
//
// The pool holds fully validated pending transactions (the network and RPC
// admission paths run CheckTransaction + CheckTransactionWithUTXO +
// VerifyTransactionSignatures before calling AddTransaction) and hands them
// back for relay and block assembly. What the pool itself enforces is the
// resource policy, modeled on Bitcoin Core's CTxMemPool:
//
//   - The pool is limited in BYTES (sum of serialized transaction sizes,
//     noise proofs included), not in transaction count: bytes are the real
//     memory cost, and a count limit would let an attacker occupy far more
//     RAM with large transactions than intended.
//   - When the byte limit is exceeded, TrimLocked evicts the transactions
//     with the LOWEST fee rate first (fee per 1000 bytes), so under load
//     admission becomes a fee auction instead of first-come-first-served.
//     Flooding the pool with cheap transactions therefore cannot block it:
//     anyone paying more displaces the flood.
//   - Every eviction bumps a rolling minimum fee rate to the evicted rate
//     plus INCREMENTAL_FEE_PER_K, and new transactions below the rolling
//     rate are rejected outright - re-sending the evicted spam is not
//     enough to get back in. The rolling rate decays exponentially
//     (ROLLING_FEE_HALFLIFE, faster when the pool is emptier) once a block
//     has confirmed since the last bump, exactly like Bitcoin's
//     CTxMemPool::GetMinFee.
//   - Entries older than MEMPOOL_EXPIRY_SECONDS are expired lazily on each
//     admission, so transactions that will never confirm cannot occupy the
//     pool forever.
//   - An outpoint index rejects in-pool double spends: two pending
//     transactions can never spend the same output (UTXO validation alone
//     cannot see this, because neither spend is confirmed yet).
//   - A noise-leaf index rejects in-pool reuse of a single-use leaf: two
//     pending transactions can never consume the same (KPS, leafIndex),
//     even when they spend different outputs. Leaves are not bound to
//     outpoints, so the outpoint index cannot catch this; without it a
//     wallet replaying a stale leaf (or an attacker rebinding a captured
//     one) would put two conflicting transactions into the pool and the
//     miner would assemble a block its own network rejects.
//   - RemoveForBlock drops every transaction confirmed by a connected
//     block, plus any pending transaction that conflicts with one (spends
//     an outpoint the block spent, or consumes a noise leaf the block
//     consumed). Without this, mined transactions would re-enter the next
//     block template and the chain would reject it.
//
// Absolute fee floors (MIN_TX_FEE, dust) are consensus rules enforced in
// tx_validation before admission; the rolling rate here operates above
// that floor. Coinbase transactions never enter the pool.
//
// Block assembly order: GetTransactions returns highest fee rate first,
// so miners collect the most fees the pool can offer (Bitcoin's model),
// with admission order as the tie-breaker.
class Mempool {
private:
    struct Entry {
        Transaction tx;
        int64_t     fee;        // satoshis: totalIn - totalOut, computed by
                                // the admission path against the UTXO set
        size_t      size;       // serialized bytes, noise proofs included
        int64_t     feePerK;    // fee * 1000 / size - the eviction key
        uint64_t    seq;        // admission order, tie-breaker
        int64_t     entryTime;  // unix seconds, drives expiry
        std::vector<std::string> leafKeys; // noise leaves this tx consumes,
                                           // parsed once at admission

        Entry() : fee(0), size(0), feePerK(0), seq(0), entryTime(0) {}
    };

    // {feePerK, seq} and {entryTime, seq} keys make every map entry unique
    // and give O(log n) ordered access: cheapest first for eviction,
    // oldest first for expiry.
    using FeeKey  = std::pair<int64_t, uint64_t>;
    using TimeKey = std::pair<int64_t, uint64_t>;

    mutable std::mutex mMutex;

    std::unordered_map<std::string, Entry> mIndex;      // tx hash -> entry
    std::map<FeeKey, std::string>          mByFeeRate;  // cheapest at begin()
    std::map<TimeKey, std::string>         mByTime;     // oldest at begin()
    std::unordered_map<std::string, std::string> mSpends; // outpoint -> tx hash
    std::unordered_map<std::string, std::string> mLeafSpends; // leaf -> tx hash

    // Reveals waiting to go into a block, keyed by the transaction they
    // settle. One transaction is settled once, so one entry per txid is
    // all that can ever be useful.
    //
    // These are kept apart from transactions on purpose. A reveal pays no
    // fee of its own - the fee was set by the transaction it settles - so
    // it has no place in a fee-ordered queue, and it must never be
    // displaced by one. A held spend that loses its reveal to eviction
    // would expire and the payment would simply fail.
    std::map<std::string, LeafReveal> mReveals;

    uint64_t mSequenceCounter;
    size_t   mMaxBytes;
    size_t   mTotalBytes;

    // Rolling minimum fee rate (satoshis per 1000 bytes), Bitcoin's
    // GetMinFee mechanism: bumped on eviction, decays over time once a
    // block has confirmed since the last bump.
    mutable double  mRollingMinFeeRate;
    mutable int64_t mLastRollingFeeUpdate;
    mutable bool    mBlockSinceFeeBump;

    static int64_t NowSeconds();

    std::string HashToKey(const bytes32& hash) const;
    std::string OutpointKey(const bytes32& prevTxHash,
                            uint32_t outputIndex) const;

    // Parse every input's noise proof and produce one key per consumed leaf
    // (KPS bytes + little-endian leaf index). False on a missing or
    // malformed proof - such a transaction can never confirm.
    static bool ExtractLeafKeys(const Transaction& tx,
                                std::vector<std::string>& leafKeys);

    bool ValidateForPool(const Transaction& tx, int64_t fee) const;

    // Mutex-free internals; public methods take mMutex and delegate.
    bool    RemoveLocked(const std::string& hashKey);

    // Remove a transaction together with everything in the pool that spends
    // it, directly or through a chain of spends. Returns how many went.
    //
    // RemoveLocked on its own leaves children behind pointing at an output
    // that now exists nowhere - not on the chain, not in the pool. Such a
    // child sits until it expires, keeps its outpoint and its noise leaf
    // reserved, and is handed to the miner on every rebuild only to be
    // dropped again. The leaf it burned never comes back.
    //
    // Called with mMutex already held.
    size_t  RemoveRecursiveLocked(const std::string& hashKey);

    // Collect hashKey and every descendant of it the pool holds, deepest
    // last. Called with mMutex already held.
    void    CollectDescendantsLocked(const std::string& hashKey,
                                     std::vector<std::string>& out) const;

    // How many pool entries this transaction would sit on top of, counting
    // itself. Called with mMutex already held.
    size_t  CountAncestorsLocked(const Transaction& tx) const;

    // How many pool entries already depend on this one, counting itself.
    // Called with mMutex already held.
    size_t  CountDescendantsLocked(const std::string& hashKey) const;
    void    TrimLocked(int64_t now);
    int     ExpireLocked(int64_t now);
    int64_t GetMinFeeRateLocked(int64_t now) const;

public:
    // Pool byte budget. Bitcoin Core defaults to 300 MB (-maxmempool);
    // the same figure keeps a full pool's worth of paying transactions
    // available to miners without exhausting a modest node.
    static constexpr size_t DEFAULT_MAX_BYTES = 300u * 1000u * 1000u;

    // Entries older than this are expired (Bitcoin: -mempoolexpiry, 336 h).
    static constexpr int64_t MEMPOOL_EXPIRY_SECONDS = 336LL * 3600LL;

    // Step added on top of an evicted fee rate when bumping the rolling
    // minimum (Bitcoin: incremental relay fee, 1000 sat/kvB). Re-entering
    // after eviction always costs strictly more than what was evicted.
    static constexpr int64_t INCREMENTAL_FEE_PER_K = 1000;

    // Longest chain of unconfirmed spends the pool will carry.
    //
    // Without a cap a wallet spending its own change repeatedly builds a
    // chain of any length, and every one of those has to be ordered by
    // dependency before a template can be built - work that grows faster
    // than the chain does. The cap also bounds how much is lost at once
    // when the head of a chain is evicted, since everything above it goes
    // with it. Bitcoin uses 25 in both directions for the same reasons.
    static const size_t MAX_ANCESTORS   = 25;
    static const size_t MAX_DESCENDANTS = 25;

    // One entry of the pool as it stands, for writing to disk.
    struct PersistedEntry {
        Transaction tx;
        int64_t     fee;
        int64_t     entryTime;
        bool        hasReveal;
        LeafReveal  reveal;

        PersistedEntry() : fee(0), entryTime(0), hasReveal(false) {}
    };

    // Snapshot of everything the pool holds, in admission order.
    //
    // Taken under the pool's own lock and returned by value, so the caller
    // can write it out without the pool standing still for a disk write.
    std::vector<PersistedEntry> Snapshot() const;

    // Write the pool to `path`, and read it back.
    //
    // The pool exists only in memory, so stopping a node used to throw away
    // every transaction waiting for a block. Here that costs more than
    // elsewhere: a spend consumes a noise leaf when it is signed, and a
    // transaction lost this way takes its leaf with it. The leaf does not
    // come back, so the transaction had better.
    //
    // Save() writes to a temporary file, forces it to the device and
    // renames it over the target, so an interrupted write never leaves a
    // half-written pool behind.
    //
    // Load() puts every entry back through the caller's own admission
    // check; nothing is trusted because it came from the file. A spend
    // confirmed while the node was down has its inputs already spent and
    // is refused there on its own, so the block index is never consulted.
    // Entries past the expiry window are dropped without being offered.
    //
    // `dropped` is called for every entry that did not make it back, so a
    // wallet can release the inputs it had reserved.
    typedef bool (*AdmitFn)(const Transaction& tx, int64_t& feeOut,
                            void* context);
    typedef void (*DroppedFn)(const Transaction& tx, void* context);

    bool Save(const boost::filesystem::path& path) const;
    size_t Load(const boost::filesystem::path& path,
                int64_t now,
                AdmitFn admit,
                DroppedFn dropped,
                void* context);

    // Version of the on-disk format. A file written by another version is
    // discarded rather than guessed at.
    static const uint32_t PERSIST_VERSION = 1;

    // Ceiling on how many entries a file may claim to hold, so a damaged
    // length field cannot ask for an unbounded allocation.
    static const uint32_t PERSIST_MAX_ENTRIES = 500000;

    // Half-life of the rolling minimum fee decay (Bitcoin: 12 h). Divided
    // by 2 when the pool is under half full and by 4 under a quarter, so
    // the barrier relaxes faster once pressure is gone.
    static constexpr int64_t ROLLING_FEE_HALFLIFE = 12LL * 3600LL;

    explicit Mempool(size_t maxBytes = DEFAULT_MAX_BYTES);
    ~Mempool() = default;

    Mempool(const Mempool&) = delete;
    Mempool& operator=(const Mempool&) = delete;

    // Admit a fully validated transaction with its fee (totalIn - totalOut,
    // computed by the caller against the UTXO set during validation).
    // Returns false if the transaction is structurally invalid, a
    // duplicate, a coinbase, dust, an in-pool double spend, an in-pool
    // reuse of a single-use noise leaf, below the rolling minimum fee rate,
    // or evicted immediately by the trim because the pool is full of
    // better-paying transactions.
    bool AddTransaction(const Transaction& tx, int64_t fee);

    // Remove a transaction by hash (O(log n)). No-op if absent.
    bool RemoveTransaction(const bytes32& txHash);

    // Drop every transaction confirmed by a connected block and every
    // pending transaction that conflicts with one. Call after each
    // successful block connect (own mined blocks included). Marks that a
    // block passed, which arms the rolling-fee decay.
    void RemoveForBlock(const std::vector<Transaction>& blockTxs);

    // Fetch a transaction by hash for relay. False if not present.
    bool GetTransaction(Transaction& tx, const bytes32& txHash) const;

    bool HasTransaction(const bytes32& txHash) const;

    // Snapshot for block assembly: highest fee rate first, admission order
    // as tie-breaker, capped at maxCount.
    std::vector<Transaction> GetTransactions(size_t maxCount) const;

    // Current dynamic admission threshold in satoshis per 1000 bytes
    // (0 when the pool is not under pressure).
    int64_t GetMinFeeRate() const;

    // Admit a reveal for relay and block assembly. The caller validates it
    // against the chain first, exactly as it does for transactions.
    // Returns false if one for the same transaction is already waiting.
    bool AddReveal(const LeafReveal& reveal);

    bool HasReveal(const bytes32& txid) const;
    bool GetReveal(LeafReveal& out, const bytes32& txid) const;
    bool RemoveReveal(const bytes32& txid);

    // Snapshot for block assembly, capped at maxCount.
    std::vector<LeafReveal> GetReveals(size_t maxCount) const;

    // Drop every reveal a connected block settled. Call alongside
    // RemoveForBlock.
    void RemoveRevealsForBlock(const std::vector<LeafReveal>& blockReveals);

    // Drop reveals whose transaction is no longer waiting - it either
    // settled or its window closed. Called with the set of txids that are
    // still held, so anything else goes.
    size_t DropRevealsNotHeld(const std::vector<bytes32>& stillHeld);

    size_t RevealCount() const;

    size_t Size() const;
    size_t SizeBytes() const;
    void Clear();
};

}

#endif
