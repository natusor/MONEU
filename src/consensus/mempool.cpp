// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "mempool.h"
#include <iterator>
#include <fstream>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <set>
#include <cstdint>
#include "../wallet/noise_otp.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace MONEU {

bool Mempool::ExtractLeafKeys(const Transaction& tx,
                              std::vector<std::string>& leafKeys) {
    leafKeys.clear();
    leafKeys.reserve(tx.GetInputCount());
    for (const auto& input : tx.GetInputs()) {
        const std::vector<uint8_t>& proofBytes = input.GetNoiseProof();
        if (proofBytes.empty()) continue;
        try {
            size_t offset = 0;
            NoiseProof proof = NoiseProof::Deserialize(
                proofBytes.data(), proofBytes.size(), offset);
            std::string key(reinterpret_cast<const char*>(
                                input.GetKps().data()), 32);
            key.push_back(static_cast<char>(proof.leafIndex & 0xFF));
            key.push_back(static_cast<char>((proof.leafIndex >> 8) & 0xFF));
            key.push_back(static_cast<char>((proof.leafIndex >> 16) & 0xFF));
            key.push_back(static_cast<char>((proof.leafIndex >> 24) & 0xFF));
            leafKeys.push_back(std::move(key));
        } catch (const std::exception&) {
            return false;
        }
    }
    return true;
}

Mempool::Mempool(size_t maxBytes)
    : mSequenceCounter(0)
    , mMaxBytes(maxBytes)
    , mTotalBytes(0)
    , mRollingMinFeeRate(0.0)
    , mLastRollingFeeUpdate(0)
    , mBlockSinceFeeBump(false)
{
}

int64_t Mempool::NowSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string Mempool::HashToKey(const bytes32& hash) const {
    std::ostringstream oss;
    for (uint8_t b : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    }
    return oss.str();
}

std::string Mempool::OutpointKey(const bytes32& prevTxHash,
                                 uint32_t outputIndex) const {
    std::string key(reinterpret_cast<const char*>(prevTxHash.data()), 32);
    key.push_back(static_cast<char>(outputIndex & 0xFF));
    key.push_back(static_cast<char>((outputIndex >> 8) & 0xFF));
    key.push_back(static_cast<char>((outputIndex >> 16) & 0xFF));
    key.push_back(static_cast<char>((outputIndex >> 24) & 0xFF));
    return key;
}

bool Mempool::ValidateForPool(const Transaction& tx, int64_t fee) const {
    if (!tx.IsValid()) return false;
    if (tx.IsCoinbase()) return false;
    if (fee < 0) return false;
    if (mIndex.find(HashToKey(tx.GetHash())) != mIndex.end()) return false;
    int64_t valueOut = tx.GetValueOut();
    if (valueOut < 0) return false;
    if (valueOut < NetParams::DUST_THRESHOLD) return false;
    return true;
}

int64_t Mempool::GetMinFeeRateLocked(int64_t now) const {
    if (!mBlockSinceFeeBump || mRollingMinFeeRate == 0.0) {
        return static_cast<int64_t>(std::llround(mRollingMinFeeRate));
    }
    if (now > mLastRollingFeeUpdate + 10) {
        double halflife = static_cast<double>(ROLLING_FEE_HALFLIFE);
        if (mTotalBytes < mMaxBytes / 4)      halflife /= 4.0;
        else if (mTotalBytes < mMaxBytes / 2) halflife /= 2.0;

        mRollingMinFeeRate = mRollingMinFeeRate /
            std::pow(2.0, (now - mLastRollingFeeUpdate) / halflife);
        mLastRollingFeeUpdate = now;

        if (mRollingMinFeeRate < INCREMENTAL_FEE_PER_K / 2.0) {
            mRollingMinFeeRate = 0.0;
            return 0;
        }
    }
    return std::max<int64_t>(
        static_cast<int64_t>(std::llround(mRollingMinFeeRate)),
        INCREMENTAL_FEE_PER_K);
}

bool Mempool::RemoveLocked(const std::string& hashKey) {
    auto it = mIndex.find(hashKey);
    if (it == mIndex.end()) return false;
    const Entry& e = it->second;

    mByFeeRate.erase(FeeKey(e.feePerK, e.seq));
    mByTime.erase(TimeKey(e.entryTime, e.seq));
    for (const auto& input : e.tx.GetInputs()) {
        mSpends.erase(OutpointKey(input.GetPrevTxHash(),
                                  input.GetOutputIndex()));
    }
    for (const auto& leafKey : e.leafKeys) {
        mLeafSpends.erase(leafKey);
    }
    mTotalBytes -= e.size;
    mIndex.erase(it);
    return true;
}

std::vector<Mempool::PersistedEntry> Mempool::Snapshot() const {
    std::lock_guard<std::mutex> lock(mMutex);
    std::vector<PersistedEntry> out;
    out.reserve(mIndex.size());
    for (std::unordered_map<std::string, Entry>::const_iterator it =
             mIndex.begin(); it != mIndex.end(); ++it) {
        PersistedEntry e;
        e.tx        = it->second.tx;
        e.fee       = it->second.fee;
        e.entryTime = it->second.entryTime;
        const std::string key =
            HashToKey(it->second.tx.GetHash());
        std::map<std::string, LeafReveal>::const_iterator rv =
            mReveals.find(key);
        if (rv != mReveals.end()) {
            e.hasReveal = true;
            e.reveal    = rv->second;
        }
        out.push_back(e);
    }
    std::sort(out.begin(), out.end(),
              [](const PersistedEntry& a, const PersistedEntry& b) {
                  return a.entryTime < b.entryTime;
              });
    return out;
}

namespace {

void PutU32(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

void PutU64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

bool TakeU32(const std::vector<uint8_t>& buf, size_t& off, uint32_t& out) {
    if (off + 4 > buf.size()) return false;
    out = 0;
    for (int i = 3; i >= 0; --i)
        out = (out << 8) | buf[off + static_cast<size_t>(i)];
    off += 4;
    return true;
}

bool TakeU64(const std::vector<uint8_t>& buf, size_t& off, uint64_t& out) {
    if (off + 8 > buf.size()) return false;
    out = 0;
    for (int i = 7; i >= 0; --i)
        out = (out << 8) | buf[off + static_cast<size_t>(i)];
    off += 8;
    return true;
}

}

bool Mempool::Save(const boost::filesystem::path& path) const {
    const std::vector<PersistedEntry> entries = Snapshot();

    std::vector<uint8_t> buf;
    PutU32(buf, PERSIST_VERSION);
    PutU32(buf, static_cast<uint32_t>(entries.size()));
    for (size_t i = 0; i < entries.size(); ++i) {
        const std::vector<uint8_t> raw = entries[i].tx.Serialize(true);
        PutU32(buf, static_cast<uint32_t>(raw.size()));
        buf.insert(buf.end(), raw.begin(), raw.end());
        PutU64(buf, static_cast<uint64_t>(entries[i].fee));
        PutU64(buf, static_cast<uint64_t>(entries[i].entryTime));
        if (entries[i].hasReveal) {
            const std::vector<uint8_t> rv = entries[i].reveal.Serialize();
            PutU32(buf, static_cast<uint32_t>(rv.size()));
            buf.insert(buf.end(), rv.begin(), rv.end());
        } else {
            PutU32(buf, 0);
        }
    }

    const boost::filesystem::path tmp = path.string() + ".new";
    const int fd = ::open(tmp.string().c_str(),
                          O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        std::cerr << "Mempool: cannot open " << tmp.string()
                  << " for writing\n";
        return false;
    }

    bool ok = true;
    size_t written = 0;
    while (ok && written < buf.size()) {
        const ssize_t n = ::write(fd, buf.data() + written,
                                  buf.size() - written);
        if (n < 0) { if (errno == EINTR) continue; ok = false; break; }
        if (n == 0) { ok = false; break; }
        written += static_cast<size_t>(n);
    }
    if (ok && ::fsync(fd) != 0) ok = false;
    if (::close(fd) != 0) ok = false;

    if (!ok) {
        ::unlink(tmp.string().c_str());
        std::cerr << "Mempool: failed to write " << tmp.string() << "\n";
        return false;
    }

    boost::system::error_code ec;
    boost::filesystem::rename(tmp, path, ec);
    if (ec) {
        ::unlink(tmp.string().c_str());
        std::cerr << "Mempool: cannot rename " << tmp.string() << " to "
                  << path.string() << ": " << ec.message() << "\n";
        return false;
    }

    std::cerr << "Mempool: wrote " << entries.size()
              << " transaction(s) to " << path.string() << "\n";
    return true;
}

size_t Mempool::Load(const boost::filesystem::path& path,
                     int64_t now,
                     AdmitFn admit,
                     DroppedFn dropped,
                     void* context)
{
    if (admit == NULL) return 0;

    boost::system::error_code ec;
    if (!boost::filesystem::exists(path, ec)) return 0;

    std::ifstream file(path.string().c_str(), std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Mempool: cannot open " << path.string() << "\n";
        return 0;
    }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
    file.close();

    size_t off = 0;
    uint32_t version = 0;
    uint32_t count = 0;
    if (!TakeU32(buf, off, version) || !TakeU32(buf, off, count)) {
        std::cerr << "Mempool: " << path.string()
                  << " is too short to be a pool file; ignoring it\n";
        return 0;
    }
    if (version != PERSIST_VERSION) {
        std::cerr << "Mempool: " << path.string() << " is version "
                  << version << ", this node writes version "
                  << PERSIST_VERSION << "; ignoring it\n";
        return 0;
    }
    if (count > PERSIST_MAX_ENTRIES) {
        std::cerr << "Mempool: " << path.string() << " claims " << count
                  << " entries, beyond anything this pool holds; "
                     "ignoring it\n";
        return 0;
    }

    size_t restored = 0, expiredCount = 0, refused = 0;

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t txLen = 0;
        if (!TakeU32(buf, off, txLen)) break;
        if (txLen == 0 || txLen > Transaction::MAX_TX_SIZE) break;
        if (off + txLen > buf.size()) break;

        Transaction tx;
        try {
            tx = Transaction::Deserialize(buf.data() + off, txLen);
        } catch (const std::exception&) {
            break;
        }
        off += txLen;

        uint64_t rawFee = 0, rawTime = 0;
        if (!TakeU64(buf, off, rawFee) || !TakeU64(buf, off, rawTime)) break;
        const int64_t entryTime = static_cast<int64_t>(rawTime);

        uint32_t revealLen = 0;
        if (!TakeU32(buf, off, revealLen)) break;
        LeafReveal reveal;
        bool haveReveal = false;
        if (revealLen > 0) {
            if (off + revealLen > buf.size()) break;
            try {
                size_t rOff = 0;
                reveal = LeafReveal::Deserialize(buf.data() + off,
                                                 revealLen, rOff);
                haveReveal = true;
            } catch (const std::exception&) {
                off += revealLen;
                ++refused;
                if (dropped != NULL) dropped(tx, context);
                continue;
            }
            off += revealLen;
        }

        if (entryTime > 0 && now - entryTime > MEMPOOL_EXPIRY_SECONDS) {
            ++expiredCount;
            if (dropped != NULL) dropped(tx, context);
            continue;
        }

        int64_t fee = 0;
        if (!admit(tx, fee, context)) {
            ++refused;
            if (dropped != NULL) dropped(tx, context);
            continue;
        }
        if (!HasTransaction(tx.GetHash())) {
            if (!AddTransaction(tx, fee)) {
                ++refused;
                if (dropped != NULL) dropped(tx, context);
                continue;
            }
        }
        if (haveReveal) AddReveal(reveal);
        ++restored;
    }

    std::cerr << "Mempool: restored " << restored << " transaction(s), "
              << refused << " no longer valid, " << expiredCount
              << " expired\n";
    return restored;
}

void Mempool::CollectDescendantsLocked(
    const std::string& hashKey,
    std::vector<std::string>& out) const
{
    std::set<std::string> seen;
    std::vector<std::string> queue;
    queue.push_back(hashKey);
    seen.insert(hashKey);

    for (size_t head = 0; head < queue.size(); ++head) {
        std::unordered_map<std::string, Entry>::const_iterator it =
            mIndex.find(queue[head]);
        if (it == mIndex.end()) continue;

        const bytes32 txid = it->second.tx.GetHash();
        const size_t outCount = it->second.tx.GetOutputCount();
        for (size_t i = 0; i < outCount; ++i) {
            std::unordered_map<std::string, std::string>::const_iterator sp =
                mSpends.find(OutpointKey(txid, static_cast<uint32_t>(i)));
            if (sp == mSpends.end()) continue;
            if (seen.insert(sp->second).second) queue.push_back(sp->second);
        }
    }
    out.assign(queue.begin(), queue.end());
}

size_t Mempool::RemoveRecursiveLocked(const std::string& hashKey) {
    std::vector<std::string> doomed;
    CollectDescendantsLocked(hashKey, doomed);
    size_t removed = 0;
    for (size_t i = doomed.size(); i-- > 0; ) {
        if (RemoveLocked(doomed[i])) ++removed;
    }
    return removed;
}

size_t Mempool::CountAncestorsLocked(const Transaction& tx) const {
    std::set<std::string> seen;
    std::vector<std::string> queue;

    for (size_t i = 0; i < tx.GetInputCount(); ++i) {
        const std::string parent =
            HashToKey(tx.GetInputs()[i].GetPrevTxHash());
        if (mIndex.find(parent) == mIndex.end()) continue;
        if (seen.insert(parent).second) queue.push_back(parent);
    }
    for (size_t head = 0; head < queue.size(); ++head) {
        std::unordered_map<std::string, Entry>::const_iterator it =
            mIndex.find(queue[head]);
        if (it == mIndex.end()) continue;
        const Transaction& parentTx = it->second.tx;
        for (size_t i = 0; i < parentTx.GetInputCount(); ++i) {
            const std::string grand =
                HashToKey(parentTx.GetInputs()[i].GetPrevTxHash());
            if (mIndex.find(grand) == mIndex.end()) continue;
            if (seen.insert(grand).second) queue.push_back(grand);
        }
    }
    return seen.size() + 1;
}

size_t Mempool::CountDescendantsLocked(const std::string& hashKey) const {
    std::vector<std::string> all;
    CollectDescendantsLocked(hashKey, all);
    return all.size();
}

void Mempool::TrimLocked(int64_t now) {
    while (mTotalBytes > mMaxBytes && !mByFeeRate.empty()) {
        auto cheapest = mByFeeRate.begin();
        const int64_t evictedRate = cheapest->first.first;
        const std::string hashKey = cheapest->second;

        const double bumped =
            static_cast<double>(evictedRate + INCREMENTAL_FEE_PER_K);
        if (bumped > mRollingMinFeeRate) {
            mRollingMinFeeRate = bumped;
            mLastRollingFeeUpdate = now;
            mBlockSinceFeeBump = false;
        }
        RemoveRecursiveLocked(hashKey);
        std::cerr << "Mempool: evicted lowest fee rate "
                  << evictedRate << " sat/kB (pool over "
                  << mMaxBytes << " bytes)\n";
    }
}

int Mempool::ExpireLocked(int64_t now) {
    int removed = 0;
    const int64_t cutoff = now - MEMPOOL_EXPIRY_SECONDS;
    while (!mByTime.empty() && mByTime.begin()->first.first < cutoff) {
        const std::string hashKey = mByTime.begin()->second;
        RemoveLocked(hashKey);
        ++removed;
    }
    if (removed > 0) {
        std::cerr << "Mempool: expired " << removed
                  << " transaction(s) older than "
                  << (MEMPOOL_EXPIRY_SECONDS / 3600) << "h\n";
    }
    return removed;
}

bool Mempool::AddTransaction(const Transaction& tx, int64_t fee) {
    std::lock_guard<std::mutex> lock(mMutex);
    const int64_t now = NowSeconds();

    ExpireLocked(now);

    if (!ValidateForPool(tx, fee)) return false;

    for (const auto& input : tx.GetInputs()) {
        if (mSpends.find(OutpointKey(input.GetPrevTxHash(),
                                     input.GetOutputIndex()))
            != mSpends.end()) {
            std::cerr << "Mempool: rejected in-pool double spend\n";
            return false;
        }
    }

    std::vector<std::string> leafKeys;
    ExtractLeafKeys(tx, leafKeys);
    for (size_t i = 0; i < leafKeys.size(); ++i) {
        if (mLeafSpends.find(leafKeys[i]) != mLeafSpends.end()) {
            std::cerr << "Mempool: rejected in-pool noise leaf reuse\n";
            return false;
        }
        for (size_t j = 0; j < i; ++j) {
            if (leafKeys[j] == leafKeys[i]) {
                std::cerr << "Mempool: rejected duplicate noise leaf "
                             "within transaction\n";
                return false;
            }
        }
    }

    const size_t size = tx.GetSerializedSize();
    if (size == 0) return false;
    int64_t feePerK;
    if (fee > INT64_MAX / 1000) {
        feePerK = INT64_MAX;
    } else {
        feePerK = (fee * 1000) / static_cast<int64_t>(size);
    }

    const int64_t minRate = GetMinFeeRateLocked(now);
    if (feePerK < minRate) {
        std::cerr << "Mempool: rejected, fee rate " << feePerK
                  << " below rolling minimum " << minRate << " sat/kB\n";
        return false;
    }

    const size_t ancestors = CountAncestorsLocked(tx);

    if (ancestors > MAX_ANCESTORS) {

        std::cerr << "Mempool: rejected, " << ancestors

                  << " unconfirmed ancestors exceeds "

                  << MAX_ANCESTORS << "\n";

        return false;

    }

    for (size_t i = 0; i < tx.GetInputCount(); ++i) {

        const std::string parent =

            HashToKey(tx.GetInputs()[i].GetPrevTxHash());

        if (mIndex.find(parent) == mIndex.end()) continue;

        if (CountDescendantsLocked(parent) + 1 > MAX_DESCENDANTS) {

            std::cerr << "Mempool: rejected, a parent already has "

                      << MAX_DESCENDANTS << " descendants\n";

            return false;

        }

    }

    Entry e;
    e.tx        = tx;
    e.fee       = fee;
    e.size      = size;
    e.feePerK   = feePerK;
    e.seq       = ++mSequenceCounter;
    e.entryTime = now;
    e.leafKeys  = leafKeys;

    const std::string hashKey = HashToKey(tx.GetHash());
    mIndex[hashKey] = e;
    mByFeeRate[FeeKey(e.feePerK, e.seq)] = hashKey;
    mByTime[TimeKey(e.entryTime, e.seq)] = hashKey;
    for (const auto& input : tx.GetInputs()) {
        mSpends[OutpointKey(input.GetPrevTxHash(),
                            input.GetOutputIndex())] = hashKey;
    }
    for (const auto& leafKey : leafKeys) {
        mLeafSpends[leafKey] = hashKey;
    }
    mTotalBytes += size;

    TrimLocked(now);

    return mIndex.find(hashKey) != mIndex.end();
}

bool Mempool::RemoveTransaction(const bytes32& txHash) {
    std::lock_guard<std::mutex> lock(mMutex);
    return RemoveLocked(HashToKey(txHash));
}

void Mempool::RemoveForBlock(const std::vector<Transaction>& blockTxs) {
    std::lock_guard<std::mutex> lock(mMutex);
    for (const auto& tx : blockTxs) {
        if (tx.IsCoinbase()) continue;
        RemoveRecursiveLocked(HashToKey(tx.GetHash()));
        for (const auto& input : tx.GetInputs()) {
            auto it = mSpends.find(OutpointKey(input.GetPrevTxHash(),
                                               input.GetOutputIndex()));
            if (it != mSpends.end()) {
                const std::string conflicting = it->second;
                RemoveRecursiveLocked(conflicting);
            }
        }
        std::vector<std::string> leafKeys;
        if (ExtractLeafKeys(tx, leafKeys)) {
            for (const auto& leafKey : leafKeys) {
                auto it = mLeafSpends.find(leafKey);
                if (it != mLeafSpends.end()) {
                    const std::string conflicting = it->second;
                    RemoveRecursiveLocked(conflicting);
                }
            }
        }
    }
    mBlockSinceFeeBump = true;
}

bool Mempool::GetTransaction(Transaction& tx, const bytes32& txHash) const {
    std::lock_guard<std::mutex> lock(mMutex);
    auto it = mIndex.find(HashToKey(txHash));
    if (it == mIndex.end()) return false;
    tx = it->second.tx;
    return true;
}

bool Mempool::HasTransaction(const bytes32& txHash) const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mIndex.find(HashToKey(txHash)) != mIndex.end();
}

std::vector<Transaction> Mempool::GetTransactions(size_t maxCount) const {
    std::lock_guard<std::mutex> lock(mMutex);
    std::vector<Transaction> out;
    out.reserve(std::min(maxCount, mIndex.size()));
    for (auto it = mByFeeRate.rbegin();
         it != mByFeeRate.rend() && out.size() < maxCount; ++it) {
        auto entry = mIndex.find(it->second);
        if (entry != mIndex.end()) {
            out.push_back(entry->second.tx);
        }
    }
    return out;
}

int64_t Mempool::GetMinFeeRate() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return GetMinFeeRateLocked(NowSeconds());
}

bool Mempool::AddReveal(const LeafReveal& reveal) {
    if (!reveal.IsWellFormed()) return false;
    std::lock_guard<std::mutex> lock(mMutex);
    const std::string key = HashToKey(reveal.GetTxid());
    if (mReveals.find(key) != mReveals.end()) {
        return false;
    }
    mReveals[key] = reveal;
    return true;
}

bool Mempool::HasReveal(const bytes32& txid) const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mReveals.find(HashToKey(txid)) != mReveals.end();
}

bool Mempool::GetReveal(LeafReveal& out, const bytes32& txid) const {
    std::lock_guard<std::mutex> lock(mMutex);
    auto it = mReveals.find(HashToKey(txid));
    if (it == mReveals.end()) return false;
    out = it->second;
    return true;
}

bool Mempool::RemoveReveal(const bytes32& txid) {
    std::lock_guard<std::mutex> lock(mMutex);
    return mReveals.erase(HashToKey(txid)) > 0;
}

std::vector<LeafReveal> Mempool::GetReveals(size_t maxCount) const {
    std::lock_guard<std::mutex> lock(mMutex);
    std::vector<LeafReveal> out;
    out.reserve(mReveals.size() < maxCount ? mReveals.size() : maxCount);
    for (const auto& entry : mReveals) {
        if (out.size() >= maxCount) break;
        out.push_back(entry.second);
    }
    return out;
}

void Mempool::RemoveRevealsForBlock(
    const std::vector<LeafReveal>& blockReveals) {
    std::lock_guard<std::mutex> lock(mMutex);
    for (size_t i = 0; i < blockReveals.size(); ++i) {
        mReveals.erase(HashToKey(blockReveals[i].GetTxid()));
    }
}

size_t Mempool::DropRevealsNotHeld(const std::vector<bytes32>& stillHeld) {
    std::lock_guard<std::mutex> lock(mMutex);
    std::set<std::string> keep;
    for (size_t i = 0; i < stillHeld.size(); ++i) {
        keep.insert(HashToKey(stillHeld[i]));
    }
    size_t dropped = 0;
    auto it = mReveals.begin();
    while (it != mReveals.end()) {
        if (keep.find(it->first) == keep.end()) {
            it = mReveals.erase(it);
            dropped++;
        } else {
            ++it;
        }
    }
    return dropped;
}

size_t Mempool::RevealCount() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mReveals.size();
}

size_t Mempool::Size() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mIndex.size();
}

size_t Mempool::SizeBytes() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mTotalBytes;
}

void Mempool::Clear() {
    std::lock_guard<std::mutex> lock(mMutex);
    mReveals.clear();
    mIndex.clear();
    mByFeeRate.clear();
    mByTime.clear();
    mSpends.clear();
    mLeafSpends.clear();
    mTotalBytes = 0;
}

} // namespace MONEU
