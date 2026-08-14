// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "utxo_set.h"
#include <memory>
#include "../wallet/noise_otp.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <stdexcept>

namespace MONEU {
namespace storage {

static std::string MakeNoiseLeafDBKey(const bytes32& kps, uint32_t leafIndex) {
    std::string key;
    key.reserve(1 + 32 + 4);
    key.push_back(DB_NOISE_LEAF);
    key.append(reinterpret_cast<const char*>(kps.data()), kps.size());
    for (int b = 0; b < 4; ++b) {
        key.push_back(static_cast<char>((leafIndex >> (8 * b)) & 0xFF));
    }
    return key;
}

static std::string MakePendingDBKey(const bytes32& txid) {
    std::string key;
    key.reserve(1 + 32);
    key.push_back(DB_PENDING);
    key.append(reinterpret_cast<const char*>(txid.data()), txid.size());
    return key;
}

UTXOSet::UTXOSet(const fs::path& dataDir, size_t nCacheSize)
    : mCacheSize(DEFAULT_CACHE_ENTRIES)
{
    mBestBlock.fill(0);
    fs::path chainstatePath = dataDir / "chainstate";
    try {
        fs::create_directories(chainstatePath);
    } catch (const fs::filesystem_error& e) {
        throw DBError("Failed to create chainstate directory: " + std::string(e.what()));
    }
    mDB = std::unique_ptr<DBWrapper>(
        new DBWrapper(chainstatePath, nCacheSize, false, false, true)
    );
    mDB->Read(DB_UTXO_BEST, mBestBlock);
}

UTXOSet::~UTXOSet() {
    try {
        Flush();
    } catch (...) {}
}

bool UTXOSet::FlushCache(const bytes32& bestBlock) {
    DBBatch batch(*mDB);
    size_t batchSize = 0;

    for (auto& it : mCache) {
        if (!it.second.isDirty) continue;

        const OutPoint& outpoint = it.first;
        const Coin& coin = it.second.coin;

        DataStream ssKey;
        ssKey << DB_UTXO;
        ssKey << outpoint.txHash;
        ssKey << outpoint.index;

        if (coin.isSpent) {
            batch.Erase(outpoint);
        } else {
            batch.Write(outpoint, coin);
        }

        it.second.isDirty = false;
        batchSize += sizeof(Coin) + sizeof(OutPoint);

        if (batchSize >= MAX_BATCH_SIZE) {
            mDB->WriteBatch(batch);
            batch.Clear();
            batchSize = 0;
        }
    }

    batch.Write(DB_UTXO_BEST, bestBlock);

    for (const auto& leaf : mSpentLeafDirty) {
        batch.Write(MakeNoiseLeafDBKey(leaf.kps, leaf.leafIndex),
                    static_cast<uint8_t>(1));
    }
    for (const auto& leaf : mErasedLeafDirty) {
        batch.Erase(MakeNoiseLeafDBKey(leaf.kps, leaf.leafIndex));
    }

    for (const auto& txid : mPendingDirty) {
        auto it = mPendingCache.find(txid);
        if (it == mPendingCache.end()) continue;
        const std::vector<uint8_t> blob = it->second.Serialize();
        batch.Write(MakePendingDBKey(txid),
                    std::string(blob.begin(), blob.end()));
    }
    for (const auto& txid : mErasedPendingDirty) {
        batch.Erase(MakePendingDBKey(txid));
    }

    mDB->WriteBatch(batch);

    mSpentLeafDirty.clear();
    mErasedLeafDirty.clear();
    mPendingDirty.clear();
    mErasedPendingDirty.clear();

    auto it = mCache.begin();
    while (it != mCache.end()) {
        if (it->second.coin.isSpent) {
            it = mCache.erase(it);
        } else {
            ++it;
        }
    }

    mBestBlock = bestBlock;
    return true;
}

bool UTXOSet::GetCoinLocked(const OutPoint& outpoint, Coin& coin) const {
    auto it = mCache.find(outpoint);
    if (it != mCache.end()) {
        if (it->second.coin.isSpent) return false;
        coin = it->second.coin;
        return true;
    }
    Coin dbCoin;
    if (!mDB->Read(outpoint, dbCoin)) return false;
    if (dbCoin.isSpent) return false;
    coin = dbCoin;
    return true;
}

bool UTXOSet::SpendCoinLocked(const OutPoint& outpoint) {
    auto it = mCache.find(outpoint);
    if (it != mCache.end()) {
        if (it->second.coin.isSpent) return false;
        it->second.coin.isSpent = true;
        it->second.isDirty = true;
        return true;
    }
    Coin dbCoin;
    if (!mDB->Read(outpoint, dbCoin)) return false;
    if (dbCoin.isSpent) return false;
    dbCoin.isSpent = true;
    mCache[outpoint] = UTXOEntry(dbCoin, true, false);
    return true;
}

bool UTXOSet::AddCoinLocked(const OutPoint& outpoint, const Coin& coin) {
    auto it = mCache.find(outpoint);
    if (it != mCache.end()) {
        if (!it->second.coin.isSpent) return false;
    } else {
        Coin dbCoin;
        if (mDB->Read(outpoint, dbCoin) && !dbCoin.isSpent) return false;
    }
    mCache[outpoint] = UTXOEntry(coin, true, true);
    return true;
}

bool UTXOSet::GetCoin(const OutPoint& outpoint, Coin& coin) const {
    std::lock_guard<std::mutex> lock(mMutex);

    auto it = mCache.find(outpoint);
    if (it != mCache.end()) {
        if (it->second.coin.isSpent) return false;
        coin = it->second.coin;
        return true;
    }

    Coin dbCoin;
    if (!mDB->Read(outpoint, dbCoin)) return false;
    if (dbCoin.isSpent) return false;

    coin = dbCoin;
    return true;
}

bool UTXOSet::HaveCoin(const OutPoint& outpoint) const {
    std::lock_guard<std::mutex> lock(mMutex);

    auto it = mCache.find(outpoint);
    if (it != mCache.end()) {
        return !it->second.coin.isSpent;
    }

    Coin dbCoin;
    if (!mDB->Read(outpoint, dbCoin)) return false;
    return !dbCoin.isSpent;
}

bool UTXOSet::SpendCoin(const OutPoint& outpoint) {
    std::lock_guard<std::mutex> lock(mMutex);

    auto it = mCache.find(outpoint);
    if (it != mCache.end()) {
        if (it->second.coin.isSpent) return false;
        it->second.coin.isSpent = true;
        it->second.isDirty = true;
        return true;
    }

    Coin dbCoin;
    if (!mDB->Read(outpoint, dbCoin)) return false;
    if (dbCoin.isSpent) return false;

    dbCoin.isSpent = true;
    mCache[outpoint] = UTXOEntry(dbCoin, true, false);
    return true;
}

bool UTXOSet::AddCoin(const OutPoint& outpoint, const Coin& coin) {
    std::lock_guard<std::mutex> lock(mMutex);

    auto it = mCache.find(outpoint);
    if (it != mCache.end()) {
        if (!it->second.coin.isSpent) {
            std::cerr << "UTXOSet: AddCoin called for existing unspent coin\n";
            return false;
        }
    } else {
        Coin dbCoin;
        if (mDB->Read(outpoint, dbCoin) && !dbCoin.isSpent) {
            std::cerr << "UTXOSet: AddCoin called for existing unspent coin\n";
            return false;
        }
    }

    mCache[outpoint] = UTXOEntry(coin, true, true);
    return true;
}

bool UTXOSet::ApplyTransaction(const Transaction& tx,
                                uint32_t height,
                                bool isCoinbase,
                                std::vector<Coin>* spentCoinsOut)
{
    std::lock_guard<std::mutex> lock(mMutex);

    if (spentCoinsOut) spentCoinsOut->clear();

    if (!isCoinbase) {
        std::vector<std::pair<OutPoint, Coin>> toSpend;
        std::vector<NoiseLeafKey> toMark;
        std::set<NoiseLeafKey> seenLeaves;
        toSpend.reserve(tx.GetInputCount());
        toMark.reserve(tx.GetInputCount());

        for (size_t i = 0; i < tx.GetInputCount(); ++i) {
            const TxInput& input = tx.GetInputs()[i];
            OutPoint outpoint(input.GetPrevTxHash(), input.GetOutputIndex());

            auto it = mCache.find(outpoint);
            if (it != mCache.end()) {
                if (it->second.coin.isSpent) {
                    std::cerr << "UTXOSet: double spend detected\n";
                    return false;
                }
                toSpend.push_back(std::make_pair(outpoint, it->second.coin));
            } else {
                Coin dbCoin;
                if (!mDB->Read(outpoint, dbCoin)) {
                    std::cerr << "UTXOSet: input not found\n";
                    return false;
                }
                if (dbCoin.isSpent) {
                    std::cerr << "UTXOSet: double spend detected in DB\n";
                    return false;
                }
                toSpend.push_back(std::make_pair(outpoint, dbCoin));
            }

            const std::vector<uint8_t>& proofBytes = input.GetNoiseProof();
            if (proofBytes.empty()) {
                std::cerr << "UTXOSet: missing noise proof\n";
                return false;
            }
            try {
                size_t offset = 0;
                NoiseProof proof = NoiseProof::Deserialize(
                    proofBytes.data(), proofBytes.size(), offset);
                NoiseLeafKey leafKey(input.GetKps(), proof.leafIndex);
                if (IsNoiseLeafSpentLocked(leafKey.kps, leafKey.leafIndex)) {
                    std::cerr << "UTXOSet: noise leaf already consumed\n";
                    return false;
                }
                if (!seenLeaves.insert(leafKey).second) {
                    std::cerr << "UTXOSet: duplicate noise leaf in "
                                 "transaction\n";
                    return false;
                }
                toMark.push_back(leafKey);
            } catch (const std::exception&) {
                std::cerr << "UTXOSet: malformed noise proof\n";
                return false;
            }
        }

        for (size_t i = 0; i < toSpend.size(); ++i) {
            const OutPoint& outpoint = toSpend[i].first;
            if (spentCoinsOut) spentCoinsOut->push_back(toSpend[i].second);

            auto it = mCache.find(outpoint);
            if (it != mCache.end()) {
                it->second.coin.isSpent = true;
                it->second.isDirty = true;
            } else {
                Coin spent = toSpend[i].second;
                spent.isSpent = true;
                mCache[outpoint] = UTXOEntry(spent, true, false);
            }
        }

        for (const auto& leafKey : toMark) {
            MarkNoiseLeafSpentLocked(leafKey.kps, leafKey.leafIndex);
        }
    }

    bytes32 txHash = tx.GetHash();
    for (size_t i = 0; i < tx.GetOutputCount(); ++i) {
        const TxOutput& output = tx.GetOutputs()[i];

        if (output.IsUnspendable()) continue;
        if (output.GetValue() <= 0) continue;

        bytes32 outPubkeyHash;
        if (!ExtractPubkeyHash(output.GetScriptPubKey(), outPubkeyHash)) {
            continue;
        }

        OutPoint outpoint(txHash, static_cast<uint32_t>(i));
        Coin coin(
            output.GetValue(),
            outPubkeyHash,
            height,
            isCoinbase
        );

        mCache[outpoint] = UTXOEntry(coin, true, true);
    }

    return true;
}

bool UTXOSet::UndoTransaction(const Transaction& tx,
                               const std::vector<Coin>& spentCoins)
{
    std::lock_guard<std::mutex> lock(mMutex);

    bytes32 txHash = tx.GetHash();

    // Both stores, always. A coin that has been flushed lives in the
    // database AND stays in the cache, because FlushCache only drops the
    // spent ones. Erasing whichever of the two happened to be checked
    // first left the other copy behind, and a later lookup that missed the
    // cache read the coin straight back out of the database - an output of
    // an abandoned transaction stayed spendable through a reorg.
    //
    // Erasing a key that is not there costs nothing in either store, so the
    // unconditional form is both correct and cheap.
    for (size_t i = 0; i < tx.GetOutputCount(); ++i) {
        OutPoint outpoint(txHash, static_cast<uint32_t>(i));
        mCache.erase(outpoint);
        mDB->Erase(outpoint);
    }

    if (!tx.IsCoinbase()) {
        if (spentCoins.size() != tx.GetInputCount()) {
            std::cerr << "UTXOSet: UndoTransaction spentCoins size mismatch\n";
            return false;
        }

        for (size_t i = 0; i < tx.GetInputCount(); ++i) {
            const TxInput& input = tx.GetInputs()[i];
            OutPoint outpoint(input.GetPrevTxHash(), input.GetOutputIndex());

            Coin restoredCoin = spentCoins[i];
            restoredCoin.isSpent = false;
            mCache[outpoint] = UTXOEntry(restoredCoin, true, false);

            const std::vector<uint8_t>& proofBytes = input.GetNoiseProof();
            if (!proofBytes.empty()) {
                try {
                    size_t offset = 0;
                    NoiseProof proof = NoiseProof::Deserialize(
                        proofBytes.data(), proofBytes.size(), offset);
                    UnmarkNoiseLeafSpentLocked(input.GetKps(),
                                               proof.leafIndex);
                } catch (const std::exception&) {
                    std::cerr << "UTXOSet: malformed noise proof in undo\n";
                    return false;
                }
            }
        }
    }

    return true;
}

int64_t UTXOSet::GetBalance(const bytes32& pubkeyHash) const {
    std::lock_guard<std::mutex> lock(mMutex);

    int64_t balance = 0;

    for (const auto& entry : mCache) {
        if (!entry.second.coin.isSpent &&
            entry.second.coin.pubkeyHash == pubkeyHash) {
            balance += entry.second.coin.value;
        }
    }

    std::unique_ptr<DBIterator> it(mDB->NewIterator());
    it->SeekToFirst();
    while (it->Valid()) {
        OutPoint outpoint;
        if (!it->GetKey(outpoint)) { it->Next(); continue; }

        Coin coin;
        if (!it->GetValue(coin)) {
            it->Next();
            continue;
        }

        if (!coin.isSpent && coin.pubkeyHash == pubkeyHash) {
            if (mCache.find(outpoint) == mCache.end()) {
                balance += coin.value;
            }
        }
        it->Next();
    }

    return balance;
}

std::vector<std::pair<OutPoint, Coin>> UTXOSet::GetUTXOsForAddress(
    const bytes32& pubkeyHash) const
{
    std::lock_guard<std::mutex> lock(mMutex);

    std::vector<std::pair<OutPoint, Coin>> result;

    for (const auto& entry : mCache) {
        if (!entry.second.coin.isSpent &&
            entry.second.coin.pubkeyHash == pubkeyHash) {
            result.push_back({entry.first, entry.second.coin});
        }
    }

    std::unique_ptr<DBIterator> it(mDB->NewIterator());
    it->SeekToFirst();
    while (it->Valid()) {
        OutPoint outpoint;
        if (!it->GetKey(outpoint)) { it->Next(); continue; }

        Coin coin;
        if (!it->GetValue(coin)) {
            it->Next();
            continue;
        }

        if (!coin.isSpent &&
            coin.pubkeyHash == pubkeyHash &&
            mCache.find(outpoint) == mCache.end()) {
            result.push_back({outpoint, coin});
        }
        it->Next();
    }

    return result;
}

bool UTXOSet::IsNoiseLeafSpentLocked(const bytes32& kps,
                                     uint32_t leafIndex) const {
    NoiseLeafKey key(kps, leafIndex);
    if (mSpentLeafCache.find(key) != mSpentLeafCache.end()) {
        return true;
    }
    if (mErasedLeafDirty.find(key) != mErasedLeafDirty.end()) {
        return false;
    }
    uint8_t flag = 0;
    return mDB->Read(MakeNoiseLeafDBKey(kps, leafIndex), flag);
}

bool UTXOSet::IsNoiseLeafSpent(const bytes32& kps,
                               uint32_t leafIndex) const {
    std::lock_guard<std::mutex> lock(mMutex);
    return IsNoiseLeafSpentLocked(kps, leafIndex);
}

void UTXOSet::MarkNoiseLeafSpentLocked(const bytes32& kps,
                                       uint32_t leafIndex) {
    NoiseLeafKey key(kps, leafIndex);
    mSpentLeafCache.insert(key);
    mSpentLeafDirty.insert(key);
    mErasedLeafDirty.erase(key);
}

void UTXOSet::UnmarkNoiseLeafSpentLocked(const bytes32& kps,
                                         uint32_t leafIndex) {
    NoiseLeafKey key(kps, leafIndex);
    mSpentLeafCache.erase(key);
    mSpentLeafDirty.erase(key);
    mErasedLeafDirty.insert(key);
}

namespace {

void PutLE32(std::vector<uint8_t>& out, uint32_t v) {
    for (int b = 0; b < 4; ++b) {
        out.push_back(static_cast<uint8_t>((v >> (8 * b)) & 0xFF));
    }
}

void PutLE64(std::vector<uint8_t>& out, int64_t v) {
    const uint64_t u = static_cast<uint64_t>(v);
    for (int b = 0; b < 8; ++b) {
        out.push_back(static_cast<uint8_t>((u >> (8 * b)) & 0xFF));
    }
}

uint32_t TakeLE32(const uint8_t* d, size_t len, size_t& off) {
    if (off + 4 > len) throw CryptoError("PendingSpend: truncated");
    uint32_t v = 0;
    for (int b = 3; b >= 0; --b) {
        v = (v << 8) | static_cast<uint32_t>(d[off + b]);
    }
    off += 4;
    return v;
}

int64_t TakeLE64(const uint8_t* d, size_t len, size_t& off) {
    if (off + 8 > len) throw CryptoError("PendingSpend: truncated");
    uint64_t v = 0;
    for (int b = 7; b >= 0; --b) {
        v = (v << 8) | static_cast<uint64_t>(d[off + b]);
    }
    off += 8;
    return static_cast<int64_t>(v);
}

} // namespace

std::vector<uint8_t> PendingSpend::Serialize() const {
    std::vector<uint8_t> out;
    const std::vector<uint8_t> txData = tx.Serialize();
    PutLE32(out, static_cast<uint32_t>(txData.size()));
    out.insert(out.end(), txData.begin(), txData.end());
    PutLE32(out, height);
    PutLE64(out, fee);
    PutLE32(out, static_cast<uint32_t>(spentCoins.size()));
    for (size_t i = 0; i < spentCoins.size(); ++i) {
        const Coin& c = spentCoins[i];
        PutLE64(out, c.value);
        out.insert(out.end(), c.pubkeyHash.begin(), c.pubkeyHash.end());
        PutLE32(out, c.height);
        out.push_back(c.isCoinbase ? 1 : 0);
    }
    return out;
}

PendingSpend PendingSpend::Deserialize(const uint8_t* data, size_t len) {
    if (data == NULL) throw CryptoError("PendingSpend: no data");
    PendingSpend p;
    size_t off = 0;

    const uint32_t txLen = TakeLE32(data, len, off);
    if (off + txLen > len) throw CryptoError("PendingSpend: truncated tx");
    p.tx = Transaction::Deserialize(data + off, txLen);
    off += txLen;

    p.height = TakeLE32(data, len, off);
    p.fee    = TakeLE64(data, len, off);

    const uint32_t coinCount = TakeLE32(data, len, off);
    if (coinCount > Transaction::MAX_INPUTS) {
        throw CryptoError("PendingSpend: implausible coin count");
    }
    p.spentCoins.reserve(coinCount);
    for (uint32_t i = 0; i < coinCount; ++i) {
        Coin c;
        c.value = TakeLE64(data, len, off);
        if (off + 32 > len) throw CryptoError("PendingSpend: truncated coin");
        std::memcpy(c.pubkeyHash.data(), data + off, 32);
        off += 32;
        c.height = TakeLE32(data, len, off);
        if (off + 1 > len) throw CryptoError("PendingSpend: truncated coin");
        c.isCoinbase = (data[off++] != 0);
        c.isSpent = false;
        p.spentCoins.push_back(c);
    }
    return p;
}

void UTXOSet::IndexPendingLocked(const PendingSpend& pending) {
    const std::vector<TxInput>& inputs = pending.tx.GetInputs();
    const bytes32 txid = pending.tx.GetHash();
    for (size_t i = 0; i < inputs.size(); ++i) {
        mPendingByOutpoint[OutPoint(inputs[i].GetPrevTxHash(),
                                    inputs[i].GetOutputIndex())] = txid;
    }
}

void UTXOSet::UnindexPendingLocked(const PendingSpend& pending) {
    const std::vector<TxInput>& inputs = pending.tx.GetInputs();
    for (size_t i = 0; i < inputs.size(); ++i) {
        mPendingByOutpoint.erase(OutPoint(inputs[i].GetPrevTxHash(),
                                          inputs[i].GetOutputIndex()));
    }
}

bool UTXOSet::LoadPendingLocked(const bytes32& txid,
                                PendingSpend& out) const {
    auto it = mPendingCache.find(txid);
    if (it != mPendingCache.end()) {
        out = it->second;
        return true;
    }
    if (mErasedPendingDirty.find(txid) != mErasedPendingDirty.end()) {
        return false;
    }
    std::string blob;
    if (!mDB->Read(MakePendingDBKey(txid), blob) || blob.empty()) {
        return false;
    }
    try {
        out = PendingSpend::Deserialize(
            reinterpret_cast<const uint8_t*>(blob.data()), blob.size());
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

bool UTXOSet::AddPendingSpend(const Transaction& tx,
                              uint32_t height,
                              const std::vector<Coin>& spentCoins,
                              int64_t fee) {
    std::lock_guard<std::mutex> lock(mMutex);

    const bytes32 txid = tx.GetHash();
    if (mPendingCache.find(txid) != mPendingCache.end()) {
        return false;
    }

    const std::vector<TxInput>& inputs = tx.GetInputs();
    if (inputs.empty() || spentCoins.size() != inputs.size()) {
        return false;
    }

    for (size_t i = 0; i < inputs.size(); ++i) {
        const OutPoint op(inputs[i].GetPrevTxHash(),
                          inputs[i].GetOutputIndex());
        if (mPendingByOutpoint.find(op) != mPendingByOutpoint.end()) {
            return false;
        }
        Coin existing;
        if (!GetCoinLocked(op, existing) || existing.isSpent) {
            return false;
        }
    }

    PendingSpend pending;
    pending.tx         = tx;
    pending.height     = height;
    pending.spentCoins = spentCoins;
    pending.fee        = fee;

    mPendingCache[txid] = pending;
    mPendingDirty.insert(txid);
    mErasedPendingDirty.erase(txid);
    IndexPendingLocked(pending);
    return true;
}

bool UTXOSet::GetPendingSpend(const bytes32& txid,
                              PendingSpend& out) const {
    std::lock_guard<std::mutex> lock(mMutex);
    return LoadPendingLocked(txid, out);
}

bool UTXOSet::HasPendingSpend(const bytes32& txid) const {
    PendingSpend ignored;
    return GetPendingSpend(txid, ignored);
}

bool UTXOSet::IsOutpointPending(const OutPoint& outpoint,
                                bytes32* holderTxid) const {
    std::lock_guard<std::mutex> lock(mMutex);
    auto it = mPendingByOutpoint.find(outpoint);
    if (it == mPendingByOutpoint.end()) return false;
    if (holderTxid) *holderTxid = it->second;
    return true;
}

bool UTXOSet::FinalizePendingSpend(const bytes32& txid) {
    std::lock_guard<std::mutex> lock(mMutex);

    PendingSpend pending;
    if (!LoadPendingLocked(txid, pending)) return false;

    const std::vector<TxInput>& inputs = pending.tx.GetInputs();
    for (size_t i = 0; i < inputs.size(); ++i) {
        SpendCoinLocked(OutPoint(inputs[i].GetPrevTxHash(),
                                 inputs[i].GetOutputIndex()));
    }

    const std::vector<TxOutput>& outputs = pending.tx.GetOutputs();
    for (size_t i = 0; i < outputs.size(); ++i) {
        if (outputs[i].GetScriptPubKey().IsUnspendable()) continue;
        bytes32 pkh;
        if (!ExtractPubkeyHash(outputs[i].GetScriptPubKey(), pkh)) continue;
        AddCoinLocked(OutPoint(txid, static_cast<uint32_t>(i)),
                      Coin(outputs[i].GetValue(), pkh,
                           pending.height, false));
    }

    UnindexPendingLocked(pending);
    mPendingCache.erase(txid);
    mPendingDirty.erase(txid);
    mErasedPendingDirty.insert(txid);
    return true;
}

bool UTXOSet::ReleasePendingSpend(const bytes32& txid) {
    std::lock_guard<std::mutex> lock(mMutex);

    PendingSpend pending;
    if (!LoadPendingLocked(txid, pending)) return false;

    UnindexPendingLocked(pending);
    mPendingCache.erase(txid);
    mPendingDirty.erase(txid);
    mErasedPendingDirty.insert(txid);
    return true;
}

std::vector<bytes32> UTXOSet::GetPendingSpendsAtHeight(
    uint32_t height) const {
    std::lock_guard<std::mutex> lock(mMutex);
    std::vector<bytes32> out;
    for (const auto& entry : mPendingCache) {
        if (entry.second.height == height) out.push_back(entry.first);
    }
    return out;
}

size_t UTXOSet::PendingSpendCount() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mPendingCache.size();
}

bool UTXOSet::UnmarkNoiseLeafSpent(const bytes32& kps,
                                   uint32_t leafIndex) {
    std::lock_guard<std::mutex> lock(mMutex);
    UnmarkNoiseLeafSpentLocked(kps, leafIndex);
    return true;
}

bool UTXOSet::UnfinalizePendingSpend(const Transaction& tx,
                                     uint32_t pendingHeight,
                                     const std::vector<Coin>& spentCoins,
                                     int64_t fee) {
    std::lock_guard<std::mutex> lock(mMutex);

    const bytes32 txid = tx.GetHash();
    const std::vector<TxInput>& inputs = tx.GetInputs();
    if (spentCoins.size() != inputs.size()) return false;

    const std::vector<TxOutput>& outputs = tx.GetOutputs();
    for (size_t i = 0; i < outputs.size(); ++i) {
        if (outputs[i].GetScriptPubKey().IsUnspendable()) continue;
        bytes32 pkh;
        if (!ExtractPubkeyHash(outputs[i].GetScriptPubKey(), pkh)) continue;
        const OutPoint op(txid, static_cast<uint32_t>(i));
        Coin existing;
        if (GetCoinLocked(op, existing)) {
            SpendCoinLocked(op);
        }
    }

    for (size_t i = 0; i < inputs.size(); ++i) {
        const OutPoint op(inputs[i].GetPrevTxHash(),
                          inputs[i].GetOutputIndex());
        Coin restored = spentCoins[i];
        restored.isSpent = false;
        mCache[op] = UTXOEntry(restored, true, false);
    }

    PendingSpend pending;
    pending.tx         = tx;
    pending.height     = pendingHeight;
    pending.spentCoins = spentCoins;
    pending.fee        = fee;

    mPendingCache[txid] = pending;
    mPendingDirty.insert(txid);
    mErasedPendingDirty.erase(txid);
    IndexPendingLocked(pending);
    return true;
}

bool UTXOSet::RestorePendingSpend(const Transaction& tx,
                                  uint32_t pendingHeight,
                                  const std::vector<Coin>& spentCoins,
                                  int64_t fee) {
    std::lock_guard<std::mutex> lock(mMutex);

    const bytes32 txid = tx.GetHash();
    if (spentCoins.size() != tx.GetInputs().size()) return false;

    PendingSpend pending;
    pending.tx         = tx;
    pending.height     = pendingHeight;
    pending.spentCoins = spentCoins;
    pending.fee        = fee;

    mPendingCache[txid] = pending;
    mPendingDirty.insert(txid);
    mErasedPendingDirty.erase(txid);
    IndexPendingLocked(pending);
    return true;
}

bool UTXOSet::GetHighestSpentNoiseLeaf(const bytes32& kps,
                                       uint32_t& highestOut) const {
    std::lock_guard<std::mutex> lock(mMutex);

    bool found = false;
    uint32_t highest = 0;

    auto consider = [&](uint32_t idx) {
        NoiseLeafKey key(kps, idx);
        if (mErasedLeafDirty.find(key) != mErasedLeafDirty.end()) return;
        if (!found || idx > highest) {
            highest = idx;
            found = true;
        }
    };

    for (const auto& key : mSpentLeafCache) {
        if (key.kps == kps) consider(key.leafIndex);
    }

    const std::string prefix = MakeNoiseLeafDBKey(kps, 0).substr(0, 1 + 32);
    std::unique_ptr<DBIterator> it(mDB->NewIterator());
    for (it->Seek(MakeNoiseLeafDBKey(kps, 0)); it->Valid(); it->Next()) {
        std::string key;
        if (!it->GetKey(key)) break;
        if (key.size() != 1 + 32 + 4) break;
        if (key.compare(0, prefix.size(), prefix) != 0) break;
        uint32_t idx = 0;
        for (int b = 3; b >= 0; --b) {
            idx = (idx << 8) |
                  static_cast<uint8_t>(key[1 + 32 + b]);
        }
        consider(idx);
    }

    if (found) highestOut = highest;
    return found;
}

bool UTXOSet::MarkNoiseLeafSpent(const bytes32& kps,
                                 uint32_t leafIndex) {
    std::lock_guard<std::mutex> lock(mMutex);
    MarkNoiseLeafSpentLocked(kps, leafIndex);
    return true;
}

bytes32 UTXOSet::GetBestBlock() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mBestBlock;
}

bool UTXOSet::SetBestBlock(const bytes32& blockHash) {
    std::lock_guard<std::mutex> lock(mMutex);
    mBestBlock = blockHash;
    return true;
}

bool UTXOSet::Flush() {
    std::lock_guard<std::mutex> lock(mMutex);
    return FlushCache(mBestBlock);
}

bool UTXOSet::Sync() {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!FlushCache(mBestBlock)) return false;
    return mDB->Sync();
}

size_t UTXOSet::GetCacheSize() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mCache.size();
}

size_t UTXOSet::EstimateSize() const {
    OutPoint keyBegin, keyEnd;
    keyBegin.txHash.fill(0x00);
    keyBegin.index = 0;
    keyEnd.txHash.fill(0xFF);
    keyEnd.index = 0xFFFFFFFF;
    return mDB->EstimateSize(keyBegin, keyEnd);
}

void UTXOSet::Clear() {
    std::lock_guard<std::mutex> lock(mMutex);
    mCache.clear();
    mSpentLeafCache.clear();
    mSpentLeafDirty.clear();
    mErasedLeafDirty.clear();
    mPendingDirty.clear();
    mErasedPendingDirty.clear();
    mBestBlock.fill(0);
}

#ifdef DEBUG
bool UTXOSet::CheckIntegrity() const {
    std::lock_guard<std::mutex> lock(mMutex);

    for (const auto& entry : mCache) {
        const Coin& coin = entry.second.coin;

        if (coin.value < 0) {
            std::cerr << "UTXOSet integrity: negative value coin\n";
            return false;
        }

        if (coin.value > NetParams::MAX_MONEY) {
            std::cerr << "UTXOSet integrity: coin value exceeds MAX_MONEY\n";
            return false;
        }
    }

    return true;
}
#endif

} // namespace storage
} // namespace MONEU
