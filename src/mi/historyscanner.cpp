// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "historyscanner.h"
#include "miutil.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QSaveFile>

#include <algorithm>

namespace mi {

static const int64_t BLOCKS_PER_CHUNK = 50;
static const size_t  TX_PER_BATCH = 200;
static const int64_t SAVE_EVERY = 2000;

static std::string Str(const json& obj, const char* key)
{
    if (!obj.is_object() || !obj.contains(key) || !obj[key].is_string())
        return std::string();
    return obj[key].get<std::string>();
}

static int64_t Int(const json& obj, const char* key)
{
    if (!obj.is_object() || !obj.contains(key)) return 0;
    const json& v = obj[key];
    if (v.is_number_integer()) return v.get<int64_t>();
    if (v.is_number()) return static_cast<int64_t>(v.get<double>());
    return 0;
}

static std::string OutKey(const std::string& txid, int64_t n)
{
    return txid + ":" + std::to_string(n);
}

HistoryScanner::HistoryScanner(const std::string& dataDir,
                               const QString& cacheDir)
    : mRpc(dataDir)
    , mCacheDir(cacheDir)
    , mHeight(0)
    , mSavedHeight(-1)
    , mLoaded(false)
    , mStop(false)
{
}

QString HistoryScanner::CachePath() const
{
    return mCacheDir + QStringLiteral("/history-") +
           QString::fromStdString(mWalletKey) + QStringLiteral(".json");
}

void HistoryScanner::Reset()
{
    mOuts.clear();
    mRecords.clear();
    mHeight = 0;
    mHash.clear();
    mSavedHeight = -1;
}

bool HistoryScanner::RefreshAddresses()
{
    RpcReply la = mRpc.Call("listaddresses", json::array(), 120);
    if (!la.Ok() || !la.result.is_array() || la.result.empty()) return false;

    std::string key;
    int64_t keyIndex = -1;
    std::map<std::string, std::string> own;
    std::set<std::string> change;
    for (const auto& a : la.result) {
        const std::string address = Str(a, "address");
        std::string hash;
        if (!HashHexFromAddress(address, hash)) continue;
        own[hash] = address;
        const bool isChange = a.contains("ischange") && a["ischange"].is_boolean() &&
                              a["ischange"].get<bool>();
        if (isChange) change.insert(hash);
        const int64_t index = Int(a, "index");
        if (!isChange && (keyIndex < 0 || index < keyIndex)) {
            keyIndex = index;
            key = address;
        }
    }
    if (key.empty()) key = own.empty() ? std::string() : own.begin()->second;
    if (key.empty()) return false;

    if (key != mWalletKey) {
        mWalletKey = key;
        Reset();
        mPending.clear();
        mPendingIds.clear();
        mLoaded = false;
    }
    mOwn.swap(own);
    mChange.swap(change);
    return true;
}

bool HistoryScanner::Load()
{
    QFile f(CachePath());
    if (!f.open(QIODevice::ReadOnly)) return false;
    const QByteArray raw = f.readAll();
    json doc;
    try {
        doc = json::parse(raw.constData(), raw.constData() + raw.size());
    } catch (...) {
        return false;
    }
    if (!doc.is_object() || Int(doc, "version") != 2 ||
        Str(doc, "key") != mWalletKey)
        return false;

    Reset();
    mHeight = Int(doc, "height");
    mHash = Str(doc, "hash");
    if (doc.contains("records") && doc["records"].is_array()) {
        for (const auto& r : doc["records"]) {
            TxRecord rec;
            rec.txid = QString::fromStdString(Str(r, "txid"));
            rec.height = Int(r, "height");
            rec.time = Int(r, "time");
            rec.amount = Int(r, "amount");
            rec.sent = Int(r, "sent");
            rec.fee = r.contains("fee") ? Int(r, "fee") : -1;
            rec.change = Int(r, "change");
            rec.address = QString::fromStdString(Str(r, "address"));
            rec.from = QString::fromStdString(Str(r, "from"));
            rec.coinbase = r.contains("coinbase") && r["coinbase"].is_boolean() &&
                           r["coinbase"].get<bool>();
            rec.toSelf = r.contains("toself") && r["toself"].is_boolean() &&
                         r["toself"].get<bool>();
            mRecords.push_back(rec);
        }
    }
    if (doc.contains("outs") && doc["outs"].is_array()) {
        for (const auto& o : doc["outs"]) {
            if (!o.is_array() || o.size() != 3 || !o[0].is_string() ||
                !o[1].is_number_integer() || !o[2].is_string())
                continue;
            Out out;
            out.value = o[1].get<int64_t>();
            out.hash = o[2].get<std::string>();
            mOuts[o[0].get<std::string>()] = out;
        }
    }
    mSavedHeight = mHeight;
    return true;
}

void HistoryScanner::Save()
{
    if (mWalletKey.empty()) return;
    QDir().mkpath(mCacheDir);

    json doc;
    doc["version"] = 2;
    doc["key"] = mWalletKey;
    doc["height"] = mHeight;
    doc["hash"] = mHash;
    json records = json::array();
    for (const auto& r : mRecords) {
        json j;
        j["txid"] = r.txid.toStdString();
        j["height"] = r.height;
        j["time"] = r.time;
        j["amount"] = r.amount;
        j["sent"] = r.sent;
        j["fee"] = r.fee;
        j["change"] = r.change;
        j["address"] = r.address.toStdString();
        j["from"] = r.from.toStdString();
        j["coinbase"] = r.coinbase;
        j["toself"] = r.toSelf;
        records.push_back(j);
    }
    doc["records"] = records;
    json outs = json::array();
    for (const auto& o : mOuts) {
        json j = json::array();
        j.push_back(o.first);
        j.push_back(o.second.value);
        j.push_back(o.second.hash);
        outs.push_back(j);
    }
    doc["outs"] = outs;

    const std::string text = doc.dump();
    QSaveFile f(CachePath());
    if (!f.open(QIODevice::WriteOnly)) return;
    f.write(text.data(), static_cast<qint64>(text.size()));
    if (f.commit()) mSavedHeight = mHeight;
}

bool HistoryScanner::Evaluate(const json& tx, TxRecord& rec,
                              bool& touched) const
{
    const std::string txid = Str(tx, "txid");
    if (txid.empty()) return false;
    rec.txid = QString::fromStdString(txid);
    rec.coinbase = tx.contains("coinbase") && tx["coinbase"].is_boolean() &&
                   tx["coinbase"].get<bool>();

    int64_t ownIn = 0;
    size_t inputs = 0;
    size_t ownInputs = 0;
    std::string ownInAddress;
    std::string sender;
    if (tx.contains("vin") && tx["vin"].is_array()) {
        for (const auto& in : tx["vin"]) {
            ++inputs;
            if (sender.empty()) sender = Str(in, "senderaddress");
            auto it = mOuts.find(OutKey(Str(in, "prevtxid"),
                                        Int(in, "outputindex")));
            if (it == mOuts.end()) continue;
            ++ownInputs;
            ownIn += it->second.value;
            if (ownInAddress.empty()) {
                auto own = mOwn.find(it->second.hash);
                if (own != mOwn.end()) ownInAddress = own->second;
            }
        }
    }

    int64_t totalOut = 0;
    int64_t ownOut = 0;
    int64_t toOthers = 0;
    int64_t toOwnReceive = 0;
    int64_t toChange = 0;
    std::string firstOwn;
    std::string firstOwnReceive;
    std::string firstOther;
    if (tx.contains("vout") && tx["vout"].is_array()) {
        for (const auto& out : tx["vout"]) {
            const int64_t value = Int(out, "value");
            totalOut += value;
            const std::string hash = Str(out, "pubkeyhash");
            if (hash.empty()) continue;
            auto own = mOwn.find(hash);
            if (own != mOwn.end()) {
                ownOut += value;
                if (firstOwn.empty()) firstOwn = own->second;
                if (mChange.count(hash)) {
                    toChange += value;
                } else {
                    toOwnReceive += value;
                    if (firstOwnReceive.empty()) firstOwnReceive = own->second;
                }
            } else {
                toOthers += value;
                if (firstOther.empty()) firstOther = AddressFromHashHex(hash);
            }
        }
    }

    touched = ownIn > 0 || ownOut > 0;
    rec.amount = ownOut - ownIn;
    rec.sent = 0;
    rec.fee = -1;
    rec.change = 0;
    rec.toSelf = false;

    std::string address;
    if (!rec.coinbase && ownInputs > 0 && ownInputs == inputs) {
        // Every input was this wallet's, so this wallet made the payment.
        rec.fee = ownIn - totalOut >= 0 ? ownIn - totalOut : -1;
        if (toOthers > 0) {
            rec.sent = toOthers;
            rec.change = ownOut;
            address = firstOther;
        } else if (toOwnReceive > 0) {
            rec.toSelf = true;
            rec.sent = toOwnReceive;
            rec.change = toChange;
            address = firstOwnReceive;
        } else {
            rec.toSelf = true;
            rec.sent = ownOut;
            address = firstOwn.empty() ? ownInAddress : firstOwn;
        }
    } else if (rec.amount > 0) {
        address = firstOwn;
    } else if (!firstOther.empty()) {
        address = firstOther;
    } else if (!firstOwn.empty()) {
        address = firstOwn;
    } else {
        address = ownInAddress;
    }
    rec.address = QString::fromStdString(address);
    rec.from = rec.coinbase ? QString() : QString::fromStdString(sender);
    return true;
}

void HistoryScanner::ApplyTransaction(const json& tx, int64_t height,
                                      int64_t time)
{
    TxRecord rec;
    bool touched = false;
    if (!Evaluate(tx, rec, touched) || !touched) return;

    const std::string txid = Str(tx, "txid");
    if (tx.contains("vin") && tx["vin"].is_array()) {
        for (const auto& in : tx["vin"]) {
            mOuts.erase(OutKey(Str(in, "prevtxid"), Int(in, "outputindex")));
        }
    }
    if (tx.contains("vout") && tx["vout"].is_array()) {
        for (const auto& out : tx["vout"]) {
            const std::string hash = Str(out, "pubkeyhash");
            if (hash.empty() || mOwn.find(hash) == mOwn.end()) continue;
            Out o;
            o.value = Int(out, "value");
            o.hash = hash;
            mOuts[OutKey(txid, Int(out, "n"))] = o;
        }
    }

    rec.height = height;
    rec.time = time;
    mRecords.push_back(rec);
}

bool HistoryScanner::ScanChunk(int64_t tip)
{
    const int64_t from = mHeight + 1;
    const int64_t to = std::min(tip, from + BLOCKS_PER_CHUNK - 1);

    std::vector<std::pair<std::string, json> > calls;
    for (int64_t h = from; h <= to; ++h) {
        json p = json::array();
        p.push_back(h);
        calls.push_back(std::make_pair(std::string("getblockhash"), p));
    }
    std::vector<RpcReply> hashes = mRpc.Batch(calls, 300);
    std::vector<std::string> blockHashes;
    for (size_t i = 0; i < hashes.size(); ++i) {
        if (!hashes[i].Ok() || !hashes[i].result.is_string()) return false;
        blockHashes.push_back(hashes[i].result.get<std::string>());
    }

    calls.clear();
    for (size_t i = 0; i < blockHashes.size(); ++i) {
        json p = json::array();
        p.push_back(blockHashes[i]);
        calls.push_back(std::make_pair(std::string("getblock"), p));
    }
    std::vector<RpcReply> blocks = mRpc.Batch(calls, 300);
    for (size_t i = 0; i < blocks.size(); ++i) {
        if (!blocks[i].Ok() || !blocks[i].result.is_object()) return false;
        const std::string prev = Str(blocks[i].result, "previousblockhash");
        if (i == 0) {
            if (!mHash.empty() && prev != mHash) {
                Reset();
                return false;
            }
        } else if (prev != blockHashes[i - 1]) {
            return false;
        }
    }

    std::vector<std::string> txids;
    for (size_t i = 0; i < blocks.size(); ++i) {
        const json& b = blocks[i].result;
        if (!b.contains("tx") || !b["tx"].is_array()) return false;
        for (const auto& t : b["tx"]) {
            if (!t.is_string()) return false;
            txids.push_back(t.get<std::string>());
        }
    }

    std::map<std::string, json> txs;
    for (size_t start = 0; start < txids.size(); start += TX_PER_BATCH) {
        if (mStop) return false;
        calls.clear();
        const size_t end = std::min(txids.size(), start + TX_PER_BATCH);
        for (size_t i = start; i < end; ++i) {
            json p = json::array();
            p.push_back(txids[i]);
            p.push_back(true);
            calls.push_back(std::make_pair(std::string("getrawtransaction"), p));
        }
        std::vector<RpcReply> r = mRpc.Batch(calls, 300);
        for (size_t i = 0; i < r.size(); ++i) {
            if (!r[i].Ok() || !r[i].result.is_object()) return false;
            txs[txids[start + i]] = r[i].result;
        }
    }

    for (size_t i = 0; i < blocks.size(); ++i) {
        const json& b = blocks[i].result;
        const int64_t height = from + static_cast<int64_t>(i);
        const int64_t time = Int(b, "time");
        for (const auto& t : b["tx"]) {
            auto it = txs.find(t.get<std::string>());
            if (it == txs.end()) return false;
            ApplyTransaction(it->second, height, time);
        }
    }

    mHeight = to;
    mHash = blockHashes.back();
    return true;
}

void HistoryScanner::AddPending(const QString& txid)
{
    const std::string id = txid.toStdString();
    if (id.empty() || mPendingIds.count(id)) return;
    TxRecord rec;
    rec.txid = txid;
    rec.pending = true;
    rec.time = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
    mPending.push_back(rec);
    mPendingIds.insert(id);
    RefreshPending();
    Publish();
}

void HistoryScanner::RefreshPending()
{
    std::vector<TxRecord> keep;
    std::set<std::string> keepIds;
    for (size_t i = 0; i < mPending.size(); ++i) {
        TxRecord rec = mPending[i];
        const std::string id = rec.txid.toStdString();
        bool confirmed = false;
        for (size_t k = mRecords.size(); k > 0; --k) {
            if (mRecords[k - 1].txid == rec.txid) {
                confirmed = true;
                break;
            }
        }
        if (confirmed) continue;

        json p = json::array();
        p.push_back(id);
        p.push_back(true);
        RpcReply r = mRpc.Call("getrawtransaction", p, 60);
        if (r.kind == RpcReply::RPC_ERROR) continue;
        if (r.Ok() && r.result.is_object()) {
            TxRecord fresh;
            bool touched = false;
            if (Evaluate(r.result, fresh, touched)) {
                fresh.pending = true;
                fresh.time = rec.time;
                fresh.height = -1;
                rec = fresh;
            }
        }
        keep.push_back(rec);
        keepIds.insert(id);
    }
    mPending.swap(keep);
    mPendingIds.swap(keepIds);
}

void HistoryScanner::Publish()
{
    QVector<TxRecord> out;
    out.reserve(static_cast<int>(mPending.size() + mRecords.size()));
    for (size_t i = mPending.size(); i > 0; --i) out.append(mPending[i - 1]);
    for (size_t i = mRecords.size(); i > 0; --i) out.append(mRecords[i - 1]);
    Q_EMIT Updated(out);
}

void HistoryScanner::Cycle()
{
    if (mStop) return;
    if (!RefreshAddresses()) return;
    if (!mLoaded) {
        Load();
        mLoaded = true;
        Publish();
    }

    RpcReply count = mRpc.Call("getblockcount", json::array(), 60);
    if (!count.Ok() || !count.result.is_number_integer()) return;
    const int64_t tip = count.result.get<int64_t>();

    if (mHeight > 0) {
        json p = json::array();
        p.push_back(mHeight);
        RpcReply h = mRpc.Call("getblockhash", p, 60);
        if (h.kind == RpcReply::TRANSPORT_ERROR) return;
        if (!h.Ok() || !h.result.is_string() ||
            h.result.get<std::string>() != mHash) {
            Reset();
        }
    }

    const int64_t before = mHeight;
    const size_t recordsBefore = mRecords.size();
    while (!mStop && mHeight < tip) {
        if (!ScanChunk(tip)) break;
        Q_EMIT Progress(mHeight, tip);
        if (mHeight - mSavedHeight >= SAVE_EVERY) Save();
    }
    if (mHeight != mSavedHeight) Save();

    RefreshPending();
    if (mHeight != before || mRecords.size() != recordsBefore ||
        !mPending.empty())
        Publish();
}

} // namespace mi
