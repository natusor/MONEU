// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_MI_HISTORYSCANNER_H
#define MONEU_MI_HISTORYSCANNER_H

#include "rpcclient.h"

#include <QMetaType>
#include <QObject>
#include <QString>
#include <QVector>

#include <atomic>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace mi {

// amount is how the wallet balance moved. For a payment this wallet made,
// sent is what the recipient got, fee is what the node charged and change is
// what came back to this wallet; fee is -1 when the wallet did not pay it.
struct TxRecord {
    QString txid;
    qint64  height;
    qint64  time;
    qint64  amount;
    qint64  sent;
    qint64  fee;
    qint64  change;
    QString address;
    QString from;
    bool    coinbase;
    bool    pending;
    bool    toSelf;

    TxRecord()
        : height(-1), time(0), amount(0), sent(0), fee(-1), change(0),
          coinbase(false), pending(false), toSelf(false) {}
};

// Builds the wallet's history from the chain with the node's existing
// commands: getblockhash, getblock and getrawtransaction. What has been read
// is kept on disk, so a restart only reads the blocks that came after.
class HistoryScanner : public QObject {
    Q_OBJECT

public:
    HistoryScanner(const std::string& dataDir, const QString& cacheDir);

    void Cycle();
    void AddPending(const QString& txid);
    void RequestStop() { mStop = true; }

Q_SIGNALS:
    void Updated(const QVector<mi::TxRecord>& records);
    void Progress(qint64 scanned, qint64 tip);

private:
    struct Out {
        int64_t     value;
        std::string hash;
    };

    RpcClient   mRpc;
    QString     mCacheDir;
    std::string mWalletKey;

    std::map<std::string, std::string> mOwn;
    std::set<std::string>              mChange;
    std::map<std::string, Out>         mOuts;
    std::vector<TxRecord>              mRecords;
    std::vector<TxRecord>              mPending;
    std::set<std::string>              mPendingIds;

    int64_t     mHeight;
    std::string mHash;
    int64_t     mSavedHeight;
    bool        mLoaded;

    std::atomic<bool> mStop;

    bool RefreshAddresses();
    void Reset();
    bool Load();
    void Save();
    QString CachePath() const;
    bool ScanChunk(int64_t tip);
    void ApplyTransaction(const json& tx, int64_t height, int64_t time);
    bool Evaluate(const json& tx, TxRecord& rec, bool& touched) const;
    void RefreshPending();
    void Publish();
};

} // namespace mi

Q_DECLARE_METATYPE(mi::TxRecord)
Q_DECLARE_METATYPE(QVector<mi::TxRecord>)

#endif // MONEU_MI_HISTORYSCANNER_H
