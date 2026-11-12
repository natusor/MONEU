// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_MI_RPCWORKER_H
#define MONEU_MI_RPCWORKER_H

#include "rpcclient.h"

#include <QList>
#include <QMetaType>
#include <QObject>
#include <QString>
#include <QVariantMap>

#include <cstdint>
#include <string>

namespace mi {

struct ChainInfo {
    bool    ok;
    QString error;
    qint64  height;
    int     peers;
    bool    mining;
    double  hashRate;
    double  networkHash;
    quint32 nextBits;

    ChainInfo()
        : ok(false), height(0), peers(0), mining(false), hashRate(0.0),
          networkHash(0.0), nextBits(0) {}
};

struct AddressRow {
    QString address;
    bool    isChange;
    quint32 index;
    bool    balanceKnown;
    qint64  spendable;
    qint64  immature;

    AddressRow()
        : isChange(false), index(0), balanceKnown(false), spendable(0),
          immature(0) {}
};

struct WalletInfo {
    bool    ok;
    QString error;
    bool    walletFile;
    bool    initialized;
    bool    locked;
    bool    noiseFile;
    bool    noiseLoaded;
    qint64  leavesLeft;
    qint64  leavesTotal;
    bool    balanceKnown;
    qint64  total;
    qint64  spendable;
    qint64  immature;
    QList<AddressRow> addresses;

    WalletInfo()
        : ok(false), walletFile(false), initialized(false), locked(true),
          noiseFile(false), noiseLoaded(false), leavesLeft(0),
          leavesTotal(0), balanceKnown(false), total(0), spendable(0),
          immature(0) {}
};

struct ActionResult {
    QString     kind;
    bool        ok;
    QString     text;
    QVariantMap data;

    ActionResult() : ok(false) {}
};

void RegisterMetaTypes();

// Polls the node for what the main window shows. Lives on its own thread.
class Poller : public QObject {
    Q_OBJECT

public:
    explicit Poller(const std::string& dataDir);

    void PollChain();
    void PollWallet();

Q_SIGNALS:
    void ChainUpdated(const mi::ChainInfo& info);
    void WalletUpdated(const mi::WalletInfo& info);

private:
    RpcClient mRpc;
};

// Runs what the buttons ask for, one at a time, on its own thread.
class Actions : public QObject {
    Q_OBJECT

public:
    explicit Actions(const std::string& dataDir);

    void CreateWallet(const QString& passphrase);
    void Unlock(const QString& passphrase, const QString& kind);
    void NewAddress();
    void LoadAddresses();
    void StartMining(int threads);
    void StopMining();
    void Send(const QString& address, const QString& amount,
              const QString& message);
    void LoadNetwork();

Q_SIGNALS:
    void Finished(const mi::ActionResult& result);

private:
    void ReadPayment(const std::string& txid, const std::string& address,
                     ActionResult& res);

    RpcClient   mRpc;
    std::string mDataDir;
};

} // namespace mi

Q_DECLARE_METATYPE(mi::ChainInfo)
Q_DECLARE_METATYPE(mi::WalletInfo)
Q_DECLARE_METATYPE(mi::ActionResult)

#endif // MONEU_MI_RPCWORKER_H
