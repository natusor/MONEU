// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_MI_MAINWINDOW_H
#define MONEU_MI_MAINWINDOW_H

#include "historyscanner.h"
#include "rpcworker.h"

#include <QMainWindow>
#include <QPointer>
#include <QString>
#include <QThread>
#include <QVector>

#include <functional>
#include <string>
#include <vector>

class QLabel;
class QTimer;

namespace mi {

class BusyDialog;
class CoinLogo;
class MiButton;
class NavButton;
class NodeHost;
class NoiseJob;
class ShieldCard;
class ShutdownWindow;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(const std::vector<std::string>& nodeArgs,
               const std::string& dataDir);
    ~MainWindow();

    void Start();

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    struct HistoryRow {
        QWidget*  box;
        QLabel*   type;
        QLabel*   address;
        QLabel*   detail;
        QLabel*   amount;
        QLabel*   unit;
        MiButton* arrow;
    };

    std::string mDataDir;
    NodeHost*   mNode;

    QThread mPollThread;
    QThread mActionThread;
    QThread mHistoryThread;
    QThread mNoiseThread;

    Poller*         mPoller;
    Actions*        mActions;
    HistoryScanner* mHistory;
    NoiseJob*       mNoise;

    QTimer* mChainTimer;
    QTimer* mWalletTimer;
    QTimer* mHistoryTimer;
    QTimer* mShutdownTimer;

    bool mChainPollBusy;
    bool mWalletPollBusy;
    bool mHistoryBusy;
    bool mNodeReady;
    bool mAskedUnlock;
    bool mBusy;
    bool mShuttingDown;
    bool mStopRequested;
    bool mNodeGone;
    bool mNoiseRunning;
    int  mNodeExitCode;

    ChainInfo  mChain;
    WalletInfo mWallet;
    qint64     mLastTotal;
    QVector<TxRecord> mRecords;
    qint64     mHistoryScanned;
    qint64     mHistoryTip;

    QString mNoisePass;
    QString mActionNote;
    std::function<void()> mAfterUnlock;

    QPointer<BusyDialog> mBusyDialog;
    ShutdownWindow*      mShutdownWindow;

    ShieldCard* mShield;
    CoinLogo*   mLogo;
    QLabel*     mBalance;
    QLabel*     mSpendable;
    QLabel*     mImmature;
    QWidget*    mPendingRow;
    QLabel*     mPending;
    QLabel*     mMiningState;
    QLabel*     mNetHash;
    QLabel*     mNextBits;
    QLabel*     mPeers;
    QLabel*     mHeight;
    QLabel*     mStatus;
    QLabel*     mNoHistory;
    QVector<HistoryRow> mRows;

    MiButton*  mSend;
    MiButton*  mAll;
    MiButton*  mStartMining;
    MiButton*  mStopMining;
    MiButton*  mNewAddress;
    MiButton*  mAddresses;
    MiButton*  mCreateWallet;
    MiButton*  mNoiseFile;
    NavButton* mNetwork;
    NavButton* mSettings;

    void BuildUi();
    QWidget* BuildRightPanel(QWidget* parent);
    QWidget* BuildBalance(QWidget* parent);
    QWidget* BuildHistory(QWidget* parent);

    void PollChain();
    void PollWallet();
    void CycleHistory();

    void OnChainUpdated(const ChainInfo& info);
    void OnWalletUpdated(const WalletInfo& info);
    void OnHistoryUpdated(const QVector<TxRecord>& records);
    void OnHistoryProgress(qint64 scanned, qint64 tip);
    void OnActionFinished(const ActionResult& result);
    void OnNoiseProgress(qint64 produced, qint64 target);
    void OnNoiseFinished(bool ok, const QString& text);
    void OnNodeExited(int code);

    void RunAction(const QString& text, std::function<void()> work);
    void EndBusyDialog();
    void EnsureUnlocked(std::function<void()> then);
    void PromptUnlock(std::function<void()> then);
    void UpdateButtons();
    void UpdateStatus();
    void ShowError(const QString& text);
    void ShowInfo(const QString& text);
    int  MiningThreads() const;

    void OnCreateWallet();
    void OnNoiseFile();
    void OnNewAddress();
    void OnAddresses();
    void OnStartMining();
    void OnStopMining();
    void OnSend();
    void OnAll();
    void OnRow(int index);
    void OnNetwork();
    void OnSettings();

    void BeginShutdown();
    void CheckShutdown();
};

} // namespace mi

#endif // MONEU_MI_MAINWINDOW_H
