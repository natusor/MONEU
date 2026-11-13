// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "mainwindow.h"

#include "dialogs.h"
#include "miutil.h"
#include "nodehost.h"
#include "noisejob.h"
#include "widgets.h"

#include <QApplication>
#include <QCloseEvent>
#include <QGridLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QScreen>
#include <QSettings>
#include <QStandardPaths>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>

namespace mi {

static const int CHAIN_POLL_MS = 1000;
static const int WALLET_POLL_MS = 60000;
static const int HISTORY_POLL_MS = 10000;
static const int HISTORY_ROWS = 5;

static QLabel* MakeLabel(const QString& text, const QFont& font,
                         const QColor& ink, QWidget* parent)
{
    QLabel* l = new QLabel(text, parent);
    l->setFont(font);
    l->setTextFormat(Qt::PlainText);
    QPalette pal = l->palette();
    pal.setColor(QPalette::WindowText, ink);
    l->setPalette(pal);
    return l;
}

static void SetInk(QLabel* l, const QColor& ink)
{
    QPalette pal = l->palette();
    pal.setColor(QPalette::WindowText, ink);
    l->setPalette(pal);
}

MainWindow::MainWindow(const std::vector<std::string>& nodeArgs,
                       const std::string& dataDir)
    : mDataDir(dataDir)
    , mNode(new NodeHost(nodeArgs, dataDir, this))
    , mPoller(new Poller(dataDir))
    , mActions(new Actions(dataDir))
    , mHistory(nullptr)
    , mNoise(new NoiseJob(dataDir))
    , mChainTimer(new QTimer(this))
    , mWalletTimer(new QTimer(this))
    , mHistoryTimer(new QTimer(this))
    , mShutdownTimer(new QTimer(this))
    , mChainPollBusy(false)
    , mWalletPollBusy(false)
    , mHistoryBusy(false)
    , mNodeReady(false)
    , mAskedUnlock(false)
    , mBusy(false)
    , mShuttingDown(false)
    , mStopRequested(false)
    , mNodeGone(false)
    , mNoiseRunning(false)
    , mNodeExitCode(0)
    , mLastTotal(-1)
    , mHistoryScanned(0)
    , mHistoryTip(0)
    , mShutdownWindow(nullptr)
    , mPendingRow(nullptr)
    , mPending(nullptr)
{
    const QString cacheDir =
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    mHistory = new HistoryScanner(dataDir, cacheDir);

    setWindowTitle(QStringLiteral("MONEU Interface (MI) " MI_VERSION));
    BuildUi();

    mPollThread.setObjectName(QStringLiteral("mi-poll"));
    mActionThread.setObjectName(QStringLiteral("mi-action"));
    mHistoryThread.setObjectName(QStringLiteral("mi-history"));
    mNoiseThread.setObjectName(QStringLiteral("mi-noise"));

    mPoller->moveToThread(&mPollThread);
    mActions->moveToThread(&mActionThread);
    mHistory->moveToThread(&mHistoryThread);
    mNoise->moveToThread(&mNoiseThread);
    connect(&mPollThread, &QThread::finished, mPoller, &QObject::deleteLater);
    connect(&mActionThread, &QThread::finished, mActions, &QObject::deleteLater);
    connect(&mHistoryThread, &QThread::finished, mHistory, &QObject::deleteLater);
    connect(&mNoiseThread, &QThread::finished, mNoise, &QObject::deleteLater);

    connect(mPoller, &Poller::ChainUpdated, this, &MainWindow::OnChainUpdated);
    connect(mPoller, &Poller::WalletUpdated, this, &MainWindow::OnWalletUpdated);
    connect(mActions, &Actions::Finished, this, &MainWindow::OnActionFinished);
    connect(mHistory, &HistoryScanner::Updated, this, &MainWindow::OnHistoryUpdated);
    connect(mHistory, &HistoryScanner::Progress, this, &MainWindow::OnHistoryProgress);
    connect(mNoise, &NoiseJob::Progress, this, &MainWindow::OnNoiseProgress);
    connect(mNoise, &NoiseJob::Finished, this, &MainWindow::OnNoiseFinished);
    connect(mNode, &NodeHost::NodeExited, this, &MainWindow::OnNodeExited);

    connect(mChainTimer, &QTimer::timeout, this, &MainWindow::PollChain);
    connect(mWalletTimer, &QTimer::timeout, this, &MainWindow::PollWallet);
    connect(mHistoryTimer, &QTimer::timeout, this, &MainWindow::CycleHistory);
    connect(mShutdownTimer, &QTimer::timeout, this, &MainWindow::CheckShutdown);
}

MainWindow::~MainWindow()
{
    // After a normal close the history thread has finished and already
    // deleted the scanner, so it is told to stop only while that thread runs.
    if (mHistory && !mHistoryThread.isFinished()) mHistory->RequestStop();
    mPollThread.quit();
    mActionThread.quit();
    mHistoryThread.quit();
    mNoiseThread.quit();
    mPollThread.wait();
    mActionThread.wait();
    mHistoryThread.wait();
    mNoiseThread.wait();
    if (mNode->Embedded()) {
        mNode->RequestStop();
        mNode->Join();
    }
    delete mShutdownWindow;
}

void MainWindow::Start()
{
    mPollThread.start();
    mActionThread.start();
    mHistoryThread.start();
    mNoiseThread.start();

    mNode->Start();
    UpdateStatus();
    UpdateButtons();

    mChainTimer->start(CHAIN_POLL_MS);
    mWalletTimer->start(WALLET_POLL_MS);
    mHistoryTimer->start(HISTORY_POLL_MS);
    PollChain();
}

void MainWindow::BuildUi()
{
    PaperWidget* root = new PaperWidget(this);
    setCentralWidget(root);

    QGridLayout* g = new QGridLayout(root);
    g->setContentsMargins(Px(32), Px(10), Px(32), Px(16));
    g->setHorizontalSpacing(Px(36));
    g->setVerticalSpacing(Px(8));

    QLabel* title = MakeLabel(QStringLiteral("MONEU"), MonoFont(40, true, 112.0),
                              color::Title, root);
    title->setAlignment(Qt::AlignCenter);
    title->setAttribute(Qt::WA_TransparentForMouseEvents);
    g->addWidget(title, 0, 0, 1, 3);

    mShield = new ShieldCard(root);
    mShield->setFixedWidth(Px(410));
    g->addWidget(mShield, 1, 0, Qt::AlignTop);

    g->addWidget(BuildBalance(root), 1, 1, Qt::AlignTop);

    QWidget* history = BuildHistory(root);
    QHBoxLayout* historyRow = new QHBoxLayout();
    historyRow->setContentsMargins(0, 0, 0, 0);
    historyRow->addSpacing(Px(150));
    historyRow->addWidget(history, 0, Qt::AlignLeft);
    historyRow->addStretch(1);
    g->addLayout(historyRow, 2, 0, 1, 2);

    mStatus = new QLabel(root);
    mStatus->setFont(MonoFont(14, true));
    mStatus->setTextFormat(Qt::RichText);
    mStatus->setWordWrap(false);
    SetInk(mStatus, color::Ink);
    connect(mStatus, &QLabel::linkActivated, this, [this](const QString&) {
        if (!mBusy) PromptUnlock(nullptr);
    });
    g->addWidget(mStatus, 3, 0, 1, 2, Qt::AlignBottom | Qt::AlignLeft);

    QWidget* right = BuildRightPanel(root);
    right->setFixedWidth(Px(420));
    g->addWidget(right, 0, 2, 4, 1);

    g->setColumnStretch(1, 1);
    g->setRowStretch(2, 1);

    // Opens as a window in the middle of the screen, never over the whole of it.
    const QRect screen = QGuiApplication::primaryScreen()->availableGeometry();
    const QSize start(qMin(Px(MI_FULL_WIDTH), qRound(screen.width() * 0.94)),
                      qMin(Px(MI_FULL_HEIGHT), qRound(screen.height() * 0.90)));
    setGeometry(QStyle::alignedRect(Qt::LeftToRight, Qt::AlignCenter, start, screen));
    root->setFocusPolicy(Qt::StrongFocus);
    root->setFocus();
}

QWidget* MainWindow::BuildBalance(QWidget* parent)
{
    QWidget* box = new QWidget(parent);
    QVBoxLayout* v = new QVBoxLayout(box);
    v->setContentsMargins(0, Px(8), 0, 0);
    v->setSpacing(Px(4));

    v->addWidget(MakeLabel(QStringLiteral("BALANCE"), MonoFont(15, true, 3.0),
                           color::Ink, box));

    QHBoxLayout* top = new QHBoxLayout();
    QVBoxLayout* total = new QVBoxLayout();
    total->setSpacing(Px(2));
    total->addWidget(MakeLabel(QStringLiteral("Total balance"),
                               MonoFont(13, true, 0.5), color::InkSoft, box));
    QHBoxLayout* amount = new QHBoxLayout();
    amount->setSpacing(Px(8));
    mBalance = MakeLabel(QStringLiteral("—"), MonoFont(30, true),
                         color::Ink, box);
    amount->addWidget(mBalance, 0, Qt::AlignBottom);
    amount->addWidget(MakeLabel(QStringLiteral("MONEU"), MonoFont(17, true),
                                color::Unit, box), 0, Qt::AlignBottom);
    amount->addStretch(1);
    total->addLayout(amount);
    top->addLayout(total, 1);

    mSend = new MiButton(QStringLiteral("→ SEND"), MiButton::Green, box);
    mSend->setFixedSize(Px(150), Px(46));
    connect(mSend, &QAbstractButton::clicked, this, &MainWindow::OnSend);
    top->addWidget(mSend, 0, Qt::AlignVCenter);
    v->addLayout(top);
    v->addSpacing(Px(8));

    QHBoxLayout* parts = new QHBoxLayout();
    parts->setSpacing(Px(36));
    QVBoxLayout* sp = new QVBoxLayout();
    sp->setSpacing(1);
    sp->addWidget(MakeLabel(QStringLiteral("Spendable"), MonoFont(13, true, 0.5),
                            color::InkSoft, box));
    mSpendable = MakeLabel(QStringLiteral("—"), MonoFont(14, true),
                           color::Ink, box);
    sp->addWidget(mSpendable);
    QVBoxLayout* im = new QVBoxLayout();
    im->setSpacing(1);
    im->addWidget(MakeLabel(QStringLiteral("Immature mining"),
                            MonoFont(13, true, 0.5), color::InkSoft, box));
    mImmature = MakeLabel(QStringLiteral("—"), MonoFont(14, true),
                          color::Ink, box);
    im->addWidget(mImmature);
    parts->addLayout(sp);
    parts->addLayout(im);
    parts->addStretch(1);
    v->addLayout(parts);

    // The node counts confirmed coins only, so a payment still waiting for a
    // block is shown here until it is in one.
    mPendingRow = new QWidget(box);
    QHBoxLayout* pr = new QHBoxLayout(mPendingRow);
    pr->setContentsMargins(0, Px(6), 0, 0);
    pr->setSpacing(Px(10));
    pr->addWidget(MakeLabel(QStringLiteral("Waiting for a block"),
                            MonoFont(13, true, 0.5), color::InkSoft, mPendingRow));
    mPending = MakeLabel(QString(), MonoFont(14, true), color::Ink, mPendingRow);
    pr->addWidget(mPending);
    pr->addStretch(1);
    mPendingRow->hide();
    v->addWidget(mPendingRow);
    return box;
}

QWidget* MainWindow::BuildHistory(QWidget* parent)
{
    QWidget* box = new QWidget(parent);
    box->setFixedWidth(Px(740));
    QVBoxLayout* v = new QVBoxLayout(box);
    v->setContentsMargins(0, Px(14), 0, 0);
    v->setSpacing(Px(6));

    QHBoxLayout* head = new QHBoxLayout();
    head->addWidget(MakeLabel(QStringLiteral("HISTORY"), MonoFont(15, true, 3.0),
                              color::Ink, box));
    head->addStretch(1);
    mAll = new MiButton(QStringLiteral("ALL"), MiButton::Small, box);
    mAll->setFixedSize(Px(84), Px(38));
    connect(mAll, &QAbstractButton::clicked, this, &MainWindow::OnAll);
    head->addWidget(mAll);
    v->addLayout(head);
    v->addSpacing(Px(4));

    mNoHistory = MakeLabel(QStringLiteral("No transactions yet."),
                           MonoFont(13, true), color::InkSoft, box);
    v->addWidget(mNoHistory);

    for (int i = 0; i < HISTORY_ROWS; ++i) {
        HistoryRow row;
        row.box = new QWidget(box);
        QGridLayout* g = new QGridLayout(row.box);
        g->setContentsMargins(0, Px(4), 0, Px(6));
        g->setHorizontalSpacing(Px(12));
        g->setVerticalSpacing(1);
        row.type = MakeLabel(QString(), MonoFont(16, true), color::Ink, row.box);
        row.address = MakeLabel(QString(), MonoFont(13, true), color::Ink, row.box);
        row.address->setTextInteractionFlags(Qt::TextSelectableByMouse);
        row.detail = MakeLabel(QString(), MonoFont(13, true), color::InkSoft, row.box);
        row.amount = MakeLabel(QString(), MonoFont(17, true), color::Ink, row.box);
        row.amount->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        row.unit = MakeLabel(QStringLiteral("MONEU"), MonoFont(13, true),
                             color::Unit, row.box);
        row.unit->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        row.arrow = new MiButton(QString(), MiButton::Arrow, row.box);
        row.arrow->setFixedSize(Px(40), Px(40));
        connect(row.arrow, &QAbstractButton::clicked, this, [this, i]() { OnRow(i); });
        g->addWidget(row.type, 0, 0);
        g->addWidget(row.amount, 0, 1);
        g->addWidget(row.unit, 0, 2);
        g->addWidget(row.address, 1, 0, 1, 3);
        g->addWidget(row.detail, 2, 0, 1, 3);
        g->addWidget(row.arrow, 0, 3, 3, 1, Qt::AlignVCenter);
        g->setColumnStretch(0, 1);
        row.box->hide();
        v->addWidget(row.box);
        mRows.append(row);
    }
    v->addStretch(1);
    return box;
}

QWidget* MainWindow::BuildRightPanel(QWidget* parent)
{
    QWidget* box = new QWidget(parent);
    QVBoxLayout* v = new QVBoxLayout(box);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(Px(4));

    mLogo = new CoinLogo(box);
    v->addWidget(mLogo, 0, Qt::AlignHCenter);

    v->addWidget(MakeLabel(QStringLiteral("MINING"), MonoFont(15, true, 3.0),
                           color::Ink, box));

    auto addRow = [box, v](const QString& name, QLabel*& value) {
        QHBoxLayout* h = new QHBoxLayout();
        h->addWidget(MakeLabel(name, MonoFont(13, true, 0.5), color::InkSoft, box));
        h->addStretch(1);
        value = MakeLabel(QStringLiteral("—"), MonoFont(15, true), color::Ink, box);
        value->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        h->addWidget(value);
        v->addLayout(h);
    };

    addRow(QStringLiteral("Mining"), mMiningState);
    mMiningState->setTextFormat(Qt::RichText);
    v->addWidget(new DashedLine(box));
    addRow(QStringLiteral("Network hash"), mNetHash);
    v->addWidget(new DashedLine(box));
    addRow(QStringLiteral("Next bits"), mNextBits);
    v->addSpacing(Px(10));

    QGridLayout* buttons = new QGridLayout();
    buttons->setHorizontalSpacing(Px(12));
    buttons->setVerticalSpacing(Px(12));
    mStartMining = new MiButton(QStringLiteral("START MINING"), MiButton::Green, box);
    mStopMining = new MiButton(QStringLiteral("STOP MINING"), MiButton::Graphite, box);
    mNewAddress = new MiButton(QStringLiteral("NEW ADDRESS"), MiButton::Green, box);
    mAddresses = new MiButton(QStringLiteral("ADDRESSES"), MiButton::Green, box);
    for (MiButton* b : {mStartMining, mStopMining, mNewAddress, mAddresses}) {
        b->setMinimumSize(Px(190), Px(46));
        b->setFont(MonoFont(14, true, 0.8));
    }
    buttons->addWidget(mStartMining, 0, 0);
    buttons->addWidget(mStopMining, 0, 1);
    buttons->addWidget(mNewAddress, 1, 0);
    buttons->addWidget(mAddresses, 1, 1);
    v->addLayout(buttons);
    v->addSpacing(Px(8));

    addRow(QStringLiteral("Connected nodes"), mPeers);
    v->addWidget(new DashedLine(box));
    addRow(QStringLiteral("Block height"), mHeight);
    v->addSpacing(Px(8));

    QLabel* samePass = MakeLabel(
        QStringLiteral("Use the same passphrase for the noise file as for the wallet."),
        MonoFont(14, true), Qt::white, box);
    samePass->setWordWrap(true);
    samePass->setStyleSheet(QStringLiteral(
        "QLabel { color: white; border: 2px solid #5B16B0; border-radius: %1px;"
        " padding: %2px %3px; background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        " stop:0 #B46CFF, stop:1 #7A2BE2); }")
        .arg(Px(8)).arg(Px(5)).arg(Px(9)));
    v->addWidget(samePass);
    v->addSpacing(Px(8));

    QHBoxLayout* yellow = new QHBoxLayout();
    yellow->setSpacing(Px(12));
    mCreateWallet = new MiButton(QStringLiteral("CREATE WALLET"), MiButton::Yellow, box);
    mNoiseFile = new MiButton(QStringLiteral("NOISE FILE"), MiButton::Yellow, box);
    for (MiButton* b : {mCreateWallet, mNoiseFile}) {
        b->setMinimumSize(Px(190), Px(46));
        b->setFont(MonoFont(14, true, 0.8));
    }
    yellow->addWidget(mCreateWallet);
    yellow->addWidget(mNoiseFile);
    v->addLayout(yellow);

    QHBoxLayout* nav = new QHBoxLayout();
    mNetwork = new NavButton(QStringLiteral("Network"), NavButton::Globe, box);
    mSettings = new NavButton(QStringLiteral("Settings"), NavButton::Gear, box);
    nav->addStretch(1);
    nav->addWidget(mNetwork);
    nav->addStretch(2);
    nav->addWidget(mSettings);
    nav->addStretch(1);
    v->addLayout(nav);
    v->addStretch(1);

    connect(mStartMining, &QAbstractButton::clicked, this, &MainWindow::OnStartMining);
    connect(mStopMining, &QAbstractButton::clicked, this, &MainWindow::OnStopMining);
    connect(mNewAddress, &QAbstractButton::clicked, this, &MainWindow::OnNewAddress);
    connect(mAddresses, &QAbstractButton::clicked, this, &MainWindow::OnAddresses);
    connect(mCreateWallet, &QAbstractButton::clicked, this, &MainWindow::OnCreateWallet);
    connect(mNoiseFile, &QAbstractButton::clicked, this, &MainWindow::OnNoiseFile);
    connect(mNetwork, &QAbstractButton::clicked, this, &MainWindow::OnNetwork);
    connect(mSettings, &QAbstractButton::clicked, this, &MainWindow::OnSettings);
    return box;
}

void MainWindow::PollChain()
{
    if (mChainPollBusy || mShuttingDown) return;
    mChainPollBusy = true;
    Poller* poller = mPoller;
    QMetaObject::invokeMethod(poller, [poller]() { poller->PollChain(); },
                              Qt::QueuedConnection);
}

void MainWindow::PollWallet()
{
    if (mWalletPollBusy || mShuttingDown || !mNodeReady) return;
    mWalletPollBusy = true;
    Poller* poller = mPoller;
    QMetaObject::invokeMethod(poller, [poller]() { poller->PollWallet(); },
                              Qt::QueuedConnection);
}

void MainWindow::CycleHistory()
{
    if (mHistoryBusy || mShuttingDown || !mNodeReady) return;
    if (!mWallet.ok || !mWallet.initialized) return;
    mHistoryBusy = true;
    HistoryScanner* scanner = mHistory;
    QPointer<MainWindow> self(this);
    QMetaObject::invokeMethod(scanner, [scanner, self]() {
        scanner->Cycle();
        if (self) {
            QMetaObject::invokeMethod(self.data(), [self]() {
                if (self) self->mHistoryBusy = false;
            }, Qt::QueuedConnection);
        }
    }, Qt::QueuedConnection);
}

void MainWindow::OnChainUpdated(const ChainInfo& info)
{
    mChainPollBusy = false;
    if (mShuttingDown) return;

    if (!info.ok) {
        mChain.ok = false;
        mChain.error = info.error;
        UpdateStatus();
        return;
    }

    const bool first = !mNodeReady;
    const bool moved = info.height != mChain.height;
    mChain = info;
    mNodeReady = true;

    mHeight->setText(GroupDigits(info.height));
    mPeers->setText(QString::number(info.peers));
    mNetHash->setText(FormatHashRate(info.networkHash));
    mNextBits->setText(QString::number(info.nextBits, 16).rightJustified(8, QLatin1Char('0')));
    mMiningState->setText(info.mining
        ? QStringLiteral("<span style='color:#1E7836'>●</span> ON")
        : QStringLiteral("<span style='color:#9A958A'>●</span> OFF"));
    mMiningState->setToolTip(info.mining
        ? QStringLiteral("This computer: ") + FormatHashRate(info.hashRate)
        : QString());

    if (first) {
        UpdateButtons();
        PollWallet();
    } else if (moved) {
        PollWallet();
        CycleHistory();
    }
    UpdateStatus();
    UpdateButtons();
}

void MainWindow::OnWalletUpdated(const WalletInfo& info)
{
    mWalletPollBusy = false;
    if (mShuttingDown) return;

    const bool becameLoaded = info.ok && info.initialized &&
                              !(mWallet.ok && mWallet.initialized);
    mWallet = info;

    if (info.ok && info.noiseLoaded && info.leavesTotal > 0)
        mShield->SetLeaves(info.leavesLeft, info.leavesTotal);
    else
        mShield->Clear();

    if (info.ok && info.balanceKnown) {
        mBalance->setText(FormatAmount(info.total));
        mSpendable->setText(FormatAmount(info.spendable) + QStringLiteral(" MONEU"));
        mImmature->setText(FormatAmount(info.immature) + QStringLiteral(" MONEU"));
        if (mLastTotal >= 0 && info.total > mLastTotal) mLogo->Pulse();
        mLastTotal = info.total;
    } else if (!info.ok || !info.initialized) {
        mBalance->setText(QStringLiteral("—"));
        mSpendable->setText(QStringLiteral("—"));
        mImmature->setText(QStringLiteral("—"));
    }

    if (becameLoaded) CycleHistory();

    if (info.ok && info.walletFile && (!info.initialized || info.locked) &&
        !mAskedUnlock && !mBusy) {
        mAskedUnlock = true;
        QTimer::singleShot(0, this, [this]() {
            if (!mBusy && !mShuttingDown) PromptUnlock(nullptr);
        });
    }
    UpdateStatus();
    UpdateButtons();
}

void MainWindow::OnHistoryUpdated(const QVector<TxRecord>& records)
{
    mRecords = records;
    qint64 pending = 0;
    bool anyPending = false;
    for (const TxRecord& r : records) {
        if (!r.pending) continue;
        anyPending = true;
        pending += r.amount;
    }
    if (anyPending) {
        mPending->setText(FormatSignedAmount(pending) + QStringLiteral(" MONEU"));
        mPendingRow->show();
    } else {
        mPendingRow->hide();
    }
    const int shown = qMin(HISTORY_ROWS, records.size());
    mNoHistory->setVisible(shown == 0);
    for (int i = 0; i < mRows.size(); ++i) {
        HistoryRow& row = mRows[i];
        if (i >= shown) {
            row.box->hide();
            continue;
        }
        const TxRecord& r = records[i];
        const bool in = RecordIncoming(r);
        row.type->setText(RecordType(r));
        if (RecordIncoming(r) && !r.from.isEmpty())
            row.address->setText(QStringLiteral("from ") + r.from);
        else
            row.address->setText(QStringLiteral("to ") + r.address);
        QString detail = FormatTime(r.time);
        if (r.fee >= 0)
            detail += QStringLiteral(" · fee ") + FormatAmount(r.fee) +
                      QStringLiteral(" MONEU");
        if (r.pending) detail += QStringLiteral(" · pending");
        row.detail->setText(detail);
        row.amount->setText(RecordAmountText(r));
        SetInk(row.amount, in ? color::GreenText : color::Ink);
        row.arrow->setText(in ? QStringLiteral("←") : QStringLiteral("→"));
        row.box->show();
    }
}

void MainWindow::OnHistoryProgress(qint64 scanned, qint64 tip)
{
    mHistoryScanned = scanned;
    mHistoryTip = tip;
    UpdateStatus();
}

void MainWindow::RunAction(const QString& text, std::function<void()> work)
{
    mBusy = true;
    UpdateButtons();
    EndBusyDialog();
    BusyDialog* d = new BusyDialog(text, this);
    d->setAttribute(Qt::WA_DeleteOnClose);
    d->setWindowModality(Qt::ApplicationModal);
    d->show();
    mBusyDialog = d;
    QMetaObject::invokeMethod(mActions, work, Qt::QueuedConnection);
}

void MainWindow::EndBusyDialog()
{
    if (mBusyDialog) {
        BusyDialog* d = mBusyDialog.data();
        mBusyDialog.clear();
        d->Finish();
    }
}

void MainWindow::EnsureUnlocked(std::function<void()> then)
{
    if (mWallet.ok && mWallet.walletFile &&
        (!mWallet.initialized || mWallet.locked)) {
        PromptUnlock(then);
        return;
    }
    then();
}

void MainWindow::PromptUnlock(std::function<void()> then)
{
    PassphraseDialog d(PassphraseDialog::Single, QStringLiteral("Unlock wallet"),
                       QStringLiteral("Enter the passphrase of your wallet."), this);
    if (d.exec() != QDialog::Accepted) return;
    const QString pass = d.Passphrase();
    mAfterUnlock = then;
    Actions* actions = mActions;
    RunAction(QStringLiteral("Unlocking the wallet..."), [actions, pass]() {
        actions->Unlock(pass, QStringLiteral("unlock"));
    });
}

void MainWindow::ShowError(const QString& text)
{
    ShowText(this, QStringLiteral("MONEU"), text, true);
}

void MainWindow::ShowInfo(const QString& text)
{
    ShowText(this, QStringLiteral("MONEU"), text, false);
}

int MainWindow::MiningThreads() const
{
    QSettings s;
    const int fallback = qMax(1, QThread::idealThreadCount() - 1);
    const int threads = s.value(QStringLiteral("mining/threads"), fallback).toInt();
    return qBound(1, threads, 32);
}

void MainWindow::OnActionFinished(const ActionResult& r)
{
    EndBusyDialog();
    if (mShuttingDown) {
        mBusy = false;
        return;
    }

    if (r.kind == QStringLiteral("noise-check")) {
        if (!r.ok) {
            mNoisePass.fill(QLatin1Char('\0'));
            mNoisePass.clear();
            mBusy = false;
            UpdateButtons();
            ShowError(r.text + QStringLiteral("\n\nThe noise file needs the same "
                                              "passphrase you chose for the wallet."));
            return;
        }
        BusyDialog* d = new BusyDialog(
            QStringLiteral("Do NOT shut down and do NOT interrupt\n"
                           "Your hardware is stressed on purpose to gather "
                           "physical entropy."), this);
        d->setAttribute(Qt::WA_DeleteOnClose);
        d->setWindowModality(Qt::ApplicationModal);
        d->show();
        mBusyDialog = d;
        mNoiseRunning = true;
        NoiseJob* job = mNoise;
        const QString pass = mNoisePass;
        QMetaObject::invokeMethod(job, [job, pass]() { job->Run(pass); },
                                  Qt::QueuedConnection);
        return;
    }

    mBusy = false;
    UpdateButtons();

    if (r.kind == QStringLiteral("unlock")) {
        std::function<void()> then = mAfterUnlock;
        mAfterUnlock = nullptr;
        if (!r.ok) {
            ShowError(r.text);
        } else {
            mActionNote = r.text;
            mWallet.initialized = true;
            mWallet.locked = false;
            PollWallet();
            if (then) then();
        }
    } else if (r.kind == QStringLiteral("noise-load")) {
        mNoisePass.fill(QLatin1Char('\0'));
        mNoisePass.clear();
        if (r.ok) mActionNote = r.text;
        else ShowError(r.text);
        PollWallet();
    } else if (r.kind == QStringLiteral("create")) {
        if (!r.ok) {
            ShowError(r.text);
        } else {
            mLastTotal = -1;
            MnemonicDialog d(r.data.value(QStringLiteral("mnemonic")).toString(),
                             r.data.value(QStringLiteral("warning")).toString(), this);
            d.exec();
            const QString unlock = r.data.value(QStringLiteral("unlock")).toString();
            if (!unlock.isEmpty()) ShowInfo(unlock);
            mActionNote = unlock;
        }
        PollWallet();
    } else if (r.kind == QStringLiteral("newaddress")) {
        if (!r.ok) {
            ShowError(r.text);
        } else {
            AddressDialog d(r.text, this);
            d.exec();
        }
        PollWallet();
    } else if (r.kind == QStringLiteral("addresses")) {
        if (!r.ok) {
            ShowError(r.text);
        } else {
            AddressesDialog d(r.data.value(QStringLiteral("rows")).toList(), this);
            d.exec();
        }
    } else if (r.kind == QStringLiteral("startmining")) {
        if (!r.ok) {
            ShowError(r.text);
        } else {
            const QString device = r.data.value(QStringLiteral("device")).toString();
            const QString address = r.data.value(QStringLiteral("address")).toString();
            if (device == QStringLiteral("gpu"))
                mActionNote = QStringLiteral("Mining on the graphics card to ") + address;
            else
                mActionNote = QStringLiteral("Mining on %1 CPU thread(s) to ")
                                  .arg(r.data.value(QStringLiteral("threads")).toLongLong()) +
                              address;
        }
        PollChain();
    } else if (r.kind == QStringLiteral("stopmining")) {
        if (!r.ok) ShowError(r.text);
        else mActionNote = QStringLiteral("Mining stopped.");
        PollChain();
    } else if (r.kind == QStringLiteral("send")) {
        if (!r.ok) {
            ShowError(r.text);
        } else {
            const qint64 amount = r.data.value(QStringLiteral("amount")).toLongLong();
            QString paid;
            if (r.data.contains(QStringLiteral("fee"))) {
                const qint64 fee = r.data.value(QStringLiteral("fee")).toLongLong();
                paid = QStringLiteral("\n\nFee: ") + FormatAmount(fee) +
                       QStringLiteral(" MONEU\nTotal paid: ") + FormatAmount(amount + fee) +
                       QStringLiteral(" MONEU\nChange back to your wallet: ") +
                       FormatAmount(r.data.value(QStringLiteral("change")).toLongLong()) +
                       QStringLiteral(" MONEU");
            }
            ShowInfo(QStringLiteral("Sent ") + FormatAmount(amount) +
                     QStringLiteral(" MONEU to\n") +
                     r.data.value(QStringLiteral("address")).toString() + paid +
                     QStringLiteral("\n\nTransaction id:\n") + r.text +
                     (r.data.contains(QStringLiteral("noise"))
                          ? QStringLiteral("\n\n") +
                                r.data.value(QStringLiteral("noise")).toString()
                          : QString()));
            HistoryScanner* scanner = mHistory;
            const QString txid = r.text;
            QMetaObject::invokeMethod(scanner, [scanner, txid]() {
                scanner->AddPending(txid);
            }, Qt::QueuedConnection);
        }
        PollWallet();
    } else if (r.kind == QStringLiteral("network")) {
        if (!r.ok) {
            ShowError(r.text);
        } else {
            NetworkDialog d(r.data, this);
            d.exec();
        }
    }
    UpdateStatus();
    UpdateButtons();
}

void MainWindow::OnNoiseProgress(qint64 produced, qint64 target)
{
    if (mBusyDialog) mBusyDialog->SetProgress(produced, target);
}

void MainWindow::OnNoiseFinished(bool ok, const QString& text)
{
    mNoiseRunning = false;
    EndBusyDialog();
    if (mShuttingDown) {
        mNoisePass.fill(QLatin1Char('\0'));
        mNoisePass.clear();
        mBusy = false;
        return;
    }
    if (!ok) {
        mNoisePass.fill(QLatin1Char('\0'));
        mNoisePass.clear();
        mBusy = false;
        UpdateButtons();
        ShowError(text);
        return;
    }

    ShowInfo(text);
    mActionNote = QStringLiteral("Wait 10 seconds before creating addresses for "
                                 "this wallet.");
    UpdateStatus();
    PollWallet();
    QTimer::singleShot(10000, this, [this]() {
        if (mShuttingDown) {
            mNoisePass.fill(QLatin1Char('\0'));
            mNoisePass.clear();
            mBusy = false;
            return;
        }
        const QString pass = mNoisePass;
        Actions* actions = mActions;
        RunAction(QStringLiteral("Loading the noise file..."), [actions, pass]() {
            actions->Unlock(pass, QStringLiteral("noise-load"));
        });
    });
}

void MainWindow::OnCreateWallet()
{
    if (mBusy) return;
    if (FileExists(WalletFilePathText(mDataDir))) {
        ShowError(QStringLiteral("error: Wallet already exists. Use loadwallet."));
        return;
    }
    PassphraseDialog d(PassphraseDialog::Create, QStringLiteral("Create wallet"),
                       QStringLiteral("Choose a passphrase of at least 8 characters. "
                                      "The noise file will be protected with the "
                                      "same passphrase."), this);
    if (d.exec() != QDialog::Accepted) return;
    const QString pass = d.Passphrase();
    Actions* actions = mActions;
    RunAction(QStringLiteral("Creating the wallet..."), [actions, pass]() {
        actions->CreateWallet(pass);
    });
}

void MainWindow::OnNoiseFile()
{
    if (mBusy) return;
    const std::string noisePath = NoiseFilePathText(mDataDir);
    if (FileExists(noisePath)) {
        ShowError(QString::fromStdString(
            "error: a noise file already exists: " + noisePath + "\n"
            "The addresses of this wallet are bound to it. "
            "A new noise file belongs to a new wallet only."));
        return;
    }
    PassphraseDialog d(PassphraseDialog::Single, QStringLiteral("Noise file"),
                       QStringLiteral("Enter the same passphrase you chose for the "
                                      "wallet. The noise file is encrypted with it."), this);
    if (d.exec() != QDialog::Accepted) return;
    const QString pass = d.Passphrase();
    if (pass.toStdString().size() < 8) {
        ShowError(QStringLiteral("error: passphrase must be at least 8 characters"));
        return;
    }
    mNoisePass = pass;
    Actions* actions = mActions;
    RunAction(QStringLiteral("Checking the passphrase..."), [actions, pass]() {
        actions->Unlock(pass, QStringLiteral("noise-check"));
    });
}

void MainWindow::OnNewAddress()
{
    if (mBusy) return;
    EnsureUnlocked([this]() {
        Actions* actions = mActions;
        RunAction(QStringLiteral("Creating a new address..."), [actions]() {
            actions->NewAddress();
        });
    });
}

void MainWindow::OnAddresses()
{
    if (mBusy) return;
    EnsureUnlocked([this]() {
        Actions* actions = mActions;
        RunAction(QStringLiteral("Reading the addresses..."), [actions]() {
            actions->LoadAddresses();
        });
    });
}

void MainWindow::OnStartMining()
{
    if (mBusy) return;
    EnsureUnlocked([this]() {
        Actions* actions = mActions;
        const int threads = MiningThreads();
        RunAction(QStringLiteral("Starting mining..."), [actions, threads]() {
            actions->StartMining(threads);
        });
    });
}

void MainWindow::OnStopMining()
{
    if (mBusy) return;
    Actions* actions = mActions;
    RunAction(QStringLiteral("Stopping mining..."), [actions]() {
        actions->StopMining();
    });
}

void MainWindow::OnSend()
{
    if (mBusy) return;
    EnsureUnlocked([this]() {
        SendDialog d(mWallet.spendable, mWallet.ok && mWallet.balanceKnown, this);
        if (d.exec() != QDialog::Accepted) return;
        const QString address = d.Address();
        const QString amount = d.Amount();
        const QString message = d.Message();
        ConfirmSendDialog c(address, amount, message.toUtf8().size(), this);
        if (c.exec() != QDialog::Accepted) return;
        Actions* actions = mActions;
        RunAction(QStringLiteral("Sending..."), [actions, address, amount, message]() {
            actions->Send(address, amount, message);
        });
    });
}

void MainWindow::OnAll()
{
    HistoryDialog d(mRecords, mChain.height, this);
    d.exec();
}

void MainWindow::OnRow(int index)
{
    if (index < 0 || index >= mRecords.size()) return;
    TxDetailsDialog d(mRecords[index], mChain.height, this);
    d.exec();
}

void MainWindow::OnNetwork()
{
    if (mBusy || !mNodeReady) return;
    Actions* actions = mActions;
    RunAction(QStringLiteral("Reading the network..."), [actions]() {
        actions->LoadNetwork();
    });
}

void MainWindow::OnSettings()
{
    SettingsDialog d(MiningThreads(), QString::fromStdString(mDataDir),
                     mNode->Embedded(), this);
    if (d.exec() != QDialog::Accepted) return;
    QSettings s;
    s.setValue(QStringLiteral("mining/threads"), d.Threads());
}

void MainWindow::UpdateButtons()
{
    const bool ready = mNodeReady && !mBusy && !mShuttingDown;
    mSend->setEnabled(ready);
    mNewAddress->setEnabled(ready);
    mAddresses->setEnabled(ready);
    mCreateWallet->setEnabled(ready);
    mNoiseFile->setEnabled(ready);
    mNetwork->setEnabled(ready);
    mStartMining->setEnabled(ready && !mChain.mining);
    mStopMining->setEnabled(ready && mChain.mining);
    mAll->setEnabled(!mShuttingDown);
}

void MainWindow::UpdateStatus()
{
    QStringList lines;
    if (!mNodeReady) {
        if (!mChain.error.isEmpty() && !mNode->Embedded())
            lines << mChain.error.toHtmlEscaped();
        else
            lines << (mNode->Embedded() ? QStringLiteral("Starting the node...")
                                        : QStringLiteral("Connecting to the node..."));
    } else if (!mChain.ok && !mChain.error.isEmpty()) {
        lines << mChain.error.toHtmlEscaped();
    } else if (mWallet.ok) {
        if (!mWallet.walletFile)
            lines << QStringLiteral("No wallet yet. Press CREATE WALLET, then NOISE FILE.");
        else if (!mWallet.initialized || mWallet.locked)
            lines << QStringLiteral("Wallet locked. <a href='unlock'>Unlock</a>");
        else if (!mWallet.noiseFile)
            lines << QStringLiteral("No noise file yet. Press NOISE FILE.");
    }
    if (mNodeReady && mHistoryTip > 0 && mHistoryScanned < mHistoryTip)
        lines << QStringLiteral("Reading history: %1 / %2")
                     .arg(GroupDigits(mHistoryScanned))
                     .arg(GroupDigits(mHistoryTip));
    if (!mActionNote.isEmpty()) lines << mActionNote.toHtmlEscaped();
    mStatus->setText(lines.join(QStringLiteral("<br>")));
}

void MainWindow::OnNodeExited(int code)
{
    mNodeGone = true;
    mNodeExitCode = code;
    if (mShuttingDown) return;
    BeginShutdown();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (mShuttingDown) {
        event->ignore();
        return;
    }
    if (mNoiseRunning) {
        event->ignore();
        ShowInfo(QStringLiteral("Do NOT shut down and do NOT interrupt\n"
                                "Your hardware is stressed on purpose to gather "
                                "physical entropy."));
        return;
    }
    event->ignore();
    BeginShutdown();
}

void MainWindow::BeginShutdown()
{
    if (mShuttingDown) return;
    mShuttingDown = true;
    mChainTimer->stop();
    mWalletTimer->stop();
    mHistoryTimer->stop();
    EndBusyDialog();
    mHistory->RequestStop();
    UpdateButtons();

    hide();
    if (mNode->Embedded() || mNodeGone) {
        mShutdownWindow = new ShutdownWindow();
        mShutdownWindow->show();
    }

    mPollThread.quit();
    mActionThread.quit();
    mHistoryThread.quit();
    mNoiseThread.quit();
    mShutdownTimer->start(200);
}

void MainWindow::CheckShutdown()
{
    if (!mPollThread.isFinished() || !mActionThread.isFinished() ||
        !mHistoryThread.isFinished() || !mNoiseThread.isFinished())
        return;

    if (mNode->Embedded() && mNode->Running()) {
        if (!mStopRequested) {
            mStopRequested = true;
            mNode->RequestStop();
        }
        return;
    }
    mShutdownTimer->stop();
    mNode->Join();

    if (mNodeGone && mNodeExitCode != 0) {
        if (mShutdownWindow) mShutdownWindow->hide();
        ShowText(nullptr, QStringLiteral("MONEU"),
                 QStringLiteral("The MONEU node stopped with exit code %1.\n"
                                "See %2/logs/moneu.log for the reason.")
                     .arg(mNodeExitCode)
                     .arg(QString::fromStdString(mDataDir)), true);
    }
    QApplication::quit();
}

} // namespace mi
