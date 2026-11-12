// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "dialogs.h"
#include "miutil.h"

#include "chainparams.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace mi {

static QLabel* Label(const QString& text, QWidget* parent, int px = 14,
                     bool bold = true)
{
    QLabel* l = new QLabel(text, parent);
    l->setFont(MonoFont(px, bold));
    l->setTextFormat(Qt::PlainText);
    l->setWordWrap(true);
    return l;
}

static void MakeRed(QLabel* l)
{
    l->setStyleSheet(QStringLiteral("color: #B3261E;"));
}

static QLabel* Heading(const QString& text, QWidget* parent)
{
    QLabel* l = new QLabel(text, parent);
    l->setFont(MonoFont(15, true, 3.0));
    l->setTextFormat(Qt::PlainText);
    return l;
}

static QTableWidgetItem* Cell(const QString& text, bool right = false)
{
    QTableWidgetItem* item = new QTableWidgetItem(text);
    item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
    if (right) item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    return item;
}

static QTableWidget* MakeTable(const QStringList& headers, QWidget* parent)
{
    QTableWidget* t = new QTableWidget(parent);
    t->setColumnCount(headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->verticalHeader()->setVisible(false);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setFont(MonoFont(13, true));
    t->horizontalHeader()->setFont(MonoFont(13, true));
    t->setAlternatingRowColors(true);
    return t;
}

void ShowText(QWidget* parent, const QString& title, const QString& text,
              bool error)
{
    QMessageBox box(error ? QMessageBox::Critical : QMessageBox::Information,
                    title, text, QMessageBox::Ok, parent);
    box.setTextFormat(Qt::PlainText);
    box.setTextInteractionFlags(Qt::TextSelectableByMouse);
    QLabel* body = box.findChild<QLabel*>(QStringLiteral("qt_msgbox_label"));
    if (body) body->setFont(MonoFont(13, true));
    box.exec();
}

QString FormatTime(qint64 secs)
{
    if (secs <= 0) return QString();
    const QDateTime t = QDateTime::fromSecsSinceEpoch(secs).toLocalTime();
    return QLocale(QLocale::English).toString(t, QStringLiteral("MMM d HH:mm"));
}

PassphraseDialog::PassphraseDialog(Mode mode, const QString& title,
                                   const QString& prompt, QWidget* parent)
    : QDialog(parent)
    , mMode(mode)
    , mSecond(nullptr)
{
    setWindowTitle(title);
    setModal(true);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 22, 24, 18);
    v->setSpacing(10);
    v->addWidget(Heading(title.toUpper(), this));
    v->addWidget(Label(prompt, this));

    QFormLayout* f = new QFormLayout();
    mFirst = new QLineEdit(this);
    mFirst->setEchoMode(QLineEdit::Password);
    mFirst->setMinimumWidth(400);
    f->addRow(Label(QStringLiteral("Passphrase"), this, 13, true), mFirst);
    if (mode == Create) {
        mSecond = new QLineEdit(this);
        mSecond->setEchoMode(QLineEdit::Password);
        f->addRow(Label(QStringLiteral("Repeat"), this, 13, true), mSecond);
    }
    v->addLayout(f);

    mProblem = Label(QString(), this, 13, true);
    MakeRed(mProblem);
    mProblem->hide();
    v->addWidget(mProblem);

    QDialogButtonBox* buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
    mFirst->setFocus();
}

PassphraseDialog::~PassphraseDialog()
{
    mFirst->clear();
    if (mSecond) mSecond->clear();
}

QString PassphraseDialog::Passphrase() const
{
    return mFirst->text();
}

void PassphraseDialog::accept()
{
    if (mFirst->text().isEmpty()) {
        mProblem->setText(QStringLiteral("Enter the passphrase."));
        mProblem->show();
        return;
    }
    if (mMode == Create && mFirst->text() != mSecond->text()) {
        mProblem->setText(QStringLiteral("The two passphrases are not the same."));
        mProblem->show();
        mSecond->clear();
        mSecond->setFocus();
        return;
    }
    QDialog::accept();
}

MnemonicDialog::MnemonicDialog(const QString& mnemonic, const QString& warning,
                               QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Wallet created"));
    setModal(true);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 22, 24, 18);
    v->setSpacing(12);
    v->addWidget(Heading(QStringLiteral("RECOVERY WORDS"), this));

    QLabel* warn = Label(warning, this, 14, true);
    MakeRed(warn);
    v->addWidget(warn);

    QGridLayout* g = new QGridLayout();
    g->setHorizontalSpacing(26);
    g->setVerticalSpacing(6);
    const QString clean = mnemonic.simplified();
    const QStringList words = clean.isEmpty() ? QStringList()
                                              : clean.split(QLatin1Char(' '));
    const int rows = (words.size() + 2) / 3;
    for (int i = 0; i < words.size(); ++i) {
        QLabel* w = Label(QStringLiteral("%1. %2").arg(i + 1, 2).arg(words[i]),
                          this, 15, true);
        w->setWordWrap(false);
        w->setTextInteractionFlags(Qt::TextSelectableByMouse);
        g->addWidget(w, rows > 0 ? i % rows : 0, rows > 0 ? i / rows : 0);
    }
    v->addLayout(g);

    QCheckBox* done = new QCheckBox(
        QStringLiteral("I have written these words down on paper"), this);
    done->setFont(MonoFont(13, true));
    v->addWidget(done);

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Ok, this);
    QPushButton* ok = buttons->button(QDialogButtonBox::Ok);
    ok->setEnabled(false);
    connect(done, &QCheckBox::toggled, ok, &QPushButton::setEnabled);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    v->addWidget(buttons);
}

AddressDialog::AddressDialog(const QString& address, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("New address"));
    setModal(true);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 22, 24, 18);
    v->setSpacing(12);
    v->addWidget(Heading(QStringLiteral("NEW ADDRESS"), this));
    QLineEdit* field = new QLineEdit(address, this);
    field->setReadOnly(true);
    field->setFont(MonoFont(15, true));
    field->setMinimumWidth(700);
    v->addWidget(field);

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    QPushButton* copy = buttons->addButton(QStringLiteral("Copy"),
                                           QDialogButtonBox::ActionRole);
    connect(copy, &QPushButton::clicked, this, [address]() {
        QApplication::clipboard()->setText(address);
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
}

AddressesDialog::AddressesDialog(const QVariantList& rows, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Addresses"));
    setModal(true);
    resize(1180, 560);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 22, 24, 18);
    v->setSpacing(12);
    v->addWidget(Heading(QStringLiteral("ADDRESSES"), this));

    mTable = MakeTable(QStringList() << QStringLiteral("Address")
                                     << QStringLiteral("Type")
                                     << QStringLiteral("Spendable")
                                     << QStringLiteral("Immature"), this);
    mTable->setRowCount(rows.size());
    int r = 0;
    for (int pass = 0; pass < 2; ++pass) {
        for (const QVariant& item : rows) {
            const QVariantMap row = item.toMap();
            const bool change = row.value(QStringLiteral("change")).toBool();
            if ((pass == 0) == change) continue;
            const bool known = row.value(QStringLiteral("known")).toBool();
            mTable->setItem(r, 0, Cell(row.value(QStringLiteral("address")).toString()));
            mTable->setItem(r, 1, Cell(change ? QStringLiteral("change")
                                              : QStringLiteral("receive")));
            mTable->setItem(r, 2, Cell(known ? FormatAmount(row.value(
                                           QStringLiteral("spendable")).toLongLong())
                                             : QStringLiteral("—"), true));
            mTable->setItem(r, 3, Cell(known ? FormatAmount(row.value(
                                           QStringLiteral("immature")).toLongLong())
                                             : QStringLiteral("—"), true));
            ++r;
        }
    }
    mTable->resizeColumnsToContents();
    mTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    v->addWidget(mTable);

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    QPushButton* copy = buttons->addButton(QStringLiteral("Copy address"),
                                           QDialogButtonBox::ActionRole);
    connect(copy, &QPushButton::clicked, this, [this]() {
        const int row = mTable->currentRow();
        if (row < 0 || !mTable->item(row, 0)) return;
        QApplication::clipboard()->setText(mTable->item(row, 0)->text());
    });
    connect(mTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (mTable->item(row, 0))
            QApplication::clipboard()->setText(mTable->item(row, 0)->text());
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
}

SendDialog::SendDialog(qint64 spendable, bool spendableKnown, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Send"));
    setModal(true);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 22, 24, 18);
    v->setSpacing(12);
    v->addWidget(Heading(QStringLiteral("SEND"), this));
    v->addWidget(Label(QStringLiteral("Spendable: ") +
                       (spendableKnown ? FormatAmount(spendable) +
                                             QStringLiteral(" MONEU")
                                       : QStringLiteral("—")),
                       this, 13, true));

    QFormLayout* f = new QFormLayout();
    mAddress = new QLineEdit(this);
    mAddress->setMinimumWidth(700);
    mAddress->setFont(MonoFont(14, true));
    mAmount = new QLineEdit(this);
    mAmount->setPlaceholderText(QStringLiteral("0.00000000"));
    mAmount->setFont(MonoFont(14, true));
    mMessage = new QLineEdit(this);
    mMessage->setPlaceholderText(QStringLiteral("optional, up to 300 bytes"));
    mMessage->setFont(MonoFont(14, true));
    f->addRow(Label(QStringLiteral("Pay to"), this, 13, true), mAddress);
    f->addRow(Label(QStringLiteral("Amount (MONEU)"), this, 13, true), mAmount);
    f->addRow(Label(QStringLiteral("Message"), this, 13, true), mMessage);
    v->addLayout(f);

    mProblem = Label(QString(), this, 13, true);
    MakeRed(mProblem);
    mProblem->hide();
    v->addWidget(mProblem);

    QDialogButtonBox* buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText(QStringLiteral("Send"));
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
    mAddress->setFocus();
}

QString SendDialog::Address() const { return mAddress->text().trimmed(); }
QString SendDialog::Amount() const { return mAmount->text().trimmed(); }
QString SendDialog::Message() const { return mMessage->text(); }

void SendDialog::accept()
{
    if (Address().isEmpty()) {
        mProblem->setText(QStringLiteral("Enter the address to pay to."));
        mProblem->show();
        mAddress->setFocus();
        return;
    }
    if (Amount().isEmpty()) {
        mProblem->setText(QStringLiteral("Enter the amount."));
        mProblem->show();
        mAmount->setFocus();
        return;
    }
    int64_t units = 0;
    std::string why;
    if (!ParseAmountText(Amount().toStdString(), units, why)) {
        mProblem->setText(QStringLiteral("error: Invalid amount: ") +
                          QString::fromStdString(why));
        mProblem->show();
        mAmount->setFocus();
        return;
    }
    if (units <= 0) {
        mProblem->setText(QStringLiteral("error: Amount must be positive"));
        mProblem->show();
        mAmount->setFocus();
        return;
    }
    const int bytes = Message().toUtf8().size();
    if (bytes > 300) {
        mProblem->setText(QStringLiteral("error: message is %1 bytes; the limit is 300")
                              .arg(bytes));
        mProblem->show();
        mMessage->setFocus();
        return;
    }
    QDialog::accept();
}

ConfirmSendDialog::ConfirmSendDialog(const QString& address,
                                     const QString& amount, int messageBytes,
                                     QWidget* parent)
    : QDialog(parent)
    , mTimer(new QTimer(this))
    , mLeft(3)
{
    setWindowTitle(QStringLiteral("Confirm send"));
    setModal(true);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 22, 24, 18);
    v->setSpacing(12);
    v->addWidget(Heading(QStringLiteral("CONFIRM SEND"), this));

    int64_t units = 0;
    std::string why;
    ParseAmountText(amount.toStdString(), units, why);
    const size_t message = messageBytes > 0 ? static_cast<size_t>(messageBytes) : 0;
    const int64_t fee = EstimateFeeUnits(1, 2, message);
    const int64_t extra = EstimateFeeUnits(2, 2, message) - fee;

    v->addWidget(Label(FormatAmount(units) + QStringLiteral(" MONEU"), this, 22, true));
    v->addWidget(Label(QStringLiteral("to"), this, 13));
    QLabel* to = Label(address, this, 15, true);
    to->setTextInteractionFlags(Qt::TextSelectableByMouse);
    v->addWidget(to);

    QFormLayout* f = new QFormLayout();
    f->addRow(Label(QStringLiteral("Recipient gets"), this, 13, true),
              Label(FormatAmount(units) + QStringLiteral(" MONEU"), this, 13, true));
    f->addRow(Label(QStringLiteral("Fee"), this, 13, true),
              Label(QStringLiteral("about ") + FormatAmount(fee) +
                        QStringLiteral(" MONEU"), this, 13, true));
    f->addRow(Label(QStringLiteral("Total paid"), this, 13, true),
              Label(QStringLiteral("about ") + FormatAmount(units + fee) +
                        QStringLiteral(" MONEU"), this, 13, true));
    v->addLayout(f);
    v->addWidget(Label(QStringLiteral("The node sets the exact fee from the size of "
                                      "the transaction. If it has to combine several "
                                      "coins, each one adds about %1 MONEU. The rest "
                                      "of the coins comes back to a new address of "
                                      "your wallet.").arg(FormatAmount(extra)),
                       this, 12));

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
    mYes = buttons->addButton(QStringLiteral("Send (3)"),
                              QDialogButtonBox::AcceptRole);
    mYes->setEnabled(false);
    buttons->button(QDialogButtonBox::Cancel)->setDefault(true);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);

    connect(mTimer, &QTimer::timeout, this, &ConfirmSendDialog::Tick);
    mTimer->start(1000);
}

void ConfirmSendDialog::Tick()
{
    --mLeft;
    if (mLeft <= 0) {
        mTimer->stop();
        mYes->setText(QStringLiteral("Send"));
        mYes->setEnabled(true);
        return;
    }
    mYes->setText(QStringLiteral("Send (%1)").arg(mLeft));
}

QString RecordType(const TxRecord& r)
{
    if (r.coinbase) return QStringLiteral("Mining reward");
    if (r.toSelf) return QStringLiteral("To yourself");
    if (r.fee >= 0) return QStringLiteral("Sent");
    return r.amount >= 0 ? QStringLiteral("Received") : QStringLiteral("Sent");
}

bool RecordIncoming(const TxRecord& r)
{
    return r.fee < 0 && r.amount >= 0;
}

QString RecordAmountText(const TxRecord& r)
{
    if (r.fee >= 0) {
        if (r.toSelf) return FormatAmount(r.sent);
        return FormatSignedAmount(-r.sent);
    }
    return FormatSignedAmount(r.amount);
}

static QString RecordStatus(const TxRecord& r, qint64 tip)
{
    if (r.pending || r.height < 0) return QStringLiteral("Pending");
    const qint64 confirmations = tip >= r.height ? tip - r.height + 1 : 0;
    if (r.coinbase) {
        const qint64 mature = r.height +
            static_cast<qint64>(::NetParams::COINBASE_MATURITY);
        if (tip < mature)
            return QStringLiteral("Immature, spendable at height %1")
                .arg(GroupDigits(mature));
    }
    if (confirmations == 1) return QStringLiteral("1 confirmation");
    return QStringLiteral("%1 confirmations").arg(GroupDigits(confirmations));
}

TxDetailsDialog::TxDetailsDialog(const TxRecord& r, qint64 tip, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Transaction"));
    setModal(true);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 22, 24, 18);
    v->setSpacing(10);
    v->addWidget(Heading(QStringLiteral("TRANSACTION"), this));

    QFormLayout* f = new QFormLayout();
    f->addRow(Label(QStringLiteral("Type"), this, 13, true),
              Label(RecordType(r), this));
    const QString unit = QStringLiteral(" MONEU");
    if (r.fee >= 0) {
        f->addRow(Label(r.toSelf ? QStringLiteral("Amount moved")
                                 : QStringLiteral("Amount sent"), this, 13, true),
                  Label(FormatAmount(r.sent) + unit, this));
        f->addRow(Label(QStringLiteral("Fee"), this, 13, true),
                  Label(FormatAmount(r.fee) + unit, this));
        if (!r.toSelf)
            f->addRow(Label(QStringLiteral("Total paid"), this, 13, true),
                      Label(FormatAmount(r.sent + r.fee) + unit, this));
        if (r.change > 0)
            f->addRow(Label(QStringLiteral("Change back to you"), this, 13, true),
                      Label(FormatAmount(r.change) + unit, this));
        f->addRow(Label(QStringLiteral("Balance change"), this, 13, true),
                  Label(FormatSignedAmount(r.amount) + unit, this));
    } else {
        f->addRow(Label(QStringLiteral("Amount"), this, 13, true),
                  Label(FormatSignedAmount(r.amount) + unit, this));
    }
    if (!r.from.isEmpty() && r.fee < 0) {
        QLabel* from = Label(r.from, this);
        from->setTextInteractionFlags(Qt::TextSelectableByMouse);
        f->addRow(Label(QStringLiteral("From"), this, 13, true), from);
    }
    QLabel* address = Label(r.address, this);
    address->setTextInteractionFlags(Qt::TextSelectableByMouse);
    f->addRow(Label(QStringLiteral("To"), this, 13, true), address);
    f->addRow(Label(QStringLiteral("Date"), this, 13, true),
              Label(FormatTime(r.time), this));
    f->addRow(Label(QStringLiteral("Status"), this, 13, true),
              Label(RecordStatus(r, tip), this));
    if (r.height >= 0 && !r.pending)
        f->addRow(Label(QStringLiteral("Block height"), this, 13, true),
                  Label(GroupDigits(r.height), this));
    QLabel* txid = Label(r.txid, this, 13);
    txid->setTextInteractionFlags(Qt::TextSelectableByMouse);
    f->addRow(Label(QStringLiteral("Transaction id"), this, 13, true), txid);
    v->addLayout(f);

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    QPushButton* copy = buttons->addButton(QStringLiteral("Copy id"),
                                           QDialogButtonBox::ActionRole);
    const QString id = r.txid;
    connect(copy, &QPushButton::clicked, this, [id]() {
        QApplication::clipboard()->setText(id);
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
    setMinimumWidth(980);
}

HistoryDialog::HistoryDialog(const QVector<TxRecord>& records, qint64 tip,
                             QWidget* parent)
    : QDialog(parent)
    , mRecords(records)
    , mTip(tip)
{
    setWindowTitle(QStringLiteral("History"));
    setModal(true);
    resize(1500, 680);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 22, 24, 18);
    v->setSpacing(12);
    v->addWidget(Heading(QStringLiteral("HISTORY"), this));

    QTableWidget* t = MakeTable(QStringList() << QStringLiteral("Date")
                                              << QStringLiteral("Type")
                                              << QStringLiteral("Address")
                                              << QStringLiteral("Amount")
                                              << QStringLiteral("Fee")
                                              << QStringLiteral("Status"), this);
    t->setRowCount(records.size());
    for (int i = 0; i < records.size(); ++i) {
        const TxRecord& r = records[i];
        t->setItem(i, 0, Cell(FormatTime(r.time)));
        t->setItem(i, 1, Cell(RecordType(r)));
        t->setItem(i, 2, Cell(RecordIncoming(r) && !r.from.isEmpty()
                                  ? QStringLiteral("from ") + r.from
                                  : QStringLiteral("to ") + r.address));
        QTableWidgetItem* amount = Cell(RecordAmountText(r), true);
        amount->setForeground(RecordIncoming(r) ? color::GreenText : color::Ink);
        t->setItem(i, 3, amount);
        t->setItem(i, 4, Cell(r.fee >= 0 ? FormatAmount(r.fee) : QString(), true));
        t->setItem(i, 5, Cell(RecordStatus(r, tip)));
    }
    t->resizeColumnsToContents();
    t->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    connect(t, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (row < 0 || row >= mRecords.size()) return;
        TxDetailsDialog d(mRecords[row], mTip, this);
        d.exec();
    });
    v->addWidget(t);
    v->addWidget(Label(QStringLiteral("Double-click a row for details."), this, 12));

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
}

static QString Bytes(qlonglong n)
{
    if (n < 1024) return QStringLiteral("%1 B").arg(n);
    if (n < 1024 * 1024) return QStringLiteral("%1 KB").arg(n / 1024.0, 0, 'f', 1);
    if (n < 1024LL * 1024 * 1024)
        return QStringLiteral("%1 MB").arg(n / (1024.0 * 1024.0), 0, 'f', 1);
    return QStringLiteral("%1 GB").arg(n / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
}

NetworkDialog::NetworkDialog(const QVariantMap& d, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Network"));
    setModal(true);
    resize(1180, 580);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 22, 24, 18);
    v->setSpacing(12);
    v->addWidget(Heading(QStringLiteral("NETWORK"), this));

    QFormLayout* f = new QFormLayout();
    f->addRow(Label(QStringLiteral("Node"), this, 13, true),
              Label(d.value(QStringLiteral("subversion")).toString(), this));
    f->addRow(Label(QStringLiteral("Port"), this, 13, true),
              Label(QString::number(d.value(QStringLiteral("localport")).toLongLong()),
                    this));
    f->addRow(Label(QStringLiteral("Connections"), this, 13, true),
              Label(QStringLiteral("%1 out, %2 in")
                        .arg(d.value(QStringLiteral("outbound")).toLongLong())
                        .arg(d.value(QStringLiteral("inbound")).toLongLong()), this));
    f->addRow(Label(QStringLiteral("Received / sent"), this, 13, true),
              Label(Bytes(d.value(QStringLiteral("recv")).toLongLong()) +
                        QStringLiteral(" / ") +
                        Bytes(d.value(QStringLiteral("sent")).toLongLong()), this));
    v->addLayout(f);

    const QVariantList peers = d.value(QStringLiteral("peers")).toList();
    QTableWidget* t = MakeTable(QStringList() << QStringLiteral("Peer")
                                              << QStringLiteral("Direction")
                                              << QStringLiteral("Version")
                                              << QStringLiteral("Height")
                                              << QStringLiteral("Ping"), this);
    t->setRowCount(peers.size());
    for (int i = 0; i < peers.size(); ++i) {
        const QVariantMap p = peers[i].toMap();
        t->setItem(i, 0, Cell(p.value(QStringLiteral("addr")).toString()));
        t->setItem(i, 1, Cell(p.value(QStringLiteral("inbound")).toBool()
                                  ? QStringLiteral("in") : QStringLiteral("out")));
        t->setItem(i, 2, Cell(p.value(QStringLiteral("subver")).toString()));
        t->setItem(i, 3, Cell(GroupDigits(p.value(QStringLiteral("height")).toLongLong()),
                              true));
        const double ping = p.value(QStringLiteral("ping")).toDouble();
        t->setItem(i, 4, Cell(ping > 0.0 ? QStringLiteral("%1 ms")
                                               .arg(qRound(ping * 1000.0))
                                         : QStringLiteral("—"), true));
    }
    t->resizeColumnsToContents();
    t->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    v->addWidget(t);

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
}

SettingsDialog::SettingsDialog(int threads, const QString& dataDir,
                               bool embedded, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Settings"));
    setModal(true);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 22, 24, 18);
    v->setSpacing(12);
    v->addWidget(Heading(QStringLiteral("SETTINGS"), this));

    QFormLayout* f = new QFormLayout();
    mThreads = new QSpinBox(this);
    mThreads->setRange(1, 32);
    mThreads->setValue(threads);
    mThreads->setFont(MonoFont(14, true));
    f->addRow(Label(QStringLiteral("CPU threads when there is no graphics card"),
                    this, 13, true), mThreads);
    QLabel* dir = Label(dataDir, this);
    dir->setTextInteractionFlags(Qt::TextSelectableByMouse);
    f->addRow(Label(QStringLiteral("Data directory"), this, 13, true), dir);
    f->addRow(Label(QStringLiteral("Node"), this, 13, true),
              Label(embedded ? QStringLiteral("runs inside MI")
                             : QStringLiteral("already running, MI is connected to it"),
                    this));
    f->addRow(Label(QStringLiteral("Version"), this, 13, true),
              Label(QStringLiteral("MONEU Interface (MI) " MI_VERSION), this));
    v->addLayout(f);

    QDialogButtonBox* buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
}

int SettingsDialog::Threads() const
{
    return mThreads->value();
}

BusyDialog::BusyDialog(const QString& text, QWidget* parent)
    : QDialog(parent, Qt::Dialog | Qt::CustomizeWindowHint | Qt::WindowTitleHint)
    , mDone(false)
{
    setWindowTitle(QStringLiteral("MONEU"));
    setModal(true);
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(26, 22, 26, 22);
    v->setSpacing(12);
    mText = Label(text, this, 14, true);
    mText->setWordWrap(false);
    mText->setMinimumWidth(580);
    v->addWidget(mText);
    mBar = new QProgressBar(this);
    mBar->setRange(0, 0);
    mBar->setTextVisible(false);
    v->addWidget(mBar);
    mCount = Label(QString(), this, 13, true);
    mCount->hide();
    v->addWidget(mCount);
}

void BusyDialog::SetText(const QString& text)
{
    mText->setText(text);
}

void BusyDialog::SetProgress(qint64 value, qint64 maximum)
{
    if (maximum <= 0) return;
    mBar->setRange(0, 1000);
    mBar->setValue(static_cast<int>((value * 1000) / maximum));
    mCount->setText(QStringLiteral("%1 / %2 MB")
                        .arg(value / (1024 * 1024))
                        .arg(maximum / (1024 * 1024)));
    mCount->show();
}

void BusyDialog::reject()
{
    if (mDone) QDialog::reject();
}

void BusyDialog::Finish()
{
    mDone = true;
    QDialog::accept();
}

void BusyDialog::closeEvent(QCloseEvent* event)
{
    if (!mDone) {
        event->ignore();
        return;
    }
    QDialog::closeEvent(event);
}

ShutdownWindow::ShutdownWindow(QWidget* parent)
    : QWidget(parent, Qt::Window | Qt::CustomizeWindowHint | Qt::WindowTitleHint)
{
    setWindowTitle(QStringLiteral("MONEU"));
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(30, 26, 30, 26);
    v->addWidget(Label(QStringLiteral("MONEU is shutting down...\n\n"
                                      "Do not shut down the computer until "
                                      "this window disappears."), this, 14, true));
    setMinimumWidth(580);
}

void ShutdownWindow::closeEvent(QCloseEvent* event)
{
    event->ignore();
}

} // namespace mi
