// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_MI_DIALOGS_H
#define MONEU_MI_DIALOGS_H

#include "historyscanner.h"

#include <QDialog>
#include <QString>
#include <QVariantList>
#include <QVariantMap>
#include <QVector>
#include <QWidget>

class QCheckBox;
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTimer;

namespace mi {

void ShowText(QWidget* parent, const QString& title, const QString& text,
              bool error);

QString FormatTime(qint64 secs);
QString RecordType(const TxRecord& r);
QString RecordAmountText(const TxRecord& r);
bool RecordIncoming(const TxRecord& r);

class PassphraseDialog : public QDialog {
    Q_OBJECT

public:
    enum Mode { Create, Single };

    PassphraseDialog(Mode mode, const QString& title, const QString& prompt,
                     QWidget* parent = nullptr);
    ~PassphraseDialog();

    QString Passphrase() const;

    void accept() override;

private:
    Mode       mMode;
    QLineEdit* mFirst;
    QLineEdit* mSecond;
    QLabel*    mProblem;
};

class MnemonicDialog : public QDialog {
    Q_OBJECT

public:
    MnemonicDialog(const QString& mnemonic, const QString& warning,
                   QWidget* parent = nullptr);
};

class AddressDialog : public QDialog {
    Q_OBJECT

public:
    explicit AddressDialog(const QString& address, QWidget* parent = nullptr);
};

class AddressesDialog : public QDialog {
    Q_OBJECT

public:
    explicit AddressesDialog(const QVariantList& rows, QWidget* parent = nullptr);

private:
    QTableWidget* mTable;
};

class SendDialog : public QDialog {
    Q_OBJECT

public:
    explicit SendDialog(qint64 spendable, bool spendableKnown,
                        QWidget* parent = nullptr);

    QString Address() const;
    QString Amount() const;
    QString Message() const;

    void accept() override;

private:
    QLineEdit* mAddress;
    QLineEdit* mAmount;
    QLineEdit* mMessage;
    QLabel*    mProblem;
};

class ConfirmSendDialog : public QDialog {
    Q_OBJECT

public:
    ConfirmSendDialog(const QString& address, const QString& amount,
                      int messageBytes,
                      QWidget* parent = nullptr);

private:
    QPushButton* mYes;
    QTimer*      mTimer;
    int          mLeft;

    void Tick();
};

class TxDetailsDialog : public QDialog {
    Q_OBJECT

public:
    TxDetailsDialog(const TxRecord& record, qint64 tipHeight,
                    QWidget* parent = nullptr);
};

class HistoryDialog : public QDialog {
    Q_OBJECT

public:
    HistoryDialog(const QVector<TxRecord>& records, qint64 tipHeight,
                  QWidget* parent = nullptr);

private:
    QVector<TxRecord> mRecords;
    qint64            mTip;
};

class NetworkDialog : public QDialog {
    Q_OBJECT

public:
    explicit NetworkDialog(const QVariantMap& data, QWidget* parent = nullptr);
};

class SettingsDialog : public QDialog {
    Q_OBJECT

public:
    SettingsDialog(int threads, const QString& dataDir, bool embedded,
                   QWidget* parent = nullptr);

    int Threads() const;

private:
    QSpinBox* mThreads;
};

class BusyDialog : public QDialog {
    Q_OBJECT

public:
    BusyDialog(const QString& text, QWidget* parent = nullptr);

    void SetText(const QString& text);
    void SetProgress(qint64 value, qint64 maximum);

    void reject() override;
    void Finish();

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    QLabel*       mText;
    QLabel*       mCount;
    QProgressBar* mBar;
    bool          mDone;
};

class ShutdownWindow : public QWidget {
    Q_OBJECT

public:
    explicit ShutdownWindow(QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;
};

} // namespace mi

#endif // MONEU_MI_DIALOGS_H
