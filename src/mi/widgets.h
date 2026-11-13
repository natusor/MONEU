// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_MI_WIDGETS_H
#define MONEU_MI_WIDGETS_H

#include <QAbstractButton>
#include <QColor>
#include <QPixmap>
#include <QWidget>

class QLabel;
class QVariantAnimation;

namespace mi {

class PaperWidget : public QWidget {
    Q_OBJECT

public:
    explicit PaperWidget(QWidget* parent = nullptr);

protected:
    void paintEvent(QPaintEvent* event) override;
};

class MiButton : public QAbstractButton {
    Q_OBJECT

public:
    enum Style { Green, Yellow, Small, Arrow, Graphite };

    MiButton(const QString& text, Style style, QWidget* parent = nullptr);

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    Style mStyle;
};

class LeafBar : public QWidget {
    Q_OBJECT

public:
    explicit LeafBar(QWidget* parent = nullptr);

    void SetLeaves(qint64 left, qint64 total);
    void Clear();

    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    qint64 mLeft;
    qint64 mTotal;
    bool   mKnown;
};

class ShieldCard : public QWidget {
    Q_OBJECT

public:
    explicit ShieldCard(QWidget* parent = nullptr);

    void SetLeaves(qint64 left, qint64 total);
    void Clear();

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    LeafBar* mBar;
    QLabel*  mLeaves;
    QLabel*  mPayments;
};

class CoinLogo : public QWidget {
    Q_OBJECT

public:
    explicit CoinLogo(QWidget* parent = nullptr);

    void Pulse();

    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    QPixmap            mCoin;
    qreal              mGlow;
    QVariantAnimation* mAnim;
};

class DashedLine : public QWidget {
    Q_OBJECT

public:
    explicit DashedLine(QWidget* parent = nullptr);

    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;
};

class NavButton : public QAbstractButton {
    Q_OBJECT

public:
    enum Icon { Globe, Gear };

    NavButton(const QString& text, Icon icon, QWidget* parent = nullptr);

    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    Icon mIcon;
};

QColor LeafColor(qint64 left, qint64 total);

} // namespace mi

#endif // MONEU_MI_WIDGETS_H
