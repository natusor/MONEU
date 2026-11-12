// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "widgets.h"
#include "miutil.h"

#include "chainparams.h"

#include <QFontMetrics>
#include <QGridLayout>
#include <QImage>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QRadialGradient>
#include <QVBoxLayout>
#include <QVariantAnimation>

#include <cmath>

namespace mi {

PaperWidget::PaperWidget(QWidget* parent)
    : QWidget(parent)
{
    setAttribute(Qt::WA_OpaquePaintEvent);
}

void PaperWidget::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.fillRect(rect(), color::Paper);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    QColor speck = color::PaperSpeck;
    speck.setAlpha(70);
    p.setBrush(speck);
    uint32_t seed = 0x4D4F4E45u;
    const int count = (width() * height()) / 2600;
    for (int i = 0; i < count; ++i) {
        seed = seed * 1664525u + 1013904223u;
        const int x = static_cast<int>(seed % static_cast<uint32_t>(qMax(1, width())));
        seed = seed * 1664525u + 1013904223u;
        const int y = static_cast<int>(seed % static_cast<uint32_t>(qMax(1, height())));
        seed = seed * 1664525u + 1013904223u;
        const qreal r = 0.5 + static_cast<qreal>(seed % 100) / 140.0;
        p.drawEllipse(QPointF(x, y), r, r);
    }
}

MiButton::MiButton(const QString& text, Style style, QWidget* parent)
    : QAbstractButton(parent)
    , mStyle(style)
{
    setText(text);
    setCursor(Qt::PointingHandCursor);
    setFocusPolicy(Qt::TabFocus);
    setAttribute(Qt::WA_Hover);
    if (style == Small)
        setFont(MonoFont(14, true, 1.0));
    else if (style == Arrow)
        setFont(MonoFont(16, true));
    else
        setFont(MonoFont(15, true, 1.2));
}

QSize MiButton::sizeHint() const
{
    QFontMetrics fm(font());
    const int textWidth = fm.horizontalAdvance(text());
    switch (mStyle) {
    case Small:
        return QSize(textWidth + 40, 46);
    case Arrow:
        return QSize(46, 46);
    default:
        return QSize(textWidth + 40, 58);
    }
}

QSize MiButton::minimumSizeHint() const
{
    return sizeHint();
}

void MiButton::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    const int sx = 3;
    const int sy = 4;
    const qreal radius = (mStyle == Arrow) ? 3.0 : 9.0;
    const qreal borderWidth = 3.0;

    QRectF face = QRectF(rect()).adjusted(borderWidth / 2.0, borderWidth / 2.0,
                                          -sx - borderWidth / 2.0,
                                          -sy - borderWidth / 2.0);
    const QRectF shadow = face.translated(sx, sy);
    const bool down = isDown() && isEnabled();
    if (down) face.translate(sx, sy);

    QColor fill;
    QColor border;
    QColor ink;
    switch (mStyle) {
    case Yellow:
        fill = color::Yellow;
        border = color::Green;
        ink = color::Ink;
        break;
    case Arrow:
        fill = color::Mint;
        border = color::Ink;
        ink = color::Ink;
        break;
    default:
        fill = color::Green;
        border = color::Gold;
        ink = Qt::white;
        break;
    }
    if (!isEnabled()) {
        fill = QColor(0xC9, 0xC4, 0xB8);
        border = color::Disabled;
        ink = QColor(0xF4, 0xF1, 0xEA);
    } else if (underMouse() && !down) {
        fill = fill.lighter(108);
    }

    if (!down) {
        p.setPen(Qt::NoPen);
        p.setBrush(isEnabled() ? color::Shadow : color::Disabled);
        p.drawRoundedRect(shadow, radius, radius);
    }

    p.setPen(QPen(border, borderWidth));
    p.setBrush(fill);
    p.drawRoundedRect(face, radius, radius);

    if (hasFocus()) {
        QPen focus(ink, 1.0, Qt::DotLine);
        p.setPen(focus);
        p.setBrush(Qt::NoBrush);
        p.drawRoundedRect(face.adjusted(4, 4, -4, -4), radius - 3, radius - 3);
    }

    if (mStyle == Arrow) {
        // Drawn rather than taken from the font, so it stays bold at any size.
        const bool left = text() == QStringLiteral("←");
        const QPointF c = face.center();
        const qreal half = face.width() * 0.27;
        const qreal head = face.width() * 0.2;
        QPen pen(ink, 3.4, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
        p.setPen(pen);
        const QPointF tail(c.x() + (left ? half : -half), c.y());
        const QPointF tip(c.x() + (left ? -half : half), c.y());
        const qreal back = left ? head : -head;
        p.drawLine(tail, tip);
        p.drawLine(tip, QPointF(tip.x() + back, tip.y() - head));
        p.drawLine(tip, QPointF(tip.x() + back, tip.y() + head));
        return;
    }

    p.setPen(ink);
    p.setFont(font());
    p.drawText(face, Qt::AlignCenter, text());
}

QColor LeafColor(qint64 left, qint64 total)
{
    if (total <= 0) return color::Disabled;
    if (left <= 2000) return color::Red;
    qreal used = 1.0 - static_cast<qreal>(left) / static_cast<qreal>(total);
    if (used < 0.0) used = 0.0;
    if (used > 1.0) used = 1.0;
    const QColor a = color::Green;
    const QColor b = QColor(0xD9, 0xA5, 0x20);
    return QColor::fromRgbF(a.redF() + (b.redF() - a.redF()) * used,
                            a.greenF() + (b.greenF() - a.greenF()) * used,
                            a.blueF() + (b.blueF() - a.blueF()) * used);
}

LeafBar::LeafBar(QWidget* parent)
    : QWidget(parent)
    , mLeft(0)
    , mTotal(0)
    , mKnown(false)
{
    setMinimumHeight(24);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
}

QSize LeafBar::sizeHint() const
{
    return QSize(360, 24);
}

void LeafBar::SetLeaves(qint64 left, qint64 total)
{
    mLeft = left;
    mTotal = total;
    mKnown = true;
    update();
}

void LeafBar::Clear()
{
    mKnown = false;
    update();
}

void LeafBar::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const QRectF frame = QRectF(rect()).adjusted(1.5, 2.5, -1.5, -2.5);
    const qreal r = frame.height() / 2.0;

    p.setPen(Qt::NoPen);
    p.setBrush(QColor(0xE4, 0xE0, 0xD4));
    p.drawRoundedRect(frame, r, r);

    if (mKnown && mTotal > 0 && mLeft > 0) {
        qreal fraction = static_cast<qreal>(mLeft) / static_cast<qreal>(mTotal);
        if (fraction > 1.0) fraction = 1.0;
        QRectF fill = frame;
        fill.setWidth(qMax(frame.height(), frame.width() * fraction));
        p.setBrush(LeafColor(mLeft, mTotal));
        p.drawRoundedRect(fill, r, r);
    }

    p.setPen(QPen(color::Ink, 2.0));
    p.setBrush(Qt::NoBrush);
    p.drawRoundedRect(frame, r, r);
}

static QLabel* MakeLabel(const QString& text, const QFont& font,
                         const QColor& ink, QWidget* parent)
{
    QLabel* l = new QLabel(text, parent);
    l->setFont(font);
    QPalette pal = l->palette();
    pal.setColor(QPalette::WindowText, ink);
    l->setPalette(pal);
    return l;
}

ShieldCard::ShieldCard(QWidget* parent)
    : QWidget(parent)
{
    QVBoxLayout* v = new QVBoxLayout(this);
    v->setContentsMargins(26, 22, 34, 34);
    v->setSpacing(8);

    v->addWidget(MakeLabel(QStringLiteral("OTPLEAF SHIELD"),
                           MonoFont(15, true, 3.0), color::Ink, this));
    v->addWidget(MakeLabel(QStringLiteral("Leaves left in your noise file"),
                           MonoFont(13, true, 0.5), color::InkSoft, this));
    v->addSpacing(6);
    mBar = new LeafBar(this);
    v->addWidget(mBar);
    v->addSpacing(8);

    QGridLayout* g = new QGridLayout();
    g->setHorizontalSpacing(40);
    g->setVerticalSpacing(0);
    g->addWidget(MakeLabel(QStringLiteral("Leaves"), MonoFont(13, true, 0.5),
                           color::InkSoft, this), 0, 0);
    g->addWidget(MakeLabel(QStringLiteral("Payments left"),
                           MonoFont(13, true, 0.5), color::InkSoft, this), 0, 1);
    mLeaves = MakeLabel(QStringLiteral("—"), MonoFont(15, true),
                        color::Ink, this);
    mPayments = MakeLabel(QStringLiteral("—"), MonoFont(15, true),
                          color::Ink, this);
    g->addWidget(mLeaves, 1, 0);
    g->addWidget(mPayments, 1, 1);
    g->setColumnStretch(2, 1);
    v->addLayout(g);
}

void ShieldCard::SetLeaves(qint64 left, qint64 total)
{
    mBar->SetLeaves(left, total);
    mLeaves->setText(GroupDigits(left));
    mPayments->setText(GroupDigits(
        left / static_cast<qint64>(::NetParams::NOISE_PROOFS_PER_INPUT_VALUE)));
}

void ShieldCard::Clear()
{
    mBar->Clear();
    mLeaves->setText(QStringLiteral("—"));
    mPayments->setText(QStringLiteral("—"));
}

void ShieldCard::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const qreal sx = 8.0;
    const qreal sy = 8.0;
    const qreal r = 14.0;
    const QRectF face = QRectF(rect()).adjusted(1.5, 1.5, -sx - 1.5, -sy - 1.5);

    p.setPen(Qt::NoPen);
    p.setBrush(color::Ink);
    p.drawRoundedRect(face.translated(sx, sy), r, r);

    QPainterPath path;
    path.addRoundedRect(face, r, r);
    p.fillPath(path, color::Card);
    p.save();
    p.setClipPath(path);
    p.fillRect(QRectF(face.left(), face.bottom() - 14.0, face.width(), 14.0),
               color::CardBand);
    p.restore();

    p.setPen(QPen(color::Ink, 3.0));
    p.setBrush(Qt::NoBrush);
    p.drawPath(path);
}

static const int COIN_SIZE = 144;

CoinLogo::CoinLogo(QWidget* parent)
    : QWidget(parent)
    , mGlow(0.0)
    , mAnim(new QVariantAnimation(this))
{
    // The artwork carries the coin in a wider frame. Only the coin is drawn:
    // its height is the band of rows that are not transparent.
    QImage source(QStringLiteral(":/mi/moneu_1024.png"));
    source = source.convertToFormat(QImage::Format_ARGB32);
    int top = -1;
    int bottom = -1;
    for (int y = 0; y < source.height(); ++y) {
        const QRgb* line = reinterpret_cast<const QRgb*>(source.constScanLine(y));
        bool solid = false;
        for (int x = 0; x < source.width() && !solid; ++x)
            solid = qAlpha(line[x]) > 40;
        if (solid) {
            if (top < 0) top = y;
            bottom = y;
        }
    }
    if (top >= 0 && bottom > top) {
        const int side = bottom - top + 1;
        const int left = (source.width() - side) / 2;
        source = source.copy(left, top, side, side);
    }

    QImage round(source.size(), QImage::Format_ARGB32_Premultiplied);
    round.fill(Qt::transparent);
    {
        QPainter mask(&round);
        mask.setRenderHint(QPainter::Antialiasing);
        QPainterPath circle;
        circle.addEllipse(QRectF(round.rect()));
        mask.setClipPath(circle);
        mask.drawImage(0, 0, source);
    }

    const qreal dpr = devicePixelRatioF();
    const int px = static_cast<int>(std::lround(COIN_SIZE * dpr));
    mCoin = QPixmap::fromImage(round.scaled(px, px, Qt::KeepAspectRatio,
                                            Qt::SmoothTransformation));
    mCoin.setDevicePixelRatio(dpr);

    mAnim->setDuration(3600);
    mAnim->setStartValue(0.0);
    mAnim->setKeyValueAt(0.17, 1.0);
    mAnim->setKeyValueAt(0.33, 0.25);
    mAnim->setKeyValueAt(0.5, 1.0);
    mAnim->setKeyValueAt(0.67, 0.25);
    mAnim->setKeyValueAt(0.83, 1.0);
    mAnim->setEndValue(0.0);
    connect(mAnim, &QVariantAnimation::valueChanged, this,
            [this](const QVariant& v) {
                mGlow = v.toReal();
                update();
            });
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
}

QSize CoinLogo::sizeHint() const
{
    return QSize(236, 218);
}

void CoinLogo::Pulse()
{
    mAnim->stop();
    mAnim->start();
}

void CoinLogo::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.setRenderHint(QPainter::SmoothPixmapTransform);
    const QPointF c = QRectF(rect()).center();
    const qreal coinR = COIN_SIZE / 2.0;

    QRadialGradient gold(c, coinR + 30.0);
    gold.setColorAt(0.0, QColor(0xF6, 0xE7, 0xA8, 190));
    gold.setColorAt(0.72, QColor(0xF3, 0xE4, 0xB0, 120));
    gold.setColorAt(1.0, QColor(0xF1, 0xEC, 0xE0, 0));
    p.setPen(Qt::NoPen);
    p.setBrush(gold);
    p.drawEllipse(c, coinR + 30.0, coinR + 30.0);

    if (mGlow > 0.0) {
        QRadialGradient green(c, coinR + 36.0);
        green.setColorAt(0.0, QColor(0x7F, 0xC0, 0x7A, static_cast<int>(200 * mGlow)));
        green.setColorAt(0.75, QColor(0x5C, 0xAE, 0x5E, static_cast<int>(150 * mGlow)));
        green.setColorAt(1.0, QColor(0x5C, 0xAE, 0x5E, 0));
        p.setBrush(green);
        p.drawEllipse(c, coinR + 36.0, coinR + 36.0);
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(QColor(0x6F, 0xAF, 0x6E, static_cast<int>(255 * mGlow)), 5.0));
        p.drawEllipse(c, coinR + 4.0, coinR + 4.0);
    }

    const QSizeF size = QSizeF(mCoin.size()) / mCoin.devicePixelRatio();
    p.drawPixmap(QPointF(c.x() - size.width() / 2.0, c.y() - size.height() / 2.0),
                 mCoin);
}

DashedLine::DashedLine(QWidget* parent)
    : QWidget(parent)
{
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setFixedHeight(9);
}

QSize DashedLine::sizeHint() const
{
    return QSize(200, 9);
}

void DashedLine::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    QPen pen(color::Dash, 2.0);
    pen.setDashPattern(QVector<qreal>() << 3.0 << 2.5);
    p.setPen(pen);
    const qreal y = height() / 2.0;
    p.drawLine(QPointF(0, y), QPointF(width(), y));
}

NavButton::NavButton(const QString& text, Icon icon, QWidget* parent)
    : QAbstractButton(parent)
    , mIcon(icon)
{
    setText(text);
    setFont(MonoFont(15, true, 0.5));
    setCursor(Qt::PointingHandCursor);
    setFocusPolicy(Qt::TabFocus);
    setAttribute(Qt::WA_Hover);
}

QSize NavButton::sizeHint() const
{
    QFontMetrics fm(font());
    return QSize(qMax(86, fm.horizontalAdvance(text()) + 20), 80);
}

void NavButton::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    QColor ink = isEnabled() ? color::InkSoft : color::Disabled;
    if (isEnabled() && underMouse()) ink = color::Ink;

    const QPointF c(width() / 2.0, 22.0);
    p.setPen(QPen(ink, 2.6));
    p.setBrush(Qt::NoBrush);
    if (mIcon == Globe) {
        const qreal r = 16.0;
        p.drawEllipse(c, r, r);
        p.drawLine(QPointF(c.x() - r, c.y()), QPointF(c.x() + r, c.y()));
        p.drawLine(QPointF(c.x(), c.y() - r), QPointF(c.x(), c.y() + r));
        p.drawEllipse(c, r * 0.45, r);
    } else {
        p.drawEllipse(c, 5.5, 5.5);
        for (int i = 0; i < 8; ++i) {
            const qreal a = i * 3.14159265358979323846 / 4.0;
            const QPointF dir(std::cos(a), std::sin(a));
            p.drawLine(c + dir * 11.0, c + dir * 16.5);
        }
    }

    p.setPen(ink);
    p.setFont(font());
    p.drawText(QRectF(0, 45, width(), height() - 45),
               Qt::AlignHCenter | Qt::AlignTop, text());

    if (hasFocus()) {
        p.setPen(QPen(ink, 1.0, Qt::DotLine));
        p.drawRect(QRectF(rect()).adjusted(1, 1, -1, -1));
    }
}

} // namespace mi
