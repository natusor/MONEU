// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "widgets.h"
#include "miutil.h"

#include "chainparams.h"

#include <QFontMetrics>
#include <QGridLayout>
#include <QHash>
#include <QImage>
#include <QLinearGradient>
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
    speck.setAlpha(26);
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

    // Gold frame along the edge of the whole window.
    const qreal band = qMax<qreal>(4.0, Px(7));
    const QRectF outer = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    QLinearGradient gold(outer.topLeft(), outer.bottomRight());
    gold.setColorAt(0.0, QColor(0xF8, 0xE3, 0x93));
    gold.setColorAt(0.3, QColor(0xD8, 0xB0, 0x45));
    gold.setColorAt(0.5, QColor(0xF3, 0xD7, 0x7A));
    gold.setColorAt(0.75, QColor(0xC2, 0x96, 0x2E));
    gold.setColorAt(1.0, QColor(0xE8, 0xC8, 0x62));
    QPainterPath frame;
    frame.setFillRule(Qt::OddEvenFill);
    frame.addRect(outer);
    frame.addRect(outer.adjusted(band, band, -band, -band));
    p.fillPath(frame, gold);
    p.setBrush(Qt::NoBrush);
    p.setPen(QPen(QColor(0x7A, 0x5A, 0x12), 1.0));
    p.drawRect(outer);
    p.drawRect(outer.adjusted(band, band, -band, -band));
    p.setPen(QPen(QColor(0xFF, 0xF4, 0xC8, 170), 1.0));
    p.drawRect(outer.adjusted(1.5, 1.5, -1.5, -1.5));
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
        return QSize(textWidth + Px(32), Px(38));
    case Arrow:
        return QSize(Px(40), Px(40));
    default:
        return QSize(textWidth + Px(40), Px(46));
    }
}

QSize MiButton::minimumSizeHint() const
{
    return sizeHint();
}

namespace {

struct Metal {
    QColor top;
    QColor mid;
    QColor bottom;
    QColor ink;
};

Metal ButtonMetal(MiButton::Style style)
{
    switch (style) {
    case MiButton::Yellow:
        return {QColor(0xFA, 0xDD, 0x78), QColor(0xE6, 0xB7, 0x3C),
                QColor(0xBB, 0x8A, 0x22), QColor(0x33, 0x24, 0x08)};
    case MiButton::Graphite:
        return {QColor(0x84, 0x8C, 0x93), QColor(0x5A, 0x62, 0x68),
                QColor(0x3E, 0x44, 0x49), QColor(0xFF, 0xFF, 0xFF)};
    case MiButton::Arrow:
        return {QColor(0xF6, 0xF8, 0xF7), QColor(0xD8, 0xE7, 0xE2),
                QColor(0xB3, 0xC7, 0xC1), color::Ink};
    default:
        return {QColor(0x46, 0xCC, 0xBA), QColor(0x14, 0xA3, 0x92),
                QColor(0x0B, 0x76, 0x6A), QColor(0xFF, 0xFF, 0xFF)};
    }
}

} // namespace

void MiButton::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    const bool down = isDown() && isEnabled();
    const qreal drop = qMax<qreal>(2.0, Px(3));
    const qreal radius = (mStyle == Arrow) ? qMax<qreal>(4.0, Px(6)) : qMax<qreal>(6.0, Px(9));
    const qreal rim = qMax<qreal>(2.0, Px(3));

    QRectF frame = QRectF(rect()).adjusted(1.0, 1.0, -1.0, -1.0 - drop);
    if (down) frame.translate(0, drop * 0.7);

    Metal m = ButtonMetal(mStyle);
    if (!isEnabled()) {
        m = {QColor(0x9C, 0xA3, 0xA9), QColor(0x7E, 0x85, 0x8B),
             QColor(0x65, 0x6C, 0x72), QColor(0xE9, 0xEB, 0xED)};
    } else if (underMouse() && !down) {
        m.top = m.top.lighter(106);
        m.mid = m.mid.lighter(108);
        m.bottom = m.bottom.lighter(108);
    }

    if (!down) {
        QColor shade = color::Shadow;
        shade.setAlpha(isEnabled() ? 60 : 30);
        p.setPen(Qt::NoPen);
        p.setBrush(shade);
        p.drawRoundedRect(frame.translated(0, drop), radius, radius);
        shade.setAlpha(isEnabled() ? 35 : 18);
        p.setBrush(shade);
        p.drawRoundedRect(frame.translated(0, drop * 0.5).adjusted(-1, 0, 1, 1),
                          radius, radius);
    }

    // Chrome rim around the face.
    QLinearGradient chrome(frame.topLeft(), frame.bottomLeft());
    chrome.setColorAt(0.0, QColor(0xFD, 0xFD, 0xFD));
    chrome.setColorAt(0.45, QColor(0xC6, 0xCB, 0xCF));
    chrome.setColorAt(0.55, QColor(0x9C, 0xA2, 0xA7));
    chrome.setColorAt(1.0, QColor(0xE4, 0xE7, 0xE9));
    p.setPen(QPen(QColor(0x4E, 0x55, 0x5A, 200), 1.0));
    p.setBrush(chrome);
    p.drawRoundedRect(frame, radius, radius);

    const QRectF face = frame.adjusted(rim, rim, -rim, -rim);
    const qreal faceRadius = qMax<qreal>(2.0, radius - rim);
    QPainterPath facePath;
    facePath.addRoundedRect(face, faceRadius, faceRadius);

    QLinearGradient body(face.topLeft(), face.bottomLeft());
    body.setColorAt(0.0, m.top);
    body.setColorAt(0.5, m.mid);
    body.setColorAt(1.0, m.bottom);
    p.fillPath(facePath, body);

    p.save();
    p.setClipPath(facePath);
    // Fine horizontal lines give the face the look of brushed metal.
    uint32_t seed = 0x9E3779B9u ^ static_cast<uint32_t>(qHash(text()));
    for (qreal y = face.top(); y < face.bottom(); y += 1.0) {
        seed = seed * 1664525u + 1013904223u;
        const int a = static_cast<int>((seed >> 24) % 16u);
        const bool light = (seed >> 8) & 1u;
        p.setPen(QPen(light ? QColor(255, 255, 255, a) : QColor(0, 0, 0, a), 1.0));
        p.drawLine(QPointF(face.left(), y + 0.5), QPointF(face.right(), y + 0.5));
    }
    if (isEnabled()) {
        QLinearGradient gloss(face.topLeft(), QPointF(face.left(), face.center().y()));
        gloss.setColorAt(0.0, QColor(255, 255, 255, down ? 40 : 120));
        gloss.setColorAt(1.0, QColor(255, 255, 255, 0));
        p.fillRect(QRectF(face.left(), face.top(), face.width(), face.height() / 2.0),
                   gloss);
        QLinearGradient base(QPointF(face.left(), face.bottom() - face.height() * 0.3),
                             face.bottomLeft());
        base.setColorAt(0.0, QColor(0, 0, 0, 0));
        base.setColorAt(1.0, QColor(0, 0, 0, down ? 20 : 45));
        p.fillRect(QRectF(face.left(), face.bottom() - face.height() * 0.3,
                          face.width(), face.height() * 0.3), base);
    }
    p.restore();

    p.setPen(QPen(QColor(0, 0, 0, 70), 1.0));
    p.setBrush(Qt::NoBrush);
    p.drawPath(facePath);

    const QColor ink = m.ink;
    if (hasFocus()) {
        QPen focus(ink, 1.0, Qt::DotLine);
        p.setPen(focus);
        p.setBrush(Qt::NoBrush);
        p.drawRoundedRect(face.adjusted(3, 3, -3, -3), faceRadius - 2, faceRadius - 2);
    }

    if (mStyle == Arrow) {
        // Drawn rather than taken from the font, so it stays bold at any size.
        const bool left = text() == QStringLiteral("←");
        const QPointF c = face.center();
        const qreal half = face.width() * 0.27;
        const qreal head = face.width() * 0.2;
        QPen pen(ink, qMax<qreal>(2.4, 3.4 * UiScale()), Qt::SolidLine, Qt::RoundCap,
                 Qt::RoundJoin);
        p.setPen(pen);
        const QPointF tail(c.x() + (left ? half : -half), c.y());
        const QPointF tip(c.x() + (left ? -half : half), c.y());
        const qreal back = left ? head : -head;
        p.drawLine(tail, tip);
        p.drawLine(tip, QPointF(tip.x() + back, tip.y() - head));
        p.drawLine(tip, QPointF(tip.x() + back, tip.y() + head));
        return;
    }

    // Text on whole pixels, so the letters stay sharp.
    p.setFont(font());
    p.setPen(ink);
    p.drawText(face.toAlignedRect(), Qt::AlignCenter, text());
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
    setMinimumHeight(Px(24));
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
}

QSize LeafBar::sizeHint() const
{
    return QSize(Px(360), Px(24));
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
    v->setContentsMargins(Px(26), Px(20), Px(34), Px(30));
    v->setSpacing(Px(8));

    v->addWidget(MakeLabel(QStringLiteral("OTPLEAF SHIELD"),
                           MonoFont(15, true, 3.0), color::Ink, this));
    v->addWidget(MakeLabel(QStringLiteral("Leaves left in your noise file"),
                           MonoFont(13, true, 0.5), color::InkSoft, this));
    v->addSpacing(Px(6));
    mBar = new LeafBar(this);
    v->addWidget(mBar);
    v->addSpacing(Px(8));

    QGridLayout* g = new QGridLayout();
    g->setHorizontalSpacing(Px(40));
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
    const qreal sx = qMax(4, Px(8));
    const qreal sy = qMax(4, Px(8));
    const qreal r = qMax(8, Px(14));
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
    const int px = static_cast<int>(std::lround(Px(COIN_SIZE) * dpr));
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
    return QSize(Px(236), Px(218));
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
    const qreal coinR = Px(COIN_SIZE) / 2.0;
    const qreal glow = Px(30);
    const qreal halo = Px(36);

    QRadialGradient gold(c, coinR + glow);
    gold.setColorAt(0.0, QColor(0xF6, 0xE7, 0xA8, 190));
    gold.setColorAt(0.72, QColor(0xF3, 0xE4, 0xB0, 120));
    gold.setColorAt(1.0, QColor(0xF1, 0xEC, 0xE0, 0));
    p.setPen(Qt::NoPen);
    p.setBrush(gold);
    p.drawEllipse(c, coinR + glow, coinR + glow);

    if (mGlow > 0.0) {
        QRadialGradient green(c, coinR + halo);
        green.setColorAt(0.0, QColor(0x7F, 0xC0, 0x7A, static_cast<int>(200 * mGlow)));
        green.setColorAt(0.75, QColor(0x5C, 0xAE, 0x5E, static_cast<int>(150 * mGlow)));
        green.setColorAt(1.0, QColor(0x5C, 0xAE, 0x5E, 0));
        p.setBrush(green);
        p.drawEllipse(c, coinR + halo, coinR + halo);
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(QColor(0x6F, 0xAF, 0x6E, static_cast<int>(255 * mGlow)),
                      qMax<qreal>(3.0, 5.0 * UiScale())));
        p.drawEllipse(c, coinR + Px(4), coinR + Px(4));
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
    return QSize(qMax(Px(86), fm.horizontalAdvance(text()) + Px(20)), Px(76));
}

void NavButton::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    QColor ink = isEnabled() ? color::InkSoft : color::Disabled;
    if (isEnabled() && underMouse()) ink = color::Ink;

    const qreal k = UiScale();
    const QPointF c(width() / 2.0, 22.0 * k);
    p.setPen(QPen(ink, qMax<qreal>(1.8, 2.6 * k)));
    p.setBrush(Qt::NoBrush);
    if (mIcon == Globe) {
        const qreal r = 16.0 * k;
        p.drawEllipse(c, r, r);
        p.drawLine(QPointF(c.x() - r, c.y()), QPointF(c.x() + r, c.y()));
        p.drawLine(QPointF(c.x(), c.y() - r), QPointF(c.x(), c.y() + r));
        p.drawEllipse(c, r * 0.45, r);
    } else {
        p.drawEllipse(c, 5.5 * k, 5.5 * k);
        for (int i = 0; i < 8; ++i) {
            const qreal a = i * 3.14159265358979323846 / 4.0;
            const QPointF dir(std::cos(a), std::sin(a));
            p.drawLine(c + dir * (11.0 * k), c + dir * (16.5 * k));
        }
    }

    p.setPen(ink);
    p.setFont(font());
    p.drawText(QRect(0, qRound(45.0 * k), width(), height() - qRound(45.0 * k)),
               Qt::AlignHCenter | Qt::AlignTop, text());

    if (hasFocus()) {
        p.setPen(QPen(ink, 1.0, Qt::DotLine));
        p.drawRect(QRectF(rect()).adjusted(1, 1, -1, -1));
    }
}

} // namespace mi
