// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_MI_MIUTIL_H
#define MONEU_MI_MIUTIL_H

#include <QColor>
#include <QFont>
#include <QString>

#include <cstddef>
#include <cstdint>
#include <string>

class QMutex;

namespace mi {

namespace color {
static const QColor Paper(0xFB, 0xFA, 0xF6);
static const QColor PaperSpeck(0xB8, 0xB0, 0x9C);
static const QColor Card(0xFF, 0xFF, 0xFF);
static const QColor CardBand(0xEC, 0xEF, 0xEB);
static const QColor Ink(0x1C, 0x1C, 0x14);
static const QColor InkSoft(0x2A, 0x27, 0x20);
static const QColor Title(0xB4, 0x5A, 0x14);
static const QColor Unit(0xB0, 0x5E, 0x22);
static const QColor Green(0x1E, 0x78, 0x36);
static const QColor GreenText(0x2F, 0x6A, 0x3A);
static const QColor Gold(0xC9, 0xA6, 0x33);
static const QColor Yellow(0xE6, 0xC6, 0x45);
static const QColor Mint(0xCF, 0xE6, 0xD5);
static const QColor Shadow(0x1F, 0x1A, 0x0C);
static const QColor Dash(0xD6, 0xD0, 0xC0);
static const QColor Red(0xB3, 0x26, 0x1E);
static const QColor Disabled(0x9A, 0x95, 0x8A);
}

// Size of the main window at full scale.
static const int MI_FULL_WIDTH = 1480;
static const int MI_FULL_HEIGHT = 820;

void SetUiScale(qreal scale);
qreal UiScale();
int Px(qreal size);

QFont MonoFont(int pixelSize, bool bold = false, qreal letterSpacing = 0.0);

QString FormatAmount(int64_t units);
QString FormatSignedAmount(int64_t units);
QString GroupDigits(int64_t value);
QString FormatHashRate(double hashesPerSecond);
QString ShortAddress(const QString& address);

int64_t CoinsToUnits(double coins);
int64_t EstimateFeeUnits(int inputs, int outputs, size_t messageBytes);
bool ParseAmountText(const std::string& text, int64_t& out, std::string& why);

std::string AddressFromHashHex(const std::string& hashHex);
bool HashHexFromAddress(const std::string& address, std::string& hashHexOut);

std::string NoiseFilePathText(const std::string& dataDir);
std::string WalletFilePathText(const std::string& dataDir);
bool FileExists(const std::string& path);

QMutex& MinerCallLock();

} // namespace mi

#endif // MONEU_MI_MIUTIL_H
