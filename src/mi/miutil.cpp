// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "miutil.h"

#include "chainparams.h"
#include "primitives/keys.h"
#include "primitives/script.h"
#include "primitives/transaction.h"

extern "C" {
#include "crypto/base58.h"
}

#include <QFileInfo>
#include <QMutex>

#include <cmath>
#include <cstring>
#include <vector>

namespace mi {

// Every text in MI goes through here, so this one factor sets how large
// the whole interface reads.
static const qreal TEXT_SCALE = 1.25;

// Set once at start from the size of the screen, so the whole window fits
// on a small laptop screen the same way it fits on a large one.
static qreal g_uiScale = 1.0;

void SetUiScale(qreal scale)
{
    g_uiScale = qBound<qreal>(0.6, scale, 1.0);
}

qreal UiScale()
{
    return g_uiScale;
}

int Px(qreal size)
{
    return qRound(size * g_uiScale);
}

QFont MonoFont(int pixelSize, bool bold, qreal letterSpacing)
{
    QFont f(QStringLiteral("DejaVu Sans Mono"));
    f.setStyleHint(QFont::TypeWriter);
#if defined(WIN32)
    f.setFamily(QStringLiteral("Consolas"));
#endif
    // Never below 12 pixels, so no text in MI gets too small to read.
    f.setPixelSize(qMax(12, qRound(pixelSize * TEXT_SCALE * g_uiScale)));
    f.setBold(bold);
    f.setHintingPreference(QFont::PreferFullHinting);
    if (letterSpacing != 0.0) {
        // Whole pixels only. A fraction of a pixel between letters blurs them.
        f.setLetterSpacing(QFont::AbsoluteSpacing,
                           qMax<qreal>(1.0, qRound(letterSpacing * TEXT_SCALE * g_uiScale)));
    }
    return f;
}

QString FormatAmount(int64_t units)
{
    const bool negative = units < 0;
    const uint64_t magnitude = negative
        ? (~static_cast<uint64_t>(units) + 1ull)
        : static_cast<uint64_t>(units);
    const uint64_t coin = static_cast<uint64_t>(::NetParams::COIN);
    const uint64_t whole = magnitude / coin;
    const uint64_t frac = magnitude % coin;
    QString out = QString::number(whole) + QLatin1Char('.') +
                  QString::number(frac).rightJustified(8, QLatin1Char('0'));
    if (negative) out.prepend(QLatin1Char('-'));
    return out;
}

QString FormatSignedAmount(int64_t units)
{
    if (units > 0) return QLatin1Char('+') + FormatAmount(units);
    return FormatAmount(units);
}

QString GroupDigits(int64_t value)
{
    const bool negative = value < 0;
    QString digits = QString::number(negative ? -value : value);
    QString out;
    int count = 0;
    for (int i = digits.size() - 1; i >= 0; --i) {
        out.prepend(digits[i]);
        if (++count % 3 == 0 && i > 0) out.prepend(QLatin1Char(' '));
    }
    if (negative) out.prepend(QLatin1Char('-'));
    return out;
}

QString FormatHashRate(double h)
{
    static const char* units[] = {"H/s", "kH/s", "MH/s", "GH/s", "TH/s",
                                  "PH/s", "EH/s"};
    if (!(h > 0.0)) return QStringLiteral("0 H/s");
    int u = 0;
    while (h >= 1000.0 && u < 6) {
        h /= 1000.0;
        ++u;
    }
    return QString::number(h, 'f', 2) + QLatin1Char(' ') +
           QLatin1String(units[u]);
}

QString ShortAddress(const QString& address)
{
    if (address.size() <= 10) return address;
    return address.left(5) + QChar(0x2026) + address.right(3);
}

int64_t CoinsToUnits(double coins)
{
    return static_cast<int64_t>(
        std::llround(coins * static_cast<double>(::NetParams::COIN)));
}

bool ParseAmountText(const std::string& text, int64_t& out, std::string& why)
{
    if (text.empty()) { why = "amount is empty"; return false; }

    const int64_t coin = ::NetParams::COIN;
    const int64_t maxMoney = static_cast<int64_t>(::NetParams::MAX_MONEY);

    size_t i = 0;
    int64_t whole = 0;
    size_t wholeDigits = 0;
    while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
        if (whole > maxMoney / coin) {
            why = "amount out of range";
            return false;
        }
        whole = whole * 10 + (text[i] - '0');
        ++i;
        ++wholeDigits;
    }

    int64_t frac = 0;
    size_t fracDigits = 0;
    if (i < text.size() && text[i] == '.') {
        ++i;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
            if (fracDigits >= 8) {
                why = "amount has more than eight decimal places";
                return false;
            }
            frac = frac * 10 + (text[i] - '0');
            ++i;
            ++fracDigits;
        }
    }

    if (i != text.size()) { why = "amount is not a number"; return false; }
    if (wholeDigits == 0 && fracDigits == 0) {
        why = "amount has no digits";
        return false;
    }

    for (size_t k = fracDigits; k < 8; ++k) frac *= 10;

    if (whole > (maxMoney - frac) / coin) {
        why = "amount out of range";
        return false;
    }
    out = whole * coin + frac;
    return true;
}

static int HexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string AddressFromHashHex(const std::string& hashHex)
{
    if (hashHex.size() != 64) return std::string();
    uint8_t payload[33];
    payload[0] = ::NetParams::PUBKEY_ADDRESS_PREFIX;
    for (size_t i = 0; i < 32; ++i) {
        const int hi = HexValue(hashHex[2 * i]);
        const int lo = HexValue(hashHex[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::string();
        payload[1 + i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    char out[128];
    const int n = base58_encode_check(payload, 33, out, sizeof(out));
    if (n <= 0) return std::string();
    return std::string(out);
}

bool HashHexFromAddress(const std::string& address, std::string& hashHexOut)
{
    uint8_t prefix = 0;
    MONEU::bytes32 hash;
    if (!MONEU::DecodeNoiseAddress(address, prefix, hash)) return false;
    if (prefix != ::NetParams::PUBKEY_ADDRESS_PREFIX) return false;
    static const char* digits = "0123456789abcdef";
    hashHexOut.clear();
    hashHexOut.reserve(64);
    for (size_t i = 0; i < hash.size(); ++i) {
        hashHexOut.push_back(digits[(hash[i] >> 4) & 0xF]);
        hashHexOut.push_back(digits[hash[i] & 0xF]);
    }
    return true;
}

std::string NoiseFilePathText(const std::string& dataDir)
{
    return dataDir + "/wallet" + "/noise.dat";
}

std::string WalletFilePathText(const std::string& dataDir)
{
    return dataDir + "/wallet" + "/wallet.dat";
}

bool FileExists(const std::string& path)
{
    return QFileInfo::exists(QString::fromStdString(path));
}

// Same size rule the node applies in sendtoaddress: the serialized
// transaction plus the noise proofs each input will carry.
int64_t EstimateFeeUnits(int inputs, int outputs, size_t messageBytes)
{
    MONEU::Transaction tx;
    for (int i = 0; i < inputs; ++i) tx.AddInput(MONEU::TxInput());
    for (int o = 0; o < outputs; ++o)
        tx.AddOutput(MONEU::TxOutput(1, MONEU::bytes32()));
    if (messageBytes > 0)
        tx.AddOutput(MONEU::TxOutput(
            0, MONEU::CreateNullData(std::vector<uint8_t>(messageBytes, 0))));

    size_t depth = 0;
    uint32_t leaves = ::NetParams::NOISE_LEAF_COUNT_VALUE;
    while (leaves > 1) {
        leaves >>= 1;
        ++depth;
    }
    const size_t proof = 4 + 32 + 32 + 4 + depth * 32 + depth;
    const size_t perInput = 4 + proof * ::NetParams::NOISE_PROOFS_PER_INPUT;
    const int64_t size = static_cast<int64_t>(
        tx.GetSerializedSize(true) + static_cast<size_t>(inputs) * perInput);
    const int64_t perByte = size * ::NetParams::MIN_FEE_PER_BYTE;
    return perByte > ::NetParams::MIN_TX_FEE ? perByte : ::NetParams::MIN_TX_FEE;
}

QMutex& MinerCallLock()
{
    static QMutex lock;
    return lock;
}

} // namespace mi
