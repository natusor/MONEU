// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "noisejob.h"

#include "chainparams.h"
#include "primitives/keys.h"
#include "wallet/noise_generator.h"
#include "wallet/noise_store.h"
#include "wallet/noise_tree.h"

#include <sys/stat.h>
#ifdef WIN32
#include <direct.h>
#endif

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <vector>

namespace mi {

static const size_t   NOISE_FILE_BYTES = ::NetParams::NOISE_FILE_BYTES;
static const uint32_t NOISE_LEAF_COUNT = ::NetParams::NOISE_LEAF_COUNT_VALUE;

static std::string ToHex(const MONEU::bytes32& b)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (size_t i = 0; i < b.size(); ++i) {
        out.push_back(hex[(b[i] >> 4) & 0xF]);
        out.push_back(hex[b[i] & 0xF]);
    }
    return out;
}

static bool EnsureDir(const std::string& path)
{
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return (st.st_mode & S_IFDIR) != 0;
    }
#ifdef WIN32
    return _mkdir(path.c_str()) == 0;
#else
    return mkdir(path.c_str(), 0700) == 0;
#endif
}

static bool PathExists(const std::string& path)
{
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

NoiseJob::NoiseJob(const std::string& dataDir)
    : mDataDir(dataDir)
{
}

void NoiseJob::Run(const QString& passphraseText)
{
    std::string passphrase = passphraseText.toStdString();
    auto finish = [&](bool ok, const std::string& text) {
        std::fill(passphrase.begin(), passphrase.end(), '\0');
        passphrase.clear();
        Q_EMIT Finished(ok, QString::fromStdString(text));
    };

    if (passphrase.size() < 8) {
        finish(false, "error: passphrase must be at least 8 characters");
        return;
    }

    const std::string dataDir = mDataDir;
    if (dataDir.empty()) {
        finish(false, "error: cannot determine data directory");
        return;
    }
    if (!EnsureDir(dataDir)) {
        finish(false, "error: cannot create " + dataDir);
        return;
    }
    const std::string walletDir = dataDir + "/wallet";
    if (!EnsureDir(walletDir)) {
        finish(false, "error: cannot create " + walletDir);
        return;
    }
    const std::string noisePath = walletDir + "/noise.dat";
    if (PathExists(noisePath)) {
        finish(false, "error: a noise file already exists: " + noisePath + "\n"
                      "The addresses of this wallet are bound to it. "
                      "A new noise file belongs to a new wallet only.");
        return;
    }

    {
        std::string why;
        if (!MONEU::NoiseGenerator::CheckTimingSources(why)) {
            finish(false, "makenoise: refusing to generate - " + why);
            return;
        }
    }

    MONEU::NoiseGenerator::ProgressFn progress =
        [this](size_t produced, size_t target) {
            Q_EMIT Progress(static_cast<qint64>(produced),
                            static_cast<qint64>(target));
        };

    std::vector<uint8_t> noise =
        MONEU::NoiseGenerator::Generate(NOISE_FILE_BYTES, 0, progress);
    if (noise.size() != NOISE_FILE_BYTES) {
        std::fill(noise.begin(), noise.end(), 0);
        finish(false, "error: noise generation produced wrong size");
        return;
    }

    MONEU::bytes32 kps;
    if (!MONEU::NoiseTreeBuilder::ComputeRoot(
            noise.data(), noise.size(), NOISE_LEAF_COUNT, walletDir, kps)) {
        std::fill(noise.begin(), noise.end(), 0);
        finish(false, "error: failed to compute KPS");
        return;
    }

    if (PathExists(noisePath)) {
        std::fill(noise.begin(), noise.end(), 0);
        finish(false, "error: a noise file was created meanwhile: " +
                      noisePath + "\nIt is kept. This run is discarded.");
        return;
    }

    const bool written =
        MONEU::NoiseStore::EncryptToFile(noise, passphrase, noisePath);
    std::fill(noise.begin(), noise.end(), 0);
    if (!written) {
        finish(false, "error: failed to write noise file");
        return;
    }

    const double mbps =
        MONEU::NoiseGenerator::LastBytesPerSecond() / (1024.0 * 1024.0);

    std::ostringstream out;
    out << "Done. Noise shield (OTP file) created.\n"
        << "  KPS (public key of noise): " << ToHex(kps) << "\n"
        << "  File: " << noisePath << "\n"
        << "  Size: " << (NOISE_FILE_BYTES / (1024 * 1024)) << " MB"
        << "  (" << NOISE_LEAF_COUNT << " leaves)\n";
    out.setf(std::ios::fixed);
    out.precision(2);
    out << "  Rate: " << mbps << " MB/s\n\n"
        << "Wait 10 seconds before creating addresses for this wallet.\n"
        << "Copy the noise file to TWO separate drives - it is "
           "REQUIRED to sign transactions.\n"
        << "Lose it and you lose access to funds, even with your seed.";
    finish(true, out.str());
}

} // namespace mi
