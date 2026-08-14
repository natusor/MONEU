// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "noise_tree.h"

#include <cstdio>
#include <cstring>
#include <string>

extern "C" {
    #include "../crypto/sha2.h"
}

namespace MONEU {

namespace {

bytes32 Sha256(const uint8_t* data, size_t len) {
    bytes32 out;
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, data, len);
    sha256_Final(&ctx, out.data());
    return out;
}

bytes32 Sha256Pair(const bytes32& a, const bytes32& b) {
    uint8_t buf[64];
    std::memcpy(buf, a.data(), 32);
    std::memcpy(buf + 32, b.data(), 32);
    return Sha256(buf, 64);
}

bytes32 CommitmentAt(const uint8_t* rawNoise, uint32_t i) {
    uint8_t buf[36];
    std::memcpy(buf, rawNoise + static_cast<size_t>(i) * 32, 32);
    buf[32] = static_cast<uint8_t>(i & 0xFF);
    buf[33] = static_cast<uint8_t>((i >> 8) & 0xFF);
    buf[34] = static_cast<uint8_t>((i >> 16) & 0xFF);
    buf[35] = static_cast<uint8_t>((i >> 24) & 0xFF);
    bytes32 leaf = Sha256(buf, 36);
    return Sha256(leaf.data(), 32);
}

std::string LevelPath(const std::string& dir, int level) {
    return dir + "/moneu_noise_level_" + std::to_string(level) + ".tmp";
}

} // namespace

bool NoiseTreeBuilder::ComputeRoot(
    const uint8_t* rawNoise,
    size_t          rawLen,
    uint32_t        leafCount,
    const std::string& scratchDir,
    bytes32&        rootOut)
{
    if (leafCount == 0) {
        rootOut.fill(0);
        return true;
    }
    if (rawLen < static_cast<size_t>(leafCount) * 32) {
        return false;
    }

    std::string path0 = LevelPath(scratchDir, 0);
    {
        FILE* f = std::fopen(path0.c_str(), "wb");
        if (!f) return false;
        for (uint32_t i = 0; i < leafCount; ++i) {
            bytes32 c = CommitmentAt(rawNoise, i);
            if (std::fwrite(c.data(), 1, 32, f) != 32) {
                std::fclose(f);
                std::remove(path0.c_str());
                return false;
            }
        }
        std::fclose(f);
    }

    int      level      = 0;
    uint64_t levelCount = leafCount;

    while (levelCount > 1) {
        std::string inPath  = LevelPath(scratchDir, level);
        std::string outPath = LevelPath(scratchDir, level + 1);

        FILE* in = std::fopen(inPath.c_str(), "rb");
        if (!in) return false;
        FILE* out = std::fopen(outPath.c_str(), "wb");
        if (!out) { std::fclose(in); return false; }

        uint64_t produced = 0;
        bytes32  left, right;
        uint64_t remaining = levelCount;

        while (remaining > 0) {
            if (std::fread(left.data(), 1, 32, in) != 32) {
                std::fclose(in); std::fclose(out);
                std::remove(inPath.c_str()); std::remove(outPath.c_str());
                return false;
            }
            --remaining;

            if (remaining > 0) {
                if (std::fread(right.data(), 1, 32, in) != 32) {
                    std::fclose(in); std::fclose(out);
                    std::remove(inPath.c_str()); std::remove(outPath.c_str());
                    return false;
                }
                --remaining;
            } else {
                right = left;
            }

            bytes32 parent = Sha256Pair(left, right);
            if (std::fwrite(parent.data(), 1, 32, out) != 32) {
                std::fclose(in); std::fclose(out);
                std::remove(inPath.c_str()); std::remove(outPath.c_str());
                return false;
            }
            ++produced;
        }

        std::fclose(in);
        std::fclose(out);
        std::remove(inPath.c_str());

        levelCount = produced;
        ++level;
    }

    std::string rootPath = LevelPath(scratchDir, level);
    FILE* rf = std::fopen(rootPath.c_str(), "rb");
    if (!rf) return false;
    bool ok = (std::fread(rootOut.data(), 1, 32, rf) == 32);
    std::fclose(rf);
    std::remove(rootPath.c_str());
    return ok;
}

} // namespace MONEU
