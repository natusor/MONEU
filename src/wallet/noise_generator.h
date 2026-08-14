// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_WALLET_NOISE_GENERATOR_H
#define MONEU_WALLET_NOISE_GENERATOR_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <functional>

namespace MONEU {

class NoiseGenerator {
public:
    using ProgressFn = std::function<void(size_t produced, size_t target)>;

    static bool CheckTimingSources(std::string& reasonOut);

    static std::vector<uint8_t> Generate(
        size_t      targetBytes,
        unsigned    stressThreads = 0,
        ProgressFn  progress      = nullptr);

    static double LastBytesPerSecond();

private:
    static const size_t   CONDITION_BLOCK = 64;

    static const unsigned CPU_SAMPLES_PER_BLOCK = 128;

    static const unsigned MEM_SAMPLES_PER_BLOCK = 64;

    static const unsigned SLOW_REFRESH_BLOCKS = 1024;

    static const size_t   MEM_BUFFER_BYTES = 1u << 20;
};

} // namespace MONEU

#endif // MONEU_WALLET_NOISE_GENERATOR_H
