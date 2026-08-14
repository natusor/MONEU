// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "noise_generator.h"
#include <set>
#include <string>

#include <atomic>
#include <thread>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/time.h>

#ifdef __x86_64__
#include <x86intrin.h>
#endif

extern "C" {
    #include "../crypto/sha2.h"
}

namespace MONEU {

namespace {

double gLastBytesPerSecond = 0.0;

inline uint64_t ReadCycleCounter() {
#ifdef __x86_64__
    return static_cast<uint64_t>(__rdtsc());
#else
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::high_resolution_clock::now()
                .time_since_epoch()).count());
#endif
}

inline void AppendU64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

void HarvestCPUJitter(std::vector<uint8_t>& buf, unsigned samples,
                      uint64_t& mixState) {
    for (unsigned i = 0; i < samples; ++i) {
        uint64_t start = ReadCycleCounter();
        volatile uint64_t acc = mixState;
        for (int j = 0; j < 32; ++j) {
            acc += (acc << 3) ^ (acc >> 1) ^ static_cast<uint64_t>(j);
        }
        uint64_t end = ReadCycleCounter();
        uint64_t delta = end - start;
        mixState += delta ^ static_cast<uint64_t>(acc);
        AppendU64(buf, delta);
    }
}

void HarvestMemoryTiming(std::vector<uint8_t>& buf, unsigned samples,
                         std::vector<uint8_t>& work, uint64_t& mixState) {
    if (work.empty()) return;
    const size_t mask = work.size() - 1;
    for (unsigned i = 0; i < samples; ++i) {
        size_t idx = static_cast<size_t>(mixState) & mask;
        uint64_t start = ReadCycleCounter();
        volatile uint8_t v = work[idx];
        work[idx] = static_cast<uint8_t>(v + 1 + (i & 0xFF));
        uint64_t end = ReadCycleCounter();
        uint64_t delta = end - start;
        mixState = (mixState * 6364136223846793005ULL)
                   + delta + idx + 1;
        AppendU64(buf, delta);
    }
}

void HarvestThermal(std::vector<uint8_t>& buf) {
    std::ifstream f("/sys/class/thermal/thermal_zone0/temp");
    if (f.is_open()) {
        uint64_t temp = 0;
        f >> temp;
        AppendU64(buf, temp);
    }
}

void HarvestProcCounters(std::vector<uint8_t>& buf) {
    {
        std::ifstream f("/proc/diskstats");
        std::string line;
        for (int i = 0; i < 4 && std::getline(f, line); ++i) {
            for (char c : line) buf.push_back(static_cast<uint8_t>(c));
        }
    }
    {
        std::ifstream f("/proc/net/dev");
        std::string line;
        for (int i = 0; i < 6 && std::getline(f, line); ++i) {
            for (char c : line) buf.push_back(static_cast<uint8_t>(c));
        }
    }
}

void HarvestKernelMix(std::vector<uint8_t>& buf) {
    std::ifstream f("/dev/urandom", std::ios::binary);
    if (f.is_open()) {
        uint8_t tmp[32];
        f.read(reinterpret_cast<char*>(tmp), sizeof(tmp));
        std::streamsize got = f.gcount();
        for (std::streamsize i = 0; i < got; ++i) {
            buf.push_back(tmp[static_cast<size_t>(i)]);
        }
    }
}

} // namespace

bool NoiseGenerator::CheckTimingSources(std::string& reasonOut) {
    const uint64_t first = ReadCycleCounter();
    for (volatile int spin = 0; spin < 100000; ++spin) { }
    const uint64_t second = ReadCycleCounter();
    if (second == first) {
        reasonOut = "the CPU cycle counter does not advance; timing "
                    "entropy would be worthless on this machine";
        return false;
    }

    unsigned distinct = 0;
    uint64_t prev = ReadCycleCounter();
    for (unsigned i = 0; i < 1000; ++i) {
        const uint64_t now = ReadCycleCounter();
        if (now != prev) distinct++;
        prev = now;
    }
    if (distinct < 100) {
        reasonOut = "the CPU cycle counter is too coarse: only " +
                    std::to_string(distinct) +
                    " of 1000 consecutive reads differed";
        return false;
    }

    uint64_t mixState = ReadCycleCounter();
    std::vector<uint8_t> probe;
    HarvestCPUJitter(probe, 256, mixState);
    std::set<uint64_t> seen;
    for (size_t i = 0; i + 8 <= probe.size(); i += 8) {
        uint64_t v = 0;
        for (int b = 7; b >= 0; --b) {
            v = (v << 8) | static_cast<uint64_t>(probe[i + b]);
        }
        seen.insert(v);
    }
    if (seen.size() < 8) {
        reasonOut = "timing measurements barely vary: only " +
                    std::to_string(seen.size()) +
                    " distinct values in 256 samples";
        return false;
    }

    return true;
}

std::vector<uint8_t> NoiseGenerator::Generate(
    size_t      targetBytes,
    unsigned    stressThreads,
    ProgressFn  progress)
{
    std::vector<uint8_t> out;
    if (targetBytes == 0) return out;
    out.reserve(targetBytes);

    if (stressThreads == 0) {
        unsigned hw = std::thread::hardware_concurrency();
        if (hw <= 2) {
            stressThreads = 1;
        } else {
            stressThreads = hw / 2;
        }
    }

    std::atomic<bool> stop(false);
    std::vector<std::thread> workers;
    workers.reserve(stressThreads);
    for (unsigned t = 0; t < stressThreads; ++t) {
        workers.emplace_back([&stop, t]() {
            std::vector<uint8_t> scratch(1u << 16,
                                         static_cast<uint8_t>(t + 1));
            uint64_t x = 0x9E3779B97F4A7C15ULL + t;
            const size_t mask = scratch.size() - 1;
            while (!stop.load(std::memory_order_relaxed)) {
                for (int k = 0; k < 4096; ++k) {
                    x += (x << 7) ^ (x >> 3) ^ static_cast<uint64_t>(k);
                    size_t idx = static_cast<size_t>(x) & mask;
                    scratch[idx] = static_cast<uint8_t>(
                        scratch[idx] + static_cast<uint8_t>(x));
                }
            }
            volatile uint8_t sink = scratch[static_cast<size_t>(x) & mask];
            (void)sink;
        });
    }

    std::vector<uint8_t> memWork(MEM_BUFFER_BYTES, 0);

    uint64_t mixState = ReadCycleCounter();
    uint64_t blockCounter = 0;

    auto startTime = std::chrono::steady_clock::now();
    size_t lastReported = 0;

    std::vector<uint8_t> slowSnapshot;

    while (out.size() < targetBytes) {
        if ((blockCounter % SLOW_REFRESH_BLOCKS) == 0) {
            slowSnapshot.clear();
            HarvestThermal(slowSnapshot);
            HarvestProcCounters(slowSnapshot);
            HarvestKernelMix(slowSnapshot);
        }

        std::vector<uint8_t> batch;
        batch.reserve(
            (CPU_SAMPLES_PER_BLOCK + MEM_SAMPLES_PER_BLOCK) * 8
            + slowSnapshot.size() + 32);

        AppendU64(batch, mixState);
        AppendU64(batch, blockCounter);
        AppendU64(batch, ReadCycleCounter());

        HarvestCPUJitter(batch, CPU_SAMPLES_PER_BLOCK, mixState);
        HarvestMemoryTiming(batch, MEM_SAMPLES_PER_BLOCK, memWork, mixState);

        batch.insert(batch.end(), slowSnapshot.begin(), slowSnapshot.end());

        uint8_t block[SHA512_DIGEST_LENGTH];
        sha512_Raw(batch.data(), batch.size(), block);

        size_t remaining = targetBytes - out.size();
        size_t take = (remaining < CONDITION_BLOCK)
                      ? remaining : CONDITION_BLOCK;
        out.insert(out.end(), block, block + take);

        uint64_t carry = 0;
        std::memcpy(&carry, block, sizeof(carry));
        mixState ^= carry;
        ++blockCounter;

        if (progress && (out.size() - lastReported) >= (1u << 20)) {
            progress(out.size(), targetBytes);
            lastReported = out.size();
        }
    }

    stop.store(true, std::memory_order_relaxed);
    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    auto endTime = std::chrono::steady_clock::now();
    double secs = std::chrono::duration_cast<std::chrono::duration<double>>(
        endTime - startTime).count();
    gLastBytesPerSecond = (secs > 0.0)
        ? static_cast<double>(out.size()) / secs : 0.0;

    if (progress) progress(out.size(), targetBytes);
    return out;
}

double NoiseGenerator::LastBytesPerSecond() {
    return gLastBytesPerSecond;
}

} // namespace MONEU
