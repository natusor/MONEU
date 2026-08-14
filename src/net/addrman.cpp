// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addrman.h"
#include "../util/lockorder.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstdio>

extern "C" {
#include "../crypto/sha2.h"
}
#include "../log/log.h"

extern "C" {
#include "../crypto/rand.h"
}

#include <algorithm>
#include <fstream>
#include <sstream>

namespace MONEU {
namespace net {

namespace {

uint64_t Mix(uint64_t seed, const std::string& s) {
    uint8_t seedBytes[8];
    for (int i = 0; i < 8; ++i) {
        seedBytes[i] = static_cast<uint8_t>((seed >> (i * 8)) & 0xFF);
    }
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, seedBytes, sizeof(seedBytes));
    sha256_Update(&ctx,
                  reinterpret_cast<const uint8_t*>(s.data()),
                  s.size());
    uint8_t digest[32];
    sha256_Final(&ctx, digest);
    uint64_t out = 0;
    for (int i = 0; i < 8; ++i) {
        out |= static_cast<uint64_t>(digest[i]) << (i * 8);
    }
    return out;
}

uint64_t MixValue(uint64_t seed, uint64_t v) {
    uint8_t raw[8];
    for (int i = 0; i < 8; ++i) {
        raw[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
    }
    return Mix(seed, std::string(reinterpret_cast<const char*>(raw), 8));
}

}

std::string AddrEntry::Key() const {
    std::ostringstream ss;
    ss << ip << ":" << port;
    return ss.str();
}

double AddrEntry::Chance(int64_t now) const {
    double chance = 1.0;

    const int64_t sinceTry = (now > lastTry) ? (now - lastTry) : 0;
    if (lastTry != 0 && sinceTry < 10 * 60) {
        chance *= 0.01;
    }

    int penalised = attempts;
    if (penalised < 0) penalised = 0;
    if (penalised > 8) penalised = 8;
    for (int i = 0; i < penalised; ++i) {
        chance *= 0.66;
    }

    return chance;
}

bool AddrEntry::IsTerrible(int64_t now) const {
    if (lastTry != 0 && lastTry >= now - 60) return false;

    if (lastSeen > now + 10 * 60) return true;

    if (lastSeen == 0 ||
        now - lastSeen > AddrMan::HORIZON_DAYS * 24 * 60 * 60) {
        return true;
    }

    if (lastSuccess == 0 && attempts >= AddrMan::RETRIES) return true;

    if (now - lastSuccess > AddrMan::MIN_FAIL_DAYS * 24 * 60 * 60 &&
        attempts >= AddrMan::MAX_FAILURES) {
        return true;
    }

    return false;
}

AddrMan::AddrMan()
    : mKey(0)
{
    random_buffer(reinterpret_cast<uint8_t*>(&mKey), sizeof(mKey));

    mNew.resize(NEW_BUCKET_COUNT);
    mTried.resize(TRIED_BUCKET_COUNT);
}

std::string AddrMan::GroupOf(const std::string& ip) {
    unsigned char v4[4];
    if (inet_pton(AF_INET, ip.c_str(), v4) == 1) {
        char out[16];
        std::snprintf(out, sizeof(out), "4:%u.%u",
                      static_cast<unsigned>(v4[0]),
                      static_cast<unsigned>(v4[1]));
        return std::string(out);
    }

    unsigned char v6[16];
    if (inet_pton(AF_INET6, ip.c_str(), v6) == 1) {
        static const char* hexDigits = "0123456789abcdef";
        std::string out("6:");
        out.reserve(2 + 16);
        for (int i = 0; i < 8; ++i) {
            out.push_back(hexDigits[(v6[i] >> 4) & 0x0F]);
            out.push_back(hexDigits[v6[i] & 0x0F]);
        }
        return out;
    }

    return "?:" + ip;
}

size_t AddrMan::NewBucketFor(const AddrEntry& e) const {
    const std::string addrGroup   = GroupOf(e.ip);
    const std::string sourceGroup = GroupOf(e.source);

    const uint64_t h1 = Mix(Mix(mKey, addrGroup), sourceGroup);
    const uint64_t h2 = MixValue(Mix(mKey, sourceGroup),
                                 h1 % NEW_BUCKETS_PER_SOURCE_GROUP);
    return h2 % NEW_BUCKET_COUNT;
}

size_t AddrMan::TriedBucketFor(const AddrEntry& e) const {
    const uint64_t h1 = Mix(mKey, e.Key());
    const uint64_t h2 = MixValue(Mix(mKey, GroupOf(e.ip)),
                                 h1 % TRIED_BUCKETS_PER_GROUP);
    return h2 % TRIED_BUCKET_COUNT;
}

size_t AddrMan::PositionIn(size_t bucket, const std::string& key) const {
    return MixValue(Mix(mKey, key), static_cast<uint64_t>(bucket))
           % BUCKET_SIZE;
}

bool AddrMan::IsInTried(const std::string& key) const {
    for (size_t b = 0; b < mTried.size(); ++b) {
        for (size_t i = 0; i < mTried[b].size(); ++i) {
            if (mTried[b][i] == key) return true;
        }
    }
    return false;
}

bool AddrMan::AddLocked(const AddrEntry& e, int64_t now) {
    const std::string key = e.Key();

    auto existing = mEntries.find(key);
    if (existing != mEntries.end()) {
        if (e.lastSeen > existing->second.lastSeen) {
            existing->second.lastSeen = e.lastSeen;
        }
        if (e.services != 0) existing->second.services = e.services;
        return false;
    }

    mEntries[key] = e;

    const size_t bucket = NewBucketFor(e);
    const size_t pos    = PositionIn(bucket, key);

    if (mNew[bucket].size() <= pos) mNew[bucket].resize(pos + 1);

    const std::string displaced = mNew[bucket][pos];
    if (!displaced.empty() && displaced != key) {
        auto it = mEntries.find(displaced);
        if (it != mEntries.end() && !it->second.IsTerrible(now)) {
            mEntries.erase(key);
            return false;
        }
        if (it != mEntries.end() && !IsInTried(displaced)) {
            mEntries.erase(displaced);
        }
    }
    mNew[bucket][pos] = key;
    return true;
}

bool AddrMan::Add(const std::string& ip, uint16_t port, uint32_t services,
                  const std::string& source, int64_t now) {
    if (ip.empty() || port == 0) return false;

    AddrEntry e;
    e.ip       = ip;
    e.port     = port;
    e.services = services;
    e.lastSeen = now;
    e.source   = source.empty() ? ip : source;

    MONEU_LOCK(mMutex);
    return AddLocked(e, now);
}

void AddrMan::Attempt(const std::string& ip, uint16_t port, int64_t now) {
    AddrEntry probe;
    probe.ip = ip;
    probe.port = port;

    MONEU_LOCK(mMutex);
    auto it = mEntries.find(probe.Key());
    if (it == mEntries.end()) return;
    it->second.lastTry = now;
    it->second.attempts++;
}

void AddrMan::Good(const std::string& ip, uint16_t port, int64_t now) {
    AddrEntry probe;
    probe.ip = ip;
    probe.port = port;
    const std::string key = probe.Key();

    MONEU_LOCK(mMutex);
    auto it = mEntries.find(key);
    if (it == mEntries.end()) return;

    it->second.lastSuccess = now;
    it->second.lastSeen    = now;
    it->second.attempts    = 0;

    if (IsInTried(key)) return;

    const size_t bucket = TriedBucketFor(it->second);
    const size_t pos    = PositionIn(bucket, key);
    if (mTried[bucket].size() <= pos) mTried[bucket].resize(pos + 1);

    const std::string displaced = mTried[bucket][pos];
    mTried[bucket][pos] = key;

    for (size_t b = 0; b < mNew.size(); ++b) {
        for (size_t i = 0; i < mNew[b].size(); ++i) {
            if (mNew[b][i] == key) mNew[b][i].clear();
        }
    }

    if (!displaced.empty() && displaced != key) {
        auto d = mEntries.find(displaced);
        if (d != mEntries.end()) {
            const size_t nb = NewBucketFor(d->second);
            const size_t np = PositionIn(nb, displaced);
            if (mNew[nb].size() <= np) mNew[nb].resize(np + 1);
            if (mNew[nb][np].empty()) mNew[nb][np] = displaced;
            else mEntries.erase(displaced);
        }
    }
}

bool AddrMan::Select(std::string& ipOut, uint16_t& portOut,
                     int64_t now) const {
    MONEU_LOCK(mMutex);
    if (mEntries.empty()) return false;

    uint64_t r = 0;
    random_buffer(reinterpret_cast<uint8_t*>(&r), sizeof(r));

    size_t triedTotal = 0;
    for (size_t b = 0; b < mTried.size(); ++b) {
        for (size_t i = 0; i < mTried[b].size(); ++i) {
            if (!mTried[b][i].empty()) triedTotal++;
        }
    }

    const bool preferTried = triedTotal > 0 && (r % 100) < 66;

    const int kWeightedRounds = 64;

    for (int round = 0; round < kWeightedRounds + 1; ++round) {
        const bool lastResort = (round == kWeightedRounds);

        uint64_t draw = 0;
        random_buffer(reinterpret_cast<uint8_t*>(&draw), sizeof(draw));
        uint64_t spin = 0;

        for (int pass = 0; pass < 2; ++pass) {
            const bool useTried = (pass == 0) ? preferTried : !preferTried;
            const std::vector<std::vector<std::string> >& table =
                useTried ? mTried : mNew;
            if (table.empty()) continue;

            const size_t startBucket = (draw >> 8) % table.size();
            for (size_t n = 0; n < table.size(); ++n) {
                const size_t b = (startBucket + n) % table.size();
                if (table[b].empty()) continue;
                const size_t startPos = (draw >> 24) % table[b].size();
                for (size_t m = 0; m < table[b].size(); ++m) {
                    const size_t p = (startPos + m) % table[b].size();
                    const std::string& key = table[b][p];
                    if (key.empty()) continue;
                    std::map<std::string, AddrEntry>::const_iterator it =
                        mEntries.find(key);
                    if (it == mEntries.end()) continue;
                    if (it->second.IsTerrible(now)) continue;

                    if (!lastResort) {
                        ++spin;
                        uint64_t coin = draw ^ (spin * 0x9E3779B97F4A7C15ULL);
                        coin ^= coin >> 33;
                        coin *= 0xFF51AFD7ED558CCDULL;
                        coin ^= coin >> 33;
                        const double roll =
                            static_cast<double>(coin >> 11) /
                            static_cast<double>(1ULL << 53);
                        if (roll >= it->second.Chance(now)) continue;
                    }

                    ipOut   = it->second.ip;
                    portOut = it->second.port;
                    return true;
                }
            }
        }
    }
    return false;
}

std::vector<AddrEntry> AddrMan::GetAddresses(size_t max, int64_t now) const {
    MONEU_LOCK(mMutex);
    std::vector<AddrEntry> out;
    out.reserve(mEntries.size() < max ? mEntries.size() : max);

    for (const auto& entry : mEntries) {
        if (entry.second.IsTerrible(now)) continue;
        out.push_back(entry.second);
    }

    std::sort(out.begin(), out.end(),
              [](const AddrEntry& a, const AddrEntry& b) {
                  return a.lastSeen > b.lastSeen;
              });
    if (out.size() > max) out.resize(max);
    return out;
}

size_t AddrMan::Size() const {
    MONEU_LOCK(mMutex);
    return mEntries.size();
}

size_t AddrMan::TriedCount() const {
    MONEU_LOCK(mMutex);
    size_t n = 0;
    for (size_t b = 0; b < mTried.size(); ++b) {
        for (size_t i = 0; i < mTried[b].size(); ++i) {
            if (!mTried[b][i].empty()) n++;
        }
    }
    return n;
}

size_t AddrMan::NewCount() const {
    MONEU_LOCK(mMutex);
    size_t n = 0;
    for (size_t b = 0; b < mNew.size(); ++b) {
        for (size_t i = 0; i < mNew[b].size(); ++i) {
            if (!mNew[b][i].empty()) n++;
        }
    }
    return n;
}

void AddrMan::RemoveLocked(const std::string& key) {
    mEntries.erase(key);
    for (size_t b = 0; b < mNew.size(); ++b) {
        for (size_t i = 0; i < mNew[b].size(); ++i) {
            if (mNew[b][i] == key) mNew[b][i].clear();
        }
    }
    for (size_t b = 0; b < mTried.size(); ++b) {
        for (size_t i = 0; i < mTried[b].size(); ++i) {
            if (mTried[b][i] == key) mTried[b][i].clear();
        }
    }
}

size_t AddrMan::Sweep(int64_t now) {
    MONEU_LOCK(mMutex);
    size_t stale = 0;
    for (std::map<std::string, AddrEntry>::const_iterator it =
             mEntries.begin(); it != mEntries.end(); ++it) {
        if (it->second.IsTerrible(now)) ++stale;
    }
    return stale;
}

bool AddrMan::Save(const std::string& path) const {
    MONEU_LOCK(mMutex);
    std::ofstream f(path.c_str(), std::ios::trunc);
    if (!f.is_open()) return false;

    for (const auto& entry : mEntries) {
        const AddrEntry& e = entry.second;
        f << e.ip << ' ' << e.port << ' ' << e.services << ' '
          << e.lastSeen << ' ' << e.lastTry << ' ' << e.lastSuccess << ' '
          << e.attempts << ' ' << (e.source.empty() ? e.ip : e.source)
          << '\n';
    }
    return true;
}

bool AddrMan::Load(const std::string& path) {
    std::ifstream f(path.c_str());
    if (!f.is_open()) return false;

    std::vector<AddrEntry> loaded;
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        AddrEntry e;
        uint32_t port = 0;
        if (!(ss >> e.ip >> port >> e.services >> e.lastSeen
                 >> e.lastTry >> e.lastSuccess >> e.attempts >> e.source)) {
            continue;
        }
        if (port == 0 || port > 65535) continue;
        e.port = static_cast<uint16_t>(port);
        loaded.push_back(e);
    }

    const int64_t now = static_cast<int64_t>(std::time(NULL));
    MONEU_LOCK(mMutex);
    for (size_t i = 0; i < loaded.size(); ++i) {
        if (loaded[i].IsTerrible(now)) continue;
        const bool wasTried = loaded[i].lastSuccess != 0;
        AddLocked(loaded[i], now);
        if (wasTried) {
            const std::string key = loaded[i].Key();
            auto it = mEntries.find(key);
            if (it == mEntries.end()) continue;
            const size_t b = TriedBucketFor(it->second);
            const size_t p = PositionIn(b, key);
            if (mTried[b].size() <= p) mTried[b].resize(p + 1);
            if (mTried[b][p].empty()) mTried[b][p] = key;
        }
    }
    return true;
}

} // namespace net
} // namespace MONEU
