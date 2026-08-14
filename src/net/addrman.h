// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MONEU_NET_ADDRMAN_H
#define MONEU_NET_ADDRMAN_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <mutex>

namespace MONEU {
namespace net {

struct AddrEntry {
    std::string ip;
    uint16_t    port;
    uint32_t    services;

    int64_t     lastSeen;
    int64_t     lastTry;
    int64_t     lastSuccess;
    int32_t     attempts;

    std::string source;

    AddrEntry()
        : port(0)
        , services(0)
        , lastSeen(0)
        , lastTry(0)
        , lastSuccess(0)
        , attempts(0)
    {}

    std::string Key() const;
    bool IsTerrible(int64_t now) const;

    double Chance(int64_t now) const;
};

class AddrMan {
public:
    static const size_t NEW_BUCKET_COUNT   = 1024;
    static const size_t TRIED_BUCKET_COUNT = 256;
    static const size_t BUCKET_SIZE        = 64;

    static const size_t NEW_BUCKETS_PER_SOURCE_GROUP = 64;
    static const size_t TRIED_BUCKETS_PER_GROUP      = 8;

    static const int64_t HORIZON_DAYS   = 30;
    static const int32_t RETRIES        = 3;
    static const int32_t MAX_FAILURES   = 10;
    static const int64_t MIN_FAIL_DAYS  = 7;

    AddrMan();

    bool Add(const std::string& ip, uint16_t port, uint32_t services,
             const std::string& source, int64_t now);

    void Attempt(const std::string& ip, uint16_t port, int64_t now);
    void Good(const std::string& ip, uint16_t port, int64_t now);

    bool Select(std::string& ipOut, uint16_t& portOut, int64_t now) const;

    std::vector<AddrEntry> GetAddresses(size_t max, int64_t now) const;

    size_t Size() const;
    size_t TriedCount() const;
    size_t NewCount() const;

    size_t Sweep(int64_t now);

    bool Save(const std::string& path) const;
    bool Load(const std::string& path);

    static std::string GroupOf(const std::string& ip);

private:
    mutable std::mutex mMutex;

    uint64_t mKey;

    std::map<std::string, AddrEntry> mEntries;
    std::vector<std::vector<std::string> > mNew;
    std::vector<std::vector<std::string> > mTried;

    size_t NewBucketFor(const AddrEntry& e) const;
    size_t TriedBucketFor(const AddrEntry& e) const;
    size_t PositionIn(size_t bucket, const std::string& key) const;

    bool AddLocked(const AddrEntry& e, int64_t now);
    void RemoveLocked(const std::string& key);
    bool IsInTried(const std::string& key) const;
};

} // namespace net
} // namespace MONEU

#endif // MONEU_NET_ADDRMAN_H
