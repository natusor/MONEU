// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license
// Adapted from Stellar Development Foundation code (Apache 2.0)

#ifndef MONEU_PRIMITIVES_KEYS_H
#define MONEU_PRIMITIVES_KEYS_H

#include <array>
#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <functional>
#include <ostream>

extern "C" {
    #include "../crypto/ed25519-donna/ed25519.h"
    #include "../crypto/sha2.h"
    #include "../crypto/base58.h"
    #include "../crypto/rand.h"
    #include "../crypto/memzero.h"
}

namespace MONEU {

using bytes32 = std::array<uint8_t, 32>;
using bytes64 = std::array<uint8_t, 64>;

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& msg) : std::runtime_error(msg) {}
};

enum class VerifySigCacheResult {
    MISS,
    HIT,
    NO_LOOKUP
};

struct VerifySigResult {
    bool valid;
    VerifySigCacheResult cacheResult;
};

class SecretKey;

class PublicKey {
private:
    bytes32 mKey;

public:
    PublicKey();
    explicit PublicKey(const bytes32& key);
    explicit PublicKey(const uint8_t* key);
    ~PublicKey() = default;

    const bytes32& GetKey() const { return mKey; }
    const uint8_t* Data() const { return mKey.data(); }
    size_t Size() const { return mKey.size(); }

    std::string ToAddress() const;
    std::string ToHex() const;

    std::string ToAddressWithNoise(const bytes32& kps, uint8_t prefix) const;

    bool IsValid() const;
    bool IsZero() const;

    static PublicKey FromAddress(const std::string& addr);
    static PublicKey FromHex(const std::string& hex);
    static PublicKey Random();

    bool operator==(const PublicKey& other) const;
    bool operator!=(const PublicKey& other) const;
    bool operator<(const PublicKey& other) const;
};

class SecretKey {
private:
    bytes64 mSecretKey;
    bytes32 mPublicKey;

    struct Seed {
        bytes32 mSeed;
        ~Seed();
    };

    Seed GetSeed() const;

public:
    static constexpr size_t PUBLIC_KEY_SIZE = 32;
    static constexpr size_t SECRET_KEY_SIZE = 64;
    static constexpr size_t SEED_SIZE = 32;
    static constexpr size_t SIGNATURE_SIZE = 64;

    SecretKey();
    ~SecretKey();

    PublicKey GetPublicKey() const;
    std::string GetStrKeySeed() const;
    std::string GetStrKeyPublic() const;

    bool IsZero() const;

    bytes64 Sign(const uint8_t* data, size_t len) const;
    bytes64 Sign(const std::vector<uint8_t>& data) const;

    static VerifySigResult Verify(const PublicKey& pubkey, const bytes64& signature, const uint8_t* data, size_t len);
    static bool VerifySimple(const PublicKey& pubkey, const bytes64& signature, const uint8_t* data, size_t len);

    static SecretKey Random();
    static SecretKey FromSeed(const bytes32& seed);
    static SecretKey FromSeed(const uint8_t* seed, size_t len);
    static SecretKey FromStrKeySeed(const std::string& strKey);

    static void BenchmarkOpsPerSecond(size_t& sign, size_t& verify, size_t iterations, size_t cachedVerifyPasses = 1);

    bool operator==(const SecretKey& other) const;
    bool operator<(const SecretKey& other) const;
};

namespace PubKeyUtils {
    VerifySigResult VerifySig(const PublicKey& key, const bytes64& signature, const uint8_t* data, size_t len);
    void ClearVerifySigCache();
    void SeedVerifySigCache(unsigned int seed);
    void FlushVerifySigCacheCounts(uint64_t& hits, uint64_t& misses);
    PublicKey Random();
}

bytes32 NoiseBoundHash(const PublicKey& pubkey, const bytes32& kps);

bool DecodeNoiseAddress(const std::string& addr,
                        uint8_t& prefixOut,
                        bytes32& hashOut);

namespace KeyUtils {
    void LogKey(std::ostream& s, const std::string& key);
    void LogPublicKey(std::ostream& s, const PublicKey& pk);
    void LogSecretKey(std::ostream& s, const SecretKey& sk);
}

} // namespace MONEU

namespace std {
    template<>
    struct hash<MONEU::PublicKey> {
        size_t operator()(const MONEU::PublicKey& pk) const noexcept;
    };
} // namespace std

#endif // MONEU_PRIMITIVES_KEYS_H
