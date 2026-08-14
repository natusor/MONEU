// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license
// Adapted from Stellar Development Foundation code (Apache 2.0)

#include "keys.h"
#include <cstring>
#include <mutex>
#include <chrono>
#include <algorithm>
#include <map>
#include <sstream>
#include <iomanip>
#include <cstdlib>

namespace MONEU {

template<typename Key, typename Value>
class SimpleCache {
private:
    std::map<Key, Value> mData;
    size_t               mMaxSize;

public:
    explicit SimpleCache(size_t maxSize) : mMaxSize(maxSize) {}

    bool Exists(const Key& key) const {
        return mData.find(key) != mData.end();
    }

    Value Get(const Key& key) const {
        auto it = mData.find(key);
        if (it != mData.end()) return it->second;
        throw std::runtime_error("Key not found in cache");
    }

    void Put(const Key& key, const Value& value) {
        if (mData.size() >= mMaxSize &&
            mData.find(key) == mData.end()) {
            mData.erase(mData.begin());
        }
        mData[key] = value;
    }

    void Clear() { mData.clear(); }

    size_t Size() const { return mData.size(); }
};

static const size_t VERIFY_SIG_CACHE_SIZE = 250000;
static std::mutex gVerifySigCacheMutex;
static SimpleCache<bytes32, bool> gVerifySigCache(
    VERIFY_SIG_CACHE_SIZE);
static uint64_t gVerifyCacheHit  = 0;
static uint64_t gVerifyCacheMiss = 0;

static bytes32 VerifySigCacheKey(
    const PublicKey& key,
    const bytes64&   signature,
    const uint8_t*   data,
    size_t           len)
{
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, key.Data(), key.Size());
    sha256_Update(&ctx, signature.data(), signature.size());
    sha256_Update(&ctx, data, len);
    bytes32 hash;
    sha256_Final(&ctx, hash.data());
    return hash;
}

PublicKey::PublicKey() {
    mKey.fill(0);
}

PublicKey::PublicKey(const bytes32& key) : mKey(key) {}

PublicKey::PublicKey(const uint8_t* key) {
    std::memcpy(mKey.data(), key, 32);
}

std::string PublicKey::ToAddress() const {
    char   address[64];
    size_t len = sizeof(address);
    if (!b58enc(address, &len, mKey.data(), 32)) {
        throw CryptoError("Failed to encode address");
    }
    return std::string(address);
}

std::string PublicKey::ToAddressWithNoise(const bytes32& kps,
                                          uint8_t prefix) const {
    bytes32 h = NoiseBoundHash(*this, kps);
    uint8_t payload[33];
    payload[0] = prefix;
    std::memcpy(payload + 1, h.data(), 32);

    char   out[128];
    int    n = base58_encode_check(payload, 33, out, sizeof(out));
    if (n <= 0) {
        throw CryptoError("Failed to encode noise address");
    }
    return std::string(out);
}

std::string PublicKey::ToHex() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : mKey) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

bool PublicKey::IsValid() const { return !IsZero(); }

bool PublicKey::IsZero() const {
    for (uint8_t byte : mKey) {
        if (byte != 0) return false;
    }
    return true;
}

PublicKey PublicKey::FromAddress(const std::string& addr) {
    uint8_t decoded[32];
    size_t  len = 32;
    if (!b58tobin(decoded, &len, addr.c_str()) ||
        len != 32) {
        throw CryptoError("Invalid address format");
    }
    return PublicKey(decoded);
}

PublicKey PublicKey::FromHex(const std::string& hex) {
    if (hex.length() != 64) {
        throw CryptoError(
            "Invalid hex length (expected 64 chars)");
    }
    bytes32 key;
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(
            std::stoul(hex.substr(i * 2, 2),
                       nullptr, 16));
    }
    return PublicKey(key);
}

PublicKey PublicKey::Random() {
    bytes32 key;
    random_buffer(key.data(), 32);
    return PublicKey(key);
}

bool PublicKey::operator==(const PublicKey& other) const {
    return mKey == other.mKey;
}

bool PublicKey::operator!=(const PublicKey& other) const {
    return !(*this == other);
}

bool PublicKey::operator<(const PublicKey& other) const {
    return mKey < other.mKey;
}

SecretKey::Seed::~Seed() {
    memzero(mSeed.data(), mSeed.size());
}

SecretKey::SecretKey() {
    static_assert(PUBLIC_KEY_SIZE == 32,
                  "Ed25519 pubkey must be 32 bytes");
    static_assert(SECRET_KEY_SIZE == 64,
                  "Ed25519 secret must be 64 bytes");
    static_assert(SEED_SIZE == 32,
                  "Ed25519 seed must be 32 bytes");
    static_assert(SIGNATURE_SIZE == 64,
                  "Ed25519 signature must be 64 bytes");
    mSecretKey.fill(0);
    mPublicKey.fill(0);
}

SecretKey::~SecretKey() {
    memzero(mSecretKey.data(), mSecretKey.size());
    memzero(mPublicKey.data(), mPublicKey.size());
}

SecretKey::Seed SecretKey::GetSeed() const {
    Seed seed;
    std::memcpy(seed.mSeed.data(), mSecretKey.data(), 32);
    return seed;
}

PublicKey SecretKey::GetPublicKey() const {
    return PublicKey(mPublicKey);
}

std::string SecretKey::GetStrKeySeed() const {
    Seed   seed = GetSeed();
    char   encoded[64];
    size_t len = sizeof(encoded);
    if (!b58enc(encoded, &len, seed.mSeed.data(), 32)) {
        throw CryptoError("Failed to encode seed");
    }
    return std::string(encoded);
}

std::string SecretKey::GetStrKeyPublic() const {
    return GetPublicKey().ToAddress();
}

bool SecretKey::IsZero() const {
    for (uint8_t byte : mSecretKey) {
        if (byte != 0) return false;
    }
    return true;
}

bytes64 SecretKey::Sign(const uint8_t* data,
                         size_t         len) const
{
    if (IsZero()) {
        throw CryptoError("Cannot sign with zero key");
    }
    bytes64 signature;
    ed25519_sign(data, len,
                 mSecretKey.data(),
                 signature.data());
    return signature;
}

bytes64 SecretKey::Sign(
    const std::vector<uint8_t>& data) const
{
    return Sign(data.data(), data.size());
}

static bool IsCanonicalSignatureScalar(const uint8_t* sig) {
    static const uint8_t L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    const uint8_t* S = sig + 32;
    uint8_t borrowed = 0;
    uint8_t stillEqual = 1;
    for (int i = 31; i >= 0; --i) {
        const int diff = (int)S[i] - (int)L[i];
        borrowed = (uint8_t)(borrowed | ((uint8_t)(diff >> 8) & stillEqual));
        const int x = (int)(S[i] ^ L[i]) - 1;
        stillEqual = (uint8_t)(stillEqual & (uint8_t)(x >> 8));
    }
    return borrowed != 0;
}

VerifySigResult SecretKey::Verify(
    const PublicKey& pubkey,
    const bytes64&   signature,
    const uint8_t*   data,
    size_t           len)
{
    if (signature.size() != 64) {
        return {false, VerifySigCacheResult::NO_LOOKUP};
    }
    if (!IsCanonicalSignatureScalar(signature.data())) {
        return {false, VerifySigCacheResult::NO_LOOKUP};
    }
    auto cacheKey = VerifySigCacheKey(
        pubkey, signature, data, len);
    {
        std::lock_guard<std::mutex> guard(
            gVerifySigCacheMutex);
        if (gVerifySigCache.Exists(cacheKey)) {
            ++gVerifyCacheHit;
            return {gVerifySigCache.Get(cacheKey),
                    VerifySigCacheResult::HIT};
        }
    }
    bool ok = (ed25519_sign_open(
        data, len,
        pubkey.Data(),
        signature.data()) == 0);
    std::lock_guard<std::mutex> guard(gVerifySigCacheMutex);
    ++gVerifyCacheMiss;
    if (ok) {
        gVerifySigCache.Put(cacheKey, ok);
    }
    return {ok, VerifySigCacheResult::MISS};
}

bool SecretKey::VerifySimple(
    const PublicKey& pubkey,
    const bytes64&   signature,
    const uint8_t*   data,
    size_t           len)
{
    return Verify(pubkey, signature, data, len).valid;
}

SecretKey SecretKey::Random() {
    uint8_t seed[32];
    random_buffer(seed, 32);
    return FromSeed(seed, 32);
}

SecretKey SecretKey::FromSeed(const bytes32& seed) {
    return FromSeed(seed.data(), 32);
}

SecretKey SecretKey::FromSeed(const uint8_t* seed,
                               size_t         len)
{
    if (len != 32) {
        throw CryptoError("Seed must be 32 bytes");
    }
    SecretKey sk;
    ed25519_publickey(seed, sk.mPublicKey.data());
    std::memcpy(sk.mSecretKey.data(), seed, 32);
    std::memcpy(sk.mSecretKey.data() + 32,
                sk.mPublicKey.data(), 32);
    return sk;
}

SecretKey SecretKey::FromStrKeySeed(
    const std::string& strKey)
{
    uint8_t decoded[32];
    size_t  len = 32;
    if (!b58tobin(decoded, &len, strKey.c_str()) ||
        len != 32) {
        throw CryptoError("Invalid seed format");
    }
    return FromSeed(decoded, 32);
}

struct SignVerifyTestcase {
    SecretKey             key;
    std::vector<uint8_t>  msg;
    bytes64               sig;

    void sign() {
        sig = key.Sign(msg.data(), msg.size());
    }
    void verify() {
        if (!SecretKey::VerifySimple(
                key.GetPublicKey(), sig,
                msg.data(), msg.size())) {
            throw std::runtime_error("verify failed");
        }
    }
    static SignVerifyTestcase create() {
        SignVerifyTestcase st;
        st.key = SecretKey::Random();
        st.msg.resize(256);
        random_buffer(st.msg.data(), 256);
        return st;
    }
};

void SecretKey::BenchmarkOpsPerSecond(
    size_t& sign,
    size_t& verify,
    size_t  iterations,
    size_t  cachedVerifyPasses)
{
    namespace ch = std::chrono;
    using clock  = ch::high_resolution_clock;
    using usec   = ch::microseconds;

    std::vector<SignVerifyTestcase> cases;
    for (size_t i = 0; i < iterations; ++i) {
        cases.push_back(SignVerifyTestcase::create());
    }
    auto signStart = clock::now();
    for (auto& c : cases) c.sign();
    auto signEnd = clock::now();

    auto verifyStart = clock::now();
    for (size_t pass = 0; pass < cachedVerifyPasses;
         ++pass)
    {
        if (pass == 1) verifyStart = clock::now();
        for (auto& c : cases) c.verify();
    }
    auto verifyEnd = clock::now();

    auto signUsec = ch::duration_cast<usec>(
        signEnd - signStart);
    auto verifyUsec = ch::duration_cast<usec>(
        verifyEnd - verifyStart);

    sign = 1000000 / std::max(
        size_t(1),
        size_t(signUsec.count() / iterations));
    verify = 1000000 / std::max(
        size_t(1),
        size_t(verifyUsec.count() / iterations));
}

bool SecretKey::operator==(
    const SecretKey& other) const
{
    return mSecretKey == other.mSecretKey;
}

bool SecretKey::operator<(
    const SecretKey& other) const
{
    return mSecretKey < other.mSecretKey;
}

namespace PubKeyUtils {

VerifySigResult VerifySig(
    const PublicKey& key,
    const bytes64&   signature,
    const uint8_t*   data,
    size_t           len)
{
    return SecretKey::Verify(key, signature, data, len);
}

void ClearVerifySigCache() {
    std::lock_guard<std::mutex> guard(gVerifySigCacheMutex);
    gVerifySigCache.Clear();
}

void SeedVerifySigCache(unsigned int seed) {
    std::lock_guard<std::mutex> guard(gVerifySigCacheMutex);
    std::srand(seed);
}

void FlushVerifySigCacheCounts(uint64_t& hits,
                                uint64_t& misses)
{
    std::lock_guard<std::mutex> guard(gVerifySigCacheMutex);
    hits             = gVerifyCacheHit;
    misses           = gVerifyCacheMiss;
    gVerifyCacheHit  = 0;
    gVerifyCacheMiss = 0;
}

PublicKey Random() {
    return PublicKey::Random();
}

}

namespace KeyUtils {

void LogKey(std::ostream& s, const std::string& key) {
    s << key;
}

void LogPublicKey(std::ostream& s, const PublicKey& pk) {
    s << pk.ToHex();
}

void LogSecretKey(std::ostream& s, const SecretKey& sk) {
    s << sk.GetStrKeyPublic();
}

}

bytes32 NoiseBoundHash(const PublicKey& pubkey, const bytes32& kps) {
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, pubkey.Data(), pubkey.Size());
    sha256_Update(&ctx, kps.data(), kps.size());
    bytes32 out;
    sha256_Final(&ctx, out.data());
    return out;
}

bool DecodeNoiseAddress(const std::string& addr,
                        uint8_t& prefixOut,
                        bytes32& hashOut) {
    uint8_t payload[64];
    int n = base58_decode_check(addr.c_str(), payload, 33);
    if (n != 33) {
        return false;
    }
    prefixOut = payload[0];
    std::memcpy(hashOut.data(), payload + 1, 32);
    return true;
}

} // namespace MONEU

namespace std {
size_t hash<MONEU::PublicKey>::operator()(
    const MONEU::PublicKey& pk) const noexcept
{
    size_t         result = 0;
    const uint8_t* data   = pk.Data();
    for (size_t i = 0; i < pk.Size(); ++i) {
        result = result * 31 + data[i];
    }
    return result;
}
} // namespace std
