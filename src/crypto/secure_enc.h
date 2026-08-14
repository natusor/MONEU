// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_CRYPTO_SECURE_ENC_H
#define MONEU_CRYPTO_SECURE_ENC_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace MONEU {
namespace crypto {

// Authenticated encryption at rest for wallet secrets and the noise file.
//
// AES-256-CBC for confidentiality, HMAC-SHA256 for integrity, applied in
// that order (encrypt-then-MAC). AES is a block cipher: the plaintext is
// transformed through the cipher itself and each block is chained into the
// next, so no keystream is generated and nothing is masked by hashing.
//
// Two independent keys come out of one PBKDF2-HMAC-SHA256 call producing 64
// bytes: the first 32 encrypt, the second 32 authenticate. Reusing a single
// key for both jobs is what lets a flaw in one primitive weaken the other,
// so they are kept apart.
//
// The tag covers the file header as well as the ciphertext. Salt and IV are
// stored in that header, so binding them means a modified salt or IV is
// rejected instead of quietly producing different keys or a shifted first
// block.
//
// Every buffer holding key material is wiped before it goes out of scope.

const size_t ENC_KEY_SIZE  = 32;   // AES-256
const size_t MAC_KEY_SIZE  = 32;   // HMAC-SHA256
const size_t ENC_IV_SIZE   = 16;   // AES block size
const size_t ENC_TAG_SIZE  = 32;   // HMAC-SHA256 output
const size_t ENC_SALT_SIZE = 16;   // PBKDF2 salt
const size_t ENC_BLOCK_SIZE = 16;  // AES block size

// PBKDF2 work factor. Raised over the previous 100000 because the noise
// file is a long-lived secret that an attacker can copy once and grind on
// offline for as long as they like.
const uint32_t ENC_PBKDF2_ITERATIONS = 200000;

// Encryption and authentication keys derived from a passphrase. The
// destructor wipes both, so a SecureKeys object must never be copied - a
// copy would leave a second set of key bytes behind in memory.
class SecureKeys {
public:
    SecureKeys();
    ~SecureKeys();

    // Derive both keys from passphrase and salt. Returns false only if the
    // arguments are unusable (no salt, zero iterations).
    bool Derive(const std::string& passphrase,
                const uint8_t* salt,
                size_t saltLen,
                uint32_t iterations = ENC_PBKDF2_ITERATIONS);

    const uint8_t* EncKey() const { return mEnc; }
    const uint8_t* MacKey() const { return mMac; }

    // Wipe both keys. Called by the destructor; exposed so a caller can
    // drop the keys as soon as it is done rather than at end of scope.
    void Clear();

private:
    uint8_t mEnc[ENC_KEY_SIZE];
    uint8_t mMac[MAC_KEY_SIZE];

    SecureKeys(const SecureKeys&);
    SecureKeys& operator=(const SecureKeys&);
};

// AES-256-CBC with PKCS#7 padding. cipherOut is resized to hold the result,
// which is always a whole number of blocks and always longer than the
// plaintext by 1 to 16 bytes. Returns false on any OpenSSL error.
bool EncryptCBC(const uint8_t* plain,
                size_t plainLen,
                const SecureKeys& keys,
                const uint8_t iv[ENC_IV_SIZE],
                std::vector<uint8_t>& cipherOut);

// Inverse of EncryptCBC. Returns false on an OpenSSL error or on padding
// that does not decode, in which case plainOut is left empty. The caller
// must verify the tag before calling this.
bool DecryptCBC(const uint8_t* cipher,
                size_t cipherLen,
                const SecureKeys& keys,
                const uint8_t iv[ENC_IV_SIZE],
                std::vector<uint8_t>& plainOut);

// HMAC-SHA256 over header followed by ciphertext, using the MAC key. The
// ciphertext is fed in 1 MiB chunks so a file of any size is handled
// without a copy and without overflowing the 32-bit length of a single
// update call.
void ComputeTag(const SecureKeys& keys,
                const uint8_t* header,
                size_t headerLen,
                const uint8_t* cipher,
                size_t cipherLen,
                uint8_t tagOut[ENC_TAG_SIZE]);

// Wipes a buffer when it goes out of scope, however that happens.
//
// Manual wiping works until a function grows a second way out. An early
// return on a failed key derivation, or a throw from something further
// down, skips whatever cleanup was written at the bottom - and the secret
// stays in freed memory. That is not a hypothetical: this class was added
// after exactly one such path was found in NoiseStore::DecryptFromFile.
//
// Blockstream's Jade solves this with a registry of sensitive buffers that
// its error handler walks. C++ gives it for free through destructors, so
// there is nothing to register and nothing to remember to pop.
//
//     std::vector<uint8_t> secret = ...;
//     WipeGuard guard(secret);      // wiped on every exit from here
//
template <typename Container>
class WipeGuard {
public:
    explicit WipeGuard(Container& target) : mTarget(target) {}

    ~WipeGuard() {
        if (!mTarget.empty()) {
            Wipe(&mTarget[0], mTarget.size() * sizeof(mTarget[0]));
        }
    }

private:
    Container& mTarget;

    // Out of line so the compiler cannot decide the write is dead and
    // remove it - which is what happens to a plain memset on a buffer
    // nothing reads afterwards.
    static void Wipe(void* data, size_t len);

    WipeGuard(const WipeGuard&);
    WipeGuard& operator=(const WipeGuard&);
};

// Comparison whose running time does not depend on where the first
// difference is. Used for tags, so a wrong passphrase cannot be narrowed
// down by timing.
bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len);

} // namespace crypto
} // namespace MONEU

#endif // MONEU_CRYPTO_SECURE_ENC_H
