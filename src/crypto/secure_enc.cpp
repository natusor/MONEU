// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "secure_enc.h"

#include <cstring>

#include <openssl/evp.h>
#include <openssl/err.h>

extern "C" {
    #include "hmac.h"
    #include "memzero.h"
    #include "pbkdf2.h"
}

namespace MONEU {
namespace crypto {

SecureKeys::SecureKeys() {
    std::memset(mEnc, 0, sizeof(mEnc));
    std::memset(mMac, 0, sizeof(mMac));
}

SecureKeys::~SecureKeys() {
    Clear();
}

void SecureKeys::Clear() {
    memzero(mEnc, sizeof(mEnc));
    memzero(mMac, sizeof(mMac));
}

bool SecureKeys::Derive(const std::string& passphrase,
                        const uint8_t* salt,
                        size_t saltLen,
                        uint32_t iterations) {
    if (salt == NULL || saltLen == 0 || iterations == 0) {
        return false;
    }

    // One PBKDF2 pass produces both keys. Splitting a single 64-byte output
    // is cheaper than two passes and gives the same separation, because the
    // two halves of a PBKDF2 output are independent.
    uint8_t material[ENC_KEY_SIZE + MAC_KEY_SIZE];
    pbkdf2_hmac_sha256(
        reinterpret_cast<const uint8_t*>(passphrase.data()),
        static_cast<int>(passphrase.size()),
        salt,
        static_cast<int>(saltLen),
        iterations,
        material,
        static_cast<int>(sizeof(material)));

    std::memcpy(mEnc, material, ENC_KEY_SIZE);
    std::memcpy(mMac, material + ENC_KEY_SIZE, MAC_KEY_SIZE);
    memzero(material, sizeof(material));
    return true;
}

bool EncryptCBC(const uint8_t* plain,
                size_t plainLen,
                const SecureKeys& keys,
                const uint8_t iv[ENC_IV_SIZE],
                std::vector<uint8_t>& cipherOut) {
    cipherOut.clear();
    if (plain == NULL && plainLen != 0) return false;
    if (iv == NULL) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return false;

    bool ok = true;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                           keys.EncKey(), iv) != 1) {
        ok = false;
    }

    if (ok) {
        // PKCS#7 padding adds between 1 and one full block, so the output
        // never exceeds plainLen + one block.
        cipherOut.resize(plainLen + ENC_BLOCK_SIZE);
        int written = 0;
        int total = 0;

        // Feed the plaintext in bounded chunks: EVP takes an int length, so
        // a buffer larger than INT_MAX would otherwise wrap.
        const size_t CHUNK = 1u << 20; // 1 MiB
        size_t pos = 0;
        while (ok && pos < plainLen) {
            size_t take = (plainLen - pos < CHUNK) ? (plainLen - pos) : CHUNK;
            if (EVP_EncryptUpdate(ctx,
                                  cipherOut.data() + total, &written,
                                  plain + pos,
                                  static_cast<int>(take)) != 1) {
                ok = false;
                break;
            }
            total += written;
            pos += take;
        }

        if (ok) {
            if (EVP_EncryptFinal_ex(ctx, cipherOut.data() + total,
                                    &written) != 1) {
                ok = false;
            } else {
                total += written;
                cipherOut.resize(static_cast<size_t>(total));
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        if (!cipherOut.empty()) {
            memzero(cipherOut.data(), cipherOut.size());
        }
        cipherOut.clear();
    }
    return ok;
}

bool DecryptCBC(const uint8_t* cipher,
                size_t cipherLen,
                const SecureKeys& keys,
                const uint8_t iv[ENC_IV_SIZE],
                std::vector<uint8_t>& plainOut) {
    plainOut.clear();
    if (cipher == NULL || iv == NULL) return false;
    // CBC output is always whole blocks, and PKCS#7 means there is always at
    // least one block of padding, so an empty or ragged input is malformed.
    if (cipherLen == 0 || (cipherLen % ENC_BLOCK_SIZE) != 0) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return false;

    bool ok = true;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                           keys.EncKey(), iv) != 1) {
        ok = false;
    }

    if (ok) {
        plainOut.resize(cipherLen + ENC_BLOCK_SIZE);
        int written = 0;
        int total = 0;

        const size_t CHUNK = 1u << 20; // 1 MiB
        size_t pos = 0;
        while (ok && pos < cipherLen) {
            size_t take = (cipherLen - pos < CHUNK) ? (cipherLen - pos) : CHUNK;
            if (EVP_DecryptUpdate(ctx,
                                  plainOut.data() + total, &written,
                                  cipher + pos,
                                  static_cast<int>(take)) != 1) {
                ok = false;
                break;
            }
            total += written;
            pos += take;
        }

        if (ok) {
            if (EVP_DecryptFinal_ex(ctx, plainOut.data() + total,
                                    &written) != 1) {
                ok = false; // padding did not decode
            } else {
                total += written;
                plainOut.resize(static_cast<size_t>(total));
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        if (!plainOut.empty()) {
            memzero(plainOut.data(), plainOut.size());
        }
        plainOut.clear();
    }
    return ok;
}

void ComputeTag(const SecureKeys& keys,
                const uint8_t* header,
                size_t headerLen,
                const uint8_t* cipher,
                size_t cipherLen,
                uint8_t tagOut[ENC_TAG_SIZE]) {
    HMAC_SHA256_CTX hctx;
    hmac_sha256_Init(&hctx, keys.MacKey(), MAC_KEY_SIZE);

    if (header != NULL && headerLen > 0) {
        hmac_sha256_Update(&hctx, header,
                           static_cast<uint32_t>(headerLen));
    }

    const size_t CHUNK = 1u << 20; // 1 MiB per update
    size_t pos = 0;
    while (cipher != NULL && pos < cipherLen) {
        size_t take = (cipherLen - pos < CHUNK) ? (cipherLen - pos) : CHUNK;
        hmac_sha256_Update(&hctx, cipher + pos,
                           static_cast<uint32_t>(take));
        pos += take;
    }

    hmac_sha256_Final(&hctx, tagOut);
    memzero(&hctx, sizeof(hctx));
}

template <typename Container>
void WipeGuard<Container>::Wipe(void* data, size_t len) {
    memzero(data, len);
}

// The instantiations actually used. Keeping the definition out of the
// header means the wipe is a real call the optimiser cannot discard.
template class WipeGuard<std::vector<uint8_t> >;

bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    if (a == NULL || b == NULL) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace crypto
} // namespace MONEU
