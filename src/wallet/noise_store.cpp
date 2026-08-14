// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "noise_store.h"
#include "../crypto/secure_enc.h"

#include <iostream>
#include <sys/stat.h>

#include <cstdio>
#include <cstring>

extern "C" {
    #include "../crypto/rand.h"
    #include "../crypto/memzero.h"
}

namespace MONEU {

namespace {

const uint8_t MAGIC[4] = { 'M', 'N', 'Z', '2' };
const uint8_t VERSION  = 0x02;

const size_t AUTH_HEADER_SIZE = 4 + 1 + crypto::ENC_SALT_SIZE +
                                crypto::ENC_IV_SIZE;

void BuildAuthHeader(const uint8_t* salt,
                     const uint8_t* iv,
                     uint8_t* out) {
    size_t pos = 0;
    std::memcpy(out + pos, MAGIC, 4);            pos += 4;
    out[pos] = VERSION;                          pos += 1;
    std::memcpy(out + pos, salt, crypto::ENC_SALT_SIZE);
    pos += crypto::ENC_SALT_SIZE;
    std::memcpy(out + pos, iv, crypto::ENC_IV_SIZE);
}

} // namespace

bool NoiseStore::EncryptToFile(const std::vector<uint8_t>& raw,
                               const std::string& passphrase,
                               const std::string& path) {
    if (raw.empty()) {
        return false;
    }

    uint8_t salt[crypto::ENC_SALT_SIZE];
    uint8_t iv[crypto::ENC_IV_SIZE];
    random_buffer(salt, sizeof(salt));
    random_buffer(iv, sizeof(iv));

    crypto::SecureKeys keys;
    if (!keys.Derive(passphrase, salt, sizeof(salt))) {
        return false;
    }

    std::vector<uint8_t> cipher;
    if (!crypto::EncryptCBC(raw.data(), raw.size(), keys, iv, cipher)) {
        return false;
    }

    uint8_t header[AUTH_HEADER_SIZE];
    BuildAuthHeader(salt, iv, header);

    uint8_t tag[crypto::ENC_TAG_SIZE];
    crypto::ComputeTag(keys, header, sizeof(header),
                       cipher.data(), cipher.size(), tag);

    keys.Clear();

    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) {
        memzero(cipher.data(), cipher.size());
        return false;
    }

    bool ok = true;
    ok = ok && (std::fwrite(header, 1, sizeof(header), f) == sizeof(header));
    ok = ok && (std::fwrite(tag, 1, sizeof(tag), f) == sizeof(tag));
    ok = ok && (std::fwrite(cipher.data(), 1, cipher.size(), f)
                == cipher.size());
    std::fclose(f);

    memzero(cipher.data(), cipher.size());

    if (!ok) {
        std::remove(path.c_str());
        return false;
    }

    if (chmod(path.c_str(), 0600) != 0) {
        std::cerr << "NoiseStore: could not restrict permissions on "
                  << path << "\n";
    }
    return true;
}

bool NoiseStore::DecryptFromFile(const std::string& path,
                                 const std::string& passphrase,
                                 std::vector<uint8_t>& rawOut) {
    rawOut.clear();

    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;

    uint8_t header[AUTH_HEADER_SIZE];
    uint8_t tag[crypto::ENC_TAG_SIZE];

    if (std::fread(header, 1, sizeof(header), f) != sizeof(header) ||
        std::fread(tag, 1, sizeof(tag), f) != sizeof(tag)) {
        std::fclose(f);
        return false;
    }
    if (std::memcmp(header, MAGIC, 4) != 0 || header[4] != VERSION) {
        std::fclose(f);
        return false;
    }

    const uint8_t* salt = header + 5;
    const uint8_t* iv   = header + 5 + crypto::ENC_SALT_SIZE;

    std::vector<uint8_t> cipher;
    {
        uint8_t buf[65536];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
            cipher.insert(cipher.end(), buf, buf + n);
        }
        memzero(buf, sizeof(buf));
    }
    std::fclose(f);

    if (cipher.empty()) {
        return false;
    }

    crypto::WipeGuard<std::vector<uint8_t> > cipherGuard(cipher);

    crypto::SecureKeys keys;
    if (!keys.Derive(passphrase, salt, crypto::ENC_SALT_SIZE)) {
        return false;
    }

    uint8_t expectTag[crypto::ENC_TAG_SIZE];
    crypto::ComputeTag(keys, header, sizeof(header),
                       cipher.data(), cipher.size(), expectTag);

    const bool tagOk = crypto::ConstantTimeEqual(expectTag, tag,
                                                 crypto::ENC_TAG_SIZE);
    memzero(expectTag, sizeof(expectTag));

    if (!tagOk) {
        return false;
    }

    std::vector<uint8_t> plain;
    const bool decOk = crypto::DecryptCBC(cipher.data(), cipher.size(),
                                          keys, iv, plain);
    keys.Clear();

    if (!decOk) {
        return false;
    }

    rawOut.swap(plain);
    return true;
}

} // namespace MONEU
