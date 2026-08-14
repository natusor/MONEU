// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_WALLET_NOISE_STORE_H
#define MONEU_WALLET_NOISE_STORE_H

#include <cstdint>
#include <string>
#include <vector>

namespace MONEU {

// Encrypted on-disk container for the raw physical-noise file.
//
// The raw noise is the secret material a wallet needs to spend; its single
// public value, the KPS root, is derived from it. It must be stored
// encrypted under the user's passphrase.
//
// The key comes from PBKDF2-HMAC-SHA256 over the passphrase and a random
// per-file salt. The noise is then encrypted with AES-256-CBC, and an
// HMAC-SHA256 tag over the header and ciphertext gives integrity, so a
// wrong passphrase or a corrupted file is detected before anything is
// decrypted. AES is a block cipher, so the noise is transformed through the
// cipher itself rather than masked with a generated keystream.
//
// The tag covers the header as well as the ciphertext. Salt and IV live in
// that header, so a file with either of them altered fails authentication
// instead of decrypting to something else.
//
// File layout:
//   magic       4 bytes  "MNZ2"
//   version     1 byte   0x02
//   salt       16 bytes  random, per file, for PBKDF2
//   iv         16 bytes  random, per file, for AES-CBC
//   tag        32 bytes  HMAC-SHA256 over the 37 bytes above + ciphertext
//   ciphertext  N bytes  AES-256-CBC with PKCS#7 padding
//
// Ciphertext is one to sixteen bytes longer than the noise because of the
// padding. The peak memory cost is the file held twice, once encrypted and
// once not, which for the fixed 32 MiB noise file is 64 MiB.

class NoiseStore {
public:
    // Encrypt raw noise under passphrase and write it to path. Returns false
    // on any filesystem or encoding error. raw is left unchanged.
    static bool EncryptToFile(const std::vector<uint8_t>& raw,
                              const std::string& passphrase,
                              const std::string& path);

    // Read and decrypt path under passphrase into rawOut. Returns false if
    // the file is missing, malformed, or the passphrase is wrong (tag
    // mismatch), in which case rawOut is left empty.
    static bool DecryptFromFile(const std::string& path,
                                const std::string& passphrase,
                                std::vector<uint8_t>& rawOut);

private:
    // Layout sizes are owned by crypto/secure_enc.h; see the file layout
    // above. Nothing here duplicates them, so the two can never disagree.
};

}

#endif
