// Copyright (c) 2020 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MONEU_CRYPTO_SHA3_256_H
#define MONEU_CRYPTO_SHA3_256_H

#include <cstddef>
#include <cstdint>

class SHA3_256 {
private:
    uint64_t m_state[25];
    unsigned char m_buffer[8];
    unsigned m_bufsize;
    unsigned m_pos;

    static const unsigned RATE_BUFFERS = 17;

public:
    static const size_t OUTPUT_SIZE = 32;

    SHA3_256();
    SHA3_256& Write(const unsigned char* data, size_t len);
    SHA3_256& Finalize(unsigned char output[OUTPUT_SIZE]);
    SHA3_256& Reset();
};

void KeccakF(uint64_t (&st)[25]);

#endif // MONEU_CRYPTO_SHA3_256_H
