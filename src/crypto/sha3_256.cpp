// Copyright (c) 2020 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Based on https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
// by Markku-Juhani O. Saarinen <mjos@iki.fi>

#include "sha3_256.h"

#include <algorithm>
#include <iterator>
#include <cstring>

namespace {

inline uint64_t Rotl(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

inline uint64_t ReadLE64(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

inline void WriteLE64(unsigned char* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<unsigned char>(v & 0xff);
        v >>= 8;
    }
}

} // namespace

void KeccakF(uint64_t (&st)[25])
{
    static const uint64_t RNDC[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };
    static const int ROTC[24] = {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };
    static const int PILN[24] = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };

    for (int round = 0; round < 24; ++round) {
        uint64_t bc[5];
        for (int i = 0; i < 5; ++i) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (int i = 0; i < 5; ++i) {
            const uint64_t t = bc[(i + 4) % 5] ^ Rotl(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }

        uint64_t t = st[1];
        for (int i = 0; i < 24; ++i) {
            const int j = PILN[i];
            const uint64_t tmp = st[j];
            st[j] = Rotl(t, ROTC[i]);
            t = tmp;
        }

        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; ++i) bc[i] = st[j + i];
            for (int i = 0; i < 5; ++i) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        st[0] ^= RNDC[round];
    }
}

SHA3_256::SHA3_256()
{
    Reset();
}

SHA3_256& SHA3_256::Write(const unsigned char* data, size_t len)
{
    if (m_bufsize && len >= sizeof(m_buffer) - m_bufsize) {
        std::memcpy(m_buffer + m_bufsize, data, sizeof(m_buffer) - m_bufsize);
        data += sizeof(m_buffer) - m_bufsize;
        len  -= sizeof(m_buffer) - m_bufsize;
        m_state[m_pos++] ^= ReadLE64(m_buffer);
        m_bufsize = 0;
        if (m_pos == RATE_BUFFERS) {
            KeccakF(m_state);
            m_pos = 0;
        }
    }
    while (len >= sizeof(m_buffer)) {
        m_state[m_pos++] ^= ReadLE64(data);
        data += 8;
        len  -= 8;
        if (m_pos == RATE_BUFFERS) {
            KeccakF(m_state);
            m_pos = 0;
        }
    }
    if (len) {
        std::memcpy(m_buffer + m_bufsize, data, len);
        m_bufsize += static_cast<unsigned>(len);
    }
    return *this;
}

SHA3_256& SHA3_256::Finalize(unsigned char output[OUTPUT_SIZE])
{
    std::memset(m_buffer + m_bufsize, 0, sizeof(m_buffer) - m_bufsize);
    m_buffer[m_bufsize] ^= 0x06;
    m_state[m_pos] ^= ReadLE64(m_buffer);
    m_state[RATE_BUFFERS - 1] ^= 0x8000000000000000ULL;
    KeccakF(m_state);
    for (unsigned i = 0; i < 4; ++i) {
        WriteLE64(output + 8 * i, m_state[i]);
    }
    return *this;
}

SHA3_256& SHA3_256::Reset()
{
    m_bufsize = 0;
    m_pos = 0;
    std::fill(std::begin(m_state), std::end(m_state), 0);
    return *this;
}
