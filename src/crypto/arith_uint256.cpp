// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"

namespace PNC {

namespace {
const char* kHexDigits = "0123456789abcdef";
}

template <unsigned int BITS>
base_uint<BITS>& base_uint<BITS>::operator<<=(unsigned int shift)
{
    base_uint<BITS> a(*this);
    for (int i = 0; i < WIDTH; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < WIDTH; i++)
    {
        if (i + k + 1 < WIDTH && shift != 0)
            pn[i + k + 1] |= (a.pn[i] >> (32 - shift));
        if (i + k < WIDTH)
            pn[i + k] |= (a.pn[i] << shift);
    }
    return *this;
}

template <unsigned int BITS>
base_uint<BITS>& base_uint<BITS>::operator>>=(unsigned int shift)
{
    base_uint<BITS> a(*this);
    for (int i = 0; i < WIDTH; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < WIDTH; i++)
    {
        if (i - k - 1 >= 0 && shift != 0)
            pn[i - k - 1] |= (a.pn[i] << (32 - shift));
        if (i - k >= 0)
            pn[i - k] |= (a.pn[i] >> shift);
    }
    return *this;
}

template <unsigned int BITS>
base_uint<BITS>& base_uint<BITS>::operator*=(uint32_t b32)
{
    uint64_t carry = 0;
    for (int i = 0; i < WIDTH; i++)
    {
        uint64_t n = carry + (uint64_t)b32 * pn[i];
        pn[i] = n & 0xffffffff;
        carry = n >> 32;
    }
    return *this;
}

template <unsigned int BITS>
base_uint<BITS>& base_uint<BITS>::operator*=(const base_uint& b)
{
    base_uint<BITS> a;
    for (int j = 0; j < WIDTH; j++)
    {
        uint64_t carry = 0;
        for (int i = 0; i + j < WIDTH; i++)
        {
            uint64_t n = carry + a.pn[i + j] + (uint64_t)pn[j] * b.pn[i];
            a.pn[i + j] = n & 0xffffffff;
            carry = n >> 32;
        }
    }
    *this = a;
    return *this;
}

template <unsigned int BITS>
base_uint<BITS>& base_uint<BITS>::operator/=(const base_uint& b)
{
    base_uint<BITS> div = b;     // make a copy, so we can shift.
    base_uint<BITS> num = *this; // make a copy, so we can subtract.
    *this = 0;                   // the quotient.
    int num_bits = num.bits();
    int div_bits = div.bits();
    if (div_bits == 0)
        throw uint_error("Division by zero");
    if (div_bits > num_bits) // the result is certainly 0.
        return *this;
    int shift = num_bits - div_bits;
    div <<= shift; // shift so that div and num align.
    while (shift >= 0)
    {
        if (num >= div)
        {
            num -= div;
            pn[shift / 32] |= (1U << (shift & 31)); // set a bit of the result.
        }
        div >>= 1; // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return *this;
}

template <unsigned int BITS>
int base_uint<BITS>::CompareTo(const base_uint<BITS>& b) const
{
    for (int i = WIDTH - 1; i >= 0; i--)
    {
        if (pn[i] < b.pn[i])
            return -1;
        if (pn[i] > b.pn[i])
            return 1;
    }
    return 0;
}

template <unsigned int BITS>
bool base_uint<BITS>::EqualTo(uint64_t b) const
{
    for (int i = WIDTH - 1; i >= 2; i--)
    {
        if (pn[i])
            return false;
    }
    if (pn[1] != (uint32_t)(b >> 32))
        return false;
    if (pn[0] != (uint32_t)b)
        return false;
    return true;
}

template <unsigned int BITS>
std::string base_uint<BITS>::GetHex() const
{
    // Big-endian hex, most significant nibble first, fixed width.
    std::string out;
    out.reserve(BITS / 4);
    for (int i = WIDTH - 1; i >= 0; i--)
    {
        for (int nibble = 28; nibble >= 0; nibble -= 4)
        {
            out.push_back(kHexDigits[(pn[i] >> nibble) & 0xF]);
        }
    }
    return out;
}

template <unsigned int BITS>
std::string base_uint<BITS>::ToString() const
{
    return GetHex();
}

template <unsigned int BITS>
unsigned int base_uint<BITS>::bits() const
{
    for (int pos = WIDTH - 1; pos >= 0; pos--)
    {
        if (pn[pos])
        {
            for (int nbits = 31; nbits > 0; nbits--)
            {
                if (pn[pos] & (1U << nbits))
                    return 32 * pos + nbits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

// Explicit instantiations for base_uint<256>
template base_uint<256>& base_uint<256>::operator<<=(unsigned int);
template base_uint<256>& base_uint<256>::operator>>=(unsigned int);
template base_uint<256>& base_uint<256>::operator*=(uint32_t);
template base_uint<256>& base_uint<256>::operator*=(const base_uint<256>&);
template base_uint<256>& base_uint<256>::operator/=(const base_uint<256>&);
template int base_uint<256>::CompareTo(const base_uint<256>&) const;
template bool base_uint<256>::EqualTo(uint64_t) const;
template std::string base_uint<256>::GetHex() const;
template std::string base_uint<256>::ToString() const;
template unsigned int base_uint<256>::bits() const;

// This implementation directly uses shifts instead of going
// through an intermediate MPI representation.
arith_uint256& arith_uint256::SetCompact(uint32_t nCompact, bool* pfNegative, bool* pfOverflow)
{
    int nSize = nCompact >> 24;
    uint32_t nWord = nCompact & 0x007fffff;
    if (nSize <= 3)
    {
        nWord >>= 8 * (3 - nSize);
        *this = nWord;
    }
    else
    {
        *this = nWord;
        *this <<= 8 * (nSize - 3);
    }
    if (pfNegative)
        *pfNegative = nWord != 0 && (nCompact & 0x00800000) != 0;
    if (pfOverflow)
        *pfOverflow = nWord != 0 && ((nSize > 34) ||
                                     (nWord > 0xff && nSize > 33) ||
                                     (nWord > 0xffff && nSize > 32));
    return *this;
}

uint32_t arith_uint256::GetCompact(bool fNegative) const
{
    int nSize = (bits() + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3)
    {
        nCompact = GetLow64() << 8 * (3 - nSize);
    }
    else
    {
        arith_uint256 bn = *this >> 8 * (nSize - 3);
        nCompact = bn.GetLow64();
    }
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if (nCompact & 0x00800000)
    {
        nCompact >>= 8;
        nSize++;
    }
    nCompact |= nSize << 24;
    nCompact |= (fNegative && (nCompact & 0x007fffff) ? 0x00800000 : 0);
    return nCompact;
}

arith_uint256 ArithFromBytes32(const bytes32& b)
{
    // bytes32 is big-endian (b[0] most significant); limbs are little-endian.
    arith_uint256 out;
    for (int limb = 0; limb < 8; limb++)
    {
        const int base = 32 - 4 * (limb + 1); // byte offset of this limb's MSB group
        out.pn[limb] = ((uint32_t)b[base] << 24) |
                       ((uint32_t)b[base + 1] << 16) |
                       ((uint32_t)b[base + 2] << 8) |
                       ((uint32_t)b[base + 3]);
    }
    return out;
}

bytes32 ArithToBytes32(const arith_uint256& a)
{
    bytes32 out;
    for (int limb = 0; limb < 8; limb++)
    {
        const int base = 32 - 4 * (limb + 1);
        out[base]     = (uint8_t)(a.pn[limb] >> 24);
        out[base + 1] = (uint8_t)(a.pn[limb] >> 16);
        out[base + 2] = (uint8_t)(a.pn[limb] >> 8);
        out[base + 3] = (uint8_t)(a.pn[limb]);
    }
    return out;
}

} // namespace PNC
