// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_NODE_MINER_KERNEL_H
#define MONEU_NODE_MINER_KERNEL_H

namespace MONEU {

static const char* const MONEU_MINER_KERNEL_SRC = R"CLSRC(
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n)  ((x) >> (n))
#define Ch(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x) (ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3))
#define s1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

__constant uint K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void transform(const uint state[8], const uint blk[16], uint out[8]) {
    uint w[64];
    for (int i = 0; i < 16; i++) w[i] = blk[i];
    for (int i = 16; i < 64; i++)
        w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];

    uint a=state[0],b=state[1],c=state[2],d=state[3];
    uint e=state[4],f=state[5],g=state[6],h=state[7];

    for (int i = 0; i < 64; i++) {
        uint T1 = h + S1(e) + Ch(e,f,g) + K[i] + w[i];
        uint T2 = S0(a) + Maj(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    out[0]=state[0]+a; out[1]=state[1]+b; out[2]=state[2]+c; out[3]=state[3]+d;
    out[4]=state[4]+e; out[5]=state[5]+f; out[6]=state[6]+g; out[7]=state[7]+h;
}

__kernel void moneu_search(
    __global const uint* midstate,
    __global const uint* block2_in,
    __global const uint* block3_in,
    const uint targetTop,
    const uint start_nonce,
    const uint count,
    __global uint* found)
{
    uint gid = get_global_id(0);
    if (gid >= count) return;

    uint nonce = start_nonce + gid;

    uint ms[8];
    for (int i = 0; i < 8; i++) ms[i] = midstate[i];

    uint b2[16];
    for (int i = 0; i < 16; i++) b2[i] = block2_in[i];
    b2[13] = ((nonce & 0x000000FFu) << 24) |
             ((nonce & 0x0000FF00u) << 8)  |
             ((nonce & 0x00FF0000u) >> 8)  |
             ((nonce & 0xFF000000u) >> 24);

    uint b3[16];
    for (int i = 0; i < 16; i++) b3[i] = block3_in[i];

    uint state[8], hw[8];
    transform(ms, b2, state);
    transform(state, b3, hw);

    if (hw[0] <= targetTop) {
        if (atomic_cmpxchg(&found[0], 0u, 1u) == 0u) {
            found[1] = nonce;
        }
    }
}
)CLSRC";

} // namespace MONEU

#endif
