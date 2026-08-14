/**
 * Copyright (c) 2013-2016 Tomas Dzetkulic
 * Copyright (c) 2013-2016 Pavol Rusnak
 * Copyright (c) 2025-2026 natusor (MONEU)
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * MONEU: Stripped to Ed25519 SLIP-0010 only.
 * No secp256k1, no ECDSA, no NEM, no Cardano.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "bip32.h"
#include "../crypto/hmac.h"
#include "../crypto/sha2.h"
#include "../crypto/memzero.h"
#include "../crypto/ed25519-donna/ed25519.h"

#define ED25519_SEED_NAME "ed25519 seed"

static const curve_info ed25519_info = {
    .bip32_name    = ED25519_SEED_NAME,
    .params        = NULL,
    .hasher_base58 = HASHER_SHA2D,
    .hasher_sign   = HASHER_SHA2D,
    .hasher_pubkey = HASHER_SHA2_RIPEMD,
    .hasher_script = HASHER_SHA2,
};

const curve_info *get_curve_by_name(const char *curve_name) {
    if (!curve_name) return NULL;
    if (strcmp(curve_name, ED25519_SEED_NAME) == 0 ||
        strcmp(curve_name, "ed25519")          == 0) {
        return &ed25519_info;
    }
    return NULL;
}

int hdnode_from_seed(const uint8_t *seed,
                     int seed_len,
                     const char *curve,
                     HDNode *out)
{
    uint8_t I[64];
    memzero(out, sizeof(HDNode));
    out->curve = get_curve_by_name(curve);
    if (!out->curve) return 0;

    HMAC_SHA512_CTX ctx;
    hmac_sha512_Init(&ctx,
        (const uint8_t *)out->curve->bip32_name,
        strlen(out->curve->bip32_name));
    hmac_sha512_Update(&ctx, seed, (size_t)seed_len);
    hmac_sha512_Final(&ctx, I);

    memcpy(out->private_key, I,      32);
    memcpy(out->chain_code,  I + 32, 32);
    memzero(out->public_key, sizeof(out->public_key));
    out->is_public_key_set = false;
    out->depth             = 0;
    out->child_num         = 0;

    memzero(I, sizeof(I));
    return 1;
}

int hdnode_fill_public_key(HDNode *node) {
    if (node->is_public_key_set) return 0;
    if (!node->curve) return 1;

    // SLIP-0010 Ed25519: prefix 0x00 + 32-byte pubkey
    node->public_key[0] = 0x00;
    ed25519_publickey(node->private_key,
                      node->public_key + 1);
    node->is_public_key_set = true;
    return 0;
}

int hdnode_private_ckd(HDNode *inout, uint32_t i) {
    uint8_t data[37];
    uint8_t I[64];

    if (!inout->curve) return 0;
    if (inout->depth == 0xFFFFFFFF) return 0;

    // Ed25519 SLIP-0010: ONLY hardened derivation!
    // Force hardened if not already set
    if (!(i & 0x80000000U)) {
        i |= 0x80000000U;
    }

    // Data = 0x00 || private_key[32] || index(4 BE)
    data[0] = 0x00;
    memcpy(data + 1, inout->private_key, 32);
    data[33] = (i >> 24) & 0xFF;
    data[34] = (i >> 16) & 0xFF;
    data[35] = (i >>  8) & 0xFF;
    data[36] = (i      ) & 0xFF;

    HMAC_SHA512_CTX ctx;
    hmac_sha512_Init(&ctx, inout->chain_code, 32);
    hmac_sha512_Update(&ctx, data, 37);
    hmac_sha512_Final(&ctx, I);

    memcpy(inout->private_key, I,      32);
    memcpy(inout->chain_code,  I + 32, 32);
    inout->depth++;
    inout->child_num         = i;
    memzero(inout->public_key, sizeof(inout->public_key));
    inout->is_public_key_set = false;

    memzero(data, sizeof(data));
    memzero(I,    sizeof(I));
    return 1;
}

int hdnode_public_ckd(HDNode *inout, uint32_t i) {
    // Ed25519 SLIP-0010 does NOT support
    // public key derivation
    (void)inout;
    (void)i;
    return 0;
}

uint32_t hdnode_fingerprint(HDNode *node) {
    uint8_t digest[32];
    uint32_t fingerprint;

    hdnode_fill_public_key(node);
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, node->public_key, 33);
    sha256_Final(&ctx, digest);

    fingerprint =
        ((uint32_t)digest[0] << 24) |
        ((uint32_t)digest[1] << 16) |
        ((uint32_t)digest[2] <<  8) |
        ((uint32_t)digest[3]);

    memzero(digest, sizeof(digest));
    return fingerprint;
}

int hdnode_from_xpub(uint32_t depth,
                     uint32_t child_num,
                     const uint8_t *chain_code,
                     const uint8_t *public_key,
                     const char *curve,
                     HDNode *out)
{
    const curve_info *info = get_curve_by_name(curve);
    if (!info) return 0;
    out->curve             = info;
    out->depth             = depth;
    out->child_num         = child_num;
    memcpy(out->chain_code, chain_code, 32);
    memzero(out->private_key, 32);
    memzero(out->private_key_extension, 32);
    memcpy(out->public_key, public_key, 33);
    out->is_public_key_set = true;
    return 1;
}

int hdnode_from_xprv(uint32_t depth,
                     uint32_t child_num,
                     const uint8_t *chain_code,
                     const uint8_t *private_key,
                     const char *curve,
                     HDNode *out)
{
    const curve_info *info = get_curve_by_name(curve);
    if (!info) return 0;
    out->curve             = info;
    out->depth             = depth;
    out->child_num         = child_num;
    memcpy(out->chain_code,  chain_code,  32);
    memcpy(out->private_key, private_key, 32);
    memzero(out->public_key, sizeof(out->public_key));
    out->is_public_key_set = false;
    memzero(out->private_key_extension,
            sizeof(out->private_key_extension));
    return 1;
}

int hdnode_sign(HDNode *node,
                const uint8_t *msg,
                uint32_t msg_len,
                HasherType hasher_sign,
                uint8_t *sig,
                uint8_t *pby,
                int (*is_canonical)(uint8_t by,
                                    uint8_t sig[64]))
{
    (void)hasher_sign;
    (void)pby;
    (void)is_canonical;
    if (!node->curve || node->curve->params) return 1;
    ed25519_sign(msg, msg_len,
                 node->private_key, sig);
    return 0;
}

int hdnode_sign_digest(HDNode *node,
                       const uint8_t *digest,
                       uint8_t *sig,
                       uint8_t *pby,
                       int (*is_canonical)(uint8_t by,
                                           uint8_t sig[64]))
{
    return hdnode_sign(node, digest, 32, 0,
                       sig, pby, is_canonical);
}

int hdnode_get_shared_key(const HDNode *node,
                          const uint8_t *peer_public_key,
                          uint8_t *session_key,
                          int *result_size)
{
    (void)node;
    (void)peer_public_key;
    (void)session_key;
    *result_size = 0;
    return 1;
}

static int hdnode_serialize(const HDNode *node,
                             uint32_t fingerprint,
                             uint32_t version,
                             bool use_private,
                             char *str,
                             int strsize)
{
    uint8_t node_data[78];
    memzero(node_data, sizeof(node_data));
    node_data[0] = (version >> 24) & 0xFF;
    node_data[1] = (version >> 16) & 0xFF;
    node_data[2] = (version >>  8) & 0xFF;
    node_data[3] = (version      ) & 0xFF;
    node_data[4] = node->depth;
    node_data[5] = (fingerprint >> 24) & 0xFF;
    node_data[6] = (fingerprint >> 16) & 0xFF;
    node_data[7] = (fingerprint >>  8) & 0xFF;
    node_data[8] = (fingerprint      ) & 0xFF;
    node_data[9]  = (node->child_num >> 24) & 0xFF;
    node_data[10] = (node->child_num >> 16) & 0xFF;
    node_data[11] = (node->child_num >>  8) & 0xFF;
    node_data[12] = (node->child_num      ) & 0xFF;
    memcpy(node_data + 13, node->chain_code, 32);
    if (use_private) {
        node_data[45] = 0x00;
        memcpy(node_data + 46, node->private_key, 32);
    } else {
        memcpy(node_data + 45, node->public_key, 33);
    }
    int ret = base58_encode_check(
        node_data, sizeof(node_data), str, strsize);
    memzero(node_data, sizeof(node_data));
    return ret;
}

int hdnode_serialize_public(const HDNode *node,
                             uint32_t fingerprint,
                             uint32_t version,
                             char *str,
                             int strsize)
{
    return hdnode_serialize(node, fingerprint,
                             version, false,
                             str, strsize);
}

int hdnode_serialize_private(const HDNode *node,
                              uint32_t fingerprint,
                              uint32_t version,
                              char *str,
                              int strsize)
{
    return hdnode_serialize(node, fingerprint,
                             version, true,
                             str, strsize);
}

int hdnode_deserialize_public(const char *str,
                               uint32_t version,
                               const char *curve,
                               HDNode *node,
                               uint32_t *fingerprint)
{
    uint8_t node_data[78];
    memzero(node, sizeof(HDNode));
    node->curve = get_curve_by_name(curve);
    if (!node->curve) return -1;
    if (base58_decode_check(str, node_data,
                             sizeof(node_data))
        != sizeof(node_data)) return -1;
    uint32_t ver =
        ((uint32_t)node_data[0] << 24) |
        ((uint32_t)node_data[1] << 16) |
        ((uint32_t)node_data[2] <<  8) |
        ((uint32_t)node_data[3]);
    if (ver != version) { memzero(node_data, 78); return -3; }
    memzero(node->private_key, 32);
    memcpy(node->public_key, node_data + 45, 33);
    node->is_public_key_set = true;
    node->depth = node_data[4];
    if (fingerprint) {
        *fingerprint =
            ((uint32_t)node_data[5] << 24) |
            ((uint32_t)node_data[6] << 16) |
            ((uint32_t)node_data[7] <<  8) |
            ((uint32_t)node_data[8]);
    }
    node->child_num =
        ((uint32_t)node_data[9]  << 24) |
        ((uint32_t)node_data[10] << 16) |
        ((uint32_t)node_data[11] <<  8) |
        ((uint32_t)node_data[12]);
    memcpy(node->chain_code, node_data + 13, 32);
    memzero(node_data, sizeof(node_data));
    return 0;
}

int hdnode_deserialize_private(const char *str,
                                uint32_t version,
                                const char *curve,
                                HDNode *node,
                                uint32_t *fingerprint)
{
    uint8_t node_data[78];
    memzero(node, sizeof(HDNode));
    node->curve = get_curve_by_name(curve);
    if (!node->curve) return -1;
    if (base58_decode_check(str, node_data,
                             sizeof(node_data))
        != sizeof(node_data)) return -1;
    uint32_t ver =
        ((uint32_t)node_data[0] << 24) |
        ((uint32_t)node_data[1] << 16) |
        ((uint32_t)node_data[2] <<  8) |
        ((uint32_t)node_data[3]);
    if (ver != version) { memzero(node_data, 78); return -3; }
    if (node_data[45]) { memzero(node_data, 78); return -2; }
    memcpy(node->private_key, node_data + 46, 32);
    memzero(node->public_key, sizeof(node->public_key));
    node->is_public_key_set = false;
    node->depth = node_data[4];
    if (fingerprint) {
        *fingerprint =
            ((uint32_t)node_data[5] << 24) |
            ((uint32_t)node_data[6] << 16) |
            ((uint32_t)node_data[7] <<  8) |
            ((uint32_t)node_data[8]);
    }
    node->child_num =
        ((uint32_t)node_data[9]  << 24) |
        ((uint32_t)node_data[10] << 16) |
        ((uint32_t)node_data[11] <<  8) |
        ((uint32_t)node_data[12]);
    memcpy(node->chain_code, node_data + 13, 32);
    memzero(node_data, sizeof(node_data));
    return 0;
}

int hdnode_get_address_raw(HDNode *node,
                            uint32_t version,
                            uint8_t *addr_raw)
{
    (void)version;
    if (hdnode_fill_public_key(node) != 0) return 1;
    // MONEU: address = pubkey bytes (Ed25519)
    memcpy(addr_raw, node->public_key + 1, 32);
    return 0;
}

int hdnode_get_address(HDNode *node,
                        uint32_t version,
                        char *addr,
                        int addrsize)
{
    (void)version;
    if (hdnode_fill_public_key(node) != 0) return 1;
    // MONEU: Base58 encode raw pubkey
    size_t b58sz = (size_t)addrsize;
    if (!b58enc(addr, &b58sz,
                node->public_key + 1, 32)) return 1;
    return 0;
}
