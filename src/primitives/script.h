// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_PRIMITIVES_SCRIPT_H
#define MONEU_PRIMITIVES_SCRIPT_H

#include "keys.h"
#include <vector>
#include <cstdint>
#include <cstddef>

namespace MONEU {

enum opcodetype : uint8_t {
    // Push operations. Byte values 0x01..0x4b push that many bytes directly.
    OP_0            = 0x00,
    OP_PUSHDATA1    = 0x4c,
    OP_PUSHDATA2    = 0x4d,
    OP_PUSHDATA4    = 0x4e,

    // Control
    OP_RETURN       = 0x6a,

    // Stack
    OP_DUP          = 0x76,

    // Bitwise logic
    OP_EQUAL        = 0x87,
    OP_EQUALVERIFY  = 0x88,

    // Crypto
    OP_SHA256       = 0xa8,
    OP_CHECKSIG     = 0xac,

    OP_INVALIDOPCODE = 0xff,
};

static const size_t MAX_SCRIPT_SIZE = 10000;

enum class TxoutType {
    NONSTANDARD,
    PUBKEYHASH,
    NULL_DATA,
};

class Script : public std::vector<uint8_t> {
public:
    Script() {}
    Script(const uint8_t* data, size_t len) : std::vector<uint8_t>(data, data + len) {}
    explicit Script(const std::vector<uint8_t>& bytes) : std::vector<uint8_t>(bytes) {}

    Script& operator<<(opcodetype opcode);

    Script& PushData(const uint8_t* data, size_t len);
    Script& PushData(const std::vector<uint8_t>& data);

    bool GetOp(size_t& pc, opcodetype& opcodeRet, std::vector<uint8_t>& vchRet) const;

    bool IsUnspendable() const;

    bool IsPayToPubkeyHash(bytes32* hashOut = nullptr) const;
};

TxoutType Solver(const Script& scriptPubKey,
                 std::vector<std::vector<uint8_t>>& solutions);

Script CreatePayToPubkeyHash(const bytes32& pubkeyHash);

Script CreateNullData(const std::vector<uint8_t>& data);

bool ExtractPubkeyHash(const Script& scriptPubKey, bytes32& hashOut);

} // namespace MONEU

#endif // MONEU_PRIMITIVES_SCRIPT_H
