// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "script.h"

#include <cstring>

namespace MONEU {

Script& Script::operator<<(opcodetype opcode) {
    push_back(static_cast<uint8_t>(opcode));
    return *this;
}

Script& Script::PushData(const uint8_t* data, size_t len) {
    if (len == 0) {
        push_back(static_cast<uint8_t>(OP_0));
        return *this;
    }
    if (len <= 75) {
        push_back(static_cast<uint8_t>(len));
    } else if (len <= 0xff) {
        push_back(static_cast<uint8_t>(OP_PUSHDATA1));
        push_back(static_cast<uint8_t>(len));
    } else if (len <= 0xffff) {
        push_back(static_cast<uint8_t>(OP_PUSHDATA2));
        push_back(static_cast<uint8_t>(len & 0xff));
        push_back(static_cast<uint8_t>((len >> 8) & 0xff));
    } else {
        push_back(static_cast<uint8_t>(OP_PUSHDATA4));
        push_back(static_cast<uint8_t>(len & 0xff));
        push_back(static_cast<uint8_t>((len >> 8) & 0xff));
        push_back(static_cast<uint8_t>((len >> 16) & 0xff));
        push_back(static_cast<uint8_t>((len >> 24) & 0xff));
    }
    insert(end(), data, data + len);
    return *this;
}

Script& Script::PushData(const std::vector<uint8_t>& data) {
    return PushData(data.data(), data.size());
}

bool Script::GetOp(size_t& pc, opcodetype& opcodeRet,
                   std::vector<uint8_t>& vchRet) const {
    opcodeRet = OP_INVALIDOPCODE;
    vchRet.clear();
    if (pc >= size()) return false;

    uint8_t opcode = (*this)[pc++];

    // Direct pushes and the PUSHDATA family carry a payload; everything else
    // is a bare opcode.
    if (opcode >= 0x01 && opcode <= 0x4b) {
        size_t len = opcode;
        if (pc + len > size()) return false;
        vchRet.assign(begin() + pc, begin() + pc + len);
        pc += len;
        // A direct push has no named opcode; report the raw byte value so the
        // caller can still see the push size if it wants to.
        opcodeRet = static_cast<opcodetype>(opcode);
        return true;
    }
    if (opcode == OP_PUSHDATA1) {
        if (pc + 1 > size()) return false;
        size_t len = (*this)[pc++];
        if (pc + len > size()) return false;
        vchRet.assign(begin() + pc, begin() + pc + len);
        pc += len;
        opcodeRet = OP_PUSHDATA1;
        return true;
    }
    if (opcode == OP_PUSHDATA2) {
        if (pc + 2 > size()) return false;
        size_t len = static_cast<size_t>((*this)[pc]) |
                     (static_cast<size_t>((*this)[pc + 1]) << 8);
        pc += 2;
        if (pc + len > size()) return false;
        vchRet.assign(begin() + pc, begin() + pc + len);
        pc += len;
        opcodeRet = OP_PUSHDATA2;
        return true;
    }
    if (opcode == OP_PUSHDATA4) {
        if (pc + 4 > size()) return false;
        size_t len = static_cast<size_t>((*this)[pc]) |
                     (static_cast<size_t>((*this)[pc + 1]) << 8) |
                     (static_cast<size_t>((*this)[pc + 2]) << 16) |
                     (static_cast<size_t>((*this)[pc + 3]) << 24);
        pc += 4;
        if (len > MAX_SCRIPT_SIZE) return false;
        if (pc + len > size()) return false;
        vchRet.assign(begin() + pc, begin() + pc + len);
        pc += len;
        opcodeRet = OP_PUSHDATA4;
        return true;
    }

    opcodeRet = static_cast<opcodetype>(opcode);
    return true;
}

bool Script::IsUnspendable() const {
    return (!empty() && (*this)[0] == static_cast<uint8_t>(OP_RETURN)) ||
           size() > MAX_SCRIPT_SIZE;
}

bool Script::IsPayToPubkeyHash(bytes32* hashOut) const {
    // Exact template, byte for byte:
    //   OP_DUP OP_SHA256 0x20 <32 bytes> OP_EQUALVERIFY OP_CHECKSIG
    // Total length 37. Anything longer, shorter or reordered is not the
    // payment template.
    if (size() != 37) return false;
    if ((*this)[0]  != static_cast<uint8_t>(OP_DUP))         return false;
    if ((*this)[1]  != static_cast<uint8_t>(OP_SHA256))      return false;
    if ((*this)[2]  != 0x20)                                 return false;
    if ((*this)[35] != static_cast<uint8_t>(OP_EQUALVERIFY)) return false;
    if ((*this)[36] != static_cast<uint8_t>(OP_CHECKSIG))    return false;
    if (hashOut) {
        std::memcpy(hashOut->data(), data() + 3, 32);
    }
    return true;
}

TxoutType Solver(const Script& scriptPubKey,
                 std::vector<std::vector<uint8_t>>& solutions) {
    solutions.clear();

    bytes32 hash;
    if (scriptPubKey.IsPayToPubkeyHash(&hash)) {
        solutions.emplace_back(hash.begin(), hash.end());
        return TxoutType::PUBKEYHASH;
    }

    // Data carrier: OP_RETURN followed exclusively by pushes. The pushed
    // chunks are concatenated into a single solution so the caller can apply
    // one size limit to the total payload regardless of how it was split.
    if (!scriptPubKey.empty() &&
        scriptPubKey[0] == static_cast<uint8_t>(OP_RETURN)) {
        std::vector<uint8_t> payload;
        size_t pc = 1;
        opcodetype opcode;
        std::vector<uint8_t> chunk;
        while (pc < scriptPubKey.size()) {
            if (!scriptPubKey.GetOp(pc, opcode, chunk)) {
                return TxoutType::NONSTANDARD;
            }
            bool isPush =
                opcode == OP_0 ||
                (opcode >= 0x01 && opcode <= 0x4b) ||
                opcode == OP_PUSHDATA1 ||
                opcode == OP_PUSHDATA2 ||
                opcode == OP_PUSHDATA4;
            if (!isPush) return TxoutType::NONSTANDARD;
            payload.insert(payload.end(), chunk.begin(), chunk.end());
        }
        solutions.push_back(payload);
        return TxoutType::NULL_DATA;
    }

    return TxoutType::NONSTANDARD;
}

Script CreatePayToPubkeyHash(const bytes32& pubkeyHash) {
    Script script;
    script << OP_DUP << OP_SHA256;
    script.PushData(pubkeyHash.data(), pubkeyHash.size());
    script << OP_EQUALVERIFY << OP_CHECKSIG;
    return script;
}

Script CreateNullData(const std::vector<uint8_t>& data) {
    Script script;
    script << OP_RETURN;
    script.PushData(data);
    return script;
}

bool ExtractPubkeyHash(const Script& scriptPubKey, bytes32& hashOut) {
    return scriptPubKey.IsPayToPubkeyHash(&hashOut);
}

}
