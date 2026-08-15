// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "block_undo.h"
#include <cstring>
#include <stdexcept>

namespace MONEU {
namespace storage {

static void WriteLE32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(value & 0xFF);
    out.push_back((value >> 8) & 0xFF);
    out.push_back((value >> 16) & 0xFF);
    out.push_back((value >> 24) & 0xFF);
}

static uint32_t ReadLE32(const uint8_t* data, size_t& offset) {
    uint32_t value = (uint32_t)data[offset] |
                     ((uint32_t)data[offset + 1] << 8) |
                     ((uint32_t)data[offset + 2] << 16) |
                     ((uint32_t)data[offset + 3] << 24);
    offset += 4;
    return value;
}

static const size_t COIN_BLOB_SIZE = 8 + 4 + 1 + 1 + 32;

static void WriteCoin(std::vector<uint8_t>& out, const Coin& c) {
    uint64_t v = (uint64_t)c.value;
    for (int i = 0; i < 8; i++) out.push_back((v >> (8 * i)) & 0xFF);
    WriteLE32(out, c.height);
    out.push_back(c.isCoinbase ? 1 : 0);
    out.push_back(c.isSpent ? 1 : 0);
    out.insert(out.end(), c.pubkeyHash.begin(), c.pubkeyHash.end());
}

static Coin ReadCoin(const uint8_t* data, size_t& offset) {
    Coin c;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)data[offset + i]) << (8 * i);
    offset += 8;
    c.value = (int64_t)v;
    c.height = ReadLE32(data, offset);
    c.isCoinbase = data[offset++] != 0;
    c.isSpent = data[offset++] != 0;
    std::memcpy(c.pubkeyHash.data(), data + offset, 32);
    offset += 32;
    return c;
}

std::vector<uint8_t> BlockUndo::Serialize() const {
    std::vector<uint8_t> out;
    WriteLE32(out, (uint32_t)txUndo.size());
    for (const auto& tu : txUndo) {
        WriteLE32(out, (uint32_t)tu.spentCoins.size());
        for (const auto& c : tu.spentCoins) {
            WriteCoin(out, c);
        }
    }

    return out;
}

BlockUndo BlockUndo::Deserialize(const uint8_t* data, size_t len) {
    BlockUndo undo;
    size_t offset = 0;
    if (len < 4) {
        throw std::runtime_error("BlockUndo: data too short");
    }
    uint32_t txCount = ReadLE32(data, offset);
    if (txCount > Block::MAX_TRANSACTIONS) {
        throw std::runtime_error("BlockUndo: transaction count implausible");
    }
    undo.txUndo.reserve(txCount);
    for (uint32_t i = 0; i < txCount; i++) {
        if (offset + 4 > len) {
            throw std::runtime_error("BlockUndo: truncated at input count");
        }
        uint32_t coinCount = ReadLE32(data, offset);
        if (coinCount > Block::MAX_TRANSACTIONS) {
            throw std::runtime_error("BlockUndo: coin count implausible");
        }
        if (offset + (size_t)coinCount * COIN_BLOB_SIZE > len) {
            throw std::runtime_error("BlockUndo: truncated inside coins");
        }
        TxUndo tu;
        tu.spentCoins.reserve(coinCount);
        for (uint32_t j = 0; j < coinCount; j++) {
            tu.spentCoins.push_back(ReadCoin(data, offset));
        }
        undo.txUndo.push_back(std::move(tu));
    }

    if (offset + 4 > len) return undo;

    return undo;
}

} // namespace storage
} // namespace MONEU
