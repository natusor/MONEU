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

static void WriteLE64(std::vector<uint8_t>& out, uint64_t value) {
    for (int b = 0; b < 8; ++b) {
        out.push_back((uint8_t)((value >> (8 * b)) & 0xFF));
    }
}

static uint64_t ReadLE64(const uint8_t* data, size_t& offset) {
    uint64_t value = 0;
    for (int b = 7; b >= 0; --b) {
        value = (value << 8) | (uint64_t)data[offset + b];
    }
    offset += 8;
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

    WriteLE32(out, (uint32_t)revealUndo.size());
    for (const auto& ru : revealUndo) {
        out.insert(out.end(), ru.txid.begin(), ru.txid.end());
        WriteLE32(out, ru.pendingHeight);
        WriteLE64(out, ru.fee);
        const std::vector<uint8_t> ruTx = ru.tx.Serialize();
        WriteLE32(out, (uint32_t)ruTx.size());
        out.insert(out.end(), ruTx.begin(), ruTx.end());
        WriteLE32(out, (uint32_t)ru.spentCoins.size());
        for (const auto& c : ru.spentCoins) {
            WriteCoin(out, c);
        }
    }

    WriteLE32(out, (uint32_t)expiryUndo.size());
    for (const auto& eu : expiryUndo) {
        out.insert(out.end(), eu.txid.begin(), eu.txid.end());
        WriteLE32(out, eu.pendingHeight);
        WriteLE64(out, eu.fee);
        const std::vector<uint8_t> txData = eu.tx.Serialize();
        WriteLE32(out, (uint32_t)txData.size());
        out.insert(out.end(), txData.begin(), txData.end());
        WriteLE32(out, (uint32_t)eu.spentCoins.size());
        for (const auto& c : eu.spentCoins) {
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

    uint32_t revealCount = ReadLE32(data, offset);
    if (revealCount > Block::MAX_REVEALS) {
        throw std::runtime_error("BlockUndo: reveal count implausible");
    }
    undo.revealUndo.reserve(revealCount);
    for (uint32_t i = 0; i < revealCount; i++) {
        if (offset + 32 + 4 + 8 + 4 > len) {
            throw std::runtime_error("BlockUndo: truncated in reveal undo");
        }
        RevealUndo ru;
        std::memcpy(ru.txid.data(), data + offset, 32);
        offset += 32;
        ru.pendingHeight = ReadLE32(data, offset);
        ru.fee = (int64_t)ReadLE64(data, offset);
        uint32_t ruTxLen = ReadLE32(data, offset);
        if (ruTxLen == 0 || offset + ruTxLen > len) {
            throw std::runtime_error("BlockUndo: truncated reveal transaction");
        }
        ru.tx = Transaction::Deserialize(data + offset, ruTxLen);
        offset += ruTxLen;
        if (offset + 4 > len) {
            throw std::runtime_error("BlockUndo: truncated at reveal coins");
        }
        uint32_t coinCount = ReadLE32(data, offset);
        if (coinCount > Transaction::MAX_INPUTS) {
            throw std::runtime_error("BlockUndo: reveal coin count implausible");
        }
        if (offset + (size_t)coinCount * COIN_BLOB_SIZE > len) {
            throw std::runtime_error("BlockUndo: truncated inside reveal coins");
        }
        ru.spentCoins.reserve(coinCount);
        for (uint32_t j = 0; j < coinCount; j++) {
            ru.spentCoins.push_back(ReadCoin(data, offset));
        }
        undo.revealUndo.push_back(std::move(ru));
    }

    if (offset + 4 > len) return undo;

    uint32_t expiryCount = ReadLE32(data, offset);
    if (expiryCount > Block::MAX_TRANSACTIONS) {
        throw std::runtime_error("BlockUndo: expiry count implausible");
    }
    undo.expiryUndo.reserve(expiryCount);
    for (uint32_t i = 0; i < expiryCount; i++) {
        if (offset + 32 + 4 + 8 + 4 > len) {
            throw std::runtime_error("BlockUndo: truncated in expiry undo");
        }
        ExpiryUndo eu;
        std::memcpy(eu.txid.data(), data + offset, 32);
        offset += 32;
        eu.pendingHeight = ReadLE32(data, offset);
        eu.fee = (int64_t)ReadLE64(data, offset);
        uint32_t txLen = ReadLE32(data, offset);
        if (txLen == 0 || offset + txLen > len) {
            throw std::runtime_error("BlockUndo: truncated expiry transaction");
        }
        eu.tx = Transaction::Deserialize(data + offset, txLen);
        offset += txLen;
        if (offset + 4 > len) {
            throw std::runtime_error("BlockUndo: truncated at expiry coins");
        }
        uint32_t coinCount = ReadLE32(data, offset);
        if (coinCount > Transaction::MAX_INPUTS) {
            throw std::runtime_error("BlockUndo: expiry coin count implausible");
        }
        if (offset + (size_t)coinCount * COIN_BLOB_SIZE > len) {
            throw std::runtime_error("BlockUndo: truncated inside expiry coins");
        }
        eu.spentCoins.reserve(coinCount);
        for (uint32_t j = 0; j < coinCount; j++) {
            eu.spentCoins.push_back(ReadCoin(data, offset));
        }
        undo.expiryUndo.push_back(std::move(eu));
    }
    return undo;
}

} // namespace storage
} // namespace MONEU
