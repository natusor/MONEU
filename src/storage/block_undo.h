// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_STORAGE_BLOCK_UNDO_H
#define MONEU_STORAGE_BLOCK_UNDO_H

#include "utxo_set.h"
#include "../primitives/block.h"
#include <vector>
#include <cstdint>

namespace MONEU {
namespace storage {

struct TxUndo {
    std::vector<Coin> spentCoins;
};

struct RevealUndo {
    bytes32           txid;
    uint32_t          pendingHeight;
    int64_t           fee;
    Transaction       tx;
    std::vector<Coin> spentCoins;

    RevealUndo() : pendingHeight(0), fee(0) { txid.fill(0); }
};

struct ExpiryUndo {
    bytes32           txid;
    uint32_t          pendingHeight;
    int64_t           fee;
    Transaction       tx;
    std::vector<Coin> spentCoins;

    ExpiryUndo() : pendingHeight(0), fee(0) { txid.fill(0); }
};

struct BlockUndo {
    std::vector<TxUndo> txUndo;

    std::vector<RevealUndo>  revealUndo;
    std::vector<ExpiryUndo>  expiryUndo;

    std::vector<uint8_t> Serialize() const;
    static BlockUndo Deserialize(const uint8_t* data, size_t len);
};

} // namespace storage
} // namespace MONEU

#endif // MONEU_STORAGE_BLOCK_UNDO_H
