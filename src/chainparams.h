// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MONEU_CHAINPARAMS_H
#define MONEU_CHAINPARAMS_H

#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace PNC {
    using bytes32 = std::array<uint8_t, 32>;
}

namespace MONEU {
    class Block;
}

namespace NetParams {

extern const uint8_t  MAINNET_MAGIC[4];
extern const char*    NETWORK_ID;
extern const char*    USER_AGENT;

extern const uint16_t DEFAULT_PORT;
extern const uint16_t RPC_PORT;

extern const uint8_t  PUBKEY_ADDRESS_PREFIX;
extern const uint8_t  SCRIPT_ADDRESS_PREFIX;
extern const uint8_t  SECRET_KEY_PREFIX;
extern const uint8_t  EXT_PUBLIC_KEY_PREFIX[4];
extern const uint8_t  EXT_SECRET_KEY_PREFIX[4];

extern const char*     GENESIS_MESSAGE;
extern const uint64_t  GENESIS_TIMESTAMP;
extern const uint32_t  GENESIS_VERSION;
extern const int64_t   GENESIS_REWARD;
extern const uint32_t  GENESIS_NONCE;

extern const int64_t   COIN;
extern const int64_t   MAX_MONEY;
extern const int64_t   INITIAL_SUBSIDY;
extern const uint64_t  HALVING_INTERVAL;
extern const uint64_t  LAST_SUBSIDY_HEIGHT;

extern const uint64_t  BLOCK_TIME_TARGET;

extern const uint32_t  POW_LIMIT_COMPACT;
extern const uint32_t  DIFFICULTY_ADJUSTMENT_INTERVAL;
extern const uint64_t  POW_TARGET_TIMESPAN;
extern const uint32_t  POW_MIN_TIMESPAN_PERCENT;
extern const uint32_t  POW_MAX_TIMESPAN_PERCENT;

extern const uint32_t  COINBASE_MATURITY;
extern const uint32_t  MAX_BLOCK_SIZE;
extern const uint32_t  MAX_OP_RETURN_SIZE;

extern const int64_t   MIN_FEE_PER_BYTE;
extern const int64_t   MIN_TX_FEE;
extern const int64_t   DUST_THRESHOLD;

static const uint32_t NOISE_LEAF_COUNT_VALUE = 1048576;
extern const uint32_t  NOISE_LEAF_COUNT;

static const size_t NOISE_FILE_BYTES =
    (size_t)NOISE_LEAF_COUNT_VALUE * 32u;

extern const uint32_t REVEAL_WINDOW_BLOCKS;

extern const uint32_t  MAX_OUTBOUND_CONNECTIONS;
extern const uint32_t  MAX_INBOUND_CONNECTIONS;
extern const uint32_t  MAX_TOTAL_CONNECTIONS;
extern const uint32_t  PEER_DISCOVERY_TIMEOUT;

struct Checkpoint {
    uint64_t    height;
    const char* block_hash;
};

extern const Checkpoint MAINNET_CHECKPOINTS[];
extern const size_t     CHECKPOINT_COUNT;

extern const char* DNS_SEEDS[];
extern const size_t DNS_SEED_COUNT;

MONEU::Block  BuildGenesisBlock();
uint32_t      GetNetworkMagic();
bool          VerifyNetworkMagic(const uint8_t* magic);
PNC::bytes32  GetGenesisHash();
bool          IsCheckpoint(uint64_t height);
PNC::bytes32  GetCheckpointHash(uint64_t height);
std::vector<std::string> GetDNSSeeds();
std::vector<std::string> GetFixedSeeds();
PNC::bytes32  HexToBytes32(const char* hex);

uint64_t GetBlockSubsidy(uint64_t block_height);
bool     CheckMoneyRange(uint64_t nMoneyTotal);

} // namespace NetParams

#endif
