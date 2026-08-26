// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include <cstring>
#include <algorithm>
#include <stdexcept>

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "primitives/script.h"

namespace NetParams {

const uint8_t MAINNET_MAGIC[4] = {0xB6, 0xFD, 0xFA, 0x84};
const char* NETWORK_ID = "moneu";
const char* USER_AGENT = "/MONEU:0.1.0/";

const uint16_t DEFAULT_PORT = 8327;
const uint16_t RPC_PORT = 8328;

const uint8_t PUBKEY_ADDRESS_PREFIX = 33;
const uint8_t SCRIPT_ADDRESS_PREFIX = 110;
const uint8_t SECRET_KEY_PREFIX = 183;
const uint8_t EXT_PUBLIC_KEY_PREFIX[4] = {0x03, 0xA0, 0x68, 0x13};
const uint8_t EXT_SECRET_KEY_PREFIX[4] = {0x03, 0xA0, 0x68, 0x6E};

const char* GENESIS_MESSAGE =
    "54686520477561726469616e205765656b6c792031342f4175672f323032362047"
    "6f6e6520726f6775653a20414920747269636b73206974732074657374657273";
const uint64_t GENESIS_TIMESTAMP = 1786724267;
const uint32_t GENESIS_VERSION = 1;
const int64_t GENESIS_REWARD = 7700000000LL;
const uint32_t GENESIS_NONCE = 1708084064U;

const char* GENESIS_REWARD_PUBKEYHASH_HEX =
    "8fb311b4e4a09e775d0e9910e2ff55325469e8b7a0b7085bd2fd1b0c80a316c5";

const int64_t COIN = 100000000;
const int64_t MAX_MONEY = 30000000 * COIN;
const int64_t INITIAL_SUBSIDY = 77 * COIN;
const uint64_t HALVING_INTERVAL = 194804;
const uint64_t LAST_SUBSIDY_HEIGHT = 33ULL * HALVING_INTERVAL;
const uint64_t BLOCK_TIME_TARGET = 600;

const uint32_t POW_LIMIT_COMPACT           = 0x1d00ffff;
const uint32_t DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;
const uint64_t POW_TARGET_TIMESPAN         = 2016ULL * 600ULL;
const uint32_t POW_MIN_TIMESPAN_PERCENT    = 80;
const uint32_t POW_MAX_TIMESPAN_PERCENT    = 400;

const uint32_t COINBASE_MATURITY = 50;
const uint32_t MAX_BLOCK_SIZE = 6 * 1024 * 1024;
const uint32_t MAX_OP_RETURN_SIZE = 300;

const int64_t MIN_FEE_PER_BYTE = 1;
const int64_t MIN_TX_FEE = 1000;
const int64_t DUST_THRESHOLD = 1000;

const uint32_t NOISE_LEAF_COUNT = NOISE_LEAF_COUNT_VALUE;

const uint32_t MAX_OUTBOUND_CONNECTIONS = 8;
const uint32_t MAX_INBOUND_CONNECTIONS = 117;
const uint32_t MAX_TOTAL_CONNECTIONS = 125;
const uint32_t PEER_DISCOVERY_TIMEOUT = 60;

const Checkpoint MAINNET_CHECKPOINTS[] = {
    {0, "00000000a03ce5faf3e74612dc86207af4b317a840cbeb0a2bb672475a04a9ea"},
    {1000, "00000000e1ae20a687641859f30eb371c120d313c1b7461b6a98811d03293136"}
};
const size_t CHECKPOINT_COUNT = sizeof(MAINNET_CHECKPOINTS) / sizeof(Checkpoint);

const char* DNS_SEEDS[] = {
    "seed1.moneu.network",
    "seed2.moneu.network",
    "seed3.moneu.network",
    "dnsseed.moneu.io"
};
const size_t DNS_SEED_COUNT = sizeof(DNS_SEEDS) / sizeof(char*);

const char* FIXED_SEEDS[] = {
    "135.181.255.219:8327"
};
const size_t FIXED_SEED_COUNT = sizeof(FIXED_SEEDS) / sizeof(char*);

PNC::bytes32 HexToBytes32(const char* hex) {
    PNC::bytes32 out;
    if (std::strlen(hex) != 64) {
        std::fill(out.begin(), out.end(), 0);
        return out;
    }
    for (size_t i = 0; i < 32; ++i) {
        char high = hex[2 * i];
        char low = hex[2 * i + 1];
        auto char_to_nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out[i] = (char_to_nibble(high) << 4) | char_to_nibble(low);
    }
    return out;
}

MONEU::Block BuildGenesisBlock() {
    PNC::bytes32 zero;
    zero.fill(0);

    MONEU::Transaction coinbase;

    MONEU::TxInput in;
    in.SetPrevTxHash(zero);
    in.SetOutputIndex(0xFFFFFFFFu);
    coinbase.AddInput(in);

    const PNC::bytes32 rewardHash =
        HexToBytes32(GENESIS_REWARD_PUBKEYHASH_HEX);
    MONEU::TxOutput reward(GENESIS_REWARD, rewardHash);
    coinbase.AddOutput(reward);

    const std::string fullMessage(GENESIS_MESSAGE);
    const std::vector<uint8_t> msg(fullMessage.begin(), fullMessage.end());
    MONEU::TxOutput msgOut(0, MONEU::CreateNullData(msg));
    coinbase.AddOutput(msgOut);

    return MONEU::BlockBuilder(GENESIS_VERSION)
        .SetPrevBlockHash(zero)
        .SetTimestamp(GENESIS_TIMESTAMP)
        .SetHeight(0)
        .SetBits(POW_LIMIT_COMPACT)
        .SetNonce(GENESIS_NONCE)
        .AddCoinbase(coinbase)
        .Build();
}

uint32_t GetNetworkMagic() {
    uint32_t magic;
    std::memcpy(&magic, MAINNET_MAGIC, sizeof(uint32_t));
    return magic;
}

bool VerifyNetworkMagic(const uint8_t* magic) {
    if (!magic) return false;
    return std::memcmp(magic, MAINNET_MAGIC, sizeof(MAINNET_MAGIC)) == 0;
}

PNC::bytes32 GetGenesisHash() {
    return HexToBytes32(
        "00000000a03ce5faf3e74612dc86207af4b317a840cbeb0a2bb672475a04a9ea");
}

bool IsCheckpoint(uint64_t height) {
    for (size_t i = 0; i < CHECKPOINT_COUNT; ++i) {
        if (MAINNET_CHECKPOINTS[i].height == height) {
            return true;
        }
    }
    return false;
}

PNC::bytes32 GetCheckpointHash(uint64_t height) {
    for (size_t i = 0; i < CHECKPOINT_COUNT; ++i) {
        if (MAINNET_CHECKPOINTS[i].height == height) {
            return HexToBytes32(MAINNET_CHECKPOINTS[i].block_hash);
        }
    }
    PNC::bytes32 empty_hash;
    std::fill(empty_hash.begin(), empty_hash.end(), 0);
    return empty_hash;
}

std::vector<std::string> GetDNSSeeds() {
    std::vector<std::string> seeds;
    seeds.reserve(DNS_SEED_COUNT);
    for (size_t i = 0; i < DNS_SEED_COUNT; ++i) {
        seeds.push_back(DNS_SEEDS[i]);
    }
    return seeds;
}

std::vector<std::string> GetFixedSeeds() {
    std::vector<std::string> seeds;
    seeds.reserve(FIXED_SEED_COUNT);
    for (size_t i = 0; i < FIXED_SEED_COUNT; ++i) {
        seeds.push_back(FIXED_SEEDS[i]);
    }
    return seeds;
}

uint64_t GetBlockSubsidy(uint64_t block_height) {
    const uint64_t halvings = block_height / HALVING_INTERVAL;
    if (halvings >= 64) return 0;
    return INITIAL_SUBSIDY >> halvings;
}

bool CheckMoneyRange(uint64_t nMoneyTotal) {
    return nMoneyTotal <= static_cast<uint64_t>(MAX_MONEY);
}

}
