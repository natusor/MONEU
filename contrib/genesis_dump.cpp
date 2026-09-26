// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "primitives/block.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static std::string RunCli(const std::string& cli, const std::string& args) {
    const std::string cmd = cli + " " + args + " 2>/dev/null";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return std::string();
    std::string out;
    char buf[256];
    while (fgets(buf, sizeof(buf), p)) out += buf;
    pclose(p);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                            out.back() == ' '))
        out.pop_back();
    return out;
}

static std::string ToHex(const PNC::bytes32& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (size_t i = 0; i < h.size(); ++i) {
        s += d[h[i] >> 4];
        s += d[h[i] & 0x0F];
    }
    return s;
}

int main(int argc, char** argv) {
    const std::string cli = (argc > 1) ? argv[1]
                                       : "./build/src/moneu-cli";

    MONEU::Block genesis = NetParams::BuildGenesisBlock();
    const std::vector<uint8_t> raw = genesis.Serialize();
    const std::string localHash = ToHex(genesis.GetHeader().GetHash());

    const std::string nodeHash = RunCli(cli, "getblockhash 0");
    const std::string height   = RunCli(cli, "getblockcount");

    std::printf("MONEU Genesis Block\n");
    std::printf("Raw Hex Version\n\n");

    for (size_t off = 0; off < raw.size(); off += 16) {
        std::printf("%08zX  ", off);
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < raw.size()) std::printf(" %02X", raw[off + i]);
            else                      std::printf("   ");
            if (i == 7) std::printf(" ");
        }
        std::printf("  ");
        for (size_t i = 0; i < 16 && off + i < raw.size(); ++i) {
            const uint8_t c = raw[off + i];
            std::printf("%c", (c >= 32 && c < 127) ? (char)c : '.');
        }
        std::printf("\n");
    }

    std::printf("\nbytes            %zu\n", raw.size());
    std::printf("hash             %s\n", localHash.c_str());

    if (nodeHash.empty()) {
        std::printf("node             not reachable, hash not verified\n");
        return 2;
    }
    std::printf("node block 0     %s\n", nodeHash.c_str());
    std::printf("node height      %s\n", height.c_str());
    if (nodeHash == localHash) {
        std::printf("\nMATCH. This is the genesis block the node has on chain.\n");
        return 0;
    }
    std::printf("\nMISMATCH. The node has a different genesis block.\n");
    return 1;
}
