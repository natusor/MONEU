// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cerrno>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>

#include <nlohmann/json.hpp>

#include "wallet/noise_generator.h"
#include "wallet/noise_tree.h"
#include "wallet/noise_store.h"
#include "primitives/keys.h"
#include "chainparams.h"

using json = nlohmann::json;

static std::string gRPCHost     = "127.0.0.1";
static int         gRPCPort     = 8328;
static bool        gRPCPortFromArgs = false;
static std::string gRPCUser     = "";
static std::string gRPCPassword = "";
static std::string gDataDir     = "";
static bool        gPretty      = true;

static const std::string B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static std::string Base64Encode(
    const std::string& in)
{
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(
                B64_CHARS[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(
            B64_CHARS[((val << 8) >>
                       (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

static void ReadNodeConfig(const std::string& dataDir) {
    if (dataDir.empty()) return;
    std::ifstream f(dataDir + "/moneu.conf");
    if (!f.is_open()) return;

    std::string line;
    while (std::getline(f, line)) {
        size_t hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        auto trim = [](std::string& v) {
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
                v.erase(v.begin());
            while (!v.empty() && (v.back() == ' ' || v.back() == '\t' ||
                                  v.back() == '\r' || v.back() == '\n'))
                v.pop_back();
        };
        trim(key);
        trim(val);
        if (val.empty()) continue;
        if (key == "rpcuser" && gRPCUser.empty())
            gRPCUser = val;
        else if (key == "rpcpassword" && gRPCPassword.empty())
            gRPCPassword = val;
        else if (key == "rpcport" && !gRPCPortFromArgs) {
            int p = std::atoi(val.c_str());
            if (p > 0 && p < 65536) gRPCPort = p;
        }
    }
}

static bool ReadCookieFile(
    const std::string& dataDir)
{
    std::string cookiePath =
        dataDir + "/.rpc.cookie";
    std::ifstream f(cookiePath);
    if (!f.is_open()) return false;

    std::string line;
    if (!std::getline(f, line)) return false;

    size_t colonPos = line.find(':');
    if (colonPos == std::string::npos)
        return false;

    gRPCUser     = line.substr(0, colonPos);
    gRPCPassword = line.substr(colonPos + 1);
    return true;
}

static std::string GetDefaultDataDir() {
    if (!gDataDir.empty()) return gDataDir;
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) return "";
    return std::string(home) + "/.moneu";
}

static std::string SendRPCRequest(
    const std::string& body)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "error: cannot create socket\n";
        exit(1);
    }

    struct timeval tv;
    tv.tv_sec  = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
               &tv, sizeof(tv));

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port   = htons(gRPCPort);
    if (inet_pton(AF_INET, gRPCHost.c_str(),
                  &server.sin_addr) <= 0) {
        std::cerr << "error: invalid host address\n";
        close(sock);
        exit(1);
    }

    if (connect(sock,
                (struct sockaddr*)&server,
                sizeof(server)) < 0) {
        std::cerr << "error: cannot connect to "
                  << gRPCHost << ":" << gRPCPort
                  << "\n"
                  << "Is moneud running?\n";
        close(sock);
        exit(1);
    }

    std::string auth = Base64Encode(
        gRPCUser + ":" + gRPCPassword);

    std::ostringstream req;
    req << "POST / HTTP/1.1\r\n"
        << "Host: " << gRPCHost << "\r\n"
        << "Authorization: Basic " << auth << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: "
        << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;

    std::string reqStr = req.str();
    if (send(sock, reqStr.c_str(),
             reqStr.size(), 0) < 0) {
        std::cerr << "error: send failed\n";
        close(sock);
        exit(1);
    }

    std::string response;
    char buf[4096];
    ssize_t n;
    while (true) {
        n = recv(sock, buf, sizeof(buf), 0);
        if (n > 0) {
            response.append(buf, static_cast<size_t>(n));
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(sock);

    size_t bodyStart = response.find("\r\n\r\n");
    if (bodyStart == std::string::npos) {
        std::cerr << "error: invalid HTTP response\n";
        exit(1);
    }
    return response.substr(bodyStart + 4);
}

static json CallRPC(
    const std::string& method,
    const json& params)
{
    json request;
    request["jsonrpc"] = "2.0";
    request["id"]      = 1;
    request["method"]  = method;
    request["params"]  = params;

    std::string body = request.dump();
    std::string responseStr = SendRPCRequest(body);

    try {
        return json::parse(responseStr);
    } catch (...) {
        std::cerr << "error: invalid JSON response\n";
        exit(1);
    }
}

static int PrintResult(const json& response) {
    if (response.contains("error") &&
        !response["error"].is_null()) {
        auto err = response["error"];
        std::cerr << "error: ";
        if (err.contains("message"))
            std::cerr << err["message"].get<std::string>();
        else
            std::cerr << err.dump();
        std::cerr << "\n";
        return 1;
    }

    if (!response.contains("result")) {
        std::cerr << "error: no result in response\n";
        return 1;
    }

    auto result = response["result"];

    if (result.is_null()) {
        return 0;
    } else if (result.is_string()) {
        std::cout << result.get<std::string>() << "\n";
    } else if (result.is_number_integer()) {
        std::cout << result.get<int64_t>() << "\n";
    } else if (result.is_number_float()) {
        std::cout << result.get<double>() << "\n";
    } else if (result.is_boolean()) {
        std::cout << (result.get<bool>()
            ? "true" : "false") << "\n";
    } else if (result.is_object() ||
               result.is_array()) {
        if (gPretty)
            std::cout << result.dump(4) << "\n";
        else
            std::cout << result.dump() << "\n";
    }

    return 0;
}

static void PrintUsage() {
    std::cout
        << "Usage: moneu-cli [options] <command> "
           "[parameters]\n\n"
        << "Options:\n"
        << "  -rpcuser=<user>      "
           "RPC user\n"
        << "  -rpcpassword=<password> "
           "RPC password\n"
        << "  -rpcport=<port>      "
           "RPC port (default: 8328)\n"
        << "  -datadir=<path>      "
           "Data directory\n\n"
        << "Node commands:\n"
        << "  stop                 "
           "Stop the node\n"
        << "  getinfo              "
           "Node information\n"
        << "  getblockcount        "
           "Current block height\n"
        << "  getblockchaininfo    "
           "Blockchain state\n"
        << "  getconnectioncount   "
           "Connection count\n"
        << "  getnetworkinfo       "
           "Network information\n"
        << "  uptime               "
           "Node uptime\n"
        << "  help                 "
           "List every command the node accepts\n\n"
        << "Blockchain commands:\n"
        << "  getbestblockhash     "
           "Hash of the current tip\n"
        << "  getblockhash <height> "
           "Hash of the block at that height\n"
        << "  getblock <hash>      "
           "Block data, including its transaction ids\n"
        << "  getrawtransaction <txid>  "
           "One transaction by id\n"
        << "  getdifficulty        "
           "Current difficulty as a number\n"
        << "  getmempoolinfo       "
           "Pending transactions and pool size\n\n"
        << "Network commands:\n"
        << "  addnode <ip:port>    "
           "Connect to a peer\n"
        << "  setnetworkactive <true|false>  "
           "Enable or disable networking\n"
        << "  getpeerinfo          "
           "Connected peers\n\n"
        << "Wallet commands:\n"
        << "  makenoise <password> "
           "Create the noise file (anti-quantum shield)\n"
        << "  createwallet <password> "
           "Create a new wallet\n"
        << "  loadwallet <password> "
           "Load the wallet\n"
        << "  walletunlock <password> "
           "Unlock the wallet\n"
        << "  walletlock           "
           "Lock the wallet\n"
        << "  getnewaddress        "
           "Generate a new address\n"
        << "  listaddresses        "
           "List all addresses\n"
        << "  getwalletinfo        "
           "Wallet status\n"
        << "  getbalance <address> "
           "Address balance\n"
        << "  dumpmnemonic <password> "
           "Show the mnemonic (SECRET!)\n"
        << "  dumpprivkey <address> <password>  "
           "Private key of one address (SECRET!)\n"
        << "  importseedphrase <seed phrase> <password>  "
           "Rebuild a wallet from its seed phrase\n"
        << "  rescanwallet  "
           "Find addresses this wallet's seed produces that hold coins\n"
        << "  importprivkey <privkey> <password> [label]  "
           "Take one private key into this wallet\n"
        << "  sendtoaddress <address> <amount> [fee] [message]  "
           "Send funds\n"
        << "  sendrawtransaction <hex>  "
           "Broadcast a prepared transaction\n\n"
        << "Mining commands:\n"
        << "  getmininginfo        "
           "PoW consensus status\n"
        << "  startmining <address> [threads]  "
           "Mine to that address\n"
        << "  stopmining           "
           "Stop mining\n\n"
        << "Examples:\n"
        << "  moneu-cli stop\n"
        << "  moneu-cli createwallet MyPassword123\n"
        << "  moneu-cli getnewaddress\n"
        << "  moneu-cli listaddresses\n"
        << "  moneu-cli getblockcount\n\n";
}

static const size_t   NOISE_FILE_BYTES = NetParams::NOISE_FILE_BYTES;
static const uint32_t NOISE_LEAF_COUNT = NetParams::NOISE_LEAF_COUNT_VALUE;

static_assert(NOISE_FILE_BYTES / 32u == NOISE_LEAF_COUNT,
              "noise file size must be exactly 32 bytes per leaf");

static std::string ToHex(const MONEU::bytes32& b) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (size_t i = 0; i < b.size(); ++i) {
        out.push_back(hex[(b[i] >> 4) & 0xF]);
        out.push_back(hex[b[i] & 0xF]);
    }
    return out;
}

static bool EnsureDir(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return (st.st_mode & S_IFDIR) != 0;
    }
    return mkdir(path.c_str(), 0700) == 0;
}

static int HandleMakeNoise(const std::string& passphrase) {
    if (passphrase.size() < 8) {
        std::cerr << "error: passphrase must be at least 8 characters\n";
        return 1;
    }

    std::string dataDir = GetDefaultDataDir();
    if (dataDir.empty()) {
        std::cerr << "error: cannot determine data directory\n";
        return 1;
    }
    if (!EnsureDir(dataDir)) {
        std::cerr << "error: cannot create " << dataDir << "\n";
        return 1;
    }
    std::string walletDir = dataDir + "/wallet";
    if (!EnsureDir(walletDir)) {
        std::cerr << "error: cannot create " << walletDir << "\n";
        return 1;
    }
    std::string noisePath = walletDir + "/noise.dat";

    std::cout << "Do NOT shut down and do NOT interrupt\n"
              << "Your hardware is stressed on purpose to gather "
                 "physical entropy.\n"
              << std::flush;

    MONEU::NoiseGenerator::ProgressFn progress =
        [](size_t produced, size_t target) {
            static size_t lastMark = 0;
            size_t mb = produced / (1024 * 1024);
            if (produced >= target || mb >= lastMark + 32) {
                lastMark = mb;
                std::cout << "  " << mb << " / "
                          << (target / (1024 * 1024)) << " MB\n"
                          << std::flush;
            }
        };

    {
        std::string why;
        if (!MONEU::NoiseGenerator::CheckTimingSources(why)) {
            std::cerr << "makenoise: refusing to generate - " << why
                      << "\n";
            return 1;
        }
    }

    std::vector<uint8_t> noise =
        MONEU::NoiseGenerator::Generate(NOISE_FILE_BYTES, 0, progress);
    if (noise.size() != NOISE_FILE_BYTES) {
        std::cerr << "error: noise generation produced wrong size\n";
        return 1;
    }

    MONEU::bytes32 kps;
    if (!MONEU::NoiseTreeBuilder::ComputeRoot(
            noise.data(), noise.size(), NOISE_LEAF_COUNT, walletDir, kps)) {
        std::cerr << "error: failed to compute KPS\n";
        return 1;
    }

    if (!MONEU::NoiseStore::EncryptToFile(noise, passphrase, noisePath)) {
        std::cerr << "error: failed to write noise file\n";
        return 1;
    }

    double mbps = MONEU::NoiseGenerator::LastBytesPerSecond() / (1024.0 * 1024.0);

    std::cout << "\nDone. Noise shield (OTP file) created.\n"
              << "  KPS (public key of noise): " << ToHex(kps) << "\n"
              << "  File: " << noisePath << "\n"
              << "  Size: " << (NOISE_FILE_BYTES / (1024 * 1024)) << " MB"
              << "  (" << NOISE_LEAF_COUNT << " leaves)\n";
    std::cout.setf(std::ios::fixed);
    std::cout.precision(2);
    std::cout << "  Rate: " << mbps << " MB/s\n\n"
              << "Wait 10 seconds before creating addresses for this "
                 "wallet.\n"
              << "Copy the noise file to TWO separate drives - it is "
                 "REQUIRED to sign transactions.\n"
              << "Lose it and you lose access to funds, even with your "
                 "seed.\n"
              << std::flush;
    return 0;
}

static bool IsTextArgument(const std::string& command, size_t pos) {
    if (command == "createwallet"  || command == "loadwallet" ||
        command == "walletunlock"  || command == "dumpmnemonic" ||
        command == "makenoise") {
        return pos == 0;
    }
    if (command == "dumpprivkey")  return pos == 0 || pos == 1;
    if (command == "importseedphrase") return pos == 0 || pos == 1;
    if (command == "importprivkey") return pos == 0 || pos == 1 || pos == 2;
    if (command == "getbalance")   return pos == 0;
    if (command == "sendtoaddress") {
        return pos == 0 || pos == 2 || pos == 3;
    }
    if (command == "startmining")  return pos == 0;
    if (command == "getblock" || command == "getrawtransaction" ||
        command == "sendrawtransaction" || command == "addnode") {
        return pos == 0;
    }
    return false;
}

int main(int argc, char* argv[]) {
    std::vector<std::string> args(
        argv + 1, argv + argc);

    if (args.empty() ||
        args[0] == "-help" ||
        args[0] == "--help" ||
        args[0] == "-h") {
        PrintUsage();
        return 0;
    }

    std::vector<std::string> cmdArgs;
    for (const auto& arg : args) {
        if (arg.find("-rpcuser=") == 0) {
            gRPCUser = arg.substr(9);
        } else if (arg.find("-rpcpassword=") == 0) {
            gRPCPassword = arg.substr(13);
        } else if (arg.find("-rpcport=") == 0) {
            gRPCPort = std::stoi(arg.substr(9));
            gRPCPortFromArgs = true;
        } else if (arg.find("-rpchost=") == 0) {
            gRPCHost = arg.substr(9);
        } else if (arg.find("-datadir=") == 0) {
            gDataDir = arg.substr(9);
        } else if (arg == "-compact") {
            gPretty = false;
        } else {
            cmdArgs.push_back(arg);
        }
    }

    if (cmdArgs.empty()) {
        PrintUsage();
        return 1;
    }

    if (cmdArgs[0] == "makenoise") {
        if (cmdArgs.size() < 2) {
            std::cerr << "usage: moneu-cli makenoise <passphrase>\n";
            return 1;
        }
        return HandleMakeNoise(cmdArgs[1]);
    }

    ReadNodeConfig(GetDefaultDataDir());

    if (gRPCUser.empty() || gRPCPassword.empty()) {
        std::string dataDir = GetDefaultDataDir();
        if (!dataDir.empty()) {
            if (!ReadCookieFile(dataDir)) {
                std::cerr << "error: missing RPC credentials\n"
                          << "Provide -rpcuser and "
                             "-rpcpassword\n"
                          << "or make sure the node "
                             "is running\n"
                          << "(looking for: "
                          << dataDir
                          << "/.rpc.cookie)\n";
                return 1;
            }
        }
    }

    std::string command = cmdArgs[0];

    if (command == "sendtoaddress" && cmdArgs.size() >= 5) {
        const std::string& msg = cmdArgs[4];
        bool isHex = (msg.size() % 2 == 0) && !msg.empty();
        for (size_t i = 0; isHex && i < msg.size(); ++i) {
            const char c = msg[i];
            isHex = (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F');
        }
        if (!isHex) {
            static const char* hexDigits = "0123456789abcdef";
            std::string encoded;
            encoded.reserve(msg.size() * 2);
            for (size_t i = 0; i < msg.size(); ++i) {
                const unsigned char b = static_cast<unsigned char>(msg[i]);
                encoded.push_back(hexDigits[(b >> 4) & 0x0F]);
                encoded.push_back(hexDigits[b & 0x0F]);
            }
            cmdArgs[4] = encoded;
        }
        if (cmdArgs[4].size() / 2 > 300) {
            std::cerr << "error: message is "
                      << (cmdArgs[4].size() / 2)
                      << " bytes; the limit is 300\n";
            return 1;
        }
    }

    json params = json::array();
    for (size_t i = 1; i < cmdArgs.size(); ++i) {
        if (IsTextArgument(command, i - 1)) {
            params.push_back(cmdArgs[i]);
            continue;
        }
        try {
            params.push_back(json::parse(cmdArgs[i]));
        } catch (...) {
            params.push_back(cmdArgs[i]);
        }
    }


    const bool reportNoise = (command == "sendtoaddress");

    json response = CallRPC(command, params);
    const int printed = PrintResult(response);

    if (reportNoise && printed == 0 &&
        response.contains("result") && !response["result"].is_null()) {
        try {
            const json info = CallRPC("getwalletinfo", json::array());
            if (info.contains("result") && info["result"].is_object()) {
                const json& w = info["result"];
                if (w.contains("noise_leaves_remaining") &&
                    w.contains("noise_leaves_total")) {
                    const uint64_t left =
                        w["noise_leaves_remaining"].get<uint64_t>();
                    const uint64_t total =
                        w["noise_leaves_total"].get<uint64_t>();
                    std::cout << "\nNoise file: " << left << " of " << total
                              << " single-use leaves left.\n";
                    if (left == 0) {
                        std::cout
                            << "WARNING: none are left. No further transfer "
                               "can be authorised from this wallet.\n";
                    } else if (left <= 100) {
                        std::cout
                            << "WARNING: create a new wallet and move the "
                               "funds while there are still leaves to do it "
                               "with.\n";
                    } else if (left <= 10000) {
                        std::cout
                            << "Plan a move to a new wallet before they run "
                               "out.\n";
                    }
                }
            }
        } catch (...) {
        }
    }
    return printed;
}
