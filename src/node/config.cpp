// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "config.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifndef WIN32
#include <sys/stat.h>
#endif

namespace MONEU {
namespace node {

static const uint32_t MAX_ALLOWED_CONNECTIONS  = 1000;
static const uint32_t MIN_ALLOWED_CONNECTIONS  = 1;
static const uint64_t MAX_DB_CACHE_SIZE        = 16384ULL * 1024 * 1024;
static const uint64_t MIN_DB_CACHE_SIZE        = 4ULL * 1024 * 1024;
static const uint64_t MAX_LOG_SIZE             = 1024ULL * 1024 * 1024;

static std::string Trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

static std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(),
                   result.begin(), ::tolower);
    return result;
}

Config::Config()
    : mLoaded(false)
{}

Config::Config(const fs::path& configFile)
    : mLoaded(false)
{
    Load(configFile);
}

bool Config::ParseLine(const std::string& line,
                        std::string& key,
                        std::string& value) const
{
    std::string trimmed = Trim(line);
    if (trimmed.empty()) return false;
    if (trimmed[0] == '#') return false;
    if (trimmed[0] == '[') return false;
    size_t pos = trimmed.find('=');
    if (pos == std::string::npos) return false;
    key   = Trim(trimmed.substr(0, pos));
    value = Trim(trimmed.substr(pos + 1));
    if (key.empty()) return false;
    return true;
}

std::string Config::GetValue(const std::string& key,
                              const std::string& defaultVal) const
{
    auto it = mRawValues.find(ToLower(key));
    if (it == mRawValues.end()) return defaultVal;
    return it->second;
}

int64_t Config::GetIntValue(const std::string& key, int64_t defaultVal) const {
    std::string val = GetValue(key, "");
    if (val.empty()) return defaultVal;
    try {
        return std::stoll(val);
    } catch (...) {
        std::cerr << "Config: invalid integer value for key '" << key << "'\n";
        return defaultVal;
    }
}

bool Config::GetBoolValue(const std::string& key, bool defaultVal) const {
    std::string val = ToLower(GetValue(key, ""));
    if (val.empty()) return defaultVal;
    if (val == "1" || val == "true" || val == "yes") return true;
    if (val == "0" || val == "false" || val == "no") return false;
    return defaultVal;
}

void Config::ApplyNetworkValues() {
    int64_t port = GetIntValue("port", NetParams::DEFAULT_PORT);
    if (port > 0 && port < 65536) {
        mNetwork.port = static_cast<uint16_t>(port);
    } else {
        std::cerr << "Config: invalid port value, using default "
                  << NetParams::DEFAULT_PORT << "\n";
        mNetwork.port = NetParams::DEFAULT_PORT;
    }
    int64_t rpcPort = GetIntValue("rpcport", NetParams::RPC_PORT);
    if (rpcPort > 0 && rpcPort < 65536) {
        mNetwork.rpcPort = static_cast<uint16_t>(rpcPort);
    } else {
        mNetwork.rpcPort = NetParams::RPC_PORT;
    }
    int64_t maxConn = GetIntValue("maxconnections",
                                   NetParams::MAX_TOTAL_CONNECTIONS);
    if (maxConn < MIN_ALLOWED_CONNECTIONS) {
        std::cerr << "Config: maxconnections too low, setting to "
                  << MIN_ALLOWED_CONNECTIONS << "\n";
        maxConn = MIN_ALLOWED_CONNECTIONS;
    }
    if (maxConn > MAX_ALLOWED_CONNECTIONS) {
        std::cerr << "Config: maxconnections " << maxConn
                  << " exceeds maximum " << MAX_ALLOWED_CONNECTIONS
                  << ", clamping!\n";
        maxConn = MAX_ALLOWED_CONNECTIONS;
    }
    mNetwork.maxConnections = static_cast<uint32_t>(maxConn);
    mNetwork.maxOutbound = std::min(
        static_cast<uint32_t>(
            GetIntValue("maxoutbound", NetParams::MAX_OUTBOUND_CONNECTIONS)),
        mNetwork.maxConnections
    );
    mNetwork.maxInbound = std::min(
        static_cast<uint32_t>(
            GetIntValue("maxinbound", NetParams::MAX_INBOUND_CONNECTIONS)),
        mNetwork.maxConnections
    );
    mNetwork.listen = GetBoolValue("listen", true);
    mNetwork.upnp   = GetBoolValue("upnp", false);
    mNetwork.externalIp = GetValue("externalip", "");
    const std::vector<std::string> addNodes = GetListValues("addnode");
    for (size_t i = 0; i < addNodes.size(); ++i) {
        if (!addNodes[i].empty()) mNetwork.addNodes.push_back(addNodes[i]);
    }
    const std::vector<std::string> connectNodes = GetListValues("connect");
    for (size_t i = 0; i < connectNodes.size(); ++i) {
        if (!connectNodes[i].empty())
            mNetwork.connectNodes.push_back(connectNodes[i]);
    }
}

void Config::ApplyRPCValues() {
    mRPC.rpcUser     = GetValue("rpcuser", "");
    mRPC.rpcPassword = GetValue("rpcpassword", "");
    if (mRPC.rpcUser.empty() || mRPC.rpcPassword.empty()) {
        std::cerr << "Config: WARNING - rpcuser or rpcpassword not set!\n";
        std::cerr << "Config: RPC will be disabled for security.\n";
        mRPC.rpcEnabled = false;
    } else {
        mRPC.rpcEnabled = true;
    }
    mRPC.rpcBindAddr = GetValue("rpcbind", "127.0.0.1");
    mRPC.rpcBindSet  = !GetValue("rpcbind", "").empty();
    int64_t rpcPort = GetIntValue("rpcport", NetParams::RPC_PORT);
    if (rpcPort > 0 && rpcPort < 65536) {
        mRPC.rpcPort = static_cast<uint16_t>(rpcPort);
    }
    const std::vector<std::string> allowIps = GetListValues("rpcallowip");
    for (size_t i = 0; i < allowIps.size(); ++i) {
        if (!allowIps[i].empty()) mRPC.rpcAllowIp.push_back(allowIps[i]);
    }
    mRPC.rpcAllowIpSet = !mRPC.rpcAllowIp.empty();
    if (mRPC.rpcAllowIp.empty()) {
        mRPC.rpcAllowIp.push_back("127.0.0.1");
    }
}

void Config::ApplyMiningValues() {
    mMining.enabled = GetBoolValue("mine", false);

    mMining.rewardAddress = GetValue("rewardaddress", "");
}

void Config::ApplyStorageValues() {
    int64_t cacheSize = GetIntValue("dbcache", 450) * 1024 * 1024;
    if (cacheSize < static_cast<int64_t>(MIN_DB_CACHE_SIZE)) {
        std::cerr << "Config: dbcache too small, setting to minimum 4MB\n";
        cacheSize = MIN_DB_CACHE_SIZE;
    }
    if (cacheSize > static_cast<int64_t>(MAX_DB_CACHE_SIZE)) {
        std::cerr << "Config: dbcache too large, clamping to 16384MB\n";
        cacheSize = MAX_DB_CACHE_SIZE;
    }
    mStorage.dbCacheSize = static_cast<uint64_t>(cacheSize);
    mStorage.pruneMode   = GetBoolValue("prune", false);
    mStorage.reindex     = GetBoolValue("reindex", false);
    mStorage.txIndex     = GetBoolValue("txindex", false);
    if (mStorage.pruneMode) {
        int64_t pruneTarget = GetIntValue("prunetarget", 550);
        if (pruneTarget < 550) {
            std::cerr << "Config: prunetarget too small, setting to 550MB\n";
            pruneTarget = 550;
        }
        mStorage.pruneTarget = static_cast<uint64_t>(pruneTarget) * 1024 * 1024;
    }
}

void Config::ApplyLogValues() {
    mLog.logLevel = GetValue("loglevel", "info");
    std::string level = ToLower(mLog.logLevel);
    if (level != "debug" && level != "info" &&
        level != "warn"  && level != "error") {
        std::cerr << "Config: unknown loglevel '" << mLog.logLevel
                  << "', using 'info'\n";
        mLog.logLevel = "info";
    }
    mLog.logToFile    = GetBoolValue("logtofile", true);
    mLog.logToConsole = GetBoolValue("logtoconsole", true);
    mLog.logIPs       = GetBoolValue("logips", false);
    int64_t maxSize = GetIntValue("maxlogsize", 10) * 1024 * 1024;
    if (maxSize < 0) maxSize = 10 * 1024 * 1024;
    if (maxSize > static_cast<int64_t>(MAX_LOG_SIZE)) {
        maxSize = MAX_LOG_SIZE;
    }
    mLog.maxLogSize = static_cast<uint64_t>(maxSize);
}

namespace {
bool IsListKey(const std::string& key) {
    return key == "addnode" || key == "connect" ||
           key == "rpcallowip" || key == "seednode";
}
}

void Config::ApplyValue(const std::string& key, const std::string& value) {
    const std::string k = ToLower(key);
    if (IsListKey(k)) {
        mRawLists[k].push_back(value);
        mRawValues[k] = value;
        return;
    }
    mRawValues[k] = value;
}

std::vector<std::string> Config::GetListValues(
    const std::string& key) const
{
    std::map<std::string, std::vector<std::string> >::const_iterator it =
        mRawLists.find(ToLower(key));
    if (it == mRawLists.end()) return std::vector<std::string>();
    return it->second;
}

bool Config::Load(const fs::path& configFile) {
    if (!fs::exists(configFile)) {
        std::cerr << "Config: config file not found at "
                  << configFile.string()
                  << " - using defaults\n";
        mLoaded = true;
        ApplyNetworkValues();
        ApplyRPCValues();
        ApplyMiningValues();
        ApplyStorageValues();
        ApplyLogValues();
        return true;
    }
    std::ifstream file(configFile.string());
    if (!file.is_open()) {
        throw ConfigError("Cannot open config file: " + configFile.string());
    }
    std::string line;
    int lineNum = 0;
    while (std::getline(file, line)) {
        lineNum++;
        std::string key, value;
        if (!ParseLine(line, key, value)) continue;
        ApplyValue(key, value);
    }
    file.close();
    ApplyNetworkValues();
    ApplyRPCValues();
    ApplyMiningValues();
    ApplyStorageValues();
    ApplyLogValues();
    mLoaded = true;
    std::cerr << "Config: loaded from " << configFile.string() << "\n";
    return true;
}

bool Config::LoadFromDataDir(const DataDir& dataDir) {
    fs::path configPath = dataDir.GetConfigFilePath();
    mStorage.dataDir = dataDir.GetDataDir();
    return Load(configPath);
}

void Config::PrintConfig() const {
    std::cerr << "=== MONEU Configuration ===\n";
    std::cerr << "Network:\n";
    std::cerr << "  port:           " << mNetwork.port           << "\n";
    std::cerr << "  rpcport:        " << mNetwork.rpcPort        << "\n";
    std::cerr << "  maxconnections: " << mNetwork.maxConnections << "\n";
    std::cerr << "  maxoutbound:    " << mNetwork.maxOutbound    << "\n";
    std::cerr << "  maxinbound:     " << mNetwork.maxInbound     << "\n";
    std::cerr << "  listen:         " << mNetwork.listen         << "\n";
    std::cerr << "Mining:\n";
    std::cerr << "  enabled:        " << mMining.enabled << "\n";
    std::cerr << "  reward address: "
              << (mMining.rewardAddress.empty()
                      ? std::string("(not set)")
                      : mMining.rewardAddress)
              << "\n";
    std::cerr << "Storage:\n";
    std::cerr << "  datadir:        " << mStorage.dataDir.string() << "\n";
    std::cerr << "  dbcache:        " << mStorage.dbCacheSize / (1024*1024) << " MB\n";
    std::cerr << "  prunemode:      " << mStorage.pruneMode      << "\n";
    std::cerr << "  txindex:        " << mStorage.txIndex        << "\n";
    std::cerr << "RPC:\n";
    std::cerr << "  enabled:        " << mRPC.rpcEnabled         << "\n";
    std::cerr << "  bind:           " << mRPC.rpcBindAddr        << "\n";
    std::cerr << "  port:           " << mRPC.rpcPort            << "\n";
    std::cerr << "Log:\n";
    std::cerr << "  level:          " << mLog.logLevel           << "\n";
    std::cerr << "  tofile:         " << mLog.logToFile          << "\n";
    std::cerr << "===========================\n";
}

} // namespace node
} // namespace MONEU
