// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_NODE_CONFIG_H
#define MONEU_NODE_CONFIG_H

#include "data_dir.h"
#include "../chainparams.h"

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <stdexcept>

#include <boost/filesystem.hpp>

namespace MONEU {
namespace node {

namespace fs = boost::filesystem;

class ConfigError : public std::runtime_error {
public:
    explicit ConfigError(const std::string& msg)
        : std::runtime_error(msg) {}
};

struct NetworkConfig {
    uint16_t    port;
    uint16_t    rpcPort;
    uint32_t    maxConnections;
    uint32_t    maxOutbound;
    uint32_t    maxInbound;
    bool        listen;
    bool        upnp;

    std::string externalIp;
    std::vector<std::string> seedNodes;
    std::vector<std::string> addNodes;
    std::vector<std::string> connectNodes;

    NetworkConfig()
        : port(NetParams::DEFAULT_PORT)
        , rpcPort(NetParams::RPC_PORT)
        , maxConnections(NetParams::MAX_TOTAL_CONNECTIONS)
        , maxOutbound(NetParams::MAX_OUTBOUND_CONNECTIONS)
        , maxInbound(NetParams::MAX_INBOUND_CONNECTIONS)
        , listen(true)
        , upnp(false)
    {}
};

struct RPCConfig {
    std::string rpcUser;
    std::string rpcPassword;
    std::string rpcBindAddr;
    uint16_t    rpcPort;
    bool        rpcEnabled;
    std::vector<std::string> rpcAllowIp;

    // Whether the config named these, as opposed to taking the default.
    // Binding wider than the loopback takes both.
    bool        rpcBindSet;
    bool        rpcAllowIpSet;

    RPCConfig()
        : rpcBindAddr("127.0.0.1")
        , rpcPort(NetParams::RPC_PORT)
        , rpcEnabled(true)
        , rpcBindSet(false)
        , rpcAllowIpSet(false)
    {}
};

struct MiningConfig {
    bool enabled;

    std::string rewardAddress;

    MiningConfig()
        : enabled(false)
    {}
};

struct StorageConfig {
    fs::path dataDir;
    uint64_t dbCacheSize;
    bool     pruneMode;
    uint64_t pruneTarget;
    bool     reindex;
    bool     txIndex;

    StorageConfig()
        : dbCacheSize(450 * 1024 * 1024)
        , pruneMode(false)
        , pruneTarget(0)
        , reindex(false)
        , txIndex(false)
    {}
};

struct LogConfig {
    std::string logLevel;
    bool        logToFile;
    bool        logToConsole;
    uint64_t    maxLogSize;
    bool        logIPs;

    LogConfig()
        : logLevel("info")
        , logToFile(true)
        , logToConsole(true)
        , maxLogSize(10 * 1024 * 1024)
        , logIPs(false)
    {}
};

class Config {
private:
    NetworkConfig mNetwork;
    RPCConfig     mRPC;
    MiningConfig mMining;
    StorageConfig mStorage;
    LogConfig     mLog;
    bool          mLoaded;

    std::map<std::string, std::string> mRawValues;

    std::map<std::string, std::vector<std::string> > mRawLists;

    bool ParseLine(const std::string& line,
                   std::string& key,
                   std::string& value) const;

    void ApplyValue(const std::string& key,
                    const std::string& value);

    void ApplyNetworkValues();
    void ApplyRPCValues();
    void ApplyMiningValues();
    void ApplyStorageValues();
    void ApplyLogValues();

    std::vector<std::string> GetListValues(const std::string& key) const;

    std::string GetValue(const std::string& key,
                         const std::string& defaultVal = "") const;

    int64_t GetIntValue(const std::string& key,
                        int64_t defaultVal = 0) const;

    bool GetBoolValue(const std::string& key,
                      bool defaultVal = false) const;

public:
    Config();
    explicit Config(const fs::path& configFile);

    ~Config() = default;

    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    bool Load(const fs::path& configFile);
    bool LoadFromDataDir(const DataDir& dataDir);
    bool IsLoaded() const { return mLoaded; }

    void SetDataDir(const fs::path& dataDir) {
        mStorage.dataDir = dataDir;
    }

    const NetworkConfig&  GetNetwork()  const { return mNetwork; }
    const RPCConfig&      GetRPC()      const { return mRPC; }
    const MiningConfig& GetMining() const { return mMining; }
    const StorageConfig&  GetStorage()  const { return mStorage; }
    const LogConfig&      GetLog()      const { return mLog; }

    NetworkConfig&  GetNetworkMutable()  { return mNetwork; }
    RPCConfig&      GetRPCMutable()      { return mRPC; }
    MiningConfig& GetMiningMutable() { return mMining; }
    StorageConfig&  GetStorageMutable()  { return mStorage; }
    LogConfig&      GetLogMutable()      { return mLog; }

    void PrintConfig() const;
};

} // namespace node
} // namespace MONEU

#endif // MONEU_NODE_CONFIG_H
