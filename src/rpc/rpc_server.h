// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license
// Adapted from Bitcoin Core (MIT)

#ifndef MONEU_RPC_SERVER_H
#define MONEU_RPC_SERVER_H

#include "../primitives/block.h"
#include "../primitives/transaction.h"
#include "../storage/chain_state.h"
#include "../consensus/mempool.h"
#include "../net/net.h"
#include "../node/config.h"
#include "../node/wallet_manager.h"
#include "../miner.h"
#include "../chainparams.h"

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <stdexcept>

#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>

namespace MONEU {
namespace rpc {

using json = nlohmann::json;
namespace asio = boost::asio;
using tcp = boost::asio::ip::tcp;

static const uint16_t RPC_PORT               = NetParams::RPC_PORT;
// Must hold the largest legal block as hex, which is two characters per
// byte, plus the JSON around it. A limit below that would make the biggest
// valid blocks unsubmittable while doing nothing about abuse, since a
// smaller flood is just as effective at wasting parsing time.
// How long an identical getblocktemplate request returns the same answer.
//
// A template stays usable until the tip moves, which the cache also checks,
// so this only bounds how often the work of building one is repeated for a
// caller asking in a tight loop.
static const int64_t  GETBLOCKTEMPLATE_CACHE_SEC = 5;

static const uint32_t RPC_MAX_BODY_SIZE =
    NetParams::MAX_BLOCK_SIZE * 2 + 4096;
static const uint32_t RPC_MAX_CONNECTIONS     = 20;
static const uint32_t RPC_CLIENT_TIMEOUT_SEC  = 10;
static const uint32_t PROTOCOL_VERSION        = 1;

class RPCError : public std::runtime_error {
public:
    int code;
    explicit RPCError(int c, const std::string& msg)
        : std::runtime_error(msg), code(c) {}
};

enum RPCErrorCode {
    RPC_INVALID_REQUEST  = -32600,
    RPC_METHOD_NOT_FOUND = -32601,
    RPC_INVALID_PARAMS   = -32602,
    RPC_INTERNAL_ERROR   = -32603,
    RPC_PARSE_ERROR      = -32700,
    RPC_IN_WARMUP        = -32000,
    RPC_FORBIDDEN        = -32001,
    RPC_DATABASE_ERROR   = -32002,
    RPC_DESERIALIZATION  = -32003,
    RPC_VERIFY_ERROR     = -32004,
    RPC_VERIFY_REJECTED  = -32005,
    RPC_MISC_ERROR       = -32006,
    // Standard Bitcoin RPC code for a bad or unknown address/key.
    RPC_INVALID_ADDRESS_OR_KEY = -5
};

struct RPCRequest {
    std::string method;
    json        params;
    json        id;
    bool        isNotification;
    std::string clientIP;

    RPCRequest()
        : isNotification(false)
    {}
};

struct RPCResponse {
    json result;
    json error;
    json id;
    bool hasError;

    RPCResponse()
        : hasError(false)
    {}

    static RPCResponse Success(const json& result,
                                const json& id)
    {
        RPCResponse r;
        r.result   = result;
        r.id       = id;
        r.hasError = false;
        return r;
    }

    static RPCResponse Error(int code,
                              const std::string& msg,
                              const json& id)
    {
        RPCResponse r;
        r.error    = {{"code", code}, {"message", msg}};
        r.id       = id;
        r.hasError = true;
        return r;
    }

    json ToJson() const {
        json obj;
        obj["jsonrpc"] = "2.0";
        obj["id"]      = id;
        if (hasError) {
            obj["error"]  = error;
            obj["result"] = nullptr;
        } else {
            obj["result"] = result;
            obj["error"]  = nullptr;
        }
        return obj;
    }
};

struct RPCContext {
    storage::ChainState*      chainState;
    Mempool*                  mempool;
    net::ConnManager*         connManager;
    node::Config*             config;
    node::WalletManager*      wallet;
    node::Miner*              miner;

    // Publishes reveals for transactions already held on chain. The node
    // otherwise only tries this when a block connects, so a wallet
    // unlocked inside the six-block window would sit on a usable proof
    // until the next block instead of sending it at once.

    RPCContext()
        : chainState(nullptr)
        , mempool(nullptr)
        , connManager(nullptr)
        , config(nullptr)
        , wallet(nullptr)
        , miner(nullptr)
    {}
};

using RPCHandler = std::function<json(
    const RPCRequest&,
    const RPCContext&)>;

struct RPCCommand {
    std::string category;
    std::string name;
    std::string description;
    RPCHandler  handler;

    RPCCommand() = default;

    RPCCommand(const std::string& cat,
               const std::string& n,
               const std::string& desc,
               RPCHandler h)
        : category(cat)
        , name(n)
        , description(desc)
        , handler(std::move(h))
    {}
};

class RPCTable {
private:
    std::map<std::string, RPCCommand> mCommands;
    mutable std::mutex                mMutex;

public:
    RPCTable() = default;

    bool Register(const RPCCommand& cmd);
    bool Unregister(const std::string& name);

    json Execute(const RPCRequest& request,
                  const RPCContext& context) const;

    std::string Help(const std::string& command) const;
    std::vector<std::string> ListCommands() const;
    bool HasCommand(const std::string& name) const;
};

class RPCServer {
private:
    asio::io_context            mIO;
    tcp::acceptor               mAcceptor;
    mutable std::mutex          mMutex;
    std::atomic<bool>           mRunning;
    std::atomic<bool>           mInWarmup;
    std::string                 mWarmupStatus;
    std::atomic<uint32_t>       mActiveConnections;
    std::string                 mRPCUser;
    std::string                 mRPCPassword;
    std::vector<std::string>    mAllowedIPs;
    RPCTable                    mTable;
    RPCContext                  mContext;
    std::vector<std::thread>    mThreads;
    uint16_t                    mPort;

    // Shutdown synchronization - wakes sleeping loops on Interrupt()
    std::condition_variable     mCv;
    std::mutex                  mCvMutex;
    // Client threads are joined during Stop(). Each one sets a flag when it
    // ends so the accept loop can join and drop finished entries.
    struct ClientThread {
        std::thread                        thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::vector<ClientThread>   mClientThreads;

    void ReapFinishedClients();

    void AcceptLoop();
    void HandleClient(tcp::socket socket);

    bool ParseRequest(const std::string& body,
                       RPCRequest& request);

    std::string ProcessBatch(
        const json& batch,
        const std::string& clientIP);

    bool CheckAuth(const std::string& authHeader) const;
    bool IsIPAllowed(const std::string& ip) const;

    void RegisterBuiltinCommands();

    static std::string Base64Decode(const std::string& in);

public:
    explicit RPCServer(uint16_t port = RPC_PORT);
    ~RPCServer();

    RPCServer(const RPCServer&) = delete;
    RPCServer& operator=(const RPCServer&) = delete;

    bool Start(const RPCContext& context,
               const std::string& rpcUser,
               const std::string& rpcPassword,
               const std::vector<std::string>& allowedIPs);

    void Stop();
    void Interrupt();

    bool IsRunning() const { return mRunning; }

    void SetWarmupStatus(const std::string& status);
    void SetWarmupFinished();
    bool IsInWarmup() const { return mInWarmup; }

    bool RegisterCommand(const RPCCommand& cmd);
    bool UnregisterCommand(const std::string& name);

    std::string ExecuteCommand(const std::string& method,
                                const json& params);
};

void RegisterBlockchainRPCCommands(RPCTable& table);
void RegisterNetworkRPCCommands(RPCTable& table);
void RegisterWalletRPCCommands(RPCTable& table);
void RegisterMiningRPCCommands(RPCTable& table);

} // namespace rpc
} // namespace MONEU

#endif // MONEU_RPC_SERVER_H
