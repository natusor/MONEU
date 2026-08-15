// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_NET_NET_H
#define MONEU_NET_NET_H

#include "../primitives/block.h"
#include "../primitives/transaction.h"
#include "../chainparams.h"
#include "addrman.h"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <condition_variable>
#include <cstdint>
#include <stdexcept>

#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/filesystem.hpp>

namespace MONEU {
namespace net {


namespace fs   = boost::filesystem;
namespace asio = boost::asio;
using tcp      = boost::asio::ip::tcp;

static const int64_t  PING_INTERVAL_SEC      = 120;

static const int64_t  DOWNLOAD_CHECK_INTERVAL_SEC = 20;
static const int64_t  TIMEOUT_SEC            = 1200;
static const int64_t  HANDSHAKE_TIMEOUT_SEC  = 30;
static const uint32_t MAX_INV_SIZE           = 50000;

static const size_t   ADDR_RELAY_PEERS = 2;

static const size_t   MAX_ADDR_KNOWN_PER_PEER = 5000;

static const int64_t  GETADDR_INTERVAL_SEC = 3600;
static const uint32_t MAX_GETDATA_SIZE       = 1000;

static const size_t   MAX_BLOCKS_IN_FLIGHT_PER_PEER = 16;

static const size_t   MAX_TX_IN_FLIGHT_PER_PEER = 100;

static const int64_t  TX_REQUEST_TIMEOUT_SEC = 60;

static const uint32_t BLOCK_DOWNLOAD_WINDOW = 1024;

static const int64_t  BLOCK_STALL_TIMEOUT_SEC = 60;

static const double   BLOCK_DOWNLOAD_TIMEOUT_BASE     = 1.0;
static const double   BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 0.5;
static const uint32_t MAX_ADDR_TO_SEND       = 1000;

static const uint64_t ADDR_HORIZON_SECONDS   = 30ULL * 24 * 60 * 60;

static const size_t   MAX_KNOWN_ADDRESSES    = 10000;
static const int64_t  SELF_ADVERTISE_SEC     = 24 * 60 * 60;
static const int64_t  ADDR_SAVE_INTERVAL_SEC = 60 * 60;

static const size_t   MAX_OUTBOUND_PER_GROUP = 2;

static const double   ADDR_TOKENS_PER_SECOND = 0.1;
static const double   ADDR_TOKEN_BUCKET_CAP  = 1000.0;
static const uint32_t MAX_PROTOCOL_MSG_SIZE  = 8 * 1024 * 1024;

static const size_t   READ_CHUNK_SIZE        = 64 * 1024;
static const uint32_t PROTOCOL_VERSION       = 1;
static const uint32_t MIN_PROTOCOL_VERSION   = 1;
static const uint32_t MAX_CONNECTIONS_PER_IP = 3;
static const size_t   BUFFER_POOL_MAX_SIZE   = 100;
static const uint32_t MAX_QUEUE_PER_NODE     = 1000;
static const size_t   MIN_TX_PAYLOAD         = 10;
static const size_t   MIN_BLOCK_PAYLOAD      = 80;

class NetError : public std::runtime_error {
public:
    explicit NetError(const std::string& msg)
        : std::runtime_error(msg) {}
};

enum class MsgType : uint8_t {
    VERSION    = 1,
    VERACK     = 2,
    PING       = 3,
    PONG       = 4,
    ADDR       = 5,
    GETADDR    = 6,
    INV        = 7,
    GETDATA    = 8,
    TX         = 9,
    BLOCK      = 10,
    GETBLOCKS  = 11,
    GETHEADERS = 12,
    HEADERS    = 13,
    REJECT     = 14,
    REVEAL     = 15
};

enum class InvType : uint8_t {
    TX     = 1,
    BLOCK  = 2,
    REVEAL = 3
};

struct InvItem {
    InvType type;
    bytes32 hash;

    InvItem() { hash.fill(0); }
    InvItem(InvType t, const bytes32& h)
        : type(t), hash(h) {}
};

struct NetAddress {
    std::string ip;
    uint16_t    port;
    uint64_t    lastSeen;
    uint32_t    services;

    NetAddress()
        : port(0)
        , lastSeen(0)
        , services(0)
    {}

    NetAddress(const std::string& ip_, uint16_t port_)
        : ip(ip_)
        , port(port_)
        , lastSeen(0)
        , services(0)
    {}

    std::string ToString() const {
        return ip + ":" + std::to_string(port);
    }
};

struct NetMessage {
    uint32_t             magic;
    MsgType              type;
    std::vector<uint8_t> payload;

    NetMessage()
        : magic(0)
        , type(MsgType::PING)
    {}

    NetMessage(MsgType t,
               const std::vector<uint8_t>& p)
        : magic(NetParams::GetNetworkMagic())
        , type(t)
        , payload(p)
    {}

    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const uint8_t* data,
                             size_t len,
                             NetMessage& msg);
};

struct VersionMessage {
    uint32_t    version;
    uint64_t    timestamp;
    uint32_t    bestHeight;
    uint64_t    bestRound;
    bytes32     bestBlockHash;
    std::string userAgent;
    uint64_t    nonce;

    VersionMessage()
        : version(PROTOCOL_VERSION)
        , timestamp(0)
        , bestHeight(0)
        , bestRound(0)
        , nonce(0)
    {
        bestBlockHash.fill(0);
        userAgent = NetParams::USER_AGENT;
    }

    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(
        const std::vector<uint8_t>& data,
        VersionMessage& msg);
};

using NodeId = uint64_t;

class Node {
public:
    NodeId              id;
    NetAddress          addr;
    bool                inbound;
    bool                connected;
    bool                versionSent;
    bool                versionAcked;
    uint32_t            version;
    uint32_t            bestHeight;
    uint64_t            bestRound;
    bytes32             bestBlockHash;
    std::string         userAgent;
    int64_t             lastSend;
    int64_t             lastRecv;
    int64_t             connTime;
    int64_t             lastPingSent;
    int64_t             lastPingRecv;
    uint64_t            pingNonce;
    uint64_t            bytesRecv;
    uint64_t            bytesSent;
    int32_t             misbehavior;

    std::set<std::string> addrKnown;
    mutable std::mutex    addrKnownMutex;
    bool                  addrRequested;

    int64_t               lastNovelBlock;

    int64_t               lastNovelTx;

    double              addrTokens;
    int64_t             addrTokenTimestamp;

    std::vector<uint8_t>             recvBuffer;

    std::deque<std::vector<uint8_t>> sendQueue;
    mutable std::mutex               sendMutex;

    tcp::socket                         socket;
    std::unique_ptr<asio::steady_timer> timeoutTimer;

    explicit Node(asio::io_context& io,
                  NodeId nodeId,
                  bool isInbound)
        : id(nodeId)
        , inbound(isInbound)
        , connected(false)
        , versionSent(false)
        , versionAcked(false)
        , version(0)
        , bestHeight(0)
        , bestRound(0)
        , lastSend(0)
        , lastRecv(0)
        , connTime(0)
        , lastPingSent(0)
        , lastPingRecv(0)
        , pingNonce(0)
        , bytesRecv(0)
        , bytesSent(0)
        , misbehavior(0)
        , addrRequested(false)
        , lastNovelBlock(0)
        , lastNovelTx(0)
        , addrTokens(ADDR_TOKEN_BUCKET_CAP)
        , addrTokenTimestamp(0)
        , socket(io)
        , timeoutTimer(new asio::steady_timer(io))
    {
        bestBlockHash.fill(0);
    }

    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    void PushMessage(const NetMessage& msg);

    bool IsFullyConnected() const {
        return connected && versionSent && versionAcked;
    }

    void AddMisbehavior(int32_t score) {
        misbehavior += score;
    }

    bool IsBanned() const {
        return misbehavior >= 100;
    }

    bool IsSaturated() const {
        std::lock_guard<std::mutex> lock(sendMutex);
        return sendQueue.size() > MAX_QUEUE_PER_NODE;
    }
};

using NodePtr = std::shared_ptr<Node>;

struct NetCallbacks {
    std::function<void(NodeId,
                       const Transaction&)> onTransaction;
    std::function<bool(uint32_t&, bytes32&)> getChainTip;
    std::function<std::vector<bytes32>(const bytes32&, size_t)>
        getBlockHashesAfter;
    std::function<std::vector<bytes32>()> getBlockLocator;
    std::function<std::vector<bytes32>(const std::vector<bytes32>&, size_t)>
        getBlockHashesAfterLocator;
    std::function<bool(const bytes32&)> haveBlock;
    std::function<bool(const bytes32&)> haveTx;
    std::function<void(NodeId,
                       const Block&)>       onBlock;
    std::function<void(NodeId)>             onNodeConnected;
    std::function<void(NodeId)>             onNodeDisconnected;
    std::function<void(NodeId,
                       const std::vector<InvItem>&)> onGetData;
};

struct ConnManagerOptions {
    uint16_t    listenPort;
    uint32_t    maxConnections;
    uint32_t    maxOutbound;
    uint32_t    maxInbound;
    bool        listen;
    uint32_t    bestHeight;
    uint64_t    bestRound;
    bytes32     bestBlockHash;
    std::vector<std::string> seedNodes;
    std::vector<std::string> addNodes;

    ConnManagerOptions()
        : listenPort(NetParams::DEFAULT_PORT)
        , maxConnections(
              NetParams::MAX_TOTAL_CONNECTIONS)
        , maxOutbound(
              NetParams::MAX_OUTBOUND_CONNECTIONS)
        , maxInbound(
              NetParams::MAX_INBOUND_CONNECTIONS)
        , listen(true)
        , bestHeight(0)
        , bestRound(0)
    {
        bestBlockHash.fill(0);
    }
};

class ConnManager
    : public std::enable_shared_from_this<ConnManager>
{
private:
    asio::io_context          mIO;
    tcp::acceptor             mAcceptor;
    mutable std::mutex        mNodesMutex;
    std::unordered_map<NodeId, NodePtr> mNodes;
    std::atomic<NodeId>       mNextNodeId;
    std::atomic<bool>         mRunning;
    std::atomic<bool>         mNetworkActive;
    ConnManagerOptions        mOptions;
    NetCallbacks              mCallbacks;
    std::vector<std::thread>  mThreads;
    AddrMan                   mAddrMan;
    std::vector<NetAddress>   mKnownAddresses;
    NetAddress                mExternalAddress;
    int64_t                   mLastSelfAdvertise;
    int64_t                   mLastAddressSave;
    fs::path                  mAddressFile;
    mutable std::mutex        mAddrMutex;
    uint64_t                  mLocalNonce;

    int64_t                   mLastAddrRequest;

    struct InFlightEntry {
        NodeId  peer;
        int64_t requestedAt;
    };
    std::map<std::string, InFlightEntry> mBlocksInFlight;
    std::map<std::string, InFlightEntry> mTxInFlight;
    mutable std::mutex                   mInFlightMutex;

    bool ShouldRequestBlock(const bytes32& hash, NodeId from);

    bool ShouldRequestTx(const bytes32& hash, NodeId from);
    void ClearTxInFlight(const bytes32& hash);
    void ClearTxInFlightForPeer(NodeId peer);
    void ClearInFlight(const bytes32& hash);
    void ClearInFlightForPeer(NodeId peer);

    void CheckDownloadProgress();
    void DownloadLoop();

    bool EvictOneInboundPeer();

    uint64_t KeyedNetGroup(const std::string& ip) const;

    static const size_t EVICT_PROTECT_BY_NETGROUP = 4;
    static const size_t EVICT_PROTECT_BY_PING     = 8;
    static const size_t EVICT_PROTECT_BY_BLOCKS   = 4;
    static const size_t EVICT_PROTECT_BY_TX       = 4;

    std::map<NodeId, int64_t> mStallingSince;

    std::vector<std::string>  mBannedIPs;
    mutable std::mutex        mBanMutex;

    std::unordered_map<std::string, int> mConnectionsPerIP;
    mutable std::mutex                   mConnPerIPMutex;

    std::vector<std::vector<uint8_t>> mBufferPool;
    std::mutex                        mPoolMutex;

    std::unique_ptr<
        asio::executor_work_guard<asio::io_context::executor_type> >
        mWorkGuard;

    std::condition_variable mCv;
    std::mutex              mCvMutex;

    std::vector<uint8_t> AcquireBuffer();
    void ReleaseBuffer(std::vector<uint8_t> buffer);

    void AcceptLoop();
    void ConnectLoop();
    void MessageLoop();
    void PingLoop();

    void StartHandshakeTimeout(NodePtr node);
    void CancelHandshakeTimeout(NodePtr node);

    void StartRead(NodePtr node);
    void HandleRead(
        NodePtr node,
        std::shared_ptr<std::vector<uint8_t>> buffer,
        size_t bytesRead);

    void HandleMessage(NodePtr node,
                       const NetMessage& msg);
    void HandleVersion(NodePtr node,
                       const NetMessage& msg);
    void HandleVerack(NodePtr node);
    void HandlePing(NodePtr node,
                    const NetMessage& msg);
    void HandlePong(NodePtr node,
                    const NetMessage& msg);
    void HandleAddr(NodePtr node,
                    const NetMessage& msg);
    void HandleInv(NodePtr node,
                   const NetMessage& msg);
    void HandleGetData(NodePtr node,
                       const NetMessage& msg);
    void MaybeStartSync(NodePtr node);

    void SyncFromAllPeers();

    void RelayAddress(const NetAddress& addr, NodeId originator);

    void RequestAddresses();

    void HandleGetBlocks(NodePtr node,
                         const NetMessage& msg);
    void HandleGetHeaders(NodePtr node,
                          const NetMessage& msg);
    void HandleTx(NodePtr node,
                  const NetMessage& msg);
    void HandleBlock(NodePtr node,
                     const NetMessage& msg);
    void HandleGetAddr(NodePtr node);
    void HandleReject(NodePtr node,
                      const NetMessage& msg);

    void SendVersion(NodePtr node);
    void SendVerack(NodePtr node);
    void SendPing(NodePtr node);
    void SendAddr(NodePtr node,
                  const std::vector<NetAddress>& addrs);

    void DisconnectNode(NodePtr node,
                        const std::string& reason);
    void RemoveNode(NodeId id);

    bool IsIPBanned(const std::string& ip) const;

    bool IsAlreadyConnected(const NetAddress& addr) const;
    bool CheckConnectionLimitForIP(
        const std::string& ip);
    void DecrementConnectionCount(
        const std::string& ip);
    bool ConnectToAddress(const NetAddress& addr);
    bool AddKnownAddress(const NetAddress& addr);
    bool AddKnownAddressFrom(const NetAddress& addr,
                             const std::string& source);

    void AddOperatorAddress(const NetAddress& addr);

    static std::string GetGroup16(const NetAddress& addr);

    size_t CountOutboundInGroup(const std::string& group) const;
    NodeId GetNextNodeId();

    static int64_t GetCurrentTimestamp();
    static int64_t GetCurrentMicros();

public:
    explicit ConnManager(
        const ConnManagerOptions& options);
    ~ConnManager();

    ConnManager(const ConnManager&) = delete;
    ConnManager& operator=(
        const ConnManager&) = delete;

    bool Start(const NetCallbacks& callbacks);
    void Stop();
    void Interrupt();

    bool GetNetworkActive() const {
        return mNetworkActive;
    }
    void SetNetworkActive(bool active) {
        mNetworkActive = active;
    }

    bool AddNode(const std::string& addrStr);
    bool DisconnectNode(NodeId id);
    bool BanNode(const std::string& ip);
    void ClearBanned();

    void BroadcastTransaction(const Transaction& tx);

    void RequestBlocksFrom(NodeId nodeId);
    void BroadcastBlock(const Block& block);
    void BroadcastInv(
        const std::vector<InvItem>& items);

    void SendMessageToNode(NodeId id,
                           const NetMessage& msg);

    size_t GetNodeCount() const;
    size_t GetInboundCount() const;
    size_t GetOutboundCount() const;

    std::vector<NetAddress> GetKnownAddresses() const;

    void SetExternalAddress(const std::string& ip, uint16_t port);

    void AdvertiseSelf(NodePtr node);

    void DiscoverLocalAddresses();

    bool SelectLocalAddressFor(const NetAddress& peer,
                               NetAddress& out) const;

    static int ReachabilityScore(const std::string& local,
                                 const std::string& peer);

    static bool IsRelayableAddress(const std::string& ip);

    static bool IsUsableAddress(const std::string& ip);

    static bool IsPrivateAddress(const std::string& ip);

    std::vector<NetAddress> mLocalAddresses;
    mutable std::mutex      mLocalAddrMutex;

    bool LoadAddresses(const fs::path& file);
    bool SaveAddresses(const fs::path& file) const;

    size_t BootstrapFromSeeds();
    std::vector<NodeId> GetConnectedNodeIds() const;

    struct PeerInfo {
        NodeId      id;
        std::string address;
        bool        inbound;
        uint32_t    version;
        std::string userAgent;
        uint32_t    bestHeight;
        std::string bestBlockHash;
        int64_t     connectedAt;
        uint32_t    services;
        int64_t     lastSend;
        int64_t     lastRecv;
        uint64_t    bytesSent;
        uint64_t    bytesRecv;
        int32_t     misbehavior;
        double      pingSeconds;
    };

    std::vector<PeerInfo> GetPeerInfo() const;

    void UpdateBestChain(uint32_t height,
                         uint64_t round,
                         const bytes32& blockHash);

    uint64_t GetTotalBytesRecv() const;
    uint64_t GetTotalBytesSent() const;
};

} // namespace net
} // namespace MONEU

#endif // MONEU_NET_NET_H
