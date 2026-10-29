// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "net.h"
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#endif
#include <map>
#include <set>
#include <cctype>
#include <cstdio>
#include "log/log.h"
#include "../crypto/sha3_256.h"
#include <ctime>
extern "C" {
#include "../crypto/rand.h"
}
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <condition_variable>

#ifndef WIN32
#include <sys/select.h>
#include <sys/socket.h>
#endif

namespace MONEU {
namespace net {

static_assert(MAX_PROTOCOL_MSG_SIZE > 6u * 1024u * 1024u,
              "MAX_PROTOCOL_MSG_SIZE must leave room above MAX_BLOCK_SIZE");

int64_t ConnManager::GetCurrentTimestamp() {
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now()
            .time_since_epoch()).count());
}

int64_t ConnManager::GetCurrentMicros() {
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now()
            .time_since_epoch()).count());
}

std::vector<uint8_t> ConnManager::AcquireBuffer() {
    std::lock_guard<std::mutex> lock(mPoolMutex);
    if (!mBufferPool.empty()) {
        auto buf = std::move(mBufferPool.back());
        mBufferPool.pop_back();
        buf.assign(READ_CHUNK_SIZE, 0);
        return buf;
    }
    return std::vector<uint8_t>(READ_CHUNK_SIZE, 0);
}

void ConnManager::ReleaseBuffer(
    std::vector<uint8_t> buffer)
{
    std::lock_guard<std::mutex> lock(mPoolMutex);
    if (mBufferPool.size() < BUFFER_POOL_MAX_SIZE) {
        mBufferPool.push_back(std::move(buffer));
    }
}

std::vector<uint8_t> NetMessage::Serialize() const {
    std::vector<uint8_t> data;
    uint32_t payloadSize =
        static_cast<uint32_t>(payload.size());
    uint8_t typeVal = static_cast<uint8_t>(type);
    data.reserve(4 + 1 + 4 + payloadSize);
    data.push_back((magic      ) & 0xFF);
    data.push_back((magic >>  8) & 0xFF);
    data.push_back((magic >> 16) & 0xFF);
    data.push_back((magic >> 24) & 0xFF);
    data.push_back(typeVal);
    data.push_back((payloadSize      ) & 0xFF);
    data.push_back((payloadSize >>  8) & 0xFF);
    data.push_back((payloadSize >> 16) & 0xFF);
    data.push_back((payloadSize >> 24) & 0xFF);
    data.insert(data.end(),
                payload.begin(), payload.end());
    return data;
}

bool NetMessage::Deserialize(const uint8_t* data,
                               size_t len,
                               NetMessage& msg)
{
    if (len < 9) return false;
    uint32_t magic =
        static_cast<uint32_t>(data[0]) |
        (static_cast<uint32_t>(data[1]) << 8) |
        (static_cast<uint32_t>(data[2]) << 16) |
        (static_cast<uint32_t>(data[3]) << 24);
    if (magic != NetParams::GetNetworkMagic())
        return false;
    msg.magic = magic;
    msg.type  = static_cast<MsgType>(data[4]);
    uint32_t payloadSize =
        static_cast<uint32_t>(data[5]) |
        (static_cast<uint32_t>(data[6]) << 8) |
        (static_cast<uint32_t>(data[7]) << 16) |
        (static_cast<uint32_t>(data[8]) << 24);
    if (payloadSize > MAX_PROTOCOL_MSG_SIZE)
        return false;
    if (len < 9 + payloadSize) return false;
    msg.payload.assign(data + 9,
                       data + 9 + payloadSize);
    return true;
}

std::vector<uint8_t> VersionMessage::Serialize() const
{
    std::vector<uint8_t> data;
    data.push_back((version      ) & 0xFF);
    data.push_back((version >>  8) & 0xFF);
    data.push_back((version >> 16) & 0xFF);
    data.push_back((version >> 24) & 0xFF);
    for (int i = 0; i < 8; ++i)
        data.push_back((timestamp >> (i*8)) & 0xFF);
    data.push_back((bestHeight      ) & 0xFF);
    data.push_back((bestHeight >>  8) & 0xFF);
    data.push_back((bestHeight >> 16) & 0xFF);
    data.push_back((bestHeight >> 24) & 0xFF);
    for (int i = 0; i < 8; ++i)
        data.push_back((bestRound >> (i*8)) & 0xFF);
    for (int i = 0; i < 8; ++i)
        data.push_back((nonce >> (i*8)) & 0xFF);
    data.insert(data.end(),
                bestBlockHash.begin(),
                bestBlockHash.end());
    uint32_t agentLen =
        static_cast<uint32_t>(userAgent.size());
    data.push_back((agentLen      ) & 0xFF);
    data.push_back((agentLen >>  8) & 0xFF);
    data.push_back((agentLen >> 16) & 0xFF);
    data.push_back((agentLen >> 24) & 0xFF);
    data.insert(data.end(),
                userAgent.begin(), userAgent.end());
    return data;
}

bool VersionMessage::Deserialize(
    const std::vector<uint8_t>& data,
    VersionMessage& msg)
{
    if (data.size() < 4 + 8 + 4 + 8 + 8 + 32 + 4)
        return false;
    size_t offset = 0;
    msg.version =
        static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset+1]) << 8) |
        (static_cast<uint32_t>(data[offset+2]) << 16) |
        (static_cast<uint32_t>(data[offset+3]) << 24);
    offset += 4;
    msg.timestamp = 0;
    for (int i = 0; i < 8; ++i)
        msg.timestamp |=
            static_cast<uint64_t>(
                data[offset+i]) << (i*8);
    offset += 8;
    msg.bestHeight =
        static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset+1]) << 8) |
        (static_cast<uint32_t>(data[offset+2]) << 16) |
        (static_cast<uint32_t>(data[offset+3]) << 24);
    offset += 4;
    msg.bestRound = 0;
    for (int i = 0; i < 8; ++i)
        msg.bestRound |=
            static_cast<uint64_t>(
                data[offset+i]) << (i*8);
    offset += 8;
    msg.nonce = 0;
    for (int i = 0; i < 8; ++i)
        msg.nonce |=
            static_cast<uint64_t>(
                data[offset+i]) << (i*8);
    offset += 8;
    std::memcpy(msg.bestBlockHash.data(),
                data.data() + offset, 32);
    offset += 32;
    if (offset + 4 > data.size()) return false;
    uint32_t agentLen =
        static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset+1]) << 8) |
        (static_cast<uint32_t>(data[offset+2]) << 16) |
        (static_cast<uint32_t>(data[offset+3]) << 24);
    offset += 4;
    if (agentLen > 256) return false;
    if (offset + agentLen > data.size()) return false;
    msg.userAgent.assign(
        data.begin() + offset,
        data.begin() + offset + agentLen);
    return true;
}

void Node::PushMessage(const NetMessage& msg) {
    std::lock_guard<std::mutex> lock(sendMutex);
    sendQueue.push_back(msg.Serialize());
}

ConnManager::ConnManager(
    const ConnManagerOptions& options)
    : mBindOnAny(true)
    , mNextNodeId(1)
    , mRunning(false)
    , mNetworkActive(true)
    , mOptions(options)
    , mLastSelfAdvertise(0)
    , mLastAddressSave(0)
    , mLastAddrRequest(0)
    , mHaveProxy(false)
    , mHaveOnionProxy(false)
    , mNetConfigError(false)
    , mReachIPv4(true)
    , mReachIPv6(true)
    , mReachOnion(true)
    , mLastTipChange(0)
    , mLastStaleProbe(0)
{
    random_buffer(reinterpret_cast<uint8_t*>(&mLocalNonce),
                  sizeof(mLocalNonce));

    if (!mOptions.proxy.empty()) {
        if (ParseHostPort(mOptions.proxy, 9050, mProxy) &&
            (Classify(mProxy.ip) == NetKind::IPV4 ||
             Classify(mProxy.ip) == NetKind::IPV6)) {
            mHaveProxy = true;
        } else {
            MONEU_LOG_ERROR("P2P: cannot use proxy=" + mOptions.proxy +
                            " (give the IP address and port of the proxy)");
            mNetConfigError = true;
        }
    }
    if (!mOptions.onionProxy.empty()) {
        if (ParseHostPort(mOptions.onionProxy, 9050, mOnionProxy) &&
            (Classify(mOnionProxy.ip) == NetKind::IPV4 ||
             Classify(mOnionProxy.ip) == NetKind::IPV6)) {
            mHaveOnionProxy = true;
        } else {
            MONEU_LOG_ERROR("P2P: cannot use onion=" + mOptions.onionProxy +
                            " (give the IP address and port of the proxy)");
            mNetConfigError = true;
        }
    } else if (mHaveProxy) {
        mOnionProxy     = mProxy;
        mHaveOnionProxy = true;
    }

    if (!mOptions.onlyNets.empty()) {
        mReachIPv4  = false;
        mReachIPv6  = false;
        mReachOnion = false;
        for (const std::string& raw : mOptions.onlyNets) {
            std::string n;
            for (char c : raw) n.push_back(static_cast<char>(std::tolower(
                static_cast<unsigned char>(c))));
            if (n == "ipv4") mReachIPv4 = true;
            else if (n == "ipv6") mReachIPv6 = true;
            else if (n == "onion" || n == "tor") mReachOnion = true;
            else {
                MONEU_LOG_ERROR("P2P: unknown onlynet=" + raw +
                                " (use ipv4, ipv6 or onion)");
                mNetConfigError = true;
            }
        }
    }

    for (const std::string& raw : mOptions.binds) {
        const size_t eq = raw.rfind('=');
        NetAddress a;
        bool ok = false;
        bool onion = false;
        if (eq == std::string::npos) {
            ok = ParseHostPort(raw, mOptions.listenPort, a);
        } else if (raw.substr(eq + 1) == "onion") {
            onion = true;
            ok = ParseHostPort(raw.substr(0, eq), mOptions.onionBindPort, a);
        }
        const NetKind kind = ok ? Classify(a.ip) : NetKind::INVALID;
        if (kind != NetKind::IPV4 && kind != NetKind::IPV6) {
            MONEU_LOG_ERROR("P2P: cannot use bind=" + raw +
                            " (give an IP address, optionally :port and =onion)");
            mNetConfigError = true;
            continue;
        }
        if (onion) {
            mOnionBinds.push_back(a);
        } else {
            mBinds.push_back(a);
        }
    }
    mBindOnAny = mOptions.binds.empty();
    if (mOnionBinds.empty() && mOptions.onionBindPort != 0) {
        mOnionBinds.push_back(NetAddress("127.0.0.1", mOptions.onionBindPort));
    }

    mLastTipChange = GetCurrentTimestamp();
}

ConnManager::~ConnManager() {
    Stop();
}

NodeId ConnManager::GetNextNodeId() {
    return mNextNodeId++;
}

bool ConnManager::CheckConnectionLimitForIP(
    const std::string& ip)
{
    std::lock_guard<std::mutex> lock(mConnPerIPMutex);
    auto it = mConnectionsPerIP.find(ip);
    if (it != mConnectionsPerIP.end()) {
        if (it->second >= static_cast<int>(
                MAX_CONNECTIONS_PER_IP))
        {
            std::cerr << "ConnManager: connection "
                         "limit exceeded for peer ("
                      << it->second << "/"
                      << MAX_CONNECTIONS_PER_IP
                      << ")\n";
            return false;
        }
        it->second++;
    } else {
        mConnectionsPerIP[ip] = 1;
    }
    return true;
}

void ConnManager::DecrementConnectionCount(
    const std::string& ip)
{
    std::lock_guard<std::mutex> lock(mConnPerIPMutex);
    auto it = mConnectionsPerIP.find(ip);
    if (it != mConnectionsPerIP.end()) {
        it->second--;
        if (it->second <= 0)
            mConnectionsPerIP.erase(it);
    }
}

void ConnManager::StartHandshakeTimeout(
    NodePtr node)
{
    auto self = shared_from_this();
    const bool overTor = node->viaProxy || node->onionInbound;
    node->timeoutTimer->expires_after(
        std::chrono::seconds(overTor ? HANDSHAKE_TIMEOUT_PROXY_SEC
                                     : HANDSHAKE_TIMEOUT_SEC));
    node->timeoutTimer->async_wait(
        [this, self, node](
            const boost::system::error_code& ec) {
            if (ec) return;
            if (!node->IsFullyConnected()) {
                std::cerr << "ConnManager: handshake"
                             " timeout "
                          << "peer=" << node->id
                          << "\n";
                DisconnectNode(node,
                               "handshake timeout");
            }
        });
}

void ConnManager::CancelHandshakeTimeout(
    NodePtr node)
{
    node->timeoutTimer->cancel();
}

bool ConnManager::Start(
    const NetCallbacks& callbacks)
{
    if (mNetConfigError) return false;
    mCallbacks = callbacks;
    mRunning   = true;
    bool onionListening = false;
    if (mOptions.listen) {
        for (const auto& b : mBinds) {
            if (!BindListener(b, false)) return false;
        }
        if (mBindOnAny &&
            !BindListener(NetAddress("0.0.0.0", mOptions.listenPort), false)) {
            return false;
        }
        for (size_t i = 0; i < mOnionBinds.size(); ++i) {
            const bool bound = BindListener(mOnionBinds[i], true);
            if (i == 0) onionListening = bound;
        }
    }

    for (const auto& s : mOptions.seedNodes) {
        NetAddress a;
        if (ParseHostPort(s, mOptions.listenPort, a)) AddOperatorAddress(a);
    }
    for (const auto& s : mOptions.addNodes) {
        NetAddress a;
        if (ParseHostPort(s, mOptions.listenPort, a)) AddOperatorAddress(a);
    }

    mThreads.emplace_back(
        [this]() { AcceptLoop(); });
    mThreads.emplace_back(
        [this]() { ConnectLoop(); });
    mThreads.emplace_back(
        [this]() { MessageLoop(); });
    mThreads.emplace_back(
        [this]() { PingLoop(); });
    mThreads.emplace_back(
        [this]() { DownloadLoop(); });

    if (mOptions.discover && mBindOnAny) {
        DiscoverLocalAddresses();
    } else {
        std::vector<NetAddress> externals;
        {
            std::lock_guard<std::mutex> lock(mAddrMutex);
            externals = mExternalAddresses;
        }
        std::lock_guard<std::mutex> lock(mLocalAddrMutex);
        for (const auto& e : externals) {
            if (!e.ip.empty()) mLocalAddresses.push_back(e);
        }
        if (mOptions.discover && mOptions.listen) {
            for (const auto& b : mBinds) {
                bool named = false;
                for (const auto& e : externals) {
                    if (e.ip == b.ip) named = true;
                }
                if (IsRelayableAddress(b.ip) && !named) {
                    mLocalAddresses.push_back(b);
                }
            }
        }
    }
    mWorkGuard.reset(
        new asio::executor_work_guard<asio::io_context::executor_type>(
            asio::make_work_guard(mIO)));
    mThreads.emplace_back([this]() {
        try { mIO.run(); } catch (...) {}
    });
    MONEU_LOG_INFO("P2P: listening on port " +
                   std::to_string(mOptions.listenPort));
    if (mHaveProxy) {
        MONEU_LOG_INFO("P2P: outbound connections go through proxy " +
                       mProxy.ToString());
    }

    if (mOptions.listenOnion && onionListening) {
        const NetAddress& target = mOnionBinds.front();
        if (mOnionBinds.size() > 1) {
            MONEU_LOG_WARN("P2P: more than one onion bind address is given, "
                           "using " + target.ToString() + " for the onion "
                           "service created through Tor");
        }
        TorControlOptions torOptions;
        torOptions.control     = mOptions.torControl;
        torOptions.password    = mOptions.torPassword;
        torOptions.keyFile     = mOptions.onionKeyFile;
        torOptions.virtualPort = NetParams::DEFAULT_PORT;
        torOptions.target      =
            (Classify(target.ip) == NetKind::IPV6 ? "[" + target.ip + "]"
                                                  : target.ip) +
            ":" + std::to_string(target.port);
        TorControlCallbacks torCallbacks;
        torCallbacks.onAuthenticated = [this]() { UseDefaultOnionProxy(); };
        torCallbacks.onService = [this](const std::string& host) {
            OnOnionService(host);
        };
        torCallbacks.onServiceLost = [this](const std::string& host) {
            OnOnionServiceLost(host);
        };
        mTor.reset(new TorController(torOptions, torCallbacks));
        mTor->Start();
    }
    return true;
}

void ConnManager::Stop() {
    if (mThreads.empty()) return;

    // The waiting threads test mRunning under mCvMutex, so the flag has to be
    // cleared while that mutex is held. Setting it outside leaves a gap: a
    // thread that has just read the old value, and has not yet begun to wait,
    // misses the notification and sleeps out its whole interval. With a ping
    // loop on a two minute timer that turned a shutdown into a two minute
    // wait, which looked to anyone watching like the node had hung.
    {
        std::lock_guard<std::mutex> lock(mCvMutex);
        mRunning = false;
    }

    if (mTor) mTor->Stop();

    CloseListeners();

    mCv.notify_all();

    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        for (auto& pair : mNodes) {
            boost::system::error_code ec;
            pair.second->timeoutTimer->cancel();
            pair.second->socket.shutdown(
                tcp::socket::shutdown_both, ec);
            pair.second->socket.close(ec);
        }
        mNodes.clear();
    }

    if (mWorkGuard) mWorkGuard->reset();
    mIO.stop();

    for (auto& t : mThreads) {
        if (t.joinable()) t.join();
    }
    mThreads.clear();

    MONEU_LOG_INFO("P2P: stopped");
}

void ConnManager::Interrupt() {
    // Cleared under mCvMutex for the same reason as in Stop below.
    {
        std::lock_guard<std::mutex> lock(mCvMutex);
        mRunning = false;
    }
    if (mTor) mTor->Stop();
    CloseListeners();
    mCv.notify_all();
    if (mWorkGuard) mWorkGuard->reset();
    mIO.stop();
}

void ConnManager::AcceptLoop() {
    while (mRunning) {
        try {
            fd_set rfds;
            FD_ZERO(&rfds);
            int maxFd = -1;
            std::vector<size_t> open;
            for (size_t i = 0; i < mListeners.size(); ++i) {
                tcp::acceptor& a = *mListeners[i].acceptor;
                if (!a.is_open()) continue;
                FD_SET(a.native_handle(), &rfds);
                const int fd = static_cast<int>(a.native_handle());
                if (fd > maxFd) maxFd = fd;
                open.push_back(i);
            }
            if (open.empty()) {
                std::unique_lock<std::mutex> lock(mCvMutex);
                mCv.wait_for(lock, std::chrono::seconds(1),
                             [this]() { return !mRunning; });
                continue;
            }

            struct timeval tv = {0, 500000};  // 500 ms
            int sel = select(maxFd + 1, &rfds,
                             nullptr, nullptr, &tv);
            if (!mRunning) break;
            if (sel <= 0) {
                continue;
            }
            for (size_t i : open) {
                Listener& l = mListeners[i];
                if (l.acceptor->is_open() &&
                    FD_ISSET(l.acceptor->native_handle(), &rfds)) {
                    AcceptOne(*l.acceptor, l.onion);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "ConnManager: AcceptLoop "
                         "exception: "
                      << e.what() << "\n";
        }
    }
}

bool ConnManager::BindListener(const NetAddress& addr, bool onion) {
    boost::system::error_code ec;
    const asio::ip::address ip = asio::ip::make_address(addr.ip, ec);
    if (ec) return false;
    std::unique_ptr<tcp::acceptor> acceptor(new tcp::acceptor(mIO));
    try {
        const tcp::endpoint endpoint(ip, addr.port);
        acceptor->open(endpoint.protocol());
        acceptor->set_option(asio::socket_base::reuse_address(true));
        if (ip.is_v6()) acceptor->set_option(asio::ip::v6_only(true));
        acceptor->bind(endpoint);
        acceptor->listen();
        acceptor->non_blocking(true);
    } catch (const std::exception& e) {
        std::cerr << "ConnManager: listen failed on "
                  << addr.ToString() << ": " << e.what() << "\n";
        if (onion) {
            MONEU_LOG_WARN("P2P: cannot listen for onion connections on " +
                           addr.ToString() + ": " + e.what());
        } else {
            MONEU_LOG_ERROR("P2P: cannot listen on " + addr.ToString() +
                            ": " + e.what());
        }
        return false;
    }
    std::cerr << "ConnManager: listening on " << addr.ToString()
              << (onion ? " for onion peers" : "") << "\n";
    Listener l;
    l.acceptor = std::move(acceptor);
    l.onion    = onion;
    mListeners.push_back(std::move(l));
    return true;
}

void ConnManager::CloseListeners() {
    for (auto& l : mListeners) {
        boost::system::error_code ec;
        l.acceptor->cancel(ec);
        l.acceptor->close(ec);
    }
}

void ConnManager::AcceptOne(tcp::acceptor& acceptor, bool onion) {
    auto node = std::make_shared<Node>(
        mIO, GetNextNodeId(), true);
    node->onionInbound = onion;
    boost::system::error_code ec;
    acceptor.accept(node->socket, ec);
    if (ec) {
        if (mRunning &&
            ec != boost::asio::error::would_block &&
            ec != boost::asio::error::try_again) {
            std::cerr << "ConnManager: "
                         "accept error: "
                      << ec.message()
                      << "\n";
        }
        return;
    }
    node->socket.non_blocking(true, ec);
    std::string ip = node->socket
        .remote_endpoint(ec)
        .address().to_string();
    if (ec) return;
    const uint16_t remotePort =
        node->socket.remote_endpoint(ec).port();
    if (ec) return;

    if (!onion) {
        if (IsIPBanned(ip)) {
            std::cerr << "ConnManager: rejected"
                         " banned " << ip << "\n";
            boost::system::error_code closeEc;
            node->socket.close(closeEc);
            return;
        }
        if (!CheckConnectionLimitForIP(ip)) {
            boost::system::error_code closeEc;
            node->socket.close(closeEc);
            return;
        }
    }
    bool atCapacity = false;
    {
        std::lock_guard<std::mutex> lock(
            mNodesMutex);
        atCapacity = mNodes.size() >= mOptions.maxConnections;
    }

    if (atCapacity) {
        if (!EvictOneInboundPeer()) {
            MONEU_LOG_DEBUG("Connection slots full and no peer "
                            "worth evicting; refusing a connection");
            if (!onion) DecrementConnectionCount(ip);
            boost::system::error_code closeEc;
            node->socket.close(closeEc);
            return;
        }
    }

    {
        std::lock_guard<std::mutex> lock(
            mNodesMutex);
        node->addr.ip   = ip;
        node->addr.port = remotePort;
        node->connected = true;
        node->connTime  = GetCurrentTimestamp();
        mNodes[node->id] = node;
    }
    MONEU_LOG_INFO(std::string(onion ? "New inbound onion peer connected: peer="
                                     : "New inbound peer connected: peer=") +
                   std::to_string(node->id) +
                   (onion ? std::string()
                          : node::Log::PeerAddr(node->addr.ToString())));
    StartHandshakeTimeout(node);
    SendVersion(node);
    StartRead(node);
    if (mCallbacks.onNodeConnected)
        mCallbacks.onNodeConnected(node->id);
}

void ConnManager::ConnectLoop() {
    static const int64_t RETRY_SEC = 10 * 60;
    bool firstPass = true;
    std::map<std::string, int64_t> lastTry;
    while (mRunning) {
        if (!firstPass) {
            std::unique_lock<std::mutex> lock(mCvMutex);
            mCv.wait_for(lock, std::chrono::seconds(30),
                         [this]() { return !mRunning; });
        }
        firstPass = false;
        if (!mRunning) break;
        if (!mNetworkActive) continue;
        size_t outbound = GetOutboundCount();
        if (outbound >= mOptions.maxOutbound) continue;

        std::vector<NetAddress> candidates;
        std::vector<NetAddress> learned;
        {
            std::lock_guard<std::mutex> lock(mAddrMutex);
            candidates = mOperatorAddresses;
            candidates.insert(candidates.end(),
                              mSeedAddresses.begin(), mSeedAddresses.end());
            learned = mKnownAddresses;
        }
        std::stable_sort(learned.begin(), learned.end(),
                         [](const NetAddress& x, const NetAddress& y) {
                             return x.lastSeen > y.lastSeen;
                         });
        candidates.insert(candidates.end(), learned.begin(), learned.end());

        const int64_t now = GetCurrentTimestamp();
        for (auto it = lastTry.begin(); it != lastTry.end();) {
            if (now - it->second >= RETRY_SEC) it = lastTry.erase(it);
            else ++it;
        }

        const size_t fixedCount = candidates.size() - learned.size();
        std::set<std::string> tried;
        size_t attempts = 0;
        for (size_t i = 0; i < candidates.size(); ++i) {
            const NetAddress& addr = candidates[i];
            if (outbound >= mOptions.maxOutbound) break;
            if (!mRunning) break;
            if (attempts >= MAX_CONNECT_ATTEMPTS_PER_PASS) break;
            const std::string key = addr.ToString();
            if (!tried.insert(key).second) continue;
            if (IsOwnAddress(addr)) continue;
            if (IsIPBanned(addr.ip)) continue;
            if (!IsReachable(addr.ip)) continue;
            if (IsAlreadyConnected(addr)) continue;
            if (i >= fixedCount && lastTry.count(key)) continue;
            const std::string group = GetGroup16(addr);
            if (CountOutboundInGroup(group) >= MAX_OUTBOUND_PER_GROUP) {
                continue;
            }
            ++attempts;
            lastTry[key] = GetCurrentTimestamp();
            if (ConnectToAddress(addr)) outbound++;
        }
    }
}

bool ConnManager::IsAlreadyConnected(const NetAddress& addr) const {
    std::lock_guard<std::mutex> lock(mNodesMutex);
    for (const auto& pair : mNodes) {
        if (!pair.second) continue;
        if (pair.second->addr.ip == addr.ip &&
            pair.second->addr.port == addr.port) {
            return true;
        }
    }
    return false;
}

bool ConnManager::ConnectSocket(NodePtr node, const tcp::endpoint& endpoint) {
    boost::system::error_code ec;
    node->socket.close(ec);

    node->socket.open(endpoint.protocol(), ec);
    if (ec) return false;

    node->socket.non_blocking(true, ec);
    if (ec) return false;

    // The connect goes through the socket directly rather than through
    // asio. Asio's synchronous connect polls with no timeout of its own,
    // so it returns only once the kernel gives up resending the first
    // packet, which takes over two minutes. The loop below never got a
    // turn, and with it the check on mRunning: a shutdown waited out
    // those two minutes, and during ordinary work one address nobody
    // answers held up every other address behind it.
    {
        const int rc = ::connect(node->socket.native_handle(),
                                 endpoint.data(),
                                 endpoint.size());
        if (rc == 0) {
            ec = boost::system::error_code();
        } else {
#ifdef WIN32
            const int wsaErr = ::WSAGetLastError();
            ec = boost::system::error_code(
                wsaErr == WSAEWOULDBLOCK ? EINPROGRESS : wsaErr,
                boost::system::system_category());
#else
            ec = boost::system::error_code(
                errno, boost::system::system_category());
#endif
        }
    }

    if (!ec) return true;
    if (ec.value() != EINPROGRESS && ec.value() != EWOULDBLOCK &&
        ec.value() != EAGAIN) {
        return false;
    }

    const int64_t deadline = GetCurrentTimestamp() + CONNECT_TIMEOUT_SEC;
    while (mRunning) {
        if (GetCurrentTimestamp() >= deadline) return false;

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(node->socket.native_handle(), &wfds);
        struct timeval tv = {0, 500000};  // 500ms
#ifdef WIN32
        fd_set efds;
        FD_ZERO(&efds);
        FD_SET(node->socket.native_handle(), &efds);
        int sel = select(0, nullptr, &wfds, &efds, &tv);
#else
        int sel = select(node->socket.native_handle() + 1,
                         nullptr, &wfds, nullptr, &tv);
#endif
        if (sel > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(node->socket.native_handle(),
                       SOL_SOCKET, SO_ERROR,
                       (char*)&err, &len);
            return err == 0;
        } else if (sel < 0) {
            return false;
        }
    }
    return false;
}

bool ConnManager::ConnectThroughProxy(NodePtr node, const NetAddress& proxy,
                                      const NetAddress& addr) {
    boost::system::error_code ec;
    const asio::ip::address proxyIp = asio::ip::make_address(proxy.ip, ec);
    if (ec) return false;
    if (!ConnectSocket(node, tcp::endpoint(proxyIp, proxy.port))) {
        MONEU_LOG_DEBUG("P2P: cannot reach proxy " + proxy.ToString());
        return false;
    }

    ProxyCredentials creds;
    const ProxyCredentials* auth = nullptr;
    if (mOptions.proxyRandomize) {
        uint8_t r[16];
        random_buffer(r, sizeof(r));
        static const char* hexDigits = "0123456789abcdef";
        for (int i = 0; i < 8; ++i) {
            creds.username.push_back(hexDigits[(r[i] >> 4) & 0x0F]);
            creds.username.push_back(hexDigits[r[i] & 0x0F]);
            creds.password.push_back(hexDigits[(r[i + 8] >> 4) & 0x0F]);
            creds.password.push_back(hexDigits[r[i + 8] & 0x0F]);
        }
        auth = &creds;
    }

    std::string err;
    if (!Socks5(node->socket.native_handle(), addr.ip, addr.port, auth,
                SOCKS5_RECV_TIMEOUT_MS, mRunning, err)) {
        MONEU_LOG_DEBUG("P2P: connection through proxy failed: " + err +
                        node::Log::PeerAddr(addr.ToString()));
        return false;
    }
    return true;
}

bool ConnManager::GetProxyFor(NetKind kind, NetAddress& out) const {
    std::lock_guard<std::mutex> lock(mProxyMutex);
    if (kind == NetKind::ONION) {
        if (!mHaveOnionProxy) return false;
        out = mOnionProxy;
        return true;
    }
    if (!mHaveProxy) return false;
    out = mProxy;
    return true;
}

bool ConnManager::IsReachableKind(NetKind kind) const {
    switch (kind) {
        case NetKind::IPV4:
            return mReachIPv4;
        case NetKind::IPV6:
            return mReachIPv6;
        case NetKind::ONION: {
            std::lock_guard<std::mutex> lock(mProxyMutex);
            return mReachOnion && mHaveOnionProxy;
        }
        case NetKind::NAME: {
            std::lock_guard<std::mutex> lock(mProxyMutex);
            return mHaveProxy || mOptions.onlyNets.empty();
        }
        default:
            return false;
    }
}

bool ConnManager::IsReachable(const std::string& host) const {
    return IsReachableKind(Classify(host));
}

bool ConnManager::ConnectToAddress(const NetAddress& addr) {
    if (IsOwnAddress(addr)) return false;
    if (IsIPBanned(addr.ip)) return false;
    const NetKind kind = Classify(addr.ip);
    if (!IsReachableKind(kind)) return false;
    mAddrMan.Attempt(addr.ip, addr.port, GetCurrentTimestamp());
    if (IsAlreadyConnected(addr)) return false;
    if (!CheckConnectionLimitForIP(addr.ip)) return false;

    auto node = std::make_shared<Node>(mIO, GetNextNodeId(), false);

    bool connected = false;
    NetAddress proxy;
    if (GetProxyFor(kind, proxy)) {
        node->viaProxy = true;
        connected = ConnectThroughProxy(node, proxy, addr);
    } else if (kind != NetKind::ONION) {
        tcp::resolver resolver(mIO);
        boost::system::error_code ec;
        auto endpoints = resolver.resolve(addr.ip, std::to_string(addr.port), ec);
        if (ec) {
            std::cerr << "ConnManager: outbound address "
                         "resolve failed: " << ec.message() << "\n";
            DecrementConnectionCount(addr.ip);
            return false;
        }
        for (auto it = endpoints.begin();
             it != endpoints.end() && !connected && mRunning; ++it) {
            connected = ConnectSocket(node, it->endpoint());
        }
    }

    boost::system::error_code ec;
    node->socket.non_blocking(true, ec);

    if (!connected || !mRunning) {
        if (mRunning) {
            std::cerr << "ConnManager: outbound connect "
                         "attempt failed\n";
        }
        DecrementConnectionCount(addr.ip);
        return false;
    }

    node->addr      = addr;
    node->connected = true;
    node->connTime  = GetCurrentTimestamp();
    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        mNodes[node->id] = node;
    }
    std::cerr << "ConnManager: connected "
                 "outbound peer=" << node->id << "\n";
    StartHandshakeTimeout(node);
    SendVersion(node);
    StartRead(node);
    if (mCallbacks.onNodeConnected)
        mCallbacks.onNodeConnected(node->id);
    return true;
}

void ConnManager::StartRead(NodePtr node) {
    auto self = shared_from_this();
    auto buffer = std::make_shared<std::vector<uint8_t>>(AcquireBuffer());
    node->socket.async_read_some(
        asio::buffer(*buffer),
        [this, self, node, buffer](
            const boost::system::error_code& ec,
            size_t bytesRead) mutable
        {
            if (!mRunning) {
                ReleaseBuffer(std::move(*buffer));
                return;
            }
            if (ec) {
                std::cerr << "ConnManager: read "
                             "error from "
                          << "peer=" << node->id
                          << ": " << ec.message()
                          << " (" << ec.value()
                          << ")\n";
                ReleaseBuffer(std::move(*buffer));
                DisconnectNode(node, ec.message());
                return;
            }
            HandleRead(node, buffer, bytesRead);
            ReleaseBuffer(std::move(*buffer));
            if (mRunning && node->connected)
                StartRead(node);
        });
}

void ConnManager::HandleRead(
    NodePtr node,
    std::shared_ptr<std::vector<uint8_t>> buffer,
    size_t bytesRead)
{
    if (bytesRead == 0) return;
    node->lastRecv  = GetCurrentTimestamp();
    node->bytesRecv += bytesRead;

    node->recvBuffer.insert(node->recvBuffer.end(),
                            buffer->begin(),
                            buffer->begin() + bytesRead);

    const size_t kHeader = 9;
    if (node->recvBuffer.size() > MAX_PROTOCOL_MSG_SIZE + kHeader) {
        std::cerr << "ConnManager: oversized stream from peer="
                  << node->id << "\n";
        node->AddMisbehavior(20);
        DisconnectNode(node, "oversized message stream");
        return;
    }

    while (node->recvBuffer.size() >= kHeader) {
        uint32_t payloadSize =
            static_cast<uint32_t>(node->recvBuffer[5]) |
            (static_cast<uint32_t>(node->recvBuffer[6]) << 8) |
            (static_cast<uint32_t>(node->recvBuffer[7]) << 16) |
            (static_cast<uint32_t>(node->recvBuffer[8]) << 24);

        if (payloadSize > MAX_PROTOCOL_MSG_SIZE) {
            std::cerr << "ConnManager: declared payload too large from "
                      << "peer=" << node->id << "\n";
            node->AddMisbehavior(20);
            DisconnectNode(node, "declared payload too large");
            return;
        }

        const size_t total = kHeader + payloadSize;
        if (node->recvBuffer.size() < total) {
            break;
        }

        NetMessage msg;
        if (!NetMessage::Deserialize(
                node->recvBuffer.data(), total, msg))
        {
            std::cerr << "ConnManager: invalid message"
                         " from "
                      << "peer=" << node->id << "\n";
            node->AddMisbehavior(10);
            if (node->IsBanned())
                DisconnectNode(node,
                               "misbehavior limit");
            return;
        }

        node->recvBuffer.erase(node->recvBuffer.begin(),
                               node->recvBuffer.begin() + total);
        HandleMessage(node, msg);

        if (!node->connected) return;
    }
}

void ConnManager::HandleMessage(
    NodePtr node, const NetMessage& msg)
{
    switch (msg.type) {
        case MsgType::VERSION:
            HandleVersion(node, msg); break;
        case MsgType::VERACK:
            HandleVerack(node);       break;
        case MsgType::PING:
            HandlePing(node, msg);    break;
        case MsgType::PONG:
            HandlePong(node, msg);    break;
        case MsgType::ADDR:
            HandleAddr(node, msg);    break;
        case MsgType::GETADDR:
            HandleGetAddr(node);      break;
        case MsgType::INV:
            HandleInv(node, msg);     break;
        case MsgType::GETDATA:
            HandleGetData(node, msg); break;
        case MsgType::GETBLOCKS:
            HandleGetBlocks(node, msg); break;
        case MsgType::GETHEADERS:
            HandleGetHeaders(node, msg); break;
        case MsgType::TX:
            HandleTx(node, msg);      break;
        case MsgType::REVEAL:
        case MsgType::BLOCK:
            HandleBlock(node, msg);   break;
        case MsgType::REJECT:
            HandleReject(node, msg);  break;
        default:
            std::cerr << "ConnManager: unknown "
                         "message type "
                      << static_cast<int>(msg.type)
                      << " from "
                      << "peer=" << node->id
                      << "\n";
            node->AddMisbehavior(5);
            break;
    }
}

void ConnManager::HandleVersion(
    NodePtr node, const NetMessage& msg)
{
    if (node->versionSent && node->versionAcked) {
        node->AddMisbehavior(10);
        return;
    }
    if (msg.payload.size() < 4+8+4+8+8+32+4) {
        DisconnectNode(node,
                       "version payload too small");
        return;
    }
    VersionMessage verMsg;
    if (!VersionMessage::Deserialize(
            msg.payload, verMsg)) {
        DisconnectNode(node,
                       "invalid version message");
        return;
    }

    if (verMsg.nonce != 0 && verMsg.nonce == mLocalNonce) {
        std::cerr << "ConnManager: dropped a connection to self "
                     "(peer=" << node->id << ")\n";
        DisconnectNode(node, "connected to self");
        return;
    }
    if (verMsg.version < MIN_PROTOCOL_VERSION) {
        DisconnectNode(node,
                       "protocol version too old");
        return;
    }
    node->version       = verMsg.version;
    node->bestHeight    = verMsg.bestHeight;
    node->bestRound     = verMsg.bestRound;
    node->bestBlockHash = verMsg.bestBlockHash;
    node->userAgent     = verMsg.userAgent;
    node->versionSent   = true;
    SendVerack(node);
    std::cerr << "ConnManager: version from "
              << "peer=" << node->id
              << " height=" << node->bestHeight
              << " round="  << node->bestRound
              << "\n";
}

void ConnManager::HandleVerack(NodePtr node) {
    node->versionAcked = true;
    CancelHandshakeTimeout(node);
    MONEU_LOG_DEBUG("Handshake complete with peer=" +
                    std::to_string(node->id));

    if (!node->inbound) {
        mAddrMan.Good(node->addr.ip, node->addr.port,
                      GetCurrentTimestamp());
    }
    SendAddr(node, GetKnownAddresses());
    AdvertiseSelf(node);

    if (!node->addrRequested) {
        node->addrRequested = true;
        node->PushMessage(NetMessage(MsgType::GETADDR,
                                     std::vector<uint8_t>()));
    }

    MaybeStartSync(node);
}

void ConnManager::HandlePing(
    NodePtr node, const NetMessage& msg)
{
    if (msg.payload.size() < 8) {
        node->AddMisbehavior(5);
        return;
    }
    uint64_t nonce = 0;
    for (int i = 0; i < 8; ++i)
        nonce |= static_cast<uint64_t>(
            msg.payload[i]) << (i*8);
    std::vector<uint8_t> pongPayload(8);
    for (int i = 0; i < 8; ++i)
        pongPayload[i] = (nonce >> (i*8)) & 0xFF;
    NetMessage pong(MsgType::PONG, pongPayload);
    node->PushMessage(pong);
}

void ConnManager::HandlePong(
    NodePtr node, const NetMessage& msg)
{
    if (msg.payload.size() < 8) {
        node->AddMisbehavior(5);
        return;
    }
    uint64_t nonce = 0;
    for (int i = 0; i < 8; ++i)
        nonce |= static_cast<uint64_t>(
            msg.payload[i]) << (i*8);
    if (nonce == node->pingNonce)
        node->lastPingRecv = GetCurrentMicros();
}

void ConnManager::HandleAddr(
    NodePtr node, const NetMessage& msg)
{
    if (msg.payload.size() < 4) {
        node->AddMisbehavior(5);
        return;
    }
    uint32_t count =
        static_cast<uint32_t>(msg.payload[0]) |
        (static_cast<uint32_t>(msg.payload[1]) << 8) |
        (static_cast<uint32_t>(msg.payload[2]) << 16) |
        (static_cast<uint32_t>(msg.payload[3]) << 24);
    if (count > MAX_ADDR_TO_SEND) {
        node->AddMisbehavior(20);
        return;
    }

    const int64_t now = GetCurrentTimestamp();
    if (node->addrTokenTimestamp == 0) {
        node->addrTokenTimestamp = now;
    }
    if (now > node->addrTokenTimestamp) {
        const double elapsed =
            static_cast<double>(now - node->addrTokenTimestamp);
        node->addrTokens += elapsed * ADDR_TOKENS_PER_SECOND;
        if (node->addrTokens > ADDR_TOKEN_BUCKET_CAP) {
            node->addrTokens = ADDR_TOKEN_BUCKET_CAP;
        }
        node->addrTokenTimestamp = now;
    }

    size_t offset = 4;
    for (uint32_t i = 0; i < count; ++i) {
        if (offset + 2 > msg.payload.size()) break;
        uint16_t port =
            static_cast<uint16_t>(
                msg.payload[offset]) |
            (static_cast<uint16_t>(
                msg.payload[offset+1]) << 8);
        offset += 2;
        if (offset + 4 > msg.payload.size()) break;
        uint32_t ipLen =
            static_cast<uint32_t>(
                msg.payload[offset]) |
            (static_cast<uint32_t>(
                msg.payload[offset+1]) << 8) |
            (static_cast<uint32_t>(
                msg.payload[offset+2]) << 16) |
            (static_cast<uint32_t>(
                msg.payload[offset+3]) << 24);
        offset += 4;
        if (ipLen == 0 || ipLen > 64) break;
        if (offset + ipLen > msg.payload.size())
            break;
        std::string ip(
            msg.payload.begin() + offset,
            msg.payload.begin() + offset + ipLen);
        offset += ipLen;
        if (port > 0 && port < 65535 && !ip.empty()) {
            if (node->addrTokens >= 1.0) {
                node->addrTokens -= 1.0;
                const NetAddress learned(ip, port);
                const std::string vouchedBy = node->addr.ip;
                if (AddKnownAddressFrom(learned, vouchedBy)) {
                    RelayAddress(learned, node->id);
                }
            }
        }
    }
}

void ConnManager::HandleGetAddr(NodePtr node) {
    SendAddr(node, GetKnownAddresses());
}

void ConnManager::HandleInv(
    NodePtr node, const NetMessage& msg)
{
    if (!node->connected) return;
    if (msg.payload.size() < 4) {
        node->AddMisbehavior(5);
        return;
    }
    uint32_t count =
        static_cast<uint32_t>(msg.payload[0]) |
        (static_cast<uint32_t>(msg.payload[1]) << 8) |
        (static_cast<uint32_t>(msg.payload[2]) << 16) |
        (static_cast<uint32_t>(msg.payload[3]) << 24);
    if (count > MAX_INV_SIZE) {
        node->AddMisbehavior(20);
        return;
    }
    size_t expectedMinSize = 4 + (size_t)count * 33;
    if (msg.payload.size() < expectedMinSize) {
        std::cerr << "ConnManager: INV payload too"
                     " small from "
                  << "peer=" << node->id << "\n";
        node->AddMisbehavior(10);
        return;
    }
    size_t offset = 4;
    std::vector<InvItem> getDataItems;
    size_t blocksFromThisPeer = 0;
    {
        std::lock_guard<std::mutex> lock(mInFlightMutex);
        blocksFromThisPeer = CountBlocksInFlightLocked(node->id);
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (offset + 1 + 32 > msg.payload.size())
            break;
        InvItem item;
        item.type = static_cast<InvType>(
            msg.payload[offset]);
        offset++;
        std::memcpy(item.hash.data(),
                    msg.payload.data() + offset, 32);
        offset += 32;
        if (item.type == InvType::TX) {
            if (mCallbacks.haveTx && mCallbacks.haveTx(item.hash)) continue;
            if (!ShouldRequestTx(item.hash, node->id)) continue;
            getDataItems.push_back(item);
        } else if (item.type == InvType::BLOCK) {
            if (blocksFromThisPeer >= MAX_BLOCKS_IN_FLIGHT_PER_PEER) continue;
            if (mCallbacks.haveBlock && mCallbacks.haveBlock(item.hash)) {
                continue;
            }
            if (!ShouldRequestBlock(item.hash, node->id)) continue;
            ++blocksFromThisPeer;
            getDataItems.push_back(item);
        }
    }
    if (!getDataItems.empty()) {
        std::vector<uint8_t> getDataPayload;
        uint32_t gdCount =
            static_cast<uint32_t>(
                getDataItems.size());
        getDataPayload.push_back(
            (gdCount      ) & 0xFF);
        getDataPayload.push_back(
            (gdCount >>  8) & 0xFF);
        getDataPayload.push_back(
            (gdCount >> 16) & 0xFF);
        getDataPayload.push_back(
            (gdCount >> 24) & 0xFF);
        for (const auto& item : getDataItems) {
            getDataPayload.push_back(
                static_cast<uint8_t>(item.type));
            getDataPayload.insert(
                getDataPayload.end(),
                item.hash.begin(),
                item.hash.end());
        }
        NetMessage getDataMsg(
            MsgType::GETDATA, getDataPayload);
        node->PushMessage(getDataMsg);
    }
}

void ConnManager::HandleTx(
    NodePtr node, const NetMessage& msg)
{
    if (msg.payload.size() < MIN_TX_PAYLOAD) {
        std::cerr << "ConnManager: TX payload too"
                     " small from "
                  << "peer=" << node->id << "\n";
        node->AddMisbehavior(10);
        return;
    }
    if (msg.payload.size() > MAX_PROTOCOL_MSG_SIZE) {
        node->AddMisbehavior(20);
        DisconnectNode(node, "TX payload too large");
        return;
    }
    try {
        Transaction tx =
            Transaction::Deserialize(msg.payload);
        node->lastNovelTx = GetCurrentTimestamp();

        ClearTxInFlight(tx.GetHash());

        if (mCallbacks.onTransaction)
            mCallbacks.onTransaction(node->id, tx);
    } catch (const std::exception& e) {
        std::cerr << "ConnManager: invalid TX from "
                  << "peer=" << node->id
                  << ": " << e.what() << "\n";
        node->AddMisbehavior(10);
    }
}

void ConnManager::HandleBlock(
    NodePtr node, const NetMessage& msg)
{
    if (msg.payload.size() < MIN_BLOCK_PAYLOAD) {
        std::cerr << "ConnManager: Block payload "
                     "too small from "
                  << "peer=" << node->id << "\n";
        node->AddMisbehavior(20);
        return;
    }
    if (msg.payload.size() > MAX_PROTOCOL_MSG_SIZE) {
        node->AddMisbehavior(20);
        DisconnectNode(node,
                       "Block payload too large");
        return;
    }
    try {
        Block block =
            Block::Deserialize(msg.payload);
        ClearInFlight(block.GetHeader().GetHash());

        node->lastNovelBlock = GetCurrentTimestamp();

        const uint32_t blockHeight = block.GetHeader().GetHeight();
        if (blockHeight > node->bestHeight) node->bestHeight = blockHeight;

        const bytes32 parentHash = block.GetHeader().GetPrevBlockHash();
        if (mCallbacks.haveBlock && !mCallbacks.haveBlock(parentHash)) {
            ReRequestStalledParent(node, parentHash);
        }

        if (mCallbacks.onBlock)
            mCallbacks.onBlock(node->id, block);
    } catch (const std::exception& e) {
        std::cerr << "ConnManager: invalid block "
                     "from "
                  << "peer=" << node->id
                  << ": " << e.what() << "\n";
        node->AddMisbehavior(20);
    }
}

void ConnManager::ReRequestStalledParent(NodePtr node,
                                         const bytes32& parentHash)
{
    const std::string parentKey(
        reinterpret_cast<const char*>(parentHash.data()), 32);
    const int64_t now = GetCurrentTimestamp();
    {
        std::lock_guard<std::mutex> lock(mInFlightMutex);
        auto it = mBlocksInFlight.find(parentKey);
        if (it == mBlocksInFlight.end()) return;
        if (it->second.peer == node->id) return;
        if (now - it->second.requestedAt < BLOCK_PARENT_REREQUEST_SEC) return;
        it->second.peer = node->id;
        it->second.requestedAt = now;
    }
    std::vector<uint8_t> payload;
    payload.push_back(1);
    payload.push_back(0);
    payload.push_back(0);
    payload.push_back(0);
    payload.push_back(static_cast<uint8_t>(InvType::BLOCK));
    payload.insert(payload.end(), parentHash.begin(), parentHash.end());
    node->PushMessage(NetMessage(MsgType::GETDATA, payload));
    MONEU_LOG_DEBUG("Parent block re-requested from peer=" +
                    std::to_string(node->id));
}

void ConnManager::HandleReject(
    NodePtr node, const NetMessage& msg)
{
    if (msg.payload.size() < 1) return;
    uint8_t code = msg.payload[0];
    std::cerr << "ConnManager: reject from "
              << "peer=" << node->id
              << " code="
              << static_cast<int>(code) << "\n";
}

void ConnManager::HandleGetData(NodePtr node, const NetMessage& msg) {
    if (msg.payload.size() < 4) {
        node->AddMisbehavior(5);
        return;
    }
    uint32_t count =
        static_cast<uint32_t>(msg.payload[0]) |
        (static_cast<uint32_t>(msg.payload[1]) << 8) |
        (static_cast<uint32_t>(msg.payload[2]) << 16) |
        (static_cast<uint32_t>(msg.payload[3]) << 24);
    if (count > MAX_GETDATA_SIZE) {
        node->AddMisbehavior(20);
        return;
    }
    std::vector<InvItem> items;
    size_t offset = 4;
    for (uint32_t i = 0; i < count; ++i) {
        if (offset + 1 + 32 > msg.payload.size()) break;
        InvItem item;
        item.type = static_cast<InvType>(msg.payload[offset]);
        offset++;
        std::memcpy(item.hash.data(), msg.payload.data() + offset, 32);
        offset += 32;
        items.push_back(item);
    }
    if (mCallbacks.onGetData) {
        mCallbacks.onGetData(node->id, items);
    }
}

void ConnManager::HandleGetBlocks(NodePtr node, const NetMessage& msg) {
    if (msg.payload.size() < 4) {
        node->AddMisbehavior(5);
        return;
    }
    if (!mCallbacks.getBlockHashesAfterLocator) return;

    const uint32_t count =
        static_cast<uint32_t>(msg.payload[0]) |
        (static_cast<uint32_t>(msg.payload[1]) << 8) |
        (static_cast<uint32_t>(msg.payload[2]) << 16) |
        (static_cast<uint32_t>(msg.payload[3]) << 24);

    if (count == 0 || count > 64) {
        node->AddMisbehavior(20);
        return;
    }
    if (msg.payload.size() < 4 + static_cast<size_t>(count) * 32) {
        node->AddMisbehavior(10);
        return;
    }

    std::vector<bytes32> locator;
    locator.reserve(count);
    size_t offset = 4;
    for (uint32_t i = 0; i < count; ++i) {
        bytes32 h;
        std::memcpy(h.data(), msg.payload.data() + offset, 32);
        offset += 32;
        locator.push_back(h);
    }

    const std::vector<bytes32> hashes =
        mCallbacks.getBlockHashesAfterLocator(locator, MAX_GETDATA_SIZE);
    if (hashes.empty()) return;

    std::vector<uint8_t> payload;
    const uint32_t n = static_cast<uint32_t>(hashes.size());
    payload.push_back((n      ) & 0xFF);
    payload.push_back((n >>  8) & 0xFF);
    payload.push_back((n >> 16) & 0xFF);
    payload.push_back((n >> 24) & 0xFF);
    for (size_t i = 0; i < hashes.size(); ++i) {
        payload.push_back(static_cast<uint8_t>(InvType::BLOCK));
        payload.insert(payload.end(), hashes[i].begin(), hashes[i].end());
    }
    node->PushMessage(NetMessage(MsgType::INV, payload));
    MONEU_LOG_DEBUG("Sent inv of " + std::to_string(n) +
                    " block(s) to peer=" + std::to_string(node->id));
}

void ConnManager::RequestBlocksFrom(NodeId nodeId) {
    {
        std::lock_guard<std::mutex> lock(mInFlightMutex);
        if (CountBlocksInFlightLocked(nodeId) >
            MAX_BLOCKS_IN_FLIGHT_PER_PEER / 2) return;
    }
    NodePtr node;
    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        auto it = mNodes.find(nodeId);
        if (it == mNodes.end() || !it->second) return;
        node = it->second;
    }
    if (!node->IsFullyConnected()) return;
    if (!mCallbacks.getBlockLocator) return;

    const std::vector<bytes32> locator = mCallbacks.getBlockLocator();
    if (locator.empty()) return;

    std::vector<uint8_t> payload;
    const uint32_t count = static_cast<uint32_t>(locator.size());
    payload.push_back((count      ) & 0xFF);
    payload.push_back((count >>  8) & 0xFF);
    payload.push_back((count >> 16) & 0xFF);
    payload.push_back((count >> 24) & 0xFF);
    for (size_t i = 0; i < locator.size(); ++i) {
        payload.insert(payload.end(), locator[i].begin(), locator[i].end());
    }
    node->PushMessage(NetMessage(MsgType::GETBLOCKS, payload));
}

size_t ConnManager::CountBlocksInFlightLocked(NodeId peer) const {
    size_t count = 0;
    for (const auto& entry : mBlocksInFlight) {
        if (entry.second.peer == peer) ++count;
    }
    return count;
}

bool ConnManager::ShouldRequestBlock(const bytes32& hash, NodeId from) {
    const std::string key(reinterpret_cast<const char*>(hash.data()), 32);
    const int64_t now = GetCurrentTimestamp();

    std::lock_guard<std::mutex> lock(mInFlightMutex);

    for (auto it = mBlocksInFlight.begin(); it != mBlocksInFlight.end(); ) {
        if (now - it->second.requestedAt > BLOCK_IN_FLIGHT_TIMEOUT_SEC) {
            it = mBlocksInFlight.erase(it);
        } else {
            ++it;
        }
    }

    if (mBlocksInFlight.find(key) != mBlocksInFlight.end()) return false;

    if (mBlocksInFlight.size() >= BLOCK_DOWNLOAD_WINDOW) return false;

    if (CountBlocksInFlightLocked(from) >= MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;
    }

    InFlightEntry e;
    e.peer = from;
    e.requestedAt = now;
    mBlocksInFlight[key] = e;
    return true;
}

bool ConnManager::ShouldRequestTx(const bytes32& hash, NodeId from) {
    const std::string key(reinterpret_cast<const char*>(hash.data()), 32);
    const int64_t now = GetCurrentTimestamp();

    std::lock_guard<std::mutex> lock(mInFlightMutex);

    for (auto it = mTxInFlight.begin(); it != mTxInFlight.end(); ) {
        if (now - it->second.requestedAt > TX_REQUEST_TIMEOUT_SEC) {
            it = mTxInFlight.erase(it);
        } else {
            ++it;
        }
    }

    if (mTxInFlight.find(key) != mTxInFlight.end()) return false;

    size_t fromThisPeer = 0;
    for (const auto& entry : mTxInFlight) {
        if (entry.second.peer == from) fromThisPeer++;
    }
    if (fromThisPeer >= MAX_TX_IN_FLIGHT_PER_PEER) return false;

    InFlightEntry e;
    e.peer = from;
    e.requestedAt = now;
    mTxInFlight[key] = e;
    return true;
}

void ConnManager::ClearTxInFlight(const bytes32& hash) {
    const std::string key(reinterpret_cast<const char*>(hash.data()), 32);
    std::lock_guard<std::mutex> lock(mInFlightMutex);
    mTxInFlight.erase(key);
}

void ConnManager::ClearTxInFlightForPeer(NodeId peer) {
    std::lock_guard<std::mutex> lock(mInFlightMutex);
    for (auto it = mTxInFlight.begin(); it != mTxInFlight.end(); ) {
        if (it->second.peer == peer) {
            it = mTxInFlight.erase(it);
        } else {
            ++it;
        }
    }
}

void ConnManager::ClearInFlightForPeer(NodeId peer) {
    std::lock_guard<std::mutex> lock(mInFlightMutex);
    for (auto it = mBlocksInFlight.begin(); it != mBlocksInFlight.end(); ) {
        if (it->second.peer == peer) {
            it = mBlocksInFlight.erase(it);
        } else {
            ++it;
        }
    }
}

void ConnManager::ClearInFlight(const bytes32& hash) {
    const std::string key(reinterpret_cast<const char*>(hash.data()), 32);
    std::lock_guard<std::mutex> lock(mInFlightMutex);
    mBlocksInFlight.erase(key);
}

void ConnManager::DownloadLoop() {
    while (mRunning) {
        {
            std::unique_lock<std::mutex> lock(mCvMutex);
            mCv.wait_for(lock,
                         std::chrono::seconds(DOWNLOAD_CHECK_INTERVAL_SEC),
                         [this]() { return !mRunning; });
        }
        if (!mRunning) break;

        CheckDownloadProgress();
        SyncFromAllPeers();

        const size_t swept = mAddrMan.Sweep(GetCurrentTimestamp());
        if (swept > 0) {
            MONEU_LOG_DEBUG("Dropped " + std::to_string(swept) +
                            " dead address(es); " +
                            std::to_string(mAddrMan.TriedCount()) +
                            " tried, " + std::to_string(mAddrMan.NewCount()) +
                            " new remain");
        }

        const int64_t nowSec = GetCurrentTimestamp();
        if (nowSec - mLastAddrRequest > GETADDR_INTERVAL_SEC) {
            mLastAddrRequest = nowSec;
            RequestAddresses();
        }
    }
}

uint64_t ConnManager::KeyedNetGroup(const std::string& ip) const {
    const std::string group = AddrMan::GroupOf(ip);
    uint64_t h = mLocalNonce;
    for (size_t i = 0; i < group.size(); ++i) {
        h ^= static_cast<unsigned char>(group[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

bool ConnManager::EvictOneInboundPeer() {
    struct Candidate {
        NodeId      id;
        std::string group;
        uint64_t    keyedGroup;
        int64_t     connTime;
        int64_t     minPing;
        int64_t     lastBlock;
        int64_t     lastTx;
        bool        onion;
        bool        local;
    };

    std::vector<Candidate> candidates;
    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        for (const auto& pair : mNodes) {
            const NodePtr& n = pair.second;
            if (!n || !n->IsFullyConnected()) continue;
            if (!n->inbound) continue;

            Candidate c;
            c.id        = n->id;
            c.group      = AddrMan::GroupOf(n->addr.ip);
            c.keyedGroup = KeyedNetGroup(n->addr.ip);
            c.connTime  = n->connTime;
            c.minPing   = (n->lastPingRecv > 0 && n->lastPingSent > 0 &&
                           n->lastPingRecv >= n->lastPingSent)
                          ? (n->lastPingRecv - n->lastPingSent)
                          : 0x7FFFFFFFFFFFFFFFLL;
            c.lastBlock = n->lastNovelBlock;
            c.lastTx    = n->lastNovelTx;
            c.onion     = n->onionInbound;
            c.local     = !n->onionInbound &&
                          (n->addr.ip.compare(0, 4, "127.") == 0 ||
                           n->addr.ip == "::1" ||
                           n->addr.ip.compare(0, 11, "::ffff:127.") == 0);
            candidates.push_back(c);
        }
    }
    if (candidates.empty()) return false;

    auto protectBest = [&candidates](size_t k,
            std::function<bool(const Candidate&, const Candidate&)> better) {
        if (candidates.size() <= k) { candidates.clear(); return; }
        std::sort(candidates.begin(), candidates.end(), better);
        candidates.erase(candidates.begin(), candidates.begin() + k);
    };

    protectBest(EVICT_PROTECT_BY_NETGROUP,
                [](const Candidate& a, const Candidate& b) {
                    return a.keyedGroup < b.keyedGroup;
                });
    if (candidates.empty()) return false;

    protectBest(EVICT_PROTECT_BY_PING,
                [](const Candidate& a, const Candidate& b) {
                    return a.minPing < b.minPing;
                });
    if (candidates.empty()) return false;

    protectBest(EVICT_PROTECT_BY_TX,
                [](const Candidate& a, const Candidate& b) {
                    return a.lastTx > b.lastTx;
                });
    if (candidates.empty()) return false;

    protectBest(EVICT_PROTECT_BY_BLOCKS,
                [](const Candidate& a, const Candidate& b) {
                    return a.lastBlock > b.lastBlock;
                });
    if (candidates.empty()) return false;

    {
        const size_t totalProtect = candidates.size() / 2;
        const size_t maxByNetwork = totalProtect / 2;
        size_t protectedCount = 0;

        struct Net { bool onion; size_t count; };
        Net nets[2] = {{false, 0}, {true, 0}};
        auto inNet = [](const Candidate& c, const Net& n) {
            return n.onion ? c.onion : c.local;
        };
        for (Net& n : nets) {
            for (const Candidate& c : candidates) {
                if (inNet(c, n)) n.count++;
            }
        }
        if (nets[1].count < nets[0].count) std::swap(nets[0], nets[1]);

        while (protectedCount < maxByNetwork) {
            const size_t numNets = (nets[0].count ? 1 : 0) +
                                   (nets[1].count ? 1 : 0);
            if (numNets == 0) break;
            const size_t perNet =
                std::max((maxByNetwork - protectedCount) / numNets,
                         static_cast<size_t>(1));
            bool protectedAny = false;
            for (Net& n : nets) {
                if (n.count == 0) continue;
                std::vector<size_t> members;
                for (size_t i = 0; i < candidates.size(); ++i) {
                    if (inNet(candidates[i], n)) members.push_back(i);
                }
                std::sort(members.begin(), members.end(),
                          [&candidates](size_t x, size_t y) {
                              return candidates[x].connTime <
                                     candidates[y].connTime;
                          });
                const size_t k = std::min(perNet, members.size());
                if (k == 0) continue;
                members.resize(k);
                std::sort(members.begin(), members.end());
                for (size_t j = k; j-- > 0; ) {
                    candidates.erase(candidates.begin() + members[j]);
                }
                protectedAny = true;
                protectedCount += k;
                if (protectedCount >= maxByNetwork) break;
                n.count -= k;
            }
            if (!protectedAny) break;
        }

        protectBest(totalProtect - protectedCount,
                    [](const Candidate& a, const Candidate& b) {
                        return a.connTime < b.connTime;
                    });
    }
    if (candidates.empty()) return false;

    std::map<std::string, std::vector<size_t> > byGroup;
    for (size_t i = 0; i < candidates.size(); ++i) {
        byGroup[candidates[i].group].push_back(i);
    }

    std::string worstGroup;
    size_t worstCount = 0;
    int64_t worstOldest = 0;
    for (const auto& g : byGroup) {
        int64_t oldest = 0x7FFFFFFFFFFFFFFFLL;
        for (size_t i = 0; i < g.second.size(); ++i) {
            const int64_t t = candidates[g.second[i]].connTime;
            if (t < oldest) oldest = t;
        }
        if (g.second.size() > worstCount ||
            (g.second.size() == worstCount && oldest > worstOldest)) {
            worstCount  = g.second.size();
            worstOldest = oldest;
            worstGroup  = g.first;
        }
    }
    if (worstGroup.empty()) return false;

    NodeId victim = 0;
    int64_t newest = -1;
    bool found = false;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (candidates[i].group != worstGroup) continue;
        if (candidates[i].connTime > newest) {
            newest = candidates[i].connTime;
            victim = candidates[i].id;
            found  = true;
        }
    }
    if (!found) return false;

    NodePtr node;
    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        auto it = mNodes.find(victim);
        if (it == mNodes.end() || !it->second) return false;
        node = it->second;
    }
    MONEU_LOG_INFO("Connection slots full: evicting peer=" +
                   std::to_string(victim) +
                   " from the network group holding the most connections");
    DisconnectNode(node, "evicted to make room");
    return true;
}

void ConnManager::CheckDownloadProgress() {
    const int64_t now = GetCurrentTimestamp();
    std::vector<std::pair<NodeId, std::string> > toDrop;

    {
        std::lock_guard<std::mutex> lock(mInFlightMutex);
        if (mBlocksInFlight.empty()) {
            mStallingSince.clear();
            return;
        }

        std::map<NodeId, int64_t> oldestPerPeer;
        for (const auto& entry : mBlocksInFlight) {
            const NodeId peer = entry.second.peer;
            const int64_t at  = entry.second.requestedAt;
            auto it = oldestPerPeer.find(peer);
            if (it == oldestPerPeer.end() || at < it->second) {
                oldestPerPeer[peer] = at;
            }
        }

        for (auto it = mStallingSince.begin(); it != mStallingSince.end(); ) {
            if (oldestPerPeer.find(it->first) == oldestPerPeer.end()) {
                it = mStallingSince.erase(it);
            } else {
                ++it;
            }
        }

        NodeId blocker = 0;
        int64_t oldest = now + 1;
        bool haveBlocker = false;
        for (const auto& entry : oldestPerPeer) {
            if (entry.second < oldest) {
                oldest = entry.second;
                blocker = entry.first;
                haveBlocker = true;
            }
        }

        if (haveBlocker) {
            if (mStallingSince.find(blocker) == mStallingSince.end()) {
                mStallingSince[blocker] = now;
                MONEU_LOG_DEBUG("Download window is not advancing; peer=" +
                                std::to_string(blocker) +
                                " holds the oldest outstanding request");
            }
            for (auto it = mStallingSince.begin();
                 it != mStallingSince.end(); ) {
                if (it->first != blocker) {
                    it = mStallingSince.erase(it);
                } else {
                    ++it;
                }
            }
            if (now - oldest > BLOCK_STALL_TIMEOUT_SEC) {
                toDrop.push_back(std::make_pair(
                    blocker, std::string("stalling the block download")));
            }
        }

        std::set<NodeId> downloading;
        for (const auto& entry : mBlocksInFlight) {
            downloading.insert(entry.second.peer);
        }
        const size_t others =
            downloading.size() > 0 ? downloading.size() - 1 : 0;
        const double limit =
            static_cast<double>(NetParams::BLOCK_TIME_TARGET) *
            (BLOCK_DOWNLOAD_TIMEOUT_BASE +
             BLOCK_DOWNLOAD_TIMEOUT_PER_PEER * static_cast<double>(others));

        for (const auto& entry : oldestPerPeer) {
            if (static_cast<double>(now - entry.second) > limit) {
                bool already = false;
                for (size_t i = 0; i < toDrop.size(); ++i) {
                    if (toDrop[i].first == entry.first) already = true;
                }
                if (!already) {
                    toDrop.push_back(std::make_pair(
                        entry.first,
                        std::string("block download timed out")));
                }
            }
        }
    }

    for (size_t i = 0; i < toDrop.size(); ++i) {
        NodePtr node;
        {
            std::lock_guard<std::mutex> lock(mNodesMutex);
            auto it = mNodes.find(toDrop[i].first);
            if (it != mNodes.end() && it->second) node = it->second;
        }
        if (!node) {
            MONEU_LOG_INFO("Peer=" + std::to_string(toDrop[i].first) +
                           " is gone, its block requests go to other peers");
            ClearInFlightForPeer(toDrop[i].first);
            std::lock_guard<std::mutex> lock(mInFlightMutex);
            mStallingSince.erase(toDrop[i].first);
            continue;
        }
        if (CountFullyConnected() <= 1) {
            MONEU_LOG_INFO("Peer=" + std::to_string(toDrop[i].first) + " " +
                           toDrop[i].second + ", but it is the only peer - "
                           "keeping it and asking again");
            ClearInFlightForPeer(toDrop[i].first);
            {
                std::lock_guard<std::mutex> lock(mInFlightMutex);
                mStallingSince.erase(toDrop[i].first);
            }
            RequestBlocksFrom(toDrop[i].first);
            continue;
        }
        MONEU_LOG_INFO("Peer=" + std::to_string(toDrop[i].first) + " " +
                       toDrop[i].second + ", disconnecting - its blocks go "
                       "to other peers");
        DisconnectNode(node, toDrop[i].second);
        {
            std::lock_guard<std::mutex> lock(mInFlightMutex);
            mStallingSince.erase(toDrop[i].first);
        }
    }
}

void ConnManager::RelayAddress(const NetAddress& addr, NodeId originator) {
    if (addr.ip.empty() || addr.port == 0) return;

    if (!IsRelayableAddress(addr.ip)) return;

    const std::string key = addr.ToString();

    uint64_t seed = 1469598103934665603ULL;
    for (size_t i = 0; i < key.size(); ++i) {
        seed ^= static_cast<uint8_t>(key[i]);
        seed *= 1099511628211ULL;
    }

    std::vector<std::pair<uint64_t, NodePtr> > candidates;
    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        for (const auto& pair : mNodes) {
            const NodePtr& n = pair.second;
            if (!n || !n->IsFullyConnected()) continue;
            if (n->id == originator) continue;
            if (n->addr.ToString() == key) continue;

            uint64_t h = seed;
            h ^= static_cast<uint64_t>(n->id);
            h *= 1099511628211ULL;
            candidates.push_back(std::make_pair(h, n));
        }
    }
    if (candidates.empty()) return;

    std::sort(candidates.begin(), candidates.end(),
              [](const std::pair<uint64_t, NodePtr>& a,
                 const std::pair<uint64_t, NodePtr>& b) {
                  return a.first > b.first;
              });

    size_t sent = 0;
    for (size_t i = 0; i < candidates.size() && sent < ADDR_RELAY_PEERS; ++i) {
        NodePtr n = candidates[i].second;
        {
            std::lock_guard<std::mutex> lock(n->addrKnownMutex);
            if (n->addrKnown.find(key) != n->addrKnown.end()) continue;
            if (n->addrKnown.size() >= MAX_ADDR_KNOWN_PER_PEER) {
                n->addrKnown.clear();
            }
            n->addrKnown.insert(key);
        }
        std::vector<NetAddress> one;
        one.push_back(addr);
        SendAddr(n, one);
        sent++;
    }
    if (sent > 0) {
        MONEU_LOG_DEBUG("Relayed an address to " + std::to_string(sent) +
                        " peer(s)");
    }
}

void ConnManager::RequestAddresses() {
    std::vector<NodePtr> nodes;
    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        for (const auto& pair : mNodes) {
            if (pair.second && pair.second->IsFullyConnected()) {
                nodes.push_back(pair.second);
            }
        }
    }
    for (size_t i = 0; i < nodes.size(); ++i) {
        nodes[i]->PushMessage(NetMessage(MsgType::GETADDR,
                                         std::vector<uint8_t>()));
    }
    if (!nodes.empty()) {
        MONEU_LOG_DEBUG("Asked " + std::to_string(nodes.size()) +
                        " peer(s) for addresses");
    }
}

void ConnManager::SyncFromAllPeers() {
    if (!mCallbacks.getChainTip) return;

    uint32_t ourHeight = 0;
    bytes32 ourTip;
    if (!mCallbacks.getChainTip(ourHeight, ourTip)) return;

    const int64_t now = GetCurrentTimestamp();
    const bool stale = now - mLastTipChange >= STALE_TIP_SEC &&
                       now - mLastStaleProbe >= STALE_TIP_SEC;
    if (stale) mLastStaleProbe = now;

    std::vector<NodeId> behindUs;
    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        for (const auto& pair : mNodes) {
            const NodePtr& n = pair.second;
            if (!n || !n->IsFullyConnected()) continue;
            if (stale || n->bestHeight > ourHeight) behindUs.push_back(n->id);
        }
    }
    if (behindUs.empty()) return;

    if (stale) {
        MONEU_LOG_INFO("Sync check: no new block for " +
                       std::to_string((now - mLastTipChange) / 60) +
                       " minutes, asking " + std::to_string(behindUs.size()) +
                       " peer(s)");
    }

    MONEU_LOG_DEBUG("Sync check: at height " + std::to_string(ourHeight) +
                    ", " + std::to_string(behindUs.size()) +
                    " peer(s) report being ahead");

    for (size_t i = 0; i < behindUs.size(); ++i) {
        RequestBlocksFrom(behindUs[i]);
    }
}

void ConnManager::MaybeStartSync(NodePtr node) {
    if (!mCallbacks.getChainTip) return;

    uint32_t ourHeight = 0;
    bytes32 ourTip;
    if (!mCallbacks.getChainTip(ourHeight, ourTip)) return;

    if (node->bestHeight <= ourHeight) return;

    (void)ourTip;
    MONEU_LOG_INFO("Syncing from peer=" + std::to_string(node->id) +
                   ": we are at height " + std::to_string(ourHeight) +
                   ", peer reports " + std::to_string(node->bestHeight));

    RequestBlocksFrom(node->id);
}

void ConnManager::HandleGetHeaders(NodePtr node, const NetMessage& msg) {
    (void)node;
    (void)msg;
}

void ConnManager::SendVersion(NodePtr node) {
    VersionMessage verMsg;
    verMsg.nonce = mLocalNonce;
    verMsg.timestamp =
        static_cast<uint64_t>(GetCurrentTimestamp());
    verMsg.bestHeight    = mOptions.bestHeight;
    verMsg.bestRound     = mOptions.bestRound;
    verMsg.bestBlockHash = mOptions.bestBlockHash;
    NetMessage msg(MsgType::VERSION,
                   verMsg.Serialize());
    node->PushMessage(msg);
    node->lastSend  = GetCurrentTimestamp();
    node->bytesSent += msg.Serialize().size();
}

void ConnManager::SendVerack(NodePtr node) {
    NetMessage msg(MsgType::VERACK, {});
    node->PushMessage(msg);
}

void ConnManager::SendPing(NodePtr node) {
    uint64_t nonce = static_cast<uint64_t>(
        GetCurrentTimestamp());
    node->pingNonce    = nonce;
    node->lastPingSent = GetCurrentMicros();
    std::vector<uint8_t> payload(8);
    for (int i = 0; i < 8; ++i)
        payload[i] = (nonce >> (i*8)) & 0xFF;
    NetMessage msg(MsgType::PING, payload);
    node->PushMessage(msg);
}

void ConnManager::SendAddr(
    NodePtr node,
    const std::vector<NetAddress>& addrs)
{
    if (addrs.empty()) return;
    std::vector<uint8_t> payload;
    uint32_t count = static_cast<uint32_t>(
        std::min(addrs.size(),
                 static_cast<size_t>(
                     MAX_ADDR_TO_SEND)));
    payload.push_back((count      ) & 0xFF);
    payload.push_back((count >>  8) & 0xFF);
    payload.push_back((count >> 16) & 0xFF);
    payload.push_back((count >> 24) & 0xFF);
    for (uint32_t i = 0; i < count; ++i) {
        const NetAddress& addr = addrs[i];
        payload.push_back((addr.port     ) & 0xFF);
        payload.push_back((addr.port >> 8) & 0xFF);
        uint32_t ipLen =
            static_cast<uint32_t>(addr.ip.size());
        payload.push_back((ipLen      ) & 0xFF);
        payload.push_back((ipLen >>  8) & 0xFF);
        payload.push_back((ipLen >> 16) & 0xFF);
        payload.push_back((ipLen >> 24) & 0xFF);
        payload.insert(payload.end(),
                       addr.ip.begin(),
                       addr.ip.end());
    }
    NetMessage msg(MsgType::ADDR, payload);
    node->PushMessage(msg);
}

void ConnManager::MessageLoop() {
    while (mRunning) {
        {
            std::unique_lock<std::mutex> lock(mCvMutex);
            mCv.wait_for(lock, std::chrono::milliseconds(10),
                         [this]() { return !mRunning; });
        }
        if (!mRunning) break;

        std::vector<NodePtr> nodes;
        {
            std::lock_guard<std::mutex> lock(
                mNodesMutex);
            for (auto& pair : mNodes)
                nodes.push_back(pair.second);
        }
        for (auto& node : nodes) {
            if (!node->connected) continue;
            std::deque<std::vector<uint8_t>> toSend;
            {
                std::lock_guard<std::mutex> lock(
                    node->sendMutex);
                std::swap(toSend, node->sendQueue);
            }
            if (toSend.empty()) {
                node->sendStallSince = 0;
                continue;
            }

            // The socket is non-blocking: a peer whose receive window is
            // full gets what fits now and the rest on a later pass, and
            // the loop moves on to the next peer instead of waiting.
            bool failed  = false;
            bool blocked = false;
            while (!toSend.empty()) {
                const std::vector<uint8_t>& data = toSend.front();
                if (node->sendOffset >= data.size()) {
                    toSend.pop_front();
                    node->sendOffset = 0;
                    continue;
                }
                boost::system::error_code ec;
                const size_t n = node->socket.write_some(
                    asio::buffer(data.data() + node->sendOffset,
                                 data.size() - node->sendOffset),
                    ec);
                if (ec == asio::error::would_block ||
                    ec == asio::error::try_again) {
                    blocked = true;
                    break;
                }
                if (ec) {
                    std::cerr << "ConnManager: write"
                                 " error to "
                              << "peer=" << node->id
                              << ": " << ec.message()
                              << " (" << ec.value()
                              << ")\n";
                    DisconnectNode(node, ec.message());
                    failed = true;
                    break;
                }
                node->sendOffset    += n;
                node->bytesSent     += n;
                node->lastSend       = GetCurrentTimestamp();
                node->sendStallSince = 0;
            }
            if (failed) continue;

            if (blocked) {
                const int64_t now = GetCurrentTimestamp();
                if (node->sendStallSince == 0) {
                    node->sendStallSince = now;
                } else if (now - node->sendStallSince >=
                           SEND_STALL_TIMEOUT_SEC) {
                    DisconnectNode(node, "peer takes no data");
                    continue;
                }
                // What did not go out goes back to the front of the
                // queue, ahead of anything queued meanwhile, so the order
                // of messages on the wire stays the same.
                std::lock_guard<std::mutex> lock(node->sendMutex);
                for (auto it = toSend.rbegin(); it != toSend.rend(); ++it)
                    node->sendQueue.push_front(std::move(*it));
            } else {
                node->sendStallSince = 0;
            }
        }
    }
}

void ConnManager::SetExternalAddress(const std::string& ip,
                                     uint16_t port) {
    {
        std::lock_guard<std::mutex> lock(mAddrMutex);
        mExternalAddresses.clear();
    }
    AddExternalAddress(ip, port);
}

void ConnManager::AddExternalAddress(const std::string& ip,
                                     uint16_t port) {
    std::lock_guard<std::mutex> lock(mAddrMutex);
    for (const auto& a : mExternalAddresses) {
        if (a.ip == ip && a.port == port) return;
    }
    NetAddress a(ip, port);
    a.lastSeen = GetCurrentTimestamp();
    mExternalAddresses.push_back(a);
}

namespace {

bool ParseIPv4(const std::string& ip, int out[4]) {
    int a = 0, b = 0, c = 0, d = 0;
    char tail = 0;
    if (std::sscanf(ip.c_str(), "%d.%d.%d.%d%c", &a, &b, &c, &d, &tail) != 4) {
        return false;
    }
    if (a < 0 || a > 255 || b < 0 || b > 255 ||
        c < 0 || c > 255 || d < 0 || d > 255) return false;
    out[0] = a; out[1] = b; out[2] = c; out[3] = d;
    return true;
}

}

bool ConnManager::IsOnionAddress(const std::string& host) {
    static const std::string suffix = ".onion";
    if (host.size() != 56 + suffix.size()) return false;
    if (host.compare(56, suffix.size(), suffix) != 0) return false;

    uint8_t raw[35];
    uint32_t acc = 0;
    int bits = 0;
    size_t out = 0;
    for (size_t i = 0; i < 56; ++i) {
        const char c = host[i];
        int v;
        if (c >= 'a' && c <= 'z') {
            v = c - 'a';
        } else if (c >= '2' && c <= '7') {
            v = c - '2' + 26;
        } else {
            return false;
        }
        acc = (acc << 5) | static_cast<uint32_t>(v);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            raw[out++] = static_cast<uint8_t>((acc >> bits) & 0xFF);
        }
    }
    if (out != sizeof(raw)) return false;
    if (raw[34] != 3) return false;

    static const unsigned char prefix[] = ".onion checksum";
    unsigned char sum[SHA3_256::OUTPUT_SIZE];
    SHA3_256 hasher;
    hasher.Write(prefix, sizeof(prefix) - 1);
    hasher.Write(raw, 32);
    hasher.Write(raw + 34, 1);
    hasher.Finalize(sum);
    return sum[0] == raw[32] && sum[1] == raw[33];
}

NetKind ConnManager::Classify(const std::string& host) {
    if (host.empty() || host.size() > 255) return NetKind::INVALID;
    if (IsOnionAddress(host)) return NetKind::ONION;
    int o[4];
    if (ParseIPv4(host, o)) return NetKind::IPV4;
    boost::system::error_code ec;
    asio::ip::make_address_v6(host, ec);
    if (!ec) return NetKind::IPV6;
    if (host.size() >= 6 && host.compare(host.size() - 6, 6, ".onion") == 0) {
        return NetKind::INVALID;
    }
    bool letter = false;
    for (char c : host) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
            letter = true;
        } else if (!((c >= '0' && c <= '9') || c == '.' || c == '-')) {
            return NetKind::INVALID;
        }
    }
    return letter ? NetKind::NAME : NetKind::INVALID;
}

bool ConnManager::ParseHostPort(const std::string& in, uint16_t defaultPort,
                                NetAddress& out) {
    std::string host;
    uint16_t port = defaultPort;
    if (in.empty()) return false;
    if (in[0] == '[') {
        const size_t close = in.find(']');
        if (close == std::string::npos) return false;
        host = in.substr(1, close - 1);
        if (close + 1 < in.size()) {
            if (in[close + 1] != ':') return false;
            try {
                const unsigned long p = std::stoul(in.substr(close + 2));
                if (p == 0 || p > 65535) return false;
                port = static_cast<uint16_t>(p);
            } catch (const std::exception&) {
                return false;
            }
        }
    } else if (std::count(in.begin(), in.end(), ':') == 1) {
        const size_t colon = in.rfind(':');
        host = in.substr(0, colon);
        try {
            const unsigned long p = std::stoul(in.substr(colon + 1));
            if (p == 0 || p > 65535) return false;
            port = static_cast<uint16_t>(p);
        } catch (const std::exception&) {
            return false;
        }
    } else {
        host = in;
    }
    if (host == "localhost") host = "127.0.0.1";
    if (host.size() > 6) {
        std::string lower;
        for (char c : host) lower.push_back(static_cast<char>(std::tolower(
            static_cast<unsigned char>(c))));
        if (lower.compare(lower.size() - 6, 6, ".onion") == 0) host = lower;
    }
    if (Classify(host) == NetKind::INVALID) {
        int o[4];
        if (!ParseIPv4(host, o)) return false;
    }
    out = NetAddress(host, port);
    return true;
}

bool ConnManager::IsPrivateAddress(const std::string& ip) {
    if (IsOnionAddress(ip)) return false;
    int o[4];
    if (ParseIPv4(ip, o)) {
        if (o[0] == 10) return true;
        if (o[0] == 192 && o[1] == 168) return true;
        if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return true;
        if (o[0] == 100 && o[1] >= 64 && o[1] <= 127) return true;
        if (o[0] == 169 && o[1] == 254) return true;
        return false;
    }
    if (ip.size() >= 2) {
        const std::string p = ip.substr(0, 2);
        if (p == "fc" || p == "fd" || p == "FC" || p == "FD") return true;
    }
    if (ip.compare(0, 4, "fe80") == 0 || ip.compare(0, 4, "FE80") == 0) {
        return true;
    }
    return false;
}

bool ConnManager::IsUsableAddress(const std::string& ip) {
    if (ip.empty()) return false;
    if (ip == "::" || ip == "::1") return false;

    int o[4];
    if (ParseIPv4(ip, o)) {
        if (o[0] == 0) return false;
        if (o[0] == 127) return false;
        return true;
    }
    if (IsOnionAddress(ip)) return true;

    boost::system::error_code ec;
    asio::ip::make_address_v6(ip, ec);
    return !ec;
}

bool ConnManager::IsRelayableAddress(const std::string& ip) {
    if (!IsUsableAddress(ip)) return false;
    if (IsPrivateAddress(ip)) return false;

    int o[4];
    if (ParseIPv4(ip, o)) {
        if (o[0] == 198 && (o[1] == 18 || o[1] == 19)) return false;
        if (o[0] == 192 && o[1] == 0   && o[2] == 2)   return false;
        if (o[0] == 198 && o[1] == 51  && o[2] == 100) return false;
        if (o[0] == 203 && o[1] == 0   && o[2] == 113) return false;
        if (o[0] >= 224) return false;
        return true;
    }
    return true;
}

int ConnManager::ReachabilityScore(const std::string& local,
                                   const std::string& peer) {
    if (!IsUsableAddress(local)) return 0;

    if (IsOnionAddress(local)) return IsOnionAddress(peer) ? 5 : 1;

    const bool localPrivate = IsPrivateAddress(local);
    const bool peerPrivate  = IsPrivateAddress(peer);

    if (peerPrivate) {
        return localPrivate ? 4 : 1;
    }

    return localPrivate ? 0 : 4;
}

void ConnManager::DiscoverLocalAddresses() {
    std::vector<NetAddress> found;

    {
        std::lock_guard<std::mutex> lock(mAddrMutex);
        for (const auto& e : mExternalAddresses) {
            if (!e.ip.empty()) found.push_back(e);
        }
    }

#ifdef WIN32
    ULONG bufLen = 16 * 1024;
    std::vector<uint8_t> buf;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf.resize(bufLen);
        rc = ::GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
            NULL,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()),
            &bufLen);
    }
    if (rc == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES ad =
                 reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
             ad != NULL; ad = ad->Next) {
            if (ad->OperStatus != IfOperStatusUp) continue;
            if (ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

            for (PIP_ADAPTER_UNICAST_ADDRESS ua = ad->FirstUnicastAddress;
                 ua != NULL; ua = ua->Next) {
                const struct sockaddr* sa = ua->Address.lpSockaddr;
                if (sa == NULL) continue;

                socklen_t saLen = 0;
                if (sa->sa_family == AF_INET) {
                    saLen = sizeof(struct sockaddr_in);
                } else if (sa->sa_family == AF_INET6) {
                    saLen = sizeof(struct sockaddr_in6);
                } else {
                    continue;
                }

                char host[NI_MAXHOST];
                if (::getnameinfo(sa, saLen, host, NI_MAXHOST, NULL, 0,
                                  NI_NUMERICHOST) != 0) {
                    continue;
                }
                char* pct = std::strchr(host, '%');
                if (pct) *pct = '\0';

                const std::string ip(host);
                if (!IsRelayableAddress(ip)) continue;

                bool already = false;
                for (size_t i = 0; i < found.size(); ++i) {
                    if (found[i].ip == ip) { already = true; break; }
                }
                if (already) continue;

                NetAddress a(ip, mOptions.listenPort);
                a.lastSeen = static_cast<uint64_t>(GetCurrentTimestamp());
                found.push_back(a);
            }
        }
    }
#else
    struct ifaddrs* addrs = NULL;
    if (getifaddrs(&addrs) == 0) {
        for (struct ifaddrs* ifa = addrs; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if (ifa->ifa_name && std::strcmp(ifa->ifa_name, "lo") == 0) {
                continue;
            }

            char host[NI_MAXHOST];
            if (ifa->ifa_addr->sa_family == AF_INET) {
                if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                host, NI_MAXHOST, NULL, 0,
                                NI_NUMERICHOST) != 0) continue;
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6),
                                host, NI_MAXHOST, NULL, 0,
                                NI_NUMERICHOST) != 0) continue;
                char* pct = std::strchr(host, '%');
                if (pct) *pct = '\0';
            } else {
                continue;
            }

            const std::string ip(host);

            if (!IsRelayableAddress(ip)) continue;

            bool already = false;
            for (size_t i = 0; i < found.size(); ++i) {
                if (found[i].ip == ip) { already = true; break; }
            }
            if (already) continue;

            NetAddress a(ip, mOptions.listenPort);
            a.lastSeen = static_cast<uint64_t>(GetCurrentTimestamp());
            found.push_back(a);
        }
        freeifaddrs(addrs);
    }
#endif

    {
        std::lock_guard<std::mutex> lock(mLocalAddrMutex);
        mLocalAddresses = found;
    }

    if (found.empty()) {
        MONEU_LOG_INFO("No usable local address found: this node will not "
                       "announce itself and can only make outbound "
                       "connections");
    } else {
        MONEU_LOG_INFO("Discovered " + std::to_string(found.size()) +
                       " local address(es) to announce");
    }
}

bool ConnManager::IsOwnAddress(const NetAddress& addr) const {
    if (addr.ip.empty()) return false;

    {
        std::lock_guard<std::mutex> lock(mAddrMutex);
        for (const auto& e : mExternalAddresses) {
            if (!e.ip.empty() && e.ip == addr.ip &&
                (e.port == addr.port || addr.port == 0)) {
                return true;
            }
        }
    }

    std::lock_guard<std::mutex> lock(mLocalAddrMutex);
    for (size_t i = 0; i < mLocalAddresses.size(); ++i) {
        if (mLocalAddresses[i].ip == addr.ip) return true;
    }
    return false;
}

bool ConnManager::SelectLocalAddressFor(const NetAddress& peer,
                                        NetAddress& out) const {
    std::lock_guard<std::mutex> lock(mLocalAddrMutex);
    int best = 0;
    bool have = false;
    for (size_t i = 0; i < mLocalAddresses.size(); ++i) {
        const int score = ReachabilityScore(mLocalAddresses[i].ip, peer.ip);
        if (score > best) {
            best = score;
            out = mLocalAddresses[i];
            have = true;
        }
    }
    return have;
}

void ConnManager::AdvertiseSelf(NodePtr node) {
    NetAddress self;
    if (node->onionInbound) {
        const std::string onion = GetOnionService();
        if (!onion.empty()) {
            self = NetAddress(onion, NetParams::DEFAULT_PORT);
        } else {
            std::lock_guard<std::mutex> lock(mAddrMutex);
            bool found = false;
            for (const auto& e : mExternalAddresses) {
                if (IsOnionAddress(e.ip)) {
                    self = e;
                    found = true;
                    break;
                }
            }
            if (!found) return;
        }
    } else if (!SelectLocalAddressFor(node->addr, self)) {
        return;
    }
    self.lastSeen = static_cast<uint64_t>(GetCurrentTimestamp());

    std::vector<NetAddress> one;
    one.push_back(self);
    SendAddr(node, one);

    MONEU_LOG_DEBUG("Announced " + node::Log::PeerAddr(self.ToString()) +
                    " to peer=" + std::to_string(node->id));
}

size_t ConnManager::BootstrapFromSeeds() {
    size_t added = 0;

    for (const auto& entry : NetParams::GetFixedSeeds()) {
        size_t colon = entry.rfind(':');
        if (colon == std::string::npos) continue;
        std::string ip = entry.substr(0, colon);
        int port = std::atoi(entry.c_str() + colon + 1);
        if (ip.empty() || port <= 0 || port > 65535) continue;
        const NetAddress seed(ip, static_cast<uint16_t>(port));
        AddKnownAddress(seed);
        {
            std::lock_guard<std::mutex> lock(mAddrMutex);
            bool listed = false;
            for (const auto& a : mSeedAddresses) {
                if (a.ip == seed.ip && a.port == seed.port) listed = true;
            }
            if (!listed) mSeedAddresses.push_back(seed);
        }
        added++;
    }

    if (mHaveProxy) return added;

    for (const auto& host : NetParams::GetDNSSeeds()) {
        try {
            tcp::resolver resolver(mIO);
            boost::system::error_code ec;
            auto results = resolver.resolve(
                host, std::to_string(NetParams::DEFAULT_PORT), ec);
            if (ec) continue;
            for (auto it = results.begin(); it != results.end(); ++it) {
                AddKnownAddress(
                    NetAddress(it->endpoint().address().to_string(),
                               NetParams::DEFAULT_PORT));
                added++;
            }
        } catch (const std::exception&) {
            continue;
        }
    }
    return added;
}

bool ConnManager::LoadAddresses(const fs::path& file) {
    mAddrMan.Load(file.string() + ".table");

    mAddressFile = file;
    mLastAddressSave = int64_t(GetCurrentTimestamp());

    std::ifstream in(file.string());
    if (!in.is_open()) return false;

    std::string line;
    size_t loaded = 0;
    const uint64_t now = GetCurrentTimestamp();
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t sp = line.rfind(' ');
        if (sp == std::string::npos) continue;
        std::string hostPort = line.substr(0, sp);
        uint64_t seen = std::strtoull(line.c_str() + sp + 1, nullptr, 10);
        size_t colon = hostPort.rfind(':');
        if (colon == std::string::npos) continue;
        std::string ip = hostPort.substr(0, colon);
        int port = std::atoi(hostPort.c_str() + colon + 1);
        if (ip.empty() || port <= 0 || port > 65535) continue;
        if (seen != 0 && now > seen &&
            now - seen > ADDR_HORIZON_SECONDS) continue;
        NetAddress a(ip, static_cast<uint16_t>(port));
        a.lastSeen = seen;
        AddKnownAddress(a);
        loaded++;
    }
    std::cerr << "ConnManager: loaded " << loaded
              << " peer addresses\n";
    return true;
}

bool ConnManager::SaveAddresses(const fs::path& file) const {
    mAddrMan.Save(file.string() + ".table");

    std::ofstream out(file.string(), std::ios::trunc);
    if (!out.is_open()) return false;
    out << "# MONEU peer addresses: host:port last_seen_unix\n";
    std::lock_guard<std::mutex> lock(mAddrMutex);
    for (const auto& a : mKnownAddresses) {
        out << a.ip << ":" << a.port << " " << a.lastSeen << "\n";
    }
    return true;
}

void ConnManager::PingLoop() {
    while (mRunning) {
        {
            std::unique_lock<std::mutex> lock(mCvMutex);
            mCv.wait_for(lock,
                         std::chrono::seconds(PING_INTERVAL_SEC),
                         [this]() { return !mRunning; });
        }
        if (!mRunning) break;

        int64_t now = GetCurrentTimestamp();
        std::vector<NodePtr> nodes;
        {
            std::lock_guard<std::mutex> lock(
                mNodesMutex);
            for (auto& pair : mNodes)
                nodes.push_back(pair.second);
        }
        if (!mAddressFile.empty() &&
            now - mLastAddressSave >= ADDR_SAVE_INTERVAL_SEC) {
            mLastAddressSave = now;
            if (SaveAddresses(mAddressFile)) {
                std::cerr << "ConnManager: peer addresses saved\n";
            }
        }

        bool advertise = false;
        if (now - mLastSelfAdvertise >= SELF_ADVERTISE_SEC) {
            mLastSelfAdvertise = now;
            advertise = true;
        }

        for (auto& node : nodes) {
            if (!node->IsFullyConnected()) continue;
            if (now - node->lastRecv > TIMEOUT_SEC) {
                DisconnectNode(node, "ping timeout");
                continue;
            }
            SendPing(node);
            if (advertise) AdvertiseSelf(node);
        }
    }
}

void ConnManager::DisconnectNode(
    NodePtr node, const std::string& reason)
{
    if (!node->connected) return;
    MONEU_LOG_INFO("Disconnecting peer=" + std::to_string(node->id) +
                   node::Log::PeerAddr(node->addr.ToString()) +
                   " reason=" + reason);
    ClearInFlightForPeer(node->id);
    ClearTxInFlightForPeer(node->id);
    node->connected = false;
    boost::system::error_code ec;
    node->timeoutTimer->cancel();
    node->socket.shutdown(
        tcp::socket::shutdown_both, ec);
    node->socket.close(ec);
    if (!node->onionInbound) DecrementConnectionCount(node->addr.ip);
    if (mCallbacks.onNodeDisconnected)
        mCallbacks.onNodeDisconnected(node->id);
    RemoveNode(node->id);
}

void ConnManager::RemoveNode(NodeId id) {
    std::lock_guard<std::mutex> lock(mNodesMutex);
    mNodes.erase(id);
}

bool ConnManager::AddKnownAddress(
    const NetAddress& addr)
{
    return AddKnownAddressFrom(addr, addr.ip);
}

void ConnManager::AddOperatorAddress(const NetAddress& addr) {
    if (addr.ip.empty() || addr.port == 0) return;
    const NetKind kind = Classify(addr.ip);
    if (kind == NetKind::INVALID) return;

    {
        std::lock_guard<std::mutex> lock(mAddrMutex);
        bool listed = false;
        for (const auto& a : mOperatorAddresses) {
            if (a.ip == addr.ip && a.port == addr.port) listed = true;
        }
        if (!listed) mOperatorAddresses.push_back(addr);
    }
    if (kind == NetKind::NAME || !IsUsableAddress(addr.ip)) return;

    const int64_t now = GetCurrentTimestamp();
    mAddrMan.Add(addr.ip, addr.port, addr.services, addr.ip, now);

    std::lock_guard<std::mutex> lock(mAddrMutex);
    for (const auto& a : mKnownAddresses) {
        if (a.ip == addr.ip && a.port == addr.port) return;
    }
    NetAddress copy = addr;
    if (copy.lastSeen == 0) copy.lastSeen = static_cast<uint64_t>(now);
    mKnownAddresses.push_back(copy);
}

bool ConnManager::AddKnownAddressFrom(
    const NetAddress& addr, const std::string& source)
{
    if (IsOwnAddress(addr)) return false;
    if (!IsRelayableAddress(addr.ip)) return false;

    const int64_t now = GetCurrentTimestamp();

    const bool isNew = mAddrMan.Add(addr.ip, addr.port, addr.services,
                                    source, now);

    {
        std::lock_guard<std::mutex> lock(mAddrMutex);
        bool found = false;
        for (auto& a : mKnownAddresses) {
            if (a.ip == addr.ip && a.port == addr.port) {
                if (static_cast<uint64_t>(now) > a.lastSeen) {
                    a.lastSeen = static_cast<uint64_t>(now);
                }
                if (addr.services != 0) a.services = addr.services;
                found = true;
                break;
            }
        }
        if (!found) {
            if (mKnownAddresses.size() >= MAX_KNOWN_ADDRESSES) {
                size_t oldest = 0;
                for (size_t i = 1; i < mKnownAddresses.size(); ++i) {
                    if (mKnownAddresses[i].lastSeen <
                        mKnownAddresses[oldest].lastSeen) {
                        oldest = i;
                    }
                }
                mKnownAddresses.erase(mKnownAddresses.begin() + oldest);
            }
            NetAddress copy = addr;
            if (copy.lastSeen == 0) copy.lastSeen = static_cast<uint64_t>(now);
            mKnownAddresses.push_back(copy);
        }
    }
    return isNew;
}

bool ConnManager::IsIPBanned(
    const std::string& ip) const
{
    std::lock_guard<std::mutex> lock(mBanMutex);
    for (const auto& banned : mBannedIPs) {
        if (banned == ip) return true;
    }
    return false;
}

bool ConnManager::AddNode(
    const std::string& addrStr)
{
    {
        NetAddress parsed;
        if (ParseHostPort(addrStr, mOptions.listenPort, parsed)) {
            AddOperatorAddress(parsed);
            return ConnectToAddress(parsed);
        }
    }

    std::string ip;
    uint16_t port = mOptions.listenPort;

    if (!addrStr.empty() && addrStr[0] == '[') {
        const size_t close = addrStr.find(']');
        if (close == std::string::npos) return false;
        ip = addrStr.substr(1, close - 1);
        if (close + 2 < addrStr.size() && addrStr[close + 1] == ':') {
            try {
                port = static_cast<uint16_t>(
                    std::stoul(addrStr.substr(close + 2)));
            } catch (const std::exception&) {
                return false;
            }
        }
        NetAddress bracketed(ip, port);
        AddOperatorAddress(bracketed);
        return ConnectToAddress(bracketed);
    }

    size_t colonPos = (std::count(addrStr.begin(), addrStr.end(), ':') == 1)
                      ? addrStr.rfind(':') : std::string::npos;
    if (colonPos != std::string::npos) {
        ip   = addrStr.substr(0, colonPos);
        try {
            port = static_cast<uint16_t>(
                std::stoul(addrStr.substr(colonPos + 1)));
        } catch (const std::exception&) {
            return false;
        }
    } else {
        ip = addrStr;
    }
    NetAddress addr(ip, port);
    AddOperatorAddress(addr);
    return ConnectToAddress(addr);
}

bool ConnManager::DisconnectNode(NodeId id) {
    NodePtr node;
    {
        std::lock_guard<std::mutex> lock(
            mNodesMutex);
        auto it = mNodes.find(id);
        if (it == mNodes.end()) return false;
        node = it->second;
    }
    DisconnectNode(node, "manual disconnect");
    return true;
}

bool ConnManager::BanNode(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mBanMutex);
    mBannedIPs.push_back(ip);
    return true;
}

void ConnManager::ClearBanned() {
    std::lock_guard<std::mutex> lock(mBanMutex);
    mBannedIPs.clear();
}

void ConnManager::BroadcastTransaction(
    const Transaction& tx)
{
    std::vector<uint8_t> data = tx.Serialize();
    NetMessage msg(MsgType::TX, data);
    std::lock_guard<std::mutex> lock(mNodesMutex);
    for (auto& pair : mNodes) {
        if (!pair.second->IsFullyConnected())
            continue;
        {
            std::lock_guard<std::mutex> qlock(
                pair.second->sendMutex);
            if (pair.second->sendQueue.size() >
                MAX_QUEUE_PER_NODE)
            {
                std::cerr << "ConnManager: node "
                          << pair.second->addr
                                 .ToString()
                          << " queue saturated\n";
                continue;
            }
        }
        pair.second->PushMessage(msg);
    }
}

void ConnManager::BroadcastBlock(
    const Block& block)
{
    std::vector<uint8_t> data = block.Serialize();
    NetMessage msg(MsgType::BLOCK, data);
    std::lock_guard<std::mutex> lock(mNodesMutex);
    for (auto& pair : mNodes) {
        if (!pair.second->IsFullyConnected())
            continue;
        pair.second->PushMessage(msg);
    }
}

void ConnManager::BroadcastInv(
    const std::vector<InvItem>& items)
{
    std::vector<uint8_t> payload;
    uint32_t count =
        static_cast<uint32_t>(items.size());
    payload.push_back((count      ) & 0xFF);
    payload.push_back((count >>  8) & 0xFF);
    payload.push_back((count >> 16) & 0xFF);
    payload.push_back((count >> 24) & 0xFF);
    for (const auto& item : items) {
        payload.push_back(
            static_cast<uint8_t>(item.type));
        payload.insert(payload.end(),
                       item.hash.begin(),
                       item.hash.end());
    }
    NetMessage msg(MsgType::INV, payload);
    std::lock_guard<std::mutex> lock(mNodesMutex);
    for (auto& pair : mNodes) {
        if (!pair.second->IsFullyConnected())
            continue;
        {
            std::lock_guard<std::mutex> qlock(
                pair.second->sendMutex);
            if (pair.second->sendQueue.size() >
                MAX_QUEUE_PER_NODE) continue;
        }
        pair.second->PushMessage(msg);
    }
}

void ConnManager::SendMessageToNode(
    NodeId id, const NetMessage& msg)
{
    std::lock_guard<std::mutex> lock(mNodesMutex);
    auto it = mNodes.find(id);
    if (it != mNodes.end() &&
        it->second->IsFullyConnected())
        it->second->PushMessage(msg);
}

size_t ConnManager::GetNodeCount() const {
    std::lock_guard<std::mutex> lock(mNodesMutex);
    return mNodes.size();
}

size_t ConnManager::GetInboundCount() const {
    std::lock_guard<std::mutex> lock(mNodesMutex);
    size_t count = 0;
    for (const auto& pair : mNodes)
        if (pair.second->inbound) count++;
    return count;
}

size_t ConnManager::GetOutboundCount() const {
    std::lock_guard<std::mutex> lock(mNodesMutex);
    size_t count = 0;
    for (const auto& pair : mNodes)
        if (!pair.second->inbound) count++;
    return count;
}

std::string ConnManager::GetGroup16(const NetAddress& addr) {
    const std::string& ip = addr.ip;
    if (ip.empty()) return std::string();

    if (IsOnionAddress(ip)) return "onion:" + ip.substr(0, 1);

    size_t o1 = ip.find('.');
    if (o1 == std::string::npos) return std::string();
    size_t o2 = ip.find('.', o1 + 1);
    if (o2 == std::string::npos) return std::string();
    size_t o3 = ip.find('.', o2 + 1);
    if (o3 == std::string::npos) return std::string();

    const std::string a = ip.substr(0, o1);
    const std::string b = ip.substr(o1 + 1, o2 - (o1 + 1));
    const std::string c = ip.substr(o2 + 1, o3 - (o2 + 1));
    const std::string d = ip.substr(o3 + 1);

    const std::string* parts[4] = { &a, &b, &c, &d };
    for (int i = 0; i < 4; ++i) {
        const std::string& p = *parts[i];
        if (p.empty() || p.size() > 3) return std::string();
        int value = 0;
        for (char ch : p) {
            if (ch < '0' || ch > '9') return std::string();
            value = value * 10 + (ch - '0');
        }
        if (value > 255) return std::string();
    }

    return a + "." + b;
}

size_t ConnManager::CountOutboundInGroup(
    const std::string& group) const
{
    if (group.empty()) return 0;

    std::lock_guard<std::mutex> lock(mNodesMutex);
    size_t count = 0;
    for (const auto& pair : mNodes) {
        if (pair.second->inbound) continue;
        if (GetGroup16(pair.second->addr) == group) count++;
    }
    return count;
}

std::vector<NetAddress>
ConnManager::GetKnownAddresses() const
{
    std::lock_guard<std::mutex> lock(mAddrMutex);

    const int64_t now = GetCurrentTimestamp();
    std::vector<NetAddress> fresh;
    fresh.reserve(mKnownAddresses.size());
    for (const auto& a : mKnownAddresses) {
        if (!IsRelayableAddress(a.ip)) continue;

        if (a.lastSeen == 0 ||
            static_cast<uint64_t>(now) < a.lastSeen ||
            static_cast<uint64_t>(now) - a.lastSeen <= ADDR_HORIZON_SECONDS) {
            fresh.push_back(a);
        }
    }
    return fresh;
}

std::vector<ConnManager::PeerInfo> ConnManager::GetPeerInfo() const {
    std::vector<PeerInfo> out;
    std::lock_guard<std::mutex> lock(mNodesMutex);
    out.reserve(mNodes.size());
    for (const auto& pair : mNodes) {
        const NodePtr& n = pair.second;
        if (!n || !n->IsFullyConnected()) continue;

        PeerInfo info;
        info.id        = n->id;
        info.address   = n->addr.ToString();
        info.inbound   = n->inbound;
        info.version   = n->version;
        info.userAgent = n->userAgent;
        info.bestHeight = n->bestHeight;

        static const char* hexDigits = "0123456789abcdef";
        std::string h;
        h.reserve(64);
        for (size_t i = 0; i < n->bestBlockHash.size(); ++i) {
            h.push_back(hexDigits[(n->bestBlockHash[i] >> 4) & 0x0F]);
            h.push_back(hexDigits[n->bestBlockHash[i] & 0x0F]);
        }
        info.bestBlockHash = h;

        info.connectedAt = n->connTime;
        info.services    = n->addr.services;
        info.lastSend    = n->lastSend;
        info.lastRecv    = n->lastRecv;
        info.bytesSent   = n->bytesSent;
        info.bytesRecv   = n->bytesRecv;
        info.misbehavior = n->misbehavior;

        info.pingSeconds =
            (n->lastPingRecv > 0 && n->lastPingSent > 0 &&
             n->lastPingRecv >= n->lastPingSent)
            ? static_cast<double>(n->lastPingRecv - n->lastPingSent) /
              1000000.0
            : -1.0;

        out.push_back(info);
    }
    return out;
}

std::vector<NodeId>
ConnManager::GetConnectedNodeIds() const
{
    std::lock_guard<std::mutex> lock(mNodesMutex);
    std::vector<NodeId> ids;
    for (const auto& pair : mNodes)
        if (pair.second->IsFullyConnected())
            ids.push_back(pair.first);
    return ids;
}

void ConnManager::UpdateBestChain(
    uint32_t height,
    uint64_t round,
    const bytes32& blockHash)
{
    if (!(blockHash == mOptions.bestBlockHash)) {
        mLastTipChange = GetCurrentTimestamp();
    }
    mOptions.bestHeight    = height;
    mOptions.bestRound     = round;
    mOptions.bestBlockHash = blockHash;
}

size_t ConnManager::CountFullyConnected() const {
    std::lock_guard<std::mutex> lock(mNodesMutex);
    size_t count = 0;
    for (const auto& pair : mNodes) {
        if (pair.second && pair.second->IsFullyConnected()) count++;
    }
    return count;
}

void ConnManager::UseDefaultOnionProxy() {
    std::lock_guard<std::mutex> lock(mProxyMutex);
    if (mHaveOnionProxy) return;
    mOnionProxy     = NetAddress("127.0.0.1", 9050);
    mHaveOnionProxy = true;
    MONEU_LOG_INFO("P2P: onion peers reachable through 127.0.0.1:9050");
}

void ConnManager::OnOnionService(const std::string& host) {
    const NetAddress self(host, NetParams::DEFAULT_PORT);
    {
        std::lock_guard<std::mutex> lock(mLocalAddrMutex);
        bool listed = false;
        for (const auto& a : mLocalAddresses) {
            if (a.ip == host) listed = true;
        }
        if (!listed) mLocalAddresses.push_back(self);
        mOnionService = host;
    }

    std::vector<NodePtr> nodes;
    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        for (auto& pair : mNodes) {
            if (pair.second && pair.second->IsFullyConnected()) {
                nodes.push_back(pair.second);
            }
        }
    }
    for (auto& node : nodes) AdvertiseSelf(node);
}

void ConnManager::OnOnionServiceLost(const std::string& host) {
    std::lock_guard<std::mutex> lock(mLocalAddrMutex);
    for (auto it = mLocalAddresses.begin(); it != mLocalAddresses.end(); ) {
        if (it->ip == host) {
            it = mLocalAddresses.erase(it);
        } else {
            ++it;
        }
    }
    if (mOnionService == host) mOnionService.clear();
}

std::string ConnManager::GetProxyString() const {
    std::lock_guard<std::mutex> lock(mProxyMutex);
    return mHaveProxy ? mProxy.ToString() : std::string();
}

std::string ConnManager::GetOnionProxyString() const {
    std::lock_guard<std::mutex> lock(mProxyMutex);
    return mHaveOnionProxy ? mOnionProxy.ToString() : std::string();
}

std::string ConnManager::GetOnionService() const {
    std::lock_guard<std::mutex> lock(mLocalAddrMutex);
    return mOnionService;
}

uint64_t ConnManager::GetTotalBytesRecv() const {
    std::lock_guard<std::mutex> lock(mNodesMutex);
    uint64_t total = 0;
    for (const auto& pair : mNodes)
        total += pair.second->bytesRecv;
    return total;
}

uint64_t ConnManager::GetTotalBytesSent() const {
    std::lock_guard<std::mutex> lock(mNodesMutex);
    uint64_t total = 0;
    for (const auto& pair : mNodes)
        total += pair.second->bytesSent;
    return total;
}

} // namespace net
} // namespace MONEU
