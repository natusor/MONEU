// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "net.h"
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <map>
#include <set>
#include <cstdio>
#include "log/log.h"
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
    : mAcceptor(mIO)
    , mNextNodeId(1)
    , mRunning(false)
    , mNetworkActive(true)
    , mOptions(options)
    , mLastSelfAdvertise(0)
    , mLastAddressSave(0)
    , mLastAddrRequest(0)
{
    random_buffer(reinterpret_cast<uint8_t*>(&mLocalNonce),
                  sizeof(mLocalNonce));
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
    node->timeoutTimer->expires_after(
        std::chrono::seconds(HANDSHAKE_TIMEOUT_SEC));
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
    boost::system::error_code ec;
    node->timeoutTimer->cancel(ec);
}

bool ConnManager::Start(
    const NetCallbacks& callbacks)
{
    mCallbacks = callbacks;
    mRunning   = true;
    if (mOptions.listen) {
        try {
            tcp::endpoint endpoint(
                tcp::v4(), mOptions.listenPort);
            mAcceptor.open(endpoint.protocol());
            mAcceptor.set_option(
                asio::socket_base::reuse_address(
                    true));
            mAcceptor.bind(endpoint);
            mAcceptor.listen();
            mAcceptor.non_blocking(true);
            std::cerr << "ConnManager: listening "
                         "on port "
                      << mOptions.listenPort << "\n";
        } catch (const std::exception& e) {
            std::cerr << "ConnManager: listen "
                         "failed: "
                      << e.what() << "\n";
            return false;
        }
    }
    for (const auto& s : mOptions.seedNodes)
        AddNode(s);
    for (const auto& a : mOptions.addNodes)
        AddNode(a);
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

    DiscoverLocalAddresses();
    mWorkGuard.reset(
        new asio::executor_work_guard<asio::io_context::executor_type>(
            asio::make_work_guard(mIO)));
    mThreads.emplace_back([this]() {
        try { mIO.run(); } catch (...) {}
    });
    MONEU_LOG_INFO("P2P: listening on port " +
                   std::to_string(mOptions.listenPort));
    return true;
}

void ConnManager::Stop() {
    if (mThreads.empty()) return;

    mRunning = false;

    {
        boost::system::error_code ec;
        mAcceptor.cancel(ec);
        mAcceptor.close(ec);
    }

    mCv.notify_all();

    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        for (auto& pair : mNodes) {
            boost::system::error_code ec;
            pair.second->timeoutTimer->cancel(ec);
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
    mRunning = false;
    {
        boost::system::error_code ec;
        mAcceptor.cancel(ec);
        mAcceptor.close(ec);
    }
    mCv.notify_all();
    if (mWorkGuard) mWorkGuard->reset();
    mIO.stop();
}

void ConnManager::AcceptLoop() {
    while (mRunning) {
        try {
            if (!mAcceptor.is_open()) {
                std::unique_lock<std::mutex> lock(mCvMutex);
                mCv.wait_for(lock, std::chrono::seconds(1),
                             [this]() { return !mRunning; });
                continue;
            }

            int fd = static_cast<int>(mAcceptor.native_handle());
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            struct timeval tv = {0, 500000};  // 500 ms
            int sel = select(fd + 1, &rfds,
                             nullptr, nullptr, &tv);
            if (!mRunning) break;
            if (sel <= 0) {
                continue;
            }

            auto node = std::make_shared<Node>(
                mIO, GetNextNodeId(), true);
            boost::system::error_code ec;
            mAcceptor.accept(node->socket, ec);
            if (ec) {
                if (mRunning &&
                    ec != boost::asio::error::would_block &&
                    ec != boost::asio::error::try_again) {
                    std::cerr << "ConnManager: "
                                 "accept error: "
                              << ec.message()
                              << "\n";
                }
                continue;
            }
            node->socket.non_blocking(false, ec);
            std::string ip = node->socket
                .remote_endpoint(ec)
                .address().to_string();
            if (ec) continue;
            const uint16_t remotePort =
                node->socket.remote_endpoint(ec).port();
            if (ec) continue;
            if (IsIPBanned(ip)) {
                std::cerr << "ConnManager: rejected"
                             " banned " << ip << "\n";
                boost::system::error_code closeEc;
                node->socket.close(closeEc);
                continue;
            }
            if (!CheckConnectionLimitForIP(ip)) {
                boost::system::error_code closeEc;
                node->socket.close(closeEc);
                continue;
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
                    DecrementConnectionCount(ip);
                    boost::system::error_code closeEc;
                    node->socket.close(closeEc);
                    continue;
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
            MONEU_LOG_INFO("New inbound peer connected: peer=" +
                           std::to_string(node->id) +
                           node::Log::PeerAddr(node->addr.ToString()));
            StartHandshakeTimeout(node);
            SendVersion(node);
            StartRead(node);
            if (mCallbacks.onNodeConnected)
                mCallbacks.onNodeConnected(node->id);
        } catch (const std::exception& e) {
            std::cerr << "ConnManager: AcceptLoop "
                         "exception: "
                      << e.what() << "\n";
        }
    }
}

void ConnManager::ConnectLoop() {
    while (mRunning) {
        {
            std::unique_lock<std::mutex> lock(mCvMutex);
            mCv.wait_for(lock, std::chrono::seconds(30),
                         [this]() { return !mRunning; });
        }
        if (!mRunning) break;
        if (!mNetworkActive) continue;
        size_t outbound = GetOutboundCount();
        if (outbound >= mOptions.maxOutbound) continue;
        std::vector<NetAddress> candidates;
        {
            std::lock_guard<std::mutex> lock(
                mAddrMutex);
            candidates = mKnownAddresses;
        }
        for (const auto& addr : candidates) {
            if (outbound >= mOptions.maxOutbound) break;
            if (!mRunning) break;
            const std::string group = GetGroup16(addr);
            if (CountOutboundInGroup(group) >= MAX_OUTBOUND_PER_GROUP) {
                continue;
            }
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

bool ConnManager::ConnectToAddress(const NetAddress& addr) {
    if (IsIPBanned(addr.ip)) return false;
    mAddrMan.Attempt(addr.ip, addr.port, GetCurrentTimestamp());
    if (IsAlreadyConnected(addr)) return false;
    if (!CheckConnectionLimitForIP(addr.ip)) return false;

    auto node = std::make_shared<Node>(mIO, GetNextNodeId(), false);

    tcp::resolver resolver(mIO);
    boost::system::error_code ec;
    auto endpoints = resolver.resolve(addr.ip, std::to_string(addr.port), ec);
    if (ec) {
        std::cerr << "ConnManager: outbound address "
                     "resolve failed: " << ec.message() << "\n";
        DecrementConnectionCount(addr.ip);
        return false;
    }

    bool connected = false;
    for (auto it = endpoints; it != tcp::resolver::iterator(); ++it) {
        ec = boost::system::error_code();
        node->socket.close(ec);

        node->socket.open(it->endpoint().protocol(), ec);
        if (ec) continue;

        node->socket.non_blocking(true, ec);
        if (ec) continue;

        node->socket.connect(*it, ec);
        if (ec == boost::asio::error::would_block ||
            ec == boost::asio::error::in_progress) {
            while (!connected && mRunning) {
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(node->socket.native_handle(), &wfds);
                struct timeval tv = {0, 500000};  // 500ms
                int sel = select(node->socket.native_handle() + 1,
                                 nullptr, &wfds, nullptr, &tv);
                if (sel > 0) {
                    boost::system::error_code ec2;
                    node->socket.non_blocking(false, ec2);
                    int err = 0;
                    socklen_t len = sizeof(err);
                    getsockopt(node->socket.native_handle(),
                               SOL_SOCKET, SO_ERROR,
                               (char*)&err, &len);
                    if (err == 0) {
                        connected = true;
                    }
                } else if (sel == 0) {
                } else {
                    break;
                }
            }
        } else if (!ec) {
            connected = true;
        }
        if (connected) break;
    }

    node->socket.non_blocking(false, ec);

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
            if (mCallbacks.haveBlock && mCallbacks.haveBlock(item.hash)) {
                continue;
            }
            if (!ShouldRequestBlock(item.hash, node->id)) continue;
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

namespace {
const int64_t BLOCK_IN_FLIGHT_TIMEOUT_SEC = 1800;
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

    size_t fromThisPeer = 0;
    for (const auto& entry : mBlocksInFlight) {
        if (entry.second.peer == from) fromThisPeer++;
    }
    if (fromThisPeer >= MAX_BLOCKS_IN_FLIGHT_PER_PEER) return false;

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
        const size_t protectByAge = candidates.size() / 2;
        protectBest(protectByAge,
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
            if (now - mStallingSince[blocker] > BLOCK_STALL_TIMEOUT_SEC) {
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
            if (it == mNodes.end() || !it->second) continue;
            node = it->second;
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

    std::vector<NodeId> behindUs;
    {
        std::lock_guard<std::mutex> lock(mNodesMutex);
        for (const auto& pair : mNodes) {
            const NodePtr& n = pair.second;
            if (!n || !n->IsFullyConnected()) continue;
            if (n->bestHeight > ourHeight) behindUs.push_back(n->id);
        }
    }
    if (behindUs.empty()) return;

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
            for (const auto& data : toSend) {
                boost::system::error_code ec;
                asio::write(node->socket,
                            asio::buffer(data), ec);
                if (ec) {
                    std::cerr << "ConnManager: write"
                                 " error to "
                              << "peer=" << node->id
                              << ": " << ec.message()
                              << " (" << ec.value()
                              << ")\n";
                    DisconnectNode(node,
                                   ec.message());
                    break;
                }
                node->bytesSent += data.size();
                node->lastSend =
                    GetCurrentTimestamp();
            }
        }
    }
}

void ConnManager::SetExternalAddress(const std::string& ip,
                                     uint16_t port) {
    std::lock_guard<std::mutex> lock(mAddrMutex);
    mExternalAddress = NetAddress(ip, port);
    mExternalAddress.lastSeen = GetCurrentTimestamp();
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

bool ConnManager::IsPrivateAddress(const std::string& ip) {
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
    return true;
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
        if (!mExternalAddress.ip.empty()) found.push_back(mExternalAddress);
    }

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
    if (!SelectLocalAddressFor(node->addr, self)) {
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
        AddKnownAddress(NetAddress(ip, static_cast<uint16_t>(port)));
        added++;
    }

    for (const auto& host : NetParams::GetDNSSeeds()) {
        try {
            tcp::resolver resolver(mIO);
            tcp::resolver::query query(
                host, std::to_string(NetParams::DEFAULT_PORT));
            boost::system::error_code ec;
            auto it = resolver.resolve(query, ec);
            if (ec) continue;
            for (; it != tcp::resolver::iterator(); ++it) {
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
    node->timeoutTimer->cancel(ec);
    node->socket.shutdown(
        tcp::socket::shutdown_both, ec);
    node->socket.close(ec);
    DecrementConnectionCount(node->addr.ip);
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
    if (!IsUsableAddress(addr.ip)) return;

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
    mOptions.bestHeight    = height;
    mOptions.bestRound     = round;
    mOptions.bestBlockHash = blockHash;
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
