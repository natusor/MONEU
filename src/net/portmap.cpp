// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "portmap.h"

#include "../log/log.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace MONEU {
namespace net {

namespace {

// The port every NAT-PMP router listens on, fixed by RFC 6886.
const uint16_t NATPMP_PORT = 5351;

// The only version of the protocol.
const uint8_t NATPMP_VERSION = 0;

const uint8_t OP_ASK_ADDRESS = 0;
const uint8_t OP_MAP_TCP     = 2;

// A router answers with the opcode plus 128.
const uint8_t OP_ANSWER_FLAG = 128;

// Result code zero means the router agreed.
const uint16_t RESULT_OK = 0;

// A router that does answer usually answers at once. Waiting longer than this
// only delays the log line that says it did not.
const int REQUEST_TIMEOUT_MS = 1000;

// Two tries, because a single lost UDP packet should not be taken for a router
// that does not speak the protocol.
const int REQUEST_ATTEMPTS = 2;

void WriteBE16(uint8_t* out, uint16_t v) {
    out[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[1] = static_cast<uint8_t>(v & 0xFF);
}

void WriteBE32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(v & 0xFF);
}

uint16_t ReadBE16(const uint8_t* in) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(in[0]) << 8) | static_cast<uint16_t>(in[1]));
}

} // namespace

PortMapper::PortMapper()
    : mRunning(false)
    , mStopping(false)
    , mMapped(false)
    , mExternalPort(0)
{}

PortMapper::~PortMapper() {
    Stop();
}

std::string PortMapper::GetExternalAddress() const {
    std::lock_guard<std::mutex> lock(mAddressMutex);
    return mExternalAddress;
}

std::string PortMapper::FindDefaultGateway() {
#ifndef WIN32
    // The kernel lists routes here. The default route is the one whose
    // destination is all zeroes; its gateway field is the router.
    std::ifstream routes("/proc/net/route");
    if (!routes.is_open()) return std::string();

    std::string line;
    // The first line names the columns.
    std::getline(routes, line);

    while (std::getline(routes, line)) {
        std::istringstream fields(line);
        std::string iface, destination, gateway;
        if (!(fields >> iface >> destination >> gateway)) continue;
        if (destination != "00000000") continue;
        if (gateway.size() != 8) continue;

        unsigned long raw = 0;
        try {
            raw = std::stoul(gateway, NULL, 16);
        } catch (...) {
            continue;
        }
        if (raw == 0) continue;

        // The field is little endian, so the first pair of digits is the
        // last number of the address.
        struct in_addr addr;
        addr.s_addr = static_cast<in_addr_t>(raw);
        char text[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &addr, text, sizeof(text))) continue;
        return std::string(text);
    }
#endif
    return std::string();
}

size_t PortMapper::Exchange(const std::string& gateway,
                            const uint8_t* request, size_t requestLen,
                            uint8_t* response, size_t responseCapacity,
                            int timeoutMs)
{
#ifndef WIN32
    if (gateway.empty() || request == NULL || response == NULL) return 0;

    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    struct timeval tv;
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in to;
    std::memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port   = htons(NATPMP_PORT);
    if (inet_pton(AF_INET, gateway.c_str(), &to.sin_addr) != 1) {
        ::close(sock);
        return 0;
    }

    const ssize_t sent = ::sendto(sock, request, requestLen, 0,
                                  reinterpret_cast<struct sockaddr*>(&to),
                                  sizeof(to));
    if (sent != static_cast<ssize_t>(requestLen)) {
        ::close(sock);
        return 0;
    }

    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    std::memset(&from, 0, sizeof(from));

    const ssize_t got = ::recvfrom(sock, response, responseCapacity, 0,
                                   reinterpret_cast<struct sockaddr*>(&from),
                                   &fromLen);
    ::close(sock);

    if (got <= 0) return 0;

    // Only the router we asked may answer. Anything else on the network
    // could otherwise claim to have granted a mapping.
    if (from.sin_addr.s_addr != to.sin_addr.s_addr) return 0;

    return static_cast<size_t>(got);
#else
    (void)gateway; (void)request; (void)requestLen;
    (void)response; (void)responseCapacity; (void)timeoutMs;
    return 0;
#endif
}

bool PortMapper::AskExternalAddress(const std::string& gateway,
                                    std::string& addressOut)
{
#ifndef WIN32
    // Two bytes: the version and the opcode.
    uint8_t request[2];
    request[0] = NATPMP_VERSION;
    request[1] = OP_ASK_ADDRESS;

    // Twelve bytes come back: version, opcode, result, seconds since the
    // router started, and the address itself.
    uint8_t response[16];

    for (int attempt = 0; attempt < REQUEST_ATTEMPTS; ++attempt) {
        std::memset(response, 0, sizeof(response));
        const size_t got = Exchange(gateway, request, sizeof(request),
                                    response, sizeof(response),
                                    REQUEST_TIMEOUT_MS);
        if (got < 12) continue;
        if (response[0] != NATPMP_VERSION) continue;
        if (response[1] != (OP_ASK_ADDRESS + OP_ANSWER_FLAG)) continue;
        if (ReadBE16(&response[2]) != RESULT_OK) return false;

        struct in_addr addr;
        std::memcpy(&addr.s_addr, &response[8], 4);
        char text[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &addr, text, sizeof(text))) return false;
        addressOut = text;
        return true;
    }
#else
    (void)gateway; (void)addressOut;
#endif
    return false;
}

bool PortMapper::AskMapping(const std::string& gateway,
                            uint16_t privatePort,
                            uint16_t suggestedExternalPort,
                            uint32_t lifetimeSeconds,
                            uint16_t& grantedPortOut)
{
#ifndef WIN32
    // Twelve bytes: version, opcode, two reserved, the port here, the port
    // asked for outside, and how long the mapping should hold.
    uint8_t request[12];
    std::memset(request, 0, sizeof(request));
    request[0] = NATPMP_VERSION;
    request[1] = OP_MAP_TCP;
    WriteBE16(&request[4], privatePort);
    WriteBE16(&request[6], suggestedExternalPort);
    WriteBE32(&request[8], lifetimeSeconds);

    // Sixteen bytes come back, ending with the lifetime the router granted.
    uint8_t response[24];

    for (int attempt = 0; attempt < REQUEST_ATTEMPTS; ++attempt) {
        std::memset(response, 0, sizeof(response));
        const size_t got = Exchange(gateway, request, sizeof(request),
                                    response, sizeof(response),
                                    REQUEST_TIMEOUT_MS);
        if (got < 16) continue;
        if (response[0] != NATPMP_VERSION) continue;
        if (response[1] != (OP_MAP_TCP + OP_ANSWER_FLAG)) continue;
        if (ReadBE16(&response[2]) != RESULT_OK) return false;

        // The router repeats the port on this side, so a stray answer meant
        // for another program is not taken for ours.
        if (ReadBE16(&response[8]) != privatePort) continue;

        grantedPortOut = ReadBE16(&response[10]);
        return true;
    }
#else
    (void)gateway; (void)privatePort; (void)suggestedExternalPort;
    (void)lifetimeSeconds; (void)grantedPortOut;
#endif
    return false;
}

bool PortMapper::WaitFor(int seconds) {
    std::unique_lock<std::mutex> lock(mWaitMutex);
    mWaitCV.wait_for(lock, std::chrono::seconds(seconds),
                     [this]() { return mStopping.load(); });
    return !mStopping.load();
}

bool PortMapper::Start(uint16_t privatePort) {
    if (privatePort == 0) return false;
    if (mRunning.load()) return false;

    mStopping = false;
    mMapped   = false;
    mExternalPort = 0;
    {
        std::lock_guard<std::mutex> lock(mAddressMutex);
        mExternalAddress.clear();
        mGateway.clear();
    }

    mRunning = true;
    mThread = std::thread(&PortMapper::Loop, this, privatePort);
    return true;
}

void PortMapper::Stop() {
    if (!mRunning.load()) {
        if (mThread.joinable()) mThread.join();
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mWaitMutex);
        mStopping = true;
    }
    mWaitCV.notify_all();

    if (mThread.joinable()) mThread.join();
    mRunning = false;
}

void PortMapper::Loop(uint16_t privatePort) {
    const std::string gateway = FindDefaultGateway();
    if (gateway.empty()) {
        MONEU_LOG_INFO(
            "Port mapping: no gateway on this machine, nothing to ask. "
            "Incoming connections work only if this address is reachable "
            "already.");
        mRunning = false;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mAddressMutex);
        mGateway = gateway;
    }

    bool announced = false;

    while (!mStopping.load()) {
        uint16_t granted = 0;
        const uint16_t suggested =
            mExternalPort.load() != 0 ? mExternalPort.load() : privatePort;

        if (AskMapping(gateway, privatePort, suggested,
                       MAPPING_LIFETIME_SECONDS, granted)) {
            mExternalPort = granted;
            mMapped = true;

            if (!announced) {
                std::string external;
                if (AskExternalAddress(gateway, external)) {
                    std::lock_guard<std::mutex> lock(mAddressMutex);
                    mExternalAddress = external;
                }

                const std::string seen = GetExternalAddress();
                if (!seen.empty()) {
                    MONEU_LOG_INFO(
                        "Port mapping: the router forwards port " +
                        std::to_string(granted) + " to this node. Others can "
                        "reach it at " + seen + ":" +
                        std::to_string(granted));
                } else {
                    MONEU_LOG_INFO(
                        "Port mapping: the router forwards port " +
                        std::to_string(granted) + " to this node.");
                }
                announced = true;
            }

            if (!WaitFor(RENEW_SECONDS)) break;
            continue;
        }

        if (mMapped.load()) {
            // It worked before, so this is most likely a lost packet or a
            // router that just restarted. Say so once and keep trying.
            MONEU_LOG_INFO(
                "Port mapping: the router stopped answering, trying again "
                "in a few minutes.");
        } else if (!announced) {
            MONEU_LOG_INFO(
                "Port mapping: the router did not grant a forward for port " +
                std::to_string(privatePort) + ". The node works and mines as "
                "usual, but other nodes cannot reach it. Forward the port by "
                "hand to let them in.");
            announced = true;
        }

        mMapped = false;
        if (!WaitFor(RETRY_SECONDS)) break;
    }

    // Leaving the mapping behind would keep a hole open in the router long
    // after the node is gone.
    if (mMapped.load()) {
        uint16_t ignored = 0;
        const uint16_t mapped = mExternalPort.load();
        if (AskMapping(gateway, privatePort, mapped, 0, ignored)) {
            MONEU_LOG_INFO("Port mapping: the forward has been removed.");
        }
    }

    mMapped = false;
    mExternalPort = 0;
    mRunning = false;
}

} // namespace net
} // namespace MONEU
