// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "portmap.h"

#include "../log/log.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace MONEU {
namespace net {

namespace {

// Both protocols use this port, fixed by RFC 6886 and kept by RFC 6887.
const uint16_t NATPMP_PORT = 5351;

// NAT-PMP has only ever had one version. PCP took the next number, which is
// how a router tells the two apart: the first byte of the request.
const uint8_t NATPMP_VERSION = 0;
const uint8_t PCP_VERSION    = 2;

const uint8_t OP_ASK_ADDRESS = 0;
const uint8_t OP_MAP_TCP     = 2;

// PCP opcodes. MAP asks for an incoming port, which is what a node needs.
const uint8_t PCP_OP_MAP = 1;

// PCP marks an answer with the top bit of the opcode byte rather than by
// adding 128 to the opcode the way NAT-PMP does.
const uint8_t PCP_RESPONSE_BIT = 0x80;

// The protocol number for TCP, as used inside a PCP MAP request.
const uint8_t PCP_PROTOCOL_TCP = 6;

// A PCP request is 24 bytes of header and, for MAP, 36 bytes after it.
const size_t PCP_REQUEST_SIZE  = 60;

// An answer is 24 bytes of header and 36 after it as well.
const size_t PCP_RESPONSE_SIZE = 60;

// Result code zero in a PCP answer means the router agreed.
const uint8_t PCP_SUCCESS = 0;

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

// PCP carries every address as sixteen bytes, so an IPv4 address travels as
// the IPv4-mapped IPv6 form: eighty zero bits, sixteen one bits, then the
// four bytes themselves.
void WriteMappedV4(uint8_t out[16], const struct in_addr& addr) {
    std::memset(out, 0, 16);
    out[10] = 0xFF;
    out[11] = 0xFF;
    std::memcpy(&out[12], &addr.s_addr, 4);
}

bool IsMappedV4(const uint8_t in[16]) {
    for (int i = 0; i < 10; ++i) {
        if (in[i] != 0) return false;
    }
    return in[10] == 0xFF && in[11] == 0xFF;
}

#ifdef WIN32
std::atomic<bool> gWinsockStarted(false);

void ReleaseWinsock() {
    if (gWinsockStarted.exchange(false)) ::WSACleanup();
}
#endif

} // namespace

PortMapper::PortMapper()
    : mRunning(false)
    , mStopping(false)
    , mMapped(false)
    , mExternalPort(0)
    , mProtocol(PROTO_NONE)
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
#else
    ULONG size = 0;
    if (::GetIpForwardTable(NULL, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        return std::string();
    }
    std::vector<uint8_t> buffer(size);
    PMIB_IPFORWARDTABLE table =
        reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());
    if (::GetIpForwardTable(table, &size, TRUE) != NO_ERROR) {
        return std::string();
    }

    DWORD bestGateway = 0;
    DWORD bestMetric  = 0xFFFFFFFF;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_IPFORWARDROW& row = table->table[i];
        if (row.dwForwardDest != 0 || row.dwForwardMask != 0) continue;
        if (row.dwForwardNextHop == 0) continue;
        if (row.dwForwardMetric1 < bestMetric) {
            bestMetric  = row.dwForwardMetric1;
            bestGateway = row.dwForwardNextHop;
        }
    }
    if (bestGateway == 0) return std::string();

    struct in_addr addr;
    addr.s_addr = bestGateway;
    char text[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, text, sizeof(text))) return std::string();
    return std::string(text);
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
    if (gateway.empty() || request == NULL || response == NULL) return 0;

    const SOCKET sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return 0;

    const DWORD tv = static_cast<DWORD>(timeoutMs);
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));

    struct sockaddr_in to;
    std::memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port   = htons(NATPMP_PORT);
    if (inet_pton(AF_INET, gateway.c_str(), &to.sin_addr) != 1) {
        ::closesocket(sock);
        return 0;
    }

    const int sent = ::sendto(sock, reinterpret_cast<const char*>(request),
                              static_cast<int>(requestLen), 0,
                              reinterpret_cast<struct sockaddr*>(&to),
                              sizeof(to));
    if (sent != static_cast<int>(requestLen)) {
        ::closesocket(sock);
        return 0;
    }

    struct sockaddr_in from;
    int fromLen = sizeof(from);
    std::memset(&from, 0, sizeof(from));

    const int got = ::recvfrom(sock, reinterpret_cast<char*>(response),
                               static_cast<int>(responseCapacity), 0,
                               reinterpret_cast<struct sockaddr*>(&from),
                               &fromLen);
    ::closesocket(sock);

    if (got <= 0) return 0;

    if (from.sin_addr.s_addr != to.sin_addr.s_addr) return 0;

    return static_cast<size_t>(got);
#endif
}

bool PortMapper::FindLocalAddressTowards(const std::string& gateway,
                                        uint8_t addrOut[16])
{
#ifndef WIN32
    // A PCP request names the host the mapping is for, and on a machine with
    // several addresses only the kernel knows which one leads to the gateway.
    // Connecting a UDP socket sends nothing, but it makes the kernel pick a
    // route, and the chosen address can then be read back.
    if (gateway.empty()) return false;

    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in to;
    std::memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port   = htons(NATPMP_PORT);
    if (inet_pton(AF_INET, gateway.c_str(), &to.sin_addr) != 1) {
        ::close(sock);
        return false;
    }

    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&to),
                  sizeof(to)) != 0) {
        ::close(sock);
        return false;
    }

    struct sockaddr_in local;
    socklen_t localLen = sizeof(local);
    std::memset(&local, 0, sizeof(local));
    const int got = ::getsockname(
        sock, reinterpret_cast<struct sockaddr*>(&local), &localLen);
    ::close(sock);

    if (got != 0) return false;
    if (local.sin_addr.s_addr == 0) return false;

    WriteMappedV4(addrOut, local.sin_addr);
    return true;
#else
    if (gateway.empty()) return false;

    const SOCKET sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return false;

    struct sockaddr_in to;
    std::memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port   = htons(NATPMP_PORT);
    if (inet_pton(AF_INET, gateway.c_str(), &to.sin_addr) != 1) {
        ::closesocket(sock);
        return false;
    }

    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&to),
                  sizeof(to)) != 0) {
        ::closesocket(sock);
        return false;
    }

    struct sockaddr_in local;
    int localLen = sizeof(local);
    std::memset(&local, 0, sizeof(local));
    const int got = ::getsockname(
        sock, reinterpret_cast<struct sockaddr*>(&local), &localLen);
    ::closesocket(sock);

    if (got != 0) return false;
    if (local.sin_addr.s_addr == 0) return false;

    WriteMappedV4(addrOut, local.sin_addr);
    return true;
#endif
}

bool PortMapper::AskExternalAddress(const std::string& gateway,
                                    std::string& addressOut)
{
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
    return false;
}

bool PortMapper::AskMappingPCP(const std::string& gateway,
                               uint16_t privatePort,
                               uint16_t suggestedExternalPort,
                               uint32_t lifetimeSeconds,
                               uint16_t& grantedPortOut,
                               std::string& externalAddressOut)
{
    uint8_t client[16];
    if (!FindLocalAddressTowards(gateway, client)) return false;

    // The nonce ties an answer to this request and lets the router recognise
    // a renewal as the same mapping rather than a new one. It is drawn once
    // per mapping and kept for as long as the node holds it.
    static uint8_t nonce[12];
    static bool nonceReady = false;
    if (!nonceReady) {
        // The clock and the address are enough here: the nonce is not a
        // secret, it only has to be unlikely to repeat.
        const uint64_t now =
            static_cast<uint64_t>(std::time(NULL));
        std::memcpy(&nonce[0], &now, 8);
        std::memcpy(&nonce[8], &client[12], 4);
        nonceReady = true;
    }

    uint8_t request[PCP_REQUEST_SIZE];
    std::memset(request, 0, sizeof(request));

    // Header: version, opcode, two reserved bytes, lifetime, then the
    // address of the host asking.
    request[0] = PCP_VERSION;
    request[1] = PCP_OP_MAP;
    WriteBE32(&request[4], lifetimeSeconds);
    std::memcpy(&request[8], client, 16);

    // MAP body: the nonce, the protocol, three reserved bytes, the port on
    // this side, the port asked for outside, and the address asked for.
    // Zeroes in the last field let the router choose, which is what a home
    // connection with a changing address needs.
    std::memcpy(&request[24], nonce, 12);
    request[36] = PCP_PROTOCOL_TCP;
    WriteBE16(&request[40], privatePort);
    WriteBE16(&request[42], suggestedExternalPort);

    uint8_t response[PCP_RESPONSE_SIZE];

    for (int attempt = 0; attempt < REQUEST_ATTEMPTS; ++attempt) {
        std::memset(response, 0, sizeof(response));
        const size_t got = Exchange(gateway, request, sizeof(request),
                                    response, sizeof(response),
                                    REQUEST_TIMEOUT_MS);
        if (got < PCP_RESPONSE_SIZE) continue;
        if (response[0] != PCP_VERSION) continue;
        if (response[1] != (PCP_OP_MAP | PCP_RESPONSE_BIT)) continue;
        if (response[3] != PCP_SUCCESS) return false;

        // The router repeats the nonce and the port on this side. Anything
        // that does not match belongs to another program on this network.
        if (std::memcmp(&response[24], nonce, 12) != 0) continue;
        if (ReadBE16(&response[40]) != privatePort) continue;

        grantedPortOut = ReadBE16(&response[42]);

        // The assigned address comes back in the same answer, so unlike
        // NAT-PMP there is no second exchange to make.
        uint8_t assigned[16];
        std::memcpy(assigned, &response[44], 16);
        if (IsMappedV4(assigned)) {
            struct in_addr addr;
            std::memcpy(&addr.s_addr, &assigned[12], 4);
            char text[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr, text, sizeof(text))) {
                externalAddressOut = text;
            }
        }
        return true;
    }
    return false;
}

bool PortMapper::AskMappingNATPMP(const std::string& gateway,
                                  uint16_t privatePort,
                                  uint16_t suggestedExternalPort,
                                  uint32_t lifetimeSeconds,
                                  uint16_t& grantedPortOut)
{
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
    mProtocol = PROTO_NONE;
    {
        std::lock_guard<std::mutex> lock(mAddressMutex);
        mExternalAddress.clear();
        mGateway.clear();
    }

#ifdef WIN32
    if (!gWinsockStarted.load()) {
        WSADATA wsa;
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
        gWinsockStarted = true;
    }
#endif

    mRunning = true;
    mThread = std::thread(&PortMapper::Loop, this, privatePort);
    return true;
}

void PortMapper::Stop() {
    if (!mRunning.load()) {
        if (mThread.joinable()) mThread.join();
#ifdef WIN32
        ReleaseWinsock();
#endif
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mWaitMutex);
        mStopping = true;
    }
    mWaitCV.notify_all();

    if (mThread.joinable()) mThread.join();
    mRunning = false;
#ifdef WIN32
    ReleaseWinsock();
#endif
}

void PortMapper::Loop(uint16_t privatePort) {
    // No gateway means nothing to ask, which is the normal case on a machine
    // with a public address of its own. Nothing is written: the node is not
    // worse off than before, and a line about it would only look like a
    // fault where there is none.
    const std::string gateway = FindDefaultGateway();
    if (gateway.empty()) {
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
        std::string external;
        const uint16_t suggested =
            mExternalPort.load() != 0 ? mExternalPort.load() : privatePort;

        // PCP first, because it is what most routers of the last decade
        // answer. A box that only knows NAT-PMP simply says nothing to a
        // version it does not recognise, and the fallback below catches it.
        // Once one of them has worked, the renewals go straight to it.
        bool ok = false;
        const int chosen = mProtocol.load();

        if (chosen != PROTO_NATPMP) {
            ok = AskMappingPCP(gateway, privatePort, suggested,
                               MAPPING_LIFETIME_SECONDS, granted, external);
            if (ok) mProtocol = PROTO_PCP;
        }

        if (!ok && chosen != PROTO_PCP) {
            ok = AskMappingNATPMP(gateway, privatePort, suggested,
                                  MAPPING_LIFETIME_SECONDS, granted);
            if (ok) mProtocol = PROTO_NATPMP;
        }

        if (ok) {
            mExternalPort = granted;
            mMapped = true;

            if (!announced) {
                // PCP hands the address back with the mapping. NAT-PMP needs
                // a second exchange for it.
                if (external.empty()) {
                    AskExternalAddress(gateway, external);
                }
                if (!external.empty()) {
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

        // A router that says no is not a fault: most of them are set to
        // refuse, and the node runs exactly as it did before. Nothing is
        // written, so nobody reads a warning into a state that is normal.
        // The loop keeps asking, so turning the setting on in the router
        // later is noticed by itself.
        mMapped = false;
        if (!WaitFor(RETRY_SECONDS)) break;
    }

    // Leaving the mapping behind would keep a hole open in the router long
    // after the node is gone.
    if (mMapped.load()) {
        uint16_t ignored = 0;
        std::string unused;
        const uint16_t mapped = mExternalPort.load();
        if (mProtocol.load() == PROTO_PCP) {
            AskMappingPCP(gateway, privatePort, mapped, 0, ignored, unused);
        } else {
            AskMappingNATPMP(gateway, privatePort, mapped, 0, ignored);
        }
    }

    mMapped = false;
    mExternalPort = 0;
    mRunning = false;
}

} // namespace net
} // namespace MONEU
