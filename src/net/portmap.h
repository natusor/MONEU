// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MONEU_NET_PORTMAP_H
#define MONEU_NET_PORTMAP_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

namespace MONEU {
namespace net {

// Asks the home router to forward the listening port, so that other nodes can
// reach this one from the outside.
//
// Without this a node behind a home router can only make outgoing connections.
// It still mines and still follows the chain, but nobody can connect to it, so
// it adds no entry point to the network. Only machines with a public address
// of their own can take incoming connections, and in a young network those are
// few.
//
// The protocol is NAT-PMP, RFC 6886: a short UDP exchange with the default
// gateway on port 5351. Routers have supported it for years and it needs no
// library, unlike UPnP, which Bitcoin dropped after repeated security holes in
// the library it relied on.
//
// The mapping expires by itself, so a thread renews it every twenty minutes.
// If the router does not answer, the node writes one line to the log and works
// on exactly as before.
class PortMapper {
public:
    // How long the router is asked to hold the mapping.
    static const uint32_t MAPPING_LIFETIME_SECONDS = 3600;

    // Renewed well before it expires, so a missed renewal is not fatal.
    static const int RENEW_SECONDS = 20 * 60;

    // After a failure the node waits this long before trying again, rather
    // than asking a router that clearly does not answer every few seconds.
    static const int RETRY_SECONDS = 5 * 60;

    PortMapper();
    ~PortMapper();

    PortMapper(const PortMapper&) = delete;
    PortMapper& operator=(const PortMapper&) = delete;

    // Starts the renewing thread. Returns false when already running or when
    // the port is zero. Never blocks: the first attempt happens on the thread,
    // so a router that does not answer cannot hold up startup.
    bool Start(uint16_t privatePort);

    // Removes the mapping and stops the thread. Safe to call more than once
    // and safe to call when Start failed.
    void Stop();

    bool IsRunning() const { return mRunning.load(); }

    // True once a router has granted a mapping.
    bool IsMapped() const { return mMapped.load(); }

    // The address the outside world sees, empty until a router answers.
    std::string GetExternalAddress() const;

    // The port the router granted, which is usually the one asked for but
    // does not have to be.
    uint16_t GetExternalPort() const { return mExternalPort.load(); }

private:
    void Loop(uint16_t privatePort);

    // Reads the default gateway from the routing table. Empty when there is
    // none, which is the normal case on a machine with a public address.
    static std::string FindDefaultGateway();

    // One request and one answer. Returns the number of bytes read, or zero
    // on timeout or error.
    static size_t Exchange(const std::string& gateway,
                           const uint8_t* request, size_t requestLen,
                           uint8_t* response, size_t responseCapacity,
                           int timeoutMs);

    // Asks the router what address the outside world sees.
    static bool AskExternalAddress(const std::string& gateway,
                                   std::string& addressOut);

    // Asks for the mapping. A lifetime of zero removes it.
    static bool AskMapping(const std::string& gateway,
                           uint16_t privatePort,
                           uint16_t suggestedExternalPort,
                           uint32_t lifetimeSeconds,
                           uint16_t& grantedPortOut);

    // Sleeps unless Stop was called meanwhile. Returns false when it is time
    // to leave the loop.
    bool WaitFor(int seconds);

    std::thread             mThread;
    std::atomic<bool>       mRunning;
    std::atomic<bool>       mStopping;
    std::atomic<bool>       mMapped;
    std::atomic<uint16_t>   mExternalPort;

    mutable std::mutex      mAddressMutex;
    std::string             mExternalAddress;
    std::string             mGateway;

    std::mutex              mWaitMutex;
    std::condition_variable mWaitCV;
};

} // namespace net
} // namespace MONEU

#endif // MONEU_NET_PORTMAP_H
