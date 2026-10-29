// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MONEU_NET_SOCKS5_H
#define MONEU_NET_SOCKS5_H

#include <boost/asio.hpp>

#include <atomic>
#include <cstdint>
#include <string>

namespace MONEU {
namespace net {

using SocketHandle = boost::asio::ip::tcp::socket::native_handle_type;

static const int SOCKS5_RECV_TIMEOUT_MS = 20 * 1000;

struct ProxyCredentials {
    std::string username;
    std::string password;
};

bool Socks5(SocketHandle fd,
            const std::string& dest,
            uint16_t port,
            const ProxyCredentials* auth,
            int timeoutMs,
            const std::atomic<bool>& running,
            std::string& error);

bool WaitSocket(SocketHandle fd, bool forWrite, int timeoutMs);

} // namespace net
} // namespace MONEU

#endif // MONEU_NET_SOCKS5_H
