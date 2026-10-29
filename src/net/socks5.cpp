// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "socks5.h"

#include <chrono>
#include <cerrno>
#include <vector>

#ifndef WIN32
#include <sys/select.h>
#include <sys/socket.h>
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace MONEU {
namespace net {

namespace {

enum SOCKSVersion : uint8_t {
    SOCKS5 = 0x05
};

enum SOCKS5Method : uint8_t {
    NOAUTH       = 0x00,
    USER_PASS    = 0x02,
    NO_ACCEPTABLE = 0xff
};

enum SOCKS5Command : uint8_t {
    CONNECT = 0x01
};

enum SOCKS5Reply : uint8_t {
    SUCCEEDED        = 0x00,
    GENFAILURE       = 0x01,
    NOTALLOWED       = 0x02,
    NETUNREACHABLE   = 0x03,
    HOSTUNREACHABLE  = 0x04,
    CONNREFUSED      = 0x05,
    TTLEXPIRED       = 0x06,
    CMDUNSUPPORTED   = 0x07,
    ATYPEUNSUPPORTED = 0x08
};

enum SOCKS5Atyp : uint8_t {
    IPV4       = 0x01,
    DOMAINNAME = 0x03,
    IPV6       = 0x04
};

enum class IntrRecvError {
    OK,
    Timeout,
    Disconnected,
    NetworkError,
    Interrupted
};

const int MAX_WAIT_FOR_IO_MS = 100;

int64_t NowMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

bool WouldBlock() {
#ifdef WIN32
    const int err = ::WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEINVAL;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
           errno == EINPROGRESS;
#endif
}

IntrRecvError InterruptibleRecv(SocketHandle fd, uint8_t* data, size_t len,
                                int timeoutMs,
                                const std::atomic<bool>& running)
{
    int64_t curTime = NowMillis();
    const int64_t endTime = curTime + timeoutMs;
    while (len > 0 && curTime < endTime) {
        const int ret = ::recv(fd, reinterpret_cast<char*>(data),
                               static_cast<int>(len), 0);
        if (ret > 0) {
            len  -= static_cast<size_t>(ret);
            data += ret;
        } else if (ret == 0) {
            return IntrRecvError::Disconnected;
        } else {
            if (!WouldBlock()) return IntrRecvError::NetworkError;
            const int64_t remaining = endTime - curTime;
            const int wait = static_cast<int>(
                remaining < MAX_WAIT_FOR_IO_MS ? remaining : MAX_WAIT_FOR_IO_MS);
            WaitSocket(fd, false, wait);
        }
        if (!running) return IntrRecvError::Interrupted;
        curTime = NowMillis();
    }
    return len == 0 ? IntrRecvError::OK : IntrRecvError::Timeout;
}

bool SendAll(SocketHandle fd, const std::vector<uint8_t>& data, int timeoutMs,
             const std::atomic<bool>& running)
{
    size_t sent = 0;
    const int64_t endTime = NowMillis() + timeoutMs;
    while (sent < data.size()) {
        if (!running) return false;
        if (NowMillis() >= endTime) return false;
        const int ret = ::send(fd,
                               reinterpret_cast<const char*>(data.data() + sent),
                               static_cast<int>(data.size() - sent),
                               MSG_NOSIGNAL);
        if (ret > 0) {
            sent += static_cast<size_t>(ret);
            continue;
        }
        if (ret < 0 && WouldBlock()) {
            WaitSocket(fd, true, MAX_WAIT_FOR_IO_MS);
            continue;
        }
        return false;
    }
    return true;
}

std::string Socks5ErrorString(uint8_t err) {
    switch (err) {
        case GENFAILURE:       return "general failure";
        case NOTALLOWED:       return "connection not allowed";
        case NETUNREACHABLE:   return "network unreachable";
        case HOSTUNREACHABLE:  return "host unreachable";
        case CONNREFUSED:      return "connection refused";
        case TTLEXPIRED:       return "TTL expired";
        case CMDUNSUPPORTED:   return "protocol error";
        case ATYPEUNSUPPORTED: return "address type not supported";
        default:               return "unknown";
    }
}

} // namespace

bool WaitSocket(SocketHandle fd, bool forWrite, int timeoutMs) {
    if (timeoutMs < 0) timeoutMs = 0;
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);
#ifdef WIN32
    fd_set err;
    FD_ZERO(&err);
    FD_SET(fd, &err);
#endif
    struct timeval tv;
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
#ifdef WIN32
    const int sel = ::select(0, forWrite ? nullptr : &set,
                             forWrite ? &set : nullptr, &err, &tv);
#else
    const int sel = ::select(static_cast<int>(fd) + 1,
                             forWrite ? nullptr : &set,
                             forWrite ? &set : nullptr, nullptr, &tv);
#endif
    return sel > 0;
}

bool Socks5(SocketHandle fd,
            const std::string& dest,
            uint16_t port,
            const ProxyCredentials* auth,
            int timeoutMs,
            const std::atomic<bool>& running,
            std::string& error)
{
    IntrRecvError recvr;
    if (dest.empty() || dest.size() > 255) {
        error = "destination name too long";
        return false;
    }

    std::vector<uint8_t> vSocks5Init;
    vSocks5Init.push_back(SOCKS5);
    if (auth) {
        vSocks5Init.push_back(0x02);
        vSocks5Init.push_back(NOAUTH);
        vSocks5Init.push_back(USER_PASS);
    } else {
        vSocks5Init.push_back(0x01);
        vSocks5Init.push_back(NOAUTH);
    }
    if (!SendAll(fd, vSocks5Init, timeoutMs, running)) {
        error = "error sending to proxy";
        return false;
    }
    uint8_t pchRet1[2];
    if ((recvr = InterruptibleRecv(fd, pchRet1, 2, timeoutMs, running)) !=
        IntrRecvError::OK) {
        error = "proxy did not answer the greeting";
        return false;
    }
    if (pchRet1[0] != SOCKS5) {
        error = "proxy failed to initialize";
        return false;
    }
    if (pchRet1[1] == USER_PASS && auth) {
        if (auth->username.size() > 255 || auth->password.size() > 255) {
            error = "proxy username or password too long";
            return false;
        }
        std::vector<uint8_t> vAuth;
        vAuth.push_back(0x01);
        vAuth.push_back(static_cast<uint8_t>(auth->username.size()));
        vAuth.insert(vAuth.end(), auth->username.begin(), auth->username.end());
        vAuth.push_back(static_cast<uint8_t>(auth->password.size()));
        vAuth.insert(vAuth.end(), auth->password.begin(), auth->password.end());
        if (!SendAll(fd, vAuth, timeoutMs, running)) {
            error = "error sending authentication to proxy";
            return false;
        }
        uint8_t pchRetA[2];
        if ((recvr = InterruptibleRecv(fd, pchRetA, 2, timeoutMs, running)) !=
            IntrRecvError::OK) {
            error = "error reading proxy authentication response";
            return false;
        }
        if (pchRetA[0] != 0x01 || pchRetA[1] != 0x00) {
            error = "proxy authentication unsuccessful";
            return false;
        }
    } else if (pchRet1[1] == NOAUTH) {
    } else {
        error = "proxy requested a wrong authentication method";
        return false;
    }

    std::vector<uint8_t> vSocks5;
    vSocks5.push_back(SOCKS5);
    vSocks5.push_back(CONNECT);
    vSocks5.push_back(0x00);
    vSocks5.push_back(DOMAINNAME);
    vSocks5.push_back(static_cast<uint8_t>(dest.size()));
    vSocks5.insert(vSocks5.end(), dest.begin(), dest.end());
    vSocks5.push_back((port >> 8) & 0xFF);
    vSocks5.push_back((port >> 0) & 0xFF);
    if (!SendAll(fd, vSocks5, timeoutMs, running)) {
        error = "error sending to proxy";
        return false;
    }
    uint8_t pchRet2[4];
    if ((recvr = InterruptibleRecv(fd, pchRet2, 4, timeoutMs, running)) !=
        IntrRecvError::OK) {
        error = recvr == IntrRecvError::Timeout
            ? "timed out waiting for the remote node"
            : "error while reading proxy response";
        return false;
    }
    if (pchRet2[0] != SOCKS5) {
        error = "proxy failed to accept request";
        return false;
    }
    if (pchRet2[1] != SUCCEEDED) {
        error = Socks5ErrorString(pchRet2[1]);
        return false;
    }
    if (pchRet2[2] != 0x00) {
        error = "malformed proxy response";
        return false;
    }
    uint8_t pchRet3[256];
    switch (pchRet2[3]) {
        case IPV4:
            recvr = InterruptibleRecv(fd, pchRet3, 4, timeoutMs, running);
            break;
        case IPV6:
            recvr = InterruptibleRecv(fd, pchRet3, 16, timeoutMs, running);
            break;
        case DOMAINNAME: {
            recvr = InterruptibleRecv(fd, pchRet3, 1, timeoutMs, running);
            if (recvr != IntrRecvError::OK) {
                error = "error reading from proxy";
                return false;
            }
            const int nRecv = pchRet3[0];
            recvr = InterruptibleRecv(fd, pchRet3, nRecv, timeoutMs, running);
            break;
        }
        default:
            error = "malformed proxy response";
            return false;
    }
    if (recvr != IntrRecvError::OK) {
        error = "error reading from proxy";
        return false;
    }
    if ((recvr = InterruptibleRecv(fd, pchRet3, 2, timeoutMs, running)) !=
        IntrRecvError::OK) {
        error = "error reading from proxy";
        return false;
    }
    return true;
}

} // namespace net
} // namespace MONEU
