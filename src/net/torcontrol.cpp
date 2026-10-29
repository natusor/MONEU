// Copyright (c) 2015-2021 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "torcontrol.h"
#include "log/log.h"

extern "C" {
#include "../crypto/hmac.h"
#include "../crypto/rand.h"
}

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace MONEU {
namespace net {

namespace {

const size_t TOR_COOKIE_SIZE = 32;
const size_t TOR_NONCE_SIZE  = 32;
const char* const TOR_SAFE_SERVERKEY =
    "Tor safe cookie authentication server-to-controller hash";
const char* const TOR_SAFE_CLIENTKEY =
    "Tor safe cookie authentication controller-to-server hash";
const double RECONNECT_TIMEOUT_START = 1.0;
const double RECONNECT_TIMEOUT_EXP   = 1.5;
const double RECONNECT_TIMEOUT_MAX   = 600.0;
const size_t MAX_LINE_LENGTH         = 100000;
const int    CONTROL_CONNECT_TIMEOUT_MS = 10 * 1000;
const int    CONTROL_REPLY_TIMEOUT_MS   = 60 * 1000;

struct TorControlReply {
    int code;
    std::vector<std::string> lines;
    TorControlReply() : code(0) {}
};

std::string HexStr(const uint8_t* data, size_t len) {
    static const char* hexDigits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hexDigits[(data[i] >> 4) & 0x0F]);
        out.push_back(hexDigits[data[i] & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> ParseHex(const std::string& s) {
    std::vector<uint8_t> out;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        const int hi = nibble(s[i]);
        const int lo = nibble(s[i + 1]);
        if (hi < 0 || lo < 0) return std::vector<uint8_t>();
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string Sanitize(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c >= 0x20 && c < 0x7f) out.push_back(c);
    }
    return out;
}

void CloseSocket(SocketHandle fd) {
#ifdef WIN32
    ::closesocket(fd);
#else
    ::close(fd);
#endif
}

bool SetNonBlocking(SocketHandle fd) {
#ifdef WIN32
    u_long on = 1;
    return ::ioctlsocket(fd, FIONBIO, &on) == 0;
#else
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool LastErrorIsWouldBlock() {
#ifdef WIN32
    const int err = ::WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
           errno == EINPROGRESS;
#endif
}

bool SplitHostPort(const std::string& in, std::string& host, std::string& port) {
    if (!in.empty() && in[0] == '[') {
        const size_t close = in.find(']');
        if (close == std::string::npos) return false;
        host = in.substr(1, close - 1);
        port = (close + 2 <= in.size() && in[close + 1] == ':')
            ? in.substr(close + 2) : "9051";
        return !host.empty();
    }
    const size_t colon = in.rfind(':');
    if (colon == std::string::npos) {
        host = in;
        port = "9051";
    } else {
        host = in.substr(0, colon);
        port = in.substr(colon + 1);
    }
    return !host.empty() && !port.empty();
}

SocketHandle ConnectControl(const std::string& control,
                            const std::atomic<bool>& running)
{
    std::string host, port;
    if (!SplitHostPort(control, host, port)) return static_cast<SocketHandle>(-1);

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
        return static_cast<SocketHandle>(-1);
    }

    SocketHandle result = static_cast<SocketHandle>(-1);
    for (struct addrinfo* ai = res; ai && running; ai = ai->ai_next) {
        SocketHandle fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#ifdef WIN32
        if (fd == INVALID_SOCKET) continue;
#else
        if (fd < 0) continue;
#endif
        if (!SetNonBlocking(fd)) {
            CloseSocket(fd);
            continue;
        }
        const int rc = ::connect(fd, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        bool ok = (rc == 0);
        if (!ok && LastErrorIsWouldBlock()) {
            const auto deadline = std::chrono::steady_clock::now() +
                std::chrono::milliseconds(CONTROL_CONNECT_TIMEOUT_MS);
            while (running && std::chrono::steady_clock::now() < deadline) {
                if (WaitSocket(fd, true, 200)) {
                    int err = 0;
                    socklen_t len = sizeof(err);
                    ::getsockopt(fd, SOL_SOCKET, SO_ERROR,
                                 reinterpret_cast<char*>(&err), &len);
                    ok = (err == 0);
                    break;
                }
            }
        }
        if (ok) {
            result = fd;
            break;
        }
        CloseSocket(fd);
    }
    ::freeaddrinfo(res);
    return result;
}

bool IsValidSocket(SocketHandle fd) {
#ifdef WIN32
    return fd != INVALID_SOCKET;
#else
    return fd >= 0;
#endif
}

bool SendLine(SocketHandle fd, const std::string& line,
              const std::atomic<bool>& running)
{
    const std::string data = line + "\r\n";
    size_t sent = 0;
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(CONTROL_REPLY_TIMEOUT_MS);
    while (sent < data.size()) {
        if (!running || std::chrono::steady_clock::now() >= deadline) return false;
        const int ret = ::send(fd, data.data() + sent,
                               static_cast<int>(data.size() - sent), MSG_NOSIGNAL);
        if (ret > 0) {
            sent += static_cast<size_t>(ret);
        } else if (ret < 0 && LastErrorIsWouldBlock()) {
            WaitSocket(fd, true, 200);
        } else {
            return false;
        }
    }
    return true;
}

bool ReadReply(SocketHandle fd, std::string& buffer, TorControlReply& reply,
               int timeoutMs, const std::atomic<bool>& running)
{
    reply = TorControlReply();
    bool inData = false;
    const auto start = std::chrono::steady_clock::now();
    while (running) {
        const size_t eol = buffer.find("\r\n");
        if (eol == std::string::npos) {
            if (buffer.size() > MAX_LINE_LENGTH) return false;
            if (timeoutMs >= 0 &&
                std::chrono::steady_clock::now() - start >
                    std::chrono::milliseconds(timeoutMs)) {
                return false;
            }
            if (!WaitSocket(fd, false, 500)) continue;
            char chunk[4096];
            const int ret = ::recv(fd, chunk, sizeof(chunk), 0);
            if (ret > 0) {
                buffer.append(chunk, static_cast<size_t>(ret));
                continue;
            }
            if (ret < 0 && LastErrorIsWouldBlock()) continue;
            return false;
        }

        const std::string line = buffer.substr(0, eol);
        buffer.erase(0, eol + 2);

        if (inData) {
            if (line == ".") inData = false;
            continue;
        }
        if (line.size() < 4) continue;

        const int code = std::atoi(line.substr(0, 3).c_str());
        const char sep = line[3];
        const std::string text = line.substr(4);

        if (code >= 600 && code < 700) continue;

        reply.code = code;
        reply.lines.push_back(text);
        if (sep == '+') {
            inData = true;
        } else if (sep == ' ') {
            return true;
        }
    }
    return false;
}

bool Command(SocketHandle fd, std::string& buffer, const std::string& cmd,
             TorControlReply& reply, const std::atomic<bool>& running)
{
    if (!SendLine(fd, cmd, running)) return false;
    return ReadReply(fd, buffer, reply, CONTROL_REPLY_TIMEOUT_MS, running);
}

std::vector<uint8_t> ComputeResponse(const char* key,
                                     const std::vector<uint8_t>& cookie,
                                     const std::vector<uint8_t>& clientNonce,
                                     const std::vector<uint8_t>& serverNonce)
{
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), cookie.begin(), cookie.end());
    msg.insert(msg.end(), clientNonce.begin(), clientNonce.end());
    msg.insert(msg.end(), serverNonce.begin(), serverNonce.end());
    std::vector<uint8_t> out(32, 0);
    hmac_sha256(reinterpret_cast<const uint8_t*>(key),
                static_cast<uint32_t>(std::strlen(key)),
                msg.data(), static_cast<uint32_t>(msg.size()), out.data());
    return out;
}

bool ReadFileExact(const std::string& path, size_t maxSize, std::string& out) {
    std::ifstream in(path.c_str(), std::ios::binary);
    if (!in.is_open()) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return out.size() <= maxSize;
}

bool WritePrivateFile(const std::string& path, const std::string& data) {
    {
        std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out << data;
        if (!out.good()) return false;
    }
#ifndef WIN32
    ::chmod(path.c_str(), 0600);
#endif
    return true;
}

} // namespace

std::pair<std::string, std::string> SplitTorReplyLine(const std::string& s) {
    size_t ptr = 0;
    std::string type;
    while (ptr < s.size() && s[ptr] != ' ') {
        type.push_back(s[ptr]);
        ++ptr;
    }
    if (ptr < s.size()) ++ptr;
    return std::make_pair(type, s.substr(ptr));
}

std::map<std::string, std::string> ParseTorReplyMapping(const std::string& s) {
    std::map<std::string, std::string> mapping;
    size_t ptr = 0;
    while (ptr < s.size()) {
        std::string key, value;
        while (ptr < s.size() && s[ptr] != '=' && s[ptr] != ' ') {
            key.push_back(s[ptr]);
            ++ptr;
        }
        if (ptr == s.size()) return std::map<std::string, std::string>();
        if (s[ptr] == ' ') break;
        ++ptr;
        if (ptr < s.size() && s[ptr] == '"') {
            ++ptr;
            bool escape_next = false;
            while (ptr < s.size() && (escape_next || s[ptr] != '"')) {
                escape_next = (s[ptr] == '\\' && !escape_next);
                value.push_back(s[ptr]);
                ++ptr;
            }
            if (ptr == s.size()) return std::map<std::string, std::string>();
            ++ptr;
            std::string escaped_value;
            for (size_t i = 0; i < value.size(); ++i) {
                if (value[i] == '\\') {
                    ++i;
                    if (value[i] == 'n') {
                        escaped_value.push_back('\n');
                    } else if (value[i] == 't') {
                        escaped_value.push_back('\t');
                    } else if (value[i] == 'r') {
                        escaped_value.push_back('\r');
                    } else if ('0' <= value[i] && value[i] <= '7') {
                        size_t j;
                        for (j = 1; j < 3 && (i + j) < value.size() &&
                             '0' <= value[i + j] && value[i + j] <= '7'; ++j) {}
                        if (j == 3 && value[i] > '3') {
                            j--;
                        }
                        const size_t end = i + j;
                        uint8_t val = 0;
                        while (i < end) {
                            val *= 8;
                            val += value[i++] - '0';
                        }
                        escaped_value.push_back(static_cast<char>(val));
                        --i;
                    } else {
                        escaped_value.push_back(value[i]);
                    }
                } else {
                    escaped_value.push_back(value[i]);
                }
            }
            value = escaped_value;
        } else {
            while (ptr < s.size() && s[ptr] != ' ') {
                value.push_back(s[ptr]);
                ++ptr;
            }
        }
        if (ptr < s.size() && s[ptr] == ' ') ++ptr;
        mapping[key] = value;
    }
    return mapping;
}

TorController::TorController(const TorControlOptions& options,
                             const TorControlCallbacks& callbacks)
    : mOptions(options)
    , mCallbacks(callbacks)
    , mRunning(false)
{
}

TorController::~TorController() {
    Stop();
}

void TorController::Start() {
    if (mRunning) return;
    mRunning = true;
    mThread = std::thread([this]() { Run(); });
}

void TorController::Stop() {
    if (!mRunning && !mThread.joinable()) return;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mRunning = false;
    }
    mCv.notify_all();
    if (mThread.joinable()) mThread.join();
}

std::string TorController::GetServiceHost() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mServiceHost;
}

bool TorController::SleepFor(double seconds) {
    std::unique_lock<std::mutex> lock(mMutex);
    mCv.wait_for(lock, std::chrono::milliseconds(static_cast<int64_t>(seconds * 1000.0)),
                 [this]() { return !mRunning; });
    return mRunning;
}

void TorController::Run() {
    double reconnectTimeout = RECONNECT_TIMEOUT_START;
    bool loggedUnreachable = false;
    while (mRunning) {
        SocketHandle fd = ConnectControl(mOptions.control, mRunning);
        if (!IsValidSocket(fd)) {
            if (!loggedUnreachable) {
                MONEU_LOG_INFO("tor: control port " + mOptions.control +
                               " not reachable, will keep trying");
                loggedUnreachable = true;
            }
        } else {
            loggedUnreachable = false;
            MONEU_LOG_DEBUG("tor: connected to control port " + mOptions.control);
            const bool reachedService = Session(fd);
            CloseSocket(fd);
            std::string lost;
            {
                std::lock_guard<std::mutex> lock(mMutex);
                lost.swap(mServiceHost);
            }
            if (!lost.empty()) {
                MONEU_LOG_INFO("tor: lost the control connection, no longer "
                               "advertising " + lost);
                if (mCallbacks.onServiceLost) mCallbacks.onServiceLost(lost);
            }
            if (reachedService) reconnectTimeout = RECONNECT_TIMEOUT_START;
        }
        if (!SleepFor(reconnectTimeout)) break;
        reconnectTimeout *= RECONNECT_TIMEOUT_EXP;
        if (reconnectTimeout > RECONNECT_TIMEOUT_MAX) {
            reconnectTimeout = RECONNECT_TIMEOUT_MAX;
        }
    }
}

bool TorController::Session(SocketHandle fd) {
    std::string buffer;
    TorControlReply reply;

    if (!Command(fd, buffer, "PROTOCOLINFO 1", reply, mRunning) ||
        reply.code != 250) {
        MONEU_LOG_WARN("tor: requesting protocol info failed");
        return false;
    }

    std::set<std::string> methods;
    std::string cookieFile;
    for (const std::string& s : reply.lines) {
        const std::pair<std::string, std::string> l = SplitTorReplyLine(s);
        if (l.first == "AUTH") {
            std::map<std::string, std::string> m = ParseTorReplyMapping(l.second);
            std::map<std::string, std::string>::iterator i;
            if ((i = m.find("METHODS")) != m.end()) {
                std::stringstream ss(i->second);
                std::string method;
                while (std::getline(ss, method, ',')) methods.insert(method);
            }
            if ((i = m.find("COOKIEFILE")) != m.end()) cookieFile = i->second;
        } else if (l.first == "VERSION") {
            std::map<std::string, std::string> m = ParseTorReplyMapping(l.second);
            std::map<std::string, std::string>::iterator i;
            if ((i = m.find("Tor")) != m.end()) {
                MONEU_LOG_DEBUG("tor: connected to Tor version " + Sanitize(i->second));
            }
        }
    }

    if (!mOptions.password.empty()) {
        if (!methods.count("HASHEDPASSWORD")) {
            MONEU_LOG_WARN("tor: torpassword is set, but Tor does not offer "
                           "HASHEDPASSWORD authentication");
            return false;
        }
        std::string pw;
        for (char c : mOptions.password) {
            if (c == '"' || c == '\\') pw.push_back('\\');
            pw.push_back(c);
        }
        if (!Command(fd, buffer, "AUTHENTICATE \"" + pw + "\"", reply, mRunning) ||
            reply.code != 250) {
            MONEU_LOG_WARN("tor: authentication failed");
            return false;
        }
    } else if (methods.count("NULL")) {
        if (!Command(fd, buffer, "AUTHENTICATE", reply, mRunning) ||
            reply.code != 250) {
            MONEU_LOG_WARN("tor: authentication failed");
            return false;
        }
    } else if (methods.count("SAFECOOKIE")) {
        std::string cookieData;
        if (!ReadFileExact(cookieFile, TOR_COOKIE_SIZE, cookieData) ||
            cookieData.size() != TOR_COOKIE_SIZE) {
            MONEU_LOG_WARN("tor: cannot read the authentication cookie " +
                           Sanitize(cookieFile) +
                           " (check permissions, the user running moneud must be "
                           "allowed to read it)");
            return false;
        }
        const std::vector<uint8_t> cookie(cookieData.begin(), cookieData.end());
        std::vector<uint8_t> clientNonce(TOR_NONCE_SIZE, 0);
        random_buffer(clientNonce.data(), clientNonce.size());

        if (!Command(fd, buffer,
                     "AUTHCHALLENGE SAFECOOKIE " +
                         HexStr(clientNonce.data(), clientNonce.size()),
                     reply, mRunning) ||
            reply.code != 250 || reply.lines.empty()) {
            MONEU_LOG_WARN("tor: SAFECOOKIE authentication challenge failed");
            return false;
        }
        const std::pair<std::string, std::string> l = SplitTorReplyLine(reply.lines[0]);
        if (l.first != "AUTHCHALLENGE") {
            MONEU_LOG_WARN("tor: invalid reply to AUTHCHALLENGE");
            return false;
        }
        std::map<std::string, std::string> m = ParseTorReplyMapping(l.second);
        const std::vector<uint8_t> serverHash  = ParseHex(m["SERVERHASH"]);
        const std::vector<uint8_t> serverNonce = ParseHex(m["SERVERNONCE"]);
        if (serverNonce.size() != 32) {
            MONEU_LOG_WARN("tor: ServerNonce is not 32 bytes, as required by spec");
            return false;
        }
        const std::vector<uint8_t> computedServerHash =
            ComputeResponse(TOR_SAFE_SERVERKEY, cookie, clientNonce, serverNonce);
        if (computedServerHash != serverHash) {
            MONEU_LOG_WARN("tor: ServerHash does not match the expected value");
            return false;
        }
        const std::vector<uint8_t> computedClientHash =
            ComputeResponse(TOR_SAFE_CLIENTKEY, cookie, clientNonce, serverNonce);
        if (!Command(fd, buffer,
                     "AUTHENTICATE " +
                         HexStr(computedClientHash.data(), computedClientHash.size()),
                     reply, mRunning) ||
            reply.code != 250) {
            MONEU_LOG_WARN("tor: authentication failed");
            return false;
        }
    } else if (methods.count("HASHEDPASSWORD")) {
        MONEU_LOG_WARN("tor: the only authentication left is a password, set "
                       "torpassword in moneu.conf");
        return false;
    } else {
        MONEU_LOG_WARN("tor: no supported authentication method");
        return false;
    }

    MONEU_LOG_DEBUG("tor: authentication successful");
    if (mCallbacks.onAuthenticated) mCallbacks.onAuthenticated();

    std::string privateKey;
    if (!mOptions.keyFile.empty()) {
        std::string stored;
        if (ReadFileExact(mOptions.keyFile, 1024, stored)) {
            while (!stored.empty() &&
                   (stored.back() == '\n' || stored.back() == '\r' ||
                    stored.back() == ' ')) {
                stored.pop_back();
            }
            for (char c : stored) {
                if (c < 0x21 || c > 0x7e) {
                    MONEU_LOG_WARN("tor: the onion service key in " +
                                   mOptions.keyFile + " is damaged");
                    return false;
                }
            }
            privateKey = stored;
        }
    }
    const bool newKey = privateKey.empty();
    if (newKey) privateKey = "NEW:ED25519-V3";

    if (!Command(fd, buffer,
                 "ADD_ONION " + privateKey + " Port=" +
                     std::to_string(mOptions.virtualPort) + "," + mOptions.target,
                 reply, mRunning)) {
        MONEU_LOG_WARN("tor: no reply to ADD_ONION");
        return false;
    }
    if (reply.code == 510) {
        MONEU_LOG_WARN("tor: ADD_ONION is not recognized, Tor needs an upgrade");
        return false;
    }
    if (reply.code != 250) {
        MONEU_LOG_WARN("tor: ADD_ONION failed with code " + std::to_string(reply.code));
        return false;
    }

    std::string serviceId;
    for (const std::string& s : reply.lines) {
        std::map<std::string, std::string> m = ParseTorReplyMapping(s);
        std::map<std::string, std::string>::iterator i;
        if ((i = m.find("ServiceID")) != m.end()) serviceId = i->second;
        if ((i = m.find("PrivateKey")) != m.end()) privateKey = i->second;
    }
    if (serviceId.empty()) {
        MONEU_LOG_WARN("tor: error parsing the ADD_ONION reply");
        return false;
    }
    if (newKey && !mOptions.keyFile.empty()) {
        if (WritePrivateFile(mOptions.keyFile, privateKey)) {
            MONEU_LOG_DEBUG("tor: service key saved to " + mOptions.keyFile);
        } else {
            MONEU_LOG_WARN("tor: cannot save the service key to " + mOptions.keyFile);
        }
    }

    const std::string host = serviceId + ".onion";
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mServiceHost = host;
    }
    MONEU_LOG_INFO("tor: advertising onion service " + host + ":" +
                   std::to_string(mOptions.virtualPort));
    if (mCallbacks.onService) mCallbacks.onService(host);

    while (mRunning) {
        TorControlReply ignored;
        if (!ReadReply(fd, buffer, ignored, -1, mRunning)) break;
    }
    return true;
}

} // namespace net
} // namespace MONEU
