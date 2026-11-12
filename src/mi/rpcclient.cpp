// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "rpcclient.h"

#ifdef WIN32
#undef NOGDI
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace mi {

#ifdef WIN32
typedef SOCKET SocketHandle;
static const SocketHandle BAD_SOCKET = INVALID_SOCKET;
static void CloseSocket(SocketHandle s) { closesocket(s); }
#else
typedef int SocketHandle;
static const SocketHandle BAD_SOCKET = -1;
static void CloseSocket(SocketHandle s) { close(s); }
#endif

static const std::string B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static std::string Base64Encode(const std::string& in)
{
    std::string out;
    uint32_t val = 0;
    int valb = -6;
    for (unsigned char c : in) {
        val = ((val << 8) | static_cast<uint32_t>(c)) & 0x00FFFFFFu;
        valb += 8;
        while (valb >= 0) {
            out.push_back(B64_CHARS[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(B64_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

std::string RpcReply::ErrorText() const
{
    if (kind == RPC_ERROR) return "error: " + message;
    return message;
}

RpcClient::RpcClient(const std::string& dataDir)
    : mDataDir(dataDir)
    , mHost("127.0.0.1")
    , mPort(8328)
{
}

bool RpcClient::LoadCredentials(std::string& errorText)
{
    mUser.clear();
    mPassword.clear();
    mPort = 8328;

    std::ifstream conf(mDataDir + "/moneu.conf");
    if (conf.is_open()) {
        std::string line;
        while (std::getline(conf, line)) {
            size_t hash = line.find('#');
            if (hash != std::string::npos) line = line.substr(0, hash);
            size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            auto trim = [](std::string& v) {
                while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
                    v.erase(v.begin());
                while (!v.empty() && (v.back() == ' ' || v.back() == '\t' ||
                                      v.back() == '\r' || v.back() == '\n'))
                    v.pop_back();
            };
            trim(key);
            trim(val);
            if (val.empty()) continue;
            if (key == "rpcuser" && mUser.empty())
                mUser = val;
            else if (key == "rpcpassword" && mPassword.empty())
                mPassword = val;
            else if (key == "rpcport") {
                int p = std::atoi(val.c_str());
                if (p > 0 && p < 65536) mPort = p;
            }
        }
    }

    if (mUser.empty() || mPassword.empty()) {
        std::ifstream f(mDataDir + "/.rpc.cookie");
        std::string line;
        size_t colon = std::string::npos;
        if (f.is_open() && std::getline(f, line))
            colon = line.find(':');
        if (colon == std::string::npos) {
            errorText = "error: missing RPC credentials\n"
                        "Provide -rpcuser and -rpcpassword\n"
                        "or make sure the node is running\n"
                        "(looking for: " + mDataDir + "/.rpc.cookie)";
            return false;
        }
        mUser = line.substr(0, colon);
        mPassword = line.substr(colon + 1);
    }
    return true;
}

static SocketHandle Connect(const std::string& host, int port, long timeoutSec)
{
    SocketHandle sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == BAD_SOCKET) return BAD_SOCKET;

#ifdef WIN32
    const DWORD tv = static_cast<DWORD>(timeoutSec) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeoutSec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    struct sockaddr_in server;
    std::memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &server.sin_addr) <= 0 ||
        connect(sock, reinterpret_cast<struct sockaddr*>(&server),
                sizeof(server)) != 0) {
        CloseSocket(sock);
        return BAD_SOCKET;
    }
    return sock;
}

bool RpcClient::PortOpen()
{
    std::string ignored;
    LoadCredentials(ignored);
    SocketHandle sock = Connect(mHost, mPort, 5);
    if (sock == BAD_SOCKET) return false;
    CloseSocket(sock);
    return true;
}

static bool SendAll(SocketHandle sock, const std::string& data)
{
    size_t sent = 0;
    while (sent < data.size()) {
#ifdef WIN32
        const int n = send(sock, data.data() + sent,
                           static_cast<int>(data.size() - sent), 0);
#else
        const ssize_t n = send(sock, data.data() + sent,
                               data.size() - sent, MSG_NOSIGNAL);
#endif
        if (n <= 0) {
#ifndef WIN32
            if (n < 0 && errno == EINTR) continue;
#endif
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool RpcClient::Post(const std::string& body, long timeoutSec,
                     std::string& replyBody, std::string& errorText)
{
    if (!LoadCredentials(errorText)) return false;

    SocketHandle sock = Connect(mHost, mPort, timeoutSec);
    if (sock == BAD_SOCKET) {
        std::ostringstream oss;
        oss << "error: cannot connect to " << mHost << ":" << mPort << "\n"
            << "Is moneud running?";
        errorText = oss.str();
        return false;
    }

    std::ostringstream req;
    req << "POST / HTTP/1.1\r\n"
        << "Host: " << mHost << "\r\n"
        << "Authorization: Basic " << Base64Encode(mUser + ":" + mPassword)
        << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;

    if (!SendAll(sock, req.str())) {
        CloseSocket(sock);
        errorText = "error: send failed";
        return false;
    }

    std::string response;
    char buf[16384];
    bool timedOut = false;
    while (true) {
#ifdef WIN32
        const int n = recv(sock, buf, sizeof(buf), 0);
        if (n > 0) {
            response.append(buf, static_cast<size_t>(n));
            continue;
        }
        if (n < 0 && WSAGetLastError() == WSAETIMEDOUT) timedOut = true;
#else
        const ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n > 0) {
            response.append(buf, static_cast<size_t>(n));
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            timedOut = true;
#endif
        break;
    }
    CloseSocket(sock);

    if (response.empty()) {
        std::ostringstream oss;
        if (timedOut) {
            oss << "error: no reply within " << timeoutSec << " s\n"
                << "The node accepted the connection and did not answer. "
                   "Raise the wait with -rpcclienttimeout=<seconds>.";
        } else {
            oss << "error: the node closed the connection without "
                   "replying\n"
                << "Check " << mDataDir
                << "/logs/moneu.log for the reason.";
        }
        errorText = oss.str();
        return false;
    }

    const size_t bodyStart = response.find("\r\n\r\n");
    if (bodyStart == std::string::npos) {
        std::ostringstream oss;
        oss << "error: the reply was cut off after " << response.size()
            << " bytes";
        errorText = oss.str();
        return false;
    }

    const std::string statusLine = response.substr(0, response.find("\r\n"));
    replyBody = response.substr(bodyStart + 4);
    if (statusLine.size() > 12 &&
        statusLine.compare(0, 9, "HTTP/1.1 ") == 0 &&
        statusLine.compare(9, 3, "200") != 0 &&
        replyBody.empty()) {
        errorText = "error: " + statusLine;
        return false;
    }
    return true;
}

static RpcReply ReplyFromJson(const json& response)
{
    RpcReply reply;
    if (!response.is_object()) {
        reply.kind = RpcReply::TRANSPORT_ERROR;
        reply.message = "error: invalid JSON response";
        return reply;
    }
    if (response.contains("error") && !response["error"].is_null()) {
        const json& err = response["error"];
        reply.kind = RpcReply::RPC_ERROR;
        if (err.is_object() && err.contains("code") &&
            err["code"].is_number_integer())
            reply.code = err["code"].get<int>();
        if (err.is_object() && err.contains("message") &&
            err["message"].is_string())
            reply.message = err["message"].get<std::string>();
        else
            reply.message = err.dump();
        return reply;
    }
    if (!response.contains("result")) {
        reply.kind = RpcReply::TRANSPORT_ERROR;
        reply.message = "error: no result in response";
        return reply;
    }
    reply.kind = RpcReply::OK;
    reply.result = response["result"];
    return reply;
}

RpcReply RpcClient::Call(const std::string& method, const json& params,
                         long timeoutSec)
{
    json request;
    request["jsonrpc"] = "2.0";
    request["id"] = 1;
    request["method"] = method;
    request["params"] = params;

    RpcReply reply;
    std::string body;
    std::string errorText;
    if (!Post(request.dump(), timeoutSec, body, errorText)) {
        reply.kind = RpcReply::TRANSPORT_ERROR;
        reply.message = errorText;
        return reply;
    }
    json parsed;
    try {
        parsed = json::parse(body);
    } catch (...) {
        reply.kind = RpcReply::TRANSPORT_ERROR;
        reply.message = "error: invalid JSON response";
        return reply;
    }
    return ReplyFromJson(parsed);
}

std::vector<RpcReply> RpcClient::Batch(
    const std::vector<std::pair<std::string, json> >& calls,
    long timeoutSec)
{
    std::vector<RpcReply> replies(calls.size());
    if (calls.empty()) return replies;

    json batch = json::array();
    for (size_t i = 0; i < calls.size(); ++i) {
        json request;
        request["jsonrpc"] = "2.0";
        request["id"] = static_cast<uint64_t>(i);
        request["method"] = calls[i].first;
        request["params"] = calls[i].second;
        batch.push_back(request);
    }

    std::string body;
    std::string errorText;
    json parsed;
    bool failed = !Post(batch.dump(), timeoutSec, body, errorText);
    if (!failed) {
        try {
            parsed = json::parse(body);
        } catch (...) {
            failed = true;
            errorText = "error: invalid JSON response";
        }
    }
    if (!failed && !parsed.is_array()) {
        // A refusal of the whole batch comes back as a single object.
        RpcReply single = ReplyFromJson(parsed);
        if (single.kind == RpcReply::OK) {
            single.kind = RpcReply::TRANSPORT_ERROR;
            single.message = "error: invalid JSON response";
        }
        for (size_t i = 0; i < replies.size(); ++i) replies[i] = single;
        return replies;
    }
    if (failed) {
        for (size_t i = 0; i < replies.size(); ++i) {
            replies[i].kind = RpcReply::TRANSPORT_ERROR;
            replies[i].message = errorText;
        }
        return replies;
    }

    std::vector<bool> filled(calls.size(), false);
    for (const auto& item : parsed) {
        if (!item.is_object() || !item.contains("id") ||
            !item["id"].is_number_unsigned())
            continue;
        const uint64_t id = item["id"].get<uint64_t>();
        if (id >= replies.size()) continue;
        replies[id] = ReplyFromJson(item);
        filled[id] = true;
    }
    for (size_t i = 0; i < replies.size(); ++i) {
        if (!filled[i]) {
            replies[i].kind = RpcReply::TRANSPORT_ERROR;
            replies[i].message = "error: no result in response";
        }
    }
    return replies;
}

} // namespace mi
