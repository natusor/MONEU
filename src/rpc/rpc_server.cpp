// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license
// Adapted from Bitcoin Core (MIT)

#include "rpc_server.h"
#include "../validation/tx_validation.h"
#include "../crypto/arith_uint256.h"
#include "../consensus/pow.h"
#include "../log/log.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <chrono>
#include <thread>

#ifndef WIN32
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

namespace {

// Base units rendered as MONEU, with all eight decimal places and no
// exponent. Built from the integer rather than from a double, so the text
// says exactly what the chain holds.
std::string FormatAmount(int64_t units) {
    const bool negative = units < 0;
    uint64_t magnitude = negative
        ? (~static_cast<uint64_t>(units) + 1ull)
        : static_cast<uint64_t>(units);
    const uint64_t whole = magnitude / static_cast<uint64_t>(NetParams::COIN);
    const uint64_t frac  = magnitude % static_cast<uint64_t>(NetParams::COIN);
    std::ostringstream oss;
    if (negative) oss << '-';
    oss << whole << '.' << std::setfill('0') << std::setw(8) << frac;
    return oss.str();
}

// Amount in MONEU as written by the caller, converted to base units without
// going through double.
//
// A double holds fifteen to sixteen significant decimal digits, and
// 21 million MONEU in base units needs seventeen. Multiplying by 1e8 and
// rounding therefore turned 1.9999999999 into exactly 2.00000000, and
// 0.000000005 into one whole base unit nobody asked for. The text is parsed
// digit by digit instead, so what the caller wrote is what they send.
bool ParseAmount(const std::string& text, int64_t& out, std::string& why) {
    if (text.empty()) { why = "amount is empty"; return false; }

    size_t i = 0;
    bool negative = false;
    if (text[i] == '+' || text[i] == '-') {
        negative = (text[i] == '-');
        ++i;
    }

    int64_t whole = 0;
    size_t wholeDigits = 0;
    while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
        if (whole > (NetParams::MAX_MONEY / NetParams::COIN)) {
            why = "amount out of range";
            return false;
        }
        whole = whole * 10 + (text[i] - '0');
        ++i;
        ++wholeDigits;
    }

    int64_t frac = 0;
    size_t fracDigits = 0;
    if (i < text.size() && text[i] == '.') {
        ++i;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
            if (fracDigits >= 8) {
                why = "amount has more than eight decimal places";
                return false;
            }
            frac = frac * 10 + (text[i] - '0');
            ++i;
            ++fracDigits;
        }
    }

    if (i != text.size()) { why = "amount is not a number"; return false; }
    if (wholeDigits == 0 && fracDigits == 0) {
        why = "amount has no digits";
        return false;
    }

    // Scale the fraction to eight places: "1.5" is 50000000, not 5.
    for (size_t k = fracDigits; k < 8; ++k) frac *= 10;

    if (whole > (NetParams::MAX_MONEY - frac) / NetParams::COIN) {
        why = "amount out of range";
        return false;
    }
    out = whole * NetParams::COIN + frac;
    if (negative) out = -out;
    return true;
}

// Bytes a signed input carries beyond an unsigned one. Signing attaches a
// noise proof, and its serialized length is fixed by the leaf count: the
// path is one hash and one direction bit per level, so the whole record is
// the same size for every spend. Knowing it up front lets the fee be
// settled before the transaction is built rather than after, which is when
// the size would otherwise first be measurable.
int HexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t NoiseProofBytesPerInput() {
    size_t depth = 0;
    uint32_t leaves = NetParams::NOISE_LEAF_COUNT_VALUE;
    while (leaves > 1) { leaves >>= 1; ++depth; }
    const size_t proof = 4 + 32 + 32 + 4 + depth * 32 + depth;
    return 4 + proof;
}

// What the transaction will weigh once it is signed.
size_t SignedSizeOf(const MONEU::Transaction& tx) {
    return tx.GetSerializedSize(true) +
           tx.GetInputCount() * NoiseProofBytesPerInput();
}

// The fee that size demands, by the same rule validation applies:
// max(size * MIN_FEE_PER_BYTE, MIN_TX_FEE).
int64_t RequiredFeeForSize(size_t size) {
    const int64_t perByte =
        static_cast<int64_t>(size) * NetParams::MIN_FEE_PER_BYTE;
    return (perByte > NetParams::MIN_TX_FEE)
               ? perByte : NetParams::MIN_TX_FEE;
}

// The same value straight from JSON, whether it arrived as a string or a
// number. A number is re-rendered without exponent so ParseAmount sees the
// digits the caller meant.
bool ParseAmountJson(const nlohmann::json& v, int64_t& out,
                     std::string& why) {
    if (v.is_string()) return ParseAmount(v.get<std::string>(), out, why);
    if (v.is_number_integer()) {
        const int64_t whole = v.get<int64_t>();
        if (whole < 0 || whole > NetParams::MAX_MONEY / NetParams::COIN) {
            why = "amount out of range";
            return false;
        }
        out = whole * NetParams::COIN;
        return true;
    }
    if (v.is_number_float()) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(8) << v.get<double>();
        return ParseAmount(oss.str(), out, why);
    }
    why = "amount must be a number or a decimal string";
    return false;
}

// Service flags as the sixteen-digit hex string Bitcoin prints, so the
// field reads the same in both.
inline std::string ServicesToHex(uint32_t services) {
    static const char* digits = "0123456789abcdef";
    const uint64_t wide = static_cast<uint64_t>(services);
    std::string out;
    out.reserve(16);
    for (int shift = 60; shift >= 0; shift -= 4) {
        out.push_back(digits[(wide >> shift) & 0x0F]);
    }
    return out;
}

// RPC-side admission: the same three validation layers the network path
// runs (structural, contextual against the UTXO set, signatures/noise),
// plus the fee (totalIn - totalOut) the mempool stores. A locally
// submitted transaction gets no more trust than one from a stranger.
bool ValidateAndComputeFee(const MONEU::Transaction& tx,
                           const MONEU::rpc::RPCContext& ctx,
                           int64_t& feeOut,
                           std::string& reasonOut)
{
    using namespace MONEU;
    if (!ctx.chainState) {
        reasonOut = "ChainState not available";
        return false;
    }
    validation::TxValidationState txState;
    if (!validation::TxValidation::CheckTransaction(tx, txState)) {
        reasonOut = txState.reason;
        return false;
    }
    if (tx.IsCoinbase()) {
        reasonOut = "loose coinbase is never valid";
        return false;
    }
    const uint32_t nextHeight = ctx.chainState->GetHeight() + 1;
    if (!validation::TxValidation::CheckTransactionWithUTXO(
            tx, ctx.chainState->GetUTXOSet(), nextHeight, txState)) {
        reasonOut = txState.reason;
        return false;
    }
    if (!validation::TxValidation::VerifyTransactionSignatures(
            tx, ctx.chainState->GetUTXOSet(), txState)) {
        reasonOut = txState.reason;
        return false;
    }
    int64_t totalIn = 0;
    for (const auto& input : tx.GetInputs()) {
        storage::OutPoint outpoint(input.GetPrevTxHash(),
                                   input.GetOutputIndex());
        storage::Coin coin;
        if (!ctx.chainState->GetUTXOSet().GetCoin(outpoint, coin)) {
            reasonOut = "input vanished during fee computation";
            return false;
        }
        totalIn += coin.value;
    }
    feeOut = totalIn - tx.GetValueOut();
    return true;
}

} // namespace

#endif

// Declared in main.cpp - triggers graceful node shutdown
extern void RequestShutdown();

namespace MONEU {
namespace rpc {

static const std::string BASE64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string RPCServer::Base64Decode(const std::string& in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T[static_cast<uint8_t>(BASE64_CHARS[i])] = i;
    // Unsigned and masked to the bits still owed to the output. As a signed
    // int shifted left without a mask this overflowed past four characters,
    // which is undefined behaviour on the path that checks the password.
    uint32_t val = 0;
    int valb = -8;
    for (uint8_t c : in) {
        if (c == '=') break;
        if (T[c] == -1) continue;
        val = ((val << 6) | static_cast<uint32_t>(T[c])) & 0x00FFFFFFu;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFFu));
            valb -= 8;
        }
    }
    return out;
}

bool RPCTable::Register(const RPCCommand& cmd) {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mCommands.find(cmd.name) != mCommands.end())
        return false;
    mCommands[cmd.name] = cmd;
    return true;
}

bool RPCTable::Unregister(const std::string& name) {
    std::lock_guard<std::mutex> lock(mMutex);
    return mCommands.erase(name) > 0;
}

bool RPCTable::HasCommand(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mCommands.find(name) != mCommands.end();
}

json RPCTable::Execute(const RPCRequest& request,
                        const RPCContext& context) const
{
    RPCHandler handler;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto it = mCommands.find(request.method);
        if (it == mCommands.end()) {
            throw RPCError(RPC_METHOD_NOT_FOUND,
                "Method not found: " + request.method);
        }
        handler = it->second.handler;
    }
    return handler(request, context);
}

std::string RPCTable::Help(const std::string& command) const {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!command.empty()) {
        auto it = mCommands.find(command);
        if (it == mCommands.end())
            return "Unknown command: " + command;
        return it->second.description;
    }
    std::map<std::string, std::vector<std::string>> categories;
    for (const auto& pair : mCommands)
        categories[pair.second.category].push_back(pair.first);
    std::ostringstream oss;
    for (const auto& cat : categories) {
        oss << "== " << cat.first << " ==\n";
        for (const auto& name : cat.second)
            oss << name << "\n";
        oss << "\n";
    }
    return oss.str();
}

std::vector<std::string> RPCTable::ListCommands() const {
    std::lock_guard<std::mutex> lock(mMutex);
    std::vector<std::string> result;
    result.reserve(mCommands.size());
    for (const auto& pair : mCommands)
        result.push_back(pair.first);
    return result;
}

namespace {

// operator== stops at the first mismatching byte, and that timing tells a
// caller how much of a guessed password was right.
bool TimingSafeEqual(const std::string& a, const std::string& b) {
    const size_t n = a.size() > b.size() ? a.size() : b.size();
    unsigned char diff =
        static_cast<unsigned char>(a.size() != b.size() ? 1 : 0);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char ca =
            i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
        const unsigned char cb =
            i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
        diff = static_cast<unsigned char>(diff | (ca ^ cb));
    }
    return diff == 0;
}

std::string ToLowerAscii(const std::string& in) {
    std::string out(in);
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i] >= 'A' && out[i] <= 'Z')
            out[i] = static_cast<char>(out[i] - 'A' + 'a');
    }
    return out;
}

std::string TrimAscii(const std::string& in) {
    size_t b = 0;
    size_t e = in.size();
    while (b < e && (in[b] == ' ' || in[b] == '\t')) ++b;
    while (e > b && (in[e - 1] == ' ' || in[e - 1] == '\t' ||
                     in[e - 1] == '\r' || in[e - 1] == '\n')) --e;
    return in.substr(b, e - b);
}

const char* HttpStatusText(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 413: return "Payload Too Large";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        default:  return "Error";
    }
}

} // namespace

bool RPCSubNet::Match(const RPCAddrBytes& addr) const {
    if (addr.isV6 != isV6) return false;
    const size_t width = isV6 ? 16u : 4u;
    for (size_t i = 0; i < width; ++i) {
        if (static_cast<uint8_t>(addr.bytes[i] & netmask[i]) != network[i])
            return false;
    }
    return true;
}

std::string RPCSubNet::ToString() const {
    const size_t width = isV6 ? 16u : 4u;
    size_t bits = 0;
    for (size_t i = 0; i < width; ++i) {
        uint8_t byte = netmask[i];
        while (byte & 0x80) { ++bits; byte = static_cast<uint8_t>(byte << 1); }
    }
    std::ostringstream oss;
    if (isV6) {
        std::array<unsigned char, 16> raw;
        for (size_t i = 0; i < 16; ++i) raw[i] = network[i];
        oss << asio::ip::address_v6(raw).to_string();
    } else {
        oss << static_cast<int>(network[0]) << '.'
            << static_cast<int>(network[1]) << '.'
            << static_cast<int>(network[2]) << '.'
            << static_cast<int>(network[3]);
    }
    oss << '/' << bits;
    return oss.str();
}

bool RPCAddressToBytes(const asio::ip::address& addr, RPCAddrBytes& out) {
    out.bytes.fill(0);
    if (addr.is_v4()) {
        const asio::ip::address_v4::bytes_type raw = addr.to_v4().to_bytes();
        out.isV6 = false;
        for (size_t i = 0; i < 4; ++i)
            out.bytes[i] = static_cast<uint8_t>(raw[i]);
        return true;
    }
    if (!addr.is_v6()) return false;

    const asio::ip::address_v6::bytes_type raw = addr.to_v6().to_bytes();

    // ::ffff:a.b.c.d is an IPv4 client on a dual-stack socket. Matched as
    // IPv6 it would make rpcallowip=127.0.0.1 miss its own loopback.
    bool mapped = true;
    for (size_t i = 0; i < 10; ++i) {
        if (raw[i] != 0) { mapped = false; break; }
    }
    if (mapped && (raw[10] != 0xFF || raw[11] != 0xFF)) mapped = false;

    if (mapped) {
        out.isV6 = false;
        for (size_t i = 0; i < 4; ++i)
            out.bytes[i] = static_cast<uint8_t>(raw[12 + i]);
        return true;
    }
    out.isV6 = true;
    for (size_t i = 0; i < 16; ++i)
        out.bytes[i] = static_cast<uint8_t>(raw[i]);
    return true;
}

bool RPCParseSubNet(const std::string& text, RPCSubNet& out) {
    const std::string trimmed = TrimAscii(text);
    if (trimmed.empty()) return false;

    std::string addrPart = trimmed;
    std::string maskPart;
    const size_t slash = trimmed.find('/');
    if (slash != std::string::npos) {
        addrPart = trimmed.substr(0, slash);
        maskPart = trimmed.substr(slash + 1);
        if (maskPart.empty()) return false;
    }

    boost::system::error_code ec;
    const asio::ip::address addr = asio::ip::make_address(addrPart, ec);
    if (ec) return false;

    RPCAddrBytes parsed;
    if (!RPCAddressToBytes(addr, parsed)) return false;

    const size_t width = parsed.isV6 ? 16u : 4u;
    size_t bits = width * 8;

    if (!maskPart.empty()) {
        if (maskPart.find('.') != std::string::npos) {
            // Dotted IPv4 netmask, e.g. 255.255.255.0
            if (parsed.isV6) return false;
            const asio::ip::address mask =
                asio::ip::make_address(maskPart, ec);
            if (ec || !mask.is_v4()) return false;
            const asio::ip::address_v4::bytes_type mb =
                mask.to_v4().to_bytes();
            uint32_t value = 0;
            for (size_t i = 0; i < 4; ++i)
                value = (value << 8) | static_cast<uint8_t>(mb[i]);
            bits = 0;
            while (bits < 32 && (value & (0x80000000u >> bits))) ++bits;
            // A mask with a gap in it is a typo, not a network.
            const uint32_t expected =
                (bits == 0) ? 0u : (0xFFFFFFFFu << (32 - bits));
            if (value != expected) return false;
        } else {
            for (size_t i = 0; i < maskPart.size(); ++i) {
                if (maskPart[i] < '0' || maskPart[i] > '9') return false;
            }
            if (maskPart.size() > 3) return false;
            const unsigned long n =
                std::strtoul(maskPart.c_str(), NULL, 10);
            if (n > width * 8) return false;
            bits = static_cast<size_t>(n);
        }
    }

    out.isV6 = parsed.isV6;
    out.network.fill(0);
    out.netmask.fill(0);
    for (size_t i = 0; i < width; ++i) {
        size_t take = 0;
        if (bits >= (i + 1) * 8)      take = 8;
        else if (bits > i * 8)        take = bits - i * 8;
        const uint8_t m = (take == 0)
            ? 0u
            : static_cast<uint8_t>(0xFFu << (8 - take));
        out.netmask[i] = m;
        out.network[i] = static_cast<uint8_t>(parsed.bytes[i] & m);
    }
    return true;
}

// Reading is asynchronous on the single event thread, so a caller that sends
// one byte and waits costs a socket and nothing more. Once the request is
// whole the deadline is dropped and a worker takes sole ownership.
class RPCConnection
    : public std::enable_shared_from_this<RPCConnection>
{
public:
    RPCConnection(RPCServer& server,
                  asio::io_context& io,
                  std::shared_ptr<tcp::socket> socket,
                  const std::string& clientIP)
        : mServer(server)
        , mSocket(socket)
        , mTimer(io)
        , mClientIP(clientIP)
        , mHeaderEnd(std::string::npos)
        , mContentLength(0)
        , mHaveContentLength(false)
        , mDispatched(false)
        , mClosed(false)
    {
        mServer.mActiveConnections++;
    }

    ~RPCConnection() {
        Close();
        mServer.mActiveConnections--;
    }

    RPCConnection(const RPCConnection&) = delete;
    RPCConnection& operator=(const RPCConnection&) = delete;

    // Event thread.
    void Start() {
        boost::system::error_code ec;
        mTimer.expires_after(
            std::chrono::seconds(RPC_CLIENT_TIMEOUT_SEC));
        (void)ec;
        auto self = shared_from_this();
        mTimer.async_wait(
            [self](const boost::system::error_code& terr) {
                self->OnDeadline(terr);
            });
        DoRead();
    }

    // Refusal decided at accept time. Event thread.
    void Reject(int status, const std::string& reason) {
        SendStatusAndClose(status, reason);
    }

    // Worker thread. No asynchronous operation is outstanding on the socket.
    void Execute() {
        std::string reply;
        try {
            reply = mServer.BuildResponseBody(mBody, mClientIP);
        } catch (const std::exception& e) {
            MONEU_LOG_ERROR(std::string("RPC: command failed for ") +
                            node::Log::PeerAddr(mClientIP) + ": " + e.what());
            SendStatusAndClose(500, "Internal error");
            return;
        }
        std::ostringstream oss;
        oss << "HTTP/1.1 200 OK\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << reply.size() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << reply;
        WriteAllAndClose(oss.str());
    }

private:
    void DoRead() {
        auto self = shared_from_this();
        mSocket->async_read_some(
            asio::buffer(mChunk),
            [self](const boost::system::error_code& ec, size_t n) {
                self->OnRead(ec, n);
            });
    }

    void OnRead(const boost::system::error_code& ec, size_t bytes) {
        if (mDispatched || mClosed) return;
        if (ec) {
            // The caller went away, or the deadline closed the socket.
            CancelTimer();
            Close();
            return;
        }
        mIn.append(mChunk.data(), bytes);

        if (mHeaderEnd == std::string::npos) {
            mHeaderEnd = mIn.find("\r\n\r\n");
            if (mHeaderEnd == std::string::npos) {
                if (mIn.size() > RPC_MAX_HEADERS_SIZE) {
                    MONEU_LOG_WARN(
                        "RPC: header block too large from" +
                        node::Log::PeerAddr(mClientIP));
                    SendStatusAndClose(431, "Header too large");
                    return;
                }
                DoRead();
                return;
            }
            if (!ParseHeaders()) return;
        }

        const size_t have = mIn.size() - (mHeaderEnd + 4);
        if (have < mContentLength) {
            DoRead();
            return;
        }
        mBody = mIn.substr(mHeaderEnd + 4, mContentLength);
        Dispatch();
    }

    // Answers and returns false when the request cannot be served.
    bool ParseHeaders() {
        const std::string head = mIn.substr(0, mHeaderEnd);
        std::istringstream stream(head);
        std::string line;

        if (!std::getline(stream, line)) {
            SendStatusAndClose(400, "Empty request");
            return false;
        }
        if (!line.empty() && line[line.size() - 1] == '\r')
            line.erase(line.size() - 1);
        if (line.compare(0, 5, "POST ") != 0) {
            MONEU_LOG_DEBUG("RPC: non-POST request from" +
                            node::Log::PeerAddr(mClientIP));
            SendStatusAndClose(405, "Only POST is served");
            return false;
        }

        while (std::getline(stream, line)) {
            if (!line.empty() && line[line.size() - 1] == '\r')
                line.erase(line.size() - 1);
            const size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            const std::string name  = ToLowerAscii(line.substr(0, colon));
            const std::string value = TrimAscii(line.substr(colon + 1));

            if (name == "authorization") {
                const std::string lowered = ToLowerAscii(value);
                if (lowered.compare(0, 6, "basic ") == 0)
                    mAuth = TrimAscii(value.substr(6));
            } else if (name == "content-length") {
                if (value.empty()) {
                    SendStatusAndClose(400, "Bad Content-Length");
                    return false;
                }
                for (size_t i = 0; i < value.size(); ++i) {
                    if (value[i] < '0' || value[i] > '9') {
                        SendStatusAndClose(400, "Bad Content-Length");
                        return false;
                    }
                }
                if (value.size() > 20) {
                    SendStatusAndClose(413, "Body too large");
                    return false;
                }
                const unsigned long long declared =
                    std::strtoull(value.c_str(), NULL, 10);
                if (declared > RPC_MAX_BODY_SIZE) {
                    MONEU_LOG_WARN(
                        "RPC: declared body of " + value +
                        " bytes refused from" +
                        node::Log::PeerAddr(mClientIP));
                    SendStatusAndClose(413, "Body too large");
                    return false;
                }
                mContentLength     = static_cast<size_t>(declared);
                mHaveContentLength = true;
            }
        }

        if (!mHaveContentLength) {
            SendStatusAndClose(400, "Content-Length required");
            return false;
        }
        if (!mServer.CheckAuth(mAuth)) {
            MONEU_LOG_WARN("RPC: authentication failed from" +
                           node::Log::PeerAddr(mClientIP));
            SendUnauthorizedAndClose();
            return false;
        }
        if (mContentLength == 0) {
            SendStatusAndClose(400, "Empty body");
            return false;
        }
        // Sized by this request, not by the largest one imaginable.
        mIn.reserve(mHeaderEnd + 4 + mContentLength);
        return true;
    }

    // Event thread. From here the socket belongs to a worker.
    void Dispatch() {
        mDispatched = true;
        CancelTimer();
        auto self = shared_from_this();
        if (!mServer.EnqueueConnection(self)) {
            MONEU_LOG_WARN(
                "RPC: work queue full, refusing a request from" +
                node::Log::PeerAddr(mClientIP));
            SendStatusAndClose(503, "Work queue depth exceeded");
        }
    }

    void OnDeadline(const boost::system::error_code& ec) {
        if (ec == asio::error::operation_aborted) return;
        if (mDispatched || mClosed) return;
        MONEU_LOG_DEBUG("RPC: request deadline reached for" +
                        node::Log::PeerAddr(mClientIP));
        SendStatusAndClose(408, "Request timed out");
    }

    void CancelTimer() {
        boost::system::error_code ec;
        mTimer.cancel(ec);
    }

    void SendStatusAndClose(int status, const std::string& reason) {
        json payload;
        payload["jsonrpc"] = "2.0";
        payload["id"]      = nullptr;
        payload["result"]  = nullptr;
        payload["error"]   = {{"code", RPC_MISC_ERROR},
                              {"message", reason}};
        const std::string body = payload.dump();

        std::ostringstream oss;
        oss << "HTTP/1.1 " << status << ' '
            << HttpStatusText(status) << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << body;
        WriteAllAndClose(oss.str());
    }

    void SendUnauthorizedAndClose() {
        json payload;
        payload["jsonrpc"] = "2.0";
        payload["id"]      = nullptr;
        payload["result"]  = nullptr;
        payload["error"]   = {{"code", RPC_FORBIDDEN},
                              {"message", "Authentication failed"}};
        const std::string body = payload.dump();

        std::ostringstream oss;
        oss << "HTTP/1.1 401 Unauthorized\r\n"
            << "WWW-Authenticate: Basic realm=\"MONEU\"\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << body;
        WriteAllAndClose(oss.str());
    }

    // Called from the event thread for refusals and from a worker for
    // answers. Nothing else is using the socket at that moment.
    void WriteAllAndClose(const std::string& payload) {
        if (mClosed) return;
        boost::system::error_code ec;
#ifndef WIN32
        struct timeval tv;
        tv.tv_sec  = static_cast<time_t>(RPC_CLIENT_TIMEOUT_SEC);
        tv.tv_usec = 0;
        setsockopt(mSocket->native_handle(), SOL_SOCKET, SO_SNDTIMEO,
                   &tv, sizeof(tv));
#endif
        asio::write(*mSocket, asio::buffer(payload), ec);
        if (ec) {
            MONEU_LOG_DEBUG("RPC: could not write the reply to" +
                            node::Log::PeerAddr(mClientIP) + ": " +
                            ec.message());
        }
        Close();
    }

    void Close() {
        if (mClosed) return;
        mClosed = true;
        boost::system::error_code ec;
        mTimer.cancel(ec);
        mSocket->shutdown(tcp::socket::shutdown_both, ec);
        mSocket->close(ec);
    }

    RPCServer&                   mServer;
    std::shared_ptr<tcp::socket> mSocket;
    asio::steady_timer           mTimer;
    std::string                  mClientIP;
    std::array<char, 4096>       mChunk;
    std::string                  mIn;
    std::string                  mBody;
    std::string                  mAuth;
    size_t                       mHeaderEnd;
    size_t                       mContentLength;
    bool                         mHaveContentLength;
    std::atomic<bool>            mDispatched;
    std::atomic<bool>            mClosed;
};

RPCServer::RPCServer(uint16_t port)
    : mAcceptor(mIO)
    , mRunning(false)
    , mInWarmup(true)
    , mWarmupStatus("RPC server starting")
    , mActiveConnections(0)
    , mPort(port)
    , mBindAddress("127.0.0.1")
    , mWorkerCount(RPC_DEFAULT_THREADS)
    , mQueueDepth(RPC_DEFAULT_WORKQUEUE)
    , mQueueRunning(false)
{}

RPCServer::~RPCServer() { Stop(); }

bool RPCServer::Start(
    const RPCContext& context,
    const std::string& rpcUser,
    const std::string& rpcPassword,
    const std::vector<std::string>& allowedIPs,
    const std::string& bindAddress,
    size_t workerThreads,
    size_t queueDepth)
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (mRunning) return false;
    if (rpcUser.empty() || rpcPassword.empty()) {
        MONEU_LOG_ERROR("RPC: rpcuser and rpcpassword are both required");
        return false;
    }
    mContext     = context;
    mRPCUser     = rpcUser;
    mRPCPassword = rpcPassword;
    mWorkerCount = workerThreads > 0 ? workerThreads : 1;
    mQueueDepth  = queueDepth > 0 ? queueDepth : 1;
    mBindAddress = bindAddress.empty() ? std::string("127.0.0.1")
                                       : bindAddress;

    mAllowedSubnets.clear();
    for (size_t i = 0; i < allowedIPs.size(); ++i) {
        RPCSubNet subnet;
        if (!RPCParseSubNet(allowedIPs[i], subnet)) {
            MONEU_LOG_ERROR("RPC: rpcallowip entry '" + allowedIPs[i] +
                            "' is not an address, a network/CIDR or a "
                            "network/netmask");
            return false;
        }
        mAllowedSubnets.push_back(subnet);
    }
    if (mAllowedSubnets.empty()) {
        RPCSubNet loopback;
        if (RPCParseSubNet("127.0.0.1", loopback))
            mAllowedSubnets.push_back(loopback);
    }

    RegisterBuiltinCommands();
    RegisterBlockchainRPCCommands(mTable);
    RegisterNetworkRPCCommands(mTable);
    RegisterWalletRPCCommands(mTable);
    RegisterMiningRPCCommands(mTable);

    try {
        boost::system::error_code ec;
        const asio::ip::address addr =
            asio::ip::make_address(mBindAddress, ec);
        if (ec) {
            MONEU_LOG_ERROR("RPC: rpcbind address '" + mBindAddress +
                            "' cannot be read");
            return false;
        }
        const tcp::endpoint endpoint(addr, mPort);
        mAcceptor.open(endpoint.protocol());
        mAcceptor.set_option(asio::socket_base::reuse_address(true));
        mAcceptor.bind(endpoint);
        mAcceptor.listen();
        if (addr.is_unspecified()) {
            MONEU_LOG_WARN("RPC: the control port is bound to every "
                           "interface; close it at the firewall unless "
                           "that is what you meant");
        }
    } catch (const std::exception& e) {
        MONEU_LOG_ERROR("RPC: cannot listen on " + mBindAddress + ":" +
                        std::to_string(mPort) + ": " + e.what());
        return false;
    }

    mRunning      = true;
    mQueueRunning = true;

    mWorkGuard.reset(
        new asio::executor_work_guard<asio::io_context::executor_type>(
            asio::make_work_guard(mIO)));

    for (size_t i = 0; i < mWorkerCount; ++i)
        mWorkers.emplace_back([this]() { WorkerLoop(); });

    StartAccept();

    // One event thread, as in Bitcoin. Everything a connection does outside
    // Execute() therefore runs on a single thread and needs no lock.
    mThreads.emplace_back([this]() {
        try { mIO.run(); } catch (...) {}
    });

    std::string allowed;
    for (size_t i = 0; i < mAllowedSubnets.size(); ++i) {
        if (i) allowed += " ";
        allowed += mAllowedSubnets[i].ToString();
    }
    MONEU_LOG_INFO("RPC: listening on " + mBindAddress + ":" +
                   std::to_string(mPort) + ", " +
                   std::to_string(mWorkerCount) + " worker threads, " +
                   "queue depth " + std::to_string(mQueueDepth) +
                   ", allowed: " + allowed);
    return true;
}

void RPCServer::Stop() {
    if (mThreads.empty() && mWorkers.empty()) return;

    Interrupt();

    for (size_t i = 0; i < mWorkers.size(); ++i) {
        if (mWorkers[i].joinable()) mWorkers[i].join();
    }
    mWorkers.clear();

    for (size_t i = 0; i < mThreads.size(); ++i) {
        if (mThreads[i].joinable()) mThreads[i].join();
    }
    mThreads.clear();

    {
        std::lock_guard<std::mutex> lock(mQueueMutex);
        mQueue.clear();
    }

    MONEU_LOG_INFO("RPC: stopped");
}

void RPCServer::Interrupt() {
    mRunning = false;
    {
        boost::system::error_code ec;
        mAcceptor.cancel(ec);
        mAcceptor.close(ec);
    }
    {
        std::lock_guard<std::mutex> lock(mQueueMutex);
        mQueueRunning = false;
    }
    mQueueCv.notify_all();
    if (mWorkGuard) mWorkGuard->reset();
    mIO.stop();
}

void RPCServer::SetWarmupStatus(const std::string& status) {
    std::lock_guard<std::mutex> lock(mMutex);
    mWarmupStatus = status;
    mInWarmup     = true;
}

void RPCServer::SetWarmupFinished() {
    std::lock_guard<std::mutex> lock(mMutex);
    mInWarmup = false;
    MONEU_LOG_INFO("RPC: warmup finished");
}

void RPCServer::StartAccept() {
    if (!mRunning) return;
    auto socket = std::make_shared<tcp::socket>(mIO);
    mAcceptor.async_accept(
        *socket,
        [this, socket](const boost::system::error_code& ec) {
            OnAccept(socket, ec);
        });
}

void RPCServer::OnAccept(std::shared_ptr<tcp::socket> socket,
                          const boost::system::error_code& ec)
{
    if (!mRunning) return;
    if (ec) {
        if (ec != asio::error::operation_aborted) {
            MONEU_LOG_WARN("RPC: accept failed: " + ec.message());
            StartAccept();
        }
        return;
    }

    boost::system::error_code epEc;
    const tcp::endpoint remote = socket->remote_endpoint(epEc);
    if (epEc) {
        boost::system::error_code closeEc;
        socket->close(closeEc);
        StartAccept();
        return;
    }

    RPCAddrBytes addrBytes;
    const bool readable = RPCAddressToBytes(remote.address(), addrBytes);
    const std::string clientIP = remote.address().to_string();

    auto conn = std::make_shared<RPCConnection>(
        *this, mIO, socket, clientIP);

    if (!readable || !IsAddressAllowed(addrBytes)) {
        MONEU_LOG_WARN("RPC: refused a connection from an address that is "
                       "not on the rpcallowip list" +
                       node::Log::PeerAddr(clientIP));
        conn->Reject(403, "Client is not allowed control access");
        StartAccept();
        return;
    }

    if (mActiveConnections.load() > RPC_MAX_CONNECTIONS) {
        MONEU_LOG_WARN("RPC: connection limit of " +
                       std::to_string(RPC_MAX_CONNECTIONS) +
                       " reached, refusing" +
                       node::Log::PeerAddr(clientIP));
        conn->Reject(503, "Too many control connections");
        StartAccept();
        return;
    }

    conn->Start();
    StartAccept();
}

bool RPCServer::EnqueueConnection(
    const std::shared_ptr<RPCConnection>& conn)
{
    {
        std::lock_guard<std::mutex> lock(mQueueMutex);
        if (!mQueueRunning) return false;
        if (mQueue.size() >= mQueueDepth) return false;
        mQueue.push_back(conn);
    }
    mQueueCv.notify_one();
    return true;
}

void RPCServer::WorkerLoop() {
    for (;;) {
        std::shared_ptr<RPCConnection> conn;
        {
            std::unique_lock<std::mutex> lock(mQueueMutex);
            while (mQueueRunning && mQueue.empty())
                mQueueCv.wait(lock);
            if (!mQueueRunning && mQueue.empty()) return;
            conn = mQueue.front();
            mQueue.pop_front();
        }
        if (!conn) continue;
        try {
            conn->Execute();
        } catch (const std::exception& e) {
            MONEU_LOG_ERROR(std::string("RPC: worker caught: ") + e.what());
        }
    }
}

std::string RPCServer::BuildResponseBody(const std::string& body,
                                          const std::string& clientIP)
{
    try {
        const json parsed = json::parse(body);
        if (parsed.is_array()) {
            if (parsed.empty()) {
                return RPCResponse::Error(
                    RPC_INVALID_REQUEST, "Empty batch",
                    nullptr).ToJson().dump();
            }
            return ProcessBatch(parsed, clientIP);
        }

        RPCRequest request;
        request.clientIP = clientIP;
        if (!ParseRequest(body, request)) {
            return RPCResponse::Error(
                RPC_INVALID_REQUEST, "Invalid request",
                nullptr).ToJson().dump();
        }

        if (mInWarmup) {
            std::string warmupMsg;
            {
                std::lock_guard<std::mutex> lock(mMutex);
                warmupMsg = mWarmupStatus;
            }
            return RPCResponse::Error(
                RPC_IN_WARMUP, "Server in warmup: " + warmupMsg,
                request.id).ToJson().dump();
        }

        try {
            const json result = mTable.Execute(request, mContext);
            return RPCResponse::Success(result, request.id)
                .ToJson().dump();
        } catch (const RPCError& e) {
            return RPCResponse::Error(e.code, e.what(), request.id)
                .ToJson().dump();
        } catch (const std::exception& e) {
            return RPCResponse::Error(
                RPC_INTERNAL_ERROR, e.what(), request.id)
                .ToJson().dump();
        }
    } catch (const json::exception& e) {
        return RPCResponse::Error(
            RPC_PARSE_ERROR,
            std::string("JSON parse error: ") + e.what(),
            nullptr).ToJson().dump();
    }
}

bool RPCServer::ParseRequest(const std::string& body,
                               RPCRequest& request)
{
    try {
        json j = json::parse(body);
        if (!j.is_object()) return false;
        if (!j.contains("method") ||
            !j["method"].is_string()) return false;
        request.method = j["method"].get<std::string>();
        request.params = j.contains("params")
            ? j["params"] : json::array();
        if (j.contains("id")) {
            request.id = j["id"];
        } else {
            request.id = nullptr;
            request.isNotification = true;
        }
        return true;
    } catch (...) { return false; }
}

std::string RPCServer::ProcessBatch(
    const json& batch, const std::string& clientIP)
{
    json results = json::array();
    for (const auto& req : batch) {
        RPCRequest rpcReq;
        rpcReq.clientIP = clientIP;
        std::string reqStr = req.dump();
        RPCResponse rpcResp;
        if (!ParseRequest(reqStr, rpcReq)) {
            rpcResp = RPCResponse::Error(
                RPC_PARSE_ERROR,
                "Parse error in batch", nullptr);
        } else if (mInWarmup) {
            std::string warmupMsg;
            {
                std::lock_guard<std::mutex> lk(mMutex);
                warmupMsg = mWarmupStatus;
            }
            rpcResp = RPCResponse::Error(
                RPC_IN_WARMUP,
                "Server in warmup: " + warmupMsg,
                rpcReq.id);
        } else {
            try {
                json result =
                    mTable.Execute(rpcReq, mContext);
                rpcResp = RPCResponse::Success(
                    result, rpcReq.id);
            } catch (const RPCError& e) {
                rpcResp = RPCResponse::Error(
                    e.code, e.what(), rpcReq.id);
            } catch (const std::exception& e) {
                rpcResp = RPCResponse::Error(
                    RPC_INTERNAL_ERROR,
                    e.what(), rpcReq.id);
            }
        }
        if (!rpcReq.isNotification)
            results.push_back(rpcResp.ToJson());
    }
    return results.dump();
}

bool RPCServer::CheckAuth(
    const std::string& authHeader) const
{
    if (authHeader.empty()) return false;
    std::string decoded = Base64Decode(authHeader);
    if (decoded.empty()) return false;
    size_t colonPos = decoded.find(':');
    if (colonPos == std::string::npos) return false;
    if (colonPos == 0 ||
        colonPos == decoded.size() - 1) return false;
    // Both halves are compared in full and combined afterwards, so neither
    // can be probed one byte at a time by timing the answer.
    const bool userOk =
        TimingSafeEqual(decoded.substr(0, colonPos), mRPCUser);
    const bool passOk =
        TimingSafeEqual(decoded.substr(colonPos + 1), mRPCPassword);
    return userOk && passOk;
}

bool RPCServer::IsAddressAllowed(const RPCAddrBytes& addr) const {
    for (size_t i = 0; i < mAllowedSubnets.size(); ++i) {
        if (mAllowedSubnets[i].Match(addr)) return true;
    }
    return false;
}

bool RPCServer::RegisterCommand(const RPCCommand& cmd) {
    return mTable.Register(cmd);
}

bool RPCServer::UnregisterCommand(const std::string& name) {
    return mTable.Unregister(name);
}

std::string RPCServer::ExecuteCommand(
    const std::string& method, const json& params)
{
    RPCRequest req;
    req.method = method;
    req.params = params;
    req.id     = 1;
    try {
        json result = mTable.Execute(req, mContext);
        return RPCResponse::Success(result, req.id)
            .ToJson().dump();
    } catch (const RPCError& e) {
        return RPCResponse::Error(
            e.code, e.what(), req.id).ToJson().dump();
    } catch (const std::exception& e) {
        return RPCResponse::Error(
            RPC_INTERNAL_ERROR, e.what(), req.id)
            .ToJson().dump();
    }
}

// Difficulty as a plain number, the way Bitcoin reports it: how many times
// harder the current target is than the easiest one the network allows.
// Bits carry an exponent and a mantissa, so the two are compared by
// shifting one toward the other rather than by expanding both into 256-bit
// integers, which would need no more precision than a double can hold.
static double BitsToDifficulty(uint32_t bits) {
    int shift = (bits >> 24) & 0xFF;
    double diff = double(0x0000FFFF) / double(bits & 0x00FFFFFF);
    while (shift < 29) { diff *= 256.0; ++shift; }
    while (shift > 29) { diff /= 256.0; --shift; }
    return diff;
}

// Decode a payment address to its hash, checking prefix, length and
// checksum. Shared by startmining and getblocktemplate so a mistyped
// address fails the same way in both rather than in one of them.
static bool DecodeRewardAddress(const std::string& addrStr,
                                bytes32& hashOut,
                                std::string& whyOut) {
    uint8_t decoded[37];
    size_t  decodedLen = 37;
    if (addrStr.empty() || addrStr.size() > 64 ||
        !b58tobin(decoded, &decodedLen, addrStr.c_str()) ||
        decodedLen != 37) {
        whyOut = "Invalid reward address encoding";
        return false;
    }
    if (decoded[0] != NetParams::PUBKEY_ADDRESS_PREFIX) {
        whyOut = "Reward address has wrong network prefix";
        return false;
    }
    uint8_t h1[32], h2[32];
    SHA256_CTX sctx;
    sha256_Init(&sctx);
    sha256_Update(&sctx, decoded, 33);
    sha256_Final(&sctx, h1);
    sha256_Init(&sctx);
    sha256_Update(&sctx, h1, 32);
    sha256_Final(&sctx, h2);
    if (std::memcmp(decoded + 33, h2, 4) != 0) {
        whyOut = "Reward address checksum does not match";
        return false;
    }
    std::memcpy(hashOut.data(), decoded + 1, 32);
    return true;
}

// Difficulty bits as the eight-digit hex string, the way Bitcoin prints
// them, so mining software reading this output needs no translation.
static std::string BitsToHex(uint32_t bits) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(8);
    for (int shift = 28; shift >= 0; shift -= 4) {
        out.push_back(d[(bits >> shift) & 0x0F]);
    }
    return out;
}

// The target the block hash must come in under, expanded from the compact
// form. Sent alongside bits because mining software compares against this
// directly and should not have to expand it itself.
static std::string TargetFromBits(uint32_t bits) {
    // Expand the compact form by hand rather than through arith_uint256,
    // which has no way to read its words back out. The compact encoding is
    // an exponent in the top byte and a three-byte mantissa, so the target
    // is the mantissa shifted left by (exponent - 3) bytes.
    const uint32_t exponent = bits >> 24;
    const uint32_t mantissa = bits & 0x007FFFFF;

    uint8_t target[32];
    std::memset(target, 0, sizeof(target));

    if (exponent <= 3) {
        const uint32_t shifted = mantissa >> (8 * (3 - exponent));
        target[31] = static_cast<uint8_t>(shifted & 0xFF);
        if (exponent >= 2) target[30] = static_cast<uint8_t>((shifted >> 8) & 0xFF);
        if (exponent >= 3) target[29] = static_cast<uint8_t>((shifted >> 16) & 0xFF);
    } else if (exponent <= 32) {
        // Mantissa occupies the three bytes ending at position (32 - exponent).
        const int end = 32 - static_cast<int>(exponent);
        if (end + 2 < 32 && end >= 0) {
            target[end]     = static_cast<uint8_t>((mantissa >> 16) & 0xFF);
            target[end + 1] = static_cast<uint8_t>((mantissa >> 8) & 0xFF);
            target[end + 2] = static_cast<uint8_t>(mantissa & 0xFF);
        }
    }

    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; ++i) {
        out.push_back(d[(target[i] >> 4) & 0x0F]);
        out.push_back(d[target[i] & 0x0F]);
    }
    return out;
}

// Hex string to bytes, refusing anything that is not an even run of hex
// digits rather than silently decoding half of it.
static bool HexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nib(hex[i]);
        const int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

static std::string BytesToHex(const bytes32& hash) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : hash)
        oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

// Hex-encode an arbitrary byte vector (for raw transaction/block hex).
static std::string BytesToHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : data) oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

// Parse a 64-character hex string into a bytes32 (e.g. a txid or block hash).
// Throws RPC_INVALID_PARAMS on bad length or non-hex characters.
static bytes32 Hex64ToBytes32(const std::string& hex) {
    if (hex.size() != 64) {
        throw RPCError(RPC_INVALID_PARAMS,
            "Expected a 64-character hex hash");
    }
    bytes32 out;
    for (size_t i = 0; i < 32; ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(hex[2*i]), lo = nib(hex[2*i+1]);
        if (hi < 0 || lo < 0) {
            throw RPCError(RPC_INVALID_PARAMS,
                "Invalid hex character in hash");
        }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

void RPCServer::RegisterBuiltinCommands() {
    mTable.Register(RPCCommand(
        "control", "help",
        "help ( \"command\" ) - List all commands or "
        "get help for one",
        [this](const RPCRequest& req,
               const RPCContext&) -> json {
            std::string cmd;
            if (req.params.is_array() &&
                req.params.size() > 0 &&
                req.params[0].is_string())
                cmd = req.params[0].get<std::string>();
            return mTable.Help(cmd);
        }
    ));

    // Shutdown is deferred by 200ms so the HTTP response
    // reaches the client before the server closes.
    // This mirrors Bitcoin's approach where libevent
    // finishes the active request before shutting down.
    mTable.Register(RPCCommand(
        "control", "stop",
        "stop - Gracefully stop the MONEU node",
        [](const RPCRequest&, const RPCContext&) -> json {
            MONEU_LOG_INFO("RPC: stop requested");
            std::thread([]() {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(200));
                RequestShutdown();
            }).detach();
            return "MONEU node stopping...";
        }
    ));

    mTable.Register(RPCCommand(
        "control", "uptime",
        "uptime - Returns node uptime in seconds",
        [](const RPCRequest&, const RPCContext&) -> json {
            static auto startTime =
                std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            return std::chrono::duration_cast<
                std::chrono::seconds>(
                    now - startTime).count();
        }
    ));

    mTable.Register(RPCCommand(
        "control", "getinfo",
        "getinfo - Returns basic node information",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            json result;
            result["version"]   = "0.1.0";
            result["network"]   = NetParams::NETWORK_ID;
            result["useragent"] = NetParams::USER_AGENT;
            // From the running configuration, not the compiled default. A
            // node started on a different port used to report the built-in
            // one, so an operator saw a number unrelated to what the node
            // was actually listening on.
            result["port"]      = ctx.config
                ? ctx.config->GetNetwork().port
                : NetParams::DEFAULT_PORT;
            result["rpcport"]   = ctx.config
                ? ctx.config->GetRPC().rpcPort
                : NetParams::RPC_PORT;
            if (ctx.chainState) {
                result["blocks"] =
                    ctx.chainState->GetHeight();
                result["bestblockhash"] = BytesToHex(
                    ctx.chainState->GetBestBlockHash());
            }
            if (ctx.connManager)
                result["connections"] =
                    ctx.connManager->GetNodeCount();
            if (ctx.wallet)
                result["wallet"] =
                    ctx.wallet->IsInitialized()
                    ? "loaded" : "not loaded";
            return result;
        }
    ));
}

void RegisterBlockchainRPCCommands(RPCTable& table) {
    table.Register(RPCCommand(
        "blockchain", "getblockcount",
        "getblockcount - Returns current block height",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.chainState)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ChainState not available");
            return ctx.chainState->GetHeight();
        }
    ));

    table.Register(RPCCommand(
        "blockchain", "getbestblockhash",
        "getbestblockhash - Returns best block hash hex",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.chainState)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ChainState not available");
            return BytesToHex(
                ctx.chainState->GetBestBlockHash());
        }
    ));

    table.Register(RPCCommand(
        "blockchain", "getblockhash",
        "getblockhash <height> - Returns the block hash at a height",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.chainState)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ChainState not available");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_number_integer())
                throw RPCError(RPC_INVALID_PARAMS,
                    "height (integer) required");
            int64_t h = req.params[0].get<int64_t>();
            if (h < 0)
                throw RPCError(RPC_INVALID_PARAMS,
                    "height must be non-negative");
            bytes32 hash;
            if (!ctx.chainState->GetBlockHashByHeight(
                    static_cast<uint32_t>(h), hash))
                throw RPCError(RPC_INVALID_PARAMS,
                    "Block height out of range");
            return BytesToHex(hash);
        }
    ));

    table.Register(RPCCommand(
        "blockchain", "getblock",
        "getblock \"blockhash\" - Returns block data",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.chainState)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ChainState not available");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "blockhash required");
            std::string hashStr =
                req.params[0].get<std::string>();
            if (hashStr.size() != 64)
                throw RPCError(RPC_INVALID_PARAMS,
                    "Invalid block hash length");
            bytes32 blockHash;
            for (size_t i = 0; i < 32; ++i) {
                try {
                    blockHash[i] = static_cast<uint8_t>(
                        std::stoul(
                            hashStr.substr(i*2, 2),
                            nullptr, 16));
                } catch (...) {
                    throw RPCError(RPC_INVALID_PARAMS,
                        "Invalid block hash hex");
                }
            }
            Block block;
            if (!ctx.chainState->GetBlock(
                    block, blockHash))
                throw RPCError(RPC_MISC_ERROR,
                    "Block not found");
            const BlockHeader& hdr = block.GetHeader();
            json result;
            result["hash"]              = hashStr;
            result["height"]            = hdr.GetHeight();
            result["version"]           = hdr.GetVersion();
            result["time"]              = hdr.GetTimestamp();
            result["bits"]              = hdr.GetBits();
            result["nonce"]             = hdr.GetNonce();
            result["merkleroot"]        = BytesToHex(hdr.GetMerkleRoot());
            result["leafroot"]          = BytesToHex(hdr.GetLeafRoot());
            result["previousblockhash"] = BytesToHex(hdr.GetPrevBlockHash());
            result["ntx"]               = block.GetTransactionCount();

            // Transaction ids in this block, in order (coinbase first).
            json txids = json::array();
            for (const auto& tx : block.GetTransactions()) {
                txids.push_back(BytesToHex(tx.GetHash()));
            }
            result["tx"] = txids;
            return result;
        }
    ));

    table.Register(RPCCommand(
        "blockchain", "getrawmempool",
        "getrawmempool (verbose) - "
        "List the transactions this node is holding for a future block. "
        "With verbose true, each entry carries its size, fee, age, whether "
        "its leaves are published, and the parents it is waiting on.",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            // What the pool is holding, by name.
            //
            // getmempoolinfo answers only with a count and a byte total,
            // which says a queue exists but not what is in it. When a
            // transaction sits through block after block there is no way to
            // ask which one it is, what it waits for, or whether the miner
            // can even value it. That is the question this answers.
            if (!ctx.mempool)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Mempool not available");

            bool verbose = false;
            if (req.params.is_array() && req.params.size() > 0 &&
                !req.params[0].is_null()) {
                const nlohmann::json& v = req.params[0];
                if (v.is_boolean())              verbose = v.get<bool>();
                else if (v.is_number_integer())  verbose = v.get<int64_t>() != 0;
                else if (v.is_number())          verbose = v.get<double>() != 0.0;
                else if (v.is_string()) {
                    const std::string t = v.get<std::string>();
                    verbose = (t == "1" || t == "true" || t == "TRUE" ||
                               t == "True" || t == "yes");
                }
            }

            const std::vector<Mempool::PersistedEntry> entries =
                ctx.mempool->Snapshot();

            if (!verbose) {
                json out = json::array();
                for (size_t i = 0; i < entries.size(); ++i) {
                    out.push_back(BytesToHex(entries[i].tx.GetHash()));
                }
                return out;
            }

            // Every hash the pool holds, so a parent in the pool can be
            // told from an input pointing at the chain instead.
            std::set<std::string> inPool;
            for (size_t i = 0; i < entries.size(); ++i) {
                inPool.insert(BytesToHex(entries[i].tx.GetHash()));
            }

            const int64_t now = static_cast<int64_t>(std::time(NULL));
            json out = json::object();
            for (size_t i = 0; i < entries.size(); ++i) {
                const Transaction& tx = entries[i].tx;
                const size_t size = tx.GetSerializedSize(true);

                json e;
                e["size"]        = static_cast<uint64_t>(size);
                e["fee"]         = entries[i].fee;
                e["fee_moneu"]   = FormatAmount(entries[i].fee);
                e["time"]        = entries[i].entryTime;
                e["age_seconds"] = (now > entries[i].entryTime)
                                   ? (now - entries[i].entryTime) : 0;
                e["feerate_per_kb"] = (size > 0)
                    ? (entries[i].fee * 1000 / static_cast<int64_t>(size))
                    : 0;
                e["vin"]  = static_cast<uint64_t>(tx.GetInputCount());
                e["vout"] = static_cast<uint64_t>(tx.GetOutputCount());

                // Whether the leaves that authorise this spend are in the
                // pool alongside it. A transaction without them cannot be
                // settled by any block, so this is the first thing to look
                // at when one will not confirm.

                // Inputs, split by where the output they name lives. One
                // whose parent is neither in the pool nor on the chain can
                // never be valued by a miner and will sit until it expires.
                json waitingOn      = json::array();
                json missingParents = json::array();
                for (size_t k = 0; k < tx.GetInputCount(); ++k) {
                    const TxInput& in = tx.GetInputs()[k];
                    const std::string parent = BytesToHex(in.GetPrevTxHash());
                    if (inPool.count(parent) > 0) {
                        waitingOn.push_back(parent);
                        continue;
                    }
                    if (ctx.chainState) {
                        storage::Coin coin;
                        const storage::OutPoint outpoint(
                            in.GetPrevTxHash(), in.GetOutputIndex());
                        if (ctx.chainState->GetUTXOSet().GetCoin(
                                outpoint, coin)) {
                            continue;   // spendable on the chain
                        }
                    }
                    missingParents.push_back(parent);
                }
                e["depends"]         = waitingOn;
                e["missing_parents"] = missingParents;
                e["spendable"]       = missingParents.empty();

                out[BytesToHex(tx.GetHash())] = e;
            }
            return out;
        }
    ));

    table.Register(RPCCommand(
        "blockchain", "getmempoolinfo",
        "getmempoolinfo - Returns the state of the transaction memory pool",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.mempool)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Mempool not available");
            json result;
            result["size"]  = ctx.mempool->Size();
            result["bytes"] = ctx.mempool->SizeBytes();
            // The pool is bounded by bytes rather than by a transaction
            // count, because a count limit lets an attacker occupy far
            // more memory than intended by sending large transactions.
            result["maxmempool"] = Mempool::DEFAULT_MAX_BYTES;
            result["mempoolminfee"] =
                static_cast<double>(ctx.mempool->GetMinFeeRate()) /
                static_cast<double>(NetParams::COIN);
            return result;
        }
    ));

    table.Register(RPCCommand(
        "network", "getpeerinfo",
        "getpeerinfo - Returns data about each connected peer",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.connManager)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Network not available");
            json peers = json::array();
            for (const auto& info : ctx.connManager->GetPeerInfo()) {
                json p;
                // Field names and shapes follow Bitcoin's getpeerinfo, so
                // anyone who has read that output can read this one, and
                // existing tooling needs no translation layer.
                p["id"]             = info.id;
                p["addr"]           = info.address;
                p["services"]       = ServicesToHex(info.services);
                p["lastsend"]       = info.lastSend;
                p["lastrecv"]       = info.lastRecv;
                p["bytessent"]      = info.bytesSent;
                p["bytesrecv"]      = info.bytesRecv;
                p["conntime"]       = info.connectedAt;
                // Omitted rather than reported as zero until a ping has
                // actually come back, so a peer that has never answered is
                // not shown as the fastest one on the list.
                if (info.pingSeconds >= 0.0) {
                    p["pingtime"]   = info.pingSeconds;
                }
                p["version"]        = info.version;
                p["subver"]         = info.userAgent;
                p["inbound"]        = info.inbound;
                p["startingheight"] = info.bestHeight;
                // Beyond Bitcoin's set, and worth having: the peer's tip
                // shows at a glance whether it agrees with us about the
                // chain, and the ban score whether it is misbehaving.
                p["bestblockhash"]  = info.bestBlockHash;
                p["banscore"]       = info.misbehavior;
                peers.push_back(p);
            }
            json result;
            result["peers"]    = peers;
            result["count"]    = peers.size();
            result["inbound"]  = ctx.connManager->GetInboundCount();
            result["outbound"] =
                ctx.connManager->GetNodeCount() -
                ctx.connManager->GetInboundCount();
            return result;
        }
    ));

    table.Register(RPCCommand(
        "blockchain", "getdifficulty",
        "getdifficulty - Returns the current difficulty as a number",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.chainState)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ChainState not available");
            // Difficulty is the ratio of the easiest allowed target to the
            // current one. Bits are a compact floating form, so both are
            // expanded before dividing; the result is the same number
            // Bitcoin reports and means the same thing.
            const uint32_t bits = ctx.chainState->GetNextBits();
            return json(BitsToDifficulty(bits));
        }
    ));

    table.Register(RPCCommand(
        "blockchain", "getblockchaininfo",
        "getblockchaininfo - Returns full blockchain state",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.chainState)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ChainState not available");
            const storage::ChainTip tip = ctx.chainState->GetBestChain();
            const uint32_t height = ctx.chainState->GetHeight();

            json result;
            result["chain"]         = NetParams::NETWORK_ID;
            result["blocks"]        = height;
            result["bestblockhash"] = BytesToHex(tip.blockHash);

            // Difficulty as a plain number rather than the compact form,
            // because the compact form is unreadable to a person.
            result["difficulty"] =
                BitsToDifficulty(ctx.chainState->GetNextBits());
            result["bits"] = ctx.chainState->GetNextBits();

            // Cumulative proof of work behind the tip. Two chains are
            // compared on this and never on their height, so it is the
            // number that decides which chain the node is on.
            result["chainwork"] = BytesToHex(tip.chainWork);

            // Median of the last eleven block times. Timestamp rules are
            // written against this rather than the newest block, because a
            // single miner can move one timestamp and cannot move a median.
            result["mediantime"] = ctx.chainState->GetMedianTimePast();

            result["maxmoney"] = NetParams::MAX_MONEY;
            // Bitcoin reports headers separately from blocks so the gap
            // shows how much is still to download. We have no headers-first
            // sync, so the two are always the same - reported anyway, so
            // anything reading this output does not have to special-case us.
            result["headers"] = ctx.chainState->GetHeight();
            result["networkhashps"] =
                ctx.chainState->EstimateNetworkHashPS();
            result["subsidy"]  =
                NetParams::GetBlockSubsidy(height + 1);

            // Every node keeps the whole chain from the founding block.
            // Reported so an operator never has to wonder whether history
            // was discarded to save space.
            result["pruned"] = false;

            return result;
        }
    ));
}

void RegisterNetworkRPCCommands(RPCTable& table) {
    table.Register(RPCCommand(
        "network", "getconnectioncount",
        "getconnectioncount - Returns number of connections",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.connManager)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ConnManager not available");
            return ctx.connManager->GetNodeCount();
        }
    ));

    table.Register(RPCCommand(
        "network", "getnetworkinfo",
        "getnetworkinfo - Returns network information",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            json result;
            result["version"]         = PROTOCOL_VERSION;
            result["subversion"]      = NetParams::USER_AGENT;
            result["protocolversion"] = 1;
            result["localport"]       = ctx.config
                ? ctx.config->GetNetwork().port
                : NetParams::DEFAULT_PORT;
            if (ctx.connManager) {
                result["connections"]  =
                    ctx.connManager->GetNodeCount();
                result["inbound"]      =
                    ctx.connManager->GetInboundCount();
                result["outbound"]     =
                    ctx.connManager->GetOutboundCount();
                result["networkactive"] =
                    ctx.connManager->GetNetworkActive();
                result["totalbytesrecv"] =
                    ctx.connManager->GetTotalBytesRecv();
                result["totalbytessent"] =
                    ctx.connManager->GetTotalBytesSent();
            }
            return result;
        }
    ));

    table.Register(RPCCommand(
        "network", "addnode",
        "addnode \"ip:port\" - Add a P2P peer node",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.connManager)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ConnManager not available");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "node address required");
            std::string addr =
                req.params[0].get<std::string>();
            if (addr.empty() || addr.size() > 256)
                throw RPCError(RPC_INVALID_PARAMS,
                    "Invalid node address");
            ctx.connManager->AddNode(addr);
            return nullptr;
        }
    ));

    table.Register(RPCCommand(
        "network", "setnetworkactive",
        "setnetworkactive true|false - "
        "Enable or disable P2P",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.connManager)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ConnManager not available");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_boolean())
                throw RPCError(RPC_INVALID_PARAMS,
                    "state (bool) required");
            bool state = req.params[0].get<bool>();
            ctx.connManager->SetNetworkActive(state);
            return state;
        }
    ));
}

void RegisterWalletRPCCommands(RPCTable& table) {

    table.Register(RPCCommand(
        "wallet", "createwallet",
        "createwallet \"passphrase\" - "
        "Create new wallet, returns mnemonic",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.wallet)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Wallet not available");
            if (ctx.wallet->IsInitialized())
                throw RPCError(RPC_MISC_ERROR,
                    "Wallet already exists. "
                    "Use loadwallet.");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "passphrase required");
            std::string passphrase =
                req.params[0].get<std::string>();
            if (passphrase.size() < 8)
                throw RPCError(RPC_INVALID_PARAMS,
                    "Passphrase must be at least "
                    "8 characters");
            std::string mnemonic;
            try {
                ctx.wallet->Create(passphrase, mnemonic);
            } catch (const node::WalletError& e) {
                throw RPCError(RPC_INTERNAL_ERROR,
                    std::string("Wallet create failed: ")
                    + e.what());
            }
            json result;
            result["status"]   = "created";
            result["mnemonic"] = mnemonic;
            result["warning"]  =
                "SAVE YOUR MNEMONIC! "
                "It cannot be recovered if lost!";
            return result;
        }
    ));

    table.Register(RPCCommand(
        "wallet", "loadwallet",
        "loadwallet \"passphrase\" - "
        "Load existing wallet from disk",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.wallet)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Wallet not available");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "passphrase required");
            std::string passphrase =
                req.params[0].get<std::string>();
            try {
                ctx.wallet->Load(passphrase);
            } catch (const node::WalletError& e) {
                throw RPCError(RPC_INTERNAL_ERROR,
                    std::string("Wallet load failed: ")
                    + e.what());
            }
            json result;
            result["status"]    = "loaded";
            result["addresses"] =
                ctx.wallet->GetAllAddresses().size();
            return result;
        }
    ));

    table.Register(RPCCommand(
        "wallet", "getnewaddress",
        "getnewaddress (\"label\") - "
        "Generate a new address",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.wallet)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Wallet not available");
            if (!ctx.wallet->IsInitialized())
                throw RPCError(RPC_MISC_ERROR,
                    "Wallet not loaded. Use "
                    "createwallet or loadwallet first.");
            if (ctx.wallet->IsLocked())
                throw RPCError(RPC_MISC_ERROR,
                    "Wallet is locked. "
                    "Use walletunlock first.");
            std::string label;
            if (req.params.is_array() &&
                req.params.size() > 0 &&
                req.params[0].is_string())
                label = req.params[0].get<std::string>();
            try {
                auto addr =
                    ctx.wallet->GetNewAddress(label);
                return addr.address;
            } catch (const node::WalletError& e) {
                throw RPCError(RPC_INTERNAL_ERROR,
                    std::string(
                        "Address generation failed: ")
                    + e.what());
            }
        }
    ));

    table.Register(RPCCommand(
        "wallet", "listaddresses",
        "listaddresses - List all wallet addresses",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.wallet)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Wallet not available");
            if (!ctx.wallet->IsInitialized())
                throw RPCError(RPC_MISC_ERROR,
                    "Wallet not loaded.");
            auto addrs = ctx.wallet->GetAllAddresses();
            json result = json::array();
            for (const auto& a : addrs) {
                json entry;
                entry["address"]  = a.address;
                entry["label"]    = a.label;
                entry["index"]    = a.keyIndex;
                entry["ischange"] = a.isChange;
                result.push_back(entry);
            }
            return result;
        }
    ));

    table.Register(RPCCommand(
        "wallet", "getwalletinfo",
        "getwalletinfo - Returns wallet status and info",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.wallet)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Wallet not available");
            json result;
            result["initialized"] =
                ctx.wallet->IsInitialized();
            result["locked"] = ctx.wallet->IsLocked();
            if (ctx.wallet->IsInitialized()) {
                result["addresses"] =
                    ctx.wallet->GetAllAddresses().size();
            }

            // State of the anti-quantum shield. Every address in this
            // wallet is bound to the same noise file, so the KPS shown
            // here appears inside all of them and an operator can confirm
            // that rather than take it on trust.
            //
            // The remaining leaf count is the number of spends this wallet
            // has left in total, not per address. Adding addresses does not
            // add leaves. Without this number a user has no way to know how
            // close the wallet is to being unable to spend.
            // Balance of every address this wallet owns, the way Bitcoin
            // reports it. Without this a user has to query each address
            // separately and add the results by hand.
            if (ctx.wallet->IsInitialized() && ctx.chainState) {
                const int64_t bal = ctx.wallet->GetTotalBalance(
                    ctx.chainState->GetUTXOSet());
                result["balance"] =
                    static_cast<double>(bal) /
                    static_cast<double>(NetParams::COIN);
                result["balance_units"] = bal;
            }

            // Two separate facts. The file can sit on disk while the
            // wallet is locked, and in that state there is no KPS and no
            // leaf pool in memory - asking for either throws. Reporting
            // the file's presence as though it were loaded made this
            // command fail outright on a locked wallet, which is exactly
            // when an operator most needs it to answer.
            const bool haveNoiseFile = ctx.wallet->HasNoiseFile();
            const bool noiseLoaded   = ctx.wallet->IsNoiseLoaded();
            result["noise_file_present"] = haveNoiseFile;
            result["noise_loaded"]       = noiseLoaded;

            // Transactions already signed and waiting for their leaves.
            // The leaves behind them are spent whatever happens next, so
            // an operator needs to see that something is outstanding
            // without reading the wallet file by hand.

            if (noiseLoaded) {
                result["kps"] = BytesToHex(ctx.wallet->GetNoiseKps());

                const uint32_t left  = ctx.wallet->GetNoiseRemaining();
                const uint32_t total = NetParams::NOISE_LEAF_COUNT;
                result["noise_leaves_remaining"] = left;
                result["noise_leaves_total"]     = total;

                // Size of the file on disk, derived rather than measured:
                // one leaf per 32 bytes is what the tree is built from, so
                // this always matches even if the file is elsewhere.
                result["noise_file_bytes"] =
                    static_cast<uint64_t>(total) * 32ull;

                // How much of the pool has been spent. A wallet that never
                // sees this number has no way to know it is approaching the
                // point where it holds funds it can no longer move.
                if (total > 0) {
                    result["noise_used_percent"] =
                        (100.0 * double(total - left)) / double(total);
                }
            }
            return result;
        }
    ));

    table.Register(RPCCommand(
        "wallet", "walletunlock",
        "walletunlock \"passphrase\" - Unlock the wallet",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.wallet)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Wallet not available");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "passphrase required");
            std::string passphrase =
                req.params[0].get<std::string>();

            // Load the wallet from disk if it is not in memory yet.
            //
            // It never is after a restart, and requiring a separate
            // loadwallet first meant this command answered "Wallet not
            // loaded" without saying what to do about it. Unlocking a
            // wallet that exists on disk should simply work.
            if (!ctx.wallet->IsInitialized()) {
                if (!ctx.wallet->Exists())
                    throw RPCError(RPC_MISC_ERROR,
                        "No wallet in this data directory. Create one "
                        "with: moneu-cli createwallet <passphrase>");
                if (!ctx.wallet->Load(passphrase))
                    throw RPCError(RPC_MISC_ERROR,
                        "Could not load the wallet - wrong passphrase, or "
                        "the file is damaged");
            }

            try {
                ctx.wallet->Unlock(passphrase);
            } catch (const node::WalletError& e) {
                throw RPCError(RPC_MISC_ERROR,
                    std::string("Unlock failed: ")
                    + e.what());
            }
            // Load the noise (anti-quantum OTP) file with the same
            // passphrase. Noise-bound addresses and spending need the KPS
            // in memory, so this is loaded as part of unlocking. A wallet
            // with no noise file can unlock but cannot create addresses or
            // spend until makenoise has produced one.
            if (ctx.wallet->HasNoiseFile()) {
                if (!ctx.wallet->LoadNoiseFile(passphrase)) {
                    throw RPCError(RPC_MISC_ERROR,
                        "Wallet unlocked but noise file could not be "
                        "loaded (wrong passphrase or corrupt file)");
                }
                // The noise file records nothing about what it has already
                // spent, so the pool always reloads with its pointer at the
                // start. Move it past every leaf the chain has seen from
                // this KPS before the wallet can sign anything. This is
                // what lets a noise file restored from a backup copy keep
                // working instead of re-offering leaves already consumed.
                uint32_t moved = 0;
                if (ctx.chainState) {
                    moved = ctx.wallet->SyncNoiseLeafPointer(
                        ctx.chainState->GetUTXOSet());
                }
                // A transaction held on chain while the wallet was locked
                // has a window of six blocks and no way of knowing the
                // wallet came back. Send whatever is already publishable
                // now rather than wait for the next block to notice.
                if (moved > 0) {
                    return std::string(
                        "Wallet unlocked and noise file loaded; leaf "
                        "pointer advanced past ") +
                        std::to_string(moved) +
                        " leaf(s) already spent on chain";
                }
                return "Wallet unlocked and noise file loaded";
            }
            return "Wallet unlocked (no noise file found; run makenoise "
                   "to enable address creation and spending)";
        }
    ));

    table.Register(RPCCommand(
        "wallet", "walletlock",
        "walletlock - Lock the wallet",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.wallet)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Wallet not available");
            ctx.wallet->Lock();
            return "Wallet locked";
        }
    ));

    table.Register(RPCCommand(
        "wallet", "dumpmnemonic",
        "dumpmnemonic \"passphrase\" - "
        "Show wallet mnemonic (KEEP SECRET!)",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.wallet)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Wallet not available");
            if (!ctx.wallet->IsInitialized())
                throw RPCError(RPC_MISC_ERROR,
                    "Wallet not loaded.");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "passphrase required");
            std::string passphrase =
                req.params[0].get<std::string>();
            try {
                std::string mnemonic =
                    ctx.wallet->GetMnemonic(passphrase);
                json result;
                result["mnemonic"] = mnemonic;
                result["warning"]  =
                    "NEVER share your mnemonic "
                    "with anyone!";
                return result;
            } catch (const node::WalletError& e) {
                throw RPCError(RPC_MISC_ERROR,
                    std::string("Failed: ") + e.what());
            }
        }
    ));

    // dumpprivkey "address" "passphrase" - export the private key of a single
    // wallet address, mirroring Bitcoin's dumpprivkey. The passphrase is
    // required and the key is derived from the unlocked seed, so a locked
    // wallet can never leak a key. The private key alone does NOT grant
    // spending power on MONEU: spending also requires the noise (OTP) file,
    // which is never exported here.
    table.Register(RPCCommand(
        "wallet", "dumpprivkey",
        "dumpprivkey \"address\" \"passphrase\" - "
        "Show the private key of one address (KEEP SECRET!)",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.wallet)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Wallet not available");
            if (!ctx.wallet->IsInitialized())
                throw RPCError(RPC_MISC_ERROR,
                    "Wallet not loaded.");
            if (!req.params.is_array() ||
                req.params.size() < 2 ||
                !req.params[0].is_string() ||
                !req.params[1].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "address and passphrase required");
            std::string addrStr =
                req.params[0].get<std::string>();
            std::string passphrase =
                req.params[1].get<std::string>();
            try {
                std::string privHex =
                    ctx.wallet->DumpPrivKey(addrStr, passphrase);
                json result;
                result["address"]    = addrStr;
                result["privatekey"] = privHex;
                result["warning"]    =
                    "NEVER share your private key with anyone!";
                return result;
            } catch (const node::WalletError& e) {
                throw RPCError(RPC_MISC_ERROR,
                    std::string("Failed: ") + e.what());
            }
        }
    ));

    table.Register(RPCCommand(
        "wallet", "getbalance",
        "getbalance \"address\" - "
        "Returns address balance in MONEU",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.chainState)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ChainState not available");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "address required");
            std::string addrStr =
                req.params[0].get<std::string>();
            if (addrStr.empty() || addrStr.size() > 64)
                throw RPCError(RPC_INVALID_PARAMS,
                    "Invalid address");
            // Addresses are Base58Check: a version byte, the 32-byte
            // noise-bound hash and a four-byte checksum. Decoding the raw
            // Base58 and demanding exactly 32 bytes rejects every address
            // the wallet produces, because the encoded payload is 37 bytes
            // and the condition can never hold. Use the same decoder the
            // rest of the node uses.
            uint8_t prefix = 0;
            bytes32 pubkeyHash;
            if (!DecodeNoiseAddress(addrStr, prefix, pubkeyHash))
                throw RPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    "Invalid address encoding");
            if (prefix != NetParams::PUBKEY_ADDRESS_PREFIX)
                throw RPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    "Not a payment address for this network");
            // Split into what can be spent now and what is still waiting.
            //
            // A single figure was misleading in the way that matters most:
            // it showed a balance the owner could not spend and gave no clue
            // why, so the first attempt to send failed with an error about
            // maturity that named no amount and no coins.
            const uint32_t height = ctx.chainState->GetHeight();
            const auto utxos =
                ctx.chainState->GetUTXOSet().GetUTXOsForAddress(pubkeyHash);

            int64_t spendable = 0;
            int64_t immature  = 0;
            for (const auto& u : utxos) {
                if (u.second.isCoinbase &&
                    height < u.second.height +
                             NetParams::COINBASE_MATURITY) {
                    immature += u.second.value;
                } else {
                    spendable += u.second.value;
                }
            }

            json result;
            result["spendable"] =
                static_cast<double>(spendable) /
                static_cast<double>(NetParams::COIN);
            result["immature"] =
                static_cast<double>(immature) /
                static_cast<double>(NetParams::COIN);
            result["total"] =
                static_cast<double>(spendable + immature) /
                static_cast<double>(NetParams::COIN);

            // The height at which the next reward becomes spendable, so the
            // owner can tell how long the wait is rather than guessing.
            if (immature > 0) {
                uint32_t soonest = 0;
                bool have = false;
                for (const auto& u : utxos) {
                    if (!u.second.isCoinbase) continue;
                    const uint32_t at =
                        u.second.height + NetParams::COINBASE_MATURITY;
                    if (at <= height) continue;
                    if (!have || at < soonest) { soonest = at; have = true; }
                }
                if (have) result["next_mature_at_height"] = soonest;
            }
            return result;
        }
    ));

    table.Register(RPCCommand(
        "wallet", "sendrawtransaction",
        "sendrawtransaction \"hexstring\" - "
        "Broadcast a raw TX",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.mempool)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Mempool not available");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "hexstring required");
            std::string hex =
                req.params[0].get<std::string>();
            if (hex.empty() || hex.size() % 2 != 0)
                throw RPCError(RPC_INVALID_PARAMS,
                    "Invalid hex string");
            if (hex.size() > RPC_MAX_BODY_SIZE * 2)
                throw RPCError(RPC_INVALID_PARAMS,
                    "Hex string too large");
            std::vector<uint8_t> data;
            data.reserve(hex.size() / 2);
            for (size_t i = 0; i < hex.size(); i += 2) {
                try {
                    data.push_back(
                        static_cast<uint8_t>(
                            std::stoul(
                                hex.substr(i, 2),
                                nullptr, 16)));
                } catch (...) {
                    throw RPCError(RPC_INVALID_PARAMS,
                        "Invalid hex character");
                }
            }
            Transaction tx;
            try {
                tx = Transaction::Deserialize(data);
            } catch (const std::exception& e) {
                throw RPCError(RPC_DESERIALIZATION,
                    "TX decode failed: " +
                    std::string(e.what()));
            }
            int64_t fee = 0;
            std::string reason;
            if (!ValidateAndComputeFee(tx, ctx, fee, reason))
                throw RPCError(RPC_VERIFY_REJECTED,
                    "TX invalid: " + reason);
            if (!ctx.mempool->AddTransaction(tx, fee))
                throw RPCError(RPC_VERIFY_REJECTED,
                    "TX rejected by mempool (duplicate, conflict, "
                    "or fee rate below the rolling minimum)");
            if (ctx.connManager)
                ctx.connManager->BroadcastTransaction(tx);
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (uint8_t b : tx.GetHash())
                oss << std::setw(2)
                    << static_cast<int>(b);
            return oss.str();
        }
    ));

    table.Register(RPCCommand(
        "wallet", "sendtoaddress",
        "sendtoaddress \"address\" amount (fee) - "
        "Create, sign and broadcast a payment from this wallet",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.wallet)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Wallet not available");
            if (!ctx.chainState)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ChainState not available");
            if (!ctx.mempool)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Mempool not available");
            if (!ctx.wallet->IsInitialized())
                throw RPCError(RPC_MISC_ERROR,
                    "Wallet not loaded. Use "
                    "createwallet or loadwallet first.");
            if (ctx.wallet->IsLocked())
                throw RPCError(RPC_MISC_ERROR,
                    "Wallet is locked. Use walletunlock first.");
            if (!ctx.wallet->IsNoiseLoaded())
                throw RPCError(RPC_MISC_ERROR,
                    "Noise file not loaded. Unlock with the correct "
                    "passphrase, or run makenoise first.");
            if (!req.params.is_array() ||
                req.params.size() < 2 ||
                !req.params[0].is_string() ||
                !req.params[1].is_number())
                throw RPCError(RPC_INVALID_PARAMS,
                    "address and amount required");
            std::string toAddress =
                req.params[0].get<std::string>();
            if (toAddress.empty() || toAddress.size() > 64)
                throw RPCError(RPC_INVALID_PARAMS,
                    "Invalid address");
            // Read digit by digit, never through a double. What the caller
            // typed is what they send: 1.99999 stays 199999000 base units
            // instead of rounding up to two whole MONEU.
            int64_t amount = 0;
            {
                std::string why;
                if (!ParseAmountJson(req.params[1], amount, why))
                    throw RPCError(RPC_INVALID_PARAMS,
                        "Invalid amount: " + why);
            }
            if (amount <= 0)
                throw RPCError(RPC_INVALID_PARAMS,
                    "Amount must be positive");
            // Fee: if the caller passed an explicit fee, honor it (they may
            // pay more to gain priority). Otherwise compute the per-byte
            // minimum from the actual transaction size, exactly as validation
            // requires: max(size_with_noise_proof * MIN_FEE_PER_BYTE,
            // MIN_TX_FEE). Because the size is not known until the transaction
            // is built, we build once at the floor, measure, then rebuild at
            // the size-based fee if it is higher. One rebuild converges: the
            // fee change does not alter the serialized size (a fixed-width
            // amount field), so the second build's size equals the first's.
            bool feeExplicit = false;
            int64_t fee = NetParams::MIN_TX_FEE;
            if (req.params.size() >= 3 && !req.params[2].is_null()) {
                std::string why;
                if (!ParseAmountJson(req.params[2], fee, why))
                    throw RPCError(RPC_INVALID_PARAMS,
                        "Invalid fee: " + why);
                if (fee < 0)
                    throw RPCError(RPC_INVALID_PARAMS,
                        "Fee must not be negative");
                feeExplicit = true;
            }
            if (amount <= 0)
                throw RPCError(RPC_INVALID_PARAMS,
                    "Amount too small");
            // An optional message, given as hex, that travels with the
            // transfer as an output carrying no value.
            std::vector<uint8_t> message;
            if (req.params.size() >= 4 && !req.params[3].is_null()) {
                if (!req.params[3].is_string())
                    throw RPCError(RPC_INVALID_PARAMS,
                        "Message must be a hex string");
                const std::string hex = req.params[3].get<std::string>();
                if (hex.size() % 2 != 0)
                    throw RPCError(RPC_INVALID_PARAMS,
                        "Message hex has an odd number of digits");
                if (hex.size() / 2 > NetParams::MAX_OP_RETURN_SIZE)
                    throw RPCError(RPC_INVALID_PARAMS,
                        "Message is " + std::to_string(hex.size() / 2) +
                        " bytes; the limit is " +
                        std::to_string(NetParams::MAX_OP_RETURN_SIZE));
                message.reserve(hex.size() / 2);
                for (size_t i = 0; i < hex.size(); i += 2) {
                    const int hi = HexDigit(hex[i]);
                    const int lo = HexDigit(hex[i + 1]);
                    if (hi < 0 || lo < 0)
                        throw RPCError(RPC_INVALID_PARAMS,
                            "Message is not valid hex");
                    message.push_back(
                        static_cast<uint8_t>((hi << 4) | lo));
                }
            }

            // What the pool is holding, so the wallet can spend the change
            // of its own transfers that have not confirmed yet and can hold
            // back outputs one of them already took.
            std::vector<Transaction> poolTxs;
            if (ctx.mempool) {
                const std::vector<Mempool::PersistedEntry> snap =
                    ctx.mempool->Snapshot();
                poolTxs.reserve(snap.size());
                for (size_t i = 0; i < snap.size(); ++i) {
                    poolTxs.push_back(snap[i].tx);
                }
            }

            Transaction tx;
            try {
                tx = ctx.wallet->CreateTransaction(
                    toAddress, amount, fee,
                    ctx.chainState->GetUTXOSet(),
                    ctx.chainState->GetHeight(),
                    &poolTxs, &message);
            } catch (const node::WalletError& e) {
                throw RPCError(RPC_MISC_ERROR,
                    std::string("CreateTransaction failed: ")
                    + e.what());
            }

            // The fee the size will demand once the proofs are attached.
            // Measuring the unsigned transaction would read short by the
            // proof bytes and leave the fee under the minimum, so the size
            // is projected from the input count instead.
            if (!feeExplicit) {
                const int64_t required =
                    RequiredFeeForSize(SignedSizeOf(tx));
                if (required > fee) {
                    fee = required;
                    try {
                        // The first attempt held the outputs it picked;
                        // release them so the rebuild at the higher fee can
                        // reach for the same ones.
                        ctx.wallet->ReleaseOutpointsFor(tx.GetHash());
                        tx = ctx.wallet->CreateTransaction(
                            toAddress, amount, fee,
                            ctx.chainState->GetUTXOSet(),
                            ctx.chainState->GetHeight(),
                            &poolTxs, &message);
                    } catch (const node::WalletError& e) {
                        throw RPCError(RPC_MISC_ERROR,
                            std::string("CreateTransaction failed: ")
                            + e.what());
                    }
                }
            } else {
                const int64_t required =
                    RequiredFeeForSize(SignedSizeOf(tx));
                if (fee < required) {
                    ctx.wallet->ReleaseOutpointsFor(tx.GetHash());
                    throw RPCError(RPC_INVALID_PARAMS,
                        "Fee " + std::to_string(fee) +
                        " is below the minimum " +
                        std::to_string(required) +
                        " this transfer requires; omit the fee to have it "
                        "set from the size");
                }
            }
            if (!ctx.wallet->SignTransaction(tx))
                throw RPCError(RPC_VERIFY_ERROR,
                    "Failed to sign transaction "
                    "(missing key for an input)");
            int64_t actualFee = 0;
            std::string reason;
            if (!ValidateAndComputeFee(tx, ctx, actualFee, reason))
                throw RPCError(RPC_VERIFY_REJECTED,
                    "Transaction invalid: " + reason);
            if (!ctx.mempool->AddTransaction(tx, actualFee))
                throw RPCError(RPC_VERIFY_REJECTED,
                    "Transaction rejected by mempool (duplicate, "
                    "conflict, or fee rate below the rolling minimum)");
            if (ctx.connManager)
                ctx.connManager->BroadcastTransaction(tx);
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (uint8_t b : tx.GetHash())
                oss << std::setw(2)
                    << static_cast<int>(b);
            return oss.str();
        }
    ));

    table.Register(RPCCommand(
        "wallet", "getrawtransaction",
        "getrawtransaction \"txid\" (verbose) - "
        "Get a transaction by id, as hex or decoded",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.chainState)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "ChainState not available");
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "txid required");
            bytes32 txid = Hex64ToBytes32(
                req.params[0].get<std::string>());
            // Accepted as true, 1, or "true".
            //
            // Only a JSON boolean used to count, so the form every other
            // client writes - getrawtransaction <txid> 1 - silently
            // returned the raw hex instead of the decoded transaction,
            // with nothing said about why. Bitcoin takes a number here too.
            bool verbose = false;
            if (req.params.size() > 1) {
                const nlohmann::json& v = req.params[1];
                if (v.is_boolean())              verbose = v.get<bool>();
                else if (v.is_number_integer())  verbose = v.get<int64_t>() != 0;
                else if (v.is_number())          verbose = v.get<double>() != 0.0;
                else if (v.is_string()) {
                    const std::string t = v.get<std::string>();
                    verbose = (t == "1" || t == "true" || t == "TRUE" ||
                               t == "True" || t == "yes");
                }
            }
            // The chain first, then the pool.
            //
            // Reading only the block index meant a transaction the caller
            // had just broadcast could not be looked up until a block took
            // it, and a message saying "unknown or unconfirmed" that gave
            // no way to tell those two apart. A transaction waiting in the
            // pool is a real transaction and is answered as one; only its
            // confirmation count and block hash differ.
            Transaction tx;
            bytes32 blockHash;
            blockHash.fill(0);
            uint32_t height = 0;
            bool confirmed = false;

            if (ctx.chainState->GetTransaction(
                    txid, tx, &blockHash, &height)) {
                confirmed = true;
            } else if (ctx.mempool &&
                       ctx.mempool->GetTransaction(tx, txid)) {
                confirmed = false;
            } else {
                throw RPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    "No such transaction: it is in no block on this "
                    "chain and not in this node's memory pool.");
            }
            if (!verbose) {
                return BytesToHex(tx.Serialize());
            }
            // Confirmations, counted the way every other chain counts
            // them: a transaction in the tip block has one. Zero means it
            // is in the pool and in no block yet. The figure was missing
            // entirely, which is the first thing anyone asks of a payment.
            uint32_t confirmations = 0;
            if (confirmed) {
                const uint32_t tip = ctx.chainState->GetHeight();
                confirmations = (tip >= height) ? (tip - height + 1) : 0;
            }

            json result;
            result["txid"]          = BytesToHex(tx.GetHash());
            result["confirmations"] = confirmations;
            result["inmempool"]     = !confirmed;
            if (confirmed) {
                result["blockhash"] = BytesToHex(blockHash);
                result["height"]    = height;
            } else {
                // Left empty rather than filled with zeros, so nobody reads
                // a hash of all zeros as a block that exists.
                result["blockhash"] = "";
                result["height"]    = nullptr;
            }
            result["coinbase"]  = tx.IsCoinbase();
            result["hex"]       = BytesToHex(tx.Serialize());
            json vin = json::array();
            for (const auto& in : tx.GetInputs()) {
                json j;
                j["prevtxid"]    = BytesToHex(in.GetPrevTxHash());
                j["outputindex"] = in.GetOutputIndex();
                // The anti-quantum shield is what makes an input spendable,
                // so it is shown rather than left to hand-decoding of the
                // raw hex. Nothing here is secret: every field travels in
                // the clear on the wire and is needed to verify the spend.
                j["pubkey"] = BytesToHex(in.GetPubkey());
                j["kps"]    = BytesToHex(in.GetKps());
                const std::vector<uint8_t>& proof = in.GetNoiseProof();
                j["noiseproofsize"] = static_cast<uint64_t>(proof.size());
                j["hasnoiseproof"]  = !proof.empty();

                // The address the coin was held at, spelled out.
                //
                // Everything needed is already in the input - the address
                // is Base58Check over the prefix and SHA256(pubkey || KPS)
                // - but working that out by hand from the hex is not
                // something a reader should have to do to answer "who sent
                // this".
                try {
                    const PublicKey senderKey(in.GetPubkey());
                    j["senderaddress"] = senderKey.ToAddressWithNoise(
                        in.GetKps(), NetParams::PUBKEY_ADDRESS_PREFIX);
                } catch (const std::exception&) {
                    // A malformed key cannot be encoded. The other fields
                    // still describe the input, so the entry is kept rather
                    // than the whole call failing.
                }
                vin.push_back(j);
            }
            result["vin"] = vin;
            json vout = json::array();
            const auto& outs = tx.GetOutputs();
            for (size_t i = 0; i < outs.size(); ++i) {
                json j;
                j["n"]     = static_cast<uint32_t>(i);
                // Base units, and the same figure in MONEU beside it.
                // getbalance answers in MONEU, so a reader comparing the
                // two had to divide by a hundred million in their head.
                j["value"] = outs[i].GetValue();
                j["value_moneu"] = FormatAmount(outs[i].GetValue());
                const Script& script = outs[i].GetScriptPubKey();
                json spk;
                spk["hex"] = BytesToHex(
                    std::vector<uint8_t>(script.begin(), script.end()));
                std::vector<std::vector<uint8_t>> solutions;
                TxoutType type = Solver(script, solutions);
                switch (type) {
                case TxoutType::PUBKEYHASH:
                    spk["type"] = "pubkeyhash";
                    j["pubkeyhash"] = BytesToHex(outs[i].GetPubkeyHash());
                    break;
                case TxoutType::NULL_DATA:
                    spk["type"] = "nulldata";
                    j["data"] = BytesToHex(solutions[0]);
                    break;
                default:
                    spk["type"] = "nonstandard";
                    break;
                }
                j["scriptPubKey"] = spk;
                vout.push_back(j);
            }
            result["vout"] = vout;
            return result;
        }
    ));
}

// Mining commands. The address a mined block pays to is resolved by the
// caller: the configured reward address when one is set and decodable,
// otherwise a fresh wallet address. Either way the coinbase pays to a
// noise-bound hash, SHA256(pubkey || KPS), so the reward is spendable only
// by whoever holds both the private key and the wallet's noise file. The
// shield therefore covers mined coins without the miner doing anything.
void RegisterMiningRPCCommands(RPCTable& table) {
    table.Register(RPCCommand(
        "mining", "getblocktemplate",
        "getblocktemplate \"address\" - Returns a block ready to be hashed "
        "by external mining software",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            // The node assembles the template; the caller only searches for
            // a nonce. Which transactions go in, what the coinbase may pay
            // and how the reveals are ordered are consensus matters, and a
            // node that let the caller decide them would be trusting
            // software on the far end of a socket not to produce a block
            // its own rules reject.
            if (!ctx.miner || !ctx.chainState)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Mining not available");
            if (!req.params.is_array() || req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "reward address required");

            const std::string addr = req.params[0].get<std::string>();
            bytes32 rewardHash;
            std::string why;
            if (!DecodeRewardAddress(addr, rewardHash, why))
                throw RPCError(RPC_INVALID_PARAMS, why);

            // Building a template is not cheap: it reads the mempool,
            // assembles a coinbase and computes two Merkle roots. Repeated
            // in a loop it would keep the node busy producing work nobody
            // is going to mine, so identical requests inside a short window
            // get the same template back.
            //
            // That costs a caller nothing real. A template stays valid
            // until the tip moves or the mempool changes enough to matter,
            // and mining software asks again after either.
            static std::mutex tmplMutex;
            static std::map<std::string, std::pair<int64_t, Block> > tmplCache;
            const int64_t nowSec = static_cast<int64_t>(std::time(NULL));

            Block tmpl;
            bool fromCache = false;
            {
                std::lock_guard<std::mutex> lock(tmplMutex);
                auto it = tmplCache.find(addr);
                if (it != tmplCache.end() &&
                    nowSec - it->second.first < GETBLOCKTEMPLATE_CACHE_SEC &&
                    it->second.second.GetHeader().GetPrevBlockHash() ==
                        ctx.chainState->GetBestBlockHash()) {
                    tmpl = it->second.second;
                    fromCache = true;
                }
            }
            if (!fromCache) {
                tmpl = ctx.miner->BuildBlockTemplate(rewardHash);
                std::lock_guard<std::mutex> lock(tmplMutex);
                // Bound the cache. One entry per reward address is all that
                // is useful, and an unbounded map would be a way to make
                // the node hold memory by asking for many addresses.
                if (tmplCache.size() > 64) tmplCache.clear();
                tmplCache[addr] = std::make_pair(nowSec, tmpl);
            }

            const BlockHeader& hdr = tmpl.GetHeader();

            json result;
            result["height"]            = hdr.GetHeight();
            result["version"]           = hdr.GetVersion();
            result["previousblockhash"] = BytesToHex(hdr.GetPrevBlockHash());
            result["merkleroot"]        = BytesToHex(hdr.GetMerkleRoot());
            result["leafroot"]          = BytesToHex(hdr.GetLeafRoot());
            result["curtime"]           = hdr.GetTimestamp();
            result["bits"]              = BitsToHex(hdr.GetBits());
            result["target"]            = TargetFromBits(hdr.GetBits());
            result["transactions"]      = tmpl.GetTransactionCount();
            result["coinbasevalue"] =
                tmpl.GetTransactions().empty()
                    ? 0
                    : tmpl.GetTransactions()[0].GetValueOut();

            // The whole block, so the caller can hash the header, write the
            // winning nonce into it and hand the result back through
            // submitblock without having to build the serialisation itself.
            const std::vector<uint8_t> blob = tmpl.Serialize();
            result["blocktemplate"] = BytesToHex(blob);

            // Where the nonce sits in that blob, so it can be replaced in
            // place. The header is fixed width, so this offset does not
            // depend on what the block contains.
            result["nonceoffset"] =
                BlockHeader::SERIALIZED_SIZE - 4;
            result["headersize"] = BlockHeader::SERIALIZED_SIZE;

            return result;
        }
    ));

    table.Register(RPCCommand(
        "mining", "submitblock",
        "submitblock \"hexdata\" - Offers a solved block to the network",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.miner)
                throw RPCError(RPC_INTERNAL_ERROR,
                    "Mining not available");
            if (!req.params.is_array() || req.params.empty() ||
                !req.params[0].is_string())
                throw RPCError(RPC_INVALID_PARAMS,
                    "block data required");

            const std::string hex = req.params[0].get<std::string>();

            // Refuse on length before decoding. Decoding first would mean
            // parsing megabytes of whatever arrived only to discard it,
            // which is work an attacker gets for free by repeating the
            // call. The bound is what a legal block can occupy in hex.
            if (hex.size() > static_cast<size_t>(
                    NetParams::MAX_BLOCK_SIZE) * 2) {
                throw RPCError(RPC_INVALID_PARAMS,
                    "Block data is larger than a block may be");
            }
            // Smallest possible block: a header and a coinbase.
            if (hex.size() < BlockHeader::SERIALIZED_SIZE * 2) {
                throw RPCError(RPC_INVALID_PARAMS,
                    "Block data is too short to be a block");
            }

            std::vector<uint8_t> blob;
            if (!HexToBytes(hex, blob) || blob.empty())
                throw RPCError(RPC_INVALID_PARAMS,
                    "Block data is not valid hex");

            Block block;
            try {
                block = Block::Deserialize(blob);
            } catch (const std::exception& e) {
                throw RPCError(RPC_INVALID_PARAMS,
                    std::string("Block could not be read: ") + e.what());
            }

            // Proof of work first, before anything expensive.
            //
            // Full validation walks every transaction against the UTXO set,
            // and a caller repeating the command would get that work for
            // nothing. Checking the header hash costs one hash and cannot
            // be passed without having done the mining, so it is the right
            // gate to put in front.
            const BlockHeader& sh = block.GetHeader();
            if (!PNC::CheckProofOfWork(sh.GetHash(), sh.GetBits())) {
                return json("high-hash");
            }

            // Then the full path, exactly as a block mined locally or
            // received from a peer. Software on the far end of a socket is
            // not a trusted party, so nothing here is taken on faith.
            if (!ctx.miner->SubmitBlock(block)) {
                // A refusal is not an error in the RPC sense - the caller
                // asked a question and got an answer. Bitcoin returns a
                // reason string here for the same reason: an operator whose
                // blocks are being refused needs to know why, not merely
                // that they were.
                return json("rejected");
            }
            return json(nullptr);
        }
    ));

    table.Register(RPCCommand(
        "mining", "getmininginfo",
        "getmininginfo - Returns proof-of-work consensus status",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            json result;
            result["consensus"]  = "PoW";
            result["algorithm"]  = "SHA-256 proof-of-work";
            result["pow"]        = true;
            result["powlimit"]   = NetParams::POW_LIMIT_COMPACT;
            result["retarget_interval"] =
                NetParams::DIFFICULTY_ADJUSTMENT_INTERVAL;
            result["block_time_target"] =
                NetParams::BLOCK_TIME_TARGET;
            if (ctx.chainState) {
                result["height"] =
                    ctx.chainState->GetHeight();
                result["nextbits"] =
                    ctx.chainState->GetNextBits();
                result["bestblockhash"] = BytesToHex(
                    ctx.chainState->GetBestBlockHash());
            }
            if (ctx.miner) {
                uint64_t hashes = 0, blocks = 0; double rate = 0.0;
                ctx.miner->GetStats(hashes, blocks, rate);
                (void)blocks;   // see below
                result["mining"]       = ctx.miner->IsMining();
                // This machine only. Bitcoin has no such field because
                // Bitcoin Core has no built-in miner; we do, and knowing
                // whether the hardware is actually working is useful.
                result["hashespersec"] = rate;
                // The whole network, inferred from the chain: work done by
                // recent blocks over the time they took. Nobody can measure
                // this directly - there is no way to ask other miners what
                // they are running - so it is an estimate, and it is zero
                // until the chain has blocks to infer from.
                if (ctx.chainState) {
                    result["networkhashps"] =
                        ctx.chainState->EstimateNetworkHashPS();
                }
                // No "blocksfound": the counter it came from rose the
                // moment a worker hit a nonce, before the chain had a say.
                // It read as success while the chain sat at height zero
                // refusing every one of them. How many blocks were really
                // accepted is the chain height.
            }
            return result;
        }
    ));

    // startmining "address" [threads] - begin background proof-of-work
    // mining, paying rewards to an explicitly supplied address. The address
    // is mandatory: the node never mines to a configured or implicit
    // address, so starting the miner is always a deliberate operator action
    // with a visible destination.
    table.Register(RPCCommand(
        "mining", "startmining",
        "startmining \"address\" [threads] - Start background proof-of-work "
        "mining, paying rewards to the given address",
        [](const RPCRequest& req,
           const RPCContext& ctx) -> json {
            if (!ctx.miner) {
                throw RPCError(RPC_MISC_ERROR,
                    "Miner not available");
            }
            if (!req.params.is_array() ||
                req.params.empty() ||
                !req.params[0].is_string()) {
                throw RPCError(RPC_INVALID_PARAMS,
                    "address required: startmining \"address\" [threads]");
            }
            std::string addrStr = req.params[0].get<std::string>();
            // Decode and fully validate the reward address: prefix byte,
            // 32-byte hash and Base58Check checksum. A mistyped address must
            // fail loudly here, never silently mine coins into a void.
            uint8_t decoded[37];
            size_t  decodedLen = 37;
            if (addrStr.empty() || addrStr.size() > 64 ||
                !b58tobin(decoded, &decodedLen, addrStr.c_str()) ||
                decodedLen != 37) {
                throw RPCError(RPC_INVALID_PARAMS,
                    "Invalid reward address encoding");
            }
            if (decoded[0] != NetParams::PUBKEY_ADDRESS_PREFIX) {
                throw RPCError(RPC_INVALID_PARAMS,
                    "Reward address has wrong network prefix");
            }
            uint8_t h1[32], h2[32];
            SHA256_CTX sctx;
            sha256_Init(&sctx);
            sha256_Update(&sctx, decoded, 33);
            sha256_Final(&sctx, h1);
            sha256_Init(&sctx);
            sha256_Update(&sctx, h1, 32);
            sha256_Final(&sctx, h2);
            if (std::memcmp(decoded + 33, h2, 4) != 0) {
                throw RPCError(RPC_INVALID_PARAMS,
                    "Invalid reward address checksum");
            }
            bytes32 outputHash;
            std::memcpy(outputHash.data(), decoded + 1, 32);

            int threads = 1;
            if (req.params.is_array() && req.params.size() >= 2 &&
                req.params[1].is_number_integer()) {
                threads = req.params[1].get<int>();
            }
            if (threads < 1) threads = 1;

            if (!ctx.miner->Start(outputHash, threads)) {
                throw RPCError(RPC_MISC_ERROR,
                    "Could not start mining (already mining?)");
            }
            json result;
            result["mining"]  = true;
            result["threads"] = threads;
            result["address"] = addrStr;
            return result;
        }
    ));

    // stopmining - stop background mining.
    table.Register(RPCCommand(
        "mining", "stopmining",
        "stopmining - Stop background proof-of-work mining",
        [](const RPCRequest&,
           const RPCContext& ctx) -> json {
            if (!ctx.miner) {
                throw RPCError(RPC_MISC_ERROR, "Miner not available");
            }
            ctx.miner->Stop();
            json result;
            result["mining"] = false;
            return result;
        }
    ));
}

} // namespace rpc
} // namespace MONEU
