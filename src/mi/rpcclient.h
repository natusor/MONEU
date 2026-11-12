// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_MI_RPCCLIENT_H
#define MONEU_MI_RPCCLIENT_H

#include <nlohmann/json.hpp>

#include <string>
#include <utility>
#include <vector>

namespace mi {

using json = nlohmann::json;

struct RpcReply {
    enum Kind { OK, RPC_ERROR, TRANSPORT_ERROR };

    Kind        kind;
    json        result;
    int         code;
    std::string message;

    RpcReply() : kind(TRANSPORT_ERROR), code(0) {}

    bool Ok() const { return kind == OK; }

    // The text moneu-cli prints for the same reply.
    std::string ErrorText() const;
};

// JSON-RPC client for the node's control port, reading credentials the
// same way moneu-cli does: moneu.conf first, then the cookie file.
class RpcClient {
public:
    explicit RpcClient(const std::string& dataDir);

    RpcReply Call(const std::string& method,
                  const json& params = json::array(),
                  long timeoutSec = 900);

    std::vector<RpcReply> Batch(
        const std::vector<std::pair<std::string, json> >& calls,
        long timeoutSec = 900);

    bool PortOpen();

    const std::string& DataDir() const { return mDataDir; }

private:
    std::string mDataDir;
    std::string mHost;
    int         mPort;
    std::string mUser;
    std::string mPassword;

    bool LoadCredentials(std::string& errorText);
    bool Post(const std::string& body, long timeoutSec,
              std::string& replyBody, std::string& errorText);
};

} // namespace mi

#endif // MONEU_MI_RPCCLIENT_H
