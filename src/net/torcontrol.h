// Copyright (c) 2015-2021 The Bitcoin Core developers
// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MONEU_NET_TORCONTROL_H
#define MONEU_NET_TORCONTROL_H

#include "socks5.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace MONEU {
namespace net {

static const char* const DEFAULT_TOR_CONTROL = "127.0.0.1:9051";

struct TorControlOptions {
    std::string control;
    std::string password;
    std::string keyFile;
    uint16_t    virtualPort;
    std::string target;

    TorControlOptions()
        : control(DEFAULT_TOR_CONTROL)
        , virtualPort(0)
    {}
};

struct TorControlCallbacks {
    std::function<void()>                   onAuthenticated;
    std::function<void(const std::string&)> onService;
    std::function<void(const std::string&)> onServiceLost;
};

class TorController {
public:
    TorController(const TorControlOptions& options,
                  const TorControlCallbacks& callbacks);
    ~TorController();

    TorController(const TorController&) = delete;
    TorController& operator=(const TorController&) = delete;

    void Start();
    void Stop();

    std::string GetServiceHost() const;

private:
    TorControlOptions   mOptions;
    TorControlCallbacks mCallbacks;
    std::atomic<bool>   mRunning;
    std::thread         mThread;

    mutable std::mutex      mMutex;
    std::condition_variable mCv;
    std::string             mServiceHost;

    void Run();
    bool Session(SocketHandle fd);
    bool SleepFor(double seconds);
};

std::pair<std::string, std::string> SplitTorReplyLine(const std::string& s);
std::map<std::string, std::string> ParseTorReplyMapping(const std::string& s);

} // namespace net
} // namespace MONEU

#endif // MONEU_NET_TORCONTROL_H
