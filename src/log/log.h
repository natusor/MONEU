// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_LOG_H
#define MONEU_LOG_H

#include <string>
#include <cstdint>
#include <boost/filesystem.hpp>

namespace MONEU {
namespace node {

namespace fs = boost::filesystem;

enum class LogLevel {
    DEBUG = 0,
    INFO  = 1,
    WARN  = 2,
    ERROR = 3
};

// Logging lives here rather than in main.cpp so every layer can reach it.
//
// It used to be a set of macros private to main.cpp, which meant the miner,
// the network layer and the chain state had nothing to call and wrote to
// std::cerr instead. In daemon mode that output goes nowhere, so a node
// could mine a block, have the chain refuse it, and leave no trace at all
// of either event. That is not a hypothetical - it happened, and finding
// out why took reading the source rather than reading a log.
class Log {
public:
    static void SetLevel(LogLevel level);
    static LogLevel GetLevel();

    static void SetConsole(bool enabled);
    static bool OpenFile(const fs::path& path, uint64_t maxSize);
    static void CloseFile();

    // Whether peer addresses may appear in the log.
    //
    // Off by default, as in Bitcoin. A log is the file someone attaches to
    // a bug report, and it should not carry the list of everyone this node
    // talks to. Addresses stay available through getpeerinfo, where the
    // person asking has already authenticated.
    static void SetLogIPs(bool enabled);
    static bool LogIPs();

    // Returns addr when addresses may be logged, and an empty string
    // otherwise, so a call site can write:
    //     "peer=" + id + PeerAddr(addr)
    // and get ", peeraddr=1.2.3.4:8327" or nothing.
    static std::string PeerAddr(const std::string& addr);

    static void Write(LogLevel level, const std::string& msg);

private:
    static void RotateFile();
};

}
}

// Short forms. Available anywhere that includes this header.
// The level is checked before the argument is built.
//
// msg is a function argument, so it used to be concatenated in full and
// then thrown away inside Write() - after taking the global log mutex. At
// DEBUG level in the network layer that is a string built and discarded for
// every message from every peer.
#define MONEU_LOG_DEBUG(msg) \
    do { \
        if (MONEU::node::Log::GetLevel() <= MONEU::node::LogLevel::DEBUG) { \
            MONEU::node::Log::Write(MONEU::node::LogLevel::DEBUG, msg); \
        } \
    } while (0)
#define MONEU_LOG_INFO(msg)  \
    MONEU::node::Log::Write(MONEU::node::LogLevel::INFO,  msg)
#define MONEU_LOG_WARN(msg)  \
    MONEU::node::Log::Write(MONEU::node::LogLevel::WARN,  msg)
#define MONEU_LOG_ERROR(msg) \
    MONEU::node::Log::Write(MONEU::node::LogLevel::ERROR, msg)

#endif
