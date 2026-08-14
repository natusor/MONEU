// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "log.h"

#include <atomic>

#include <fstream>
#include <iostream>
#include <mutex>
#include <ctime>

namespace MONEU {
namespace node {

namespace {

std::mutex    gMutex;
// Atomic so the level can be read without taking the log mutex. The macros
// consult it before building their argument, and taking a global lock to
// answer that question would put every thread in a queue for a message most
// of them are about to discard.
std::atomic<LogLevel> gLevel(LogLevel::INFO);
bool          gToConsole  = true;
bool          gToFile     = false;
bool          gLogIPs     = false;
std::ofstream gFile;
fs::path      gFilePath;
uint64_t      gFileSize   = 0;
uint64_t      gMaxSize    = 10 * 1024 * 1024;

const char* LevelName(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
    }
    return "?????";
}

std::string Timestamp() {
    const std::time_t now = std::time(NULL);
    std::tm tmLocal;
    // UTC, like block timestamps. Nodes in different time zones otherwise
    // produce logs that cannot be lined up without knowing where each one
    // was running.
    gmtime_r(&now, &tmLocal);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tmLocal);
    return std::string(buf);
}

}

void Log::SetLevel(LogLevel level) {
    gLevel.store(level, std::memory_order_relaxed);
}

LogLevel Log::GetLevel() {
    return gLevel.load(std::memory_order_relaxed);
}

void Log::SetConsole(bool enabled) {
    std::lock_guard<std::mutex> lock(gMutex);
    gToConsole = enabled;
}

void Log::SetLogIPs(bool enabled) {
    std::lock_guard<std::mutex> lock(gMutex);
    gLogIPs = enabled;
}

bool Log::LogIPs() {
    std::lock_guard<std::mutex> lock(gMutex);
    return gLogIPs;
}

std::string Log::PeerAddr(const std::string& addr) {
    if (!LogIPs()) return std::string();
    return ", peeraddr=" + addr;
}

bool Log::OpenFile(const fs::path& path, uint64_t maxSize) {
    std::lock_guard<std::mutex> lock(gMutex);
    if (gFile.is_open()) gFile.close();
    gFilePath = path;
    gMaxSize  = maxSize;
    gFile.open(path.string(), std::ios::app);
    if (!gFile.is_open()) {
        gToFile = false;
        return false;
    }
    boost::system::error_code ec;
    const uintmax_t existing = fs::file_size(path, ec);
    gFileSize = ec ? 0 : static_cast<uint64_t>(existing);
    gToFile = true;
    return true;
}

void Log::CloseFile() {
    std::lock_guard<std::mutex> lock(gMutex);
    if (gFile.is_open()) gFile.close();
    gToFile = false;
}

void Log::RotateFile() {
    // Caller holds gMutex.
    if (!gFile.is_open()) return;
    gFile.close();
    const fs::path rotated(gFilePath.string() + ".1");
    boost::system::error_code ec;
    fs::remove(rotated, ec);
    ec.clear();
    fs::rename(gFilePath, rotated, ec);
    if (ec) {
        // The rename failed, so the old file is still there. Zeroing the
        // counter anyway would let it grow past the limit for ever with
        // nothing said about it, which is the silence this class exists to
        // end. The size is re-read instead and the reason recorded.
        gFile.open(gFilePath.string(), std::ios::app);
        if (gFile.is_open()) {
            gFile << "[log] rotation failed: " << ec.message()
                  << " - this file will keep growing\n";
            gFile.flush();
            boost::system::error_code sizeEc;
            const uintmax_t sz = fs::file_size(gFilePath, sizeEc);
            gFileSize = sizeEc ? 0 : static_cast<uint64_t>(sz);
        } else {
            // Nowhere left to write. Say so on the console, which may be
            // all that is left, and stop pretending the file is open.
            gToFile = false;
            std::cerr << "[log] cannot reopen the log file after a failed "
                         "rotation; file logging is off\n";
        }
        return;
    }
    gFile.open(gFilePath.string(), std::ios::app);
    if (!gFile.is_open()) {
        gToFile = false;
        std::cerr << "[log] cannot reopen the log file after rotation; "
                     "file logging is off\n";
        return;
    }
    gFileSize = 0;
}

void Log::Write(LogLevel level, const std::string& msg) {
    std::lock_guard<std::mutex> lock(gMutex);
    if (level < gLevel.load(std::memory_order_relaxed)) return;

    const std::string line =
        "[" + Timestamp() + "] [" + LevelName(level) + "] " + msg + "\n";

    if (gToConsole) {
        if (level >= LogLevel::WARN) std::cerr << line;
        else                          std::cout << line;
    }
    if (gToFile && gFile.is_open()) {
        if (gFileSize >= gMaxSize) RotateFile();
        gFile << line;
        gFile.flush();
        gFileSize += line.size();
    }
}

}
}
