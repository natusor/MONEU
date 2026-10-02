// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <cerrno>
#include <thread>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <random>
#include <functional>
#include <map>
#include <deque>

#ifndef WIN32
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#else
#include <winsock2.h>
#include <windows.h>
#endif

#include <boost/filesystem.hpp>

#include "node/data_dir.h"
#include "node/config.h"
#include "node/wallet_manager.h"
#include "miner.h"
#include "log/log.h"
extern "C" {
#include "crypto/rand.h"
}
#include "storage/chain_state.h"
#include "consensus/mempool.h"
#include "node/node_identity.h"
#include "net/net.h"
#include "net/portmap.h"
#include "rpc/rpc_server.h"
#include "consensus/pow.h"
#include "validation/block_validation.h"
#include "validation/tx_validation.h"
#include "chainparams.h"

namespace fs = boost::filesystem;
using namespace MONEU;

static std::atomic<bool>      gShutdown{false};
static std::mutex              gShutdownMutex;
static std::condition_variable gShutdownCV;

void RequestShutdown() {
    std::lock_guard<std::mutex> lock(gShutdownMutex);
    gShutdown = true;
    gShutdownCV.notify_all();
}

static const size_t MAX_ORPHAN_BLOCKS = 500;

static std::mutex                     gOrphanMutex;
static std::multimap<bytes32, Block>  gOrphanBlocks;
static std::deque<bytes32>            gOrphanOrder;

static void ParkOrphanBlock(const bytes32& parentHash, const Block& block)
{
    std::lock_guard<std::mutex> lock(gOrphanMutex);

    const bytes32 blockHash = block.GetHeader().GetHash();
    auto range = gOrphanBlocks.equal_range(parentHash);
    for (auto it = range.first; it != range.second; ++it) {
        if (it->second.GetHeader().GetHash() == blockHash) return;
    }

    while (gOrphanBlocks.size() >= MAX_ORPHAN_BLOCKS && !gOrphanOrder.empty()) {
        const bytes32 oldestParent = gOrphanOrder.front();
        gOrphanOrder.pop_front();
        auto oldest = gOrphanBlocks.find(oldestParent);
        if (oldest != gOrphanBlocks.end()) {
            gOrphanBlocks.erase(oldest);
        }
    }

    gOrphanBlocks.insert(std::make_pair(parentHash, block));
    gOrphanOrder.push_back(parentHash);
}

static std::vector<Block> TakeOrphansOf(const bytes32& parentHash)
{
    std::lock_guard<std::mutex> lock(gOrphanMutex);
    std::vector<Block> out;
    auto range = gOrphanBlocks.equal_range(parentHash);
    for (auto it = range.first; it != range.second; ++it) {
        out.push_back(it->second);
    }
    gOrphanBlocks.erase(parentHash);
    for (auto it = gOrphanOrder.begin(); it != gOrphanOrder.end(); ) {
        it = (*it == parentHash) ? gOrphanOrder.erase(it) : it + 1;
    }
    return out;
}

static size_t OrphanCount()
{
    std::lock_guard<std::mutex> lock(gOrphanMutex);
    return gOrphanBlocks.size();
}

static bool          gDaemonized   = false;

#ifndef WIN32
static int gStartupPipeWrite = -1;

static void NotifyStartupComplete() {
    if (gStartupPipeWrite < 0) return;
    const char ok = 'K';
    ssize_t written;
    do {
        written = ::write(gStartupPipeWrite, &ok, 1);
    } while (written < 0 && errno == EINTR);
    ::close(gStartupPipeWrite);
    gStartupPipeWrite = -1;
}
#else
static HANDLE gStartupPipeWrite = NULL;

static void NotifyStartupComplete() {
    if (gStartupPipeWrite == NULL) return;
    const char ok = 'K';
    DWORD written = 0;
    ::WriteFile(gStartupPipeWrite, &ok, 1, &written, NULL);
    ::CloseHandle(gStartupPipeWrite);
    gStartupPipeWrite = NULL;
}
#endif

#ifndef WIN32
static bool Daemonize() {
    int startupPipe[2];
    if (::pipe(startupPipe) != 0) {
        std::cerr << "MONEU: cannot create the startup pipe: "
                  << std::strerror(errno) << "\n";
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        ::close(startupPipe[0]);
        ::close(startupPipe[1]);
        std::cerr << "MONEU: cannot fork into the background: "
                  << std::strerror(errno) << "\n";
        return false;
    }
    if (pid > 0) {
        ::close(startupPipe[1]);
        char status = 0;
        ssize_t got;
        do {
            got = ::read(startupPipe[0], &status, 1);
        } while (got < 0 && errno == EINTR);
        ::close(startupPipe[0]);

        if (got == 1 && status == 'K') {
            std::cout << "\n"
                      << "Node process ID is " << pid << "\n"
                      << "The log file is moneu.log inside the logs "
                         "directory of your data directory.\n"
                      << "To stop the node, type the command "
                         "moneu-cli stop\n"
                      << "\n"
                      << "MONEU is running now.\n"
                      << std::flush;
            _exit(0);
        }

        std::cout << "MONEU failed to start. See the messages above.\n"
                  << std::flush;
        _exit(1);
    }

    ::close(startupPipe[0]);
    gStartupPipeWrite = startupPipe[1];

    if (setsid() < 0) {
        std::cerr << "MONEU: setsid failed: "
                  << std::strerror(errno) << "\n";
        return false;
    }

    int devnull = ::open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
        ::dup2(devnull, STDIN_FILENO);
        if (devnull > STDERR_FILENO) ::close(devnull);
    }

    gDaemonized = true;
    return true;
}

static void DetachStandardOutput() {
    std::cout.flush();
    std::cerr.flush();
    int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        ::dup2(devnull, STDOUT_FILENO);
        ::dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) ::close(devnull);
    }
}
#else
static const char* const DAEMON_PIPE_ENV = "MONEU_DAEMON_PIPE";

static bool Daemonize() {
    char envValue[32];
    const DWORD envLen = ::GetEnvironmentVariableA(
        DAEMON_PIPE_ENV, envValue, sizeof(envValue));
    if (envLen > 0 && envLen < sizeof(envValue)) {
        ::SetEnvironmentVariableA(DAEMON_PIPE_ENV, NULL);
        const unsigned long long raw = std::strtoull(envValue, NULL, 10);
        gStartupPipeWrite =
            reinterpret_cast<HANDLE>(static_cast<uintptr_t>(raw));
        if (std::freopen("NUL", "r", stdin) == NULL) {
            std::cerr << "MONEU: cannot detach standard input\n";
        }
        gDaemonized = true;
        return true;
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle       = TRUE;

    HANDLE readEnd  = NULL;
    HANDLE writeEnd = NULL;
    if (!::CreatePipe(&readEnd, &writeEnd, &sa, 0)) {
        std::cerr << "MONEU: cannot create the startup pipe: error "
                  << ::GetLastError() << "\n";
        return false;
    }
    ::SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

    std::vector<wchar_t> exePath(32768, L'\0');
    const DWORD exeLen = ::GetModuleFileNameW(
        NULL, exePath.data(), static_cast<DWORD>(exePath.size()));
    if (exeLen == 0 || exeLen >= exePath.size()) {
        ::CloseHandle(readEnd);
        ::CloseHandle(writeEnd);
        std::cerr << "MONEU: cannot find the node's own executable\n";
        return false;
    }

    const std::wstring commandLine(::GetCommandLineW());
    std::vector<wchar_t> commandBuf(commandLine.begin(), commandLine.end());
    commandBuf.push_back(L'\0');

    char handleText[32];
    std::snprintf(handleText, sizeof(handleText), "%llu",
                  static_cast<unsigned long long>(
                      reinterpret_cast<uintptr_t>(writeEnd)));
    ::SetEnvironmentVariableA(DAEMON_PIPE_ENV, handleText);

    STARTUPINFOW si;
    std::memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    std::memset(&pi, 0, sizeof(pi));

    const BOOL created = ::CreateProcessW(
        exePath.data(), commandBuf.data(), NULL, NULL, TRUE,
        CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi);

    ::SetEnvironmentVariableA(DAEMON_PIPE_ENV, NULL);
    ::CloseHandle(writeEnd);

    if (!created) {
        ::CloseHandle(readEnd);
        std::cerr << "MONEU: cannot fork into the background: error "
                  << ::GetLastError() << "\n";
        return false;
    }
    ::CloseHandle(pi.hThread);

    char status = 0;
    DWORD got = 0;
    const BOOL readOk = ::ReadFile(readEnd, &status, 1, &got, NULL);
    ::CloseHandle(readEnd);

    if (readOk && got == 1 && status == 'K') {
        std::cout << "\n"
                  << "Node process ID is " << pi.dwProcessId << "\n"
                  << "The log file is moneu.log inside the logs "
                     "directory of your data directory.\n"
                  << "To stop the node, type the command "
                     "moneu-cli stop\n"
                  << "\n"
                  << "MONEU is running now.\n"
                  << std::flush;
        ::CloseHandle(pi.hProcess);
        _exit(0);
    }

    ::CloseHandle(pi.hProcess);
    std::cout << "MONEU failed to start. See the messages above.\n"
              << std::flush;
    _exit(1);
}

static void DetachStandardOutput() {
    std::cout.flush();
    std::cerr.flush();
    std::fflush(stdout);
    std::fflush(stderr);
    if (std::freopen("NUL", "w", stdout) == NULL) {
        std::cerr << "MONEU: cannot detach standard output\n";
    }
    if (std::freopen("NUL", "w", stderr) == NULL) {
        return;
    }
    ::FreeConsole();
}
#endif
static bool          gLogToFile    = false;
static bool          gLogToConsole = true;

#define LOG_DEBUG(msg) MONEU_LOG_DEBUG(msg)
#define LOG_INFO(msg)  MONEU_LOG_INFO(msg)
#define LOG_WARN(msg)  MONEU_LOG_WARN(msg)
#define LOG_ERROR(msg) MONEU_LOG_ERROR(msg)

static bool InitLogger(
    const node::DataDir& dataDir,
    const node::LogConfig& cfg)
{
    gLogToConsole = cfg.logToConsole;
    gLogToFile    = cfg.logToFile;

    if (gDaemonized) {
        gLogToConsole = false;
        gLogToFile    = true;
    }

    node::LogLevel level = node::LogLevel::INFO;
    if (cfg.logLevel == "debug")      level = node::LogLevel::DEBUG;
    else if (cfg.logLevel == "warn")  level = node::LogLevel::WARN;
    else if (cfg.logLevel == "error") level = node::LogLevel::ERROR;
    node::Log::SetLevel(level);
    node::Log::SetConsole(gLogToConsole);

    node::Log::SetLogIPs(cfg.logIPs);

    if (gLogToFile) {
        const fs::path logPath = dataDir.GetLogFilePath();
        // cfg.maxLogSize is already in bytes. Multiplying again here turned
        // a 10 MB limit into 10 TB and the file grew without bound.
        if (!node::Log::OpenFile(logPath,
                                 static_cast<uint64_t>(cfg.maxLogSize))) {
            std::cerr << "WARNING: cannot open log file "
                      << logPath.string() << "\n";
        }
    }
    return true;
}

// Bitcoin's rule: the loopback unless the config names both an address to
// bind and the addresses allowed to reach it. One without the other is a
// half-written intention, and the safe half is to stay on the loopback.
static std::string ResolveRPCBindAddress(const node::RPCConfig& rpc) {
    if (!rpc.rpcAllowIpSet) {
        if (rpc.rpcBindSet) {
            LOG_WARN("rpcbind was ignored because rpcallowip is not set; "
                     "the control port stays on 127.0.0.1");
        }
        return "127.0.0.1";
    }
    if (!rpc.rpcBindSet) {
        LOG_WARN("rpcallowip is set without rpcbind; the control port "
                 "stays on 127.0.0.1");
        return "127.0.0.1";
    }
    return rpc.rpcBindAddr;
}

static std::string GenerateRPCCookie() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    std::ostringstream oss;
    for (int i = 0; i < 4; ++i) {
        oss << std::hex << std::setfill('0')
            << std::setw(16) << dist(gen);
    }
    return oss.str();
}

static fs::path GetCookiePath(const fs::path& dataDir) {
    return dataDir / ".rpc.cookie";
}

static void CleanupOldCookie(const fs::path& dataDir) {
    fs::path cookiePath = GetCookiePath(dataDir);
    try {
        if (fs::exists(cookiePath)) {
            fs::remove(cookiePath);
            LOG_INFO("Cleaned up stale cookie file.");
        }
    } catch (...) {}
}

static bool WriteCookieFile(
    const fs::path& dataDir,
    const std::string& cookie)
{
    fs::path cookiePath = GetCookiePath(dataDir);
    std::ofstream f(cookiePath.string(),
        std::ios::out | std::ios::trunc);
    if (!f.is_open()) return false;
    f << "__cookie__:" << cookie;
    f.close();
#ifndef WIN32
    chmod(cookiePath.string().c_str(), 0600);
#endif
    return true;
}

static void RemoveCookieFile(const fs::path& dataDir) {
    try {
        fs::path cookiePath = GetCookiePath(dataDir);
        if (fs::exists(cookiePath))
            fs::remove(cookiePath);
    } catch (...) {}
}

#ifndef WIN32
static bool CheckConfigFilePermissions(
    const fs::path& configPath)
{
    if (!fs::exists(configPath)) return true;
    struct stat st;
    if (stat(configPath.string().c_str(), &st) != 0)
        return true;
    if (st.st_mode & (S_IRGRP | S_IROTH |
                       S_IWGRP | S_IWOTH)) {
        LOG_ERROR(
            "SECURITY: Config file " +
            configPath.string() +
            " is readable by others! "
            "Fix with: chmod 600 " +
            configPath.string());
        return false;
    }
    return true;
}
#endif

static void SignalHandler(int signal) {
    (void)signal;
    gShutdown = true;
}

#ifdef WIN32
static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    (void)ctrlType;
    RequestShutdown();
    Sleep(INFINITE);
    return TRUE;
}
#endif

static void PrintUsage(const char* argv0) {
    std::cout
        << "Usage: " << argv0 << " [options]\n\n"
        << "Options:\n"
        << "  -daemon             Run in the background and return the "
           "shell\n"
#ifdef WIN32
        << "  -datadir=<path>     Data directory (default: %APPDATA%\\MONEU)\n"
#else
        << "  -datadir=<path>     Data directory (default: ~/.moneu)\n"
#endif
        << "  -rpcuser=<user>     RPC username\n"
        << "  -rpcpassword=<pw>   RPC password\n"
        << "  -rpcallowip=<ip>    Allow RPC from IP\n"
        << "  -addnode=<addr>     Add P2P node address\n"
        << "  -mine               Enable proof-of-work mining\n"
        << "  -loglevel=<level>   debug|info|warn|error\n"
        << "  -version            Show version and exit\n"
        << "  -help               Show this help\n\n"
        << "To stop the node:\n"
        << "  moneu-cli stop\n\n"
#ifdef WIN32
        << "Config file: %APPDATA%\\MONEU\\moneu.conf\n"
#else
        << "Config file: ~/.moneu/moneu.conf\n"
#endif
        << "Example moneu.conf:\n"
        << "  rpcuser=alice\n"
        << "  rpcpassword=strongpassword\n\n";
}

static std::string GetArgValue(
    const std::vector<std::string>& args,
    const std::string& key,
    const std::string& defaultVal = "")
{
    const std::string prefix = "-" + key + "=";
    for (const auto& arg : args) {
        if (arg.find(prefix) == 0)
            return arg.substr(prefix.size());
    }
    return defaultVal;
}

static bool HasArg(
    const std::vector<std::string>& args,
    const std::string& key)
{
    const std::string flag  = "-" + key;
    const std::string flag2 = "--" + key;
    for (const auto& arg : args) {
        if (arg == flag || arg == flag2 ||
            arg.find(flag + "=") == 0)
            return true;
    }
    return false;
}

static std::string HashToHex(const bytes32& hash) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : hash)
        oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

class MoneuNode {
public:
    std::unique_ptr<node::DataDir>       dataDir;
    node::Config                         config;
    std::shared_ptr<storage::ChainState> chainState;
    std::shared_ptr<Mempool>             mempool;
    std::unique_ptr<node::NodeIdentity>  nodeIdentity;
    std::shared_ptr<net::ConnManager>    connManager;
    std::unique_ptr<net::PortMapper>     portMapper;
    std::unique_ptr<node::WalletManager> wallet;
    std::unique_ptr<node::Miner>         miner;
    std::unique_ptr<rpc::RPCServer>      rpcServer;
    std::string                          rpcCookie;
    bool                                 initialized;

    MoneuNode() : initialized(false) {}
    ~MoneuNode() { Shutdown(10); }

    MoneuNode(const MoneuNode&) = delete;
    MoneuNode& operator=(const MoneuNode&) = delete;

    bool Shutdown(int timeoutSec = 10) {
        if (!initialized) return true;
        initialized = false;
        LOG_INFO("MoneuNode: shutdown starting...");

        if (miner) {
            miner->Stop();
        }
        if (portMapper) {
            portMapper->Stop();
            portMapper.reset();
        }
        if (connManager) {
            connManager->Interrupt();
        }
        if (rpcServer) {
            rpcServer->Interrupt();
        }

        try {
            if (connManager) {
                if (dataDir) {
                    connManager->SaveAddresses(
                        dataDir->GetDataDir() / "peers.txt");
                }
                connManager->Stop();
                LOG_INFO("P2P stopped.");
                connManager.reset();
            }
        } catch (...) {}

        try {
            if (mempool && dataDir) {
                mempool->Save(dataDir->GetDataDir() / "mempool.dat");
            }
        } catch (const std::exception& e) {
            LOG_WARN(std::string("Could not save the memory pool: ") +
                     e.what());
        } catch (...) {}

        try {
            if (wallet) {
                wallet->Lock();
                LOG_INFO("Wallet locked.");
            }
        } catch (...) {}

        try {
            if (chainState) {
                chainState->Flush();
                LOG_INFO("ChainState flushed.");
                chainState.reset();
            }
        } catch (...) {}

        try {
            if (dataDir) {
                RemoveCookieFile(dataDir->GetDataDir());
            }
        } catch (...) {}

        try {
            if (rpcServer) {
                rpcServer->Stop();
                LOG_INFO("RPC stopped.");
                rpcServer.reset();
            }
        } catch (...) {}

        (void)timeoutSec;
        return true;
    }
};


static bool AcceptToMempool(MoneuNode& node,
                            const Transaction& tx,
                            const std::string& origin)
{
    validation::TxValidationState txState;
    if (!validation::TxValidation::CheckTransaction(tx, txState)) {
        LOG_WARN(origin + ": invalid TX: " + txState.reason);
        return false;
    }

    if (tx.IsCoinbase()) {
        LOG_WARN(origin + ": rejected loose coinbase TX");
        return false;
    }

    uint32_t nextHeight = node.chainState->GetHeight() + 1;
    if (!validation::TxValidation::CheckTransactionWithUTXO(
            tx,
            node.chainState->GetUTXOSet(),
            nextHeight,
            txState)) {
        LOG_WARN(origin + ": TX rejected against UTXO set: " +
            txState.reason);
        return false;
    }
    if (!validation::TxValidation::VerifyTransactionSignatures(
            tx,
            node.chainState->GetUTXOSet(),
            txState)) {
        LOG_WARN(origin + ": TX signature verification failed: " +
            txState.reason);
        return false;
    }

    int64_t totalIn = 0;
    for (const auto& input : tx.GetInputs()) {
        storage::OutPoint outpoint(input.GetPrevTxHash(),
                                   input.GetOutputIndex());
        storage::Coin coin;
        if (!node.chainState->GetUTXOSet().GetCoin(outpoint, coin)) {
            LOG_WARN(origin + ": TX input vanished during fee computation");
            return false;
        }
        totalIn += coin.value;
    }
    const int64_t fee = totalIn - tx.GetValueOut();

    if (!node.mempool->AddTransaction(tx, fee)) return false;

    return true;
}

static void SyncMempoolWithChain(MoneuNode& node)
{
    if (!node.chainState || !node.mempool) return;

    std::vector<Transaction> connected;
    std::vector<Transaction> disconnected;
    node.chainState->TakeMempoolSync(connected, disconnected);

    if (!connected.empty()) {
        node.mempool->RemoveForBlock(connected);

        if (node.wallet) {
            for (size_t i = 0; i < connected.size(); ++i) {
                node.wallet->ReleaseOutpointsFor(connected[i].GetHash());
            }
        }
    }

    if (!disconnected.empty() && node.wallet) {
        for (size_t i = 0; i < disconnected.size(); ++i) {
            node.wallet->ReleaseOutpointsFor(disconnected[i].GetHash());
        }
    }

    for (const auto& tx : disconnected) {
        if (AcceptToMempool(node, tx, "REORG")) {
            LOG_INFO("REORG: resurrected TX into mempool");
        }
    }
}

#ifdef MONEU_SINGLE_EXE
#include "app/cli_exit.h"
#include <io.h>
#include <fcntl.h>

int MoneuCliMain(int argc, char* argv[]);
int MoneuTestMain();

namespace {

std::string AppTempLogPath() {
    char dir[MAX_PATH];
    const DWORD n = ::GetTempPathA(sizeof(dir), dir);
    if (n == 0 || n >= sizeof(dir)) return std::string("moneu-check.log");
    return std::string(dir) + "moneu-check.log";
}

int RunSelfTestQuietly(const std::string& logPath) {
    std::cout.flush();
    std::cerr.flush();
    std::fflush(stdout);
    std::fflush(stderr);
    const int savedOut = ::_dup(1);
    const int savedErr = ::_dup(2);
    const int logFd = ::_open(logPath.c_str(),
                              _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
                              _S_IREAD | _S_IWRITE);
    if (logFd >= 0) {
        ::_dup2(logFd, 1);
        ::_dup2(logFd, 2);
    }
    int result = 1;
    try {
        result = MoneuTestMain();
    } catch (...) {
        result = 1;
    }
    std::cout.flush();
    std::cerr.flush();
    std::fflush(stdout);
    std::fflush(stderr);
    if (logFd >= 0) ::_close(logFd);
    if (savedOut >= 0) { ::_dup2(savedOut, 1); ::_close(savedOut); }
    if (savedErr >= 0) { ::_dup2(savedErr, 2); ::_close(savedErr); }
    return result;
}

bool NodeAnswers() {
    const SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(static_cast<u_short>(rpc::RPC_PORT));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const bool ok = ::connect(sock, reinterpret_cast<sockaddr*>(&addr),
                              sizeof(addr)) == 0;
    ::closesocket(sock);
    return ok;
}

bool StartNodeInBackground(DWORD& pidOut) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle       = TRUE;

    HANDLE readEnd  = NULL;
    HANDLE writeEnd = NULL;
    if (!::CreatePipe(&readEnd, &writeEnd, &sa, 0)) return false;
    ::SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

    std::vector<wchar_t> exePath(32768, L'\0');
    const DWORD exeLen = ::GetModuleFileNameW(
        NULL, exePath.data(), static_cast<DWORD>(exePath.size()));
    if (exeLen == 0 || exeLen >= exePath.size()) {
        ::CloseHandle(readEnd);
        ::CloseHandle(writeEnd);
        return false;
    }

    std::wstring commandLine = L"\"";
    commandLine += exePath.data();
    commandLine += L"\" -daemon";
    std::vector<wchar_t> commandBuf(commandLine.begin(), commandLine.end());
    commandBuf.push_back(L'\0');

    char handleText[32];
    std::snprintf(handleText, sizeof(handleText), "%llu",
                  static_cast<unsigned long long>(
                      reinterpret_cast<uintptr_t>(writeEnd)));
    ::SetEnvironmentVariableA(DAEMON_PIPE_ENV, handleText);

    STARTUPINFOW si;
    std::memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    std::memset(&pi, 0, sizeof(pi));

    const BOOL created = ::CreateProcessW(
        exePath.data(), commandBuf.data(), NULL, NULL, TRUE,
        CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi);

    ::SetEnvironmentVariableA(DAEMON_PIPE_ENV, NULL);
    ::CloseHandle(writeEnd);

    if (!created) {
        ::CloseHandle(readEnd);
        return false;
    }
    ::CloseHandle(pi.hThread);

    char status = 0;
    DWORD got = 0;
    const BOOL readOk = ::ReadFile(readEnd, &status, 1, &got, NULL);
    ::CloseHandle(readEnd);
    ::CloseHandle(pi.hProcess);

    pidOut = pi.dwProcessId;
    return readOk && got == 1 && status == 'K';
}

std::vector<std::string> SplitCommand(const std::string& line) {
    std::vector<std::string> out;
    std::string current;
    bool inQuotes = false;
    bool hasToken = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '"') {
            inQuotes = !inQuotes;
            hasToken = true;
        } else if (!inQuotes && (c == ' ' || c == '\t')) {
            if (hasToken) {
                out.push_back(current);
                current.clear();
                hasToken = false;
            }
        } else {
            current.push_back(c);
            hasToken = true;
        }
    }
    if (hasToken) out.push_back(current);
    return out;
}

void PrintAppHelp() {
    std::cout
        << "\n"
        << "Type a command and press Enter. The commands are the same as\n"
        << "moneu-cli on Linux, without moneu-cli in front:\n"
        << "\n"
        << "  createwallet \"your-password\"\n"
        << "  makenoise \"your-password\"\n"
        << "  walletunlock \"your-password\"\n"
        << "  getnewaddress\n"
        << "  getwalletinfo\n"
        << "  getbalance YOUR-ADDRESS\n"
        << "  startmining YOUR-ADDRESS 2\n"
        << "  getmininginfo\n"
        << "  stopmining\n"
        << "  getblockcount\n"
        << "  help\n"
        << "\n"
        << "  stop      shut the node down\n"
        << "  exit      close this window, the node keeps running\n"
        << "\n";
}

int InteractiveMain() {
    ::SetConsoleTitleA("MONEU");

    WSADATA wsa;
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "error: cannot start Windows sockets\n";
        std::cout << "Press Enter to close." << std::flush;
        std::string ignored;
        std::getline(std::cin, ignored);
        return 1;
    }

    std::cout << "MONEU 0.2.2\n\n";

    std::cout << "Checking this computer... " << std::flush;
    const std::string logPath = AppTempLogPath();
    if (RunSelfTestQuietly(logPath) != 0) {
        std::cout << "FAILED\n\n"
                  << "This computer did not pass the MONEU self test.\n"
                  << "Details: " << logPath << "\n\n"
                  << "Press Enter to close." << std::flush;
        std::string ignored;
        std::getline(std::cin, ignored);
        ::WSACleanup();
        return 1;
    }
    std::cout << "ALL TESTS PASSED\n";

    if (NodeAnswers()) {
        std::cout << "The node is already running.\n";
    } else {
        std::cout << "Starting the node...\n\n" << std::flush;
        DWORD pid = 0;
        if (!StartNodeInBackground(pid)) {
            std::cout << "\nMONEU failed to start. See the messages above.\n\n"
                      << "Press Enter to close." << std::flush;
            std::string ignored;
            std::getline(std::cin, ignored);
            ::WSACleanup();
            return 1;
        }
        std::cout << "\n"
                  << "Node process ID is " << pid << "\n"
                  << "The log file is moneu.log inside the logs "
                     "directory of your data directory.\n"
                  << "\n"
                  << "MONEU is running now.\n";
    }

    PrintAppHelp();

    std::string line;
    while (true) {
        std::cout << "moneu> " << std::flush;
        if (!std::getline(std::cin, line)) break;

        std::vector<std::string> words = SplitCommand(line);
        if (words.empty()) continue;

        if (words[0] == "moneu-cli" || words[0] == "moneu-cli.exe") {
            words.erase(words.begin());
            if (words.empty()) continue;
        }

        if (words[0] == "exit" || words[0] == "quit") break;

        std::vector<std::string> argStore;
        argStore.push_back("moneu-cli");
        argStore.insert(argStore.end(), words.begin(), words.end());
        std::vector<char*> argvCli;
        for (size_t i = 0; i < argStore.size(); ++i) {
            argvCli.push_back(&argStore[i][0]);
        }
        argvCli.push_back(NULL);

        try {
            MoneuCliMain(static_cast<int>(argStore.size()), argvCli.data());
        } catch (const MoneuCliExit&) {
        } catch (const std::exception& e) {
            std::cerr << "error: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "error: the command failed\n";
        }
        std::cout.flush();
        std::cerr.flush();
    }

    ::WSACleanup();
    return 0;
}

}
#endif

int main(int argc, char* argv[]) {
#ifdef WIN32
    ::SetConsoleOutputCP(::GetACP());
#endif
#ifdef MONEU_SINGLE_EXE
    if (argc == 1) return InteractiveMain();
#endif
    std::vector<std::string> args(argv + 1, argv + argc);

    if (HasArg(args, "help") || HasArg(args, "h")) {
        PrintUsage(argv[0]);
        return 0;
    }

    if (HasArg(args, "version") || HasArg(args, "v")) {
        std::cout
            << "MONEU Node v0.2.2\n"
            << "Network:   " << NetParams::NETWORK_ID << "\n"
            << "Consensus: Proof-of-Work (SHA-256)\n"
            << "P2P Port:  " << NetParams::DEFAULT_PORT << "\n"
            << "RPC Port:  " << NetParams::RPC_PORT << "\n";
        return 0;
    }

    if (HasArg(args, "daemon")) {
        if (!Daemonize()) {
            return 1;
        }
    }

    std::signal(SIGINT,  SignalHandler);
    std::signal(SIGTERM, SignalHandler);
#ifndef WIN32
    std::signal(SIGHUP,  SIG_IGN);
    std::signal(SIGPIPE, SIG_IGN);
#else
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
#endif

    MoneuNode node;

    try {
        std::cout << "MONEU Node v0.2.2 starting\n";

        std::string dataDirStr = GetArgValue(args, "datadir", "");
        if (!dataDirStr.empty()) {
            node.dataDir = std::unique_ptr<node::DataDir>(
                new node::DataDir(fs::path(dataDirStr)));
        } else {
            node.dataDir = std::unique_ptr<node::DataDir>(
                new node::DataDir());
        }
        if (!node.dataDir->Initialize()) {
            std::cerr << "FATAL: DataDir init failed\n";
            return 1;
        }

#ifndef WIN32
        if (!CheckConfigFilePermissions(
                node.dataDir->GetConfigFilePath())) {
            std::cerr << "FATAL: Insecure config permissions!\n";
            return 1;
        }
#endif
        if (!node.config.LoadFromDataDir(*node.dataDir)) {
            std::cerr << "FATAL: Config load failed\n";
            return 1;
        }
        node.config.SetDataDir(node.dataDir->GetDataDir());

        std::string rpcUser     = GetArgValue(args, "rpcuser", "");
        std::string rpcPassword = GetArgValue(args, "rpcpassword", "");
        if (!rpcUser.empty())
            node.config.GetRPCMutable().rpcUser = rpcUser;
        if (!rpcPassword.empty())
            node.config.GetRPCMutable().rpcPassword = rpcPassword;

        if (!node.config.GetRPC().rpcUser.empty() &&
            !node.config.GetRPC().rpcPassword.empty()) {
            node.config.GetRPCMutable().rpcEnabled = true;
        }

        std::string logLevelArg = GetArgValue(args, "loglevel", "");
        if (!logLevelArg.empty())
            node.config.GetLogMutable().logLevel = logLevelArg;

        for (const auto& arg : args) {
            if (arg.find("-addnode=") == 0)
                node.config.GetNetworkMutable()
                    .addNodes.push_back(arg.substr(9));
            if (arg.find("-rpcallowip=") == 0)
                node.config.GetRPCMutable()
                    .rpcAllowIp.push_back(arg.substr(12));
        }
        if (HasArg(args, "mine"))
            node.config.GetMiningMutable().enabled = true;

        InitLogger(*node.dataDir, node.config.GetLog());
        CleanupOldCookie(node.dataDir->GetDataDir());

        LOG_INFO("MONEU Node v0.2.2");
        LOG_INFO("Network:   " + std::string(NetParams::NETWORK_ID));
        LOG_INFO("Consensus: Proof-of-Work (SHA-256)");
        LOG_INFO("DataDir:   " + node.dataDir->GetDataDir().string());

        if (random_sanity_check() != 0) {
            LOG_ERROR("FATAL: entropy source failed its sanity check");
            return 1;
        }

        LOG_INFO("[1/6] Initializing chain state...");
        node.chainState = std::make_shared<storage::ChainState>(
            node.dataDir->GetDataDir(),
            node.config.GetStorage().dbCacheSize);
        if (!node.chainState->Initialize()) {
            LOG_ERROR("FATAL: ChainState failed");
            return 1;
        }
        LOG_INFO("ChainState OK: height=" +
            std::to_string(node.chainState->GetHeight()));

        node.nodeIdentity = std::unique_ptr<node::NodeIdentity>(
            new node::NodeIdentity());
        if (!node.nodeIdentity->LoadOrCreate(
                node.dataDir->GetIdentityDir())) {
            LOG_ERROR("FATAL: node identity could not be loaded or created");
            return 1;
        }

        LOG_INFO("[2/6] Starting consensus buffer...");
        node.mempool = std::make_shared<Mempool>();
        LOG_INFO("Mempool OK.");

        LOG_INFO("[3/6] Initializing wallet...");
        node.wallet = std::unique_ptr<node::WalletManager>(
            new node::WalletManager(*node.dataDir));
        if (node.wallet->Exists()) {
            LOG_INFO("Wallet: found, locked - "
                "use: moneu-cli walletunlock <passphrase>. Leaves for any "
                "transaction already held on chain cannot be published "
                "until it is unlocked");
        } else {
            LOG_INFO("Wallet: not found - "
                "use: moneu-cli createwallet <passphrase>");
        }

        LOG_INFO("[4/6] Starting P2P network...");
        net::ConnManagerOptions netOptions;
        netOptions.listenPort    = node.config.GetNetwork().port;
        netOptions.maxConnections= node.config.GetNetwork().maxConnections;
        netOptions.maxOutbound   = node.config.GetNetwork().maxOutbound;
        netOptions.maxInbound    = node.config.GetNetwork().maxInbound;
        netOptions.listen        = node.config.GetNetwork().listen;
        netOptions.seedNodes     = node.config.GetNetwork().seedNodes;
        netOptions.addNodes      = node.config.GetNetwork().addNodes;
        auto bestChain           = node.chainState->GetBestChain();
        netOptions.bestHeight    = bestChain.height;
        netOptions.bestBlockHash = bestChain.blockHash;

        node.connManager = std::make_shared<net::ConnManager>(netOptions);

        net::NetCallbacks netCallbacks;

        netCallbacks.getChainTip = [&](uint32_t& heightOut,
                                       bytes32& tipOut) -> bool {
            if (!node.chainState) return false;
            heightOut = node.chainState->GetHeight();
            tipOut    = node.chainState->GetBestBlockHash();
            return true;
        };

        netCallbacks.getBlockHashesAfter =
            [&](const bytes32& after, size_t max) -> std::vector<bytes32> {
            if (!node.chainState) return std::vector<bytes32>();
            return node.chainState->GetBlockHashesAfter(after, max);
        };

        netCallbacks.haveTx = [&](const bytes32& hash) -> bool {
            return node.mempool && node.mempool->HasTransaction(hash);
        };

        netCallbacks.haveBlock = [&](const bytes32& hash) -> bool {
            if (!node.chainState) return false;
            return node.chainState->HasBlock(hash);
        };

        netCallbacks.getBlockLocator = [&]() -> std::vector<bytes32> {
            if (!node.chainState) return std::vector<bytes32>();
            return node.chainState->GetBlockLocator();
        };

        netCallbacks.getBlockHashesAfterLocator =
            [&](const std::vector<bytes32>& locator,
                size_t max) -> std::vector<bytes32> {
            if (!node.chainState) return std::vector<bytes32>();

            uint32_t forkHeight = 0;
            if (!node.chainState->FindForkPoint(locator, forkHeight)) {
                return std::vector<bytes32>();
            }
            bytes32 forkHash;
            if (!node.chainState->GetBlockHashByHeight(forkHeight,
                                                       forkHash)) {
                return std::vector<bytes32>();
            }
            return node.chainState->GetBlockHashesAfter(forkHash, max);
        };

        netCallbacks.onTransaction = [&](
            net::NodeId id, const Transaction& tx)
        {
            (void)id;

            if (AcceptToMempool(node, tx, "NET")) {
                LOG_DEBUG("NET: TX in mempool");

                if (node.connManager) {
                    node.connManager->BroadcastTransaction(tx);
                }
            }
        };

        netCallbacks.onBlock = [&](
            net::NodeId id, const Block& block)
        {
            const BlockHeader& hdr = block.GetHeader();
            const bytes32 blockHash = hdr.GetHash();

            if (node.chainState->HasBlock(blockHash)) {
                LOG_DEBUG("NET: block already known");
                return;
            }

            const bytes32 prevHash = hdr.GetPrevBlockHash();
            if (!node.chainState->HasBlock(prevHash)) {
                if (block.GetSerializedSize() > NetParams::MAX_BLOCK_SIZE) {
                    LOG_WARN("NET: oversized block from peer=" +
                        std::to_string(id));
                    return;
                }
                if (!PNC::CheckProofOfWork(blockHash, hdr.GetBits())) {
                    LOG_WARN("NET: block from peer=" + std::to_string(id) +
                        " does not meet its own target");
                    return;
                }
                if (hdr.GetHeight() <= node.chainState->GetHeight()) {
                    return;
                }
                ParkOrphanBlock(prevHash, block);
                LOG_DEBUG("NET: block at height " +
                    std::to_string(hdr.GetHeight()) +
                    " is waiting for its parent (" +
                    std::to_string(OrphanCount()) + " parked)");
                if (node.connManager) {
                    node.connManager->RequestBlocksFrom(id);
                }
                return;
            }

            if (!node.chainState->AcceptBlock(block)) {
                LOG_WARN("NET: ConnectBlock rejected block at height " +
                    std::to_string(hdr.GetHeight()) +
                    " (linkage, difficulty, proof-of-work, or state "
                    "mismatch)");
                return;
            }

            LOG_INFO("NET: connected block height=" +
                std::to_string(hdr.GetHeight()) +
                " bits=" + std::to_string(hdr.GetBits()) +
                " hash=" + HashToHex(blockHash).substr(0, 16) + "...");

            if (node.connManager) {
                node.connManager->BroadcastBlock(block);
            }

            std::vector<bytes32> frontier;
            frontier.push_back(blockHash);

            while (!frontier.empty()) {
                const bytes32 parent = frontier.back();
                frontier.pop_back();

                std::vector<Block> waiting = TakeOrphansOf(parent);
                for (size_t i = 0; i < waiting.size(); ++i) {
                    const Block& child = waiting[i];
                    const bytes32 childHash = child.GetHeader().GetHash();

                    if (node.chainState->HasBlock(childHash)) continue;

                    if (!node.chainState->AcceptBlock(child)) {
                        LOG_WARN("NET: parked block at height " +
                            std::to_string(child.GetHeader().GetHeight()) +
                            " still refused after its parent arrived");
                        continue;
                    }

                    LOG_INFO("NET: connected parked block height=" +
                        std::to_string(child.GetHeader().GetHeight()) +
                        " hash=" + HashToHex(childHash).substr(0, 16) + "...");

                    if (node.connManager) {
                        node.connManager->BroadcastBlock(child);
                    }
                    frontier.push_back(childHash);
                }
            }

            if (node.connManager) {
                node.connManager->RequestBlocksFrom(id);
            }

            SyncMempoolWithChain(node);
        };

        netCallbacks.onNodeConnected = [](net::NodeId id) {
            LOG_INFO("NET: connected node=" + std::to_string(id));
        };

        netCallbacks.onNodeDisconnected = [](net::NodeId id) {
            LOG_INFO("NET: disconnected node=" + std::to_string(id));
        };

        netCallbacks.onGetData = [&](net::NodeId id,
                                     const std::vector<net::InvItem>& items) {
            for (auto& item : items) {
                if (item.type == net::InvType::BLOCK) {
                    Block block;
                    if (node.chainState->GetBlock(block, item.hash)) {
                        node.connManager->SendMessageToNode(
                            id,
                            net::NetMessage(net::MsgType::BLOCK,
                                            block.Serialize()));
                    }
                } else if (item.type == net::InvType::TX) {
                    Transaction tx;
                    if (node.mempool->GetTransaction(tx, item.hash)) {
                        node.connManager->SendMessageToNode(
                            id,
                            net::NetMessage(net::MsgType::TX,
                                            tx.Serialize()));
                    }
                }
            }
        };

        node.connManager->LoadAddresses(
            node.dataDir->GetDataDir() / "peers.txt");
        size_t seeded = node.connManager->BootstrapFromSeeds();
        LOG_INFO("Peer discovery: " + std::to_string(seeded) +
                 " seed addresses available");

        {
            const std::string& ext = node.config.GetNetwork().externalIp;
            if (!ext.empty()) {
                node.connManager->SetExternalAddress(
                    ext, node.config.GetNetwork().port);
                LOG_INFO("Announcing self as " + ext + ":" +
                         std::to_string(node.config.GetNetwork().port));
            } else {
                LOG_INFO("No 'externalip' set: this node will announce "
                         "whichever of its own interface addresses each "
                         "peer can reach");
            }
        }

        if (!node.connManager->Start(netCallbacks)) {
            LOG_ERROR("FATAL: P2P start failed");
            return 1;
        }
        LOG_INFO("P2P OK: port=" +
            std::to_string(netOptions.listenPort));

        // A node behind a home router takes no incoming connections unless
        // the router forwards the port. Asking it costs one short exchange
        // and the node carries on either way.
        if (node.config.GetNetwork().listen &&
            node.config.GetNetwork().portMap) {
            node.portMapper = std::unique_ptr<net::PortMapper>(
                new net::PortMapper());
            node.portMapper->Start(netOptions.listenPort);
        } else if (node.config.GetNetwork().listen) {
            LOG_INFO("Port mapping is off. Other nodes reach this one only "
                     "if the port is already forwarded.");
        }

        LOG_INFO("[5/6] Starting RPC server...");
        bool useCookieAuth = false;

        if (node.config.GetRPC().rpcEnabled) {
            node.rpcServer = std::unique_ptr<rpc::RPCServer>(
                new rpc::RPCServer(node.config.GetRPC().rpcPort));

            node.miner = std::unique_ptr<node::Miner>(
                new node::Miner(node.chainState.get(),
                                node.mempool.get(),
                                node.connManager.get()));
            node.miner->SetChainSyncCallback([&node]() {
                SyncMempoolWithChain(node);
            });

            rpc::RPCContext rpcContext;
            rpcContext.chainState     = node.chainState.get();
            rpcContext.mempool        = node.mempool.get();
            rpcContext.connManager    = node.connManager.get();
            rpcContext.config         = &node.config;
            rpcContext.wallet         = node.wallet.get();
            rpcContext.miner          = node.miner.get();

            std::vector<std::string> allowedIPs =
                node.config.GetRPC().rpcAllowIp;
            if (allowedIPs.empty())
                allowedIPs.push_back("127.0.0.1");

            node.rpcServer->SetWarmupStatus("Initializing...");
            if (!node.rpcServer->Start(
                    rpcContext,
                    node.config.GetRPC().rpcUser,
                    node.config.GetRPC().rpcPassword,
                    allowedIPs,
                    ResolveRPCBindAddress(node.config.GetRPC()))) {
                LOG_ERROR("FATAL: RPC start failed");
                return 1;
            }
            LOG_INFO("RPC OK: port=" +
                std::to_string(node.config.GetRPC().rpcPort));

        } else {
            std::string cookie = GenerateRPCCookie();
            node.config.GetRPCMutable().rpcUser     = "__cookie__";
            node.config.GetRPCMutable().rpcPassword = cookie;
            node.config.GetRPCMutable().rpcEnabled  = true;

            if (WriteCookieFile(node.dataDir->GetDataDir(), cookie)) {
                useCookieAuth = true;
#ifdef WIN32
                LOG_INFO("RPC: cookie auth - "
                    "moneu-cli reads %APPDATA%\\MONEU\\.rpc.cookie");
#else
                LOG_INFO("RPC: cookie auth - "
                    "moneu-cli reads ~/.moneu/.rpc.cookie");
#endif
            }

            node.rpcServer = std::unique_ptr<rpc::RPCServer>(
                new rpc::RPCServer(node.config.GetRPC().rpcPort));

            node.miner = std::unique_ptr<node::Miner>(
                new node::Miner(node.chainState.get(),
                                node.mempool.get(),
                                node.connManager.get()));
            node.miner->SetChainSyncCallback([&node]() {
                SyncMempoolWithChain(node);
            });

            rpc::RPCContext rpcContext;
            rpcContext.chainState     = node.chainState.get();
            rpcContext.mempool        = node.mempool.get();
            rpcContext.connManager    = node.connManager.get();
            rpcContext.config         = &node.config;
            rpcContext.wallet         = node.wallet.get();
            rpcContext.miner          = node.miner.get();

            std::vector<std::string> allowedIPs = {"127.0.0.1"};

            node.rpcServer->SetWarmupStatus("Initializing...");
            if (!node.rpcServer->Start(
                    rpcContext, "__cookie__", cookie, allowedIPs,
                    "127.0.0.1")) {
                LOG_ERROR("FATAL: RPC start failed");
                return 1;
            }
            LOG_INFO("RPC OK: port=" +
                std::to_string(node.config.GetRPC().rpcPort));
        }

        if (node.mempool && node.dataDir) {
            const fs::path poolPath =
                node.dataDir->GetDataDir() / "mempool.dat";

            struct Ctx { MoneuNode* node; } ctx;
            ctx.node = &node;

            Mempool::AdmitFn admit =
                [](const Transaction& tx, int64_t& feeOut,
                   void* context) -> bool {
                    Ctx* c = static_cast<Ctx*>(context);
                    feeOut = 0;
                    return AcceptToMempool(*c->node, tx, "POOL");
                };

            Mempool::DroppedFn dropped =
                [](const Transaction& tx, void* context) {
                    Ctx* c = static_cast<Ctx*>(context);
                    if (c->node->wallet) {
                        c->node->wallet->ReleaseOutpointsFor(tx.GetHash());
                    }
                };

            const size_t restored = node.mempool->Load(
                poolPath, static_cast<int64_t>(std::time(NULL)),
                admit, dropped, &ctx);
            if (restored > 0) {
                LOG_INFO("Memory pool: " + std::to_string(restored) +
                         " transaction(s) restored from the last run");
            }
        }

        LOG_INFO("[6/6] Node ready.");
        if (node.rpcServer) {
            node.rpcServer->SetWarmupStatus("Loading chain index...");
            std::this_thread::sleep_for(
                std::chrono::milliseconds(200));
            node.rpcServer->SetWarmupFinished();
        }

        node.initialized = true;

        LOG_INFO("========================================");
        LOG_INFO("MONEU Node READY");
        LOG_INFO("Consensus : Proof-of-Work (SHA-256)");
        LOG_INFO("P2P port  : " +
            std::to_string(netOptions.listenPort));
        LOG_INFO("RPC port  : " +
            std::to_string(node.config.GetRPC().rpcPort));
        if (useCookieAuth)
#ifdef WIN32
            LOG_INFO("RPC auth  : %APPDATA%\\MONEU\\.rpc.cookie");
#else
            LOG_INFO("RPC auth  : ~/.moneu/.rpc.cookie");
#endif
        else
            LOG_INFO("RPC user  : " +
                node.config.GetRPC().rpcUser);
        LOG_INFO("Wallet    : " +
            std::string(node.wallet->Exists() ? "found" : "not found"));
        LOG_INFO("Height    : " +
            std::to_string(node.chainState->GetHeight()));
        LOG_INFO("Identity  : " +
            node.nodeIdentity->GetPublicKey().ToHex().substr(0, 16) + "...");
        LOG_INFO("Mining    : idle (use: moneu-cli startmining <address> [threads])");
        LOG_INFO("To stop   : moneu-cli stop, or Ctrl+C");
        LOG_INFO("========================================");

        if (gDaemonized) {
            NotifyStartupComplete();
            DetachStandardOutput();
        }

        auto chainSyncInterval = std::chrono::seconds(5);
        auto lastSync = std::chrono::steady_clock::now();

        while (!gShutdown) {
            std::unique_lock<std::mutex> lock(gShutdownMutex);
            gShutdownCV.wait_for(
                lock,
                std::chrono::milliseconds(500),
                []{ return gShutdown.load(); });

            if (gShutdown) break;

            auto now = std::chrono::steady_clock::now();
            if (now - lastSync >= chainSyncInterval) {
                node.connManager->UpdateBestChain(
                    node.chainState->GetHeight(),
                    0,
                    node.chainState->GetBestBlockHash());
                lastSync = now;
                LOG_DEBUG(
                    "height=" +
                    std::to_string(node.chainState->GetHeight()) +
                    " peers=" +
                    std::to_string(node.connManager->GetNodeCount()));
            }
        }

        LOG_INFO("Shutdown requested.");
        node.Shutdown(10);
        LOG_INFO("MONEU: shutdown complete.");

        node::Log::CloseFile();
        return 0;

    } catch (const node::DataDirError& e) {
        LOG_ERROR("FATAL DataDir: " + std::string(e.what()));
        node.Shutdown(5);
        return 1;
    } catch (const node::ConfigError& e) {
        LOG_ERROR("FATAL Config: " + std::string(e.what()));
        node.Shutdown(5);
        return 1;
    } catch (const storage::DBError& e) {
        LOG_ERROR("FATAL DB: " + std::string(e.what()));
        node.Shutdown(5);
        return 1;
    } catch (const std::exception& e) {
        LOG_ERROR("FATAL: " + std::string(e.what()));
        node.Shutdown(5);
        return 1;
    } catch (...) {
        LOG_ERROR("FATAL: unknown error");
        node.Shutdown(5);
        return 1;
    }
}
