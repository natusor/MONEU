// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "data_dir.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <stdexcept>

#ifdef WIN32
#include <shlobj.h>
#else
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

namespace MONEU {
namespace node {

static int gLockFd = -1;

fs::path DataDir::GetDefaultDataDir() {
#ifdef WIN32
    char path[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path) == S_OK) {
        return fs::path(path) / "MONEU";
    }
    return fs::path("C:\\MONEU");
#else
    const char* home = getenv("HOME");
    if (home && strlen(home) > 0) {
        return fs::path(home) / ".moneu";
    }
    return fs::path("/var/lib/moneu");
#endif
}

DataDir::DataDir()
    : mInitialized(false)
{
    mDataDir = GetDefaultDataDir();
}

DataDir::DataDir(const fs::path& customPath)
    : mInitialized(false)
{
    if (customPath.empty()) {
        mDataDir = GetDefaultDataDir();
    } else {
        mDataDir = customPath;
    }
}

DataDir::~DataDir() {
    UnlockDataDir();
}

void DataDir::CreateSubDirectories() {
    mBlocksDir     = mDataDir / "blocks";
    mChainstateDir = mDataDir / "chainstate";
    mIdentityDir   = mDataDir / "identity";

    mWalletDir     = mDataDir / "wallet";
    mLogDir        = mDataDir / "logs";

    std::vector<fs::path> dirs = {
        mDataDir,
        mBlocksDir,
        mBlocksDir / "index",
        mChainstateDir,
        mIdentityDir,
        mWalletDir,
        mLogDir
    };

    for (const auto& dir : dirs) {
        try {
            if (!fs::exists(dir)) {
                fs::create_directories(dir);
                std::cerr << "DataDir: created " << dir.string() << "\n";
            }
        } catch (const fs::filesystem_error& e) {
            throw DataDirError("Failed to create directory " +
                               dir.string() + ": " + e.what());
        }
    }

#ifndef WIN32
    const fs::path secretDirs[] = {
        mWalletDir,
        mIdentityDir,
    };
    for (const auto& dir : secretDirs) {
        if (::chmod(dir.string().c_str(), 0700) != 0) {
            std::cerr << "DataDir: warning, cannot restrict permissions on "
                      << dir.string() << "\n";
        }
    }
#endif
}

bool DataDir::CheckDiskSpace(uint64_t requiredBytes) const {
#ifndef WIN32
    struct statvfs stat;
    if (statvfs(mDataDir.string().c_str(), &stat) != 0) {
        std::cerr << "DataDir: cannot check disk space\n";
        return true;
    }
    uint64_t available = static_cast<uint64_t>(stat.f_bavail) *
                         static_cast<uint64_t>(stat.f_frsize);
    if (available < requiredBytes) {
        std::cerr << "DataDir: insufficient disk space! "
                  << "Available: " << available / (1024 * 1024) << " MB, "
                  << "Required: " << requiredBytes / (1024 * 1024) << " MB\n";
        return false;
    }
    return true;
#else
    return true;
#endif
}

bool DataDir::LockDataDir() {
#ifndef WIN32
    fs::path lockFile = GetLockFilePath();
    gLockFd = open(lockFile.string().c_str(),
                   O_CREAT | O_RDWR,
                   0600);
    if (gLockFd == -1) {
        std::cerr << "DataDir: cannot open lock file "
                  << lockFile.string() << "\n";
        return false;
    }
    struct flock fl;
    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    if (fcntl(gLockFd, F_SETLK, &fl) == -1) {
        close(gLockFd);
        gLockFd = -1;
        std::cerr << "DataDir: cannot lock " << lockFile.string()
                  << " - another instance may be running!\n";
        return false;
    }
    return true;
#else
    return true;
#endif
}

void DataDir::UnlockDataDir() {
#ifndef WIN32
    if (gLockFd != -1) {
        close(gLockFd);
        gLockFd = -1;
        try {
            fs::remove(GetLockFilePath());
        } catch (...) {}
    }
#endif
}

bool DataDir::Initialize() {
    if (mInitialized) return true;
    std::cerr << "DataDir: initializing at " << mDataDir.string() << "\n";
    CreateSubDirectories();
    if (!CheckDiskSpace(MIN_REQUIRED_DISK_SPACE)) {
        throw DataDirError("Insufficient disk space in " + mDataDir.string());
    }
    if (!LockDataDir()) {
        throw DataDirError("Cannot lock data directory " + mDataDir.string() +
                           " - is another MONEU instance running?");
    }
    mInitialized = true;
    std::cerr << "DataDir: initialized successfully\n";
    std::cerr << "DataDir: blocks    -> " << mBlocksDir.string()     << "\n";
    std::cerr << "DataDir: chainstate-> " << mChainstateDir.string() << "\n";
    std::cerr << "DataDir: identity -> " << mIdentityDir.string()  << "\n";
    std::cerr << "DataDir: wallet    -> " << mWalletDir.string()     << "\n";
    std::cerr << "DataDir: logs      -> " << mLogDir.string()        << "\n";
    return true;
}

bool DataDir::IsWritable() const {
    if (!mInitialized) return false;
    fs::path testFile = mDataDir / ".write_test";
    try {
        std::ofstream f(testFile.string());
        if (!f.is_open()) return false;
        f << "test";
        f.close();
        fs::remove(testFile);
        return true;
    } catch (...) {
        return false;
    }
}

uint64_t DataDir::GetFreeDiskSpace() const {
#ifndef WIN32
    struct statvfs stat;
    if (statvfs(mDataDir.string().c_str(), &stat) != 0) return 0;
    return static_cast<uint64_t>(stat.f_bavail) *
           static_cast<uint64_t>(stat.f_frsize);
#else
    return 0;
#endif
}

fs::path DataDir::GetConfigFilePath() const {
    return mDataDir / "moneu.conf";
}

fs::path DataDir::GetWalletFilePath() const {
    return mWalletDir / "wallet.dat";
}

fs::path DataDir::GetLogFilePath() const {
    return mLogDir / "moneu.log";
}

fs::path DataDir::GetLockFilePath() const {
    return mDataDir / ".moneu.lock";
}

bool DataDir::Exists(const fs::path& path) {
    return fs::exists(path);
}

bool DataDir::CreateDir(const fs::path& path) {
    try {
        return fs::create_directories(path);
    } catch (...) {
        return false;
    }
}

} // namespace node
} // namespace MONEU
