// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_NODE_DATA_DIR_H
#define MONEU_NODE_DATA_DIR_H

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

#include <boost/filesystem.hpp>

namespace MONEU {
namespace node {

namespace fs = boost::filesystem;

class DataDirError : public std::runtime_error {
public:
    explicit DataDirError(const std::string& msg)
        : std::runtime_error(msg) {}
};

class DataDir {
private:
    fs::path mDataDir;
    fs::path mBlocksDir;
    fs::path mChainstateDir;
    fs::path mIdentityDir;
    fs::path mWalletDir;
    fs::path mLogDir;
    bool     mInitialized;

    static fs::path GetDefaultDataDir();
    void CreateSubDirectories();
    bool CheckDiskSpace(uint64_t requiredBytes) const;
    bool LockDataDir();
    void UnlockDataDir();

public:
    static const uint64_t MIN_REQUIRED_DISK_SPACE = 1024 * 1024 * 1024;

    DataDir();
    explicit DataDir(const fs::path& customPath);
    ~DataDir();

    DataDir(const DataDir&) = delete;
    DataDir& operator=(const DataDir&) = delete;

    bool Initialize();
    bool IsInitialized() const { return mInitialized; }

    const fs::path& GetDataDir()       const { return mDataDir; }
    const fs::path& GetBlocksDir()     const { return mBlocksDir; }
    const fs::path& GetChainstateDir() const { return mChainstateDir; }
    const fs::path& GetIdentityDir()   const { return mIdentityDir; }
    const fs::path& GetWalletDir()     const { return mWalletDir; }
    const fs::path& GetLogDir()        const { return mLogDir; }

    bool IsWritable() const;
    uint64_t GetFreeDiskSpace() const;

    fs::path GetConfigFilePath()  const;
    fs::path GetWalletFilePath()  const;
    fs::path GetLogFilePath()     const;
    fs::path GetLockFilePath()    const;

    static bool Exists(const fs::path& path);
    static bool CreateDir(const fs::path& path);
};

} // namespace node
} // namespace MONEU

#endif // MONEU_NODE_DATA_DIR_H
