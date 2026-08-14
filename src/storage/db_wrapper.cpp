// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license
// Adapted from Bitcoin Core (MIT)

#include "db_wrapper.h"

#include <leveldb/cache.h>
#include <leveldb/env.h>
#include <leveldb/filter_policy.h>

#include <iostream>
#include <stdexcept>
#include <cstdarg>
#include <algorithm>

#include "../crypto/rand.h"

namespace MONEU {
namespace storage {

class MONEULevelDBLogger : public leveldb::Logger {
public:
    void Logv(const char* format, va_list ap) override {
        char buffer[500];
        for (int iter = 0; iter < 2; iter++) {
            char* base;
            int bufsize;
            if (iter == 0) {
                bufsize = sizeof(buffer);
                base = buffer;
            } else {
                bufsize = 30000;
                base = new char[bufsize];
            }
            char* p = base;
            char* limit = base + bufsize;
            if (p < limit) {
                va_list backup_ap;
                va_copy(backup_ap, ap);
                p += vsnprintf(p, limit - p, format, backup_ap);
                va_end(backup_ap);
            }
            if (p >= limit) {
                if (iter == 0) continue;
                else p = limit - 1;
            }
            if (p == base || p[-1] != '\n') {
                *p++ = '\n';
            }
            base[std::min(bufsize - 1,
                          (int)(p - base))] = '\0';
            std::cerr << "[LevelDB] " << base;
            if (base != buffer) delete[] base;
            break;
        }
    }
};

static void SetMaxOpenFiles(leveldb::Options* options) {
#ifndef WIN32
    if (sizeof(void*) < 8) {
        options->max_open_files = 64;
    }
#endif
}

static leveldb::Options GetOptions(size_t nCacheSize) {
    leveldb::Options options;
    options.block_cache =
        leveldb::NewLRUCache(nCacheSize / 2);
    options.write_buffer_size = nCacheSize / 4;
    options.filter_policy =
        leveldb::NewBloomFilterPolicy(10);
    options.compression = leveldb::kNoCompression;
    options.info_log = new MONEULevelDBLogger();
    if (leveldb::kMajorVersion > 1 ||
        (leveldb::kMajorVersion == 1 &&
         leveldb::kMinorVersion >= 16)) {
        options.paranoid_checks = true;
    }
    SetMaxOpenFiles(&options);
    return options;
}

const std::string DBWrapper::OBFUSCATE_KEY_KEY(
    "\000obfuscate_key", 14);
const unsigned int DBWrapper::OBFUSCATE_KEY_NUM_BYTES = 8;

DBWrapper::DBWrapper(const fs::path& path,
                     size_t nCacheSize,
                     bool fMemory,
                     bool fWipe,
                     bool obfuscate)
    : mEnv(nullptr)
    , mDB(nullptr)
    , mName(path.stem().string())
{
    if (fMemory) {
        throw DBError(
            "In-memory database not supported "
            "in production build");
    }

    mReadOptions.verify_checksums = true;
    mIterOptions.verify_checksums = true;
    mIterOptions.fill_cache       = false;
    mSyncOptions.sync             = true;
    mOptions = GetOptions(nCacheSize);
    mOptions.create_if_missing    = true;

    if (fWipe) {
        std::cerr << "Wiping LevelDB in "
                  << path.string() << "\n";
        leveldb::Status result =
            leveldb::DestroyDB(path.string(),
                               mOptions);
        db_private::HandleError(result);
    }

    try {
        fs::create_directories(path);
    } catch (const fs::filesystem_error& e) {
        throw DBError(
            "Failed to create LevelDB directory: " +
            std::string(e.what()));
    }

    std::cerr << "Opening LevelDB in "
              << path.string() << "\n";

    leveldb::Status status = leveldb::DB::Open(
        mOptions, path.string(), &mDB);
    db_private::HandleError(status);
    std::cerr << "Opened LevelDB successfully: "
              << mName << "\n";

    mObfuscateKey = std::vector<uint8_t>(
        OBFUSCATE_KEY_NUM_BYTES, 0);
    bool key_exists = Read(OBFUSCATE_KEY_KEY,
                           mObfuscateKey);

    if (!key_exists && obfuscate && IsEmpty()) {
        std::vector<uint8_t> new_key =
            CreateObfuscateKey();
        Write(OBFUSCATE_KEY_KEY, new_key);
        mObfuscateKey = new_key;
        std::cerr << "Wrote new obfuscate key for "
                  << mName << "\n";
    }
}

DBWrapper::~DBWrapper() {
    delete mDB;
    mDB = nullptr;
    delete mOptions.filter_policy;
    mOptions.filter_policy = nullptr;
    delete mOptions.info_log;
    mOptions.info_log = nullptr;
    delete mOptions.block_cache;
    mOptions.block_cache = nullptr;
    delete mEnv;
    mEnv = nullptr;
    mOptions.env = nullptr;
}

bool DBWrapper::WriteBatch(DBBatch& batch,
                            bool fSync)
{
    leveldb::Status status = mDB->Write(
        fSync ? mSyncOptions : mWriteOptions,
        &batch.mBatch);
    db_private::HandleError(status);
    return true;
}

size_t DBWrapper::DynamicMemoryUsage() const {
    std::string memory;
    if (!mDB->GetProperty(
            "leveldb.approximate-memory-usage",
            &memory)) {
        return 0;
    }
    return std::stoul(memory);
}

bool DBWrapper::IsEmpty() {
    std::unique_ptr<DBIterator> it(NewIterator());
    it->SeekToFirst();
    return !it->Valid();
}

std::vector<uint8_t>
DBWrapper::CreateObfuscateKey() const
{
    uint8_t buff[OBFUSCATE_KEY_NUM_BYTES];
    random_buffer(buff, OBFUSCATE_KEY_NUM_BYTES);
    return std::vector<uint8_t>(
        &buff[0],
        &buff[OBFUSCATE_KEY_NUM_BYTES]);
}

namespace db_private {

void HandleError(const leveldb::Status& status) {
    if (status.ok()) return;
    const std::string errmsg =
        "Fatal LevelDB error: " +
        status.ToString();
    std::cerr << errmsg << "\n";
    throw DBError(errmsg);
}

const std::vector<uint8_t>& GetObfuscateKey(
    const DBWrapper& w)
{
    return w.mObfuscateKey;
}

} // namespace db_private

} // namespace storage
} // namespace MONEU
