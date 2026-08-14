// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license
// Adapted from Bitcoin Core (MIT)

#ifndef MONEU_STORAGE_DB_WRAPPER_H
#define MONEU_STORAGE_DB_WRAPPER_H

#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <leveldb/env.h>

#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

namespace MONEU {
namespace storage {

namespace fs = boost::filesystem;

static const size_t DB_WRAPPER_PREALLOC_KEY_SIZE   = 64;
static const size_t DB_WRAPPER_PREALLOC_VALUE_SIZE = 1024;
static const size_t DB_DEFAULT_CACHE_SIZE          = 8 * 1024 * 1024;

class DBError : public std::runtime_error {
public:
    explicit DBError(const std::string& msg) : std::runtime_error(msg) {}
};

class DBWrapper;
class DBBatch;
class DBIterator;

namespace db_private {
    void HandleError(const leveldb::Status& status);
    const std::vector<uint8_t>& GetObfuscateKey(const DBWrapper& w);
}

class DataStream {
private:
    std::vector<uint8_t> mData;
    size_t mReadPos;

public:
    DataStream() : mReadPos(0) {}

    void Clear() {
        mData.clear();
        mReadPos = 0;
    }

    void Reserve(size_t size) {
        mData.reserve(size);
    }

    const char* Data() const {
        return reinterpret_cast<const char*>(mData.data());
    }

    size_t Size() const {
        return mData.size();
    }

    void WriteRaw(const void* data, size_t len) {
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data);
        mData.insert(mData.end(), bytes, bytes + len);
    }

    bool ReadRaw(void* data, size_t len) {
        if (mReadPos + len > mData.size()) return false;
        std::memcpy(data, mData.data() + mReadPos, len);
        mReadPos += len;
        return true;
    }

    void Xor(const std::vector<uint8_t>& key) {
        if (key.empty()) return;
        for (size_t i = 0; i < mData.size(); ++i) {
            mData[i] ^= key[i % key.size()];
        }
    }

    template<typename T>
    DataStream& operator<<(const T& val) {
        WriteRaw(&val, sizeof(T));
        return *this;
    }

    template<typename T>
    DataStream& operator>>(T& val) {
        if (!ReadRaw(&val, sizeof(T))) {
            throw std::runtime_error(
                "DataStream: read past the end of the record");
        }
        return *this;
    }

    DataStream& operator<<(const std::string& str) {
        uint32_t len = static_cast<uint32_t>(str.size());
        WriteRaw(&len, sizeof(len));
        WriteRaw(str.data(), str.size());
        return *this;
    }

    DataStream& operator>>(std::string& str) {
        uint32_t len = 0;
        if (!ReadRaw(&len, sizeof(len))) {
            throw std::runtime_error(
                "DataStream: read past the end of the record");
        }
        if (len > mData.size() - mReadPos) {
            throw std::runtime_error(
                "DataStream: string length exceeds the record");
        }
        str.resize(len);
        ReadRaw(&str[0], len);
        return *this;
    }

    DataStream& operator<<(const std::vector<uint8_t>& vec) {
        uint32_t len = static_cast<uint32_t>(vec.size());
        WriteRaw(&len, sizeof(len));
        if (len > 0) WriteRaw(vec.data(), len);
        return *this;
    }

    DataStream& operator>>(std::vector<uint8_t>& vec) {
        uint32_t len = 0;
        if (!ReadRaw(&len, sizeof(len))) {
            throw std::runtime_error(
                "DataStream: read past the end of the record");
        }
        if (len > mData.size() - mReadPos) {
            throw std::runtime_error(
                "DataStream: vector length exceeds the record");
        }
        vec.resize(len);
        if (len > 0) ReadRaw(vec.data(), len);
        return *this;
    }
};

class DBBatch {
    friend class DBWrapper;
private:
    const DBWrapper& mParent;
    leveldb::WriteBatch mBatch;
    size_t mSizeEstimate;

public:
    explicit DBBatch(const DBWrapper& parent)
        : mParent(parent)
        , mSizeEstimate(0)
    {}

    void Clear() {
        mBatch.Clear();
        mSizeEstimate = 0;
    }

    template<typename K, typename V>
    void Write(const K& key, const V& value) {
        DataStream ssKey;
        ssKey.Reserve(DB_WRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.Data(), ssKey.Size());

        DataStream ssValue;
        ssValue.Reserve(DB_WRAPPER_PREALLOC_VALUE_SIZE);
        ssValue << value;
        ssValue.Xor(db_private::GetObfuscateKey(mParent));
        leveldb::Slice slValue(ssValue.Data(), ssValue.Size());

        mBatch.Put(slKey, slValue);
        mSizeEstimate += 3 +
            (slKey.size() > 127 ? 1 : 0) + slKey.size() +
            (slValue.size() > 127 ? 1 : 0) + slValue.size();
    }

    template<typename K>
    void Erase(const K& key) {
        DataStream ssKey;
        ssKey.Reserve(DB_WRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.Data(), ssKey.Size());
        mBatch.Delete(slKey);
        mSizeEstimate += 2 + (slKey.size() > 127 ? 1 : 0) + slKey.size();
    }

    size_t SizeEstimate() const { return mSizeEstimate; }
};

class DBIterator {
private:
    const DBWrapper& mParent;
    leveldb::Iterator* mIter;

public:
    DBIterator(const DBWrapper& parent, leveldb::Iterator* iter)
        : mParent(parent)
        , mIter(iter)
    {}

    ~DBIterator() {
        delete mIter;
    }

    DBIterator(const DBIterator&) = delete;
    DBIterator& operator=(const DBIterator&) = delete;

    bool Valid() const {
        return mIter->Valid();
    }

    void SeekToFirst() {
        mIter->SeekToFirst();
    }

    template<typename K>
    void Seek(const K& key) {
        DataStream ssKey;
        ssKey.Reserve(DB_WRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.Data(), ssKey.Size());
        mIter->Seek(slKey);
    }

    void Next() {
        mIter->Next();
    }

    template<typename K>
    bool GetKey(K& key) {
        leveldb::Slice slKey = mIter->key();
        if (slKey.size() != sizeof(K)) return false;
        try {
            DataStream ssKey;
            ssKey.WriteRaw(slKey.data(), slKey.size());
            ssKey >> key;
            return true;
        } catch (...) {
            return false;
        }
    }

    std::string GetRawKey() const {
        leveldb::Slice slKey = mIter->key();
        return std::string(slKey.data(), slKey.size());
    }

    template<typename V>
    bool GetValue(V& value) {
        leveldb::Slice slValue = mIter->value();
        try {
            DataStream ssValue;
            ssValue.WriteRaw(slValue.data(), slValue.size());
            ssValue.Xor(db_private::GetObfuscateKey(mParent));
            ssValue >> value;
            return true;
        } catch (...) {
            return false;
        }
    }

    size_t GetValueSize() const {
        return mIter->value().size();
    }
};

class DBWrapper {
    friend const std::vector<uint8_t>& db_private::GetObfuscateKey(const DBWrapper& w);

private:
    leveldb::Env*          mEnv;
    leveldb::Options       mOptions;
    leveldb::ReadOptions   mReadOptions;
    leveldb::ReadOptions   mIterOptions;
    leveldb::WriteOptions  mWriteOptions;
    leveldb::WriteOptions  mSyncOptions;
    leveldb::DB*           mDB;
    std::string            mName;
    std::vector<uint8_t>   mObfuscateKey;

    static const std::string OBFUSCATE_KEY_KEY;
    static const unsigned int OBFUSCATE_KEY_NUM_BYTES;

    std::vector<uint8_t> CreateObfuscateKey() const;

public:
    DBWrapper(const fs::path& path,
              size_t nCacheSize,
              bool fMemory    = false,
              bool fWipe      = false,
              bool obfuscate  = false);

    ~DBWrapper();

    DBWrapper(const DBWrapper&) = delete;
    DBWrapper& operator=(const DBWrapper&) = delete;

    template<typename K, typename V>
    bool Read(const K& key, V& value) const {
        DataStream ssKey;
        ssKey.Reserve(DB_WRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.Data(), ssKey.Size());

        std::string strValue;
        leveldb::Status status = mDB->Get(mReadOptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound()) return false;
            std::cerr << "LevelDB read failure: " << status.ToString() << "\n";
            db_private::HandleError(status);
        }
        try {
            DataStream ssValue;
            ssValue.WriteRaw(strValue.data(), strValue.size());
            ssValue.Xor(mObfuscateKey);
            ssValue >> value;
        } catch (...) {
            return false;
        }
        return true;
    }

    template<typename K, typename V>
    bool Write(const K& key, const V& value, bool fSync = false) {
        DBBatch batch(*this);
        batch.Write(key, value);
        return WriteBatch(batch, fSync);
    }

    template<typename K>
    bool Exists(const K& key) const {
        DataStream ssKey;
        ssKey.Reserve(DB_WRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.Data(), ssKey.Size());

        std::string strValue;
        leveldb::Status status = mDB->Get(mReadOptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound()) return false;
            db_private::HandleError(status);
        }
        return true;
    }

    template<typename K>
    bool Erase(const K& key, bool fSync = false) {
        DBBatch batch(*this);
        batch.Erase(key);
        return WriteBatch(batch, fSync);
    }

    bool WriteBatch(DBBatch& batch, bool fSync = false);

    bool Sync() {
        DBBatch batch(*this);
        return WriteBatch(batch, true);
    }

    bool Flush() { return true; }

    bool IsEmpty();

    size_t DynamicMemoryUsage() const;

    DBIterator* NewIterator() {
        return new DBIterator(*this, mDB->NewIterator(mIterOptions));
    }

    template<typename K>
    size_t EstimateSize(const K& keyBegin, const K& keyEnd) const {
        DataStream ssKey1, ssKey2;
        ssKey1 << keyBegin;
        ssKey2 << keyEnd;
        leveldb::Slice slKey1(ssKey1.Data(), ssKey1.Size());
        leveldb::Slice slKey2(ssKey2.Data(), ssKey2.Size());
        uint64_t size = 0;
        leveldb::Range range(slKey1, slKey2);
        mDB->GetApproximateSizes(&range, 1, &size);
        return static_cast<size_t>(size);
    }

    template<typename K>
    void CompactRange(const K& keyBegin, const K& keyEnd) const {
        DataStream ssKey1, ssKey2;
        ssKey1 << keyBegin;
        ssKey2 << keyEnd;
        leveldb::Slice slKey1(ssKey1.Data(), ssKey1.Size());
        leveldb::Slice slKey2(ssKey2.Data(), ssKey2.Size());
        mDB->CompactRange(&slKey1, &slKey2);
    }
};

} // namespace storage
} // namespace MONEU

#endif // MONEU_STORAGE_DB_WRAPPER_H
