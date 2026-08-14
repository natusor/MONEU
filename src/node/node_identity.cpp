// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "node_identity.h"

#include <fstream>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <string>

extern "C" {
    #include "../crypto/rand.h"
    #include "../crypto/base58.h"
    #include "../crypto/memzero.h"
}

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace MONEU {
namespace node {

namespace fs = boost::filesystem;

static const char* IDENTITY_FILENAME = "node_identity.key";

bool NodeIdentity::ReadSeedFile(const fs::path& file) {
    std::ifstream in(file.string(), std::ios::in);
    if (!in.is_open()) return false;

    std::string b58;
    std::getline(in, b58);
    in.close();

    while (!b58.empty() &&
           (b58.back() == '\n' || b58.back() == '\r' ||
            b58.back() == ' '  || b58.back() == '\t')) {
        b58.pop_back();
    }
    if (b58.empty()) return false;

    uint8_t decoded[32];
    size_t  len = 32;
    if (!b58tobin(decoded, &len, b58.c_str()) || len != 32) {
        std::cerr << "NodeIdentity: stored seed is malformed\n";
        memzero(decoded, sizeof(decoded));
        memzero(&b58[0], b58.size());
        return false;
    }
    std::memcpy(mSeed.data(), decoded, 32);
    mKey = SecretKey::FromSeed(mSeed);
    memzero(decoded, sizeof(decoded));
    memzero(&b58[0], b58.size());
    return true;
}

bool NodeIdentity::WriteSeedFile(const fs::path& file) {
    char   encoded[64];
    size_t len = sizeof(encoded);
    if (!b58enc(encoded, &len, mSeed.data(), 32)) {
        std::cerr << "NodeIdentity: failed to encode seed\n";
        return false;
    }

#ifndef WIN32
    ::unlink(file.string().c_str());
    int fd = ::open(file.string().c_str(),
                    O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        std::cerr << "NodeIdentity: cannot create identity file: "
                  << file.string() << "\n";
        memzero(encoded, sizeof(encoded));
        return false;
    }

    std::string line = std::string(encoded) + "\n";
    memzero(encoded, sizeof(encoded));

    size_t off = 0;
    bool ok = true;
    while (off < line.size()) {
        ssize_t n = ::write(fd, line.data() + off, line.size() - off);
        if (n <= 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        off += static_cast<size_t>(n);
    }
    if (ok && ::fsync(fd) != 0) ok = false;
    if (::close(fd) != 0) ok = false;
    memzero(&line[0], line.size());

    if (!ok) {
        std::cerr << "NodeIdentity: failed to write identity file\n";
        ::unlink(file.string().c_str());
        return false;
    }
#else
    std::ofstream out(file.string(),
                      std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        std::cerr << "NodeIdentity: cannot open identity file for writing: "
                  << file.string() << "\n";
        memzero(encoded, sizeof(encoded));
        return false;
    }
    out << encoded << "\n";
    out.close();
    memzero(encoded, sizeof(encoded));
#endif
    return true;
}

bool NodeIdentity::LoadOrCreate(const fs::path& identityDir) {
    boost::system::error_code ec;
    if (!fs::exists(identityDir)) {
        fs::create_directories(identityDir, ec);
        if (ec) {
            std::cerr << "NodeIdentity: cannot create directory "
                      << identityDir.string() << ": "
                      << ec.message() << "\n";
            return false;
        }
    }

    fs::path file = identityDir / IDENTITY_FILENAME;

    if (fs::exists(file)) {
        if (!ReadSeedFile(file)) {
            std::cerr << "NodeIdentity: failed to read existing identity\n";
            return false;
        }
        mLoaded = true;
        return true;
    }

    random_buffer(mSeed.data(), 32);
    mKey = SecretKey::FromSeed(mSeed);

    if (!WriteSeedFile(file)) {
        return false;
    }

    mLoaded = true;
    return true;
}

} // namespace node
} // namespace MONEU
