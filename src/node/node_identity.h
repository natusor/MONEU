// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_NODE_IDENTITY_H
#define MONEU_NODE_IDENTITY_H

#include "../primitives/keys.h"
#include <boost/filesystem.hpp>
#include <string>

namespace MONEU {
namespace node {

class NodeIdentity {
public:
    bool LoadOrCreate(const boost::filesystem::path& identityDir);

    const SecretKey& GetKey() const { return mKey; }

    const bytes32& GetSeed() const { return mSeed; }

    PublicKey GetPublicKey() const { return mKey.GetPublicKey(); }

    bool IsLoaded() const { return mLoaded; }

private:
    SecretKey mKey;
    bytes32   mSeed;
    bool      mLoaded = false;

    bool ReadSeedFile(const boost::filesystem::path& file);
    bool WriteSeedFile(const boost::filesystem::path& file);
};

} // namespace node
} // namespace MONEU

#endif // MONEU_NODE_IDENTITY_H
