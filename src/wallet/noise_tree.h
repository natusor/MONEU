// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_WALLET_NOISE_TREE_H
#define MONEU_WALLET_NOISE_TREE_H

#include "../primitives/keys.h"
#include <cstdint>
#include <cstddef>
#include <string>

namespace MONEU {

// Streaming builder for the noise commitment tree.
//
// The in-memory tree builder in noise_otp.cpp copies a whole tree level at a
// time, which is fine for a few thousand leaves but not for the millions of
// leaves in a multi-hundred-megabyte noise file. This builder produces the
// SAME root (the public key of the noise file, "KPS") for the same input,
// but keeps memory use independent of the number of leaves by reducing the
// tree level by level through a scratch file on disk.
//
// It must match noise_otp.cpp exactly, or a proof produced there would not
// verify against a root produced here. The rules it reproduces:
//   leaf_i       = SHA256( chunk_i (32 bytes) || i (4 bytes, little endian) )
//   commitment_i = SHA256( leaf_i )
//   parent       = SHA256( left || right )      (two 32-byte children)
//   an odd node at any level is paired with itself
//   the single remaining node is the root; an empty input yields all-zero.
class NoiseTreeBuilder {
public:
    // Compute the root (KPS) from raw physical-noise bytes, deriving leaves
    // exactly as NoiseFile::Generate does. rawNoise must hold at least
    // leafCount * 32 bytes. scratchDir is a writable directory for the
    // temporary level files; they are removed before returning. Returns true
    // on success and writes the 32-byte root to rootOut. Memory use does not
    // grow with leafCount.
    static bool ComputeRoot(const uint8_t* rawNoise,
                            size_t          rawLen,
                            uint32_t        leafCount,
                            const std::string& scratchDir,
                            bytes32&        rootOut);
};

}

#endif
