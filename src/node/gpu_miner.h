// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_NODE_GPU_MINER_H
#define MONEU_NODE_GPU_MINER_H

#include <cstdint>
#include <string>

namespace MONEU {

class GpuMiner {
public:
    GpuMiner();
    ~GpuMiner();

    GpuMiner(const GpuMiner&) = delete;
    GpuMiner& operator=(const GpuMiner&) = delete;

    bool Init(const std::string& kernelSource, std::string& reasonOut);

    bool Ready() const { return mReady; }

    const std::string& DeviceName() const { return mDeviceName; }

    bool Search(const uint32_t midstate[8],
                const uint32_t block2[16],
                const uint32_t block3[16],
                uint32_t targetTop,
                uint32_t startNonce,
                uint32_t count,
                uint32_t& foundNonce,
                std::string& reasonOut);

private:
    bool        mReady;
    std::string mDeviceName;

    void* mLib;
    void* mContext;
    void* mQueue;
    void* mProgram;
    void* mKernel;
    void* mBufMidstate;
    void* mBufBlock2;
    void* mBufBlock3;
    void* mBufFound;

    bool LoadLibrary(std::string& reasonOut);
    void Release();
};

} // namespace MONEU

#endif
