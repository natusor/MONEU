// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "gpu_miner.h"

#ifdef WIN32
#include <windows.h>

#undef LoadLibrary

namespace {
const int RTLD_NOW   = 0;
const int RTLD_LOCAL = 0;

void* dlopen(const char* name, int) {
    return reinterpret_cast<void*>(::LoadLibraryA(name));
}
void* dlsym(void* lib, const char* name) {
    return reinterpret_cast<void*>(
        ::GetProcAddress(reinterpret_cast<HMODULE>(lib), name));
}
int dlclose(void* lib) {
    return ::FreeLibrary(reinterpret_cast<HMODULE>(lib)) ? 0 : 1;
}
} // namespace
#else
#include <dlfcn.h>
#endif
#include <cstddef>
#include <cstdint>
#include <vector>

namespace MONEU {

namespace {

typedef int32_t  cl_int;
typedef uint32_t cl_uint;
typedef uint64_t cl_ulong;
typedef void*    cl_handle;

const cl_int   CL_OK               = 0;
const cl_ulong CL_DEV_TYPE_GPU     = (1u << 2);
const cl_ulong CL_DEV_TYPE_ALL     = 0xFFFFFFFFu;
const cl_uint  CL_DEV_NAME         = 0x102B;
const cl_uint  CL_PROG_BUILD_LOG   = 0x1183;
const cl_ulong CL_MEM_RW           = (1u << 0);
const cl_ulong CL_MEM_RO           = (1u << 2);
const cl_uint  CL_BLOCKING         = 1;

typedef cl_int    (*FnGetPlatformIDs)(cl_uint, cl_handle*, cl_uint*);
typedef cl_int    (*FnGetDeviceIDs)(cl_handle, cl_ulong, cl_uint, cl_handle*, cl_uint*);
typedef cl_int    (*FnGetDeviceInfo)(cl_handle, cl_uint, size_t, void*, size_t*);
typedef cl_handle (*FnCreateContext)(const intptr_t*, cl_uint, const cl_handle*,
                                     void (*)(const char*, const void*, size_t, void*),
                                     void*, cl_int*);
typedef cl_handle (*FnCreateCommandQueue)(cl_handle, cl_handle, cl_ulong, cl_int*);
typedef cl_handle (*FnCreateProgramWithSource)(cl_handle, cl_uint, const char**,
                                               const size_t*, cl_int*);
typedef cl_int    (*FnBuildProgram)(cl_handle, cl_uint, const cl_handle*, const char*,
                                    void (*)(cl_handle, void*), void*);
typedef cl_int    (*FnGetProgramBuildInfo)(cl_handle, cl_handle, cl_uint, size_t,
                                           void*, size_t*);
typedef cl_handle (*FnCreateKernel)(cl_handle, const char*, cl_int*);
typedef cl_handle (*FnCreateBuffer)(cl_handle, cl_ulong, size_t, void*, cl_int*);
typedef cl_int    (*FnRelease)(cl_handle);
typedef cl_int    (*FnEnqueueWriteBuffer)(cl_handle, cl_handle, cl_uint, size_t, size_t,
                                          const void*, cl_uint, const cl_handle*,
                                          cl_handle*);
typedef cl_int    (*FnSetKernelArg)(cl_handle, cl_uint, size_t, const void*);
typedef cl_int    (*FnEnqueueNDRangeKernel)(cl_handle, cl_handle, cl_uint, const size_t*,
                                            const size_t*, const size_t*, cl_uint,
                                            const cl_handle*, cl_handle*);
typedef cl_int    (*FnFinish)(cl_handle);
typedef cl_int    (*FnEnqueueReadBuffer)(cl_handle, cl_handle, cl_uint, size_t, size_t,
                                         void*, cl_uint, const cl_handle*, cl_handle*);

struct ClApi {
    FnGetPlatformIDs          GetPlatformIDs;
    FnGetDeviceIDs            GetDeviceIDs;
    FnGetDeviceInfo           GetDeviceInfo;
    FnCreateContext           CreateContext;
    FnCreateCommandQueue      CreateCommandQueue;
    FnCreateProgramWithSource CreateProgramWithSource;
    FnBuildProgram            BuildProgram;
    FnGetProgramBuildInfo     GetProgramBuildInfo;
    FnCreateKernel            CreateKernel;
    FnCreateBuffer            CreateBuffer;
    FnRelease                 ReleaseMemObject;
    FnRelease                 ReleaseKernel;
    FnRelease                 ReleaseProgram;
    FnRelease                 ReleaseCommandQueue;
    FnRelease                 ReleaseContext;
    FnEnqueueWriteBuffer      EnqueueWriteBuffer;
    FnSetKernelArg            SetKernelArg;
    FnEnqueueNDRangeKernel    EnqueueNDRangeKernel;
    FnFinish                  Finish;
    FnEnqueueReadBuffer       EnqueueReadBuffer;
};

ClApi gCl;

template <typename T>
bool Bind(void* lib, const char* name, T& out) {
    out = reinterpret_cast<T>(dlsym(lib, name));
    return out != nullptr;
}

} // namespace

GpuMiner::GpuMiner()
    : mReady(false)
    , mLib(nullptr), mContext(nullptr), mQueue(nullptr)
    , mProgram(nullptr), mKernel(nullptr)
    , mBufMidstate(nullptr), mBufBlock2(nullptr)
    , mBufBlock3(nullptr), mBufFound(nullptr)
{}

GpuMiner::~GpuMiner() {
    Release();
    if (mLib) {
        dlclose(mLib);
        mLib = nullptr;
    }
}

bool GpuMiner::LoadLibrary(std::string& reasonOut) {
    if (mLib) return true;
#ifdef WIN32
    mLib = dlopen("OpenCL.dll", RTLD_NOW | RTLD_LOCAL);
#else
    mLib = dlopen("libOpenCL.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!mLib) mLib = dlopen("libOpenCL.so", RTLD_NOW | RTLD_LOCAL);
#endif
    if (!mLib) {
        reasonOut = "OpenCL library not installed";
        return false;
    }
    bool ok = true;
    ok = ok && Bind(mLib, "clGetPlatformIDs",          gCl.GetPlatformIDs);
    ok = ok && Bind(mLib, "clGetDeviceIDs",            gCl.GetDeviceIDs);
    ok = ok && Bind(mLib, "clGetDeviceInfo",           gCl.GetDeviceInfo);
    ok = ok && Bind(mLib, "clCreateContext",           gCl.CreateContext);
    ok = ok && Bind(mLib, "clCreateCommandQueue",      gCl.CreateCommandQueue);
    ok = ok && Bind(mLib, "clCreateProgramWithSource", gCl.CreateProgramWithSource);
    ok = ok && Bind(mLib, "clBuildProgram",            gCl.BuildProgram);
    ok = ok && Bind(mLib, "clGetProgramBuildInfo",     gCl.GetProgramBuildInfo);
    ok = ok && Bind(mLib, "clCreateKernel",            gCl.CreateKernel);
    ok = ok && Bind(mLib, "clCreateBuffer",            gCl.CreateBuffer);
    ok = ok && Bind(mLib, "clReleaseMemObject",        gCl.ReleaseMemObject);
    ok = ok && Bind(mLib, "clReleaseKernel",           gCl.ReleaseKernel);
    ok = ok && Bind(mLib, "clReleaseProgram",          gCl.ReleaseProgram);
    ok = ok && Bind(mLib, "clReleaseCommandQueue",     gCl.ReleaseCommandQueue);
    ok = ok && Bind(mLib, "clReleaseContext",          gCl.ReleaseContext);
    ok = ok && Bind(mLib, "clEnqueueWriteBuffer",      gCl.EnqueueWriteBuffer);
    ok = ok && Bind(mLib, "clSetKernelArg",            gCl.SetKernelArg);
    ok = ok && Bind(mLib, "clEnqueueNDRangeKernel",    gCl.EnqueueNDRangeKernel);
    ok = ok && Bind(mLib, "clFinish",                  gCl.Finish);
    ok = ok && Bind(mLib, "clEnqueueReadBuffer",       gCl.EnqueueReadBuffer);
    if (!ok) {
        reasonOut = "OpenCL library is incomplete";
        dlclose(mLib);
        mLib = nullptr;
        return false;
    }
    return true;
}

void GpuMiner::Release() {
    if (mLib) {
        if (mBufMidstate) gCl.ReleaseMemObject(mBufMidstate);
        if (mBufBlock2)   gCl.ReleaseMemObject(mBufBlock2);
        if (mBufBlock3)   gCl.ReleaseMemObject(mBufBlock3);
        if (mBufFound)    gCl.ReleaseMemObject(mBufFound);
        if (mKernel)      gCl.ReleaseKernel(mKernel);
        if (mProgram)     gCl.ReleaseProgram(mProgram);
        if (mQueue)       gCl.ReleaseCommandQueue(mQueue);
        if (mContext)     gCl.ReleaseContext(mContext);
    }
    mBufMidstate = mBufBlock2 = mBufBlock3 = mBufFound = nullptr;
    mKernel = mProgram = mQueue = mContext = nullptr;
    mReady = false;
}

bool GpuMiner::Init(const std::string& kernelSource, std::string& reasonOut) {
    if (mReady) return true;
    if (!LoadLibrary(reasonOut)) return false;

    cl_int err = CL_OK;
    cl_uint nplat = 0;
    cl_handle plat = nullptr;
    err = gCl.GetPlatformIDs(1, &plat, &nplat);
    if (err != CL_OK || nplat == 0 || !plat) {
        reasonOut = "no OpenCL platform";
        return false;
    }

    cl_handle dev = nullptr;
    cl_uint ndev = 0;
    err = gCl.GetDeviceIDs(plat, CL_DEV_TYPE_GPU, 1, &dev, &ndev);
    if (err != CL_OK || ndev == 0 || !dev) {
        dev = nullptr;
        ndev = 0;
        err = gCl.GetDeviceIDs(plat, CL_DEV_TYPE_ALL, 1, &dev, &ndev);
        if (err != CL_OK || ndev == 0 || !dev) {
            reasonOut = "no OpenCL device";
            return false;
        }
    }

    char name[256] = {0};
    gCl.GetDeviceInfo(dev, CL_DEV_NAME, sizeof(name) - 1, name, nullptr);
    mDeviceName = name;

    mContext = gCl.CreateContext(nullptr, 1, &dev, nullptr, nullptr, &err);
    if (err != CL_OK || !mContext) {
        reasonOut = "cannot create OpenCL context";
        Release();
        return false;
    }

    mQueue = gCl.CreateCommandQueue(mContext, dev, 0, &err);
    if (err != CL_OK || !mQueue) {
        reasonOut = "cannot create OpenCL queue";
        Release();
        return false;
    }

    const char* src = kernelSource.c_str();
    const size_t srclen = kernelSource.size();
    mProgram = gCl.CreateProgramWithSource(mContext, 1, &src, &srclen, &err);
    if (err != CL_OK || !mProgram) {
        reasonOut = "cannot create OpenCL program";
        Release();
        return false;
    }

    err = gCl.BuildProgram(mProgram, 1, &dev, nullptr, nullptr, nullptr);
    if (err != CL_OK) {
        size_t ln = 0;
        gCl.GetProgramBuildInfo(mProgram, dev, CL_PROG_BUILD_LOG, 0, nullptr, &ln);
        std::vector<char> log(ln + 1, '\0');
        if (ln > 0) {
            gCl.GetProgramBuildInfo(mProgram, dev, CL_PROG_BUILD_LOG, ln,
                                    log.data(), nullptr);
        }
        reasonOut = std::string("kernel build failed: ") + log.data();
        Release();
        return false;
    }

    mKernel = gCl.CreateKernel(mProgram, "moneu_search", &err);
    if (err != CL_OK || !mKernel) {
        reasonOut = "kernel moneu_search missing";
        Release();
        return false;
    }

    mBufMidstate = gCl.CreateBuffer(mContext, CL_MEM_RO, 8 * sizeof(uint32_t), nullptr, &err);
    if (err != CL_OK || !mBufMidstate) { reasonOut = "buffer allocation failed"; Release(); return false; }
    mBufBlock2 = gCl.CreateBuffer(mContext, CL_MEM_RO, 16 * sizeof(uint32_t), nullptr, &err);
    if (err != CL_OK || !mBufBlock2)   { reasonOut = "buffer allocation failed"; Release(); return false; }
    mBufBlock3 = gCl.CreateBuffer(mContext, CL_MEM_RO, 16 * sizeof(uint32_t), nullptr, &err);
    if (err != CL_OK || !mBufBlock3)   { reasonOut = "buffer allocation failed"; Release(); return false; }
    mBufFound = gCl.CreateBuffer(mContext, CL_MEM_RW, 2 * sizeof(uint32_t), nullptr, &err);
    if (err != CL_OK || !mBufFound)    { reasonOut = "buffer allocation failed"; Release(); return false; }

    mReady = true;
    return true;
}

bool GpuMiner::Search(const uint32_t midstate[8],
                      const uint32_t block2[16],
                      const uint32_t block3[16],
                      uint32_t targetTop,
                      uint32_t startNonce,
                      uint32_t count,
                      uint32_t& foundNonce,
                      std::string& reasonOut)
{
    if (!mReady) { reasonOut = "GPU not initialised"; return false; }
    if (count == 0) return false;

    cl_int err = gCl.EnqueueWriteBuffer(mQueue, mBufMidstate, CL_BLOCKING, 0,
                                        8 * sizeof(uint32_t), midstate, 0, nullptr, nullptr);
    if (err != CL_OK) { reasonOut = "write midstate failed"; return false; }
    err = gCl.EnqueueWriteBuffer(mQueue, mBufBlock2, CL_BLOCKING, 0,
                                 16 * sizeof(uint32_t), block2, 0, nullptr, nullptr);
    if (err != CL_OK) { reasonOut = "write block2 failed"; return false; }
    err = gCl.EnqueueWriteBuffer(mQueue, mBufBlock3, CL_BLOCKING, 0,
                                 16 * sizeof(uint32_t), block3, 0, nullptr, nullptr);
    if (err != CL_OK) { reasonOut = "write block3 failed"; return false; }

    const uint32_t zero[2] = {0u, 0u};
    err = gCl.EnqueueWriteBuffer(mQueue, mBufFound, CL_BLOCKING, 0,
                                 2 * sizeof(uint32_t), zero, 0, nullptr, nullptr);
    if (err != CL_OK) { reasonOut = "reset result failed"; return false; }

    err  = gCl.SetKernelArg(mKernel, 0, sizeof(cl_handle), &mBufMidstate);
    err |= gCl.SetKernelArg(mKernel, 1, sizeof(cl_handle), &mBufBlock2);
    err |= gCl.SetKernelArg(mKernel, 2, sizeof(cl_handle), &mBufBlock3);
    err |= gCl.SetKernelArg(mKernel, 3, sizeof(uint32_t),  &targetTop);
    err |= gCl.SetKernelArg(mKernel, 4, sizeof(uint32_t),  &startNonce);
    err |= gCl.SetKernelArg(mKernel, 5, sizeof(uint32_t),  &count);
    err |= gCl.SetKernelArg(mKernel, 6, sizeof(cl_handle), &mBufFound);
    if (err != CL_OK) { reasonOut = "kernel arguments rejected"; return false; }

    const size_t global = count;
    err = gCl.EnqueueNDRangeKernel(mQueue, mKernel, 1, nullptr, &global, nullptr,
                                   0, nullptr, nullptr);
    if (err != CL_OK) { reasonOut = "kernel launch failed"; return false; }
    err = gCl.Finish(mQueue);
    if (err != CL_OK) { reasonOut = "kernel execution failed"; return false; }

    uint32_t found[2] = {0u, 0u};
    err = gCl.EnqueueReadBuffer(mQueue, mBufFound, CL_BLOCKING, 0,
                                2 * sizeof(uint32_t), found, 0, nullptr, nullptr);
    if (err != CL_OK) { reasonOut = "read result failed"; return false; }

    if (found[0] == 1u) {
        foundNonce = found[1];
        return true;
    }
    return false;
}

} // namespace MONEU
