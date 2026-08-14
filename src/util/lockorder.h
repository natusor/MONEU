// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MONEU_UTIL_LOCKORDER_H
#define MONEU_UTIL_LOCKORDER_H

#include <mutex>
#include <string>

namespace MONEU {
namespace util {

#ifdef MONEU_DEBUG_LOCKORDER

void EnterLock(const void* mutex, const char* name,
               const char* file, int line);

void LeaveLock(const void* mutex);

bool HoldsLock(const void* mutex);

std::string HeldLocks();

bool LockOrderIsConsistent();

#else

inline void EnterLock(const void*, const char*, const char*, int) {}
inline void LeaveLock(const void*) {}
inline bool HoldsLock(const void*) { return true; }
inline std::string HeldLocks() { return std::string(); }
inline bool LockOrderIsConsistent() { return true; }

#endif

template <typename Mutex>
class TrackedLock {
public:
    TrackedLock(Mutex& m, const char* name, const char* file, int line)
        : mMutex(m)
    {
        EnterLock(&m, name, file, line);
        mMutex.lock();
    }

    ~TrackedLock() {
        mMutex.unlock();
        LeaveLock(&mMutex);
    }

    TrackedLock(const TrackedLock&) = delete;
    TrackedLock& operator=(const TrackedLock&) = delete;

private:
    Mutex& mMutex;
};

} // namespace util
} // namespace MONEU

#define MONEU_LOCK_CAT_(a, b) a##b
#define MONEU_LOCK_CAT(a, b)  MONEU_LOCK_CAT_(a, b)

#define MONEU_LOCK(mutex) \
    MONEU::util::TrackedLock<decltype(mutex)> \
        MONEU_LOCK_CAT(moneu_lock_, __LINE__)(mutex, #mutex, \
                                              __FILE__, __LINE__)

#define MONEU_ASSERT_LOCK_HELD(mutex) \
    MONEU::util::AssertLockHeld(&(mutex), #mutex, __FILE__, __LINE__)
#define MONEU_ASSERT_LOCK_NOT_HELD(mutex) \
    MONEU::util::AssertLockNotHeld(&(mutex), #mutex, __FILE__, __LINE__)

namespace MONEU {
namespace util {

#ifdef MONEU_DEBUG_LOCKORDER
void AssertLockHeld(const void* mutex, const char* name,
                    const char* file, int line);
void AssertLockNotHeld(const void* mutex, const char* name,
                       const char* file, int line);
#else
inline void AssertLockHeld(const void*, const char*, const char*, int) {}
inline void AssertLockNotHeld(const void*, const char*, const char*, int) {}
#endif

} // namespace util
} // namespace MONEU

#endif // MONEU_UTIL_LOCKORDER_H
