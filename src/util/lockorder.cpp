// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "lockorder.h"

#ifdef MONEU_DEBUG_LOCKORDER

#include "../log/log.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

namespace MONEU {
namespace util {

namespace {

struct LockSite {
    const void* mutex;
    std::string name;
    std::string file;
    int         line;
};

typedef std::vector<LockSite>            LockStack;
typedef std::pair<const void*, const void*> LockPair;

struct Registry {
    std::unordered_map<std::thread::id, LockStack> stacks;
    std::map<LockPair, std::pair<LockStack, LockStack> > orders;
    std::mutex mutex;
    std::atomic<bool> consistent;

    Registry() : consistent(true) {}
};

Registry& Reg() {
    static Registry* r = new Registry();
    return *r;
}

std::string Describe(const LockStack& stack) {
    std::ostringstream ss;
    for (size_t i = 0; i < stack.size(); ++i) {
        ss << "\n      " << stack[i].name
           << " at " << stack[i].file << ":" << stack[i].line;
    }
    return ss.str();
}

void ReportConflict(const LockSite& taking,
                    const LockStack& earlier,
                    const LockStack& current) {
    Reg().consistent.store(false);

    std::ostringstream ss;
    ss << "LOCK ORDER CONFLICT - two code paths take the same two locks in "
       << "opposite orders, which will deadlock the node when they overlap."
       << "\n\n  Taking " << taking.name
       << " at " << taking.file << ":" << taking.line
       << "\n  while this thread holds:" << Describe(current)
       << "\n\n  But another path took them the other way round:"
       << Describe(earlier)
       << "\n\n  Fix the order in one of the two places rather than hoping "
       << "the two never run together.";

    MONEU_LOG_ERROR(ss.str());
    std::fprintf(stderr, "%s\n", ss.str().c_str());

    std::abort();
}

}

void EnterLock(const void* mutex, const char* name,
               const char* file, int line) {
    Registry& reg = Reg();
    std::lock_guard<std::mutex> guard(reg.mutex);

    LockStack& stack = reg.stacks[std::this_thread::get_id()];

    LockSite site;
    site.mutex = mutex;
    site.name  = name ? name : "?";
    site.file  = file ? file : "?";
    site.line  = line;

    for (size_t i = 0; i < stack.size(); ++i) {
        if (stack[i].mutex == mutex) {
            LockStack attempted = stack;
            attempted.push_back(site);
            std::ostringstream ss;
            ss << "DOUBLE LOCK - " << site.name
               << " at " << site.file << ":" << site.line
               << " is already held by this thread, taken at "
               << stack[i].file << ":" << stack[i].line
               << ". Locking a non-recursive mutex twice from one thread is "
               << "undefined behaviour.";
            MONEU_LOG_ERROR(ss.str());
            std::fprintf(stderr, "%s\n", ss.str().c_str());
            std::abort();
        }
    }

    for (size_t i = 0; i < stack.size(); ++i) {
        const LockPair forward(stack[i].mutex, mutex);
        const LockPair reverse(mutex, stack[i].mutex);

        if (reg.orders.count(forward)) continue;

        auto it = reg.orders.find(reverse);
        if (it != reg.orders.end()) {
            LockStack attempted = stack;
            attempted.push_back(site);
            ReportConflict(site, it->second.first, attempted);
            return;
        }

        LockStack attempted = stack;
        attempted.push_back(site);
        reg.orders[forward] = std::make_pair(attempted, attempted);
    }

    stack.push_back(site);
}

void LeaveLock(const void* mutex) {
    Registry& reg = Reg();
    std::lock_guard<std::mutex> guard(reg.mutex);

    auto it = reg.stacks.find(std::this_thread::get_id());
    if (it == reg.stacks.end() || it->second.empty()) return;

    LockStack& stack = it->second;
    for (size_t i = stack.size(); i > 0; --i) {
        if (stack[i - 1].mutex == mutex) {
            stack.erase(stack.begin() + (i - 1));
            break;
        }
    }
    if (stack.empty()) reg.stacks.erase(it);
}

bool HoldsLock(const void* mutex) {
    Registry& reg = Reg();
    std::lock_guard<std::mutex> guard(reg.mutex);
    auto it = reg.stacks.find(std::this_thread::get_id());
    if (it == reg.stacks.end()) return false;
    for (size_t i = 0; i < it->second.size(); ++i) {
        if (it->second[i].mutex == mutex) return true;
    }
    return false;
}

std::string HeldLocks() {
    Registry& reg = Reg();
    std::lock_guard<std::mutex> guard(reg.mutex);
    auto it = reg.stacks.find(std::this_thread::get_id());
    if (it == reg.stacks.end()) return "(none)";
    return Describe(it->second);
}

bool LockOrderIsConsistent() {
    return Reg().consistent.load();
}

void AssertLockHeld(const void* mutex, const char* name,
                    const char* file, int line) {
    if (HoldsLock(mutex)) return;
    std::ostringstream ss;
    ss << "LOCK NOT HELD - " << (name ? name : "?")
       << " was expected to be held at " << (file ? file : "?") << ":" << line
       << ", but this thread holds:" << HeldLocks()
       << "\n  A function that reads shared state without the lock its "
       << "caller was supposed to take will read torn values under load.";
    MONEU_LOG_ERROR(ss.str());
    std::fprintf(stderr, "%s\n", ss.str().c_str());
    std::abort();
}

void AssertLockNotHeld(const void* mutex, const char* name,
                       const char* file, int line) {
    if (!HoldsLock(mutex)) return;
    std::ostringstream ss;
    ss << "LOCK HELD WHEN IT SHOULD NOT BE - " << (name ? name : "?")
       << " at " << (file ? file : "?") << ":" << line
       << ". This usually means a function that takes the lock itself was "
       << "called from inside a section that already holds it, which on a "
       << "non-recursive mutex is a deadlock with itself.";
    MONEU_LOG_ERROR(ss.str());
    std::fprintf(stderr, "%s\n", ss.str().c_str());
    std::abort();
}

} // namespace util
} // namespace MONEU

#endif // MONEU_DEBUG_LOCKORDER
