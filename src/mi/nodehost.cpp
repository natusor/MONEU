// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "nodehost.h"
#include "rpcclient.h"

#include <QMetaObject>

int MoneuNodeMain(int argc, char* argv[]);
void RequestShutdown();

namespace mi {

NodeHost::NodeHost(const std::vector<std::string>& nodeArgs,
                   const std::string& dataDir, QObject* parent)
    : QObject(parent)
    , mArgs(nodeArgs)
    , mDataDir(dataDir)
    , mRunning(false)
    , mEmbedded(false)
{
}

NodeHost::~NodeHost()
{
    if (mThread.joinable()) {
        RequestShutdown();
        mThread.join();
    }
}

bool NodeHost::Start()
{
    RpcClient probe(mDataDir);
    if (probe.PortOpen()) {
        mEmbedded = false;
        return true;
    }

    mEmbedded = true;
    mRunning = true;
    mThread = std::thread([this]() {
        std::vector<std::string> store;
        store.push_back("moneu-mi");
        store.insert(store.end(), mArgs.begin(), mArgs.end());
        std::vector<char*> argv;
        for (size_t i = 0; i < store.size(); ++i) argv.push_back(&store[i][0]);
        argv.push_back(nullptr);

        int code = 1;
        try {
            code = MoneuNodeMain(static_cast<int>(store.size()), argv.data());
        } catch (...) {
            code = 1;
        }
        mRunning = false;
        QMetaObject::invokeMethod(this, [this, code]() {
            Q_EMIT NodeExited(code);
        }, Qt::QueuedConnection);
    });
    return false;
}

void NodeHost::RequestStop()
{
    if (mEmbedded) RequestShutdown();
}

void NodeHost::Join()
{
    if (mThread.joinable()) mThread.join();
}

} // namespace mi
