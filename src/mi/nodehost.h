// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_MI_NODEHOST_H
#define MONEU_MI_NODEHOST_H

#include <QObject>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

namespace mi {

// Runs the node inside this process on its own thread, the way bitcoin-qt
// does, unless a node already answers on the control port. Then MI only
// talks to that one and leaves it running when it closes.
class NodeHost : public QObject {
    Q_OBJECT

public:
    NodeHost(const std::vector<std::string>& nodeArgs,
             const std::string& dataDir, QObject* parent = nullptr);
    ~NodeHost();

    // True when a node was already running and MI attached to it.
    bool Start();

    bool Embedded() const { return mEmbedded; }
    bool Running() const { return mRunning.load(); }

    void RequestStop();
    void Join();

Q_SIGNALS:
    void NodeExited(int code);

private:
    std::vector<std::string> mArgs;
    std::string              mDataDir;
    std::thread              mThread;
    std::atomic<bool>        mRunning;
    bool                     mEmbedded;
};

} // namespace mi

#endif // MONEU_MI_NODEHOST_H
