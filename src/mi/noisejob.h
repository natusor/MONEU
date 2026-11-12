// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_MI_NOISEJOB_H
#define MONEU_MI_NOISEJOB_H

#include <QObject>
#include <QString>

#include <string>

namespace mi {

// What moneu-cli makenoise does, step for step and with the same messages,
// with progress reported to the window instead of printed.
class NoiseJob : public QObject {
    Q_OBJECT

public:
    explicit NoiseJob(const std::string& dataDir);

    void Run(const QString& passphrase);

Q_SIGNALS:
    void Progress(qint64 produced, qint64 target);
    void Finished(bool ok, const QString& text);

private:
    std::string mDataDir;
};

} // namespace mi

#endif // MONEU_MI_NOISEJOB_H
