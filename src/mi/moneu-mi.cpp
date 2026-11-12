// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "historyscanner.h"
#include "mainwindow.h"
#include "miutil.h"
#include "rpcworker.h"

#include "node/data_dir.h"

#ifdef WIN32
#undef NOGDI
#include <winsock2.h>
#include <windows.h>
#endif

#include <QApplication>
#include <QIcon>
#include <QStringList>

#include <string>
#include <vector>

static const char* MI_STYLE =
    "QDialog, QMessageBox { background: #F1ECE0; }"
    "QDialog QLabel, QMessageBox QLabel { color: #1C1C14; }"
    "QLineEdit { background: #FCF8F1; color: #1C1C14;"
    "  border: 2px solid #1C1C14; border-radius: 6px; padding: 5px 8px; }"
    "QPushButton { background: #1E7836; color: white; font-weight: bold;"
    "  border: 2px solid #C9A633; border-radius: 7px; padding: 6px 16px;"
    "  min-width: 70px; }"
    "QPushButton:disabled { background: #C9C4B8; border-color: #9A958A; }"
    "QPushButton:hover { background: #238540; }"
    "QTableWidget { background: #FCF8F1; alternate-background-color: #F4EFE3;"
    "  color: #1C1C14; gridline-color: #D6D0C0; border: 2px solid #1C1C14;"
    "  selection-background-color: #CFE6D5; selection-color: #1C1C14; }"
    "QHeaderView::section { background: #E6E1D3; color: #1C1C14;"
    "  border: none; border-bottom: 2px solid #1C1C14; padding: 4px 6px; }"
    "QProgressBar { background: #E4E0D4; border: 2px solid #1C1C14;"
    "  border-radius: 7px; height: 14px; }"
    "QProgressBar::chunk { background: #1E7836; border-radius: 5px; }"
    "QCheckBox { color: #1C1C14; }"
    "QDialogButtonBox { dialogbuttonbox-buttons-have-icons: 0; }"
    "QToolTip { background: #FCF8F1; color: #1C1C14; border: 1px solid #1C1C14; }";

int main(int argc, char* argv[])
{
#ifdef WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);

    QApplication app(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("MONEU"));
    QApplication::setApplicationName(QStringLiteral("MI"));
    QApplication::setApplicationVersion(QStringLiteral(MI_VERSION));
    QApplication::setWindowIcon(QIcon(QStringLiteral(":/mi/moneu_64.png")));
    QApplication::setQuitOnLastWindowClosed(false);
    app.setFont(mi::MonoFont(13, true));
    app.setStyleSheet(QString::fromLatin1(MI_STYLE));

    mi::RegisterMetaTypes();
    qRegisterMetaType<mi::TxRecord>("mi::TxRecord");
    qRegisterMetaType<QVector<mi::TxRecord> >("QVector<mi::TxRecord>");

    std::vector<std::string> nodeArgs;
    std::string dataDirArg;
    const QStringList args = QApplication::arguments();
    for (int i = 1; i < args.size(); ++i) {
        const std::string a = args[i].toStdString();
        if (a == "-daemon" || a == "--daemon" || a == "-help" || a == "--help" ||
            a == "-h" || a == "-version" || a == "--version" || a == "-v")
            continue;
        if (a.compare(0, 9, "-datadir=") == 0) dataDirArg = a.substr(9);
        nodeArgs.push_back(a);
    }

    std::string dataDir;
    if (!dataDirArg.empty()) {
        dataDir = dataDirArg;
    } else {
        MONEU::node::DataDir defaults;
        dataDir = defaults.GetDataDir().string();
    }

    int code = 0;
    {
        mi::MainWindow window(nodeArgs, dataDir);
        window.show();
        window.Start();
        code = app.exec();
    }

#ifdef WIN32
    WSACleanup();
#endif
    return code;
}
