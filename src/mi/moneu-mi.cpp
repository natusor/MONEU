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
#include <QScreen>
#include <QStringList>

#include <string>
#include <vector>

static const char* MI_STYLE =
    "QDialog, QMessageBox { background: #FBFAF6; }"
    "QDialog QLabel, QMessageBox QLabel { color: #1C1C14; }"
    "QLineEdit { background: #FFFFFF; color: #1C1C14;"
    "  border: 2px solid #1C1C14; border-radius: 6px; padding: 5px 8px; }"
    "QPushButton { color: white; font-weight: bold;"
    "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
    "    stop:0 #46CCBA, stop:0.45 #14A392, stop:1 #0B766A);"
    "  border: 2px solid #9AA3A8; border-radius: 7px; padding: 6px 16px;"
    "  min-width: 70px; }"
    "QPushButton:disabled { color: #E4E6E8;"
    "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
    "    stop:0 #9CA3A9, stop:1 #656C72); border-color: #7D8388; }"
    "QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
    "    stop:0 #58D8C7, stop:0.45 #1CB2A0, stop:1 #0F8577); }"
    "QPushButton:pressed { background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
    "    stop:0 #12907F, stop:1 #08665B); }"
    "QTableWidget { background: #FFFFFF; alternate-background-color: #F5F4EF;"
    "  color: #1C1C14; gridline-color: #D6D0C0; border: 2px solid #1C1C14;"
    "  selection-background-color: #CFE6D5; selection-color: #1C1C14; }"
    "QHeaderView::section { background: #E6E1D3; color: #1C1C14;"
    "  border: none; border-bottom: 2px solid #1C1C14; padding: 4px 6px; }"
    "QProgressBar { background: #E4E0D4; border: 2px solid #1C1C14;"
    "  border-radius: 7px; height: 14px; }"
    "QProgressBar::chunk { background: #1E7836; border-radius: 5px; }"
    "QCheckBox { color: #1C1C14; }"
    "QDialogButtonBox { dialogbuttonbox-buttons-have-icons: 0; }"
    "QToolTip { background: #FFFFFF; color: #1C1C14; border: 1px solid #1C1C14; }";

int main(int argc, char* argv[])
{
#ifdef WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
    // Windows at 125 or 150 percent keeps that exact factor. Rounded to a whole
    // number it made the window larger than the screen.
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);
#endif

    QApplication app(argc, argv);
    if (QScreen* screen = QGuiApplication::primaryScreen()) {
        const QRect avail = screen->availableGeometry();
        mi::SetUiScale(qMin(avail.width() * 0.94 / mi::MI_FULL_WIDTH,
                            avail.height() * 0.90 / mi::MI_FULL_HEIGHT));
    }
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
