// Qt6 GUI entry point — reads /tmp/junknas.lock, connects to daemon API.
#include "main_window.h"
#include <QApplication>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QDir>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("JunkNAS");
    app.setApplicationVersion("0.1.0");
    app.setOrganizationName("JunkNAS");

    // Read lock file to discover daemon API port.
    QString lockPath = QDir::tempPath() + "/junknas.lock";
    QFile lock(lockPath);
    if (!lock.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(nullptr, "JunkNAS",
            "Cannot find junknas.lock.\nMake sure junknasd is running.");
        return 1;
    }
    auto doc = QJsonDocument::fromJson(lock.readAll());
    lock.close();
    int port = doc.object().value("api_port").toInt();
    if (port == 0) {
        QMessageBox::critical(nullptr, "JunkNAS", "Invalid lock file — port is 0.");
        return 1;
    }

    MainWindow w;
    w.setApiPort(port);
    w.show();

    return app.exec();
}
