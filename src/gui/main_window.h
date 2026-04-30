#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QJsonObject>
#include <QJsonArray>

class DashboardPage;
class AddNodePage;
class JoinCloudPage;
class PeersPage;
class SettingsPage;
class SidebarWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override = default;

    void setApiPort(int port);

signals:
    void statusRefreshed(const QJsonObject &status);

public slots:
    void navigateTo(const QString &page);
    void refreshStatus();

private slots:
    void onStatusReply(const QJsonObject &data);

private:
    void setupUi();
    void setupSidebar();
    void applyTheme();
    void startRefreshTimer();

    QNetworkAccessManager *m_net;
    QStackedWidget        *m_stack;
    SidebarWidget         *m_sidebar;
    QTimer                *m_refreshTimer;

    DashboardPage  *m_dashboard;
    AddNodePage    *m_addNode;
    JoinCloudPage  *m_joinCloud;
    PeersPage      *m_peers;
    SettingsPage   *m_settings;

    int    m_apiPort{0};
    QString m_apiBase;
};
