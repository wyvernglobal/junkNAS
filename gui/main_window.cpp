#include "main_window.h"
#include "dashboard_page.h"
#include "addnode_page.h"
#include "joincloud_page.h"
#include "peers_page.h"
#include "settings_page.h"
#include "sidebar_widget.h"
#include "api_client.h"

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QApplication>
#include <QScreen>
#include <QJsonDocument>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_net(new QNetworkAccessManager(this))
    , m_stack(new QStackedWidget(this))
    , m_refreshTimer(new QTimer(this))
{
    setWindowTitle("JunkNAS");
    setMinimumSize(1024, 680);
    resize(1200, 760);

    // Centre on screen.
    if (auto *screen = QApplication::primaryScreen()) {
        auto sg = screen->availableGeometry();
        move(sg.center() - rect().center());
    }

    setupUi();
    applyTheme();
    startRefreshTimer();
}

void MainWindow::setApiPort(int port) {
    m_apiPort = port;
    m_apiBase = QString("http://127.0.0.1:%1").arg(port);
    refreshStatus();
}

void MainWindow::setupUi() {
    auto *central = new QWidget(this);
    setCentralWidget(central);

    auto *root = new QHBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // Sidebar navigation.
    m_sidebar = new SidebarWidget(this);
    root->addWidget(m_sidebar);

    // Page stack.
    m_dashboard = new DashboardPage(this);
    m_addNode   = new AddNodePage(this);
    m_joinCloud = new JoinCloudPage(this);
    m_peers     = new PeersPage(this);
    m_settings  = new SettingsPage(this);

    m_stack->addWidget(m_dashboard);   // index 0
    m_stack->addWidget(m_addNode);     // index 1
    m_stack->addWidget(m_joinCloud);   // index 2
    m_stack->addWidget(m_peers);       // index 3
    m_stack->addWidget(m_settings);    // index 4

    root->addWidget(m_stack, 1);

    // Wire sidebar navigation.
    connect(m_sidebar, &SidebarWidget::pageRequested,
            this,      &MainWindow::navigateTo);

    // Wire status propagation to pages.
    connect(this,        &MainWindow::statusRefreshed,
            m_dashboard, &DashboardPage::onStatus);
    connect(this,        &MainWindow::statusRefreshed,
            m_peers,     &PeersPage::onStatus);

    // Wire Add Node page back to dashboard after completion.
    connect(m_addNode, &AddNodePage::done,
            this,      [this]{ navigateTo("dashboard"); });

    // Wire Join Cloud page.
    connect(m_joinCloud, &JoinCloudPage::joinRequested,
            this, [this](const QJsonObject &req) {
                ApiClient::post(m_net, m_apiBase + "/v1/connect", req,
                    [this](const QJsonObject &) { refreshStatus(); });
            });

    // Settings change triggers daemon reconfigure.
    connect(m_settings, &SettingsPage::settingsChanged,
            this,       [this]{ refreshStatus(); });
}

void MainWindow::navigateTo(const QString &page) {
    if (page == "dashboard")  { m_stack->setCurrentIndex(0); }
    else if (page == "addnode")    { 
        m_addNode->loadInvite(m_net, m_apiBase);
        m_stack->setCurrentIndex(1); 
    }
    else if (page == "joincloud")  { m_stack->setCurrentIndex(2); }
    else if (page == "peers")      { m_stack->setCurrentIndex(3); }
    else if (page == "settings")   { m_stack->setCurrentIndex(4); }
    m_sidebar->setActivePage(page);
}

void MainWindow::refreshStatus() {
    if (m_apiBase.isEmpty()) return;
    ApiClient::get(m_net, m_apiBase + "/v1/status",
        [this](const QJsonObject &data) {
            onStatusReply(data);
        });
}

void MainWindow::onStatusReply(const QJsonObject &data) {
    emit statusRefreshed(data);
}

void MainWindow::startRefreshTimer() {
    connect(m_refreshTimer, &QTimer::timeout, this, &MainWindow::refreshStatus);
    m_refreshTimer->start(15000); // 15 s
}

void MainWindow::applyTheme() {
    qApp->setStyleSheet(R"(
        QWidget {
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
            font-size: 13px;
        }
        QMainWindow {
            background-color: #0d1117;
        }
        QScrollBar:vertical {
            background: #161b22;
            width: 6px;
            border-radius: 3px;
        }
        QScrollBar::handle:vertical {
            background: #30363d;
            border-radius: 3px;
            min-height: 20px;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QScrollBar:horizontal {
            background: #161b22;
            height: 6px;
        }
        QScrollBar::handle:horizontal {
            background: #30363d;
            border-radius: 3px;
        }
        QToolTip {
            background-color: #161b22;
            color: #c9d1d9;
            border: 1px solid #30363d;
            padding: 4px 8px;
            border-radius: 4px;
        }
    )");
}
