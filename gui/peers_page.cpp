#include "peers_page.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QJsonArray>

PeersPage::PeersPage(QWidget *parent) : QWidget(parent) { setupUi(); }

void PeersPage::setupUi() {
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(24, 24, 24, 16);
    root->setSpacing(16);

    auto *title = new QLabel("Peers");
    title->setStyleSheet("color: #c9d1d9; font-size: 20px; font-weight: bold;");
    root->addWidget(title);

    m_emptyLabel = new QLabel("No peers yet. Add a node or join a cloud to get started.");
    m_emptyLabel->setStyleSheet("color: #6e7681; font-size: 13px;");
    m_emptyLabel->setAlignment(Qt::AlignCenter);
    root->addWidget(m_emptyLabel);

    m_table = new QTableWidget(0, 7, this);
    m_table->setHorizontalHeaderLabels(
        {"Identity", "Role", "Status", "Quota", "Mount Port", "Last Seen", "B32"});
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_table->verticalHeader()->setVisible(false);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->setStyleSheet(R"(
        QTableWidget {
            background-color: #161b22;
            alternate-background-color: #0d1117;
            border: 1px solid #21262d;
            border-radius: 8px;
        }
        QTableWidget::item { padding: 8px 12px; color: #c9d1d9; }
        QTableWidget::item:selected { background-color: #1f3a5f; }
        QHeaderView::section {
            background-color: #010409;
            color: #6e7681;
            border: none;
            border-bottom: 1px solid #21262d;
            padding: 8px 12px;
            font-size: 11px;
            letter-spacing: 1px;
        }
    )");
    m_table->hide();
    root->addWidget(m_table, 1);
}

void PeersPage::onStatus(const QJsonObject &status) {
    auto peers = status.value("peers").toArray();
    m_emptyLabel->setVisible(peers.isEmpty());
    m_table->setVisible(!peers.isEmpty());
    m_table->setRowCount(peers.size());

    for (int row = 0; row < peers.size(); ++row) {
        auto p = peers[row].toObject();
        auto phrase = p.value("phrase").toArray();
        QString ident = phrase[0].toString() + " " +
                        phrase[1].toString() + " " +
                        phrase[2].toString();
        QString role  = p.value("role").toString();
        QString st    = p.value("status").toString();
        qint64  quota = p.value("quota_bytes").toInteger();
        int     port  = p.value("local_mount_port").toInt();
        QString ls    = p.value("last_seen").toString();
        QString b32   = p.value("b32").toString();

        // Status colour.
        QColor stCol("#6e7681");
        if (st == "healthy")     stCol = QColor("#3fb950");
        if (st == "degraded")    stCol = QColor("#d29922");
        if (st == "unreachable") stCol = QColor("#f85149");

        auto set = [&](int col, const QString &txt, QColor c = QColor("#c9d1d9")) {
            auto *item = new QTableWidgetItem(txt);
            item->setForeground(c);
            m_table->setItem(row, col, item);
        };

        QString quota_s;
        if (quota >= (1LL<<30)) quota_s = QString::number(quota>>30) + " GiB";
        else quota_s = QString::number(quota) + " B";

        set(0, ident);
        set(1, role == "leech" ? "👁  leech" : "💾 storage");
        set(2, st, stCol);
        set(3, quota_s);
        set(4, port > 0 ? QString::number(port) : "—", QColor("#6e7681"));
        set(5, ls.isEmpty() ? "never" : ls, QColor("#6e7681"));
        set(6, b32, QColor("#6e7681"));
    }
}
