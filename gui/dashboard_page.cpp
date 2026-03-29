#include "dashboard_page.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QScrollArea>
#include <QDateTime>
#include <QJsonArray>

// ── shared style constants ─────────────────────────────────────────────────

static const char *CARD_STYLE = R"(
    QFrame {
        background-color: #161b22;
        border: 1px solid #21262d;
        border-radius: 8px;
    }
)";

static const char *LABEL_DIM  = "color: #6e7681; font-size: 11px;";
static const char *LABEL_VAL  = "color: #c9d1d9; font-size: 13px;";
static const char *LABEL_ACC  = "color: #58a6ff; font-size: 22px; font-weight: bold;";
static const char *LABEL_HEAD = "color: #58a6ff; font-size: 13px; font-weight: bold; letter-spacing: 1px;";

static QFrame *makeCard() {
    auto *f = new QFrame;
    f->setStyleSheet(CARD_STYLE);
    return f;
}

static QLabel *dimLabel(const QString &t = "") {
    auto *l = new QLabel(t);
    l->setStyleSheet(LABEL_DIM);
    return l;
}

static QLabel *valLabel(const QString &t = "") {
    auto *l = new QLabel(t);
    l->setStyleSheet(LABEL_VAL);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    return l;
}

// ── DashboardPage ──────────────────────────────────────────────────────────

DashboardPage::DashboardPage(QWidget *parent) : QWidget(parent) {
    setupUi();
}

void DashboardPage::setupUi() {
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(24, 24, 24, 16);
    root->setSpacing(16);

    // Page title.
    auto *title = new QLabel("Dashboard");
    title->setStyleSheet("color: #c9d1d9; font-size: 20px; font-weight: bold;");
    root->addWidget(title);

    // ── top cards row ────────────────────────────────────────────────────
    auto *cardsRow = new QHBoxLayout;
    cardsRow->setSpacing(16);

    // Self card.
    {
        auto *card = makeCard();
        auto *cl = new QVBoxLayout(card);
        cl->setContentsMargins(16, 14, 16, 14);
        cl->setSpacing(6);

        auto *head = new QLabel("◈ THIS NODE");
        head->setStyleSheet(LABEL_HEAD);
        cl->addWidget(head);
        cl->addSpacing(4);

        auto *grid = new QGridLayout;
        grid->setSpacing(4);
        grid->setColumnMinimumWidth(0, 60);

        auto addRow = [&](int row, const QString &key, QLabel *&val) {
            grid->addWidget(dimLabel(key), row, 0);
            val = valLabel("—");
            val->setWordWrap(true);
            grid->addWidget(val, row, 1);
        };

        addRow(0, "B32",   m_b32Label);
        addRow(1, "Role",  m_roleLabel);
        addRow(2, "Quota", m_quotaLabel);
        addRow(3, "Path",  m_pathLabel);

        cl->addLayout(grid);
        cardsRow->addWidget(card, 3);
    }

    // Network stats card.
    {
        auto *card = makeCard();
        auto *cl = new QVBoxLayout(card);
        cl->setContentsMargins(16, 14, 16, 14);
        cl->setSpacing(6);

        auto *head = new QLabel("◈ NETWORK");
        head->setStyleSheet(LABEL_HEAD);
        cl->addWidget(head);
        cl->addSpacing(4);

        m_peerCountLabel = new QLabel("0");
        m_peerCountLabel->setStyleSheet(LABEL_ACC);
        auto *peerDim = dimLabel("total peers");
        cl->addWidget(m_peerCountLabel);
        cl->addWidget(peerDim);

        cl->addSpacing(8);

        m_storageCountLabel = new QLabel("0");
        m_storageCountLabel->setStyleSheet(LABEL_ACC);
        auto *storageDim = dimLabel("storage nodes");
        cl->addWidget(m_storageCountLabel);
        cl->addWidget(storageDim);

        cl->addStretch();

        m_mountLabel = dimLabel("⊙ mount: checking…");
        cl->addWidget(m_mountLabel);

        cardsRow->addWidget(card, 1);
    }

    root->addLayout(cardsRow);

    // ── peers table ───────────────────────────────────────────────────────
    auto *peersHead = new QLabel("◈ PEERS");
    peersHead->setStyleSheet(LABEL_HEAD);
    root->addWidget(peersHead);

    m_peersTable = new QTableWidget(0, 6, this);
    m_peersTable->setHorizontalHeaderLabels(
        {"Identity", "Role", "Status", "Quota", "Last Seen", "B32"});
    m_peersTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_peersTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Interactive);
    m_peersTable->horizontalHeader()->setDefaultSectionSize(140);
    m_peersTable->verticalHeader()->setVisible(false);
    m_peersTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_peersTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_peersTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_peersTable->setAlternatingRowColors(true);
    m_peersTable->setShowGrid(false);
    m_peersTable->setStyleSheet(R"(
        QTableWidget {
            background-color: #161b22;
            alternate-background-color: #0d1117;
            border: 1px solid #21262d;
            border-radius: 8px;
            gridline-color: #21262d;
        }
        QTableWidget::item { padding: 6px 10px; color: #c9d1d9; }
        QTableWidget::item:selected {
            background-color: #1f3a5f;
            color: #c9d1d9;
        }
        QHeaderView::section {
            background-color: #010409;
            color: #6e7681;
            border: none;
            border-bottom: 1px solid #21262d;
            padding: 6px 10px;
            font-size: 11px;
            letter-spacing: 1px;
        }
    )");
    root->addWidget(m_peersTable, 1);

    // Status bar.
    m_statusBar = dimLabel("Waiting for daemon…");
    root->addWidget(m_statusBar);
}

void DashboardPage::onStatus(const QJsonObject &status) {
    updateSelfCard(status.value("self").toObject());
    updateNetworkCard(status);
    updatePeersTable(status);
    m_statusBar->setText("Last refreshed: " +
        QDateTime::currentDateTime().toString("hh:mm:ss"));
}

void DashboardPage::updateSelfCard(const QJsonObject &self) {
    QString b32 = self.value("b32").toString();
    if (b32.length() > 55) b32 = b32.left(55) + "…";
    m_b32Label->setText(b32);

    QString role = self.value("role").toString();
    QString roleIcon = (role == "leech") ? "👁  leech" : "💾 storage";
    m_roleLabel->setText(roleIcon);

    qint64 quota = self.value("quota_bytes").toInteger();
    m_quotaLabel->setText(formatBytes(quota));
    m_pathLabel->setText(self.value("storage_path").toString());
}

void DashboardPage::updateNetworkCard(const QJsonObject &status) {
    m_peerCountLabel->setText(QString::number(status.value("peer_count").toInt()));
    m_storageCountLabel->setText(QString::number(status.value("storage_peers").toInt()));
    m_mountLabel->setText("⊙ mount: /mnt/junknas");
}

void DashboardPage::updatePeersTable(const QJsonObject &status) {
    auto peers = status.value("peers").toArray();
    m_peersTable->setRowCount(peers.size());

    for (int row = 0; row < peers.size(); ++row) {
        auto p = peers[row].toObject();
        auto phrase = p.value("phrase").toArray();
        QString ident = phrase[0].toString() + " " +
                        phrase[1].toString() + " " +
                        phrase[2].toString();

        QString role    = p.value("role").toString();
        QString roleStr = (role == "leech") ? "👁  leech" : "💾 storage";
        QString st      = p.value("status").toString();
        QString stIcon  = statusIcon(st);
        qint64  quota   = p.value("quota_bytes").toInteger();
        QString b32     = p.value("b32").toString();
        if (b32.length() > 24) b32 = b32.left(24) + "…";
        QString ls      = p.value("last_seen").toString();

        auto setCell = [&](int col, const QString &text, const QString &color = "#c9d1d9") {
            auto *item = new QTableWidgetItem(text);
            item->setForeground(QColor(color));
            m_peersTable->setItem(row, col, item);
        };

        setCell(0, ident);
        setCell(1, roleStr);
        setCell(2, stIcon + " " + st, statusColor(st));
        setCell(3, formatBytes(quota));
        setCell(4, ls.isEmpty() ? "never" : ls, "#6e7681");
        setCell(5, b32, "#6e7681");
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

QString DashboardPage::formatBytes(qint64 b) {
    if (b >= (1LL << 40)) return QString::number(b / (1LL << 40)) + " TiB";
    if (b >= (1LL << 30)) return QString::number(b / (1LL << 30)) + " GiB";
    if (b >= (1LL << 20)) return QString::number(b / (1LL << 20)) + " MiB";
    return QString::number(b) + " B";
}

QString DashboardPage::statusIcon(const QString &s) {
    if (s == "healthy")     return "●";
    if (s == "degraded")    return "◐";
    if (s == "unreachable") return "○";
    return "◌";
}

QString DashboardPage::statusColor(const QString &s) {
    if (s == "healthy")     return "#3fb950";
    if (s == "degraded")    return "#d29922";
    if (s == "unreachable") return "#f85149";
    return "#6e7681";
}
