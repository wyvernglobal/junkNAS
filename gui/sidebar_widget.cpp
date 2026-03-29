#include "sidebar_widget.h"
#include <QSpacerItem>

SidebarWidget::SidebarWidget(QWidget *parent) : QWidget(parent) {
    setFixedWidth(200);
    setObjectName("sidebar");
    setStyleSheet(R"(
        #sidebar {
            background-color: #010409;
            border-right: 1px solid #21262d;
        }
    )");

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // Logo / title.
    auto *logoWidget = new QWidget(this);
    logoWidget->setFixedHeight(64);
    logoWidget->setStyleSheet("background-color: #010409;");
    auto *logoLayout = new QVBoxLayout(logoWidget);
    logoLayout->setContentsMargins(16, 0, 0, 0);

    auto *logoLabel = new QLabel("▓▓ JunkNAS", logoWidget);
    logoLabel->setStyleSheet(
        "color: #58a6ff;"
        "font-size: 17px;"
        "font-weight: bold;"
        "letter-spacing: 1px;"
    );
    auto *tagLabel = new QLabel("Private Cloud · I2P", logoWidget);
    tagLabel->setStyleSheet("color: #6e7681; font-size: 10px;");

    logoLayout->addWidget(logoLabel);
    logoLayout->addWidget(tagLabel);
    layout->addWidget(logoWidget);

    // Divider.
    auto *div = new QWidget(this);
    div->setFixedHeight(1);
    div->setStyleSheet("background-color: #21262d;");
    layout->addWidget(div);

    layout->addSpacing(12);

    // Nav buttons.
    struct NavItem { QString icon, label, page; };
    const QList<NavItem> items = {
        {"◈", "Dashboard",  "dashboard"},
        {"⊕", "Add Node",   "addnode"},
        {"⊙", "Join Cloud", "joincloud"},
        {"◎", "Peers",      "peers"},
        {"⚙", "Settings",   "settings"},
    };
    for (const auto &item : items) {
        auto *btn = makeNavBtn(item.icon, item.label, item.page);
        m_btns[item.page] = btn;
        layout->addWidget(btn);
    }

    layout->addStretch();

    // Version footer.
    auto *ver = new QLabel("v0.1.0-dev", this);
    ver->setStyleSheet("color: #30363d; font-size: 10px; padding: 12px 16px;");
    ver->setAlignment(Qt::AlignLeft);
    layout->addWidget(ver);

    setActivePage("dashboard");
}

QPushButton *SidebarWidget::makeNavBtn(const QString &icon,
                                        const QString &label,
                                        const QString &page) {
    auto *btn = new QPushButton(QString("  %1  %2").arg(icon, label), this);
    btn->setFixedHeight(44);
    btn->setCursor(Qt::PointingHandCursor);
    btn->setCheckable(false);
    btn->setFlat(true);
    btn->setObjectName("navBtn_" + page);
    styleBtn(btn, false);

    connect(btn, &QPushButton::clicked, this, [this, page]{
        emit pageRequested(page);
    });
    return btn;
}

void SidebarWidget::setActivePage(const QString &page) {
    m_activePage = page;
    for (auto it = m_btns.begin(); it != m_btns.end(); ++it) {
        styleBtn(it.value(), it.key() == page);
    }
}

void SidebarWidget::styleBtn(QPushButton *btn, bool active) {
    if (active) {
        btn->setStyleSheet(R"(
            QPushButton {
                background-color: #161b22;
                color: #58a6ff;
                border: none;
                border-left: 2px solid #58a6ff;
                text-align: left;
                padding-left: 14px;
                font-size: 13px;
            }
        )");
    } else {
        btn->setStyleSheet(R"(
            QPushButton {
                background-color: transparent;
                color: #8b949e;
                border: none;
                border-left: 2px solid transparent;
                text-align: left;
                padding-left: 14px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #0d1117;
                color: #c9d1d9;
            }
        )");
    }
}
