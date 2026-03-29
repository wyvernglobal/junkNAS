#include "settings_page.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QFileDialog>
#include <QFrame>

static const char *SETTING_INPUT = R"(
    QLineEdit, QSpinBox {
        background-color: #0d1117;
        color: #c9d1d9;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 6px 10px;
        font-size: 13px;
    }
    QLineEdit:focus, QSpinBox:focus { border-color: #58a6ff; }
)";

SettingsPage::SettingsPage(QWidget *parent) : QWidget(parent) { setupUi(); }

void SettingsPage::setupUi() {
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(40, 32, 40, 32);
    root->setSpacing(24);

    auto *title = new QLabel("Settings");
    title->setStyleSheet("color: #c9d1d9; font-size: 20px; font-weight: bold;");
    root->addWidget(title);

    // ── Storage section ───────────────────────────────────────────────────
    auto sectionHead = [](const QString &t) {
        auto *l = new QLabel(t);
        l->setStyleSheet("color: #58a6ff; font-size: 11px; letter-spacing: 1px;");
        return l;
    };

    root->addWidget(sectionHead("STORAGE"));

    m_leechCheck = new QCheckBox("Do not store files on this device  (leech mode)");
    m_leechCheck->setStyleSheet(R"(
        QCheckBox { color: #c9d1d9; font-size: 13px; spacing: 8px; }
        QCheckBox::indicator {
            width: 16px; height: 16px;
            border: 1px solid #30363d; border-radius: 3px;
            background: #0d1117;
        }
        QCheckBox::indicator:checked { background: #1f6feb; border-color: #1f6feb; }
    )");
    root->addWidget(m_leechCheck);

    auto *pathRow = new QHBoxLayout;
    m_storagePath = new QLineEdit;
    m_storagePath->setPlaceholderText("/var/junknas/storage");
    m_storagePath->setStyleSheet(SETTING_INPUT);
    m_storagePath->setFixedHeight(38);
    auto *browseBtn = new QPushButton("Browse…");
    browseBtn->setCursor(Qt::PointingHandCursor);
    browseBtn->setFixedSize(90, 38);
    browseBtn->setStyleSheet(R"(
        QPushButton {
            background-color: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 6px;
            font-size: 12px;
        }
        QPushButton:hover { background-color: #30363d; }
    )");
    connect(browseBtn, &QPushButton::clicked, this, [this]{
        QString dir = QFileDialog::getExistingDirectory(this, "Select storage directory");
        if (!dir.isEmpty()) m_storagePath->setText(dir);
    });
    pathRow->addWidget(m_storagePath);
    pathRow->addWidget(browseBtn);
    root->addLayout(pathRow);

    // Toggle path input with leech check.
    connect(m_leechCheck, &QCheckBox::toggled, this, [this, browseBtn](bool leech){
        m_storagePath->setEnabled(!leech);
        browseBtn->setEnabled(!leech);
        m_quotaSpin->setEnabled(!leech);
    });

    auto *quotaRow = new QHBoxLayout;
    auto *quotaLbl = new QLabel("Storage quota (GiB):");
    quotaLbl->setStyleSheet("color: #6e7681; font-size: 12px;");
    m_quotaSpin = new QSpinBox;
    m_quotaSpin->setRange(1, 1000000);
    m_quotaSpin->setValue(100);
    m_quotaSpin->setSuffix(" GiB");
    m_quotaSpin->setStyleSheet(SETTING_INPUT);
    m_quotaSpin->setFixedWidth(150);
    quotaRow->addWidget(quotaLbl);
    quotaRow->addWidget(m_quotaSpin);
    quotaRow->addStretch();
    root->addLayout(quotaRow);

    // ── Samba section ─────────────────────────────────────────────────────
    root->addWidget(sectionHead("SAMBA"));

    auto *smbRow = new QHBoxLayout;
    auto *smbLbl = new QLabel("Samba user:");
    smbLbl->setStyleSheet("color: #6e7681; font-size: 12px;");
    m_smbUser = new QLineEdit("junknas");
    m_smbUser->setStyleSheet(SETTING_INPUT);
    m_smbUser->setFixedWidth(200);
    m_smbUser->setFixedHeight(38);
    smbRow->addWidget(smbLbl);
    smbRow->addWidget(m_smbUser);
    smbRow->addStretch();
    root->addLayout(smbRow);

    root->addStretch();

    // ── Save button ───────────────────────────────────────────────────────
    m_savedLabel = new QLabel("");
    m_savedLabel->setStyleSheet("color: #3fb950; font-size: 12px;");
    root->addWidget(m_savedLabel);

    auto *saveBtn = new QPushButton("Save Settings");
    saveBtn->setCursor(Qt::PointingHandCursor);
    saveBtn->setFixedSize(140, 38);
    saveBtn->setStyleSheet(R"(
        QPushButton {
            background-color: #238636;
            color: #ffffff;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: bold;
        }
        QPushButton:hover { background-color: #2ea043; }
    )");
    connect(saveBtn, &QPushButton::clicked, this, &SettingsPage::saveSettings);
    root->addWidget(saveBtn);
}

void SettingsPage::saveSettings() {
    // In the real implementation this POSTs to /v1/settings on the daemon.
    // The daemon then rewrites smb.conf, adjusts the mergerfs quota, etc.
    m_savedLabel->setText("✓ Settings saved");
    emit settingsChanged();
}
