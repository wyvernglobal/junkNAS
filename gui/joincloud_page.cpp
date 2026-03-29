#include "joincloud_page.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QFrame>
#include <QJsonArray>
#include <QIntValidator>

static const char *INPUT_STYLE = R"(
    QLineEdit {
        background-color: #0d1117;
        color: #c9d1d9;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 8px 12px;
        font-size: 13px;
        font-family: monospace;
    }
    QLineEdit:focus {
        border-color: #58a6ff;
    }
    QLineEdit::placeholder {
        color: #6e7681;
    }
)";

JoinCloudPage::JoinCloudPage(QWidget *parent) : QWidget(parent) {
    setupUi();
}

void JoinCloudPage::setupUi() {
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(40, 32, 40, 32);
    root->setSpacing(16);

    // ── Title ─────────────────────────────────────────────────────────────
    auto *title = new QLabel("Join a JunkNAS Cloud");
    title->setStyleSheet("color: #c9d1d9; font-size: 20px; font-weight: bold;");
    root->addWidget(title);

    auto *sub = new QLabel(
        "Enter the B32 address and passphrase provided by an existing node.");
    sub->setStyleSheet("color: #6e7681; font-size: 12px;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    root->addSpacing(8);

    // ── B32 input ─────────────────────────────────────────────────────────
    auto *b32Head = new QLabel("B32 ADDRESS OF EXISTING NODE");
    b32Head->setStyleSheet("color: #58a6ff; font-size: 11px; letter-spacing: 1px;");
    root->addWidget(b32Head);

    m_b32Input = new QLineEdit;
    m_b32Input->setPlaceholderText("abc123…b32.i2p");
    m_b32Input->setStyleSheet(INPUT_STYLE);
    m_b32Input->setFixedHeight(40);
    root->addWidget(m_b32Input);

    // ── Passphrase ────────────────────────────────────────────────────────
    auto *phraseHead = new QLabel("PASSPHRASE");
    phraseHead->setStyleSheet("color: #58a6ff; font-size: 11px; letter-spacing: 1px;");
    root->addWidget(phraseHead);

    auto *phraseHint = new QLabel("Enter each word in a separate field.");
    phraseHint->setStyleSheet("color: #6e7681; font-size: 11px;");
    root->addWidget(phraseHint);

    auto *wordsRow = new QHBoxLayout;
    wordsRow->setSpacing(12);

    auto makeWord = [&](QLineEdit *&field, const QString &ph) {
        field = new QLineEdit;
        field->setPlaceholderText(ph);
        field->setStyleSheet(INPUT_STYLE);
        field->setFixedHeight(44);
        field->setAlignment(Qt::AlignCenter);
        wordsRow->addWidget(field);
    };

    makeWord(m_word0, "first word");
    makeWord(m_word1, "second word");
    makeWord(m_word2, "third word");
    root->addLayout(wordsRow);

    // ── Storage options ───────────────────────────────────────────────────
    auto *optHead = new QLabel("STORAGE OPTIONS");
    optHead->setStyleSheet("color: #58a6ff; font-size: 11px; letter-spacing: 1px;");
    root->addWidget(optHead);

    m_storeCheck = new QCheckBox("Store files on this device");
    m_storeCheck->setChecked(true);
    m_storeCheck->setStyleSheet(R"(
        QCheckBox { color: #c9d1d9; font-size: 13px; spacing: 8px; }
        QCheckBox::indicator {
            width: 16px; height: 16px;
            border: 1px solid #30363d;
            border-radius: 3px;
            background: #0d1117;
        }
        QCheckBox::indicator:checked {
            background: #238636;
            border-color: #238636;
        }
    )");
    root->addWidget(m_storeCheck);

    auto *quotaRow = new QHBoxLayout;
    auto *quotaLabel = new QLabel("Quota (GiB):");
    quotaLabel->setStyleSheet("color: #6e7681; font-size: 12px;");
    m_quotaInput = new QLineEdit("100");
    m_quotaInput->setValidator(new QIntValidator(1, 1000000, this));
    m_quotaInput->setStyleSheet(INPUT_STYLE);
    m_quotaInput->setFixedWidth(120);
    m_quotaInput->setFixedHeight(36);
    quotaRow->addWidget(quotaLabel);
    quotaRow->addWidget(m_quotaInput);
    quotaRow->addStretch();

    // Toggle quota input visibility with checkbox.
    connect(m_storeCheck, &QCheckBox::toggled, this, [this, quotaLabel](bool checked){
        m_quotaInput->setVisible(checked);
        quotaLabel->setVisible(checked);
    });

    root->addLayout(quotaRow);

    // ── Error label ───────────────────────────────────────────────────────
    m_errorLabel = new QLabel("");
    m_errorLabel->setStyleSheet("color: #f85149; font-size: 12px;");
    m_errorLabel->setWordWrap(true);
    m_errorLabel->setVisible(false);
    root->addWidget(m_errorLabel);

    root->addStretch();

    // ── Buttons ───────────────────────────────────────────────────────────
    auto *btnRow = new QHBoxLayout;

    auto *clearBtn = new QPushButton("Clear");
    clearBtn->setCursor(Qt::PointingHandCursor);
    clearBtn->setFixedSize(90, 36);
    clearBtn->setStyleSheet(R"(
        QPushButton {
            background-color: transparent;
            color: #6e7681;
            border: 1px solid #30363d;
            border-radius: 6px;
            font-size: 13px;
        }
        QPushButton:hover { border-color: #58a6ff; color: #c9d1d9; }
    )");
    connect(clearBtn, &QPushButton::clicked, this, [this]{
        m_b32Input->clear();
        m_word0->clear();
        m_word1->clear();
        m_word2->clear();
        clearError();
    });

    auto *joinBtn = new QPushButton("Join Cloud");
    joinBtn->setCursor(Qt::PointingHandCursor);
    joinBtn->setFixedSize(120, 36);
    joinBtn->setStyleSheet(R"(
        QPushButton {
            background-color: #1f6feb;
            color: #ffffff;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: bold;
        }
        QPushButton:hover { background-color: #388bfd; }
        QPushButton:pressed { background-color: #1158c7; }
    )");
    connect(joinBtn, &QPushButton::clicked, this, &JoinCloudPage::attemptJoin);

    btnRow->addStretch();
    btnRow->addWidget(clearBtn);
    btnRow->addSpacing(8);
    btnRow->addWidget(joinBtn);
    root->addLayout(btnRow);
}

void JoinCloudPage::attemptJoin() {
    clearError();

    QString b32 = m_b32Input->text().trimmed();
    QString w0  = m_word0->text().trimmed().toLower();
    QString w1  = m_word1->text().trimmed().toLower();
    QString w2  = m_word2->text().trimmed().toLower();

    if (b32.isEmpty() || w0.isEmpty() || w1.isEmpty() || w2.isEmpty()) {
        setError("All fields are required.");
        return;
    }
    if (!b32.endsWith(".b32.i2p") && !b32.endsWith(".i2p")) {
        setError("B32 address should end with .b32.i2p");
        return;
    }

    qint64 quotaGB = m_quotaInput->text().toLongLong();
    if (quotaGB <= 0) quotaGB = 100;

    QJsonObject payload;
    payload["target_b32"]  = b32;
    payload["phrase"]      = QJsonArray{w0, w1, w2};
    payload["role"]        = m_storeCheck->isChecked() ? "storage" : "leech";
    payload["quota_bytes"] = quotaGB * (1LL << 30);

    emit joinRequested(payload);
}

void JoinCloudPage::setError(const QString &msg) {
    m_errorLabel->setText("⚠  " + msg);
    m_errorLabel->setVisible(true);
}

void JoinCloudPage::clearError() {
    m_errorLabel->clear();
    m_errorLabel->setVisible(false);
}
