#include "addnode_page.h"
#include "api_client.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QFrame>
#include <QClipboard>
#include <QApplication>
#include <QJsonArray>

static const char *WORD_BOX_STYLE = R"(
    QFrame {
        background-color: #0d1117;
        border: 1px solid #58a6ff;
        border-radius: 8px;
    }
)";

AddNodePage::AddNodePage(QWidget *parent) : QWidget(parent) {
    setupUi();
    m_countdownTimer = new QTimer(this);
    connect(m_countdownTimer, &QTimer::timeout, this, [this]{
        --m_secondsLeft;
        if (m_secondsLeft <= 0) {
            m_countdownTimer->stop();
            m_timerLabel->setText("⏱ Expired — go back and regenerate");
            m_timerLabel->setStyleSheet("color: #f85149; font-size: 12px;");
        } else {
            int m = m_secondsLeft / 60, s = m_secondsLeft % 60;
            m_timerLabel->setText(QString("⏱ Expires in %1:%2")
                .arg(m, 2, 10, QLatin1Char('0'))
                .arg(s, 2, 10, QLatin1Char('0')));
        }
    });
}

void AddNodePage::setupUi() {
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(40, 32, 40, 32);
    root->setSpacing(20);

    // Title.
    auto *title = new QLabel("Add a Node");
    title->setStyleSheet("color: #c9d1d9; font-size: 20px; font-weight: bold;");
    root->addWidget(title);

    auto *subtitle = new QLabel(
        "Share the B32 address and passphrase with the machine you want to add.");
    subtitle->setStyleSheet("color: #6e7681; font-size: 12px;");
    subtitle->setWordWrap(true);
    root->addWidget(subtitle);

    root->addSpacing(8);

    // ── B32 section ──────────────────────────────────────────────────────
    auto *b32Head = new QLabel("B32 ADDRESS");
    b32Head->setStyleSheet("color: #58a6ff; font-size: 11px; letter-spacing: 1px;");
    root->addWidget(b32Head);

    auto *b32Card = new QFrame;
    b32Card->setStyleSheet(R"(
        QFrame {
            background-color: #161b22;
            border: 1px solid #21262d;
            border-radius: 8px;
        }
    )");
    auto *b32Row = new QHBoxLayout(b32Card);
    b32Row->setContentsMargins(16, 12, 12, 12);

    m_b32Label = new QLabel("—");
    m_b32Label->setStyleSheet(
        "color: #c9d1d9; font-size: 13px; font-family: monospace;");
    m_b32Label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_b32Label->setWordWrap(true);
    b32Row->addWidget(m_b32Label, 1);

    auto *copyBtn = new QPushButton("Copy");
    copyBtn->setCursor(Qt::PointingHandCursor);
    copyBtn->setFixedSize(64, 32);
    copyBtn->setStyleSheet(R"(
        QPushButton {
            background-color: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 6px;
            font-size: 12px;
        }
        QPushButton:hover { background-color: #30363d; }
        QPushButton:pressed { background-color: #58a6ff; color: #0d1117; }
    )");
    connect(copyBtn, &QPushButton::clicked, this, [this]{
        QApplication::clipboard()->setText(m_b32Label->text());
    });
    b32Row->addWidget(copyBtn);

    root->addWidget(b32Card);

    // ── Passphrase section ───────────────────────────────────────────────
    auto *phraseHead = new QLabel("PASSPHRASE");
    phraseHead->setStyleSheet("color: #58a6ff; font-size: 11px; letter-spacing: 1px;");
    root->addWidget(phraseHead);

    auto *phraseHint = new QLabel(
        "The new node must enter all three words exactly as shown.");
    phraseHint->setStyleSheet("color: #6e7681; font-size: 11px;");
    root->addWidget(phraseHint);

    auto *wordsRow = new QHBoxLayout;
    wordsRow->setSpacing(12);

    auto makeWordBox = [&](QLabel *&label) {
        auto *frame = new QFrame;
        frame->setStyleSheet(WORD_BOX_STYLE);
        frame->setFixedHeight(64);
        auto *bl = new QVBoxLayout(frame);
        bl->setContentsMargins(0, 0, 0, 0);
        label = new QLabel("—");
        label->setAlignment(Qt::AlignCenter);
        label->setStyleSheet(
            "color: #3fb950;"
            "font-size: 18px;"
            "font-weight: bold;"
            "letter-spacing: 1px;"
            "border: none;"
        );
        bl->addWidget(label);
        wordsRow->addWidget(frame);
    };

    makeWordBox(m_word0);
    makeWordBox(m_word1);
    makeWordBox(m_word2);
    root->addLayout(wordsRow);

    // Timer.
    m_timerLabel = new QLabel("⏱ —");
    m_timerLabel->setStyleSheet("color: #d29922; font-size: 12px;");
    root->addWidget(m_timerLabel);

    root->addStretch();

    // ── Actions ───────────────────────────────────────────────────────────
    auto *btnRow = new QHBoxLayout;

    auto *doneBtn = new QPushButton("Done");
    doneBtn->setCursor(Qt::PointingHandCursor);
    doneBtn->setFixedSize(100, 36);
    doneBtn->setStyleSheet(R"(
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
    connect(doneBtn, &QPushButton::clicked, this, &AddNodePage::done);

    btnRow->addStretch();
    btnRow->addWidget(doneBtn);
    root->addLayout(btnRow);
}

void AddNodePage::loadInvite(QNetworkAccessManager *net, const QString &apiBase) {
    m_countdownTimer->stop();
    m_secondsLeft = 600;
    ApiClient::get(net, apiBase + "/v1/invite",
        [this](const QJsonObject &inv) { applyInvite(inv); });
}

void AddNodePage::applyInvite(const QJsonObject &inv) {
    m_b32Label->setText(inv.value("b32").toString());
    auto phrase = inv.value("phrase").toArray();
    m_word0->setText(phrase[0].toString());
    m_word1->setText(phrase[1].toString());
    m_word2->setText(phrase[2].toString());
    startCountdown();
}

void AddNodePage::startCountdown() {
    m_secondsLeft = 600;
    m_timerLabel->setStyleSheet("color: #d29922; font-size: 12px;");
    m_countdownTimer->start(1000);
}
