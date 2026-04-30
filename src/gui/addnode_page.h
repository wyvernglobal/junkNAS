#pragma once
#include <QWidget>
#include <QLabel>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QJsonObject>

class AddNodePage : public QWidget {
    Q_OBJECT
public:
    explicit AddNodePage(QWidget *parent = nullptr);
    void loadInvite(QNetworkAccessManager *net, const QString &apiBase);

signals:
    void done();

private:
    void setupUi();
    void applyInvite(const QJsonObject &inv);
    void startCountdown();

    QLabel *m_b32Label;
    QLabel *m_word0, *m_word1, *m_word2;
    QLabel *m_timerLabel;
    QLabel *m_hintLabel;
    QTimer *m_countdownTimer;
    int     m_secondsLeft{600};
};
