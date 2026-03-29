#pragma once
#include <QWidget>
#include <QJsonObject>
#include <QLineEdit>
#include <QLabel>
#include <QCheckBox>

class JoinCloudPage : public QWidget {
    Q_OBJECT
public:
    explicit JoinCloudPage(QWidget *parent = nullptr);

signals:
    void joinRequested(const QJsonObject &payload);

private:
    void setupUi();
    void attemptJoin();
    void setError(const QString &msg);
    void clearError();

    QLineEdit *m_b32Input;
    QLineEdit *m_word0, *m_word1, *m_word2;
    QCheckBox *m_storeCheck;
    QLineEdit *m_quotaInput;
    QLabel    *m_errorLabel;
};
