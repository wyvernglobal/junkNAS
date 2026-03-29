#pragma once
#include <QWidget>
#include <QJsonObject>
#include <QLabel>
#include <QTableWidget>
#include <QFrame>

class DashboardPage : public QWidget {
    Q_OBJECT
public:
    explicit DashboardPage(QWidget *parent = nullptr);

public slots:
    void onStatus(const QJsonObject &status);

private:
    void setupUi();
    void updateSelfCard(const QJsonObject &self);
    void updateNetworkCard(const QJsonObject &status);
    void updatePeersTable(const QJsonObject &status);

    QLabel        *m_b32Label;
    QLabel        *m_roleLabel;
    QLabel        *m_quotaLabel;
    QLabel        *m_pathLabel;
    QLabel        *m_peerCountLabel;
    QLabel        *m_storageCountLabel;
    QLabel        *m_mountLabel;
    QTableWidget  *m_peersTable;
    QLabel        *m_statusBar;
};
