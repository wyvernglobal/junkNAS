#pragma once
#include <QWidget>
#include <QJsonObject>
#include <QTableWidget>
#include <QLabel>

class PeersPage : public QWidget {
    Q_OBJECT
public:
    explicit PeersPage(QWidget *parent = nullptr);
public slots:
    void onStatus(const QJsonObject &status);
private:
    void setupUi();
    QTableWidget *m_table;
    QLabel       *m_emptyLabel;
};
