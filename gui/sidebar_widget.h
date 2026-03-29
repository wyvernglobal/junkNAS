#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QMap>

class SidebarWidget : public QWidget {
    Q_OBJECT
public:
    explicit SidebarWidget(QWidget *parent = nullptr);
    void setActivePage(const QString &page);

signals:
    void pageRequested(const QString &page);

private:
    QPushButton *makeNavBtn(const QString &icon, const QString &label, const QString &page);
    void styleBtn(QPushButton *btn, bool active);

    QMap<QString, QPushButton*> m_btns;
    QString m_activePage{"dashboard"};
};
