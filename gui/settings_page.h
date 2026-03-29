#pragma once
#include <QWidget>
#include <QLineEdit>
#include <QCheckBox>
#include <QLabel>
#include <QSpinBox>

class SettingsPage : public QWidget {
    Q_OBJECT
public:
    explicit SettingsPage(QWidget *parent = nullptr);
signals:
    void settingsChanged();
private:
    void setupUi();
    void saveSettings();
    QLineEdit *m_storagePath;
    QSpinBox  *m_quotaSpin;
    QCheckBox *m_leechCheck;
    QLineEdit *m_smbUser;
    QLabel    *m_savedLabel;
};
