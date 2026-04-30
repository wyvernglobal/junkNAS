#pragma once

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUrl>
#include <functional>

// ApiClient provides static async helpers for GET and POST requests
// to the local junknasd REST API. Callbacks receive a QJsonObject.
class ApiClient {
public:
    using Callback = std::function<void(const QJsonObject &)>;
    using ErrorCb  = std::function<void(const QString &)>;

    static void get(QNetworkAccessManager *net,
                    const QString &url,
                    Callback onSuccess,
                    ErrorCb  onError = nullptr)
    {
        QNetworkRequest req{QUrl(url)};
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        auto *reply = net->get(req);

        QObject::connect(reply, &QNetworkReply::finished, reply, [reply, onSuccess, onError]{
            reply->deleteLater();
            if (reply->error() != QNetworkReply::NoError) {
                if (onError) onError(reply->errorString());
                return;
            }
            auto doc = QJsonDocument::fromJson(reply->readAll());
            if (onSuccess) onSuccess(doc.object());
        });
    }

    static void post(QNetworkAccessManager *net,
                     const QString &url,
                     const QJsonObject &payload,
                     Callback onSuccess,
                     ErrorCb  onError = nullptr)
    {
        QNetworkRequest req{QUrl(url)};
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        auto body = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        auto *reply = net->post(req, body);

        QObject::connect(reply, &QNetworkReply::finished, reply, [reply, onSuccess, onError]{
            reply->deleteLater();
            if (reply->error() != QNetworkReply::NoError) {
                if (onError) onError(reply->errorString());
                return;
            }
            auto doc = QJsonDocument::fromJson(reply->readAll());
            if (onSuccess) onSuccess(doc.object());
        });
    }
};
