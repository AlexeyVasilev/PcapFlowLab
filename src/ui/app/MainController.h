#pragma once

#include <QObject>
#include <QString>

#include "app/session/CaptureSession.h"

namespace pfl {

class MainController final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString currentInputPath READ currentInputPath NOTIFY stateChanged)
    Q_PROPERTY(bool hasCapture READ hasCapture NOTIFY stateChanged)
    Q_PROPERTY(qulonglong packetCount READ packetCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong flowCount READ flowCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong totalBytes READ totalBytes NOTIFY stateChanged)

public:
    explicit MainController(QObject* parent = nullptr);

    [[nodiscard]] QString currentInputPath() const;
    [[nodiscard]] bool hasCapture() const noexcept;
    [[nodiscard]] qulonglong packetCount() const noexcept;
    [[nodiscard]] qulonglong flowCount() const noexcept;
    [[nodiscard]] qulonglong totalBytes() const noexcept;

    Q_INVOKABLE bool openCaptureFile(const QString& path);
    Q_INVOKABLE bool openIndexFile(const QString& path);

signals:
    void stateChanged();

private:
    bool openPath(const QString& path, bool asIndex);

    CaptureSession session_ {};
    QString current_input_path_ {};
};

}  // namespace pfl
