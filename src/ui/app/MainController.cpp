#include "ui/app/MainController.h"

#include <filesystem>

namespace pfl {

MainController::MainController(QObject* parent)
    : QObject(parent) {
}

QString MainController::currentInputPath() const {
    return current_input_path_;
}

bool MainController::hasCapture() const noexcept {
    return session_.has_capture();
}

qulonglong MainController::packetCount() const noexcept {
    return static_cast<qulonglong>(session_.summary().packet_count);
}

qulonglong MainController::flowCount() const noexcept {
    return static_cast<qulonglong>(session_.summary().flow_count);
}

qulonglong MainController::totalBytes() const noexcept {
    return static_cast<qulonglong>(session_.summary().total_bytes);
}

bool MainController::openCaptureFile(const QString& path) {
    return openPath(path, false);
}

bool MainController::openIndexFile(const QString& path) {
    return openPath(path, true);
}

bool MainController::openPath(const QString& path, const bool asIndex) {
    const QString trimmed_path = path.trimmed();
    if (trimmed_path.isEmpty()) {
        current_input_path_.clear();
        session_ = {};
        emit stateChanged();
        return false;
    }

    const std::filesystem::path filesystem_path = std::filesystem::path {trimmed_path.toStdWString()};
    const bool opened = asIndex ? session_.load_index(filesystem_path) : session_.open_capture(filesystem_path);

    if (!opened) {
        current_input_path_.clear();
        session_ = {};
        emit stateChanged();
        return false;
    }

    current_input_path_ = trimmed_path;
    emit stateChanged();
    return true;
}

}  // namespace pfl
