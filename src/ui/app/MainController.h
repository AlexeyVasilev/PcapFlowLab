#pragma once

#include <filesystem>

#include <QObject>
#include <QString>

#include "app/session/CaptureSession.h"
#include "ui/app/FlowListModel.h"
#include "ui/app/PacketDetailsViewModel.h"
#include "ui/app/PacketListModel.h"

namespace pfl {

class MainController final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString currentInputPath READ currentInputPath NOTIFY stateChanged)
    Q_PROPERTY(QString openErrorText READ openErrorText NOTIFY openErrorTextChanged)
    Q_PROPERTY(bool hasCapture READ hasCapture NOTIFY stateChanged)
    Q_PROPERTY(qulonglong packetCount READ packetCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong flowCount READ flowCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong totalBytes READ totalBytes NOTIFY stateChanged)
    Q_PROPERTY(QObject* flowModel READ flowModel CONSTANT)
    Q_PROPERTY(QObject* packetModel READ packetModel CONSTANT)
    Q_PROPERTY(QObject* packetDetailsModel READ packetDetailsModel CONSTANT)
    Q_PROPERTY(int selectedFlowIndex READ selectedFlowIndex WRITE setSelectedFlowIndex NOTIFY selectedFlowIndexChanged)
    Q_PROPERTY(qulonglong selectedPacketIndex READ selectedPacketIndex WRITE setSelectedPacketIndex NOTIFY selectedPacketIndexChanged)
    Q_PROPERTY(QString flowFilterText READ flowFilterText WRITE setFlowFilterText NOTIFY flowFilterTextChanged)
    Q_PROPERTY(int flowSortColumn READ flowSortColumn NOTIFY flowSortChanged)
    Q_PROPERTY(bool flowSortAscending READ flowSortAscending NOTIFY flowSortChanged)

public:
    explicit MainController(QObject* parent = nullptr);

    [[nodiscard]] QString currentInputPath() const;
    [[nodiscard]] QString openErrorText() const;
    [[nodiscard]] bool hasCapture() const noexcept;
    [[nodiscard]] qulonglong packetCount() const noexcept;
    [[nodiscard]] qulonglong flowCount() const noexcept;
    [[nodiscard]] qulonglong totalBytes() const noexcept;
    [[nodiscard]] QObject* flowModel() noexcept;
    [[nodiscard]] QObject* packetModel() noexcept;
    [[nodiscard]] QObject* packetDetailsModel() noexcept;
    [[nodiscard]] int selectedFlowIndex() const noexcept;
    [[nodiscard]] qulonglong selectedPacketIndex() const noexcept;
    [[nodiscard]] QString flowFilterText() const;
    [[nodiscard]] int flowSortColumn() const noexcept;
    [[nodiscard]] bool flowSortAscending() const noexcept;

    Q_INVOKABLE bool openCaptureFile(const QString& path);
    Q_INVOKABLE bool openIndexFile(const QString& path);
    Q_INVOKABLE void browseCaptureFile();
    Q_INVOKABLE void browseIndexFile();
    Q_INVOKABLE void sortFlows(int column);

    void setSelectedFlowIndex(int index);
    void setSelectedPacketIndex(qulonglong packetIndex);
    void setFlowFilterText(const QString& text);

signals:
    void stateChanged();
    void openErrorTextChanged();
    void selectedFlowIndexChanged();
    void selectedPacketIndexChanged();
    void flowFilterTextChanged();
    void flowSortChanged();

private:
    bool openPath(const QString& path, bool asIndex);
    void clearPacketSelection();
    void clearFlowSelection();
    void synchronizeFlowSelection();
    void setOpenErrorText(const QString& text);
    QString chooseFile(bool forIndex) const;
    void setLastDirectoryFromPath(const std::filesystem::path& path);

    CaptureSession session_ {};
    FlowListModel flow_model_ {};
    PacketListModel packet_model_ {};
    PacketDetailsViewModel packet_details_model_ {};
    QString current_input_path_ {};
    QString open_error_text_ {};
    QString last_directory_path_ {};
    int selected_flow_index_ {-1};
    qulonglong selected_packet_index_ {0};
};

}  // namespace pfl
