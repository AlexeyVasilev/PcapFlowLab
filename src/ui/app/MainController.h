#pragma once

#include <filesystem>
#include <map>
#include <memory>
#include <vector>

#include <QObject>
#include <QString>

#include "app/session/CaptureSession.h"
#include "core/services/AnalysisSettings.h"
#include "../../../core/open_progress.h"
#include "ui/app/FlowListModel.h"
#include "ui/app/PacketDetailsViewModel.h"
#include "ui/app/PacketListModel.h"
#include "ui/app/StreamListModel.h"
#include "ui/app/TopSummaryListModel.h"

class QThread;

namespace pfl {

class MainController final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString currentInputPath READ currentInputPath NOTIFY stateChanged)
    Q_PROPERTY(QString openErrorText READ openErrorText NOTIFY openErrorTextChanged)
    Q_PROPERTY(QString statusText READ statusText NOTIFY statusTextChanged)
    Q_PROPERTY(bool statusIsError READ statusIsError NOTIFY statusTextChanged)
    Q_PROPERTY(bool hasCapture READ hasCapture NOTIFY stateChanged)
    Q_PROPERTY(bool hasSourceCapture READ hasSourceCapture NOTIFY sourceAvailabilityChanged)
    Q_PROPERTY(bool openedFromIndex READ openedFromIndex NOTIFY sourceAvailabilityChanged)
    Q_PROPERTY(bool canAttachSourceCapture READ canAttachSourceCapture NOTIFY actionAvailabilityChanged)
    Q_PROPERTY(bool canSaveIndex READ canSaveIndex NOTIFY actionAvailabilityChanged)
    Q_PROPERTY(bool partialOpen READ partialOpen NOTIFY stateChanged)
    Q_PROPERTY(QString partialOpenWarningText READ partialOpenWarningText NOTIFY stateChanged)
    Q_PROPERTY(bool canExportSelectedFlow READ canExportSelectedFlow NOTIFY actionAvailabilityChanged)
    Q_PROPERTY(bool isOpening READ isOpening NOTIFY openProgressChanged)
    Q_PROPERTY(qulonglong openProgressPackets READ openProgressPackets NOTIFY openProgressChanged)
    Q_PROPERTY(qulonglong openProgressBytes READ openProgressBytes NOTIFY openProgressChanged)
    Q_PROPERTY(qulonglong openProgressTotalBytes READ openProgressTotalBytes NOTIFY openProgressChanged)
    Q_PROPERTY(double openProgressPercent READ openProgressPercent NOTIFY openProgressChanged)
    Q_PROPERTY(bool packetsLoading READ packetsLoading NOTIFY packetListStateChanged)
    Q_PROPERTY(bool packetsPartiallyLoaded READ packetsPartiallyLoaded NOTIFY packetListStateChanged)
    Q_PROPERTY(qulonglong loadedPacketRowCount READ loadedPacketRowCount NOTIFY packetListStateChanged)
    Q_PROPERTY(qulonglong totalPacketRowCount READ totalPacketRowCount NOTIFY packetListStateChanged)
    Q_PROPERTY(bool canLoadMorePackets READ canLoadMorePackets NOTIFY packetListStateChanged)
    Q_PROPERTY(bool streamLoading READ streamLoading NOTIFY streamListStateChanged)
    Q_PROPERTY(bool streamPartiallyLoaded READ streamPartiallyLoaded NOTIFY streamListStateChanged)
    Q_PROPERTY(qulonglong loadedStreamItemCount READ loadedStreamItemCount NOTIFY streamListStateChanged)
    Q_PROPERTY(qulonglong totalStreamItemCount READ totalStreamItemCount NOTIFY streamListStateChanged)
    Q_PROPERTY(bool canLoadMoreStreamItems READ canLoadMoreStreamItems NOTIFY streamListStateChanged)
    Q_PROPERTY(qulonglong packetCount READ packetCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong flowCount READ flowCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong totalBytes READ totalBytes NOTIFY stateChanged)
    Q_PROPERTY(qulonglong tcpFlowCount READ tcpFlowCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong tcpPacketCount READ tcpPacketCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong tcpTotalBytes READ tcpTotalBytes NOTIFY stateChanged)
    Q_PROPERTY(qulonglong udpFlowCount READ udpFlowCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong udpPacketCount READ udpPacketCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong udpTotalBytes READ udpTotalBytes NOTIFY stateChanged)
    Q_PROPERTY(qulonglong otherFlowCount READ otherFlowCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong otherPacketCount READ otherPacketCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong otherTotalBytes READ otherTotalBytes NOTIFY stateChanged)
    Q_PROPERTY(qulonglong ipv4FlowCount READ ipv4FlowCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong ipv6FlowCount READ ipv6FlowCount NOTIFY stateChanged)
    Q_PROPERTY(int captureOpenMode READ captureOpenMode WRITE setCaptureOpenMode NOTIFY captureOpenModeChanged)
    Q_PROPERTY(bool httpUsePathAsServiceHint READ httpUsePathAsServiceHint WRITE setHttpUsePathAsServiceHint NOTIFY httpUsePathAsServiceHintChanged)
    Q_PROPERTY(int currentTabIndex READ currentTabIndex WRITE setCurrentTabIndex NOTIFY currentTabIndexChanged)
    Q_PROPERTY(QObject* topEndpointsModel READ topEndpointsModel CONSTANT)
    Q_PROPERTY(QObject* topPortsModel READ topPortsModel CONSTANT)
    Q_PROPERTY(QObject* flowModel READ flowModel CONSTANT)
    Q_PROPERTY(QObject* packetModel READ packetModel CONSTANT)
    Q_PROPERTY(QObject* streamModel READ streamModel CONSTANT)
    Q_PROPERTY(QObject* packetDetailsModel READ packetDetailsModel CONSTANT)
    Q_PROPERTY(int selectedFlowIndex READ selectedFlowIndex WRITE setSelectedFlowIndex NOTIFY selectedFlowIndexChanged)
    Q_PROPERTY(qulonglong selectedPacketIndex READ selectedPacketIndex WRITE setSelectedPacketIndex NOTIFY selectedPacketIndexChanged)
    Q_PROPERTY(qulonglong selectedStreamItemIndex READ selectedStreamItemIndex WRITE setSelectedStreamItemIndex NOTIFY selectedStreamItemIndexChanged)
    Q_PROPERTY(QString flowFilterText READ flowFilterText WRITE setFlowFilterText NOTIFY flowFilterTextChanged)
    Q_PROPERTY(int flowSortColumn READ flowSortColumn NOTIFY flowSortChanged)
    Q_PROPERTY(bool flowSortAscending READ flowSortAscending NOTIFY flowSortChanged)

public:
    explicit MainController(QObject* parent = nullptr);
    ~MainController() override;

    [[nodiscard]] QString currentInputPath() const;
    [[nodiscard]] QString openErrorText() const;
    [[nodiscard]] QString statusText() const;
    [[nodiscard]] bool statusIsError() const noexcept;
    [[nodiscard]] bool hasCapture() const noexcept;
    [[nodiscard]] bool hasSourceCapture() const noexcept;
    [[nodiscard]] bool openedFromIndex() const noexcept;
    [[nodiscard]] bool canAttachSourceCapture() const noexcept;
    [[nodiscard]] bool canSaveIndex() const noexcept;
    [[nodiscard]] bool partialOpen() const noexcept;
    [[nodiscard]] QString partialOpenWarningText() const;
    [[nodiscard]] bool canExportSelectedFlow() const noexcept;
    [[nodiscard]] bool isOpening() const noexcept;
    [[nodiscard]] qulonglong openProgressPackets() const noexcept;
    [[nodiscard]] qulonglong openProgressBytes() const noexcept;
    [[nodiscard]] qulonglong openProgressTotalBytes() const noexcept;
    [[nodiscard]] double openProgressPercent() const noexcept;
    [[nodiscard]] bool packetsLoading() const noexcept;
    [[nodiscard]] bool packetsPartiallyLoaded() const noexcept;
    [[nodiscard]] qulonglong loadedPacketRowCount() const noexcept;
    [[nodiscard]] qulonglong totalPacketRowCount() const noexcept;
    [[nodiscard]] bool canLoadMorePackets() const noexcept;
    [[nodiscard]] bool streamLoading() const noexcept;
    [[nodiscard]] bool streamPartiallyLoaded() const noexcept;
    [[nodiscard]] qulonglong loadedStreamItemCount() const noexcept;
    [[nodiscard]] qulonglong totalStreamItemCount() const noexcept;
    [[nodiscard]] bool canLoadMoreStreamItems() const noexcept;
    [[nodiscard]] qulonglong packetCount() const noexcept;
    [[nodiscard]] qulonglong flowCount() const noexcept;
    [[nodiscard]] qulonglong totalBytes() const noexcept;
    [[nodiscard]] qulonglong tcpFlowCount() const noexcept;
    [[nodiscard]] qulonglong tcpPacketCount() const noexcept;
    [[nodiscard]] qulonglong tcpTotalBytes() const noexcept;
    [[nodiscard]] qulonglong udpFlowCount() const noexcept;
    [[nodiscard]] qulonglong udpPacketCount() const noexcept;
    [[nodiscard]] qulonglong udpTotalBytes() const noexcept;
    [[nodiscard]] qulonglong otherFlowCount() const noexcept;
    [[nodiscard]] qulonglong otherPacketCount() const noexcept;
    [[nodiscard]] qulonglong otherTotalBytes() const noexcept;
    [[nodiscard]] qulonglong ipv4FlowCount() const noexcept;
    [[nodiscard]] qulonglong ipv6FlowCount() const noexcept;
    [[nodiscard]] int captureOpenMode() const noexcept;
    [[nodiscard]] bool httpUsePathAsServiceHint() const noexcept;
    [[nodiscard]] int currentTabIndex() const noexcept;
    [[nodiscard]] QObject* topEndpointsModel() noexcept;
    [[nodiscard]] QObject* topPortsModel() noexcept;
    [[nodiscard]] QObject* flowModel() noexcept;
    [[nodiscard]] QObject* packetModel() noexcept;
    [[nodiscard]] QObject* streamModel() noexcept;
    [[nodiscard]] QObject* packetDetailsModel() noexcept;
    [[nodiscard]] int selectedFlowIndex() const noexcept;
    [[nodiscard]] qulonglong selectedPacketIndex() const noexcept;
    [[nodiscard]] qulonglong selectedStreamItemIndex() const noexcept;
    [[nodiscard]] QString flowFilterText() const;
    [[nodiscard]] int flowSortColumn() const noexcept;
    [[nodiscard]] bool flowSortAscending() const noexcept;

    Q_INVOKABLE bool openCaptureFile(const QString& path);
    Q_INVOKABLE bool openIndexFile(const QString& path);
    Q_INVOKABLE bool attachSourceCapture(const QString& path);
    Q_INVOKABLE void cancelOpen();
    Q_INVOKABLE void loadMorePackets();
    Q_INVOKABLE void loadMoreStreamItems();
    Q_INVOKABLE bool saveAnalysisIndex(const QString& path);
    Q_INVOKABLE bool exportSelectedFlow(const QString& path);
    Q_INVOKABLE void browseCaptureFile();
    Q_INVOKABLE void browseIndexFile();
    Q_INVOKABLE void browseAttachSourceCapture();
    Q_INVOKABLE void browseSaveAnalysisIndex();
    Q_INVOKABLE void browseExportSelectedFlow();
    Q_INVOKABLE void sortFlows(int column);
    Q_INVOKABLE void drillDownToFlows(const QString& filterText);
    Q_INVOKABLE void drillDownToEndpoint(const QString& endpointText);
    Q_INVOKABLE void drillDownToPort(quint32 port);
    Q_INVOKABLE void setFlowDetailsTabIndex(int index);

    void setCaptureOpenMode(int mode);
    void setHttpUsePathAsServiceHint(bool enabled);
    void setCurrentTabIndex(int index);
    void setSelectedFlowIndex(int index);
    void setSelectedPacketIndex(qulonglong packetIndex);
    void setSelectedStreamItemIndex(qulonglong streamItemIndex);
    void setFlowFilterText(const QString& text);

signals:
    void stateChanged();
    void openErrorTextChanged();
    void statusTextChanged();
    void sourceAvailabilityChanged();
    void actionAvailabilityChanged();
    void captureOpenModeChanged();
    void httpUsePathAsServiceHintChanged();
    void currentTabIndexChanged();
    void selectedFlowIndexChanged();
    void selectedPacketIndexChanged();
    void selectedStreamItemIndexChanged();
    void flowFilterTextChanged();
    void flowSortChanged();
    void openProgressChanged();
    void packetListStateChanged();
    void streamListStateChanged();

private:
    enum class DetailsSelectionContext {
        none,
        packet,
        stream,
    };

    bool openPath(const QString& path, bool asIndex);
    void reloadSelectedPacketDetails();
    void reloadSelectedStreamDetails();
    void reloadActiveDetails();
    void refreshSelectedFlowPackets(bool resetRows);
    void refreshSelectedStreamItems(bool resetRows);
    void clearPacketSelection();
    void clearStreamSelection();
    void clearFlowSelection();
    void synchronizeFlowSelection();
    void resetLoadedState();
    void applyLoadedState(const QString& path);
    void refreshTopSummaryModels();
    void completeOpenJob(qulonglong jobId, const QString& path, bool asIndex, bool opened, bool cancelled, const QString& errorText, CaptureSession session);
    void cleanupOpenThread();
    void releaseOpenContext();
    void beginOpenProgress();
    void updateOpenProgress(const OpenProgress& progress);
    void finishOpenProgress();
    void setOpenErrorText(const QString& text);
    void setStatusText(const QString& text, bool isError = false);
    QString chooseFile(bool forIndex) const;
    QString chooseSaveFile(bool forIndex) const;
    void setLastDirectoryFromPath(const std::filesystem::path& path);

    CaptureSession session_ {};
    CaptureProtocolSummary protocol_summary_ {};
    FlowListModel flow_model_ {};
    TopSummaryListModel top_endpoints_model_ {};
    TopSummaryListModel top_ports_model_ {};
    PacketListModel packet_model_ {};
    StreamListModel stream_model_ {};
    PacketDetailsViewModel packet_details_model_ {};
    // Flow-local, ephemeral stream projection for the currently selected flow only.
    std::vector<StreamItemRow> current_stream_items_ {};
    std::map<std::uint64_t, std::uint64_t> current_flow_packet_numbers_ {};
    QString current_input_path_ {};
    QString open_error_text_ {};
    QString status_text_ {};
    QString last_directory_path_ {};
    AnalysisSettings pending_analysis_settings_ {};
    int capture_open_mode_ {0};
    int current_tab_index_ {0};
    int selected_flow_index_ {-1};
    qulonglong selected_packet_index_ {0};
    qulonglong selected_stream_item_index_ {0};
    bool status_is_error_ {false};
    bool is_opening_ {false};
    bool packets_loading_ {false};
    std::size_t loaded_packet_row_count_ {0};
    std::size_t total_packet_row_count_ {0};
    bool stream_loading_ {false};
    std::size_t loaded_stream_item_count_ {0};
    std::size_t total_stream_item_count_ {0};
    std::size_t stream_packet_window_count_ {0};
    std::size_t stream_item_budget_count_ {0};
    bool stream_tab_active_ {false};
    bool can_load_more_stream_items_ {false};
    bool stream_state_materialized_for_selected_flow_ {false};
    qulonglong open_progress_packets_ {0};
    qulonglong open_progress_bytes_ {0};
    qulonglong open_progress_total_bytes_ {0};
    double open_progress_percent_ {0.0};
    qulonglong active_open_job_id_ {0};
    QThread* open_thread_ {nullptr};
    std::shared_ptr<OpenContext> active_open_context_ {};
    DetailsSelectionContext details_selection_context_ {DetailsSelectionContext::none};
};

}  // namespace pfl















