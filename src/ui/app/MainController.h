#pragma once

#include <filesystem>
#include <map>
#include <memory>
#include <vector>

#include <QObject>
#include <QString>
#include <QVariantList>

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
    Q_PROPERTY(QString activeSourceCapturePath READ activeSourceCapturePath NOTIFY sourceAvailabilityChanged)
    Q_PROPERTY(QString expectedSourceCapturePath READ expectedSourceCapturePath NOTIFY sourceAvailabilityChanged)
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
    Q_PROPERTY(qulonglong selectedFlowCount READ selectedFlowCount NOTIFY selectedFlowCountChanged)
    Q_PROPERTY(bool canExportSelectedFlows READ canExportSelectedFlows NOTIFY actionAvailabilityChanged)
    Q_PROPERTY(bool canExportUnselectedFlows READ canExportUnselectedFlows NOTIFY actionAvailabilityChanged)
    Q_PROPERTY(bool isOpening READ isOpening NOTIFY openProgressChanged)
    Q_PROPERTY(qulonglong openProgressPackets READ openProgressPackets NOTIFY openProgressChanged)
    Q_PROPERTY(qulonglong openProgressBytes READ openProgressBytes NOTIFY openProgressChanged)
    Q_PROPERTY(qulonglong openProgressTotalBytes READ openProgressTotalBytes NOTIFY openProgressChanged)
    Q_PROPERTY(double openProgressPercent READ openProgressPercent NOTIFY openProgressChanged)
    Q_PROPERTY(QString openingInputPath READ openingInputPath NOTIFY openProgressChanged)
    Q_PROPERTY(bool openingAsIndex READ openingAsIndex NOTIFY openProgressChanged)
    Q_PROPERTY(QString openProgressProcessedText READ openProgressProcessedText NOTIFY openProgressChanged)
    Q_PROPERTY(bool isApplyingSession READ isApplyingSession NOTIFY sessionApplicationStateChanged)
    Q_PROPERTY(bool packetsLoading READ packetsLoading NOTIFY packetListStateChanged)
    Q_PROPERTY(bool packetsPartiallyLoaded READ packetsPartiallyLoaded NOTIFY packetListStateChanged)
    Q_PROPERTY(qulonglong loadedPacketRowCount READ loadedPacketRowCount NOTIFY packetListStateChanged)
    Q_PROPERTY(qulonglong totalPacketRowCount READ totalPacketRowCount NOTIFY packetListStateChanged)
    Q_PROPERTY(bool canLoadMorePackets READ canLoadMorePackets NOTIFY packetListStateChanged)
    Q_PROPERTY(bool streamLoading READ streamLoading NOTIFY streamListStateChanged)
    Q_PROPERTY(bool streamPartiallyLoaded READ streamPartiallyLoaded NOTIFY streamListStateChanged)
    Q_PROPERTY(qulonglong loadedStreamItemCount READ loadedStreamItemCount NOTIFY streamListStateChanged)
    Q_PROPERTY(qulonglong totalStreamItemCount READ totalStreamItemCount NOTIFY streamListStateChanged)
    Q_PROPERTY(qulonglong streamPacketWindowCount READ streamPacketWindowCount NOTIFY streamListStateChanged)
    Q_PROPERTY(bool streamPacketWindowPartial READ streamPacketWindowPartial NOTIFY streamListStateChanged)
    Q_PROPERTY(bool canLoadMoreStreamItems READ canLoadMoreStreamItems NOTIFY streamListStateChanged)
    Q_PROPERTY(bool analysisLoading READ analysisLoading NOTIFY analysisStateChanged)
    Q_PROPERTY(bool analysisAvailable READ analysisAvailable NOTIFY analysisStateChanged)
    Q_PROPERTY(bool analysisRateGraphAvailable READ analysisRateGraphAvailable NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisRateGraphStatusText READ analysisRateGraphStatusText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisRateGraphWindowText READ analysisRateGraphWindowText NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisRateSeriesAToB READ analysisRateSeriesAToB NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisRateSeriesBToA READ analysisRateSeriesBToA NOTIFY analysisStateChanged)
    Q_PROPERTY(bool canExportAnalysisSequence READ canExportAnalysisSequence NOTIFY actionAvailabilityChanged)
    Q_PROPERTY(bool analysisSequenceExportInProgress READ analysisSequenceExportInProgress NOTIFY analysisSequenceExportStateChanged)
    Q_PROPERTY(QString analysisSequenceExportStatusText READ analysisSequenceExportStatusText NOTIFY analysisSequenceExportStateChanged)
    Q_PROPERTY(bool analysisSequenceExportStatusIsError READ analysisSequenceExportStatusIsError NOTIFY analysisSequenceExportStateChanged)
    Q_PROPERTY(QString analysisDurationText READ analysisDurationText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisTimelineFirstPacketTime READ analysisTimelineFirstPacketTime NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisTimelineLastPacketTime READ analysisTimelineLastPacketTime NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisTimelineLargestGapText READ analysisTimelineLargestGapText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisTimelinePacketCountConsidered READ analysisTimelinePacketCountConsidered NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisTimelinePacketCountConsideredText READ analysisTimelinePacketCountConsideredText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisTotalPackets READ analysisTotalPackets NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisTotalPacketsText READ analysisTotalPacketsText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisTotalBytes READ analysisTotalBytes NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisTotalBytesText READ analysisTotalBytesText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisEndpointSummaryText READ analysisEndpointSummaryText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisPacketsPerSecondText READ analysisPacketsPerSecondText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisPacketsPerSecondAToBText READ analysisPacketsPerSecondAToBText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisPacketsPerSecondBToAText READ analysisPacketsPerSecondBToAText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisBytesPerSecondText READ analysisBytesPerSecondText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisBytesPerSecondAToBText READ analysisBytesPerSecondAToBText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisBytesPerSecondBToAText READ analysisBytesPerSecondBToAText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisAveragePacketSizeText READ analysisAveragePacketSizeText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisAveragePacketSizeAToBText READ analysisAveragePacketSizeAToBText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisAveragePacketSizeBToAText READ analysisAveragePacketSizeBToAText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisAverageInterArrivalText READ analysisAverageInterArrivalText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisMinPacketSizeText READ analysisMinPacketSizeText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisMinPacketSizeAToBText READ analysisMinPacketSizeAToBText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisMinPacketSizeBToAText READ analysisMinPacketSizeBToAText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisMaxPacketSizeText READ analysisMaxPacketSizeText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisMaxPacketSizeAToBText READ analysisMaxPacketSizeAToBText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisMaxPacketSizeBToAText READ analysisMaxPacketSizeBToAText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisPacketRatioText READ analysisPacketRatioText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisByteRatioText READ analysisByteRatioText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisPacketDirectionText READ analysisPacketDirectionText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisDataDirectionText READ analysisDataDirectionText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisProtocolHint READ analysisProtocolHint NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisServiceHint READ analysisServiceHint NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisProtocolVersionText READ analysisProtocolVersionText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisProtocolServiceText READ analysisProtocolServiceText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisProtocolFallbackText READ analysisProtocolFallbackText NOTIFY analysisStateChanged)
    Q_PROPERTY(bool analysisHasTcpControlCounts READ analysisHasTcpControlCounts NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisTcpSynPackets READ analysisTcpSynPackets NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisTcpSynPacketsText READ analysisTcpSynPacketsText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisTcpFinPackets READ analysisTcpFinPackets NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisTcpFinPacketsText READ analysisTcpFinPacketsText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisTcpRstPackets READ analysisTcpRstPackets NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisTcpRstPacketsText READ analysisTcpRstPacketsText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisBurstCount READ analysisBurstCount NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisBurstCountText READ analysisBurstCountText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisLongestBurstPacketCount READ analysisLongestBurstPacketCount NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisLongestBurstPacketCountText READ analysisLongestBurstPacketCountText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisLargestBurstBytesText READ analysisLargestBurstBytesText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisIdleGapCount READ analysisIdleGapCount NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisIdleGapCountText READ analysisIdleGapCountText NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisLargestIdleGapText READ analysisLargestIdleGapText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisPacketsAToB READ analysisPacketsAToB NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisPacketsAToBText READ analysisPacketsAToBText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisPacketsBToA READ analysisPacketsBToA NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisPacketsBToAText READ analysisPacketsBToAText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisBytesAToB READ analysisBytesAToB NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisBytesAToBText READ analysisBytesAToBText NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong analysisBytesBToA READ analysisBytesBToA NOTIFY analysisStateChanged)
    Q_PROPERTY(QString analysisBytesBToAText READ analysisBytesBToAText NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisInterArrivalHistogramAll READ analysisInterArrivalHistogramAll NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisInterArrivalHistogramAToB READ analysisInterArrivalHistogramAToB NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisInterArrivalHistogramBToA READ analysisInterArrivalHistogramBToA NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisInterArrivalHistogram READ analysisInterArrivalHistogram NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisPacketSizeHistogramAll READ analysisPacketSizeHistogramAll NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisPacketSizeHistogramAToB READ analysisPacketSizeHistogramAToB NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisPacketSizeHistogramBToA READ analysisPacketSizeHistogramBToA NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisPacketSizeHistogram READ analysisPacketSizeHistogram NOTIFY analysisStateChanged)
    Q_PROPERTY(QVariantList analysisSequencePreview READ analysisSequencePreview NOTIFY analysisStateChanged)
    Q_PROPERTY(qulonglong packetCount READ packetCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong flowCount READ flowCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong totalBytes READ totalBytes NOTIFY stateChanged)
    Q_PROPERTY(QVariantList protocolHintDistribution READ protocolHintDistribution NOTIFY stateChanged)
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
    Q_PROPERTY(qulonglong ipv4PacketCount READ ipv4PacketCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong ipv4TotalBytes READ ipv4TotalBytes NOTIFY stateChanged)
    Q_PROPERTY(qulonglong ipv6FlowCount READ ipv6FlowCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong ipv6PacketCount READ ipv6PacketCount NOTIFY stateChanged)
    Q_PROPERTY(qulonglong ipv6TotalBytes READ ipv6TotalBytes NOTIFY stateChanged)
    Q_PROPERTY(qulonglong quicTotalFlows READ quicTotalFlows NOTIFY stateChanged)
    Q_PROPERTY(qulonglong quicWithSni READ quicWithSni NOTIFY stateChanged)
    Q_PROPERTY(qulonglong quicWithoutSni READ quicWithoutSni NOTIFY stateChanged)
    Q_PROPERTY(qulonglong quicVersionV1 READ quicVersionV1 NOTIFY stateChanged)
    Q_PROPERTY(qulonglong quicVersionDraft29 READ quicVersionDraft29 NOTIFY stateChanged)
    Q_PROPERTY(qulonglong quicVersionV2 READ quicVersionV2 NOTIFY stateChanged)
    Q_PROPERTY(qulonglong quicVersionUnknown READ quicVersionUnknown NOTIFY stateChanged)
    Q_PROPERTY(qulonglong tlsTotalFlows READ tlsTotalFlows NOTIFY stateChanged)
    Q_PROPERTY(qulonglong tlsWithSni READ tlsWithSni NOTIFY stateChanged)
    Q_PROPERTY(qulonglong tlsWithoutSni READ tlsWithoutSni NOTIFY stateChanged)
    Q_PROPERTY(qulonglong tlsVersion12 READ tlsVersion12 NOTIFY stateChanged)
    Q_PROPERTY(qulonglong tlsVersion13 READ tlsVersion13 NOTIFY stateChanged)
    Q_PROPERTY(qulonglong tlsVersionUnknown READ tlsVersionUnknown NOTIFY stateChanged)
    Q_PROPERTY(int statisticsMode READ statisticsMode WRITE setStatisticsMode NOTIFY statisticsModeChanged)
    Q_PROPERTY(int captureOpenMode READ captureOpenMode WRITE setCaptureOpenMode NOTIFY captureOpenModeChanged)
    Q_PROPERTY(bool httpUsePathAsServiceHint READ httpUsePathAsServiceHint WRITE setHttpUsePathAsServiceHint NOTIFY httpUsePathAsServiceHintChanged)
    Q_PROPERTY(bool usePossibleTlsQuic READ usePossibleTlsQuic WRITE setUsePossibleTlsQuic NOTIFY usePossibleTlsQuicChanged)
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
    [[nodiscard]] QString activeSourceCapturePath() const;
    [[nodiscard]] QString expectedSourceCapturePath() const;
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
    [[nodiscard]] qulonglong selectedFlowCount() const noexcept;
    [[nodiscard]] bool canExportSelectedFlows() const noexcept;
    [[nodiscard]] bool canExportUnselectedFlows() const noexcept;
    [[nodiscard]] bool isOpening() const noexcept;
    [[nodiscard]] qulonglong openProgressPackets() const noexcept;
    [[nodiscard]] qulonglong openProgressBytes() const noexcept;
    [[nodiscard]] qulonglong openProgressTotalBytes() const noexcept;
    [[nodiscard]] double openProgressPercent() const noexcept;
    [[nodiscard]] QString openingInputPath() const;
    [[nodiscard]] bool openingAsIndex() const noexcept;
    [[nodiscard]] QString openProgressProcessedText() const;
    [[nodiscard]] bool isApplyingSession() const noexcept;
    [[nodiscard]] bool packetsLoading() const noexcept;
    [[nodiscard]] bool packetsPartiallyLoaded() const noexcept;
    [[nodiscard]] qulonglong loadedPacketRowCount() const noexcept;
    [[nodiscard]] qulonglong totalPacketRowCount() const noexcept;
    [[nodiscard]] bool canLoadMorePackets() const noexcept;
    [[nodiscard]] bool streamLoading() const noexcept;
    [[nodiscard]] bool streamPartiallyLoaded() const noexcept;
    [[nodiscard]] qulonglong loadedStreamItemCount() const noexcept;
    [[nodiscard]] qulonglong totalStreamItemCount() const noexcept;
    [[nodiscard]] qulonglong streamPacketWindowCount() const noexcept;
    [[nodiscard]] bool streamPacketWindowPartial() const noexcept;
    [[nodiscard]] bool canLoadMoreStreamItems() const noexcept;
    [[nodiscard]] bool analysisLoading() const noexcept;
    [[nodiscard]] bool analysisAvailable() const noexcept;
    [[nodiscard]] bool analysisRateGraphAvailable() const noexcept;
    [[nodiscard]] QString analysisRateGraphStatusText() const;
    [[nodiscard]] QString analysisRateGraphWindowText() const;
    [[nodiscard]] QVariantList analysisRateSeriesAToB() const;
    [[nodiscard]] QVariantList analysisRateSeriesBToA() const;
    [[nodiscard]] bool canExportAnalysisSequence() const noexcept;
    [[nodiscard]] bool analysisSequenceExportInProgress() const noexcept;
    [[nodiscard]] QString analysisSequenceExportStatusText() const;
    [[nodiscard]] bool analysisSequenceExportStatusIsError() const noexcept;
    [[nodiscard]] QString analysisDurationText() const;
    [[nodiscard]] QString analysisTimelineFirstPacketTime() const;
    [[nodiscard]] QString analysisTimelineLastPacketTime() const;
    [[nodiscard]] QString analysisTimelineLargestGapText() const;
    [[nodiscard]] qulonglong analysisTimelinePacketCountConsidered() const noexcept;
    [[nodiscard]] QString analysisTimelinePacketCountConsideredText() const;
    [[nodiscard]] qulonglong analysisTotalPackets() const noexcept;
    [[nodiscard]] QString analysisTotalPacketsText() const;
    [[nodiscard]] qulonglong analysisTotalBytes() const noexcept;
    [[nodiscard]] QString analysisTotalBytesText() const;
    [[nodiscard]] QString analysisEndpointSummaryText() const;
    [[nodiscard]] QString analysisPacketsPerSecondText() const;
    [[nodiscard]] QString analysisPacketsPerSecondAToBText() const;
    [[nodiscard]] QString analysisPacketsPerSecondBToAText() const;
    [[nodiscard]] QString analysisBytesPerSecondText() const;
    [[nodiscard]] QString analysisBytesPerSecondAToBText() const;
    [[nodiscard]] QString analysisBytesPerSecondBToAText() const;
    [[nodiscard]] QString analysisAveragePacketSizeText() const;
    [[nodiscard]] QString analysisAveragePacketSizeAToBText() const;
    [[nodiscard]] QString analysisAveragePacketSizeBToAText() const;
    [[nodiscard]] QString analysisAverageInterArrivalText() const;
    [[nodiscard]] QString analysisMinPacketSizeText() const;
    [[nodiscard]] QString analysisMinPacketSizeAToBText() const;
    [[nodiscard]] QString analysisMinPacketSizeBToAText() const;
    [[nodiscard]] QString analysisMaxPacketSizeText() const;
    [[nodiscard]] QString analysisMaxPacketSizeAToBText() const;
    [[nodiscard]] QString analysisMaxPacketSizeBToAText() const;
    [[nodiscard]] QString analysisPacketRatioText() const;
    [[nodiscard]] QString analysisByteRatioText() const;
    [[nodiscard]] QString analysisPacketDirectionText() const;
    [[nodiscard]] QString analysisDataDirectionText() const;
    [[nodiscard]] QString analysisProtocolHint() const;
    [[nodiscard]] QString analysisServiceHint() const;
    [[nodiscard]] QString analysisProtocolVersionText() const;
    [[nodiscard]] QString analysisProtocolServiceText() const;
    [[nodiscard]] QString analysisProtocolFallbackText() const;
    [[nodiscard]] bool analysisHasTcpControlCounts() const noexcept;
    [[nodiscard]] qulonglong analysisTcpSynPackets() const noexcept;
    [[nodiscard]] QString analysisTcpSynPacketsText() const;
    [[nodiscard]] qulonglong analysisTcpFinPackets() const noexcept;
    [[nodiscard]] QString analysisTcpFinPacketsText() const;
    [[nodiscard]] qulonglong analysisTcpRstPackets() const noexcept;
    [[nodiscard]] QString analysisTcpRstPacketsText() const;
    [[nodiscard]] qulonglong analysisBurstCount() const noexcept;
    [[nodiscard]] QString analysisBurstCountText() const;
    [[nodiscard]] qulonglong analysisLongestBurstPacketCount() const noexcept;
    [[nodiscard]] QString analysisLongestBurstPacketCountText() const;
    [[nodiscard]] QString analysisLargestBurstBytesText() const;
    [[nodiscard]] qulonglong analysisIdleGapCount() const noexcept;
    [[nodiscard]] QString analysisIdleGapCountText() const;
    [[nodiscard]] QString analysisLargestIdleGapText() const;
    [[nodiscard]] qulonglong analysisPacketsAToB() const noexcept;
    [[nodiscard]] QString analysisPacketsAToBText() const;
    [[nodiscard]] qulonglong analysisPacketsBToA() const noexcept;
    [[nodiscard]] QString analysisPacketsBToAText() const;
    [[nodiscard]] qulonglong analysisBytesAToB() const noexcept;
    [[nodiscard]] QString analysisBytesAToBText() const;
    [[nodiscard]] qulonglong analysisBytesBToA() const noexcept;
    [[nodiscard]] QString analysisBytesBToAText() const;
    [[nodiscard]] QVariantList analysisInterArrivalHistogramAll() const;
    [[nodiscard]] QVariantList analysisInterArrivalHistogramAToB() const;
    [[nodiscard]] QVariantList analysisInterArrivalHistogramBToA() const;
    [[nodiscard]] QVariantList analysisInterArrivalHistogram() const;
    [[nodiscard]] QVariantList analysisPacketSizeHistogramAll() const;
    [[nodiscard]] QVariantList analysisPacketSizeHistogramAToB() const;
    [[nodiscard]] QVariantList analysisPacketSizeHistogramBToA() const;
    [[nodiscard]] QVariantList analysisPacketSizeHistogram() const;
    [[nodiscard]] QVariantList analysisSequencePreview() const;
    [[nodiscard]] qulonglong packetCount() const noexcept;
    [[nodiscard]] qulonglong flowCount() const noexcept;
    [[nodiscard]] qulonglong totalBytes() const noexcept;
    [[nodiscard]] QVariantList protocolHintDistribution() const;
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
    [[nodiscard]] qulonglong ipv4PacketCount() const noexcept;
    [[nodiscard]] qulonglong ipv4TotalBytes() const noexcept;
    [[nodiscard]] qulonglong ipv6FlowCount() const noexcept;
    [[nodiscard]] qulonglong ipv6PacketCount() const noexcept;
    [[nodiscard]] qulonglong ipv6TotalBytes() const noexcept;
    [[nodiscard]] qulonglong quicTotalFlows() const noexcept;
    [[nodiscard]] qulonglong quicWithSni() const noexcept;
    [[nodiscard]] qulonglong quicWithoutSni() const noexcept;
    [[nodiscard]] qulonglong quicVersionV1() const noexcept;
    [[nodiscard]] qulonglong quicVersionDraft29() const noexcept;
    [[nodiscard]] qulonglong quicVersionV2() const noexcept;
    [[nodiscard]] qulonglong quicVersionUnknown() const noexcept;
    [[nodiscard]] qulonglong tlsTotalFlows() const noexcept;
    [[nodiscard]] qulonglong tlsWithSni() const noexcept;
    [[nodiscard]] qulonglong tlsWithoutSni() const noexcept;
    [[nodiscard]] qulonglong tlsVersion12() const noexcept;
    [[nodiscard]] qulonglong tlsVersion13() const noexcept;
    [[nodiscard]] qulonglong tlsVersionUnknown() const noexcept;
    [[nodiscard]] int statisticsMode() const noexcept;
    [[nodiscard]] int captureOpenMode() const noexcept;
    [[nodiscard]] bool httpUsePathAsServiceHint() const noexcept;
    [[nodiscard]] bool usePossibleTlsQuic() const noexcept;
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
    Q_INVOKABLE bool exportSelectedFlowSequenceCsv(const QString& path);
    Q_INVOKABLE void clearSelectedFlows();
    Q_INVOKABLE bool exportSelectedFlows(const QString& path);
    Q_INVOKABLE bool exportUnselectedFlows(const QString& path);
    Q_INVOKABLE void browseCaptureFile();
    Q_INVOKABLE void browseIndexFile();
    Q_INVOKABLE void browseAttachSourceCapture();
    Q_INVOKABLE void browseSaveAnalysisIndex();
    Q_INVOKABLE void browseExportSelectedFlow();
    Q_INVOKABLE void browseExportSelectedFlowSequenceCsv();
    Q_INVOKABLE void browseExportSelectedFlows();
    Q_INVOKABLE void browseExportUnselectedFlows();
    Q_INVOKABLE void sendSelectedFlowToAnalysis();
    Q_INVOKABLE void sortFlows(int column);
    Q_INVOKABLE void drillDownToFlows(const QString& filterText);
    Q_INVOKABLE void drillDownToEndpoint(const QString& endpointText);
    Q_INVOKABLE void drillDownToPort(quint32 port);
    Q_INVOKABLE void setFlowDetailsTabIndex(int index);

    void setCaptureOpenMode(int mode);
    void setStatisticsMode(int mode);
    void setHttpUsePathAsServiceHint(bool enabled);
    void setUsePossibleTlsQuic(bool enabled);
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
    void statisticsModeChanged();
    void httpUsePathAsServiceHintChanged();
    void usePossibleTlsQuicChanged();
    void currentTabIndexChanged();
    void selectedFlowIndexChanged();
    void selectedFlowCountChanged();
    void selectedPacketIndexChanged();
    void selectedStreamItemIndexChanged();
    void flowFilterTextChanged();
    void flowSortChanged();
    void openProgressChanged();
    void packetListStateChanged();
    void streamListStateChanged();
    void analysisStateChanged();
    void analysisSequenceExportStateChanged();
    void sessionApplicationStateChanged();

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
    void maybeEnrichSelectedFlowServiceHint();
    void refreshSelectedFlowPackets(bool resetRows);
    void refreshSelectedStreamItems(bool resetRows);
    void refreshSelectedFlowAnalysis();
    void clearSelectedFlowAnalysis();
    void clearPacketSelection();
    void clearStreamSelection();
    void clearFlowSelection();
    void synchronizeFlowSelection();
    void resetLoadedState();
    void applyLoadedState(const QString& path);
    void refreshTopSummaryModels();
    bool exportFlows(const QString& path, const std::vector<int>& flowIndices, const QString& emptySelectionMessage, const QString& failureMessage, const QString& successMessage);
    void completeAnalysisSequenceExport(qulonglong jobId, const QString& outputPath, bool exported, const QString& errorText);
    void completeOpenJob(qulonglong jobId, const QString& path, bool asIndex, bool opened, bool cancelled, const QString& errorText, CaptureSession session);
    void cleanupAnalysisSequenceExportThread();
    void cleanupOpenThread();
    void releaseOpenContext();
    void beginOpenProgress();
    void updateOpenProgress(const OpenProgress& progress);
    void finishOpenProgress();
    void setApplyingSession(bool applying);
    void setOpenErrorText(const QString& text);
    void setAnalysisSequenceExportState(bool inProgress, const QString& statusText, bool statusIsError);
    void setStatusText(const QString& text, bool isError = false);
    QString chooseFile(bool forIndex) const;
    QString chooseSaveFile(bool forIndex) const;
    QString chooseSequenceCsvSaveFile() const;
    void setLastDirectoryFromPath(const std::filesystem::path& path);

    CaptureSession session_ {};
    CaptureProtocolSummary protocol_summary_ {};
    QuicRecognitionStats quic_recognition_stats_ {};
    TlsRecognitionStats tls_recognition_stats_ {};
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
    QString active_open_input_path_ {};
    QString open_error_text_ {};
    QString status_text_ {};
    QString last_directory_path_ {};
    AnalysisSettings pending_analysis_settings_ {};
    int statistics_mode_ {0};
    int capture_open_mode_ {0};
    int current_tab_index_ {0};
    int selected_flow_index_ {-1};
    qulonglong selected_packet_index_ {0};
    qulonglong selected_stream_item_index_ {0};
    bool status_is_error_ {false};
    bool is_opening_ {false};
    bool is_applying_session_ {false};
    bool packets_loading_ {false};
    std::size_t loaded_packet_row_count_ {0};
    std::size_t total_packet_row_count_ {0};
    bool stream_loading_ {false};
    std::size_t loaded_stream_item_count_ {0};
    std::size_t total_stream_item_count_ {0};
    std::size_t stream_packet_window_count_ {0};
    std::size_t stream_item_budget_count_ {0};
    bool stream_tab_active_ {false};
    bool analysis_tab_active_ {false};
    bool can_load_more_stream_items_ {false};
    bool stream_state_materialized_for_selected_flow_ {false};
    bool analysis_loading_ {false};
    bool analysis_sequence_export_in_progress_ {false};
    std::optional<FlowAnalysisResult> current_flow_analysis_ {};
    QString analysis_sequence_export_status_text_ {};
    bool analysis_sequence_export_status_is_error_ {false};
    qulonglong active_analysis_request_id_ {0};
    qulonglong active_analysis_sequence_export_job_id_ {0};
    qulonglong open_progress_packets_ {0};
    qulonglong open_progress_bytes_ {0};
    qulonglong open_progress_total_bytes_ {0};
    double open_progress_percent_ {0.0};
    qulonglong active_open_job_id_ {0};
    bool active_open_as_index_ {false};
    QThread* analysis_sequence_export_thread_ {nullptr};
    QThread* open_thread_ {nullptr};
    std::shared_ptr<OpenContext> active_open_context_ {};
    DetailsSelectionContext details_selection_context_ {DetailsSelectionContext::none};
};

}  // namespace pfl











