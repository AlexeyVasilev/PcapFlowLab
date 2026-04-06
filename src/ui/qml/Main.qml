import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import PcapFlowLab

ApplicationWindow {
    id: window

    width: 1360
    height: 860
    visible: true
    title: "Pcap Flow Lab"

    function browseCaptureWithMode(mode) {
        mainController.captureOpenMode = mode
        mainController.browseCaptureFile()
    }

    Action {
        id: openCaptureFastAction
        text: "Open Capture (Fast)"
        enabled: !mainController.isOpening
        shortcut: StandardKey.Open
        onTriggered: window.browseCaptureWithMode(0)
    }

    Action {
        id: openCaptureDeepAction
        text: "Open Capture (Deep)"
        enabled: !mainController.isOpening
        shortcut: "Ctrl+Shift+O"
        onTriggered: window.browseCaptureWithMode(1)
    }

    Action {
        id: openIndexAction
        text: "Open Index"
        enabled: !mainController.isOpening
        onTriggered: mainController.browseIndexFile()
    }

    Action {
        id: saveIndexAction
        text: "Save Index"
        enabled: mainController.canSaveIndex
        shortcut: StandardKey.Save
        onTriggered: mainController.browseSaveAnalysisIndex()
    }

    Action {
        id: exportCurrentFlowAction
        text: "Export Current Flow"
        enabled: mainController.canExportSelectedFlow
        onTriggered: mainController.browseExportSelectedFlow()
    }

    Action {
        id: exportSelectedFlowsAction
        text: "Export Selected Flows"
        enabled: mainController.canExportSelectedFlows
        onTriggered: mainController.browseExportSelectedFlows()
    }

    Action {
        id: exportUnselectedFlowsAction
        text: "Export Unselected Flows"
        enabled: mainController.canExportUnselectedFlows
        onTriggered: mainController.browseExportUnselectedFlows()
    }

    Action {
        id: showSettingsAction
        text: "Settings"
        onTriggered: mainController.currentTabIndex = 3
    }

    Action {
        id: exitAction
        text: "Exit"
        onTriggered: Qt.quit()
    }

    menuBar: MenuBar {
        Menu {
            title: "File"

            MenuItem { action: openCaptureFastAction }
            MenuItem { action: openCaptureDeepAction }
            MenuItem { action: openIndexAction }
            MenuSeparator {}
            MenuItem { action: saveIndexAction }
            MenuSeparator {}
            MenuItem { action: exitAction }
        }

        Menu {
            title: "Flow"

            MenuItem { action: exportCurrentFlowAction }
            MenuItem { action: exportSelectedFlowsAction }
            MenuItem { action: exportUnselectedFlowsAction }
        }

        Menu {
            title: "View"

            MenuItem { action: showSettingsAction }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 12
        anchors.margins: 16

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Button {
                text: "Open Capture"
                enabled: !mainController.isOpening
                onClicked: mainController.browseCaptureFile()
            }

            ComboBox {
                enabled: !mainController.isOpening
                model: ["Fast", "Deep"]
                currentIndex: mainController.captureOpenMode
                onActivated: function(index) {
                    mainController.captureOpenMode = index
                }
                Layout.preferredWidth: 96
            }

            Button {
                text: "Open Index"
                enabled: !mainController.isOpening
                onClicked: mainController.browseIndexFile()
            }

            Button {
                text: "Save Index"
                enabled: mainController.canSaveIndex
                onClicked: mainController.browseSaveAnalysisIndex()
            }

            Button {
                text: "Export Flow"
                enabled: mainController.canExportSelectedFlow
                onClicked: mainController.browseExportSelectedFlow()
            }

            Button {
                text: "Export Selected"
                enabled: mainController.canExportSelectedFlows
                onClicked: mainController.browseExportSelectedFlows()
            }

            Button {
                text: "Export Unselected"
                enabled: mainController.canExportUnselectedFlows
                onClicked: mainController.browseExportUnselectedFlows()
            }

            TextField {
                Layout.fillWidth: true
                readOnly: true
                text: mainController.currentInputPath.length > 0
                    ? mainController.currentInputPath
                    : "No file loaded"
            }
        }

        Rectangle {
            Layout.fillWidth: true
            visible: mainController.openedFromIndex && !mainController.hasSourceCapture
            color: "#fef3c7"
            border.color: "#f59e0b"
            radius: 6
            implicitHeight: warningLayout.implicitHeight + 16

            RowLayout {
                id: warningLayout
                anchors.fill: parent
                anchors.margins: 8
                spacing: 12

                Label {
                    Layout.fillWidth: true
                    text: "Opened from analysis index. Raw packet data is unavailable until the original capture is attached."
                    color: "#92400e"
                    wrapMode: Text.WordWrap
                }

                Button {
                    text: "Attach Source Capture"
                    enabled: mainController.canAttachSourceCapture
                    onClicked: mainController.browseAttachSourceCapture()
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            visible: mainController.partialOpen
            color: "#fef3c7"
            border.color: "#f59e0b"
            radius: 6
            implicitHeight: partialWarningText.contentHeight + 16

            TextEdit {
                id: partialWarningText
                anchors.fill: parent
                anchors.margins: 8
                readOnly: true
                selectByMouse: true
                selectByKeyboard: true
                cursorVisible: false
                text: mainController.partialOpenWarningText
                color: "#92400e"
                wrapMode: TextEdit.Wrap
                textFormat: TextEdit.PlainText
            }
        }

        TextEdit {
            Layout.fillWidth: true
            visible: mainController.openErrorText.length > 0
            readOnly: true
            selectByMouse: true
            selectByKeyboard: true
            cursorVisible: false
            text: mainController.openErrorText
            color: "#b91c1c"
            wrapMode: TextEdit.Wrap
            textFormat: TextEdit.PlainText
            Layout.preferredHeight: contentHeight
        }

        TextEdit {
            Layout.fillWidth: true
            visible: mainController.statusText.length > 0
            readOnly: true
            selectByMouse: true
            selectByKeyboard: true
            cursorVisible: false
            text: mainController.statusText
            color: mainController.statusIsError ? "#b91c1c" : "#1f2937"
            wrapMode: TextEdit.Wrap
            textFormat: TextEdit.PlainText
            Layout.preferredHeight: contentHeight
        }

        Rectangle {
            Layout.fillWidth: true
            visible: mainController.isOpening
            color: "#f8fafc"
            border.color: "#cbd5e1"
            radius: 6
            implicitHeight: openProgressLayout.implicitHeight + 16

            ColumnLayout {
                id: openProgressLayout
                anchors.fill: parent
                anchors.margins: 8
                spacing: 6

                Label {
                    Layout.fillWidth: true
                    text: mainController.openProgressTotalBytes > 0
                        ? "Opening file: %1 packets, %2 / %3 bytes"
                            .arg(mainController.openProgressPackets)
                            .arg(mainController.openProgressBytes)
                            .arg(mainController.openProgressTotalBytes)
                        : "Opening file: %1 packets, %2 bytes"
                            .arg(mainController.openProgressPackets)
                            .arg(mainController.openProgressBytes)
                    color: "#334155"
                    wrapMode: Text.WordWrap
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 8

                    ProgressBar {
                        Layout.fillWidth: true
                        from: 0
                        to: 1
                        value: mainController.openProgressPercent
                        indeterminate: mainController.openProgressTotalBytes === 0
                    }

                    Button {
                        text: "Cancel"
                        enabled: mainController.isOpening
                        onClicked: mainController.cancelOpen()
                    }
                }
            }
        }

        TabBar {
            id: mainTabs
            Layout.fillWidth: true
            currentIndex: mainController.currentTabIndex
            onCurrentIndexChanged: mainController.currentTabIndex = currentIndex

            TabButton {
                text: "Flows"
            }

            TabButton {
                text: "Analysis"
            }

            TabButton {
                text: "Statistics"
            }

            TabButton {
                text: "Settings"
            }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: mainController.currentTabIndex

            FlowWorkspacePane {
                flowModel: mainController.flowModel
                selectedFlowIndex: mainController.selectedFlowIndex
                filterText: mainController.flowFilterText
                sortColumn: mainController.flowSortColumn
                sortAscending: mainController.flowSortAscending
                packetModel: mainController.packetModel
                packetsLoading: mainController.packetsLoading
                packetsPartiallyLoaded: mainController.packetsPartiallyLoaded
                loadedPacketRowCount: mainController.loadedPacketRowCount
                totalPacketRowCount: mainController.totalPacketRowCount
                canLoadMorePackets: mainController.canLoadMorePackets
                streamModel: mainController.streamModel
                streamLoading: mainController.streamLoading
                streamPartiallyLoaded: mainController.streamPartiallyLoaded
                loadedStreamItemCount: mainController.loadedStreamItemCount
                totalStreamItemCount: mainController.totalStreamItemCount
                streamPacketWindowCount: mainController.streamPacketWindowCount
                streamPacketWindowPartial: mainController.streamPacketWindowPartial
                canLoadMoreStreamItems: mainController.canLoadMoreStreamItems
                selectedPacketIndex: mainController.selectedPacketIndex
                selectedStreamItemIndex: mainController.selectedStreamItemIndex
                packetDetailsModel: mainController.packetDetailsModel
                onFlowSelected: function(flowIndex) {
                    mainController.selectedFlowIndex = flowIndex
                }
                onFilterTextEdited: function(text) {
                    mainController.flowFilterText = text
                }
                onSortRequested: function(column) {
                    mainController.sortFlows(column)
                }
                onSendFlowToAnalysisRequested: function() {
                    mainController.sendSelectedFlowToAnalysis()
                }
                onPacketSelected: function(packetIndex) {
                    mainController.selectedPacketIndex = packetIndex
                }
                onLoadMorePacketsRequested: function() {
                    mainController.loadMorePackets()
                }
                onStreamItemSelected: function(streamItemIndex) {
                    mainController.selectedStreamItemIndex = streamItemIndex
                }
                onLoadMoreStreamItemsRequested: function() {
                    mainController.loadMoreStreamItems()
                }
                onFlowDetailsTabChanged: function(index) {
                    mainController.setFlowDetailsTabIndex(index)
                }
            }

            AnalysisWorkspacePane {
                flowModel: mainController.flowModel
                selectedFlowIndex: mainController.selectedFlowIndex
                analysisLoading: mainController.analysisLoading
                analysisAvailable: mainController.analysisAvailable
                analysisRateGraphAvailable: mainController.analysisRateGraphAvailable
                analysisRateGraphStatusText: mainController.analysisRateGraphStatusText
                analysisRateGraphWindowText: mainController.analysisRateGraphWindowText
                analysisRateSeriesAToB: mainController.analysisRateSeriesAToB
                analysisRateSeriesBToA: mainController.analysisRateSeriesBToA
                canExportAnalysisSequence: mainController.canExportAnalysisSequence
                analysisSequenceExportInProgress: mainController.analysisSequenceExportInProgress
                analysisSequenceExportStatusText: mainController.analysisSequenceExportStatusText
                analysisSequenceExportStatusIsError: mainController.analysisSequenceExportStatusIsError
                analysisDurationText: mainController.analysisDurationText
                analysisTimelineFirstPacketTime: mainController.analysisTimelineFirstPacketTime
                analysisTimelineLastPacketTime: mainController.analysisTimelineLastPacketTime
                analysisTimelineLargestGapText: mainController.analysisTimelineLargestGapText
                analysisTimelinePacketCountConsidered: mainController.analysisTimelinePacketCountConsidered
                analysisTimelinePacketCountConsideredText: mainController.analysisTimelinePacketCountConsideredText
                analysisTotalPackets: mainController.analysisTotalPackets
                analysisTotalPacketsText: mainController.analysisTotalPacketsText
                analysisTotalBytes: mainController.analysisTotalBytes
                analysisTotalBytesText: mainController.analysisTotalBytesText
                analysisEndpointSummaryText: mainController.analysisEndpointSummaryText
                analysisPacketsPerSecondText: mainController.analysisPacketsPerSecondText
                analysisPacketsPerSecondAToBText: mainController.analysisPacketsPerSecondAToBText
                analysisPacketsPerSecondBToAText: mainController.analysisPacketsPerSecondBToAText
                analysisBytesPerSecondText: mainController.analysisBytesPerSecondText
                analysisBytesPerSecondAToBText: mainController.analysisBytesPerSecondAToBText
                analysisBytesPerSecondBToAText: mainController.analysisBytesPerSecondBToAText
                analysisAveragePacketSizeText: mainController.analysisAveragePacketSizeText
                analysisAveragePacketSizeAToBText: mainController.analysisAveragePacketSizeAToBText
                analysisAveragePacketSizeBToAText: mainController.analysisAveragePacketSizeBToAText
                analysisAverageInterArrivalText: mainController.analysisAverageInterArrivalText
                analysisMinPacketSizeText: mainController.analysisMinPacketSizeText
                analysisMinPacketSizeAToBText: mainController.analysisMinPacketSizeAToBText
                analysisMinPacketSizeBToAText: mainController.analysisMinPacketSizeBToAText
                analysisMaxPacketSizeText: mainController.analysisMaxPacketSizeText
                analysisMaxPacketSizeAToBText: mainController.analysisMaxPacketSizeAToBText
                analysisMaxPacketSizeBToAText: mainController.analysisMaxPacketSizeBToAText
                analysisPacketRatioText: mainController.analysisPacketRatioText
                analysisByteRatioText: mainController.analysisByteRatioText
                analysisPacketDirectionText: mainController.analysisPacketDirectionText
                analysisDataDirectionText: mainController.analysisDataDirectionText
                analysisProtocolHint: mainController.analysisProtocolHint
                analysisServiceHint: mainController.analysisServiceHint
                analysisProtocolVersionText: mainController.analysisProtocolVersionText
                analysisProtocolServiceText: mainController.analysisProtocolServiceText
                analysisProtocolFallbackText: mainController.analysisProtocolFallbackText
                analysisHasTcpControlCounts: mainController.analysisHasTcpControlCounts
                analysisTcpSynPackets: mainController.analysisTcpSynPackets
                analysisTcpSynPacketsText: mainController.analysisTcpSynPacketsText
                analysisTcpFinPackets: mainController.analysisTcpFinPackets
                analysisTcpFinPacketsText: mainController.analysisTcpFinPacketsText
                analysisTcpRstPackets: mainController.analysisTcpRstPackets
                analysisTcpRstPacketsText: mainController.analysisTcpRstPacketsText
                analysisBurstCount: mainController.analysisBurstCount
                analysisBurstCountText: mainController.analysisBurstCountText
                analysisLongestBurstPacketCount: mainController.analysisLongestBurstPacketCount
                analysisLongestBurstPacketCountText: mainController.analysisLongestBurstPacketCountText
                analysisLargestBurstBytesText: mainController.analysisLargestBurstBytesText
                analysisIdleGapCount: mainController.analysisIdleGapCount
                analysisIdleGapCountText: mainController.analysisIdleGapCountText
                analysisLargestIdleGapText: mainController.analysisLargestIdleGapText
                analysisPacketsAToB: mainController.analysisPacketsAToB
                analysisPacketsAToBText: mainController.analysisPacketsAToBText
                analysisPacketsBToA: mainController.analysisPacketsBToA
                analysisPacketsBToAText: mainController.analysisPacketsBToAText
                analysisBytesAToB: mainController.analysisBytesAToB
                analysisBytesAToBText: mainController.analysisBytesAToBText
                analysisBytesBToA: mainController.analysisBytesBToA
                analysisBytesBToAText: mainController.analysisBytesBToAText
                analysisInterArrivalHistogramAll: mainController.analysisInterArrivalHistogramAll
                analysisInterArrivalHistogramAToB: mainController.analysisInterArrivalHistogramAToB
                analysisInterArrivalHistogramBToA: mainController.analysisInterArrivalHistogramBToA
                analysisInterArrivalHistogram: mainController.analysisInterArrivalHistogram
                analysisPacketSizeHistogramAll: mainController.analysisPacketSizeHistogramAll
                analysisPacketSizeHistogramAToB: mainController.analysisPacketSizeHistogramAToB
                analysisPacketSizeHistogramBToA: mainController.analysisPacketSizeHistogramBToA
                analysisPacketSizeHistogram: mainController.analysisPacketSizeHistogram
                analysisSequencePreview: mainController.analysisSequencePreview
                onFlowSelected: function(flowIndex) {
                    mainController.selectedFlowIndex = flowIndex
                }
                onOpenInFlowsRequested: function() {
                    mainController.currentTabIndex = 0
                }
                onExportFlowSequenceRequested: function() {
                    mainController.browseExportSelectedFlowSequenceCsv()
                }
            }

            StatisticsPane {
                hasCapture: mainController.hasCapture
                packetCount: mainController.packetCount
                flowCount: mainController.flowCount
                totalBytes: mainController.totalBytes
                tcpFlowCount: mainController.tcpFlowCount
                tcpPacketCount: mainController.tcpPacketCount
                tcpTotalBytes: mainController.tcpTotalBytes
                udpFlowCount: mainController.udpFlowCount
                udpPacketCount: mainController.udpPacketCount
                udpTotalBytes: mainController.udpTotalBytes
                otherFlowCount: mainController.otherFlowCount
                otherPacketCount: mainController.otherPacketCount
                otherTotalBytes: mainController.otherTotalBytes
                ipv4FlowCount: mainController.ipv4FlowCount
                ipv4PacketCount: mainController.ipv4PacketCount
                ipv4TotalBytes: mainController.ipv4TotalBytes
                ipv6FlowCount: mainController.ipv6FlowCount
                ipv6PacketCount: mainController.ipv6PacketCount
                ipv6TotalBytes: mainController.ipv6TotalBytes
                quicTotalFlows: mainController.quicTotalFlows
                quicWithSni: mainController.quicWithSni
                quicWithoutSni: mainController.quicWithoutSni
                quicVersionV1: mainController.quicVersionV1
                quicVersionDraft29: mainController.quicVersionDraft29
                quicVersionV2: mainController.quicVersionV2
                quicVersionUnknown: mainController.quicVersionUnknown
                tlsTotalFlows: mainController.tlsTotalFlows
                tlsWithSni: mainController.tlsWithSni
                tlsWithoutSni: mainController.tlsWithoutSni
                tlsVersion12: mainController.tlsVersion12
                tlsVersion13: mainController.tlsVersion13
                tlsVersionUnknown: mainController.tlsVersionUnknown
                protocolHintDistribution: mainController.protocolHintDistribution
                statisticsMode: mainController.statisticsMode
                topEndpointsModel: mainController.topEndpointsModel
                topPortsModel: mainController.topPortsModel
                onEndpointActivated: function(endpointText) {
                    mainController.drillDownToEndpoint(endpointText)
                }
                onPortActivated: function(port) {
                    mainController.drillDownToPort(port)
                }
                onStatisticsModeChangedByUser: function(mode) {
                    mainController.statisticsMode = mode
                }
            }

            SettingsPane {
                httpUsePathAsServiceHint: mainController.httpUsePathAsServiceHint
                usePossibleTlsQuic: mainController.usePossibleTlsQuic
                onHttpUsePathAsServiceHintChangedByUser: function(enabled) {
                    mainController.httpUsePathAsServiceHint = enabled
                }
                onUsePossibleTlsQuicChangedByUser: function(enabled) {
                    mainController.usePossibleTlsQuic = enabled
                }
            }
        }
    }
}
