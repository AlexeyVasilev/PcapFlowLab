import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property var flowModel: null
    property int selectedFlowIndex: -1
    property bool analysisLoading: false
    property bool analysisAvailable: false
    property bool canExportAnalysisSequence: false
    property bool analysisSequenceExportInProgress: false
    property string analysisSequenceExportStatusText: ""
    property bool analysisSequenceExportStatusIsError: false
    property string analysisDurationText: ""
    property string analysisTimelineFirstPacketTime: ""
    property string analysisTimelineLastPacketTime: ""
    property string analysisTimelineLargestGapText: ""
    property var analysisTimelinePacketCountConsidered: 0
    property string analysisTimelinePacketCountConsideredText: ""
    property var analysisTotalPackets: 0
    property string analysisTotalPacketsText: ""
    property var analysisTotalBytes: 0
    property string analysisTotalBytesText: ""
    property string analysisEndpointSummaryText: ""
    property string analysisPacketsPerSecondText: ""
    property string analysisPacketsPerSecondAToBText: ""
    property string analysisPacketsPerSecondBToAText: ""
    property string analysisBytesPerSecondText: ""
    property string analysisBytesPerSecondAToBText: ""
    property string analysisBytesPerSecondBToAText: ""
    property string analysisAveragePacketSizeText: ""
    property string analysisAveragePacketSizeAToBText: ""
    property string analysisAveragePacketSizeBToAText: ""
    property string analysisAverageInterArrivalText: ""
    property string analysisMinPacketSizeText: ""
    property string analysisMinPacketSizeAToBText: ""
    property string analysisMinPacketSizeBToAText: ""
    property string analysisMaxPacketSizeText: ""
    property string analysisMaxPacketSizeAToBText: ""
    property string analysisMaxPacketSizeBToAText: ""
    property string analysisPacketRatioText: ""
    property string analysisByteRatioText: ""
    property string analysisPacketDirectionText: ""
    property string analysisDataDirectionText: ""
    property string analysisProtocolHint: ""
    property string analysisServiceHint: ""
    property string analysisProtocolVersionText: ""
    property string analysisProtocolServiceText: ""
    property string analysisProtocolFallbackText: ""
    property bool analysisHasTcpControlCounts: false
    property var analysisTcpSynPackets: 0
    property string analysisTcpSynPacketsText: ""
    property var analysisTcpFinPackets: 0
    property string analysisTcpFinPacketsText: ""
    property var analysisTcpRstPackets: 0
    property string analysisTcpRstPacketsText: ""
    property var analysisBurstCount: 0
    property string analysisBurstCountText: ""
    property var analysisLongestBurstPacketCount: 0
    property string analysisLongestBurstPacketCountText: ""
    property string analysisLargestBurstBytesText: ""
    property var analysisIdleGapCount: 0
    property string analysisIdleGapCountText: ""
    property string analysisLargestIdleGapText: ""
    property var analysisPacketsAToB: 0
    property string analysisPacketsAToBText: ""
    property var analysisPacketsBToA: 0
    property string analysisPacketsBToAText: ""
    property var analysisBytesAToB: 0
    property string analysisBytesAToBText: ""
    property var analysisBytesBToA: 0
    property string analysisBytesBToAText: ""
    property var analysisInterArrivalHistogramAll: []
    property var analysisInterArrivalHistogramAToB: []
    property var analysisInterArrivalHistogramBToA: []
    property var analysisInterArrivalHistogram: []
    property var analysisPacketSizeHistogramAll: []
    property var analysisPacketSizeHistogramAToB: []
    property var analysisPacketSizeHistogramBToA: []
    property var analysisPacketSizeHistogram: []
    property var analysisSequencePreview: []

    signal flowSelected(int flowIndex)
    signal openInFlowsRequested()
    signal exportFlowSequenceRequested()

    SplitView {
        anchors.fill: parent

        Frame {
            SplitView.fillHeight: true
            SplitView.preferredWidth: 440

            background: Rectangle {
                color: "#ffffff"
                border.color: "#d8dee9"
                radius: 8
            }

            ColumnLayout {
                anchors.fill: parent
                spacing: 10

                Label {
                    text: "Analysis Flows"
                    font.pixelSize: 18
                    font.bold: true
                }

                Label {
                    Layout.fillWidth: true
                    text: "Selected-flow analysis workspace"
                    color: "#64748b"
                }

                Rectangle {
                    Layout.fillWidth: true
                    height: 1
                    color: "#e2e8f0"
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 10

                    Label { text: "Index"; Layout.preferredWidth: 44 }
                    Label { text: "Hint"; Layout.preferredWidth: 70 }
                    Label { text: "Service"; Layout.fillWidth: true }
                    Label { text: "Packets"; Layout.preferredWidth: 58; horizontalAlignment: Text.AlignRight }
                    Label { text: "Bytes"; Layout.preferredWidth: 72; horizontalAlignment: Text.AlignRight }
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: "#f8fafc"
                    border.color: "#e2e8f0"
                    radius: 6

                    ListView {
                        id: analysisFlowList

                        anchors.fill: parent
                        anchors.margins: 1
                        clip: true
                        model: root.flowModel

                        ScrollBar.vertical: ScrollBar {
                            policy: ScrollBar.AsNeeded
                            visible: analysisFlowList.contentHeight > analysisFlowList.height
                        }

                        delegate: Rectangle {
                            id: analysisRow
                            required property int index
                            required property int flowIndex
                            required property string protocolHint
                            required property string serviceHint
                            required property string addressA
                            required property int portA
                            required property string addressB
                            required property int portB
                            required property string packets
                            required property string bytes

                            readonly property bool selected: root.selectedFlowIndex === flowIndex

                            width: analysisFlowList.width
                            height: 58
                            color: selected
                                ? "#dbeafe"
                                : (index % 2 === 0 ? "#ffffff" : "#f8fafc")
                            border.color: selected ? "#60a5fa" : "transparent"
                            border.width: selected ? 1 : 0
                            radius: 6

                            ColumnLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 12
                                anchors.rightMargin: 10
                                anchors.topMargin: 8
                                anchors.bottomMargin: 8
                                spacing: 4

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 10

                                    Label { text: flowIndex; Layout.preferredWidth: 44 }
                                    Label { text: protocolHint.length > 0 ? protocolHint : "-"; Layout.preferredWidth: 70; elide: Text.ElideRight }
                                    Label { text: serviceHint.length > 0 ? serviceHint : "-"; Layout.fillWidth: true; elide: Text.ElideRight }
                                    Label { text: packets; Layout.preferredWidth: 58; horizontalAlignment: Text.AlignRight }
                                    Label { text: bytes; Layout.preferredWidth: 72; horizontalAlignment: Text.AlignRight }
                                }

                                Label {
                                    Layout.fillWidth: true
                                    text: addressA + ":" + portA + "  <->  " + addressB + ":" + portB
                                    color: "#475569"
                                    elide: Text.ElideMiddle
                                }
                            }

                            Rectangle {
                                visible: selected
                                anchors.left: parent.left
                                anchors.top: parent.top
                                anchors.bottom: parent.bottom
                                width: 4
                                color: "#2563eb"
                                radius: 2
                            }

                            MouseArea {
                                anchors.fill: parent
                                onClicked: root.flowSelected(flowIndex)
                            }
                        }
                    }

                    Label {
                        anchors.centerIn: parent
                        visible: analysisFlowList.count === 0
                        color: "#64748b"
                        text: "No flows loaded"
                    }
                }
            }
        }

        FlowAnalysisPane {
            SplitView.fillWidth: true
            SplitView.fillHeight: true
            hasActiveFlow: root.selectedFlowIndex >= 0
            analysisLoading: root.analysisLoading
            analysisAvailable: root.analysisAvailable
            canExportAnalysisSequence: root.canExportAnalysisSequence
            sequenceExportInProgress: root.analysisSequenceExportInProgress
            sequenceExportStatusText: root.analysisSequenceExportStatusText
            sequenceExportStatusIsError: root.analysisSequenceExportStatusIsError
            durationText: root.analysisDurationText
            timelineFirstPacketTime: root.analysisTimelineFirstPacketTime
            timelineLastPacketTime: root.analysisTimelineLastPacketTime
            timelineLargestGapText: root.analysisTimelineLargestGapText
            timelinePacketCountConsidered: root.analysisTimelinePacketCountConsidered
            timelinePacketCountConsideredText: root.analysisTimelinePacketCountConsideredText
            totalPackets: root.analysisTotalPackets
            totalPacketsText: root.analysisTotalPacketsText
            totalBytes: root.analysisTotalBytes
            totalBytesText: root.analysisTotalBytesText
            endpointSummaryText: root.analysisEndpointSummaryText
            packetsPerSecondText: root.analysisPacketsPerSecondText
            packetsPerSecondAToBText: root.analysisPacketsPerSecondAToBText
            packetsPerSecondBToAText: root.analysisPacketsPerSecondBToAText
            bytesPerSecondText: root.analysisBytesPerSecondText
            bytesPerSecondAToBText: root.analysisBytesPerSecondAToBText
            bytesPerSecondBToAText: root.analysisBytesPerSecondBToAText
            averagePacketSizeText: root.analysisAveragePacketSizeText
            averagePacketSizeAToBText: root.analysisAveragePacketSizeAToBText
            averagePacketSizeBToAText: root.analysisAveragePacketSizeBToAText
            averageInterArrivalText: root.analysisAverageInterArrivalText
            minPacketSizeText: root.analysisMinPacketSizeText
            minPacketSizeAToBText: root.analysisMinPacketSizeAToBText
            minPacketSizeBToAText: root.analysisMinPacketSizeBToAText
            maxPacketSizeText: root.analysisMaxPacketSizeText
            maxPacketSizeAToBText: root.analysisMaxPacketSizeAToBText
            maxPacketSizeBToAText: root.analysisMaxPacketSizeBToAText
            packetRatioText: root.analysisPacketRatioText
            byteRatioText: root.analysisByteRatioText
            packetDirectionText: root.analysisPacketDirectionText
            dataDirectionText: root.analysisDataDirectionText
            protocolHint: root.analysisProtocolHint
            serviceHint: root.analysisServiceHint
            protocolVersionText: root.analysisProtocolVersionText
            protocolServiceText: root.analysisProtocolServiceText
            protocolFallbackText: root.analysisProtocolFallbackText
            hasTcpControlCounts: root.analysisHasTcpControlCounts
            tcpSynPackets: root.analysisTcpSynPackets
            tcpSynPacketsText: root.analysisTcpSynPacketsText
            tcpFinPackets: root.analysisTcpFinPackets
            tcpFinPacketsText: root.analysisTcpFinPacketsText
            tcpRstPackets: root.analysisTcpRstPackets
            tcpRstPacketsText: root.analysisTcpRstPacketsText
            burstCount: root.analysisBurstCount
            burstCountText: root.analysisBurstCountText
            longestBurstPacketCount: root.analysisLongestBurstPacketCount
            longestBurstPacketCountText: root.analysisLongestBurstPacketCountText
            largestBurstBytesText: root.analysisLargestBurstBytesText
            idleGapCount: root.analysisIdleGapCount
            idleGapCountText: root.analysisIdleGapCountText
            largestIdleGapText: root.analysisLargestIdleGapText
            packetsAToB: root.analysisPacketsAToB
            packetsAToBText: root.analysisPacketsAToBText
            packetsBToA: root.analysisPacketsBToA
            packetsBToAText: root.analysisPacketsBToAText
            bytesAToB: root.analysisBytesAToB
            bytesAToBText: root.analysisBytesAToBText
            bytesBToA: root.analysisBytesBToA
            bytesBToAText: root.analysisBytesBToAText
            interArrivalHistogramAllModel: root.analysisInterArrivalHistogramAll
            interArrivalHistogramAToBModel: root.analysisInterArrivalHistogramAToB
            interArrivalHistogramBToAModel: root.analysisInterArrivalHistogramBToA
            interArrivalHistogramModel: root.analysisInterArrivalHistogram
            packetSizeHistogramAllModel: root.analysisPacketSizeHistogramAll
            packetSizeHistogramAToBModel: root.analysisPacketSizeHistogramAToB
            packetSizeHistogramBToAModel: root.analysisPacketSizeHistogramBToA
            packetSizeHistogramModel: root.analysisPacketSizeHistogram
            sequencePreviewModel: root.analysisSequencePreview
            onOpenInFlowsRequested: root.openInFlowsRequested()
            onExportFlowSequenceRequested: root.exportFlowSequenceRequested()
        }
    }
}