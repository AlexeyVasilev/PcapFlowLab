import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    readonly property int blockPadding: 12
    readonly property int blockSpacing: 12
    readonly property int sectionSpacing: 8
    readonly property int rowSpacing: 8
    readonly property int histogramColumnSpacing: 8
    readonly property int histogramBarHeight: 18
    readonly property int groupBreakSpacing: 10
    readonly property int twoColumnMinWidth: 880
    readonly property int histogramModeAll: 0
    readonly property int histogramModeAToB: 1
    readonly property int histogramModeBToA: 2
    readonly property string forwardDirection: "A->B"
    readonly property string reverseDirection: "B->A"

    signal openInFlowsRequested()
    signal exportFlowSequenceRequested()

    component AnalysisSectionFrame: Frame {
        id: sectionFrame

        default property alias sectionContent: sectionLayout.data

        Layout.fillWidth: true
        padding: 0
        implicitHeight: sectionLayout.implicitHeight + (root.blockPadding * 3)

        background: Rectangle {
            color: "#ffffff"
            border.color: "#d8dee9"
            radius: 6
        }

        ColumnLayout {
            id: sectionLayout
            x: root.blockPadding
            y: root.blockPadding
            width: Math.max(0, parent.width - (root.blockPadding * 2))
            spacing: root.sectionSpacing
        }
    }

    component HistogramModeButton: Button {
        checkable: true
        implicitWidth: 64
        implicitHeight: 28
    }

    component HistogramInfoHint: Label {
        color: "#64748b"
        text: "ⓘ"
        font.pixelSize: 13

        ToolTip.visible: hintArea.containsMouse
        ToolTip.delay: 250
        ToolTip.timeout: 8000
        ToolTip.text: tooltipText

        required property string tooltipText

        MouseArea {
            id: hintArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
        }
    }

    function selectHistogramModel(mode, allModel, aToBModel, bToAModel) {
        if (mode === root.histogramModeAToB) {
            return aToBModel
        }
        if (mode === root.histogramModeBToA) {
            return bToAModel
        }
        return allModel
    }

    function histogramTotalCount(model) {
        var total = 0
        for (var index = 0; index < model.length; ++index) {
            total += model[index].packetCount
        }
        return total
    }

    function sequenceDirectionBackgroundColor(directionText) {
        if (directionText === root.forwardDirection || directionText === "A→B") {
            return "#e8f5ee"
        }

        if (directionText === root.reverseDirection || directionText === "B→A") {
            return "#eaf2ff"
        }

        return "transparent"
    }

    function sequenceDirectionTextColor(directionText) {
        if (directionText === root.forwardDirection || directionText === "A→B") {
            return "#2f6f4f"
        }

        if (directionText === root.reverseDirection || directionText === "B→A") {
            return "#315b91"
        }

        return "#0f172a"
    }

    property bool hasActiveFlow: false
    property bool analysisLoading: false
    property bool analysisAvailable: false
    property bool canExportAnalysisSequence: false
    property bool sequenceExportInProgress: false
    property string sequenceExportStatusText: ""
    property bool sequenceExportStatusIsError: false
    property string durationText: ""
    property string timelineFirstPacketTime: ""
    property string timelineLastPacketTime: ""
    property string timelineLargestGapText: ""
    property var timelinePacketCountConsidered: 0
    property string timelinePacketCountConsideredText: ""
    property var totalPackets: 0
    property string totalPacketsText: ""
    property var totalBytes: 0
    property string totalBytesText: ""
    property string endpointSummaryText: ""
    property string packetsPerSecondText: ""
    property string packetsPerSecondAToBText: ""
    property string packetsPerSecondBToAText: ""
    property string bytesPerSecondText: ""
    property string bytesPerSecondAToBText: ""
    property string bytesPerSecondBToAText: ""
    property string averagePacketSizeText: ""
    property string averagePacketSizeAToBText: ""
    property string averagePacketSizeBToAText: ""
    property string averageInterArrivalText: ""
    property string minPacketSizeText: ""
    property string minPacketSizeAToBText: ""
    property string minPacketSizeBToAText: ""
    property string maxPacketSizeText: ""
    property string maxPacketSizeAToBText: ""
    property string maxPacketSizeBToAText: ""
    property string packetRatioText: ""
    property string byteRatioText: ""
    property string packetDirectionText: ""
    property string dataDirectionText: ""
    property string protocolHint: ""
    property string serviceHint: ""
    property string protocolVersionText: ""
    property string protocolServiceText: ""
    property string protocolFallbackText: ""
    property bool hasTcpControlCounts: false
    property var tcpSynPackets: 0
    property string tcpSynPacketsText: ""
    property var tcpFinPackets: 0
    property string tcpFinPacketsText: ""
    property var tcpRstPackets: 0
    property string tcpRstPacketsText: ""
    property var burstCount: 0
    property string burstCountText: ""
    property var longestBurstPacketCount: 0
    property string longestBurstPacketCountText: ""
    property string largestBurstBytesText: ""
    property var idleGapCount: 0
    property string idleGapCountText: ""
    property string largestIdleGapText: ""
    property var packetsAToB: 0
    property string packetsAToBText: ""
    property var packetsBToA: 0
    property string packetsBToAText: ""
    property var bytesAToB: 0
    property string bytesAToBText: ""
    property var bytesBToA: 0
    property string bytesBToAText: ""
    property var interArrivalHistogramAllModel: []
    property var interArrivalHistogramAToBModel: []
    property var interArrivalHistogramBToAModel: []
    property var interArrivalHistogramModel: []
    property var packetSizeHistogramAllModel: []
    property var packetSizeHistogramAToBModel: []
    property var packetSizeHistogramBToAModel: []
    property var packetSizeHistogramModel: []
    property var sequencePreviewModel: []
    property int packetSizeHistogramMode: histogramModeAll
    property int interArrivalHistogramMode: histogramModeAll
    readonly property var displayedPacketSizeHistogramModel: selectHistogramModel(
        packetSizeHistogramMode,
        packetSizeHistogramAllModel.length > 0 ? packetSizeHistogramAllModel : packetSizeHistogramModel,
        packetSizeHistogramAToBModel,
        packetSizeHistogramBToAModel
    )
    readonly property var displayedInterArrivalHistogramModel: selectHistogramModel(
        interArrivalHistogramMode,
        interArrivalHistogramAllModel.length > 0 ? interArrivalHistogramAllModel : interArrivalHistogramModel,
        interArrivalHistogramAToBModel,
        interArrivalHistogramBToAModel
    )
    readonly property int displayedPacketSizeHistogramTotal: histogramTotalCount(displayedPacketSizeHistogramModel)
    readonly property int displayedInterArrivalHistogramTotal: histogramTotalCount(displayedInterArrivalHistogramModel)

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: root.blockSpacing

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Label {
                text: "Analysis"
                font.pixelSize: 18
                font.bold: true
            }

            Item {
                Layout.fillWidth: true
            }

            Button {
                objectName: "analysisOpenInFlowsButton"
                text: "Open in Flows"
                enabled: root.hasActiveFlow
                onClicked: root.openInFlowsRequested()
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            visible: root.sequenceExportInProgress || root.sequenceExportStatusText.length > 0

            BusyIndicator {
                running: root.sequenceExportInProgress
                visible: root.sequenceExportInProgress
                implicitWidth: 20
                implicitHeight: 20
            }

            Label {
                Layout.fillWidth: true
                text: root.sequenceExportInProgress
                    ? "Exporting flow sequence..."
                    : root.sequenceExportStatusText
                color: root.sequenceExportStatusIsError ? "#b91c1c" : "#475569"
                wrapMode: Text.WordWrap
            }
        }

        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            Rectangle {
                id: emptyStateCard
                objectName: "analysisEmptyState"
                anchors.centerIn: parent
                width: Math.min(parent.width - 24, 340)
                visible: !root.hasActiveFlow && !root.analysisLoading
                color: "#f8fafc"
                border.color: "#cbd5e1"
                radius: 10
                implicitHeight: emptyStateLayout.implicitHeight + 24

                ColumnLayout {
                    id: emptyStateLayout
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 6

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Select a flow to analyze"
                        font.pixelSize: 18
                        font.bold: true
                        color: "#0f172a"
                    }

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Choose a flow from the list on the left to open its analysis workspace."
                        color: "#64748b"
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.WordWrap
                    }
                }
            }

            Rectangle {
                id: loadingStateCard
                objectName: "analysisLoadingState"
                anchors.centerIn: parent
                width: Math.min(parent.width - 24, 300)
                visible: root.analysisLoading
                color: "#eff6ff"
                border.color: "#93c5fd"
                radius: 10
                implicitHeight: loadingStateLayout.implicitHeight + 24

                ColumnLayout {
                    id: loadingStateLayout
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 6

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Loading analysis..."
                        font.pixelSize: 18
                        font.bold: true
                        color: "#1d4ed8"
                    }

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Refreshing selected-flow analysis"
                        color: "#475569"
                    }
                }
            }

            Rectangle {
                id: unavailableStateCard
                objectName: "analysisUnavailableState"
                anchors.centerIn: parent
                width: Math.min(parent.width - 24, 340)
                visible: root.hasActiveFlow && !root.analysisLoading && !root.analysisAvailable
                color: "#f8fafc"
                border.color: "#cbd5e1"
                radius: 10
                implicitHeight: unavailableStateLayout.implicitHeight + 24

                ColumnLayout {
                    id: unavailableStateLayout
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 6

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Analysis unavailable"
                        font.pixelSize: 18
                        font.bold: true
                        color: "#0f172a"
                    }

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Analysis is unavailable for the selected flow."
                        color: "#64748b"
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.WordWrap
                    }
                }
            }

            ScrollView {
                id: analysisResultScroll
                objectName: "analysisResultContent"
                anchors.fill: parent
                clip: true
                visible: root.analysisAvailable && !root.analysisLoading

                ScrollBar.vertical.policy: ScrollBar.AsNeeded

                ColumnLayout {
                    width: analysisResultScroll.availableWidth
                    spacing: root.blockSpacing

                    AnalysisSectionFrame {
                        Label {
                            text: "Overview"
                            font.bold: true
                        }

                        Label {
                            objectName: "analysisEndpointSummaryLabel"
                            visible: root.endpointSummaryText.length > 0
                            text: root.endpointSummaryText
                            color: "#334155"
                            font.bold: true
                            wrapMode: Text.WordWrap
                        }

                        RowLayout {
                            width: parent.width
                            spacing: root.blockSpacing

                            GridLayout {
                                Layout.fillWidth: true
                                columns: 2
                                columnSpacing: 16
                                rowSpacing: root.rowSpacing

                                Label { text: "Total packets" }
                                Label { text: root.totalPacketsText.length > 0 ? root.totalPacketsText : "0" }

                                Label { text: "Total bytes" }
                                Label { text: root.totalBytesText.length > 0 ? root.totalBytesText : "0 B" }

                                Label { text: "Protocol hint" }
                                Label { text: root.protocolHint.length > 0 ? root.protocolHint : "-" }

                                Label { text: "Service hint" }
                                Label { text: root.serviceHint.length > 0 ? root.serviceHint : "-"; elide: Text.ElideRight; Layout.fillWidth: true }
                            }

                            Rectangle {
                                Layout.fillHeight: true
                                Layout.preferredWidth: 1
                                color: "#e2e8f0"
                            }

                            GridLayout {
                                Layout.fillWidth: true
                                columns: 2
                                columnSpacing: 16
                                rowSpacing: root.rowSpacing

                                Label { text: "First packet" }
                                Label { text: root.timelineFirstPacketTime.length > 0 ? root.timelineFirstPacketTime : "-" }

                                Label { text: "Last packet" }
                                Label { text: root.timelineLastPacketTime.length > 0 ? root.timelineLastPacketTime : "-" }

                                Label { text: "Duration" }
                                Label { text: root.durationText.length > 0 ? root.durationText : "-" }

                                Label { text: "Largest gap" }
                                Label { text: root.timelineLargestGapText.length > 0 ? root.timelineLargestGapText : "-" }

                                Label { text: "Packets considered" }
                                Label { text: root.timelinePacketCountConsideredText.length > 0 ? root.timelinePacketCountConsideredText : "0" }
                            }
                        }
                    }

                    AnalysisSectionFrame {
                        Label {
                            text: "Protocol Panel"
                            font.bold: true
                        }

                        GridLayout {
                            width: parent.width
                            columns: 2
                            columnSpacing: 16
                            rowSpacing: root.rowSpacing
                            visible: root.protocolHint === "TLS" || root.protocolHint === "QUIC"

                            Label {
                                text: root.protocolHint === "TLS" ? "TLS version" : "QUIC version"
                            }
                            Label {
                                text: root.protocolVersionText.length > 0 ? root.protocolVersionText : "unknown"
                            }

                            Label { text: "SNI / service" }
                            Label {
                                text: root.protocolServiceText.length > 0 ? root.protocolServiceText : "unknown"
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }

                        Rectangle {
                            visible: (root.protocolHint === "TLS" || root.protocolHint === "QUIC") && root.hasTcpControlCounts
                            width: parent.width
                            height: 1
                            color: "#e2e8f0"
                        }

                        GridLayout {
                            width: parent.width
                            columns: 2
                            columnSpacing: 16
                            rowSpacing: root.rowSpacing
                            visible: root.hasTcpControlCounts

                            Label { text: "SYN packets" }
                            Label { text: root.tcpSynPacketsText.length > 0 ? root.tcpSynPacketsText : "0" }

                            Label { text: "FIN packets" }
                            Label { text: root.tcpFinPacketsText.length > 0 ? root.tcpFinPacketsText : "0" }

                            Label { text: "RST packets" }
                            Label { text: root.tcpRstPacketsText.length > 0 ? root.tcpRstPacketsText : "0" }
                        }

                        Label {
                            visible: !((root.protocolHint === "TLS" || root.protocolHint === "QUIC") || root.hasTcpControlCounts)
                            text: root.protocolFallbackText.length > 0 ? root.protocolFallbackText : "No protocol-specific metadata available"
                            color: "#475569"
                            wrapMode: Text.WordWrap
                        }
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: width >= root.twoColumnMinWidth ? 2 : 1
                        columnSpacing: root.blockSpacing
                        rowSpacing: root.blockSpacing

                        AnalysisSectionFrame {
                            Label {
                                text: "Derived Metrics"
                                font.bold: true
                            }

                            GridLayout {
                                width: parent.width
                                columns: 4
                                columnSpacing: 16
                                rowSpacing: root.rowSpacing

                                Label { text: "Metric"; color: "#475569" }
                                Label { text: "All"; color: "#475569" }
                                Label { text: "A→B"; color: "#475569" }
                                Label { text: "B→A"; color: "#475569" }

                                Label { text: "Packets/sec" }
                                Label { text: root.packetsPerSecondText.length > 0 ? root.packetsPerSecondText : "-" }
                                Label { text: root.packetsPerSecondAToBText.length > 0 ? root.packetsPerSecondAToBText : "-" }
                                Label { text: root.packetsPerSecondBToAText.length > 0 ? root.packetsPerSecondBToAText : "-" }

                                Label { text: "Data rate" }
                                Label { text: root.bytesPerSecondText.length > 0 ? root.bytesPerSecondText : "-" }
                                Label { text: root.bytesPerSecondAToBText.length > 0 ? root.bytesPerSecondAToBText : "-" }
                                Label { text: root.bytesPerSecondBToAText.length > 0 ? root.bytesPerSecondBToAText : "-" }

                                Label { text: "Avg packet size" }
                                Label { text: root.averagePacketSizeText.length > 0 ? root.averagePacketSizeText : "-" }
                                Label { text: root.averagePacketSizeAToBText.length > 0 ? root.averagePacketSizeAToBText : "-" }
                                Label { text: root.averagePacketSizeBToAText.length > 0 ? root.averagePacketSizeBToAText : "-" }

                                Label { text: "Avg inter-arrival" }
                                Label { text: root.averageInterArrivalText.length > 0 ? root.averageInterArrivalText : "-" }
                                Label { text: "—" }
                                Label { text: "—" }

                                Label { text: "Min packet size" }
                                Label { text: root.minPacketSizeText.length > 0 ? root.minPacketSizeText : "-" }
                                Label { text: root.minPacketSizeAToBText.length > 0 ? root.minPacketSizeAToBText : "—" }
                                Label { text: root.minPacketSizeBToAText.length > 0 ? root.minPacketSizeBToAText : "—" }

                                Label { text: "Max packet size" }
                                Label { text: root.maxPacketSizeText.length > 0 ? root.maxPacketSizeText : "-" }
                                Label { text: root.maxPacketSizeAToBText.length > 0 ? root.maxPacketSizeAToBText : "—" }
                                Label { text: root.maxPacketSizeBToAText.length > 0 ? root.maxPacketSizeBToAText : "—" }
                            }
                        }

                        AnalysisSectionFrame {
                            Label {
                                text: "Burst / Idle Summary"
                                font.bold: true
                            }

                            GridLayout {
                                width: parent.width
                                columns: 2
                                columnSpacing: 16
                                rowSpacing: root.rowSpacing

                                Label { text: "Burst count" }
                                Label { text: root.burstCountText.length > 0 ? root.burstCountText : "0" }

                                Label { text: "Longest burst" }
                                Label { text: root.longestBurstPacketCountText.length > 0 ? root.longestBurstPacketCountText : "0" }

                                Label { text: "Largest burst bytes" }
                                Label { text: root.largestBurstBytesText.length > 0 ? root.largestBurstBytesText : "0 B" }

                                Label { text: "Idle gap count" }
                                Label { text: root.idleGapCountText.length > 0 ? root.idleGapCountText : "0" }

                                Label { text: "Largest idle gap" }
                                Label { text: root.largestIdleGapText.length > 0 ? root.largestIdleGapText : "0 us" }
                            }
                        }
                    }

                    AnalysisSectionFrame {
                        Label {
                            text: "Directional"
                            font.bold: true
                        }

                        RowLayout {
                            width: parent.width
                            spacing: root.blockSpacing

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: root.sectionSpacing

                                Label {
                                    text: "Directional"
                                    color: "#475569"
                                }

                                GridLayout {
                                    width: parent.width
                                    columns: 3
                                    columnSpacing: 16
                                    rowSpacing: root.rowSpacing

                                    Label { text: "" }
                                    Label { text: "A->B" }
                                    Label { text: "B->A" }

                                    Label { text: "Packets" }
                                    Label { text: root.packetsAToBText.length > 0 ? root.packetsAToBText : "0" }
                                    Label { text: root.packetsBToAText.length > 0 ? root.packetsBToAText : "0" }

                                    Label { text: "Bytes" }
                                    Label { text: root.bytesAToBText.length > 0 ? root.bytesAToBText : "0 B" }
                                    Label { text: root.bytesBToAText.length > 0 ? root.bytesBToAText : "0 B" }
                                }
                            }

                            Rectangle {
                                Layout.fillHeight: true
                                Layout.preferredWidth: 1
                                color: "#e2e8f0"
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: root.sectionSpacing

                                Label {
                                    text: "Ratios"
                                    color: "#475569"
                                }

                                GridLayout {
                                    width: parent.width
                                    columns: 2
                                    columnSpacing: 16
                                    rowSpacing: root.rowSpacing

                                    Label { text: "Packet ratio" }
                                    Label { text: root.packetRatioText.length > 0 ? root.packetRatioText : "-" }

                                    Label { text: "Byte ratio" }
                                    Label { text: root.byteRatioText.length > 0 ? root.byteRatioText : "-" }

                                    Label { text: "Packet direction" }
                                    Label { text: root.packetDirectionText.length > 0 ? root.packetDirectionText : "-" }

                                    Label { text: "Data direction" }
                                    Label { text: root.dataDirectionText.length > 0 ? root.dataDirectionText : "-" }
                                }
                            }
                        }
                    }

                    Item {
                        Layout.fillWidth: true
                        implicitHeight: root.groupBreakSpacing
                    }

                    AnalysisSectionFrame {
                        RowLayout {
                            width: parent.width
                            spacing: 12

                            Label {
                                text: "Packet Size Histogram"
                                font.bold: true
                            }

                            HistogramInfoHint {
                                tooltipText: "Shows packet size distribution. Directional modes filter packets by flow direction."
                            }

                            Item {
                                Layout.fillWidth: true
                            }

                            Rectangle {
                                color: "#f8fafc"
                                border.color: "#cbd5e1"
                                radius: 6
                                implicitHeight: packetSizeModeLayout.implicitHeight + 4
                                implicitWidth: packetSizeModeLayout.implicitWidth + 8

                                RowLayout {
                                    id: packetSizeModeLayout
                                    anchors.fill: parent
                                    anchors.margins: 2
                                    spacing: 2

                                    ButtonGroup {
                                        id: packetSizeHistogramModeGroup
                                    }

                                    HistogramModeButton {
                                        objectName: "packetSizeHistogramModeAllButton"
                                        text: "All"
                                        checked: root.packetSizeHistogramMode === root.histogramModeAll
                                        ButtonGroup.group: packetSizeHistogramModeGroup
                                        onClicked: root.packetSizeHistogramMode = root.histogramModeAll
                                    }

                                    HistogramModeButton {
                                        objectName: "packetSizeHistogramModeAToBButton"
                                        text: "A→B"
                                        checked: root.packetSizeHistogramMode === root.histogramModeAToB
                                        ButtonGroup.group: packetSizeHistogramModeGroup
                                        onClicked: root.packetSizeHistogramMode = root.histogramModeAToB
                                    }

                                    HistogramModeButton {
                                        objectName: "packetSizeHistogramModeBToAButton"
                                        text: "B→A"
                                        checked: root.packetSizeHistogramMode === root.histogramModeBToA
                                        ButtonGroup.group: packetSizeHistogramModeGroup
                                        onClicked: root.packetSizeHistogramMode = root.histogramModeBToA
                                    }
                                }
                            }
                        }

                        Repeater {
                            model: root.displayedPacketSizeHistogramModel

                            delegate: RowLayout {
                                required property var modelData
                                width: parent.width
                                spacing: root.histogramColumnSpacing

                                Label {
                                    text: modelData.bucketLabel
                                    Layout.preferredWidth: 94
                                    Layout.alignment: Qt.AlignVCenter
                                }

                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.topMargin: 2
                                    Layout.bottomMargin: 2
                                    implicitHeight: root.histogramBarHeight
                                    radius: 4
                                    color: "#f1f5f9"
                                    border.color: "#dbe3ee"

                                    Rectangle {
                                        anchors.left: parent.left
                                        anchors.top: parent.top
                                        anchors.bottom: parent.bottom
                                        width: parent.width * (root.displayedPacketSizeHistogramTotal > 0 ? modelData.packetCount / root.displayedPacketSizeHistogramTotal : 0)
                                        radius: 4
                                        color: modelData.packetCount > 0 ? "#60a5fa" : "transparent"
                                    }
                                }

                                Label {
                                    text: modelData.packetCountText
                                    Layout.preferredWidth: 64
                                    Layout.alignment: Qt.AlignVCenter
                                    horizontalAlignment: Text.AlignRight
                                }
                            }
                        }
                    }

                    AnalysisSectionFrame {
                        RowLayout {
                            width: parent.width
                            spacing: 12

                            Label {
                                text: "Inter-arrival Histogram"
                                font.bold: true
                            }

                            HistogramInfoHint {
                                tooltipText: "Inter-arrival times use the full packet timeline. Each interval follows the direction of the later packet."
                            }

                            Item {
                                Layout.fillWidth: true
                            }

                            Rectangle {
                                color: "#f8fafc"
                                border.color: "#cbd5e1"
                                radius: 6
                                implicitHeight: interArrivalModeLayout.implicitHeight + 4
                                implicitWidth: interArrivalModeLayout.implicitWidth + 8

                                RowLayout {
                                    id: interArrivalModeLayout
                                    anchors.fill: parent
                                    anchors.margins: 2
                                    spacing: 2

                                    ButtonGroup {
                                        id: interArrivalHistogramModeGroup
                                    }

                                    HistogramModeButton {
                                        objectName: "interArrivalHistogramModeAllButton"
                                        text: "All"
                                        checked: root.interArrivalHistogramMode === root.histogramModeAll
                                        ButtonGroup.group: interArrivalHistogramModeGroup
                                        onClicked: root.interArrivalHistogramMode = root.histogramModeAll
                                    }

                                    HistogramModeButton {
                                        objectName: "interArrivalHistogramModeAToBButton"
                                        text: "A→B"
                                        checked: root.interArrivalHistogramMode === root.histogramModeAToB
                                        ButtonGroup.group: interArrivalHistogramModeGroup
                                        onClicked: root.interArrivalHistogramMode = root.histogramModeAToB
                                    }

                                    HistogramModeButton {
                                        objectName: "interArrivalHistogramModeBToAButton"
                                        text: "B→A"
                                        checked: root.interArrivalHistogramMode === root.histogramModeBToA
                                        ButtonGroup.group: interArrivalHistogramModeGroup
                                        onClicked: root.interArrivalHistogramMode = root.histogramModeBToA
                                    }
                                }
                            }
                        }

                        Repeater {
                            model: root.displayedInterArrivalHistogramModel

                            delegate: RowLayout {
                                required property var modelData
                                width: parent.width
                                spacing: root.histogramColumnSpacing

                                Label {
                                    text: modelData.bucketLabel
                                    Layout.preferredWidth: 94
                                    Layout.alignment: Qt.AlignVCenter
                                }

                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.topMargin: 2
                                    Layout.bottomMargin: 2
                                    implicitHeight: root.histogramBarHeight
                                    radius: 4
                                    color: "#f8fafc"
                                    border.color: "#dbe3ee"

                                    Rectangle {
                                        anchors.left: parent.left
                                        anchors.top: parent.top
                                        anchors.bottom: parent.bottom
                                        width: parent.width * (root.displayedInterArrivalHistogramTotal > 0 ? modelData.packetCount / root.displayedInterArrivalHistogramTotal : 0)
                                        radius: 4
                                        color: modelData.packetCount > 0 ? "#38bdf8" : "transparent"
                                    }
                                }

                                Label {
                                    text: modelData.packetCountText
                                    Layout.preferredWidth: 64
                                    Layout.alignment: Qt.AlignVCenter
                                    horizontalAlignment: Text.AlignRight
                                }
                            }
                        }
                    }

                    AnalysisSectionFrame {
                        RowLayout {
                            width: parent.width
                            spacing: 12

                            Label {
                                text: "Sequence Preview"
                                font.bold: true
                            }

                            Item {
                                Layout.fillWidth: true
                            }

                            Button {
                                objectName: "analysisExportFlowSequenceButton"
                                text: "Export flow sequence"
                                enabled: root.canExportAnalysisSequence && !root.sequenceExportInProgress
                                onClicked: root.exportFlowSequenceRequested()
                            }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: root.histogramColumnSpacing

                            Label { text: "#"; Layout.preferredWidth: 34 }
                            Label { text: "Dir"; Layout.preferredWidth: 48 }
                            Label { text: "Delta"; Layout.preferredWidth: 90 }
                            Label { text: "Captured"; Layout.preferredWidth: 70; horizontalAlignment: Text.AlignRight }
                            Label { text: "Payload"; Layout.preferredWidth: 64; horizontalAlignment: Text.AlignRight }
                            Label { text: "Time"; Layout.fillWidth: true }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            height: 1
                            color: "#e2e8f0"
                        }

                        Repeater {
                            model: root.sequencePreviewModel

                            delegate: RowLayout {
                                required property var modelData
                                width: parent.width
                                spacing: root.histogramColumnSpacing

                                Label { text: modelData.packetNumber; Layout.preferredWidth: 34 }
                                Rectangle {
                                    objectName: "analysisSequenceDirectionChip" + parseInt(modelData.packetNumber, 10)
                                    Layout.preferredWidth: 56
                                    Layout.alignment: Qt.AlignVCenter
                                    implicitHeight: 22
                                    radius: 4
                                    color: root.sequenceDirectionBackgroundColor(modelData.direction)
                                    border.color: color === "transparent" ? "transparent" : Qt.darker(color, 1.08)

                                    Label {
                                        anchors.centerIn: parent
                                        text: modelData.direction
                                        color: root.sequenceDirectionTextColor(modelData.direction)
                                    }
                                }
                                Label { text: modelData.deltaTimeText; Layout.preferredWidth: 90 }
                                Label { text: modelData.capturedLength; Layout.preferredWidth: 70; horizontalAlignment: Text.AlignRight }
                                Label { text: modelData.payloadLength; Layout.preferredWidth: 64; horizontalAlignment: Text.AlignRight }
                                Label { text: modelData.timestampText; Layout.fillWidth: true; color: "#475569" }
                            }
                        }
                    }
                }
            }
        }
    }
}
