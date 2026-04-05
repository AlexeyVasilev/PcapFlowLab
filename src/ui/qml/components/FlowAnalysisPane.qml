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
    readonly property int rateMetricData: 0
    readonly property int rateMetricPackets: 1
    readonly property int rateDirectionAToB: 0
    readonly property int rateDirectionBToA: 1
    readonly property int rateDirectionBoth: 2
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

    function endpointLineText(summaryText) {
        var separatorIndex = summaryText.lastIndexOf(" ")
        return separatorIndex >= 0 ? summaryText.slice(0, separatorIndex) : summaryText
    }

    function endpointTransportText(summaryText) {
        var separatorIndex = summaryText.lastIndexOf(" ")
        return separatorIndex >= 0 ? summaryText.slice(separatorIndex + 1) : ""
    }

    function protocolLineText() {
        var transportText = root.endpointTransportText(root.endpointSummaryText)
        if (transportText.length > 0 && root.protocolHint.length > 0) {
            return "Protocol: " + transportText + " (" + root.protocolHint + ")"
        }

        if (transportText.length > 0) {
            return "Protocol: " + transportText
        }

        if (root.protocolHint.length > 0) {
            return "Protocol: " + root.protocolHint
        }

        return ""
    }

    function histogramMaxCountText(model) {
        var maxIndex = -1
        var maxCount = -1
        for (var index = 0; index < model.length; ++index) {
            var count = model[index].packetCount
            if (count > maxCount) {
                maxCount = count
                maxIndex = index
            }
        }

        if (maxIndex < 0) {
            return "max: 0"
        }

        return "max: " + model[maxIndex].packetCountText
    }

    function ratePointValue(point) {
        return rateMetricMode === rateMetricPackets ? point.packetsPerSecond : point.dataPerSecond
    }

    function rateSeriesMaxValue(series) {
        var maxValue = 0
        for (var index = 0; index < series.length; ++index) {
            var value = ratePointValue(series[index])
            if (value > maxValue) {
                maxValue = value
            }
        }
        return maxValue
    }

    function rateGraphMaxXValue(seriesA, seriesB) {
        var maxX = 0
        if (seriesA.length > 0) {
            maxX = Math.max(maxX, seriesA[seriesA.length - 1].xUs)
        }
        if (seriesB.length > 0) {
            maxX = Math.max(maxX, seriesB[seriesB.length - 1].xUs)
        }
        return maxX
    }

    function rateGraphMaxYValue(seriesA, seriesB) {
        return Math.max(rateSeriesMaxValue(seriesA), rateSeriesMaxValue(seriesB))
    }

    function ratePointIsZero(point) {
        return point.dataPerSecond === 0 && point.packetsPerSecond === 0
    }

    function rateGraphTrimmedPointCount(seriesA, seriesB) {
        var countA = seriesA.length
        var countB = seriesB.length
        var count = Math.max(countA, countB)
        var index = count - 1
        while (index >= 0) {
            var pointA = index < countA ? seriesA[index] : null
            var pointB = index < countB ? seriesB[index] : null
            var zeroA = pointA === null || ratePointIsZero(pointA)
            var zeroB = pointB === null || ratePointIsZero(pointB)
            if (!zeroA || !zeroB) {
                return index + 1
            }
            index -= 1
        }
        return 0
    }

    function rateSeriesPrefix(series, count) {
        var limit = Math.min(series.length, count)
        var points = []
        for (var index = 0; index < limit; ++index) {
            points.push(series[index])
        }
        return points
    }

    function formatRateNumber(value, decimals) {
        var text = value.toFixed(decimals)
        text = text.replace(/\.?0+$/, "")
        return text
    }

    function rateUnitForValue(maxValue) {
        if (rateMetricMode === rateMetricPackets) {
            return "pkt/s"
        }
        if (maxValue >= 1024 * 1024) {
            return "MB/s"
        }
        if (maxValue >= 1024) {
            return "KB/s"
        }
        return "B/s"
    }

    function scaledRateValue(value, unit) {
        if (unit === "MB/s") {
            return value / (1024 * 1024)
        }
        if (unit === "KB/s") {
            return value / 1024
        }
        return value
    }

    function formatPeakRateValue(value, unit) {
        var scaled = scaledRateValue(value, unit)
        var decimals = unit === "B/s" || unit === "pkt/s" ? 0 : 2
        return formatRateNumber(scaled, decimals) + " " + unit
    }

    function formatWindowContextText(windowText) {
        if (windowText.length === 0) {
            return "Window: -"
        }

        var match = /^Window:\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|s)\s*\(auto\)$/.exec(windowText)
        if (match === null) {
            return windowText
        }

        var value = parseFloat(match[1])
        if (isNaN(value)) {
            return windowText
        }

        var windowMs = match[2] === "s" ? value * 1000 : value
        if (windowMs < 1000) {
            return "Window: " + Math.max(1, Math.round(windowMs)) + " ms (auto)"
        }

        return "Window: " + (windowMs / 1000).toFixed(1) + " s (auto)"
    }
    property bool hasActiveFlow: false
    property bool analysisLoading: false
    property bool analysisAvailable: false
    property bool rateGraphAvailable: false
    property string rateGraphStatusText: ""
    property string rateGraphWindowText: ""
    property var rateSeriesAToBModel: []
    property var rateSeriesBToAModel: []
    property int rateMetricMode: rateMetricData
    property int rateDirectionMode: rateDirectionBoth
    readonly property var renderedRateSeriesAToB: (rateDirectionMode === rateDirectionAToB || rateDirectionMode === rateDirectionBoth) ? rateSeriesAToBModel : []
    readonly property var renderedRateSeriesBToA: (rateDirectionMode === rateDirectionBToA || rateDirectionMode === rateDirectionBoth) ? rateSeriesBToAModel : []
    readonly property int rateGraphPointCount: rateGraphTrimmedPointCount(rateSeriesAToBModel, rateSeriesBToAModel)
    readonly property var graphSeriesAToB: (rateDirectionMode === rateDirectionAToB || rateDirectionMode === rateDirectionBoth) ? rateSeriesPrefix(rateSeriesAToBModel, rateGraphPointCount) : []
    readonly property var graphSeriesBToA: (rateDirectionMode === rateDirectionBToA || rateDirectionMode === rateDirectionBoth) ? rateSeriesPrefix(rateSeriesBToAModel, rateGraphPointCount) : []
    readonly property bool rateGraphHasVisibleSeries: graphSeriesAToB.length > 0 || graphSeriesBToA.length > 0
    readonly property real rateGraphPeakRawValue: rateGraphMaxYValue(graphSeriesAToB, graphSeriesBToA)
    readonly property string rateGraphUnit: rateUnitForValue(rateGraphPeakRawValue)
    readonly property string rateGraphMetricLabel: rateMetricMode === rateMetricData ? "Data rate (" + rateGraphUnit + ")" : "Packets rate (pkt/s)"
    readonly property string rateGraphPeakText: "Peak: " + formatPeakRateValue(rateGraphPeakRawValue, rateGraphUnit)
    readonly property string rateGraphHeaderLine1: rateGraphMetricLabel + " \u2022 " + rateGraphPeakText
    readonly property string rateGraphWindowDisplayText: formatWindowContextText(rateGraphWindowText)
    readonly property string rateGraphContextText: "Duration: " + (durationText.length > 0 ? durationText : "-")
        + " \u2022 " + rateGraphWindowDisplayText
        + " \u2022 Samples: " + rateGraphPointCount
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
    readonly property real derivedMetricsMetricColumnWidth: 150
    readonly property real derivedMetricsValueColumnWidth: 104

    function requestRateGraphRepaint() {
        if (typeof rateGraphCanvas !== "undefined" && rateGraphCanvas !== null) {
            rateGraphCanvas.requestPaint()
        }
    }

    onRenderedRateSeriesAToBChanged: requestRateGraphRepaint()
    onRenderedRateSeriesBToAChanged: requestRateGraphRepaint()
    onGraphSeriesAToBChanged: requestRateGraphRepaint()
    onGraphSeriesBToAChanged: requestRateGraphRepaint()
    onRateMetricModeChanged: requestRateGraphRepaint()
    onRateDirectionModeChanged: requestRateGraphRepaint()
    onRateGraphAvailableChanged: requestRateGraphRepaint()
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
                            text: root.endpointLineText(root.endpointSummaryText)
                            color: "#334155"
                            font.bold: true
                            wrapMode: Text.WordWrap
                        }

                        Label {
                            objectName: "analysisProtocolSummaryLabel"
                            visible: root.protocolLineText().length > 0
                            text: root.protocolLineText()
                            color: "#475569"
                            wrapMode: Text.WordWrap
                        }

                        RowLayout {
                            Layout.fillWidth: true
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
                            Layout.fillWidth: true
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
                            Layout.fillWidth: true
                            height: 1
                            color: "#e2e8f0"
                        }

                        GridLayout {
                            Layout.fillWidth: true
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
                            Layout.fillWidth: true
                                columns: 4
                                columnSpacing: 16
                                rowSpacing: root.rowSpacing

                                Label { text: "Metric"; color: "#475569" }
                                Label { text: "All"; color: "#475569"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: "A→B"; color: "#475569"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: "B→A"; color: "#475569"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }

                                Label { text: "Packets/sec"; Layout.preferredWidth: root.derivedMetricsMetricColumnWidth }
                                Label { text: root.packetsPerSecondText.length > 0 ? root.packetsPerSecondText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: root.packetsPerSecondAToBText.length > 0 ? root.packetsPerSecondAToBText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: root.packetsPerSecondBToAText.length > 0 ? root.packetsPerSecondBToAText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }

                                Label { text: "Data rate"; Layout.preferredWidth: root.derivedMetricsMetricColumnWidth }
                                Label { text: root.bytesPerSecondText.length > 0 ? root.bytesPerSecondText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: root.bytesPerSecondAToBText.length > 0 ? root.bytesPerSecondAToBText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: root.bytesPerSecondBToAText.length > 0 ? root.bytesPerSecondBToAText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }

                                Label { text: "Avg packet size"; Layout.preferredWidth: root.derivedMetricsMetricColumnWidth }
                                Label { text: root.averagePacketSizeText.length > 0 ? root.averagePacketSizeText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: root.averagePacketSizeAToBText.length > 0 ? root.averagePacketSizeAToBText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: root.averagePacketSizeBToAText.length > 0 ? root.averagePacketSizeBToAText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }

                                Label { text: "Avg inter-arrival"; Layout.preferredWidth: root.derivedMetricsMetricColumnWidth }
                                Label { text: root.averageInterArrivalText.length > 0 ? root.averageInterArrivalText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: "—"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: "—"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }

                                Label { text: "Min packet size"; Layout.preferredWidth: root.derivedMetricsMetricColumnWidth }
                                Label { text: root.minPacketSizeText.length > 0 ? root.minPacketSizeText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: root.minPacketSizeAToBText.length > 0 ? root.minPacketSizeAToBText : "—"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: root.minPacketSizeBToAText.length > 0 ? root.minPacketSizeBToAText : "—"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }

                                Label { text: "Max packet size"; Layout.preferredWidth: root.derivedMetricsMetricColumnWidth }
                                Label { text: root.maxPacketSizeText.length > 0 ? root.maxPacketSizeText : "-"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: root.maxPacketSizeAToBText.length > 0 ? root.maxPacketSizeAToBText : "—"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                                Label { text: root.maxPacketSizeBToAText.length > 0 ? root.maxPacketSizeBToAText : "—"; horizontalAlignment: Text.AlignRight; Layout.preferredWidth: root.derivedMetricsValueColumnWidth }
                            }
                        }

                        AnalysisSectionFrame {
                            Label {
                                text: "Burst / Idle Summary"
                                font.bold: true
                            }

                            GridLayout {
                            Layout.fillWidth: true
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
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 10

                            Label {
                                objectName: "analysisRateUnitLabel"
                                Layout.fillWidth: true
                                text: root.rateGraphHeaderLine1
                                color: "#475569"
                                elide: Text.ElideRight
                            }

                            Label {
                                objectName: "analysisRatePeakLabel"
                                visible: false
                                text: root.rateGraphPeakText
                            }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 10

                            Label {
                                objectName: "analysisRateContextLabel"
                                Layout.fillWidth: true
                                text: root.rateGraphContextText
                                color: "#64748b"
                                wrapMode: Text.WordWrap
                            }

                            Label {
                                objectName: "analysisRateWindowLabel"
                                visible: false
                                text: root.rateGraphWindowText
                            }

                            RowLayout {
                                visible: root.rateDirectionMode === root.rateDirectionBoth && root.rateGraphAvailable && root.rateGraphHasVisibleSeries
                                spacing: 8

                                Rectangle {
                                    implicitWidth: 10
                                    implicitHeight: 10
                                    radius: 2
                                    color: "#22c55e"
                                }

                                Label {
                                    objectName: "analysisRateLegendAToB"
                                    text: "A\u2192B"
                                    color: "#2f6f4f"
                                }

                                Rectangle {
                                    implicitWidth: 10
                                    implicitHeight: 10
                                    radius: 2
                                    color: "#3b82f6"
                                }

                                Label {
                                    objectName: "analysisRateLegendBToA"
                                    text: "B\u2192A"
                                    color: "#315b91"
                                }
                            }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 10

                            Rectangle {
                                color: "#f8fafc"
                                border.color: "#cbd5e1"
                                radius: 6
                                implicitHeight: rateMetricModeLayout.implicitHeight + 4
                                implicitWidth: rateMetricModeLayout.implicitWidth + 8

                                RowLayout {
                                    id: rateMetricModeLayout
                                    anchors.fill: parent
                                    anchors.margins: 2
                                    spacing: 2

                                    ButtonGroup {
                                        id: rateMetricModeGroup
                                    }

                                    HistogramModeButton {
                                        objectName: "analysisRateMetricDataButton"
                                        text: "Data/s"
                                        checked: root.rateMetricMode === root.rateMetricData
                                        ButtonGroup.group: rateMetricModeGroup
                                        onClicked: root.rateMetricMode = root.rateMetricData
                                    }

                                    HistogramModeButton {
                                        objectName: "analysisRateMetricPacketsButton"
                                        text: "Packets/s"
                                        checked: root.rateMetricMode === root.rateMetricPackets
                                        ButtonGroup.group: rateMetricModeGroup
                                        onClicked: root.rateMetricMode = root.rateMetricPackets
                                    }
                                }
                            }

                            Rectangle {
                                color: "#f8fafc"
                                border.color: "#cbd5e1"
                                radius: 6
                                implicitHeight: rateDirectionModeLayout.implicitHeight + 4
                                implicitWidth: rateDirectionModeLayout.implicitWidth + 8

                                RowLayout {
                                    id: rateDirectionModeLayout
                                    anchors.fill: parent
                                    anchors.margins: 2
                                    spacing: 2

                                    ButtonGroup {
                                        id: rateDirectionModeGroup
                                    }

                                    HistogramModeButton {
                                        objectName: "analysisRateDirectionAToBButton"
                                        text: "A->B"
                                        checked: root.rateDirectionMode === root.rateDirectionAToB
                                        ButtonGroup.group: rateDirectionModeGroup
                                        onClicked: root.rateDirectionMode = root.rateDirectionAToB
                                    }

                                    HistogramModeButton {
                                        objectName: "analysisRateDirectionBToAButton"
                                        text: "B->A"
                                        checked: root.rateDirectionMode === root.rateDirectionBToA
                                        ButtonGroup.group: rateDirectionModeGroup
                                        onClicked: root.rateDirectionMode = root.rateDirectionBToA
                                    }

                                    HistogramModeButton {
                                        objectName: "analysisRateDirectionBothButton"
                                        text: "Both"
                                        checked: root.rateDirectionMode === root.rateDirectionBoth
                                        ButtonGroup.group: rateDirectionModeGroup
                                        onClicked: root.rateDirectionMode = root.rateDirectionBoth
                                    }
                                }
                            }

                            Item {
                                Layout.fillWidth: true
                            }
                        }

                        Label {
                            objectName: "analysisRateGraphFallbackLabel"
                            text: root.rateGraphStatusText
                            visible: !root.rateGraphAvailable && root.rateGraphStatusText.length > 0
                            color: "#64748b"
                            wrapMode: Text.WordWrap
                        }

                        Rectangle {
                            objectName: "analysisRateGraphSurface"
                            Layout.fillWidth: true
                            implicitHeight: 150
                            color: "#f8fafc"
                            border.color: "#dbe3ee"
                            radius: 6
                            visible: root.rateGraphAvailable && root.rateGraphHasVisibleSeries

                            Canvas {
                                id: rateGraphCanvas
                                objectName: "analysisRateGraphCanvas"
                                anchors.fill: parent
                                anchors.margins: 8
                                antialiasing: true

                                renderStrategy: Canvas.Immediate
                                canvasSize: Qt.size(width, height)
                                onPaint: {
                                    var context = getContext("2d")
                                    context.clearRect(0, 0, width, height)

                                    if (!root.rateGraphAvailable) {
                                        return
                                    }

                                    var seriesA = root.graphSeriesAToB
                                    var seriesB = root.graphSeriesBToA
                                    if (seriesA.length === 0 && seriesB.length === 0) {
                                        return
                                    }

                                    var padLeft = 6
                                    var padRight = 6
                                    var padTop = 8
                                    var padBottom = 8
                                    var graphWidth = Math.max(1, width - padLeft - padRight)
                                    var graphHeight = Math.max(1, height - padTop - padBottom)

                                    var maxX = root.rateGraphMaxXValue(seriesA, seriesB)
                                    if (maxX <= 0) {
                                        maxX = 1
                                    }

                                    var maxY = root.rateGraphMaxYValue(seriesA, seriesB)
                                    if (maxY <= 0) {
                                        maxY = 1
                                    }

                                    function pointX(point) {
                                        return padLeft + (point.xUs / maxX) * graphWidth
                                    }

                                    function pointY(point) {
                                        var value = root.ratePointValue(point)
                                        return padTop + (1 - (value / maxY)) * graphHeight
                                    }

                                    function drawSeries(series, color) {
                                        if (series.length === 0) {
                                            return
                                        }

                                        context.beginPath()
                                        context.lineWidth = 2
                                        context.strokeStyle = color
                                        for (var index = 0; index < series.length; ++index) {
                                            var point = series[index]
                                            var x = pointX(point)
                                            var y = pointY(point)
                                            if (index === 0) {
                                                context.moveTo(x, y)
                                            } else {
                                                context.lineTo(x, y)
                                            }
                                        }
                                        context.stroke()

                                        if (series.length === 1) {
                                            context.beginPath()
                                            context.fillStyle = color
                                            context.arc(pointX(series[0]), pointY(series[0]), 2.5, 0, 2 * Math.PI)
                                            context.fill()
                                        }
                                    }

                                    drawSeries(seriesA, "#22c55e")
                                    drawSeries(seriesB, "#3b82f6")
                                }

                                onWidthChanged: requestPaint()
                                onHeightChanged: requestPaint()
                                Component.onCompleted: requestPaint()
                            }
                        }
                    }

                    AnalysisSectionFrame {
                        Label {
                            text: "Directional"
                            font.bold: true
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: root.blockSpacing

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: root.sectionSpacing

                                Label {
                                    text: "Counts"
                                    color: "#475569"
                                }

                                GridLayout {
                            Layout.fillWidth: true
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
                            Layout.fillWidth: true
                                    columns: 2
                                    columnSpacing: 16
                                    rowSpacing: root.rowSpacing

                                    Label { text: "Packet ratio" }
                                    Label { text: root.packetRatioText.length > 0 ? root.packetRatioText : "-" }

                                    Label { text: "Byte ratio" }
                                    Label { text: root.byteRatioText.length > 0 ? root.byteRatioText : "-" }
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
                                    text: "Dominance"
                                    color: "#475569"
                                }

                                GridLayout {
                            Layout.fillWidth: true
                                    columns: 2
                                    columnSpacing: 16
                                    rowSpacing: root.rowSpacing

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
                            Layout.fillWidth: true
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

                            Label {
                                objectName: "packetSizeHistogramMaxLabel"
                                text: root.histogramMaxCountText(root.displayedPacketSizeHistogramModel)
                                color: "#475569"
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
                            Layout.fillWidth: true
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
                            Layout.fillWidth: true
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

                            Label {
                                objectName: "interArrivalHistogramMaxLabel"
                                text: root.histogramMaxCountText(root.displayedInterArrivalHistogramModel)
                                color: "#475569"
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
                            Layout.fillWidth: true
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
                            Layout.fillWidth: true
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
                            Layout.fillWidth: true
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

