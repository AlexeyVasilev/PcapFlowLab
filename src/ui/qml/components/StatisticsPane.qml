import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property bool hasCapture: false
    property int statisticsSectionsResetToken: 0
    property var packetCount: 0
    property var flowCount: 0
    property var capturedBytes: 0
    property string capturedBytesText: ""
    property var originalBytes: 0
    property string originalBytesText: ""
    property var captureTimeStatistics: ({})
    property var captureMetrics: ({})
    property var flowCharacteristics: ({})
    property var packetDirectionDistribution: ({})
    property var dataDirectionDistribution: ({})
    property var tcpFlagStatistics: ({})
    property string statisticsPartialOpenWarningText: ""
    property var tcpFlowCount: 0
    property var tcpPacketCount: 0
    property var tcpCapturedBytes: 0
    property string tcpCapturedBytesText: ""
    property var tcpOriginalBytes: 0
    property string tcpOriginalBytesText: ""
    property var udpFlowCount: 0
    property var udpPacketCount: 0
    property var udpCapturedBytes: 0
    property string udpCapturedBytesText: ""
    property var udpOriginalBytes: 0
    property string udpOriginalBytesText: ""
    property var sctpFlowCount: 0
    property var sctpPacketCount: 0
    property var sctpCapturedBytes: 0
    property string sctpCapturedBytesText: ""
    property var sctpOriginalBytes: 0
    property string sctpOriginalBytesText: ""
    property var otherFlowCount: 0
    property var otherPacketCount: 0
    property var otherCapturedBytes: 0
    property string otherCapturedBytesText: ""
    property var otherOriginalBytes: 0
    property string otherOriginalBytesText: ""
    property var ipv4FlowCount: 0
    property var ipv4PacketCount: 0
    property var ipv4CapturedBytes: 0
    property string ipv4CapturedBytesText: ""
    property var ipv4OriginalBytes: 0
    property string ipv4OriginalBytesText: ""
    property var ipv6FlowCount: 0
    property var ipv6PacketCount: 0
    property var ipv6CapturedBytes: 0
    property string ipv6CapturedBytesText: ""
    property var ipv6OriginalBytes: 0
    property string ipv6OriginalBytesText: ""
    property var unrecognizedStatsPacketCount: 0
    property var unrecognizedStatsCapturedBytes: 0
    property var unrecognizedStatsOriginalBytes: 0
    property int packetSizeDistributionState: 0
    property string packetSizeDistributionStatusText: ""
    property string packetSizeDistributionSummaryText: ""
    property var packetSizeDistributionTotalPacketCount: 0
    property var packetSizeDistributionMaximumBucketPacketCount: 0
    property var packetSizeDistributionMaximumCapturedPacketLength: 0
    property string packetSizeDistributionMaximumCapturedPacketLengthText: ""
    property var packetSizeDistributionMaximumOriginalPacketLength: 0
    property string packetSizeDistributionMaximumOriginalPacketLengthText: ""
    property var packetSizeDistributionRows: []
    property int flowPacketHistogramState: 0
    property string flowPacketHistogramStatusText: ""
    property string flowPacketHistogramSummaryText: ""
    property var flowPacketHistogramTotalFlowCount: 0
    property var flowPacketHistogramMaximumBucketFlowCount: 0
    property var flowPacketHistogramExcludedZeroPacketFlowCount: 0
    property var flowPacketHistogramRows: []
    property int protocolHintsSectionState: 0
    property string protocolHintsSectionStatusText: ""
    property var protocolHintDistribution: []
    property int protocolPathSectionState: 0
    property string protocolPathSectionStatusText: ""
    property var protocolPathStatsModel: null
    property int statisticsMode: 0
    property int quicTlsSectionState: 0
    property string quicTlsSectionStatusText: ""
    property var quicTotalFlows: 0
    property var quicWithSni: 0
    property var quicWithoutSni: 0
    property var quicVersionV1: 0
    property var quicVersionDraft29: 0
    property var quicVersionV2: 0
    property var quicVersionUnknown: 0
    property var tlsTotalFlows: 0
    property var tlsWithSni: 0
    property var tlsWithoutSni: 0
    property var tlsVersion12: 0
    property var tlsVersion13: 0
    property var tlsVersionUnknown: 0
    property int topFlowSectionState: 0
    property string topFlowSectionStatusText: ""
    property var topFlowRows: []
    property int topEndpointPortSectionState: 0
    property string topEndpointPortSectionStatusText: ""
    property var topEndpointsModel: null
    property var topPortsModel: null

    readonly property bool showTopTalkers: root.hasCapture && Number(root.flowCount || 0) > 30
    readonly property int requestStateNotRequested: 0
    readonly property int requestStateLoading: 1
    readonly property int requestStateReady: 2
    readonly property int requestStateUnavailable: 3
    readonly property int requestStateError: 4
    readonly property int sectionPacketSizeDistribution: 0
    readonly property int sectionFlowPacketHistogram: 1
    readonly property int sectionProtocolPath: 2
    readonly property int sectionProtocolHints: 3
    readonly property int sectionQuicTls: 4
    readonly property int sectionTopFlows: 5
    readonly property int sectionTopEndpointsPorts: 6
    readonly property int packetSizeDistributionModeCaptured: 0
    readonly property int packetSizeDistributionModeOriginal: 1
    readonly property int flowPacketHistogramModeFlows: 0
    readonly property int flowPacketHistogramModeCapturedBytes: 1
    readonly property int flowPacketHistogramModeOriginalBytes: 2
    readonly property int tableRowHeight: 26
    readonly property int tableHeaderHeight: 28
    readonly property int tablePadding: 8
    readonly property int tableColumnSpacing: 12
    readonly property int hintGroupColumnWidth: 92
    readonly property int hintProtocolColumnWidth: 180
    readonly property int hintFlowsColumnWidth: 110
    readonly property int hintPacketsColumnWidth: 118
    readonly property int hintCapturedColumnWidth: 118
    readonly property int hintOriginalColumnWidth: 118
    readonly property int hintTableWidth: hintGroupColumnWidth + hintProtocolColumnWidth + hintFlowsColumnWidth + hintPacketsColumnWidth + hintCapturedColumnWidth + hintOriginalColumnWidth + (tableColumnSpacing * 5) + (tablePadding * 2)
    readonly property int directionLabelColumnWidth: 220
    readonly property int directionFlowColumnWidth: 96
    readonly property int directionPercentColumnWidth: 110
    readonly property int directionTableWidth: directionLabelColumnWidth + directionFlowColumnWidth + directionPercentColumnWidth + (tableColumnSpacing * 2) + (tablePadding * 2)
    readonly property int tcpFlagLabelColumnWidth: 120
    readonly property int tcpFlagPacketColumnWidth: 110
    readonly property int tcpFlagPercentColumnWidth: 110
    readonly property int tcpFlagTableWidth: tcpFlagLabelColumnWidth + tcpFlagPacketColumnWidth + tcpFlagPercentColumnWidth + (tableColumnSpacing * 2) + (tablePadding * 2)
    readonly property int pathTreeLabelColumnWidth: 420
    readonly property int pathTreeFlowsColumnWidth: 138
    readonly property int pathTreePacketsColumnWidth: 150
    readonly property int pathTreeOriginalColumnWidth: 150
    readonly property int pathTreeTableWidth: pathTreeLabelColumnWidth + pathTreeFlowsColumnWidth + pathTreePacketsColumnWidth + pathTreeOriginalColumnWidth + (tableColumnSpacing * 3) + (tablePadding * 2)
    readonly property int pathTreeViewportMaxHeight: 420
    readonly property int pathTreeIndentWidth: 18
    readonly property int pathTreeExpanderWidth: 16
    readonly property string protocolPathPrimaryColumnTitle: root.statisticsMode === 2 ? "Path" : "Layer"
    readonly property int topFlowColumnFlowWidth: 72
    readonly property int topFlowColumnEndpointWidth: 220
    readonly property int topFlowColumnProtocolWidth: 82
    readonly property int topFlowColumnDetectedWidth: 120
    readonly property int topFlowColumnServiceWidth: 180
    readonly property int topFlowColumnPathWidth: 120
    readonly property int topFlowColumnPacketsWidth: 98
    readonly property int topFlowColumnBytesWidth: 118
    readonly property int topFlowTableWidth: topFlowColumnFlowWidth + (topFlowColumnEndpointWidth * 2) + topFlowColumnProtocolWidth + topFlowColumnDetectedWidth + topFlowColumnServiceWidth + topFlowColumnPathWidth + topFlowColumnPacketsWidth + (topFlowColumnBytesWidth * 2) + (tableColumnSpacing * 9) + (tablePadding * 2)

    property bool captureMetricsExpanded: false
    property bool flowCharacteristicsExpanded: false
    property bool directionDistributionExpanded: false
    property bool tcpFlagsExpanded: false
    property bool packetSizeDistributionExpanded: false
    property bool flowPacketHistogramExpanded: false
    property bool protocolPathExpanded: false
    property bool protocolHintsExpanded: false
    property bool quicTlsExpanded: false
    property bool topFlowsExpanded: false
    property bool topEndpointsPortsExpanded: false
    property int packetSizeDistributionDisplayMode: packetSizeDistributionModeCaptured
    property int flowPacketHistogramDisplayMode: flowPacketHistogramModeFlows

    signal endpointActivated(string endpointText)
    signal portActivated(int port)
    signal statisticsModeChangedByUser(int mode)
    signal showFlowsRequested()
    signal protocolPathExportRequested()
    signal statisticsSectionExpandedChanged(int section, bool expanded)

    onStatisticsSectionsResetTokenChanged: {
        captureMetricsExpanded = false
        flowCharacteristicsExpanded = false
        directionDistributionExpanded = false
        tcpFlagsExpanded = false
        packetSizeDistributionExpanded = false
        flowPacketHistogramExpanded = false
        protocolPathExpanded = false
        protocolHintsExpanded = false
        quicTlsExpanded = false
        topFlowsExpanded = false
        topEndpointsPortsExpanded = false
        packetSizeDistributionDisplayMode = packetSizeDistributionModeCaptured
        flowPacketHistogramDisplayMode = flowPacketHistogramModeFlows
    }

    function groupInteger(value) {
        const digits = Math.max(0, Math.round(Number(value || 0))).toString()
        return digits.replace(/\B(?=(\d{3})+(?!\d))/g, " ")
    }

    function trimTrailingZeros(text) {
        return text.replace(/\.0$/, "").replace(/(\.\d*[1-9])0+$/, "$1")
    }

    function formatBytes(value) {
        const units = ["B", "KB", "MB", "GB", "TB"]
        var scaled = Math.max(0, Number(value || 0))
        var unitIndex = 0
        while (scaled >= 1024 && unitIndex + 1 < units.length) {
            scaled /= 1024
            unitIndex += 1
        }

        var numberText = ""
        if (unitIndex === 0) {
            numberText = groupInteger(Math.round(scaled))
        } else {
            numberText = trimTrailingZeros(scaled.toFixed(1)).replace(/\B(?=(\d{3})+(?!\d))/g, " ")
        }

        return numberText + " " + units[unitIndex]
    }

    function formatShare(part, total) {
        const numericPart = Number(part || 0)
        const numericTotal = Number(total || 0)
        if (numericPart <= 0 || numericTotal <= 0)
            return "0%"

        const percent = (numericPart * 100.0) / numericTotal
        if (percent < 0.01)
            return "<0.01%"
        if (percent < 1.0)
            return percent.toFixed(2) + "%"
        return Math.round(percent) + "%"
    }

    function formatFlowPercentageAndCount(part, total) {
        if (Number(part || 0) <= 0 || Number(total || 0) <= 0)
            return "0% (0 flows)"
        return formatShare(part, total) + " (" + groupInteger(part) + " flows)"
    }

    function statisticsText(section, key) {
        if (!section || section[key] === undefined || section[key] === null)
            return "—"
        const text = String(section[key])
        return text.length > 0 ? text : "—"
    }

    function statisticsRows(section) {
        if (!section || section.rows === undefined || section.rows === null)
            return []
        return section.rows
    }

    function protocolHintGroup(title) {
        if (title === "Possible TLS" || title === "Possible QUIC")
            return "Possible"
        if (title === "Unknown")
            return "Unknown"
        return "Confirmed"
    }

    component SectionFrame: Frame {
        default property alias sectionContent: sectionLayout.data

        Layout.fillWidth: true
        Layout.minimumWidth: 0
        padding: 10

        background: Rectangle {
            color: "#ffffff"
            border.color: "#d8dee9"
            radius: 6
        }

        ColumnLayout {
            id: sectionLayout
            anchors.fill: parent
            Layout.minimumWidth: 0
            spacing: 8
        }
    }

    component CompactMetricLabel: Label {
        Layout.fillWidth: true
        Layout.minimumWidth: 0
        color: "#334155"
        wrapMode: Text.NoWrap
        elide: Text.ElideRight
    }

    component OverviewMetricBlock: Rectangle {
        required property string title
        required property string valueText
        property string subtitleText: ""
        property string valueObjectName: ""
        property bool wrapValue: false

        Layout.fillWidth: true
        Layout.minimumWidth: 0
        radius: 6
        color: "#f8fafc"
        border.color: "#e2e8f0"
        implicitHeight: metricBlockLayout.implicitHeight + 16

        ColumnLayout {
            id: metricBlockLayout
            anchors.fill: parent
            anchors.margins: 8
            spacing: 4

            Label {
                Layout.fillWidth: true
                text: parent.parent.title
                font.pixelSize: 12
                color: "#64748b"
                elide: Text.ElideRight
            }

            Label {
                objectName: parent.parent.valueObjectName
                Layout.fillWidth: true
                text: parent.parent.valueText
                font.pixelSize: 14
                font.bold: true
                color: "#0f172a"
                wrapMode: parent.parent.wrapValue ? Text.WordWrap : Text.NoWrap
                elide: parent.parent.wrapValue ? Text.ElideNone : Text.ElideRight
            }

            Label {
                Layout.fillWidth: true
                visible: parent.parent.subtitleText.length > 0
                text: parent.parent.subtitleText
                font.pixelSize: 11
                color: "#64748b"
                wrapMode: Text.WordWrap
            }
        }
    }

    component ProtocolPathModeButton: Button {
        checkable: true
        leftPadding: 12
        rightPadding: 12
        implicitWidth: Math.max(120, implicitContentWidth + leftPadding + rightPadding)
        implicitHeight: 28
    }

    component HistogramModeButton: Button {
        checkable: true
        leftPadding: 12
        rightPadding: 12
        implicitWidth: Math.max(92, implicitContentWidth + leftPadding + rightPadding)
        implicitHeight: 28
    }

    component ProtocolPathPrimaryActionButton: Button {
        implicitHeight: 30
        leftPadding: 14
        rightPadding: 14

        contentItem: Label {
            text: parent.text
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            font.pixelSize: 12
            font.bold: true
            color: parent.enabled ? "#166534" : "#94a3b8"
        }

        background: Rectangle {
            radius: 6
            color: parent.enabled
                ? (parent.down ? "#dcfce7" : (parent.hovered ? "#f0fdf4" : "#ffffff"))
                : "#f8fafc"
            border.color: parent.enabled ? "#86efac" : "#e2e8f0"
            border.width: 1

            Rectangle {
                anchors.left: parent.left
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                width: 4
                radius: 6
                color: parent.parent.enabled ? "#22c55e" : "#cbd5e1"
            }
        }
    }

    component FourColumnHeader: Rectangle {
        required property string firstTitle
        required property string secondTitle
        required property string thirdTitle
        required property string fourthTitle
        required property int firstWidth
        required property int secondWidth
        required property int thirdWidth
        required property int fourthWidth
        required property int tableWidth

        width: Math.min(tableWidth, parent ? parent.width : tableWidth)
        height: root.tableHeaderHeight
        radius: 4
        color: "#f8fafc"
        border.color: "#e2e8f0"

        Item {
            anchors.fill: parent
            anchors.leftMargin: root.tablePadding
            anchors.rightMargin: root.tablePadding

            Label {
                x: 0
                width: parent.parent.firstWidth
                anchors.verticalCenter: parent.verticalCenter
                text: parent.parent.firstTitle
                font.bold: true
                color: "#334155"
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing
                width: parent.parent.secondWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.secondTitle
                font.bold: true
                color: "#334155"
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing
                width: parent.parent.thirdWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.thirdTitle
                font.bold: true
                color: "#334155"
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing + parent.parent.thirdWidth + root.tableColumnSpacing
                width: parent.parent.fourthWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.fourthTitle
                font.bold: true
                color: "#334155"
            }
        }
    }

    component ThreeColumnHeader: Rectangle {
        required property string firstTitle
        required property string secondTitle
        required property string thirdTitle
        required property int firstWidth
        required property int secondWidth
        required property int thirdWidth
        required property int tableWidth

        width: Math.min(tableWidth, parent ? parent.width : tableWidth)
        height: root.tableHeaderHeight
        radius: 4
        color: "#f8fafc"
        border.color: "#e2e8f0"

        Item {
            anchors.fill: parent
            anchors.leftMargin: root.tablePadding
            anchors.rightMargin: root.tablePadding

            Label {
                x: 0
                width: parent.parent.firstWidth
                anchors.verticalCenter: parent.verticalCenter
                text: parent.parent.firstTitle
                font.bold: true
                color: "#334155"
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing
                width: parent.parent.secondWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.secondTitle
                font.bold: true
                color: "#334155"
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing
                width: parent.parent.thirdWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.thirdTitle
                font.bold: true
                color: "#334155"
            }
        }
    }

    ScrollView {
        id: statisticsScroll
        readonly property real verticalScrollbarGutter: statisticsVerticalScrollBar.visible
            ? Math.max(statisticsVerticalScrollBar.width, statisticsVerticalScrollBar.implicitWidth) + 6
            : 0
        anchors.fill: parent
        clip: true
        contentWidth: statisticsContent.width
        contentHeight: statisticsContent.implicitHeight
        ScrollBar.vertical: AppScrollBar {
            id: statisticsVerticalScrollBar
            parent: statisticsScroll
            x: statisticsScroll.mirrored ? 0 : statisticsScroll.width - width
            y: statisticsScroll.topPadding
            height: statisticsScroll.availableHeight
            policy: statisticsScroll.contentHeight > statisticsScroll.height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
        }
        ScrollBar.horizontal: AppScrollBar {
            parent: statisticsScroll
            x: statisticsScroll.leftPadding
            y: statisticsScroll.height - height
            width: statisticsScroll.availableWidth
            policy: statisticsScroll.contentWidth > statisticsScroll.width ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
        }

        Item {
            id: statisticsContent
            width: Math.max(0, statisticsScroll.availableWidth - statisticsScroll.verticalScrollbarGutter)
            implicitHeight: statisticsColumn.implicitHeight

            ColumnLayout {
                id: statisticsColumn
                objectName: "statisticsColumn"
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                spacing: 12

                SummaryBar {
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                    packetCount: root.packetCount
                    flowCount: root.flowCount
                    capturedBytes: root.capturedBytes
                    capturedBytesText: root.capturedBytesText
                    originalBytes: root.originalBytes
                    originalBytesText: root.originalBytesText
                    hasCapture: root.hasCapture
                }

                SectionFrame {
                    id: captureTimeSection
                    objectName: "captureTimeSection"
                    Layout.fillWidth: true

                    Rectangle {
                        objectName: "statisticsPartialOpenWarning"
                        Layout.fillWidth: true
                        visible: root.statisticsPartialOpenWarningText.length > 0
                        radius: 6
                        color: "#fffbeb"
                        border.color: "#f59e0b"
                        implicitHeight: partialOpenWarningLabel.implicitHeight + 12

                        Label {
                            id: partialOpenWarningLabel
                            anchors.fill: parent
                            anchors.margins: 6
                            text: root.statisticsPartialOpenWarningText
                            color: "#92400e"
                            wrapMode: Text.WordWrap
                        }
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: width >= 980 ? 3 : 1
                        rowSpacing: 8
                        columnSpacing: 8

                        OverviewMetricBlock {
                            title: "Capture Start"
                            valueText: root.statisticsText(root.captureTimeStatistics, "captureStartText")
                            valueObjectName: "captureStartValue"
                            wrapValue: true
                        }

                        OverviewMetricBlock {
                            title: "Capture End"
                            valueText: root.statisticsText(root.captureTimeStatistics, "captureEndText")
                            valueObjectName: "captureEndValue"
                            wrapValue: true
                        }

                        OverviewMetricBlock {
                            title: "Duration"
                            valueText: root.statisticsText(root.captureTimeStatistics, "durationText")
                            valueObjectName: "captureDurationValue"
                        }
                    }
                }

                ProtocolStatsPane {
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                    Layout.preferredHeight: implicitHeight
                    hasCapture: root.hasCapture
                    tcpFlowCount: root.tcpFlowCount
                    tcpPacketCount: root.tcpPacketCount
                    tcpCapturedBytesText: root.tcpCapturedBytesText
                    tcpOriginalBytesText: root.tcpOriginalBytesText
                    udpFlowCount: root.udpFlowCount
                    udpPacketCount: root.udpPacketCount
                    udpCapturedBytesText: root.udpCapturedBytesText
                    udpOriginalBytesText: root.udpOriginalBytesText
                    sctpFlowCount: root.sctpFlowCount
                    sctpPacketCount: root.sctpPacketCount
                    sctpCapturedBytesText: root.sctpCapturedBytesText
                    sctpOriginalBytesText: root.sctpOriginalBytesText
                    otherFlowCount: root.otherFlowCount
                    otherPacketCount: root.otherPacketCount
                    otherCapturedBytesText: root.otherCapturedBytesText
                    otherOriginalBytesText: root.otherOriginalBytesText
                    ipv4FlowCount: root.ipv4FlowCount
                    ipv4PacketCount: root.ipv4PacketCount
                    ipv4CapturedBytesText: root.ipv4CapturedBytesText
                    ipv4OriginalBytesText: root.ipv4OriginalBytesText
                    ipv6FlowCount: root.ipv6FlowCount
                    ipv6PacketCount: root.ipv6PacketCount
                    ipv6CapturedBytesText: root.ipv6CapturedBytesText
                    ipv6OriginalBytesText: root.ipv6OriginalBytesText
                }

                SectionFrame {
                    id: unrecognizedStatsSection
                    objectName: "unrecognizedStatsSection"
                    Layout.fillWidth: true
                    visible: root.hasCapture && Number(root.unrecognizedStatsPacketCount || 0) > 0
                    readonly property real packetColumnWidth: 96
                    readonly property real byteColumnWidth: 152

                    Label {
                        text: "Unrecognized Packets"
                        font.bold: true
                        font.pixelSize: 16
                        color: "#0f172a"
                    }

                    Label {
                        text: "Packets that could not be assigned to a flow"
                        color: "#64748b"
                        wrapMode: Text.WordWrap
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: root.tableHeaderHeight
                        radius: 4
                        color: "#f8fafc"
                        border.color: "#e2e8f0"

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: root.tablePadding
                            anchors.rightMargin: root.tablePadding
                            Layout.minimumWidth: 0
                            spacing: root.tableColumnSpacing

                            Label {
                                Layout.preferredWidth: unrecognizedStatsSection.packetColumnWidth
                                Layout.minimumWidth: unrecognizedStatsSection.packetColumnWidth
                                Layout.maximumWidth: unrecognizedStatsSection.packetColumnWidth
                                horizontalAlignment: Text.AlignLeft
                                text: "Packets"
                                font.bold: true
                                color: "#334155"
                                elide: Text.ElideRight
                            }

                            Label {
                                Layout.preferredWidth: unrecognizedStatsSection.byteColumnWidth
                                Layout.minimumWidth: unrecognizedStatsSection.byteColumnWidth
                                Layout.maximumWidth: unrecognizedStatsSection.byteColumnWidth
                                horizontalAlignment: Text.AlignLeft
                                text: "Captured Bytes"
                                font.bold: true
                                color: "#334155"
                                elide: Text.ElideRight
                            }

                            Label {
                                Layout.preferredWidth: unrecognizedStatsSection.byteColumnWidth
                                Layout.minimumWidth: unrecognizedStatsSection.byteColumnWidth
                                Layout.maximumWidth: unrecognizedStatsSection.byteColumnWidth
                                horizontalAlignment: Text.AlignLeft
                                text: "Original Bytes"
                                font.bold: true
                                color: "#334155"
                                elide: Text.ElideRight
                            }

                            Item {
                                Layout.fillWidth: true
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: root.tableRowHeight
                        radius: 4
                        color: "transparent"

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: root.tablePadding
                            anchors.rightMargin: root.tablePadding
                            Layout.minimumWidth: 0
                            spacing: root.tableColumnSpacing

                            Label {
                                objectName: "unrecognizedStatsPacketValue"
                                Layout.preferredWidth: unrecognizedStatsSection.packetColumnWidth
                                Layout.minimumWidth: unrecognizedStatsSection.packetColumnWidth
                                Layout.maximumWidth: unrecognizedStatsSection.packetColumnWidth
                                horizontalAlignment: Text.AlignLeft
                                text: root.groupInteger(root.unrecognizedStatsPacketCount)
                                color: "#0f172a"
                                elide: Text.ElideRight
                            }

                            Label {
                                objectName: "unrecognizedStatsCapturedBytesValue"
                                Layout.preferredWidth: unrecognizedStatsSection.byteColumnWidth
                                Layout.minimumWidth: unrecognizedStatsSection.byteColumnWidth
                                Layout.maximumWidth: unrecognizedStatsSection.byteColumnWidth
                                horizontalAlignment: Text.AlignLeft
                                text: root.formatBytes(root.unrecognizedStatsCapturedBytes)
                                color: "#334155"
                                elide: Text.ElideRight
                            }

                            Label {
                                objectName: "unrecognizedStatsOriginalBytesValue"
                                Layout.preferredWidth: unrecognizedStatsSection.byteColumnWidth
                                Layout.minimumWidth: unrecognizedStatsSection.byteColumnWidth
                                Layout.maximumWidth: unrecognizedStatsSection.byteColumnWidth
                                horizontalAlignment: Text.AlignLeft
                                text: root.formatBytes(root.unrecognizedStatsOriginalBytes)
                                color: "#334155"
                                elide: Text.ElideRight
                            }

                            Item {
                                Layout.fillWidth: true
                            }
                        }
                    }
                }

                CollapsibleStatisticsSection {
                    id: packetSizeDistributionSection
                    objectName: "packetSizeDistributionSection"
                    title: "Packet Size Distribution"
                    toggleObjectName: "packetSizeDistributionToggleButton"
                    summaryText: root.packetSizeDistributionSummaryText
                    expanded: root.packetSizeDistributionExpanded
                    onExpandedChangedByUser: function(expanded) {
                        root.packetSizeDistributionExpanded = expanded
                        root.statisticsSectionExpandedChanged(root.sectionPacketSizeDistribution, expanded)
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: 8

                        RowLayout {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            visible: root.hasCapture
                            spacing: 8

                            Label {
                                text: "Mode"
                                color: "#64748b"
                            }

                            Rectangle {
                                color: "#f8fafc"
                                border.color: "#cbd5e1"
                                radius: 6
                                implicitHeight: packetSizeDistributionModeLayout.implicitHeight + 4
                                implicitWidth: packetSizeDistributionModeLayout.implicitWidth + 8

                                RowLayout {
                                    id: packetSizeDistributionModeLayout
                                    anchors.fill: parent
                                    anchors.margins: 2
                                    spacing: 2

                                    ButtonGroup {
                                        id: packetSizeDistributionModeGroup
                                    }

                                    HistogramModeButton {
                                        objectName: "packetSizeDistributionModeCapturedButton"
                                        text: "Captured"
                                        checked: root.packetSizeDistributionDisplayMode === root.packetSizeDistributionModeCaptured
                                        ButtonGroup.group: packetSizeDistributionModeGroup
                                        onClicked: root.packetSizeDistributionDisplayMode = root.packetSizeDistributionModeCaptured
                                    }

                                    HistogramModeButton {
                                        objectName: "packetSizeDistributionModeOriginalButton"
                                        text: "Original"
                                        checked: root.packetSizeDistributionDisplayMode === root.packetSizeDistributionModeOriginal
                                        ButtonGroup.group: packetSizeDistributionModeGroup
                                        onClicked: root.packetSizeDistributionDisplayMode = root.packetSizeDistributionModeOriginal
                                    }
                                }
                            }
                        }

                        Label {
                            Layout.fillWidth: true
                            visible: root.hasCapture
                            text: root.packetSizeDistributionDisplayMode === root.packetSizeDistributionModeCaptured
                                ? "Captured packet lengths for all packets imported from the capture, including unrecognized packets."
                                : "Original packet lengths for all packets imported from the capture, including unrecognized packets."
                            color: "#64748b"
                            wrapMode: Text.WordWrap
                        }

                        Label {
                            visible: root.packetSizeDistributionState === root.requestStateLoading ||
                                root.packetSizeDistributionState === root.requestStateUnavailable ||
                                root.packetSizeDistributionState === root.requestStateError
                            text: root.packetSizeDistributionStatusText
                            color: "#64748b"
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            visible: root.packetSizeDistributionState === root.requestStateReady
                            spacing: 8

                            Repeater {
                                model: root.packetSizeDistributionRows

                                delegate: RowLayout {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    Layout.minimumWidth: 0
                                    spacing: 10

                                    Label {
                                        Layout.preferredWidth: 90
                                        Layout.minimumWidth: 60
                                        text: modelData.label
                                        color: "#0f172a"
                                        elide: Text.ElideRight
                                    }

                                    Rectangle {
                                        Layout.fillWidth: true
                                        Layout.minimumWidth: 0
                                        Layout.preferredHeight: 18
                                        radius: 9
                                        color: "#f1f5f9"
                                        border.color: "#e2e8f0"

                                        Rectangle {
                                            width: Math.max(
                                                0,
                                                (parent.width - 2) * Number(
                                                    root.packetSizeDistributionDisplayMode === root.packetSizeDistributionModeCaptured
                                                        ? modelData.capturedNormalizedFraction
                                                        : modelData.originalNormalizedFraction
                                                )
                                            )
                                            height: parent.height - 2
                                            radius: 8
                                            x: 1
                                            y: 1
                                            color: "#34d399"
                                        }
                                    }

                                    Label {
                                        Layout.preferredWidth: 90
                                        Layout.minimumWidth: 0
                                        horizontalAlignment: Text.AlignRight
                                        text: root.packetSizeDistributionDisplayMode === root.packetSizeDistributionModeCaptured
                                            ? modelData.capturedPacketCountText
                                            : modelData.originalPacketCountText
                                        color: "#334155"
                                        elide: Text.ElideLeft
                                    }
                                }
                            }

                            Label {
                                objectName: "packetSizeDistributionMaximumPacketLengthValue"
                                Layout.fillWidth: true
                                text: root.packetSizeDistributionDisplayMode === root.packetSizeDistributionModeCaptured
                                    ? "Maximum captured packet size: " + root.packetSizeDistributionMaximumCapturedPacketLengthText
                                    : "Maximum original packet size: " + root.packetSizeDistributionMaximumOriginalPacketLengthText
                                color: "#0f172a"
                                wrapMode: Text.WordWrap
                            }
                        }
                    }
                }

                CollapsibleStatisticsSection {
                    id: flowPacketHistogramSection
                    objectName: "flowPacketHistogramSection"
                    title: "Flows by Packet Count"
                    toggleObjectName: "flowPacketHistogramToggleButton"
                    summaryText: root.flowPacketHistogramSummaryText
                    expanded: root.flowPacketHistogramExpanded
                    onExpandedChangedByUser: function(expanded) {
                        root.flowPacketHistogramExpanded = expanded
                        root.statisticsSectionExpandedChanged(root.sectionFlowPacketHistogram, expanded)
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        visible: root.hasCapture
                        spacing: 8

                        Label {
                            text: "Mode"
                            color: "#64748b"
                        }

                        Rectangle {
                            color: "#f8fafc"
                            border.color: "#cbd5e1"
                            radius: 6
                            implicitHeight: flowPacketHistogramModeLayout.implicitHeight + 4
                            implicitWidth: flowPacketHistogramModeLayout.implicitWidth + 8

                            RowLayout {
                                id: flowPacketHistogramModeLayout
                                anchors.fill: parent
                                anchors.margins: 2
                                spacing: 2

                                ButtonGroup {
                                    id: flowPacketHistogramModeGroup
                                }

                                HistogramModeButton {
                                    objectName: "flowPacketHistogramModeFlowsButton"
                                    text: "Flows"
                                    checked: root.flowPacketHistogramDisplayMode === root.flowPacketHistogramModeFlows
                                    ButtonGroup.group: flowPacketHistogramModeGroup
                                    ToolTip.visible: hovered
                                    ToolTip.delay: 250
                                    ToolTip.timeout: 8000
                                    ToolTip.text: "Number of flows in each packet-count range."
                                    onClicked: root.flowPacketHistogramDisplayMode = root.flowPacketHistogramModeFlows
                                }

                                HistogramModeButton {
                                    objectName: "flowPacketHistogramModeCapturedBytesButton"
                                    text: "Captured bytes"
                                    checked: root.flowPacketHistogramDisplayMode === root.flowPacketHistogramModeCapturedBytes
                                    ButtonGroup.group: flowPacketHistogramModeGroup
                                    ToolTip.visible: hovered
                                    ToolTip.delay: 250
                                    ToolTip.timeout: 8000
                                    ToolTip.text: "Sum of captured bytes for flows in each packet-count range."
                                    onClicked: root.flowPacketHistogramDisplayMode = root.flowPacketHistogramModeCapturedBytes
                                }

                                HistogramModeButton {
                                    objectName: "flowPacketHistogramModeOriginalBytesButton"
                                    text: "Original bytes"
                                    checked: root.flowPacketHistogramDisplayMode === root.flowPacketHistogramModeOriginalBytes
                                    ButtonGroup.group: flowPacketHistogramModeGroup
                                    ToolTip.visible: hovered
                                    ToolTip.delay: 250
                                    ToolTip.timeout: 8000
                                    ToolTip.text: "Sum of original bytes for flows in each packet-count range."
                                    onClicked: root.flowPacketHistogramDisplayMode = root.flowPacketHistogramModeOriginalBytes
                                }
                            }
                        }
                    }

                    Label {
                        visible: root.flowPacketHistogramState === root.requestStateLoading ||
                            root.flowPacketHistogramState === root.requestStateUnavailable ||
                            root.flowPacketHistogramState === root.requestStateError
                        text: root.flowPacketHistogramStatusText
                        color: "#64748b"
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        visible: root.flowPacketHistogramState === root.requestStateReady
                        spacing: 8

                        Repeater {
                            model: root.flowPacketHistogramRows

                            delegate: RowLayout {
                                required property var modelData
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                spacing: 10

                                Label {
                                    Layout.preferredWidth: 90
                                    Layout.minimumWidth: 60
                                    text: modelData.label
                                    color: "#0f172a"
                                    elide: Text.ElideRight
                                }

                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.minimumWidth: 0
                                    Layout.preferredHeight: 18
                                    radius: 9
                                    color: "#f1f5f9"
                                    border.color: "#e2e8f0"

                                    Rectangle {
                                        width: Math.max(
                                            0,
                                            (parent.width - 2) * Number(
                                                root.flowPacketHistogramDisplayMode === root.flowPacketHistogramModeFlows
                                                    ? modelData.normalizedFlowFraction
                                                    : (root.flowPacketHistogramDisplayMode === root.flowPacketHistogramModeCapturedBytes
                                                        ? modelData.normalizedCapturedByteFraction
                                                        : modelData.normalizedOriginalByteFraction)
                                            )
                                        )
                                        height: parent.height - 2
                                        radius: 8
                                        x: 1
                                        y: 1
                                        color: "#60a5fa"
                                    }
                                }

                                Label {
                                    Layout.preferredWidth: root.flowPacketHistogramDisplayMode === root.flowPacketHistogramModeFlows ? 70 : 110
                                    Layout.minimumWidth: 0
                                    horizontalAlignment: Text.AlignRight
                                    text: root.flowPacketHistogramDisplayMode === root.flowPacketHistogramModeFlows
                                        ? root.groupInteger(modelData.flowCount)
                                        : (root.flowPacketHistogramDisplayMode === root.flowPacketHistogramModeCapturedBytes
                                            ? modelData.capturedByteCountText
                                            : modelData.originalByteCountText)
                                    color: "#334155"
                                    elide: Text.ElideLeft
                                }
                            }
                        }

                        Label {
                            objectName: "flowPacketHistogramExcludedZeroPacketLabel"
                            visible: Number(root.flowPacketHistogramExcludedZeroPacketFlowCount || 0) > 0
                            text: "Excluded zero-packet flows: " + root.groupInteger(root.flowPacketHistogramExcludedZeroPacketFlowCount)
                            color: "#64748b"
                            font.pixelSize: 12
                        }
                    }
                }

                CollapsibleStatisticsSection {
                    id: protocolPathSection
                    objectName: "protocolPathSection"
                    title: "Protocol Path Tree"
                    toggleObjectName: "protocolPathStatisticsToggleButton"
                    expanded: root.protocolPathExpanded
                    onExpandedChangedByUser: function(expanded) {
                        root.protocolPathExpanded = expanded
                        root.statisticsSectionExpandedChanged(root.sectionProtocolPath, expanded)
                    }

                    Label {
                        visible: root.protocolPathSectionState === root.requestStateLoading ||
                            root.protocolPathSectionState === root.requestStateUnavailable ||
                            root.protocolPathSectionState === root.requestStateError
                        text: root.protocolPathSectionStatusText
                        color: "#64748b"
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        visible: root.protocolPathSectionState === root.requestStateReady
                        spacing: 8

                        RowLayout {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            spacing: 10

                            ProtocolPathPrimaryActionButton {
                                objectName: "protocolPathShowFlowsButton"
                                text: "Show flows"
                                enabled: root.hasCapture
                                    && root.protocolPathStatsModel
                                    && root.protocolPathStatsModel.hasSelectedNode
                                    && root.protocolPathStatsModel.selectedNodeFlowCount > 0
                                onClicked: root.showFlowsRequested()
                            }

                            Label {
                                text: "Mode"
                                color: "#475569"
                            }

                            Rectangle {
                                color: "#f8fafc"
                                border.color: "#cbd5e1"
                                radius: 6
                                implicitHeight: protocolPathStatsModeLayout.implicitHeight + 4
                                implicitWidth: protocolPathStatsModeLayout.implicitWidth + 8

                                RowLayout {
                                    id: protocolPathStatsModeLayout
                                    anchors.fill: parent
                                    anchors.margins: 2
                                    spacing: 2

                                    ButtonGroup {
                                        id: protocolPathStatsModeGroup
                                    }

                                    ProtocolPathModeButton {
                                        objectName: "protocolPathStatsModeKindOverviewButton"
                                        text: "Kind overview"
                                        checked: root.statisticsMode === 0
                                        ButtonGroup.group: protocolPathStatsModeGroup
                                        onClicked: {
                                            if (root.statisticsMode !== 0)
                                                root.statisticsModeChangedByUser(0)
                                        }
                                    }

                                    ProtocolPathModeButton {
                                        objectName: "protocolPathStatsModeIdentityTreeButton"
                                        text: "Identity tree"
                                        checked: root.statisticsMode === 1
                                        ButtonGroup.group: protocolPathStatsModeGroup
                                        onClicked: {
                                            if (root.statisticsMode !== 1)
                                                root.statisticsModeChangedByUser(1)
                                        }
                                    }

                                    ProtocolPathModeButton {
                                        objectName: "protocolPathStatsModeTerminalPathsButton"
                                        text: "Terminal paths"
                                        checked: root.statisticsMode === 2
                                        ButtonGroup.group: protocolPathStatsModeGroup
                                        onClicked: {
                                            if (root.statisticsMode !== 2)
                                                root.statisticsModeChangedByUser(2)
                                        }
                                    }
                                }
                            }

                            Item { Layout.fillWidth: true }

                            Button {
                                objectName: "protocolPathExportButton"
                                text: "Export"
                                enabled: root.hasCapture && root.protocolPathSectionState === root.requestStateReady
                                onClicked: root.protocolPathExportRequested()
                            }

                            Button {
                                text: "Expand all"
                                visible: root.statisticsMode !== 2
                                enabled: visible && root.protocolPathStatsModel && root.protocolPathStatsModel.canExpand() && root.protocolPathStatsModel.rowCount() > 0
                                onClicked: root.protocolPathStatsModel.expandAll()
                            }

                            Button {
                                text: "Collapse all"
                                visible: root.statisticsMode !== 2
                                enabled: visible && root.protocolPathStatsModel && root.protocolPathStatsModel.canExpand() && root.protocolPathStatsModel.rowCount() > 0
                                onClicked: root.protocolPathStatsModel.collapseAll()
                            }
                        }

                        FourColumnHeader {
                            firstTitle: root.protocolPathPrimaryColumnTitle
                            secondTitle: "Flows"
                            thirdTitle: "Packets"
                            fourthTitle: "Original Bytes"
                            firstWidth: root.pathTreeLabelColumnWidth
                            secondWidth: root.pathTreeFlowsColumnWidth
                            thirdWidth: root.pathTreePacketsColumnWidth
                            fourthWidth: root.pathTreeOriginalColumnWidth
                            tableWidth: root.pathTreeTableWidth
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            visible: root.protocolPathStatsModel && protocolPathListView.count > 0
                            implicitHeight: {
                                const measuredContentHeight = protocolPathListView.contentHeight
                                const fallbackContentHeight = protocolPathListView.count * root.tableRowHeight
                                const contentDrivenHeight = (measuredContentHeight > 0 ? measuredContentHeight : fallbackContentHeight) + 2
                                return Math.min(root.pathTreeViewportMaxHeight, Math.max(root.tableRowHeight + 2, contentDrivenHeight))
                            }
                            Layout.preferredHeight: implicitHeight
                            color: "#ffffff"
                            border.color: "#e2e8f0"
                            radius: 6
                            clip: true

                            ListView {
                                id: protocolPathListView
                                objectName: "protocolPathListView"
                                anchors.fill: parent
                                anchors.margins: 1
                                clip: true
                                model: root.protocolPathStatsModel
                                boundsBehavior: Flickable.StopAtBounds
                                reuseItems: true
                                cacheBuffer: root.tableRowHeight * 12

                                ScrollBar.vertical: AppScrollBar {
                                    policy: protocolPathListView.contentHeight > protocolPathListView.height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
                                }

                                delegate: Rectangle {
                                    required property string layerText
                                    required property string pathText
                                    required property string compactText
                                    required property var nodeId
                                    required property var parentNodeId
                                    required property int depth
                                    required property bool hasChildren
                                    required property bool expanded
                                    required property bool canExpand
                                    required property var flowCount
                                    required property var packetCount
                                    required property var originalByteCount
                                    required property string flowCountText
                                    required property string packetCountText
                                    required property string originalByteCountText
                                    required property int rowIndex
                                    required property string tooltipText
                                    required property bool selected

                                    width: protocolPathListView.width
                                    height: root.tableRowHeight
                                    color: selected ? "#e0f2fe" : (rowIndex % 2 === 0 ? "transparent" : "#f8fafc")

                                    Item {
                                        anchors.fill: parent
                                        anchors.leftMargin: root.tablePadding
                                        anchors.rightMargin: root.tablePadding

                                        Label {
                                            x: 0
                                            width: Math.max(0, depth) * root.pathTreeIndentWidth
                                            anchors.verticalCenter: parent.verticalCenter
                                            visible: width > 0
                                        }

                                        Item {
                                            x: Math.max(0, depth) * root.pathTreeIndentWidth
                                            width: root.pathTreeExpanderWidth
                                            height: parent.height

                                            Label {
                                                anchors.centerIn: parent
                                                visible: hasChildren && canExpand
                                                text: expanded ? "\u25BC" : "\u25B6"
                                                color: "#475569"
                                            }

                                            MouseArea {
                                                anchors.fill: parent
                                                enabled: hasChildren && canExpand
                                                cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                                                onClicked: protocolPathListView.model.toggleExpanded(nodeId)
                                            }
                                        }

                                        Label {
                                            id: protocolPathLabel
                                            x: (Math.max(0, depth) * root.pathTreeIndentWidth) + root.pathTreeExpanderWidth + 4
                                            width: Math.max(0, root.pathTreeLabelColumnWidth - x)
                                            anchors.verticalCenter: parent.verticalCenter
                                            text: layerText
                                            color: "#0f172a"
                                            elide: Text.ElideRight

                                            ToolTip.visible: protocolPathHoverHandler.hovered && tooltipText.length > 0 && implicitWidth > width + 1
                                            ToolTip.text: tooltipText
                                        }

                                        MouseArea {
                                            anchors.fill: parent
                                            anchors.leftMargin: (Math.max(0, depth) * root.pathTreeIndentWidth) + root.pathTreeExpanderWidth
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: protocolPathListView.model.selectNode(nodeId)
                                        }

                                        HoverHandler { id: protocolPathHoverHandler }

                                        Label {
                                            x: root.pathTreeLabelColumnWidth + root.tableColumnSpacing
                                            width: root.pathTreeFlowsColumnWidth
                                            anchors.verticalCenter: parent.verticalCenter
                                            horizontalAlignment: Text.AlignRight
                                            text: flowCountText
                                            color: "#334155"
                                            elide: Text.ElideLeft
                                        }

                                        Label {
                                            x: root.pathTreeLabelColumnWidth + root.tableColumnSpacing + root.pathTreeFlowsColumnWidth + root.tableColumnSpacing
                                            width: root.pathTreePacketsColumnWidth
                                            anchors.verticalCenter: parent.verticalCenter
                                            horizontalAlignment: Text.AlignRight
                                            text: packetCountText
                                            color: "#334155"
                                            elide: Text.ElideLeft
                                        }

                                        Label {
                                            x: root.pathTreeLabelColumnWidth + root.tableColumnSpacing + root.pathTreeFlowsColumnWidth + root.tableColumnSpacing + root.pathTreePacketsColumnWidth + root.tableColumnSpacing
                                            width: root.pathTreeOriginalColumnWidth
                                            anchors.verticalCenter: parent.verticalCenter
                                            horizontalAlignment: Text.AlignRight
                                            text: originalByteCountText
                                            color: "#334155"
                                            elide: Text.ElideLeft
                                        }
                                    }
                                }
                            }
                        }

                    }
                }

                CollapsibleStatisticsSection {
                    id: protocolHintsSection
                    objectName: "protocolHintsSection"
                    title: "Detected Protocol Hints"
                    toggleObjectName: "protocolHintStatisticsToggleButton"
                    expanded: root.protocolHintsExpanded
                    onExpandedChangedByUser: function(expanded) {
                        root.protocolHintsExpanded = expanded
                        root.statisticsSectionExpandedChanged(root.sectionProtocolHints, expanded)
                    }

                    Label {
                        visible: root.protocolHintsSectionState === root.requestStateLoading ||
                            root.protocolHintsSectionState === root.requestStateUnavailable ||
                            root.protocolHintsSectionState === root.requestStateError
                        text: root.protocolHintsSectionStatusText
                        color: "#64748b"
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        visible: root.protocolHintsSectionState === root.requestStateReady
                        spacing: 6

                        Rectangle {
                            width: Math.min(root.hintTableWidth, parent ? parent.width : root.hintTableWidth)
                            height: root.tableHeaderHeight
                            radius: 4
                            color: "#f8fafc"
                            border.color: "#e2e8f0"

                            Item {
                                anchors.fill: parent
                                anchors.leftMargin: root.tablePadding
                                anchors.rightMargin: root.tablePadding

                                Label { x: 0; width: root.hintGroupColumnWidth; anchors.verticalCenter: parent.verticalCenter; text: "Group"; font.bold: true; color: "#334155" }
                                Label { x: root.hintGroupColumnWidth + root.tableColumnSpacing; width: root.hintProtocolColumnWidth; anchors.verticalCenter: parent.verticalCenter; text: "Protocol"; font.bold: true; color: "#334155" }
                                Label { x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing; width: root.hintFlowsColumnWidth; anchors.verticalCenter: parent.verticalCenter; horizontalAlignment: Text.AlignRight; text: "Flows"; font.bold: true; color: "#334155" }
                                Label { x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing + root.hintFlowsColumnWidth + root.tableColumnSpacing; width: root.hintPacketsColumnWidth; anchors.verticalCenter: parent.verticalCenter; horizontalAlignment: Text.AlignRight; text: "Packets"; font.bold: true; color: "#334155" }
                                Label { x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing + root.hintFlowsColumnWidth + root.tableColumnSpacing + root.hintPacketsColumnWidth + root.tableColumnSpacing; width: root.hintCapturedColumnWidth; anchors.verticalCenter: parent.verticalCenter; horizontalAlignment: Text.AlignRight; text: "Captured"; font.bold: true; color: "#334155" }
                                Label { x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing + root.hintFlowsColumnWidth + root.tableColumnSpacing + root.hintPacketsColumnWidth + root.tableColumnSpacing + root.hintCapturedColumnWidth + root.tableColumnSpacing; width: root.hintOriginalColumnWidth; anchors.verticalCenter: parent.verticalCenter; horizontalAlignment: Text.AlignRight; text: "Original"; font.bold: true; color: "#334155" }
                            }
                        }

                        Repeater {
                            model: root.protocolHintDistribution

                            delegate: Rectangle {
                                required property var modelData
                                width: Math.min(root.hintTableWidth, parent ? parent.width : root.hintTableWidth)
                                height: root.tableRowHeight
                                radius: 4
                                color: index % 2 === 0 ? "transparent" : "#f8fafc"

                                Item {
                                    anchors.fill: parent
                                    anchors.leftMargin: root.tablePadding
                                    anchors.rightMargin: root.tablePadding

                                    Label { x: 0; width: root.hintGroupColumnWidth; anchors.verticalCenter: parent.verticalCenter; text: root.protocolHintGroup(modelData["title"] || ""); color: "#334155"; elide: Text.ElideRight }
                                    Label { x: root.hintGroupColumnWidth + root.tableColumnSpacing; width: root.hintProtocolColumnWidth; anchors.verticalCenter: parent.verticalCenter; text: modelData["title"] || ""; color: "#0f172a"; elide: Text.ElideRight }
                                    Label { x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing; width: root.hintFlowsColumnWidth; anchors.verticalCenter: parent.verticalCenter; horizontalAlignment: Text.AlignRight; text: modelData["flowCountText"] || ""; color: "#334155"; elide: Text.ElideLeft }
                                    Label { x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing + root.hintFlowsColumnWidth + root.tableColumnSpacing; width: root.hintPacketsColumnWidth; anchors.verticalCenter: parent.verticalCenter; horizontalAlignment: Text.AlignRight; text: modelData["packetCountText"] || ""; color: "#334155"; elide: Text.ElideLeft }
                                    Label { x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing + root.hintFlowsColumnWidth + root.tableColumnSpacing + root.hintPacketsColumnWidth + root.tableColumnSpacing; width: root.hintCapturedColumnWidth; anchors.verticalCenter: parent.verticalCenter; horizontalAlignment: Text.AlignRight; text: modelData["capturedBytesText"] || ""; color: "#334155"; elide: Text.ElideLeft }
                                    Label { x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing + root.hintFlowsColumnWidth + root.tableColumnSpacing + root.hintPacketsColumnWidth + root.tableColumnSpacing + root.hintCapturedColumnWidth + root.tableColumnSpacing; width: root.hintOriginalColumnWidth; anchors.verticalCenter: parent.verticalCenter; horizontalAlignment: Text.AlignRight; text: modelData["originalBytesText"] || ""; color: "#334155"; elide: Text.ElideLeft }
                                }
                            }
                        }

                        Label {
                            visible: root.protocolHintDistribution.length === 0
                            text: "No protocol-hint statistics are available for this capture."
                            color: "#64748b"
                        }
                    }
                }

                CollapsibleStatisticsSection {
                    id: captureMetricsSection
                    objectName: "captureMetricsSection"
                    title: "Capture Metrics"
                    toggleObjectName: "captureMetricsToggleButton"
                    expanded: root.captureMetricsExpanded
                    onExpandedChangedByUser: function(expanded) {
                        root.captureMetricsExpanded = expanded
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: width >= 860 ? 2 : 1
                        rowSpacing: 8
                        columnSpacing: 8

                        OverviewMetricBlock {
                            title: "Average Captured Packet Size"
                            valueText: root.statisticsText(root.captureMetrics, "averageCapturedPacketSizeText")
                            valueObjectName: "averageCapturedPacketSizeValue"
                        }

                        OverviewMetricBlock {
                            title: "Average Original Packet Size"
                            valueText: root.statisticsText(root.captureMetrics, "averageOriginalPacketSizeText")
                            valueObjectName: "averageOriginalPacketSizeValue"
                        }

                        OverviewMetricBlock {
                            title: "Average Packet Rate"
                            valueText: root.statisticsText(root.captureMetrics, "averagePacketRateText")
                            valueObjectName: "averagePacketRateValue"
                        }

                        OverviewMetricBlock {
                            title: "Average Captured Data Rate"
                            valueText: root.statisticsText(root.captureMetrics, "averageCapturedDataRateText")
                            valueObjectName: "averageCapturedDataRateValue"
                        }

                        OverviewMetricBlock {
                            title: "Average Original Data Rate"
                            valueText: root.statisticsText(root.captureMetrics, "averageOriginalDataRateText")
                            valueObjectName: "averageOriginalDataRateValue"
                        }

                        OverviewMetricBlock {
                            title: "Truncated Packets"
                            valueText: root.statisticsText(root.captureMetrics, "truncatedPacketsText")
                            valueObjectName: "truncatedPacketsValue"
                        }

                        OverviewMetricBlock {
                            title: "Not Captured Bytes"
                            valueText: root.statisticsText(root.captureMetrics, "notCapturedBytesText")
                            valueObjectName: "notCapturedBytesValue"
                        }

                        OverviewMetricBlock {
                            title: "Capture Completeness"
                            valueText: root.statisticsText(root.captureMetrics, "captureCompletenessText")
                            valueObjectName: "captureCompletenessValue"
                        }
                    }
                }

                CollapsibleStatisticsSection {
                    id: flowCharacteristicsSection
                    objectName: "flowCharacteristicsSection"
                    title: "Flow Characteristics"
                    toggleObjectName: "flowCharacteristicsToggleButton"
                    expanded: root.flowCharacteristicsExpanded
                    onExpandedChangedByUser: function(expanded) {
                        root.flowCharacteristicsExpanded = expanded
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: width >= 720 ? 2 : 1
                        rowSpacing: 8
                        columnSpacing: 8

                        OverviewMetricBlock {
                            title: "Only A -> B Flows"
                            valueText: root.statisticsText(root.flowCharacteristics, "onlyAToBFlowsText")
                            valueObjectName: "onlyAToBFlowsValue"
                        }

                        OverviewMetricBlock {
                            title: "Service Recognized"
                            valueText: root.statisticsText(root.flowCharacteristics, "serviceRecognizedFlowsText")
                            valueObjectName: "serviceRecognizedFlowsValue"
                        }
                    }
                }

                CollapsibleStatisticsSection {
                    id: directionDistributionSection
                    objectName: "directionDistributionSection"
                    title: "Direction Distribution"
                    toggleObjectName: "directionDistributionToggleButton"
                    expanded: root.directionDistributionExpanded
                    onExpandedChangedByUser: function(expanded) {
                        root.directionDistributionExpanded = expanded
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: width >= (root.directionTableWidth * 2) + 24 ? 2 : 1
                        rowSpacing: 10
                        columnSpacing: 10

                        SectionFrame {
                            objectName: "packetDirectionDistributionSection"
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            Layout.alignment: Qt.AlignTop

                            Label {
                                text: "Packet Direction"
                                font.bold: true
                                font.pixelSize: 14
                                color: "#0f172a"
                            }

                            ThreeColumnHeader {
                                firstTitle: "Group"
                                secondTitle: "Flows"
                                thirdTitle: "Percent"
                                firstWidth: root.directionLabelColumnWidth
                                secondWidth: root.directionFlowColumnWidth
                                thirdWidth: root.directionPercentColumnWidth
                                tableWidth: root.directionTableWidth
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 6

                                Repeater {
                                    model: root.statisticsRows(root.packetDirectionDistribution)

                                    delegate: Rectangle {
                                        required property var modelData
                                        Layout.fillWidth: true
                                        implicitHeight: packetDirectionRowLayout.implicitHeight + 8
                                        radius: 4
                                        color: "transparent"

                                        RowLayout {
                                            id: packetDirectionRowLayout
                                            anchors.fill: parent
                                            anchors.leftMargin: root.tablePadding
                                            anchors.rightMargin: root.tablePadding
                                            spacing: root.tableColumnSpacing

                                            Label {
                                                Layout.preferredWidth: root.directionLabelColumnWidth
                                                Layout.minimumWidth: root.directionLabelColumnWidth
                                                text: modelData.label
                                                color: "#0f172a"
                                                elide: Text.ElideRight
                                            }

                                            Label {
                                                Layout.preferredWidth: root.directionFlowColumnWidth
                                                Layout.minimumWidth: root.directionFlowColumnWidth
                                                horizontalAlignment: Text.AlignRight
                                                text: modelData.flowCountText
                                                color: "#334155"
                                                elide: Text.ElideLeft
                                            }

                                            Label {
                                                Layout.preferredWidth: root.directionPercentColumnWidth
                                                Layout.minimumWidth: root.directionPercentColumnWidth
                                                horizontalAlignment: Text.AlignRight
                                                text: modelData.percentText
                                                color: "#334155"
                                                elide: Text.ElideLeft
                                            }

                                            Item {
                                                Layout.fillWidth: true
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        SectionFrame {
                            objectName: "dataDirectionDistributionSection"
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            Layout.alignment: Qt.AlignTop

                            Label {
                                text: "Data Direction (Original Bytes)"
                                font.bold: true
                                font.pixelSize: 14
                                color: "#0f172a"
                            }

                            Label {
                                objectName: "dataDirectionDistributionHelpText"
                                readonly property string helpTextValue: root.statisticsText(root.dataDirectionDistribution, "helpText")
                                visible: helpTextValue.length > 0
                                text: helpTextValue
                                color: "#64748b"
                                wrapMode: Text.WordWrap
                            }

                            ThreeColumnHeader {
                                firstTitle: "Group"
                                secondTitle: "Flows"
                                thirdTitle: "Percent"
                                firstWidth: root.directionLabelColumnWidth
                                secondWidth: root.directionFlowColumnWidth
                                thirdWidth: root.directionPercentColumnWidth
                                tableWidth: root.directionTableWidth
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 6

                                Repeater {
                                    model: root.statisticsRows(root.dataDirectionDistribution)

                                    delegate: Rectangle {
                                        required property var modelData
                                        Layout.fillWidth: true
                                        implicitHeight: dataDirectionRowLayout.implicitHeight + 8
                                        radius: 4
                                        color: "transparent"

                                        RowLayout {
                                            id: dataDirectionRowLayout
                                            anchors.fill: parent
                                            anchors.leftMargin: root.tablePadding
                                            anchors.rightMargin: root.tablePadding
                                            spacing: root.tableColumnSpacing

                                            Label {
                                                Layout.preferredWidth: root.directionLabelColumnWidth
                                                Layout.minimumWidth: root.directionLabelColumnWidth
                                                text: modelData.label
                                                color: "#0f172a"
                                                elide: Text.ElideRight
                                            }

                                            Label {
                                                Layout.preferredWidth: root.directionFlowColumnWidth
                                                Layout.minimumWidth: root.directionFlowColumnWidth
                                                horizontalAlignment: Text.AlignRight
                                                text: modelData.flowCountText
                                                color: "#334155"
                                                elide: Text.ElideLeft
                                            }

                                            Label {
                                                Layout.preferredWidth: root.directionPercentColumnWidth
                                                Layout.minimumWidth: root.directionPercentColumnWidth
                                                horizontalAlignment: Text.AlignRight
                                                text: modelData.percentText
                                                color: "#334155"
                                                elide: Text.ElideLeft
                                            }

                                            Item {
                                                Layout.fillWidth: true
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                CollapsibleStatisticsSection {
                    id: tcpFlagsSection
                    objectName: "tcpFlagsSection"
                    title: "TCP Flags"
                    toggleObjectName: "tcpFlagsToggleButton"
                    expanded: root.tcpFlagsExpanded
                    onExpandedChangedByUser: function(expanded) {
                        root.tcpFlagsExpanded = expanded
                    }

                    SectionFrame {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0

                        Label {
                            objectName: "tcpFlagsHelpText"
                            readonly property string helpTextValue: (
                                root.tcpFlagStatistics &&
                                root.tcpFlagStatistics.helpText !== undefined &&
                                root.tcpFlagStatistics.helpText !== null
                            ) ? String(root.tcpFlagStatistics.helpText) : ""
                            visible: helpTextValue.length > 0
                            text: helpTextValue
                            color: "#64748b"
                            wrapMode: Text.WordWrap
                        }

                        ThreeColumnHeader {
                            firstTitle: "Flag"
                            secondTitle: "Packets"
                            thirdTitle: "Percent"
                            firstWidth: root.tcpFlagLabelColumnWidth
                            secondWidth: root.tcpFlagPacketColumnWidth
                            thirdWidth: root.tcpFlagPercentColumnWidth
                            tableWidth: root.tcpFlagTableWidth
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 6

                            Repeater {
                                id: tcpFlagsRowsRepeater
                                objectName: "tcpFlagsRowsRepeater"
                                model: root.statisticsRows(root.tcpFlagStatistics)

                                delegate: Rectangle {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    implicitHeight: tcpFlagRowLayout.implicitHeight + 8
                                    radius: 4
                                    color: "transparent"
                                    objectName: "tcpFlagRow"

                                    RowLayout {
                                        id: tcpFlagRowLayout
                                        anchors.fill: parent
                                        anchors.leftMargin: root.tablePadding
                                        anchors.rightMargin: root.tablePadding
                                        spacing: root.tableColumnSpacing

                                        Label {
                                            Layout.preferredWidth: root.tcpFlagLabelColumnWidth
                                            Layout.minimumWidth: root.tcpFlagLabelColumnWidth
                                            text: modelData.label
                                            color: "#0f172a"
                                            elide: Text.ElideRight
                                            objectName: "tcpFlagLabel"
                                        }

                                        Label {
                                            Layout.preferredWidth: root.tcpFlagPacketColumnWidth
                                            Layout.minimumWidth: root.tcpFlagPacketColumnWidth
                                            horizontalAlignment: Text.AlignRight
                                            text: modelData.packetCountText
                                            color: "#334155"
                                            elide: Text.ElideLeft
                                            objectName: "tcpFlagPacketValue"
                                        }

                                        Label {
                                            Layout.preferredWidth: root.tcpFlagPercentColumnWidth
                                            Layout.minimumWidth: root.tcpFlagPercentColumnWidth
                                            horizontalAlignment: Text.AlignRight
                                            text: modelData.percentText
                                            color: "#334155"
                                            elide: Text.ElideLeft
                                            objectName: "tcpFlagPercentValue"
                                        }

                                        Item {
                                            Layout.fillWidth: true
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                CollapsibleStatisticsSection {
                    id: quicTlsSection
                    objectName: "quicTlsSection"
                    title: "QUIC and TLS"
                    toggleObjectName: "quicTlsStatisticsToggleButton"
                    expanded: root.quicTlsExpanded
                    onExpandedChangedByUser: function(expanded) {
                        root.quicTlsExpanded = expanded
                        root.statisticsSectionExpandedChanged(root.sectionQuicTls, expanded)
                    }

                    Label {
                        visible: root.quicTlsSectionState === root.requestStateLoading ||
                            root.quicTlsSectionState === root.requestStateUnavailable ||
                            root.quicTlsSectionState === root.requestStateError
                        text: root.quicTlsSectionStatusText
                        color: "#64748b"
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        visible: root.quicTlsSectionState === root.requestStateReady
                        spacing: 10

                        SectionFrame {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            Layout.alignment: Qt.AlignTop

                            Label { text: "QUIC"; font.bold: true }
                            CompactMetricLabel { text: "Flows: " + root.groupInteger(root.quicTotalFlows) }
                            Label { text: "Initial recognition"; font.bold: true; font.pixelSize: 12; color: "#475569" }
                            CompactMetricLabel { text: "Recognized Initial: " + root.formatFlowPercentageAndCount(root.quicWithSni, root.quicTotalFlows) }
                            CompactMetricLabel { text: "Unrecognized: " + root.formatFlowPercentageAndCount(root.quicWithoutSni, root.quicTotalFlows) }
                            Label { text: "Version"; font.bold: true; font.pixelSize: 12; color: "#475569" }
                            CompactMetricLabel { text: "v1: " + root.groupInteger(root.quicVersionV1) }
                            CompactMetricLabel { text: "draft-29: " + root.groupInteger(root.quicVersionDraft29) }
                            CompactMetricLabel { text: "v2: " + root.groupInteger(root.quicVersionV2) }
                            CompactMetricLabel { text: "Version unavailable: " + root.groupInteger(root.quicVersionUnknown) }
                        }

                        SectionFrame {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            Layout.alignment: Qt.AlignTop

                            Label { text: "TLS"; font.bold: true }
                            CompactMetricLabel { text: "Flows: " + root.groupInteger(root.tlsTotalFlows) }
                            Label { text: "SNI"; font.bold: true; font.pixelSize: 12; color: "#475569" }
                            CompactMetricLabel { text: "With SNI: " + root.formatFlowPercentageAndCount(root.tlsWithSni, root.tlsTotalFlows) }
                            CompactMetricLabel { text: "Without SNI: " + root.formatFlowPercentageAndCount(root.tlsWithoutSni, root.tlsTotalFlows) }
                            Label { text: "Version"; font.bold: true; font.pixelSize: 12; color: "#475569" }
                            CompactMetricLabel { text: "TLS 1.2: " + root.groupInteger(root.tlsVersion12) }
                            CompactMetricLabel { text: "TLS 1.3: " + root.groupInteger(root.tlsVersion13) }
                            CompactMetricLabel { text: "Version unavailable: " + root.groupInteger(root.tlsVersionUnknown) }
                        }
                    }
                }

                CollapsibleStatisticsSection {
                    id: topFlowsSection
                    objectName: "topFlowsSection"
                    title: "Top Flows by Original Bytes"
                    toggleObjectName: "topFlowStatisticsToggleButton"
                    expanded: root.topFlowsExpanded
                    visible: root.showTopTalkers
                    onExpandedChangedByUser: function(expanded) {
                        root.topFlowsExpanded = expanded
                        root.statisticsSectionExpandedChanged(root.sectionTopFlows, expanded)
                    }

                    Label {
                        visible: root.topFlowSectionState === root.requestStateLoading ||
                            root.topFlowSectionState === root.requestStateUnavailable ||
                            root.topFlowSectionState === root.requestStateError
                        text: root.topFlowSectionStatusText
                        color: "#64748b"
                    }

                    Flickable {
                        id: topFlowTableFlickable
                        objectName: "topFlowTableFlickable"
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        Layout.preferredHeight: topFlowTableContent.implicitHeight
                            + (root.topFlowTableWidth > width ? topFlowHorizontalScrollBar.implicitHeight + 4 : 0)
                        implicitHeight: Layout.preferredHeight
                        visible: root.topFlowSectionState === root.requestStateReady
                        clip: true
                        boundsBehavior: Flickable.StopAtBounds
                        flickableDirection: Flickable.HorizontalFlick
                        interactive: contentWidth > width
                        contentWidth: topFlowTableContent.width
                        contentHeight: topFlowTableContent.implicitHeight

                        ScrollBar.horizontal: AppScrollBar {
                            id: topFlowHorizontalScrollBar
                            policy: topFlowTableFlickable.contentWidth > topFlowTableFlickable.width
                                ? ScrollBar.AlwaysOn
                                : ScrollBar.AlwaysOff
                        }

                        Column {
                            id: topFlowTableContent
                            objectName: "topFlowTableContent"
                            width: Math.max(topFlowTableFlickable.width, root.topFlowTableWidth)
                            spacing: 8

                            Rectangle {
                                id: topFlowHeader
                                objectName: "topFlowTableHeader"
                                width: parent.width
                                height: root.tableHeaderHeight + 2
                                radius: 4
                                color: "#f8fafc"
                                border.color: "#e2e8f0"

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: root.tablePadding
                                    anchors.rightMargin: root.tablePadding
                                    spacing: root.tableColumnSpacing

                                    Label { Layout.preferredWidth: root.topFlowColumnFlowWidth; text: "Flow"; font.bold: true; color: "#334155" }
                                    Label { Layout.preferredWidth: root.topFlowColumnEndpointWidth; text: "Endpoint A"; font.bold: true; color: "#334155" }
                                    Label { Layout.preferredWidth: root.topFlowColumnEndpointWidth; text: "Endpoint B"; font.bold: true; color: "#334155" }
                                    Label { Layout.preferredWidth: root.topFlowColumnProtocolWidth; text: "Protocol"; font.bold: true; color: "#334155" }
                                    Label { Layout.preferredWidth: root.topFlowColumnDetectedWidth; text: "Detected Protocol"; font.bold: true; color: "#334155" }
                                    Label { Layout.preferredWidth: root.topFlowColumnServiceWidth; text: "Service"; font.bold: true; color: "#334155" }
                                    Label { Layout.preferredWidth: root.topFlowColumnPathWidth; text: "Protocol Path"; font.bold: true; color: "#334155" }
                                    Label { Layout.preferredWidth: root.topFlowColumnPacketsWidth; horizontalAlignment: Text.AlignRight; text: "Packets"; font.bold: true; color: "#334155" }
                                    Label { Layout.preferredWidth: root.topFlowColumnBytesWidth; horizontalAlignment: Text.AlignRight; text: "Captured"; font.bold: true; color: "#334155" }
                                    Label { Layout.preferredWidth: root.topFlowColumnBytesWidth; horizontalAlignment: Text.AlignRight; text: "Original"; font.bold: true; color: "#334155" }
                                }
                            }

                            Column {
                                id: topFlowRowsColumn
                                width: parent.width
                                spacing: 4

                                Repeater {
                                    id: topFlowRowsRepeater
                                    objectName: "topFlowRowsRepeater"
                                    model: root.topFlowRows

                                    delegate: Rectangle {
                                        required property int index
                                        required property var modelData
                                        width: topFlowRowsColumn.width
                                        height: 34
                                        radius: 4
                                        color: index % 2 === 0 ? "transparent" : "#f8fafc"

                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: root.tablePadding
                                            anchors.rightMargin: root.tablePadding
                                            spacing: root.tableColumnSpacing

                                            Label { Layout.preferredWidth: root.topFlowColumnFlowWidth; text: modelData.flowIndexText; color: "#0f172a" }
                                            Label { Layout.preferredWidth: root.topFlowColumnEndpointWidth; text: modelData.endpointA; elide: Text.ElideMiddle; color: "#0f172a"; ToolTip.visible: endpointAHover.hovered; ToolTip.text: modelData.endpointA; HoverHandler { id: endpointAHover } }
                                            Label { Layout.preferredWidth: root.topFlowColumnEndpointWidth; text: modelData.endpointB; elide: Text.ElideMiddle; color: "#0f172a"; ToolTip.visible: endpointBHover.hovered; ToolTip.text: modelData.endpointB; HoverHandler { id: endpointBHover } }
                                            Label { Layout.preferredWidth: root.topFlowColumnProtocolWidth; text: modelData.protocolText; color: "#0f172a" }
                                            Label { Layout.preferredWidth: root.topFlowColumnDetectedWidth; text: modelData.detectedProtocolText; color: "#0f172a"; elide: Text.ElideRight }
                                            Label { Layout.preferredWidth: root.topFlowColumnServiceWidth; text: modelData.serviceText; color: "#0f172a"; elide: Text.ElideRight; ToolTip.visible: serviceHover.hovered; ToolTip.text: modelData.serviceText; HoverHandler { id: serviceHover } }
                                            Label { Layout.preferredWidth: root.topFlowColumnPathWidth; text: modelData.protocolPathCompactText; color: "#0f172a"; elide: Text.ElideRight; ToolTip.visible: pathHover.hovered; ToolTip.text: modelData.protocolPathCompactText; HoverHandler { id: pathHover } }
                                            Label { Layout.preferredWidth: root.topFlowColumnPacketsWidth; horizontalAlignment: Text.AlignRight; text: modelData.packetCountText; color: "#0f172a" }
                                            Label { Layout.preferredWidth: root.topFlowColumnBytesWidth; horizontalAlignment: Text.AlignRight; text: modelData.capturedBytesText; color: "#0f172a" }
                                            Label { Layout.preferredWidth: root.topFlowColumnBytesWidth; horizontalAlignment: Text.AlignRight; text: modelData.originalBytesText; color: "#0f172a" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                CollapsibleStatisticsSection {
                    id: topTalkersSection
                    objectName: "topEndpointsPortsSection"
                    title: "Top Endpoints and Ports"
                    toggleObjectName: "topEndpointPortStatisticsToggleButton"
                    expanded: root.topEndpointsPortsExpanded
                    visible: root.showTopTalkers
                    onExpandedChangedByUser: function(expanded) {
                        root.topEndpointsPortsExpanded = expanded
                        root.statisticsSectionExpandedChanged(root.sectionTopEndpointsPorts, expanded)
                    }

                    Label {
                        visible: root.topEndpointPortSectionState === root.requestStateLoading ||
                            root.topEndpointPortSectionState === root.requestStateUnavailable ||
                            root.topEndpointPortSectionState === root.requestStateError
                        text: root.topEndpointPortSectionStatusText
                        color: "#64748b"
                    }

                    TopTalkersPane {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        Layout.preferredHeight: 260
                        visible: root.topEndpointPortSectionState === root.requestStateReady
                        hasCapture: root.hasCapture
                        topEndpointsModel: root.topEndpointsModel
                        topPortsModel: root.topPortsModel
                        onEndpointActivated: function(endpointText) { root.endpointActivated(endpointText) }
                        onPortActivated: function(port) { root.portActivated(port) }
                    }
                }
            }
        }
    }
}
