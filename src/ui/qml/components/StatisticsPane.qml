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
    readonly property int sectionTopEndpointsPorts: 5
    readonly property int flowPacketHistogramModeFlows: 0
    readonly property int flowPacketHistogramModeOriginalBytes: 1
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
    readonly property int pathTreeLabelColumnWidth: 420
    readonly property int pathTreeFlowsColumnWidth: 138
    readonly property int pathTreePacketsColumnWidth: 150
    readonly property int pathTreeOriginalColumnWidth: 150
    readonly property int pathTreeTableWidth: pathTreeLabelColumnWidth + pathTreeFlowsColumnWidth + pathTreePacketsColumnWidth + pathTreeOriginalColumnWidth + (tableColumnSpacing * 3) + (tablePadding * 2)
    readonly property int pathTreeViewportMaxHeight: 420
    readonly property int pathTreeIndentWidth: 18
    readonly property int pathTreeExpanderWidth: 16
    readonly property string protocolPathPrimaryColumnTitle: root.statisticsMode === 2 ? "Path" : "Layer"

    property bool packetSizeDistributionExpanded: false
    property bool flowPacketHistogramExpanded: false
    property bool protocolPathExpanded: false
    property bool protocolHintsExpanded: false
    property bool quicTlsExpanded: false
    property bool topEndpointsPortsExpanded: false
    property int flowPacketHistogramDisplayMode: flowPacketHistogramModeFlows

    signal endpointActivated(string endpointText)
    signal portActivated(int port)
    signal statisticsModeChangedByUser(int mode)
    signal showFlowsRequested()
    signal protocolPathExportRequested()
    signal statisticsSectionExpandedChanged(int section, bool expanded)

    onStatisticsSectionsResetTokenChanged: {
        packetSizeDistributionExpanded = false
        flowPacketHistogramExpanded = false
        protocolPathExpanded = false
        protocolHintsExpanded = false
        quicTlsExpanded = false
        topEndpointsPortsExpanded = false
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
        padding: 0

        background: Rectangle {
            color: "#ffffff"
            border.color: "#d8dee9"
            radius: 6
        }

        ColumnLayout {
            id: sectionLayout
            anchors.fill: parent
            anchors.margins: 10
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
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                horizontalAlignment: Text.AlignRight
                                text: "Packets"
                                font.bold: true
                                color: "#334155"
                            }

                            Label {
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                horizontalAlignment: Text.AlignRight
                                text: "Captured Bytes"
                                font.bold: true
                                color: "#334155"
                            }

                            Label {
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                horizontalAlignment: Text.AlignRight
                                text: "Original Bytes"
                                font.bold: true
                                color: "#334155"
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
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                horizontalAlignment: Text.AlignRight
                                text: root.groupInteger(root.unrecognizedStatsPacketCount)
                                color: "#0f172a"
                            }

                            Label {
                                objectName: "unrecognizedStatsCapturedBytesValue"
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                horizontalAlignment: Text.AlignRight
                                text: root.formatBytes(root.unrecognizedStatsCapturedBytes)
                                color: "#334155"
                            }

                            Label {
                                objectName: "unrecognizedStatsOriginalBytesValue"
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                horizontalAlignment: Text.AlignRight
                                text: root.formatBytes(root.unrecognizedStatsOriginalBytes)
                                color: "#334155"
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

                    Label {
                        Layout.fillWidth: true
                        visible: root.hasCapture
                        text: "Captured packet lengths for all packets imported from the capture, including unrecognized packets."
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
                                        width: Math.max(0, (parent.width - 2) * Number(modelData.normalizedFraction))
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
                                    text: root.groupInteger(modelData.packetCount)
                                    color: "#334155"
                                    elide: Text.ElideLeft
                                }
                            }
                        }

                        Label {
                            objectName: "packetSizeDistributionMaximumCapturedPacketLengthValue"
                            Layout.fillWidth: true
                            text: "Maximum captured packet size: " + root.packetSizeDistributionMaximumCapturedPacketLengthText
                            color: "#0f172a"
                            wrapMode: Text.WordWrap
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
                                                    : modelData.normalizedOriginalByteFraction
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
                                        : modelData.originalByteCountText
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
