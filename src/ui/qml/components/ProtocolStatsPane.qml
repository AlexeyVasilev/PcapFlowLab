import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var tcpFlowCount: 0
    property var tcpPacketCount: 0
    property var tcpTotalBytes: 0
    property var udpFlowCount: 0
    property var udpPacketCount: 0
    property var udpTotalBytes: 0
    property var otherFlowCount: 0
    property var otherPacketCount: 0
    property var otherTotalBytes: 0
    property var ipv4FlowCount: 0
    property var ipv4PacketCount: 0
    property var ipv4TotalBytes: 0
    property var ipv6FlowCount: 0
    property var ipv6PacketCount: 0
    property var ipv6TotalBytes: 0
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
    property var protocolHintDistribution: []
    property int statisticsMode: 0
    property bool hasCapture: false

    readonly property int modeFlows: 0
    readonly property int modePackets: 1
    readonly property int modeBytes: 2

    readonly property var selectedProtocolTotal: statisticsMode === modePackets
        ? (tcpPacketCount + udpPacketCount + otherPacketCount)
        : (statisticsMode === modeBytes
            ? (tcpTotalBytes + udpTotalBytes + otherTotalBytes)
            : (tcpFlowCount + udpFlowCount + otherFlowCount))

    readonly property var selectedIpTotal: statisticsMode === modePackets
        ? (ipv4PacketCount + ipv6PacketCount)
        : (statisticsMode === modeBytes
            ? (ipv4TotalBytes + ipv6TotalBytes)
            : (ipv4FlowCount + ipv6FlowCount))

    readonly property int hintGroupColumnWidth: 92
    readonly property int hintProtocolColumnWidth: 180
    readonly property int hintFlowsColumnWidth: 110
    readonly property int hintPacketsColumnWidth: 118
    readonly property int hintBytesColumnWidth: 118
    readonly property int hintColumnSpacing: 12
    readonly property int hintTablePadding: 8
    readonly property int hintTableWidth: hintGroupColumnWidth + hintProtocolColumnWidth + hintFlowsColumnWidth + hintPacketsColumnWidth + hintBytesColumnWidth + (hintColumnSpacing * 4) + (hintTablePadding * 2)

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

    function metricValue(flows, packets, bytes) {
        if (statisticsMode === modePackets)
            return packets
        if (statisticsMode === modeBytes)
            return bytes
        return flows
    }

    function formatMetricValue(value) {
        if (statisticsMode === modeBytes)
            return formatBytes(value)
        return groupInteger(value)
    }

    function metricLabel() {
        if (statisticsMode === modePackets)
            return "packets"
        if (statisticsMode === modeBytes)
            return ""
        return "flows"
    }

    function formatMetric(value) {
        const label = metricLabel()
        const formattedValue = formatMetricValue(value)
        return label.length > 0 ? (formattedValue + " " + label) : formattedValue
    }

    function formatShare(part, total) {
        if (total <= 0)
            return "0%"
        const percent = Math.round((part * 100) / total)
        return percent + "%"
    }

    function formatPercentageAndMetric(part, total) {
        return formatShare(part, total) + " (" + formatMetric(part) + ")"
    }

    function formatFlowPercentageAndCount(part, total) {
        if (total <= 0)
            return "0% (0 flows)"
        const percent = Math.round((part * 100) / total)
        return percent + "% (" + groupInteger(part) + " flows)"
    }

    function totalHintFlows() {
        if (!protocolHintDistribution || protocolHintDistribution.length === 0)
            return 0

        let total = 0
        for (let index = 0; index < protocolHintDistribution.length; ++index)
            total += protocolHintDistribution[index]["flows"] || 0
        return total
    }

    function totalHintPackets() {
        if (!protocolHintDistribution || protocolHintDistribution.length === 0)
            return 0

        let total = 0
        for (let index = 0; index < protocolHintDistribution.length; ++index)
            total += protocolHintDistribution[index]["packets"] || 0
        return total
    }

    function totalHintBytes() {
        if (!protocolHintDistribution || protocolHintDistribution.length === 0)
            return 0

        let total = 0
        for (let index = 0; index < protocolHintDistribution.length; ++index)
            total += protocolHintDistribution[index]["bytes"] || 0
        return total
    }

    function formatHintCell(value, total, isBytes) {
        const formattedValue = isBytes ? formatBytes(value) : groupInteger(value)
        return formattedValue + " (" + formatShare(value, total) + ")"
    }

    function protocolHintGroup(title) {
        if (title === "Possible TLS" || title === "Possible QUIC")
            return "Possible"
        if (title === "Unknown")
            return "Unknown"
        return "Confirmed"
    }

    component SectionFrame: Frame {
        id: sectionFrame

        default property alias sectionContent: sectionLayout.data

        Layout.fillWidth: true
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
            spacing: 6
        }
    }

    component CompactMetricLabel: Label {
        color: "#334155"
        wrapMode: Text.NoWrap
        elide: Text.ElideRight
    }

    padding: 0
    background: Rectangle {
        color: "#f8fafc"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 10
        spacing: 10

        Label {
            text: "Protocol Summary"
            font.bold: true
            font.pixelSize: 17
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 10

            Repeater {
                model: [
                    {
                        title: "TCP",
                        flows: root.tcpFlowCount,
                        packets: root.tcpPacketCount,
                        bytes: root.tcpTotalBytes
                    },
                    {
                        title: "UDP",
                        flows: root.udpFlowCount,
                        packets: root.udpPacketCount,
                        bytes: root.udpTotalBytes
                    },
                    {
                        title: "Other",
                        flows: root.otherFlowCount,
                        packets: root.otherPacketCount,
                        bytes: root.otherTotalBytes
                    }
                ]

                delegate: SectionFrame {
                    Layout.fillWidth: true

                    Label {
                        text: modelData.title
                        font.bold: true
                    }

                    CompactMetricLabel {
                        text: root.hasCapture
                            ? "Value: " + root.formatMetric(root.metricValue(modelData.flows, modelData.packets, modelData.bytes))
                            : "Value: -"
                    }

                    CompactMetricLabel {
                        text: root.hasCapture
                            ? "Share: " + root.formatPercentageAndMetric(
                                  root.metricValue(modelData.flows, modelData.packets, modelData.bytes),
                                  root.selectedProtocolTotal
                              )
                            : "Share: -"
                    }
                }
            }
        }

        SectionFrame {
            RowLayout {
                Layout.fillWidth: true
                spacing: 18

                CompactMetricLabel {
                    Layout.fillWidth: true
                    text: root.hasCapture
                        ? "IPv4: " + root.formatPercentageAndMetric(
                              root.metricValue(root.ipv4FlowCount, root.ipv4PacketCount, root.ipv4TotalBytes),
                              root.selectedIpTotal
                          )
                        : "IPv4: -"
                }

                CompactMetricLabel {
                    Layout.fillWidth: true
                    text: root.hasCapture
                        ? "IPv6: " + root.formatPercentageAndMetric(
                              root.metricValue(root.ipv6FlowCount, root.ipv6PacketCount, root.ipv6TotalBytes),
                              root.selectedIpTotal
                          )
                        : "IPv6: -"
                }
            }
        }

        SectionFrame {
            Label {
                text: "Detected Protocol Hints"
                font.bold: true
            }

            Rectangle {
                width: Math.min(root.hintTableWidth, parent ? parent.width : root.hintTableWidth)
                height: 28
                radius: 4
                color: "#f8fafc"
                border.color: "#e2e8f0"

                Item {
                    anchors.fill: parent
                    anchors.leftMargin: root.hintTablePadding
                    anchors.rightMargin: root.hintTablePadding

                    Label {
                        x: 0
                        width: root.hintGroupColumnWidth
                        anchors.verticalCenter: parent.verticalCenter
                        text: "Group"
                        font.bold: true
                        color: "#334155"
                    }

                    Label {
                        x: root.hintGroupColumnWidth + root.hintColumnSpacing
                        width: root.hintProtocolColumnWidth
                        anchors.verticalCenter: parent.verticalCenter
                        text: "Protocol"
                        font.bold: true
                        color: "#334155"
                    }

                    Label {
                        x: root.hintGroupColumnWidth + root.hintColumnSpacing + root.hintProtocolColumnWidth + root.hintColumnSpacing
                        width: root.hintFlowsColumnWidth
                        anchors.verticalCenter: parent.verticalCenter
                        horizontalAlignment: Text.AlignRight
                        text: "Flows"
                        font.bold: true
                        color: "#334155"
                    }

                    Label {
                        x: root.hintGroupColumnWidth + root.hintColumnSpacing + root.hintProtocolColumnWidth + root.hintColumnSpacing + root.hintFlowsColumnWidth + root.hintColumnSpacing
                        width: root.hintPacketsColumnWidth
                        anchors.verticalCenter: parent.verticalCenter
                        horizontalAlignment: Text.AlignRight
                        text: "Packets"
                        font.bold: true
                        color: "#334155"
                    }

                    Label {
                        x: root.hintGroupColumnWidth + root.hintColumnSpacing + root.hintProtocolColumnWidth + root.hintColumnSpacing + root.hintFlowsColumnWidth + root.hintColumnSpacing + root.hintPacketsColumnWidth + root.hintColumnSpacing
                        width: root.hintBytesColumnWidth
                        anchors.verticalCenter: parent.verticalCenter
                        horizontalAlignment: Text.AlignRight
                        text: "Bytes"
                        font.bold: true
                        color: "#334155"
                    }
                }
            }

            Repeater {
                model: root.protocolHintDistribution

                delegate: Rectangle {
                    width: Math.min(root.hintTableWidth, parent ? parent.width : root.hintTableWidth)
                    height: 26
                    radius: 4
                    color: index % 2 === 0 ? "transparent" : "#f8fafc"

                    Item {
                        anchors.fill: parent
                        anchors.leftMargin: root.hintTablePadding
                        anchors.rightMargin: root.hintTablePadding

                        Label {
                            x: 0
                            width: root.hintGroupColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            text: root.protocolHintGroup(modelData["title"] || "")
                            color: "#64748b"
                            elide: Text.ElideRight
                        }

                        Label {
                            x: root.hintGroupColumnWidth + root.hintColumnSpacing
                            width: root.hintProtocolColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            text: modelData["title"] || ""
                            color: "#0f172a"
                            elide: Text.ElideRight
                        }

                        Label {
                            x: root.hintGroupColumnWidth + root.hintColumnSpacing + root.hintProtocolColumnWidth + root.hintColumnSpacing
                            width: root.hintFlowsColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            horizontalAlignment: Text.AlignRight
                            text: root.hasCapture
                                ? root.formatHintCell(modelData["flows"] || 0, root.totalHintFlows(), false)
                                : "-"
                            color: "#334155"
                            elide: Text.ElideLeft
                        }

                        Label {
                            x: root.hintGroupColumnWidth + root.hintColumnSpacing + root.hintProtocolColumnWidth + root.hintColumnSpacing + root.hintFlowsColumnWidth + root.hintColumnSpacing
                            width: root.hintPacketsColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            horizontalAlignment: Text.AlignRight
                            text: root.hasCapture
                                ? root.formatHintCell(modelData["packets"] || 0, root.totalHintPackets(), false)
                                : "-"
                            color: "#334155"
                            elide: Text.ElideLeft
                        }

                        Label {
                            x: root.hintGroupColumnWidth + root.hintColumnSpacing + root.hintProtocolColumnWidth + root.hintColumnSpacing + root.hintFlowsColumnWidth + root.hintColumnSpacing + root.hintPacketsColumnWidth + root.hintColumnSpacing
                            width: root.hintBytesColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            horizontalAlignment: Text.AlignRight
                            text: root.hasCapture
                                ? root.formatHintCell(modelData["bytes"] || 0, root.totalHintBytes(), true)
                                : "-"
                            color: "#334155"
                            elide: Text.ElideLeft
                        }
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 10

            SectionFrame {
                Layout.fillWidth: true

                Label {
                    text: "QUIC"
                    font.bold: true
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "Flows: " + root.groupInteger(root.quicTotalFlows) : "Flows: -"
                }

                Label {
                    text: "Initial recognising (flow-based)"
                    font.bold: true
                    font.pixelSize: 12
                    color: "#475569"
                }

                CompactMetricLabel {
                    text: root.hasCapture
                        ? "Recognised Initial: " + root.formatFlowPercentageAndCount(root.quicWithSni, root.quicTotalFlows)
                        : "Recognised Initial: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture
                        ? "Unrecognised: " + root.formatFlowPercentageAndCount(root.quicWithoutSni, root.quicTotalFlows)
                        : "Unrecognised: -"
                }

                Label {
                    text: "Version"
                    font.bold: true
                    font.pixelSize: 12
                    color: "#475569"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "v1: " + root.groupInteger(root.quicVersionV1) : "v1: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "draft-29: " + root.groupInteger(root.quicVersionDraft29) : "draft-29: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "v2: " + root.groupInteger(root.quicVersionV2) : "v2: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "Version unavailable: " + root.groupInteger(root.quicVersionUnknown) : "Version unavailable: -"
                }
            }

            SectionFrame {
                Layout.fillWidth: true

                Label {
                    text: "TLS"
                    font.bold: true
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "Flows: " + root.groupInteger(root.tlsTotalFlows) : "Flows: -"
                }

                Label {
                    text: "SNI (flow-based)"
                    font.bold: true
                    font.pixelSize: 12
                    color: "#475569"
                }

                CompactMetricLabel {
                    text: root.hasCapture
                        ? "With SNI: " + root.formatFlowPercentageAndCount(root.tlsWithSni, root.tlsTotalFlows)
                        : "With SNI: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture
                        ? "Without SNI: " + root.formatFlowPercentageAndCount(root.tlsWithoutSni, root.tlsTotalFlows)
                        : "Without SNI: -"
                }

                Label {
                    text: "Version"
                    font.bold: true
                    font.pixelSize: 12
                    color: "#475569"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "TLS 1.2: " + root.groupInteger(root.tlsVersion12) : "TLS 1.2: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "TLS 1.3: " + root.groupInteger(root.tlsVersion13) : "TLS 1.3: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "Version unavailable: " + root.groupInteger(root.tlsVersionUnknown) : "Version unavailable: -"
                }
            }
        }
    }
}
