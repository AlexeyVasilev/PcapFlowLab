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

    readonly property var selectedHintTotal: hintMetricTotal()

    function formatBytes(value) {
        if (value < 1024)
            return value + " B"
        if (value < 1024 * 1024)
            return (value / 1024).toFixed(1) + " KB"
        if (value < 1024 * 1024 * 1024)
            return (value / (1024 * 1024)).toFixed(1) + " MB"
        return (value / (1024 * 1024 * 1024)).toFixed(1) + " GB"
    }

    function metricValue(flows, packets, bytes) {
        if (statisticsMode === modePackets)
            return packets
        if (statisticsMode === modeBytes)
            return bytes
        return flows
    }

    function formatMetric(value) {
        if (statisticsMode === modeBytes)
            return formatBytes(value)
        if (statisticsMode === modePackets)
            return value + " packets"
        return value + " flows"
    }

    function formatPercentageAndMetric(part, total) {
        if (total <= 0)
            return "0% (" + formatMetric(0) + ")"
        const percent = Math.round((part * 100) / total)
        return percent + "% (" + formatMetric(part) + ")"
    }

    function formatFlowPercentageAndCount(part, total) {
        if (total <= 0)
            return "0% (0 connections)"
        const percent = Math.round((part * 100) / total)
        return percent + "% (" + part + " connections)"
    }

    function hintMetricTotal() {
        if (!protocolHintDistribution || protocolHintDistribution.length === 0)
            return 0

        let total = 0
        for (let index = 0; index < protocolHintDistribution.length; ++index) {
            const row = protocolHintDistribution[index]
            total += metricValue(row.flows || 0, row.packets || 0, row.bytes || 0)
        }

        return total
    }

    background: Rectangle {
        color: "#f8fafc"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label {
            text: "Protocol Summary"
            font.bold: true
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

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

                delegate: Frame {
                    Layout.fillWidth: true

                    background: Rectangle {
                        color: "#ffffff"
                        border.color: "#d8dee9"
                        radius: 6
                    }

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 4

                        Label {
                            text: modelData.title
                            font.bold: true
                        }

                        Label {
                            text: root.hasCapture
                                ? "Value: " + root.formatMetric(root.metricValue(modelData.flows, modelData.packets, modelData.bytes))
                                : "Value: -"
                        }

                        Label {
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
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 24

            Label {
                text: root.hasCapture
                    ? "IPv4: " + root.formatPercentageAndMetric(
                          root.metricValue(root.ipv4FlowCount, root.ipv4PacketCount, root.ipv4TotalBytes),
                          root.selectedIpTotal
                      )
                    : "IPv4: -"
            }

            Label {
                text: root.hasCapture
                    ? "IPv6: " + root.formatPercentageAndMetric(
                          root.metricValue(root.ipv6FlowCount, root.ipv6PacketCount, root.ipv6TotalBytes),
                          root.selectedIpTotal
                      )
                    : "IPv6: -"
            }
        }

        Frame {
            Layout.fillWidth: true

            background: Rectangle {
                color: "#ffffff"
                border.color: "#d8dee9"
                radius: 6
            }

            ColumnLayout {
                anchors.fill: parent
                spacing: 6

                Label {
                    text: "Detected Protocol Hints"
                    font.bold: true
                }

                Repeater {
                    model: root.protocolHintDistribution

                    delegate: Label {
                        text: root.hasCapture
                            ? modelData.title + ": " + root.formatPercentageAndMetric(
                                  root.metricValue(modelData.flows || 0, modelData.packets || 0, modelData.bytes || 0),
                                  root.selectedHintTotal
                              )
                            : modelData.title + ": -"
                    }
                }
            }
        }

        Frame {
            Layout.fillWidth: true

            background: Rectangle {
                color: "#ffffff"
                border.color: "#d8dee9"
                radius: 6
            }

            ColumnLayout {
                anchors.fill: parent
                spacing: 6

                Label {
                    text: "QUIC"
                    font.bold: true
                }

                Label {
                    text: root.hasCapture ? "Flows: " + root.quicTotalFlows : "Flows: -"
                }

                Label {
                    text: "Initial recognising (flow-based):"
                    font.bold: true
                }

                Label {
                    text: root.hasCapture
                        ? "Recognised Initial: " + root.formatFlowPercentageAndCount(root.quicWithSni, root.quicTotalFlows)
                        : "Recognised Initial: -"
                }

                Label {
                    text: root.hasCapture
                        ? "Unrecognised: " + root.formatFlowPercentageAndCount(root.quicWithoutSni, root.quicTotalFlows)
                        : "Unrecognised: -"
                }

                Label {
                    text: "Version:"
                    font.bold: true
                }

                Label {
                    text: root.hasCapture ? "v1: " + root.quicVersionV1 : "v1: -"
                }

                Label {
                    text: root.hasCapture ? "draft-29: " + root.quicVersionDraft29 : "draft-29: -"
                }

                Label {
                    text: root.hasCapture ? "v2: " + root.quicVersionV2 : "v2: -"
                }

                Label {
                    text: root.hasCapture ? "unknown: " + root.quicVersionUnknown : "unknown: -"
                }
            }
        }

        Frame {
            Layout.fillWidth: true

            background: Rectangle {
                color: "#ffffff"
                border.color: "#d8dee9"
                radius: 6
            }

            ColumnLayout {
                anchors.fill: parent
                spacing: 6

                Label {
                    text: "TLS"
                    font.bold: true
                }

                Label {
                    text: root.hasCapture ? "Flows: " + root.tlsTotalFlows : "Flows: -"
                }

                Label {
                    text: "SNI (flow-based):"
                    font.bold: true
                }

                Label {
                    text: root.hasCapture
                        ? "With SNI: " + root.formatFlowPercentageAndCount(root.tlsWithSni, root.tlsTotalFlows)
                        : "With SNI: -"
                }

                Label {
                    text: root.hasCapture
                        ? "Without SNI: " + root.formatFlowPercentageAndCount(root.tlsWithoutSni, root.tlsTotalFlows)
                        : "Without SNI: -"
                }

                Label {
                    text: "Version:"
                    font.bold: true
                }

                Label {
                    text: root.hasCapture ? "TLS 1.2: " + root.tlsVersion12 : "TLS 1.2: -"
                }

                Label {
                    text: root.hasCapture ? "TLS 1.3: " + root.tlsVersion13 : "TLS 1.3: -"
                }

                Label {
                    text: root.hasCapture ? "unknown: " + root.tlsVersionUnknown : "unknown: -"
                }
            }
        }
    }
}

