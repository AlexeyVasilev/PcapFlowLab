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
    property var ipv6FlowCount: 0
    property var quicTotalFlows: 0
    property var quicWithSni: 0
    property var quicWithoutSni: 0
    property var quicVersionV1: 0
    property var quicVersionDraft29: 0
    property var quicVersionV2: 0
    property var quicVersionUnknown: 0
    property bool hasCapture: false

    function formatPercentageAndCount(part, total) {
        if (total <= 0)
            return "0% (0 connections)"
        const percent = Math.round((part * 100) / total)
        return percent + "% (" + part + " connections)"
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
                            text: root.hasCapture ? "Flows: " + modelData.flows : "Flows: -"
                        }

                        Label {
                            text: root.hasCapture ? "Packets: " + modelData.packets : "Packets: -"
                        }

                        Label {
                            text: root.hasCapture ? "Bytes: " + modelData.bytes : "Bytes: -"
                        }
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 24

            Label {
                text: root.hasCapture ? "IPv4 flows: " + root.ipv4FlowCount : "IPv4 flows: -"
            }

            Label {
                text: root.hasCapture ? "IPv6 flows: " + root.ipv6FlowCount : "IPv6 flows: -"
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
                    text: "Initial recognising:"
                    font.bold: true
                }

                Label {
                    text: root.hasCapture
                        ? "Recognised Initial: " + root.formatPercentageAndCount(root.quicWithSni, root.quicTotalFlows)
                        : "Recognised Initial: -"
                }

                Label {
                    text: root.hasCapture
                        ? "Unrecognised: " + root.formatPercentageAndCount(root.quicWithoutSni, root.quicTotalFlows)
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
    }
}

