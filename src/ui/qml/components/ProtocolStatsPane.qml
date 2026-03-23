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
    property bool hasCapture: false

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
    }
}
