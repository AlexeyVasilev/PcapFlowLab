import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var packetModel: null
    property var selectedPacketIndex: -1

    signal packetSelected(var packetIndex)

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label {
            text: "Packets"
            font.pixelSize: 18
            font.bold: true
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: "#e2e8f0"
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Label {
                text: "Packet"
                font.bold: true
                Layout.preferredWidth: 72
            }

            Label {
                text: "Time"
                font.bold: true
                Layout.fillWidth: true
                Layout.preferredWidth: 120
            }

            Label {
                text: "Captured"
                font.bold: true
                Layout.preferredWidth: 84
            }

            Label {
                text: "Original"
                font.bold: true
                Layout.preferredWidth: 84
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: "#f8fafc"
            border.color: "#e2e8f0"
            radius: 6

            ListView {
                id: packetListView

                anchors.fill: parent
                anchors.margins: 1
                clip: true
                model: root.packetModel

                delegate: Rectangle {
                    required property var packetIndex
                    required property string timestamp
                    required property int capturedLength
                    required property int originalLength

                    width: packetListView.width
                    height: 36
                    color: root.selectedPacketIndex === packetIndex
                        ? "#dbeafe"
                        : (index % 2 === 0 ? "#ffffff" : "#f8fafc")

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 10
                        anchors.rightMargin: 10
                        spacing: 12

                        Label {
                            text: packetIndex
                            Layout.preferredWidth: 72
                        }

                        Label {
                            text: timestamp
                            Layout.fillWidth: true
                            Layout.preferredWidth: 120
                        }

                        Label {
                            text: capturedLength
                            Layout.preferredWidth: 84
                            horizontalAlignment: Text.AlignRight
                        }

                        Label {
                            text: originalLength
                            Layout.preferredWidth: 84
                            horizontalAlignment: Text.AlignRight
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: root.packetSelected(packetIndex)
                    }
                }
            }

            Label {
                anchors.centerIn: parent
                visible: packetListView.count === 0
                color: "#64748b"
                text: "No packets for selected flow"
            }
        }
    }
}
