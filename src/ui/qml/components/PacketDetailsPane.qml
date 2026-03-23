import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var packetDetailsModel: null

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label {
            text: "Packet Details"
            font.pixelSize: 18
            font.bold: true
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: "#e2e8f0"
        }

        TabBar {
            id: tabs
            Layout.fillWidth: true

            TabButton {
                text: "Summary"
            }

            TabButton {
                text: "Hex"
            }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: tabs.currentIndex

            Rectangle {
                color: "#f8fafc"
                border.color: "#e2e8f0"
                radius: 6

                ScrollView {
                    anchors.fill: parent
                    anchors.margins: 1
                    clip: true

                    TextArea {
                        readOnly: true
                        wrapMode: TextEdit.Wrap
                        text: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                            ? root.packetDetailsModel.summaryText
                            : "No packet selected"
                    }
                }
            }

            Rectangle {
                color: "#f8fafc"
                border.color: "#e2e8f0"
                radius: 6

                ScrollView {
                    anchors.fill: parent
                    anchors.margins: 1
                    clip: true

                    TextArea {
                        readOnly: true
                        wrapMode: TextEdit.NoWrap
                        font.family: "Consolas"
                        text: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                            ? root.packetDetailsModel.hexText
                            : "No packet selected"
                    }
                }
            }
        }
    }
}
