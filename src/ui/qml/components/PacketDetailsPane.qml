import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var packetDetailsModel: null

    component TextPane: Rectangle {
        property string viewText: ""
        property bool monospace: false

        color: "#f8fafc"
        border.color: "#e2e8f0"
        radius: 6

        ScrollView {
            anchors.fill: parent
            anchors.margins: 1
            clip: true

            TextArea {
                readOnly: true
                wrapMode: monospace ? TextEdit.NoWrap : TextEdit.Wrap
                font.family: monospace ? "Consolas" : ""
                text: viewText
            }
        }
    }

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
            id: topTabs
            Layout.fillWidth: true

            TabButton {
                text: "Summary"
            }

            TabButton {
                text: "Raw"
            }

            TabButton {
                text: "Protocol"
            }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: topTabs.currentIndex

            TextPane {
                viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                    ? root.packetDetailsModel.summaryText
                    : "No packet selected"
            }

            Rectangle {
                color: "transparent"

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 10

                    TabBar {
                        id: rawTabs
                        Layout.fillWidth: true

                        TabButton {
                            text: "Hex"
                        }

                        TabButton {
                            text: "Payload"
                        }
                    }

                    StackLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        currentIndex: rawTabs.currentIndex

                        TextPane {
                            monospace: true
                            viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                                ? root.packetDetailsModel.hexText
                                : "No packet selected"
                        }

                        TextPane {
                            monospace: true
                            viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                                ? root.packetDetailsModel.payloadText
                                : "No packet selected"
                        }
                    }
                }
            }

            TextPane {
                viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                    ? root.packetDetailsModel.protocolText
                    : "No packet selected"
            }
        }
    }
}
