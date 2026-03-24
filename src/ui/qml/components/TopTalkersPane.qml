import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var topEndpointsModel: null
    property var topPortsModel: null
    property bool hasCapture: false

    signal endpointActivated(string endpointText)
    signal portActivated(int port)

    background: Rectangle {
        color: "#f8fafc"
        border.color: "#d8dee9"
        radius: 8
    }

    RowLayout {
        anchors.fill: parent
        spacing: 12

        Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true

            background: Rectangle {
                color: "#ffffff"
                border.color: "#d8dee9"
                radius: 6
            }

            ColumnLayout {
                anchors.fill: parent
                spacing: 8

                Label {
                    text: "Top Endpoints"
                    font.bold: true
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 12

                    Label {
                        Layout.fillWidth: true
                        text: "Endpoint"
                        font.bold: true
                    }

                    Label {
                        width: 80
                        horizontalAlignment: Text.AlignRight
                        text: "Packets"
                        font.bold: true
                    }

                    Label {
                        width: 100
                        horizontalAlignment: Text.AlignRight
                        text: "Bytes"
                        font.bold: true
                    }
                }

                ListView {
                    id: endpointListView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    interactive: false
                    model: root.topEndpointsModel

                    delegate: Rectangle {
                        required property string itemLabel
                        required property var packets
                        required property var bytes

                        width: endpointListView.width
                        height: 34
                        color: endpointMouseArea.containsMouse ? "#eff6ff" : "transparent"
                        radius: 4

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 6
                            anchors.rightMargin: 6
                            spacing: 12

                            Label {
                                Layout.fillWidth: true
                                text: itemLabel
                                elide: Text.ElideMiddle
                            }

                            Label {
                                width: 80
                                horizontalAlignment: Text.AlignRight
                                text: packets
                            }

                            Label {
                                width: 100
                                horizontalAlignment: Text.AlignRight
                                text: bytes
                            }
                        }

                        MouseArea {
                            id: endpointMouseArea
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.endpointActivated(itemLabel)
                        }
                    }
                }

                Label {
                    visible: root.hasCapture && endpointListView.count === 0
                    text: "No endpoint data"
                    color: "#64748b"
                }
            }
        }

        Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true

            background: Rectangle {
                color: "#ffffff"
                border.color: "#d8dee9"
                radius: 6
            }

            ColumnLayout {
                anchors.fill: parent
                spacing: 8

                Label {
                    text: "Top Ports"
                    font.bold: true
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 12

                    Label {
                        Layout.fillWidth: true
                        text: "Port"
                        font.bold: true
                    }

                    Label {
                        width: 80
                        horizontalAlignment: Text.AlignRight
                        text: "Packets"
                        font.bold: true
                    }

                    Label {
                        width: 100
                        horizontalAlignment: Text.AlignRight
                        text: "Bytes"
                        font.bold: true
                    }
                }

                ListView {
                    id: portListView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    interactive: false
                    model: root.topPortsModel

                    delegate: Rectangle {
                        required property string itemLabel
                        required property var packets
                        required property var bytes

                        width: portListView.width
                        height: 34
                        color: portMouseArea.containsMouse ? "#eff6ff" : "transparent"
                        radius: 4

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 6
                            anchors.rightMargin: 6
                            spacing: 12

                            Label {
                                Layout.fillWidth: true
                                text: itemLabel
                            }

                            Label {
                                width: 80
                                horizontalAlignment: Text.AlignRight
                                text: packets
                            }

                            Label {
                                width: 100
                                horizontalAlignment: Text.AlignRight
                                text: bytes
                            }
                        }

                        MouseArea {
                            id: portMouseArea
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.portActivated(Number(itemLabel))
                        }
                    }
                }

                Label {
                    visible: root.hasCapture && portListView.count === 0
                    text: "No port data"
                    color: "#64748b"
                }
            }
        }
    }
}
