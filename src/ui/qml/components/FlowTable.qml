import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var flowModel: null
    property int selectedFlowIndex: -1

    signal flowSelected(int flowIndex)

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label {
            text: "Flows"
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
                text: "Index"
                font.bold: true
                Layout.preferredWidth: 52
            }

            Label {
                text: "Family"
                font.bold: true
                Layout.preferredWidth: 60
            }

            Label {
                text: "Protocol"
                font.bold: true
                Layout.preferredWidth: 72
            }

            Label {
                text: "Endpoint A"
                font.bold: true
                Layout.fillWidth: true
                Layout.preferredWidth: 180
            }

            Label {
                text: "Endpoint B"
                font.bold: true
                Layout.fillWidth: true
                Layout.preferredWidth: 180
            }

            Label {
                text: "Packets"
                font.bold: true
                Layout.preferredWidth: 72
            }

            Label {
                text: "Bytes"
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
                id: flowListView

                anchors.fill: parent
                anchors.margins: 1
                clip: true
                model: root.flowModel

                delegate: Rectangle {
                    required property int flowIndex
                    required property string family
                    required property string protocol
                    required property string endpointA
                    required property string endpointB
                    required property string packets
                    required property string bytes

                    width: flowListView.width
                    height: 40
                    color: root.selectedFlowIndex === flowIndex
                        ? "#dbeafe"
                        : (index % 2 === 0 ? "#ffffff" : "#f8fafc")

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 10
                        anchors.rightMargin: 10
                        spacing: 12

                        Label {
                            text: flowIndex
                            Layout.preferredWidth: 52
                        }

                        Label {
                            text: family
                            Layout.preferredWidth: 60
                        }

                        Label {
                            text: protocol
                            Layout.preferredWidth: 72
                        }

                        Label {
                            text: endpointA
                            Layout.fillWidth: true
                            Layout.preferredWidth: 180
                            elide: Text.ElideMiddle
                        }

                        Label {
                            text: endpointB
                            Layout.fillWidth: true
                            Layout.preferredWidth: 180
                            elide: Text.ElideMiddle
                        }

                        Label {
                            text: packets
                            Layout.preferredWidth: 72
                            horizontalAlignment: Text.AlignRight
                        }

                        Label {
                            text: bytes
                            Layout.preferredWidth: 84
                            horizontalAlignment: Text.AlignRight
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: root.flowSelected(flowIndex)
                    }
                }
            }

            Label {
                anchors.centerIn: parent
                visible: flowListView.count === 0
                color: "#64748b"
                text: "No flows loaded"
            }
        }
    }
}
