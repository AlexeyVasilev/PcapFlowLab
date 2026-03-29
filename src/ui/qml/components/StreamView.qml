import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var streamModel: null
    property var selectedStreamItemIndex: 0
    readonly property string forwardDirection: "A\u2192B"
    readonly property string reverseDirection: "B\u2192A"

    signal streamItemSelected(var streamItemIndex)

    function isForward(directionText) {
        return directionText === root.forwardDirection
    }

    function isSelected(streamItemIndex) {
        return streamItemIndex === root.selectedStreamItemIndex
    }

    function bubbleColor(directionText, selected) {
        if (selected) {
            return isForward(directionText) ? "#dcecff" : "#dcf4e4"
        }
        return isForward(directionText) ? "#eef6ff" : "#eefaf2"
    }

    function bubbleBorderColor(directionText, selected) {
        if (selected) {
            return isForward(directionText) ? "#7ca9de" : "#79b38a"
        }
        return isForward(directionText) ? "#c8dbf2" : "#c9e7d1"
    }

    function bubbleTextColor(directionText) {
        return isForward(directionText) ? "#1f4b7a" : "#24563c"
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
            text: "Stream"
            font.pixelSize: 18
            font.bold: true
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: "#e2e8f0"
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: "#f8fafc"
            border.color: "#e2e8f0"
            radius: 6

            ListView {
                id: streamListView
                anchors.fill: parent
                anchors.margins: 8
                clip: true
                spacing: 8
                model: root.streamModel

                delegate: Item {
                    required property int index
                    required property var streamItemIndex
                    required property string directionText
                    required property string label
                    required property int byteCount
                    required property int packetCount

                    width: streamListView.width
                    height: bubble.implicitHeight

                    readonly property bool selected: root.isSelected(streamItemIndex)

                    RowLayout {
                        anchors.fill: parent
                        spacing: 0

                        Item {
                            Layout.fillWidth: !root.isForward(directionText)
                            implicitWidth: 0
                        }

                        Rectangle {
                            id: bubble
                            Layout.preferredWidth: Math.min(streamListView.width * 0.78, 320)
                            implicitHeight: contentColumn.implicitHeight + 18
                            radius: 10
                            color: root.bubbleColor(directionText, selected)
                            border.color: root.bubbleBorderColor(directionText, selected)
                            border.width: selected ? 2 : 1

                            ColumnLayout {
                                id: contentColumn
                                anchors.fill: parent
                                anchors.margins: 9
                                spacing: 4

                                RowLayout {
                                    Layout.fillWidth: true

                                    Label {
                                        text: directionText
                                        color: root.bubbleTextColor(directionText)
                                        font.family: "Consolas"
                                    }

                                    Item {
                                        Layout.fillWidth: true
                                    }

                                    Label {
                                        text: "#" + streamItemIndex
                                        color: "#64748b"
                                        font.family: "Consolas"
                                    }
                                }

                                Label {
                                    Layout.fillWidth: true
                                    text: label
                                    font.bold: true
                                    color: "#0f172a"
                                    elide: Text.ElideRight
                                }

                                Label {
                                    Layout.fillWidth: true
                                    text: byteCount + " bytes" + (packetCount > 1 ? " • " + packetCount + " packets" : " • 1 packet")
                                    color: "#475569"
                                }
                            }

                            TapHandler {
                                onTapped: root.streamItemSelected(streamItemIndex)
                            }
                        }

                        Item {
                            Layout.fillWidth: root.isForward(directionText)
                            implicitWidth: 0
                        }
                    }
                }
            }

            Label {
                anchors.centerIn: parent
                visible: streamListView.count === 0
                color: "#64748b"
                text: "No payload-bearing stream items for selected flow"
            }
        }
    }
}
