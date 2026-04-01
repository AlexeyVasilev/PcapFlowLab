import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var streamModel: null
    property var selectedStreamItemIndex: 0
    property bool streamLoading: false
    property bool streamPartiallyLoaded: false
    property var loadedStreamItemCount: 0
    property var totalStreamItemCount: 0
    property int streamPacketWindowCount: 0
    property bool streamPacketWindowPartial: false
    property bool canLoadMoreStreamItems: false
    readonly property string forwardDirection: "A\u2192B"
    readonly property string reverseDirection: "B\u2192A"

    signal streamItemSelected(var streamItemIndex)
    signal loadMoreRequested()

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

        RowLayout {
            Layout.fillWidth: true
            visible: root.streamLoading || root.loadedStreamItemCount > 0 || root.totalStreamItemCount > 0 || root.streamPacketWindowPartial
            spacing: 8

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2

                Label {
                    Layout.fillWidth: true
                    color: "#64748b"
                    text: root.streamLoading
                        ? "Loading stream..."
                        : root.streamPartiallyLoaded
                            ? (root.totalStreamItemCount > 0
                                ? "Showing %1 of %2 stream items".arg(root.loadedStreamItemCount).arg(root.totalStreamItemCount)
                                : "Showing first %1 stream items".arg(root.loadedStreamItemCount))
                            : "Showing all %1 stream items".arg(root.totalStreamItemCount > 0 ? root.totalStreamItemCount : root.loadedStreamItemCount)
                }

                Label {
                    Layout.fillWidth: true
                    visible: root.streamPacketWindowPartial && !root.streamLoading
                    color: "#7c5a10"
                    text: "Showing stream for first %1 packets".arg(root.streamPacketWindowCount)
                }

                Label {
                    Layout.fillWidth: true
                    visible: root.canLoadMoreStreamItems && !root.streamLoading
                    color: "#64748b"
                    text: "Load more packets to continue analysis"
                }
            }

            Button {
                text: "Load more"
                visible: root.canLoadMoreStreamItems
                enabled: root.canLoadMoreStreamItems && !root.streamLoading
                onClicked: root.loadMoreRequested()
            }
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

                ScrollBar.vertical: ScrollBar {
                    policy: ScrollBar.AsNeeded
                    visible: streamListView.contentHeight > streamListView.height
                }

                delegate: Item {
                    required property int index
                    required property var streamItemIndex
                    required property string directionText
                    required property string label
                    required property int byteCount
                    required property int packetCount

                    readonly property bool selected: root.isSelected(streamItemIndex)
                    readonly property bool forward: root.isForward(directionText)
                    readonly property string metadataText: byteCount + " bytes | " + (packetCount > 1 ? packetCount + " packets" : "1 packet")

                    width: streamListView.width
                    height: bubble.implicitHeight

                    Rectangle {
                        id: bubble
                        x: forward ? 0 : parent.width - width
                        width: Math.min(streamListView.width * 0.78, 320)
                        implicitHeight: metadataTextItem.y + metadataTextItem.implicitHeight + 9
                        radius: 10
                        color: root.bubbleColor(directionText, selected)
                        border.color: root.bubbleBorderColor(directionText, selected)
                        border.width: selected ? 2 : 1

                        Text {
                            id: directionTextItem
                            x: 9
                            y: 9
                            text: directionText
                            color: root.bubbleTextColor(directionText)
                            font.family: "Consolas"
                        }

                        Text {
                            id: itemIndexText
                            anchors.top: parent.top
                            anchors.topMargin: 9
                            anchors.right: parent.right
                            anchors.rightMargin: 9
                            text: "#" + streamItemIndex
                            color: "#64748b"
                            font.family: "Consolas"
                        }

                        Text {
                            id: labelTextItem
                            x: 9
                            y: directionTextItem.y + directionTextItem.implicitHeight + 4
                            width: parent.width - 18
                            text: label
                            font.bold: true
                            color: "#0f172a"
                            elide: Text.ElideRight
                        }

                        Text {
                            id: metadataTextItem
                            x: 9
                            y: labelTextItem.y + labelTextItem.implicitHeight + 4
                            width: parent.width - 18
                            text: metadataText
                            color: "#475569"
                            elide: Text.ElideRight
                        }

                        TapHandler {
                            onTapped: root.streamItemSelected(streamItemIndex)
                        }
                    }
                }
            }

            Label {
                anchors.centerIn: parent
                visible: !root.streamLoading && streamListView.count === 0
                color: "#64748b"
                text: "No payload-bearing stream items for selected flow"
            }
        }
    }
}
