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

    function compactSourcePacketsText(sourcePacketsText) {
        if (!sourcePacketsText || !sourcePacketsText.startsWith("packets ")) {
            return sourcePacketsText
        }

        const packetRefs = sourcePacketsText.slice(8).split(",")
        if (packetRefs.length <= 3 && sourcePacketsText.length <= 26) {
            return sourcePacketsText
        }

        return "packets " + packetRefs.slice(0, 3).join(",") + "\u2026"
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

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 8

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
            spacing: 6

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2

                Label {
                    Layout.fillWidth: true
                    color: "#6b7280"
                    text: root.streamLoading
                        ? "Building stream view..."
                        : root.streamPartiallyLoaded
                            ? (root.totalStreamItemCount > 0
                                ? "Showing %1 of %2 stream items".arg(root.loadedStreamItemCount).arg(root.totalStreamItemCount)
                                : "Showing first %1 stream items".arg(root.loadedStreamItemCount))
                            : "Showing all %1 stream items".arg(root.totalStreamItemCount > 0 ? root.totalStreamItemCount : root.loadedStreamItemCount)
                }

                Label {
                    Layout.fillWidth: true
                    visible: root.streamPacketWindowPartial && !root.streamLoading
                    color: "#8a6a12"
                    text: "Built from the first %1 packets".arg(root.streamPacketWindowCount)
                }

                Label {
                    Layout.fillWidth: true
                    visible: root.canLoadMoreStreamItems && !root.streamLoading
                    color: "#6b7280"
                    text: "Load more packets to extend the stream view"
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
                    required property string sourcePacketsText

                    readonly property bool selected: root.isSelected(streamItemIndex)
                    readonly property bool forward: root.isForward(directionText)
                    readonly property string metadataText: byteCount + " bytes | " + (sourcePacketsText.length > 0 ? root.compactSourcePacketsText(sourcePacketsText) : (packetCount > 1 ? packetCount + " packets" : "1 packet"))
                    readonly property string headerMetaText: "#" + streamItemIndex + " \u00b7 " + directionText

                    width: streamListView.width
                    height: bubble.implicitHeight

                    Rectangle {
                        id: bubble
                        x: forward ? 0 : parent.width - width
                        width: Math.min(streamListView.width * 0.84, 420)
                        implicitHeight: metadataContainer.y + metadataContainer.implicitHeight + 10
                        radius: 10
                        color: root.bubbleColor(directionText, selected)
                        border.color: root.bubbleBorderColor(directionText, selected)
                        border.width: selected ? 2 : 1

                        RowLayout {
                            id: topRow
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: 9
                            spacing: 8

                            Item {
                                Layout.fillWidth: true
                                implicitHeight: labelTextItem.implicitHeight

                                Label {
                                    id: labelTextItem
                                    anchors.fill: parent
                                    text: label
                                    font.bold: true
                                    font.pixelSize: 13
                                    color: "#0f172a"
                                    elide: Text.ElideRight
                                    verticalAlignment: Text.AlignVCenter
                                }

                                MouseArea {
                                    id: labelHoverArea
                                    anchors.fill: parent
                                    acceptedButtons: Qt.NoButton
                                    hoverEnabled: true
                                }

                                ToolTip.visible: labelHoverArea.containsMouse && labelTextItem.truncated
                                ToolTip.text: labelTextItem.text
                            }

                            Text {
                                text: headerMetaText
                                color: selected ? "#66758a" : "#7b8794"
                                font.family: "Consolas"
                                font.pixelSize: 11
                            }
                        }

                        Item {
                            id: metadataContainer
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: topRow.bottom
                            anchors.leftMargin: 9
                            anchors.rightMargin: 9
                            anchors.topMargin: 4
                            implicitHeight: metadataTextItem.implicitHeight

                            Label {
                                id: metadataTextItem
                                anchors.fill: parent
                                text: metadataText
                                color: "#475569"
                                elide: Text.ElideRight
                                verticalAlignment: Text.AlignVCenter
                                font.pixelSize: 12
                            }

                            MouseArea {
                                id: metadataHoverArea
                                anchors.fill: parent
                                acceptedButtons: Qt.NoButton
                                hoverEnabled: true
                            }

                            ToolTip.visible: metadataHoverArea.containsMouse && metadataTextItem.truncated
                            ToolTip.text: byteCount + " bytes | " + (sourcePacketsText.length > 0 ? sourcePacketsText : (packetCount > 1 ? packetCount + " packets" : "1 packet"))
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
                text: "No stream items available for this flow"
            }
        }
    }
}
