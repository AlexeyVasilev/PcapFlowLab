import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var streamModel: null
    property bool flowSelected: false
    property bool sourceCaptureAvailable: true
    property var selectedStreamItemIndex: 0
    property bool streamLoading: false
    property bool streamPartiallyLoaded: false
    property var loadedStreamItemCount: 0
    property var totalStreamItemCount: 0
    property int streamPacketWindowCount: 0
    property bool streamPacketWindowPartial: false
    property bool canLoadMoreStreamItems: false
    property bool showToolbar: true
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
            return isForward(directionText) ? "#dcf4e4" : "#dcecff"
        }

        return isForward(directionText) ? "#eefaf2" : "#eef6ff"
    }

    function bubbleBorderColor(directionText, selected) {
        if (selected) {
            return isForward(directionText) ? "#79b38a" : "#7ca9de"
        }

        return isForward(directionText) ? "#c9e7d1" : "#c8dbf2"
    }

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 6

        RowLayout {
            Layout.fillWidth: true
            visible: root.showToolbar && ((!root.sourceCaptureAvailable && root.flowSelected)
                || root.streamLoading
                || root.loadedStreamItemCount > 0
                || root.totalStreamItemCount > 0
                || root.streamPacketWindowPartial)
            spacing: 6

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2

                Label {
                    Layout.fillWidth: true
                    color: !root.sourceCaptureAvailable && root.flowSelected ? "#8a6a12" : "#6b7280"
                    text: !root.sourceCaptureAvailable && root.flowSelected
                        ? "Source capture unavailable"
                        : root.streamLoading
                        ? "Building stream view..."
                        : root.streamPartiallyLoaded
                            ? (root.totalStreamItemCount > 0
                                ? "Showing %1 of %2 stream items".arg(root.loadedStreamItemCount).arg(root.totalStreamItemCount)
                                : "Showing first %1 stream items".arg(root.loadedStreamItemCount))
                            : "Showing all %1 stream items".arg(root.totalStreamItemCount > 0 ? root.totalStreamItemCount : root.loadedStreamItemCount)
                }

                Label {
                    Layout.fillWidth: true
                    visible: root.sourceCaptureAvailable && root.streamPacketWindowPartial && !root.streamLoading
                    color: "#8a6a12"
                    text: "Built from the first %1 packets".arg(root.streamPacketWindowCount)
                }

                Label {
                    Layout.fillWidth: true
                    visible: (!root.sourceCaptureAvailable && root.flowSelected) || (root.canLoadMoreStreamItems && !root.streamLoading)
                    color: !root.sourceCaptureAvailable && root.flowSelected ? "#92400e" : "#6b7280"
                    text: !root.sourceCaptureAvailable && root.flowSelected
                        ? "Reattach the original capture file to inspect stream items."
                        : "Load more packets to extend the stream view"
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
                anchors.margins: 6
                clip: true
                spacing: 6
                model: root.streamModel

                ScrollBar.vertical: ScrollBar {
                    policy: streamListView.contentHeight > streamListView.height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
                }

                delegate: Item {
                    required property int index
                    required property var streamItemIndex
                    required property string directionText
                    required property string label
                    required property int byteCount
                    required property int packetCount
                    required property string sourcePacketsText
                    required property bool hasConstrictedContribution

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
                        implicitHeight: metadataContainer.y + metadataContainer.implicitHeight + 8
                        radius: 9
                        color: root.bubbleColor(directionText, selected)
                        border.color: root.bubbleBorderColor(directionText, selected)
                        border.width: selected ? 2 : 1

                        RowLayout {
                            id: topRow
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: 8
                            spacing: 7

                            Item {
                                Layout.fillWidth: true
                                implicitHeight: labelTextItem.implicitHeight

                                Label {
                                    id: labelTextItem
                                    anchors.fill: parent
                                    text: label
                                    font.bold: true
                                    font.pixelSize: 12
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
                            anchors.leftMargin: 8
                            anchors.rightMargin: 8
                            anchors.topMargin: 3
                            implicitHeight: Math.max(metadataTextItem.implicitHeight, constrictedBadge.visible ? constrictedBadge.implicitHeight : 0)

                            Label {
                                id: metadataTextItem
                                anchors.left: parent.left
                                anchors.right: constrictedBadge.visible ? constrictedBadge.left : parent.right
                                anchors.rightMargin: constrictedBadge.visible ? 6 : 0
                                anchors.verticalCenter: parent.verticalCenter
                                text: metadataText
                                color: "#475569"
                                elide: Text.ElideRight
                                verticalAlignment: Text.AlignVCenter
                                font.pixelSize: 11
                            }

                            MouseArea {
                                id: metadataHoverArea
                                anchors.fill: parent
                                acceptedButtons: Qt.NoButton
                                hoverEnabled: true
                            }

                            ToolTip.visible: metadataHoverArea.containsMouse && metadataTextItem.truncated
                            ToolTip.text: byteCount + " bytes | " + (sourcePacketsText.length > 0 ? sourcePacketsText : (packetCount > 1 ? packetCount + " packets" : "1 packet"))
                            
                            Rectangle {
                                id: constrictedBadge
                                visible: hasConstrictedContribution
                                anchors.right: parent.right
                                anchors.bottom: parent.bottom
                                radius: 8
                                color: selected ? "#fff3cd" : "#fff7dd"
                                border.color: selected ? "#e0be63" : "#e7ca78"
                                border.width: 1
                                implicitWidth: constrictedBadgeText.implicitWidth + 10
                                implicitHeight: constrictedBadgeText.implicitHeight + 4

                                Label {
                                    id: constrictedBadgeText
                                    anchors.centerIn: parent
                                    text: "Constricted"
                                    color: "#8a6a12"
                                    font.pixelSize: 10
                                    font.bold: true
                                }
                            }
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
                text: !root.flowSelected
                    ? "Select a flow to inspect stream items"
                    : !root.sourceCaptureAvailable
                        ? "Stream reconstruction requires the original source capture"
                        : "No stream items available for this flow"
            }
        }
    }
}
