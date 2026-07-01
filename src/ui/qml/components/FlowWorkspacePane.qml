import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property var flowModel: null
    property int selectedFlowIndex: -1
    property bool unrecognizedPacketsSelected: false
    property int unrecognizedPacketCount: 0
    property bool sourceCaptureAvailable: true
    property string filterText: ""
    property string wiresharkFilterText: ""
    property bool wiresharkFilterVisible: false
    property int sortColumn: 0
    property bool sortAscending: true
    property var packetModel: null
    property bool packetsLoading: false
    property bool packetsPartiallyLoaded: false
    property var loadedPacketRowCount: 0
    property var totalPacketRowCount: 0
    property bool canLoadMorePackets: false
    property var streamModel: null
    property bool streamLoading: false
    property bool streamPartiallyLoaded: false
    property var loadedStreamItemCount: 0
    property var totalStreamItemCount: 0
    property var streamPacketWindowCount: 0
    property bool streamPacketWindowPartial: false
    property bool canLoadMoreStreamItems: false
    property var packetDetailsModel: null
    property var selectedPacketIndex: 0
    property var selectedStreamItemIndex: 0
    readonly property bool selectedFlowWorkspaceLoading: root.selectedFlowIndex >= 0 && (root.packetsLoading || root.streamLoading)
    readonly property bool packetsTabSelected: flowDetailTabs.currentIndex === 0

    function lowerToolbarStatusColor() {
        if (!root.packetsTabSelected && !root.sourceCaptureAvailable && root.selectedFlowIndex >= 0) {
            return "#8a6a12"
        }

        return "#6b7280"
    }

    function lowerToolbarStatusText() {
        if (root.packetsTabSelected) {
            if (root.packetsLoading) {
                return "Loading packet list..."
            }
            if (root.totalPacketRowCount > 0) {
                return root.packetsPartiallyLoaded
                    ? "Showing %1 of %2 packets".arg(root.loadedPacketRowCount).arg(root.totalPacketRowCount)
                    : "Showing all %1 packets".arg(root.totalPacketRowCount)
            }
            return root.unrecognizedPacketsSelected
                ? "Select the unrecognized packets list to inspect packets"
                : "Select a flow to inspect packets"
        }

        if (!root.sourceCaptureAvailable && root.selectedFlowIndex >= 0) {
            return "Source capture unavailable. Reattach the original capture file to inspect stream items."
        }
        if (root.streamLoading) {
            return "Building stream view..."
        }
        if (root.streamPartiallyLoaded) {
            return root.totalStreamItemCount > 0
                ? "Showing %1 of %2 stream items".arg(root.loadedStreamItemCount).arg(root.totalStreamItemCount)
                : "Showing first %1 stream items".arg(root.loadedStreamItemCount)
        }
        if (root.totalStreamItemCount > 0 || root.loadedStreamItemCount > 0) {
            let text = "Showing all %1 stream items".arg(root.totalStreamItemCount > 0 ? root.totalStreamItemCount : root.loadedStreamItemCount)
            if (root.streamPacketWindowPartial && !root.streamLoading) {
                text += " Built from the first %1 packets.".arg(root.streamPacketWindowCount)
            } else if (root.canLoadMoreStreamItems && !root.streamLoading) {
                text += " Load more packets to extend the stream view."
            }
            return text
        }
        return "Select a flow to inspect stream items"
    }

    signal flowSelected(int flowIndex)
    signal unrecognizedPacketsRequested()
    signal filterTextEdited(string text)
    signal copyWiresharkFilterRequested()
    signal sortRequested(int column)
    signal sendFlowToAnalysisRequested()
    signal packetSelected(var packetIndex)
    signal loadMorePacketsRequested()
    signal streamItemSelected(var streamItemIndex)
    signal loadMoreStreamItemsRequested()
    signal flowDetailsTabChanged(int index)

    onUnrecognizedPacketsSelectedChanged: {
        if (unrecognizedPacketsSelected && flowDetailTabs.currentIndex !== 0) {
            flowDetailTabs.currentIndex = 0
            root.flowDetailsTabChanged(0)
        }
    }

    SplitView {
        anchors.fill: parent
        orientation: Qt.Vertical

        FlowTable {
            SplitView.fillWidth: true
            SplitView.fillHeight: true
            SplitView.preferredHeight: 430
            flowModel: root.flowModel
            selectedFlowIndex: root.selectedFlowIndex
            unrecognizedPacketsSelected: root.unrecognizedPacketsSelected
            unrecognizedPacketCount: root.unrecognizedPacketCount
            filterText: root.filterText
            wiresharkFilterText: root.wiresharkFilterText
            wiresharkFilterVisible: root.wiresharkFilterVisible
            sortColumn: root.sortColumn
            sortAscending: root.sortAscending
            onFlowSelected: function(flowIndex) {
                root.flowSelected(flowIndex)
            }
            onFilterTextEdited: function(text) {
                root.filterTextEdited(text)
            }
            onCopyWiresharkFilterRequested: function() {
                root.copyWiresharkFilterRequested()
            }
            onSortRequested: function(column) {
                root.sortRequested(column)
            }
            onSendFlowToAnalysisRequested: function() {
                root.sendFlowToAnalysisRequested()
            }
            onUnrecognizedPacketsRequested: function() {
                root.unrecognizedPacketsRequested()
            }
        }

        SplitView {
            id: lowerWorkspaceSplit
            SplitView.fillWidth: true
            SplitView.fillHeight: true
            SplitView.preferredHeight: 300

            Item {
                SplitView.fillWidth: true
                SplitView.fillHeight: true
                SplitView.preferredWidth: 460

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 4

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 8

                        TabBar {
                            id: flowDetailTabs
                            Layout.preferredWidth: implicitWidth
                            onCurrentIndexChanged: root.flowDetailsTabChanged(currentIndex)
                            spacing: 4

                            onVisibleChanged: {
                                if (visible && root.unrecognizedPacketsSelected && currentIndex !== 0) {
                                    currentIndex = 0
                                    root.flowDetailsTabChanged(0)
                                }
                            }

                            background: Rectangle {
                                color: "transparent"
                            }

                            TabButton {
                                text: "Packets"
                                implicitHeight: 28
                                implicitWidth: 108

                                contentItem: Label {
                                    text: parent.text
                                    horizontalAlignment: Text.AlignHCenter
                                    verticalAlignment: Text.AlignVCenter
                                    font.pixelSize: 12
                                    font.bold: parent.checked
                                    color: parent.checked ? "#0f172a" : "#64748b"
                                }

                                background: Rectangle {
                                    radius: 6
                                    color: parent.checked
                                        ? "#ffffff"
                                        : parent.hovered
                                            ? "#f8fafc"
                                            : "#f1f5f9"
                                    border.color: parent.checked ? "#cbd5e1" : "#e2e8f0"
                                }
                            }

                            TabButton {
                                text: "Stream"
                                implicitHeight: 28
                                implicitWidth: 108
                                enabled: !root.unrecognizedPacketsSelected

                                contentItem: Label {
                                    text: parent.text
                                    horizontalAlignment: Text.AlignHCenter
                                    verticalAlignment: Text.AlignVCenter
                                    font.pixelSize: 12
                                    font.bold: parent.checked
                                    color: parent.checked ? "#0f172a" : "#64748b"
                                }

                                background: Rectangle {
                                    radius: 6
                                    color: parent.checked
                                        ? "#ffffff"
                                        : parent.hovered
                                            ? "#f8fafc"
                                            : "#f1f5f9"
                                    border.color: parent.checked ? "#cbd5e1" : "#e2e8f0"
                                }
                            }
                        }

                        Label {
                            Layout.fillWidth: true
                            text: root.lowerToolbarStatusText()
                            color: root.lowerToolbarStatusColor()
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            font.pixelSize: 12
                        }

                        Button {
                            text: "Load more"
                            visible: root.packetsTabSelected ? root.canLoadMorePackets : root.canLoadMoreStreamItems
                            enabled: root.packetsTabSelected
                                ? (root.canLoadMorePackets && !root.packetsLoading)
                                : (root.canLoadMoreStreamItems && !root.streamLoading)
                            onClicked: {
                                if (root.packetsTabSelected) {
                                    root.loadMorePacketsRequested()
                                } else {
                                    root.loadMoreStreamItemsRequested()
                                }
                            }
                        }
                    }

                    StackLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        currentIndex: flowDetailTabs.currentIndex

                        PacketList {
                            titleText: root.unrecognizedPacketsSelected ? "Unrecognized Packets" : "Packets"
                            emptyText: root.unrecognizedPacketsSelected
                                ? "Select the unrecognized packets list to inspect packets"
                                : "Select a flow to inspect packets"
                            packetModel: root.packetModel
                            selectedPacketIndex: root.selectedPacketIndex
                            packetsLoading: root.packetsLoading
                            packetsPartiallyLoaded: root.packetsPartiallyLoaded
                            loadedPacketRowCount: root.loadedPacketRowCount
                            totalPacketRowCount: root.totalPacketRowCount
                            canLoadMorePackets: root.canLoadMorePackets
                            showToolbar: false
                            onPacketSelected: function(packetIndex) {
                                root.packetSelected(packetIndex)
                            }
                            onLoadMoreRequested: function() {
                                root.loadMorePacketsRequested()
                            }
                        }

                        StreamView {
                            flowSelected: root.selectedFlowIndex >= 0 && !root.unrecognizedPacketsSelected
                            sourceCaptureAvailable: root.sourceCaptureAvailable
                            streamModel: root.streamModel
                            selectedStreamItemIndex: root.selectedStreamItemIndex
                            streamLoading: root.streamLoading
                            streamPartiallyLoaded: root.streamPartiallyLoaded
                            loadedStreamItemCount: root.loadedStreamItemCount
                            totalStreamItemCount: root.totalStreamItemCount
                            streamPacketWindowCount: root.streamPacketWindowCount
                            streamPacketWindowPartial: root.streamPacketWindowPartial
                            canLoadMoreStreamItems: root.canLoadMoreStreamItems
                            showToolbar: false
                            onStreamItemSelected: function(streamItemIndex) {
                                root.streamItemSelected(streamItemIndex)
                            }
                            onLoadMoreRequested: function() {
                                root.loadMoreStreamItemsRequested()
                            }
                        }
                    }
                }
            }

            PacketDetailsPane {
                SplitView.fillWidth: true
                SplitView.fillHeight: true
                SplitView.preferredWidth: 720
                packetDetailsModel: root.packetDetailsModel
            }
        }

        Rectangle {
            anchors.horizontalCenter: lowerWorkspaceSplit.horizontalCenter
            anchors.top: lowerWorkspaceSplit.top
            anchors.topMargin: 10
            visible: root.selectedFlowWorkspaceLoading
            color: "#ffffff"
            border.color: "#cbd5e1"
            radius: 8
            z: 2
            implicitWidth: loadingColumn.implicitWidth + 20
            implicitHeight: loadingColumn.implicitHeight + 14

            ColumnLayout {
                id: loadingColumn
                anchors.centerIn: parent
                spacing: 1

                Label {
                    text: "Loading selected flow..."
                    font.pixelSize: 13
                    font.bold: true
                    color: "#0f172a"
                }

                Label {
                    text: "Preparing packets, stream, and details..."
                    font.pixelSize: 12
                    color: "#64748b"
                }
            }
        }
    }
}
