import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property var flowModel: null
    property int selectedFlowIndex: -1
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

    signal flowSelected(int flowIndex)
    signal filterTextEdited(string text)
    signal copyWiresharkFilterRequested()
    signal sortRequested(int column)
    signal sendFlowToAnalysisRequested()
    signal packetSelected(var packetIndex)
    signal loadMorePacketsRequested()
    signal streamItemSelected(var streamItemIndex)
    signal loadMoreStreamItemsRequested()
    signal flowDetailsTabChanged(int index)

    SplitView {
        anchors.fill: parent
        orientation: Qt.Vertical

        FlowTable {
            SplitView.fillWidth: true
            SplitView.fillHeight: true
            SplitView.preferredHeight: 430
            flowModel: root.flowModel
            selectedFlowIndex: root.selectedFlowIndex
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
                    spacing: 8

                    TabBar {
                        id: flowDetailTabs
                        Layout.fillWidth: true
                        onCurrentIndexChanged: root.flowDetailsTabChanged(currentIndex)
                        spacing: 6

                        background: Rectangle {
                            color: "transparent"
                        }

                        TabButton {
                            text: "Packets"
                            implicitHeight: 34

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
                            implicitHeight: 34

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

                    StackLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        currentIndex: flowDetailTabs.currentIndex

                        PacketList {
                            packetModel: root.packetModel
                            selectedPacketIndex: root.selectedPacketIndex
                            packetsLoading: root.packetsLoading
                            packetsPartiallyLoaded: root.packetsPartiallyLoaded
                            loadedPacketRowCount: root.loadedPacketRowCount
                            totalPacketRowCount: root.totalPacketRowCount
                            canLoadMorePackets: root.canLoadMorePackets
                            onPacketSelected: function(packetIndex) {
                                root.packetSelected(packetIndex)
                            }
                            onLoadMoreRequested: function() {
                                root.loadMorePacketsRequested()
                            }
                        }

                        StreamView {
                            streamModel: root.streamModel
                            selectedStreamItemIndex: root.selectedStreamItemIndex
                            streamLoading: root.streamLoading
                            streamPartiallyLoaded: root.streamPartiallyLoaded
                            loadedStreamItemCount: root.loadedStreamItemCount
                            totalStreamItemCount: root.totalStreamItemCount
                            streamPacketWindowCount: root.streamPacketWindowCount
                            streamPacketWindowPartial: root.streamPacketWindowPartial
                            canLoadMoreStreamItems: root.canLoadMoreStreamItems
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
