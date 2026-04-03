import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property var flowModel: null
    property int selectedFlowIndex: -1
    property string filterText: ""
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

    signal flowSelected(int flowIndex)
    signal filterTextEdited(string text)
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
            sortColumn: root.sortColumn
            sortAscending: root.sortAscending
            onFlowSelected: function(flowIndex) {
                root.flowSelected(flowIndex)
            }
            onFilterTextEdited: function(text) {
                root.filterTextEdited(text)
            }
            onSortRequested: function(column) {
                root.sortRequested(column)
            }
            onSendFlowToAnalysisRequested: function() {
                root.sendFlowToAnalysisRequested()
            }
        }

        SplitView {
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

                        TabButton {
                            text: "Packets"
                        }

                        TabButton {
                            text: "Stream"
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
    }
}
