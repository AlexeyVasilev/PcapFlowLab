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
    property var streamModel: null
    property var packetDetailsModel: null
    property var selectedPacketIndex: 0
    property var selectedStreamItemIndex: 0

    signal flowSelected(int flowIndex)
    signal filterTextEdited(string text)
    signal sortRequested(int column)
    signal packetSelected(var packetIndex)
    signal streamItemSelected(var streamItemIndex)

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
                            onPacketSelected: function(packetIndex) {
                                root.packetSelected(packetIndex)
                            }
                        }

                        StreamView {
                            streamModel: root.streamModel
                            selectedStreamItemIndex: root.selectedStreamItemIndex
                            onStreamItemSelected: function(streamItemIndex) {
                                root.streamItemSelected(streamItemIndex)
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
