import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import PcapFlowLab

ApplicationWindow {
    id: window

    width: 1360
    height: 860
    visible: true
    title: "Pcap Flow Lab"

    ColumnLayout {
        anchors.fill: parent
        spacing: 12
        anchors.margins: 16

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Button {
                text: "Open Capture"
                onClicked: mainController.browseCaptureFile()
            }

            Button {
                text: "Open Index"
                onClicked: mainController.browseIndexFile()
            }

            TextField {
                Layout.fillWidth: true
                readOnly: true
                text: mainController.currentInputPath.length > 0
                    ? mainController.currentInputPath
                    : "No file loaded"
            }
        }

        Label {
            Layout.fillWidth: true
            visible: mainController.openErrorText.length > 0
            text: mainController.openErrorText
            color: "#b91c1c"
            wrapMode: Text.WordWrap
        }

        SummaryBar {
            Layout.fillWidth: true
            packetCount: mainController.packetCount
            flowCount: mainController.flowCount
            totalBytes: mainController.totalBytes
            hasCapture: mainController.hasCapture
        }

        SplitView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            orientation: Qt.Vertical

            FlowTable {
                SplitView.fillWidth: true
                SplitView.fillHeight: true
                SplitView.preferredHeight: 430
                flowModel: mainController.flowModel
                selectedFlowIndex: mainController.selectedFlowIndex
                filterText: mainController.flowFilterText
                sortColumn: mainController.flowSortColumn
                sortAscending: mainController.flowSortAscending
                onFlowSelected: function(flowIndex) {
                    mainController.selectedFlowIndex = flowIndex
                }
                onFilterTextEdited: function(text) {
                    mainController.flowFilterText = text
                }
                onSortRequested: function(column) {
                    mainController.sortFlows(column)
                }
            }

            SplitView {
                SplitView.fillWidth: true
                SplitView.fillHeight: true
                SplitView.preferredHeight: 300

                PacketList {
                    SplitView.fillWidth: true
                    SplitView.fillHeight: true
                    SplitView.preferredWidth: 420
                    packetModel: mainController.packetModel
                    selectedPacketIndex: mainController.selectedPacketIndex
                    onPacketSelected: function(packetIndex) {
                        mainController.selectedPacketIndex = packetIndex
                    }
                }

                PacketDetailsPane {
                    SplitView.fillWidth: true
                    SplitView.fillHeight: true
                    SplitView.preferredWidth: 720
                    packetDetailsModel: mainController.packetDetailsModel
                }
            }
        }
    }
}
