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

            ComboBox {
                model: ["Fast", "Deep"]
                currentIndex: mainController.captureOpenMode
                onActivated: function(index) {
                    mainController.captureOpenMode = index
                }
                Layout.preferredWidth: 96
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

        TabBar {
            id: mainTabs
            Layout.fillWidth: true
            currentIndex: mainController.currentTabIndex
            onCurrentIndexChanged: mainController.currentTabIndex = currentIndex

            TabButton {
                text: "Flows"
            }

            TabButton {
                text: "Statistics"
            }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: mainController.currentTabIndex

            FlowWorkspacePane {
                flowModel: mainController.flowModel
                selectedFlowIndex: mainController.selectedFlowIndex
                filterText: mainController.flowFilterText
                sortColumn: mainController.flowSortColumn
                sortAscending: mainController.flowSortAscending
                packetModel: mainController.packetModel
                selectedPacketIndex: mainController.selectedPacketIndex
                packetDetailsModel: mainController.packetDetailsModel
                onFlowSelected: function(flowIndex) {
                    mainController.selectedFlowIndex = flowIndex
                }
                onFilterTextEdited: function(text) {
                    mainController.flowFilterText = text
                }
                onSortRequested: function(column) {
                    mainController.sortFlows(column)
                }
                onPacketSelected: function(packetIndex) {
                    mainController.selectedPacketIndex = packetIndex
                }
            }

            StatisticsPane {
                hasCapture: mainController.hasCapture
                packetCount: mainController.packetCount
                flowCount: mainController.flowCount
                totalBytes: mainController.totalBytes
                tcpFlowCount: mainController.tcpFlowCount
                tcpPacketCount: mainController.tcpPacketCount
                tcpTotalBytes: mainController.tcpTotalBytes
                udpFlowCount: mainController.udpFlowCount
                udpPacketCount: mainController.udpPacketCount
                udpTotalBytes: mainController.udpTotalBytes
                otherFlowCount: mainController.otherFlowCount
                otherPacketCount: mainController.otherPacketCount
                otherTotalBytes: mainController.otherTotalBytes
                ipv4FlowCount: mainController.ipv4FlowCount
                ipv6FlowCount: mainController.ipv6FlowCount
                topEndpointsModel: mainController.topEndpointsModel
                topPortsModel: mainController.topPortsModel
                onEndpointActivated: function(endpointText) {
                    mainController.drillDownToEndpoint(endpointText)
                }
                onPortActivated: function(port) {
                    mainController.drillDownToPort(port)
                }
            }
        }
    }
}

