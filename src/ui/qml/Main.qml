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

            Button {
                text: "Save Index"
                enabled: mainController.canSaveIndex
                onClicked: mainController.browseSaveAnalysisIndex()
            }

            Button {
                text: "Export Flow"
                enabled: mainController.canExportSelectedFlow
                onClicked: mainController.browseExportSelectedFlow()
            }

            TextField {
                Layout.fillWidth: true
                readOnly: true
                text: mainController.currentInputPath.length > 0
                    ? mainController.currentInputPath
                    : "No file loaded"
            }
        }

        Rectangle {
            Layout.fillWidth: true
            visible: mainController.openedFromIndex && !mainController.hasSourceCapture
            color: "#fef3c7"
            border.color: "#f59e0b"
            radius: 6
            implicitHeight: warningLayout.implicitHeight + 16

            RowLayout {
                id: warningLayout
                anchors.fill: parent
                anchors.margins: 8
                spacing: 12

                Label {
                    Layout.fillWidth: true
                    text: "Opened from analysis index. Raw packet data is unavailable until the original capture is attached."
                    color: "#92400e"
                    wrapMode: Text.WordWrap
                }

                Button {
                    text: "Attach Source Capture"
                    enabled: mainController.canAttachSourceCapture
                    onClicked: mainController.browseAttachSourceCapture()
                }
            }
        }

        Label {
            Layout.fillWidth: true
            visible: mainController.openErrorText.length > 0
            text: mainController.openErrorText
            color: "#b91c1c"
            wrapMode: Text.WordWrap
        }

        Label {
            Layout.fillWidth: true
            visible: mainController.statusText.length > 0
            text: mainController.statusText
            color: mainController.statusIsError ? "#b91c1c" : "#1f2937"
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

            TabButton {
                text: "Settings"
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

            SettingsPane {
                httpUsePathAsServiceHint: mainController.httpUsePathAsServiceHint
                onHttpUsePathAsServiceHintChangedByUser: function(enabled) {
                    mainController.httpUsePathAsServiceHint = enabled
                }
            }
        }
    }
}
