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
                enabled: !mainController.isOpening
                onClicked: mainController.browseCaptureFile()
            }

            ComboBox {
                enabled: !mainController.isOpening
                model: ["Fast", "Deep"]
                currentIndex: mainController.captureOpenMode
                onActivated: function(index) {
                    mainController.captureOpenMode = index
                }
                Layout.preferredWidth: 96
            }

            Button {
                text: "Open Index"
                enabled: !mainController.isOpening
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

        TextEdit {
            Layout.fillWidth: true
            visible: mainController.openErrorText.length > 0
            readOnly: true
            selectByMouse: true
            selectByKeyboard: true
            cursorVisible: false
            text: mainController.openErrorText
            color: "#b91c1c"
            wrapMode: TextEdit.Wrap
            textFormat: TextEdit.PlainText
            Layout.preferredHeight: contentHeight
        }

        TextEdit {
            Layout.fillWidth: true
            visible: mainController.statusText.length > 0
            readOnly: true
            selectByMouse: true
            selectByKeyboard: true
            cursorVisible: false
            text: mainController.statusText
            color: mainController.statusIsError ? "#b91c1c" : "#1f2937"
            wrapMode: TextEdit.Wrap
            textFormat: TextEdit.PlainText
            Layout.preferredHeight: contentHeight
        }

        Rectangle {
            Layout.fillWidth: true
            visible: mainController.isOpening
            color: "#f8fafc"
            border.color: "#cbd5e1"
            radius: 6
            implicitHeight: openProgressLayout.implicitHeight + 16

            ColumnLayout {
                id: openProgressLayout
                anchors.fill: parent
                anchors.margins: 8
                spacing: 6

                Label {
                    Layout.fillWidth: true
                    text: mainController.openProgressTotalBytes > 0
                        ? "Opening file: %1 packets, %2 / %3 bytes"
                            .arg(mainController.openProgressPackets)
                            .arg(mainController.openProgressBytes)
                            .arg(mainController.openProgressTotalBytes)
                        : "Opening file: %1 packets, %2 bytes"
                            .arg(mainController.openProgressPackets)
                            .arg(mainController.openProgressBytes)
                    color: "#334155"
                    wrapMode: Text.WordWrap
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 8

                    ProgressBar {
                        Layout.fillWidth: true
                        from: 0
                        to: 1
                        value: mainController.openProgressPercent
                        indeterminate: mainController.openProgressTotalBytes === 0
                    }

                    Button {
                        text: "Cancel"
                        enabled: mainController.isOpening
                        onClicked: mainController.cancelOpen()
                    }
                }
            }
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
                packetsLoading: mainController.packetsLoading
                packetsPartiallyLoaded: mainController.packetsPartiallyLoaded
                loadedPacketRowCount: mainController.loadedPacketRowCount
                totalPacketRowCount: mainController.totalPacketRowCount
                canLoadMorePackets: mainController.canLoadMorePackets
                streamModel: mainController.streamModel
                streamLoading: mainController.streamLoading
                streamPartiallyLoaded: mainController.streamPartiallyLoaded
                loadedStreamItemCount: mainController.loadedStreamItemCount
                totalStreamItemCount: mainController.totalStreamItemCount
                canLoadMoreStreamItems: mainController.canLoadMoreStreamItems
                selectedPacketIndex: mainController.selectedPacketIndex
                selectedStreamItemIndex: mainController.selectedStreamItemIndex
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
                onLoadMorePacketsRequested: function() {
                    mainController.loadMorePackets()
                }
                onStreamItemSelected: function(streamItemIndex) {
                    mainController.selectedStreamItemIndex = streamItemIndex
                }
                onLoadMoreStreamItemsRequested: function() {
                    mainController.loadMoreStreamItems()
                }
                onFlowDetailsTabChanged: function(index) {
                    mainController.setFlowDetailsTabIndex(index)
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





