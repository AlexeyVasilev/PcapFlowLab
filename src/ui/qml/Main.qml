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

    property string loadedLabel: mainController.currentInputPath.length > 0
        ? mainController.currentInputPath
        : "No file loaded"

    ColumnLayout {
        anchors.fill: parent
        spacing: 12
        anchors.margins: 16

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            TextField {
                id: inputPathField
                Layout.fillWidth: true
                placeholderText: "Enter a .pcap, .pcapng, or index file path"
            }

            Button {
                text: "Open Capture"
                onClicked: mainController.openCaptureFile(inputPathField.text)
            }

            Button {
                text: "Open Index"
                onClicked: mainController.openIndexFile(inputPathField.text)
            }
        }

        Label {
            Layout.fillWidth: true
            text: loadedLabel
            elide: Text.ElideMiddle
            color: "#475569"
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

            FlowTable {
                SplitView.preferredWidth: 520
                Layout.fillHeight: true
                flowCount: mainController.flowCount
            }

            SplitView {
                orientation: Qt.Vertical
                Layout.fillWidth: true
                Layout.fillHeight: true

                PacketList {
                    SplitView.preferredHeight: 240
                }

                PacketDetailsPane {
                    Layout.fillHeight: true
                }
            }
        }
    }
}

