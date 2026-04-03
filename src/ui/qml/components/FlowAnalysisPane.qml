import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property bool analysisAvailable: false
    property string durationText: ""
    property var totalPackets: 0
    property var totalBytes: 0
    property string protocolHint: ""
    property string serviceHint: ""
    property var packetsAToB: 0
    property var packetsBToA: 0
    property var bytesAToB: 0
    property var bytesBToA: 0

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 12

        Label {
            text: "Analysis"
            font.pixelSize: 18
            font.bold: true
        }

        Label {
            visible: !root.analysisAvailable
            text: "Select a flow to view analysis."
            color: "#64748b"
        }

        ColumnLayout {
            visible: root.analysisAvailable
            Layout.fillWidth: true
            spacing: 12

            Frame {
                Layout.fillWidth: true

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 10
                    spacing: 8

                    Label {
                        text: "Overview"
                        font.bold: true
                    }

                    GridLayout {
                        columns: 2
                        columnSpacing: 16
                        rowSpacing: 6

                        Label { text: "Duration" }
                        Label { text: root.durationText.length > 0 ? root.durationText : "-" }

                        Label { text: "Total packets" }
                        Label { text: root.totalPackets }

                        Label { text: "Total bytes" }
                        Label { text: root.totalBytes }

                        Label { text: "Protocol hint" }
                        Label { text: root.protocolHint.length > 0 ? root.protocolHint : "-" }

                        Label { text: "Service hint" }
                        Label { text: root.serviceHint.length > 0 ? root.serviceHint : "-"; elide: Text.ElideRight; Layout.fillWidth: true }
                    }
                }
            }

            Frame {
                Layout.fillWidth: true

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 10
                    spacing: 8

                    Label {
                        text: "Directional"
                        font.bold: true
                    }

                    GridLayout {
                        columns: 3
                        columnSpacing: 16
                        rowSpacing: 6

                        Label { text: "" }
                        Label { text: "A>B" }
                        Label { text: "B>A" }

                        Label { text: "Packets" }
                        Label { text: root.packetsAToB }
                        Label { text: root.packetsBToA }

                        Label { text: "Bytes" }
                        Label { text: root.bytesAToB }
                        Label { text: root.bytesBToA }
                    }
                }
            }
        }
    }
}
