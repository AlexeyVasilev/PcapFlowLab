import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property bool hasActiveFlow: false
    property bool analysisLoading: false
    property bool analysisAvailable: false
    property string durationText: ""
    property string timelineFirstPacketTime: ""
    property string timelineLastPacketTime: ""
    property string timelineLargestGapText: ""
    property var timelinePacketCountConsidered: 0
    property var totalPackets: 0
    property var totalBytes: 0
    property string protocolHint: ""
    property string serviceHint: ""
    property var packetsAToB: 0
    property var packetsBToA: 0
    property var bytesAToB: 0
    property var bytesBToA: 0
    property var sequencePreviewModel: []

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

        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            Rectangle {
                id: emptyStateCard
                objectName: "analysisEmptyState"
                anchors.centerIn: parent
                width: Math.min(parent.width - 24, 340)
                visible: !root.hasActiveFlow && !root.analysisLoading
                color: "#f8fafc"
                border.color: "#cbd5e1"
                radius: 10
                implicitHeight: emptyStateLayout.implicitHeight + 24

                ColumnLayout {
                    id: emptyStateLayout
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 6

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Select a flow to analyze"
                        font.pixelSize: 18
                        font.bold: true
                        color: "#0f172a"
                    }

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Choose a flow from the list on the left to open its analysis workspace."
                        color: "#64748b"
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.WordWrap
                    }
                }
            }

            Rectangle {
                id: loadingStateCard
                objectName: "analysisLoadingState"
                anchors.centerIn: parent
                width: Math.min(parent.width - 24, 300)
                visible: root.analysisLoading
                color: "#eff6ff"
                border.color: "#93c5fd"
                radius: 10
                implicitHeight: loadingStateLayout.implicitHeight + 24

                ColumnLayout {
                    id: loadingStateLayout
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 6

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Loading analysis..."
                        font.pixelSize: 18
                        font.bold: true
                        color: "#1d4ed8"
                    }

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Refreshing selected-flow analysis"
                        color: "#475569"
                    }
                }
            }

            Rectangle {
                id: unavailableStateCard
                objectName: "analysisUnavailableState"
                anchors.centerIn: parent
                width: Math.min(parent.width - 24, 340)
                visible: root.hasActiveFlow && !root.analysisLoading && !root.analysisAvailable
                color: "#f8fafc"
                border.color: "#cbd5e1"
                radius: 10
                implicitHeight: unavailableStateLayout.implicitHeight + 24

                ColumnLayout {
                    id: unavailableStateLayout
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 6

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Analysis unavailable"
                        font.pixelSize: 18
                        font.bold: true
                        color: "#0f172a"
                    }

                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Analysis is unavailable for the selected flow."
                        color: "#64748b"
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.WordWrap
                    }
                }
            }

            ColumnLayout {
                objectName: "analysisResultContent"
                anchors.fill: parent
            visible: root.analysisAvailable && !root.analysisLoading
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
                            text: "Timeline"
                            font.bold: true
                        }

                        GridLayout {
                            columns: 2
                            columnSpacing: 16
                            rowSpacing: 6

                            Label { text: "First packet" }
                            Label { text: root.timelineFirstPacketTime.length > 0 ? root.timelineFirstPacketTime : "-" }

                            Label { text: "Last packet" }
                            Label { text: root.timelineLastPacketTime.length > 0 ? root.timelineLastPacketTime : "-" }

                            Label { text: "Duration" }
                            Label { text: root.durationText.length > 0 ? root.durationText : "-" }

                            Label { text: "Largest gap" }
                            Label { text: root.timelineLargestGapText.length > 0 ? root.timelineLargestGapText : "-" }

                            Label { text: "Packets considered" }
                            Label { text: root.timelinePacketCountConsidered }
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

                Frame {
                    Layout.fillWidth: true

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 8

                        Label {
                            text: "Sequence Preview"
                            font.bold: true
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 12

                            Label { text: "#"; Layout.preferredWidth: 34 }
                            Label { text: "Dir"; Layout.preferredWidth: 48 }
                            Label { text: "Delta"; Layout.preferredWidth: 90 }
                            Label { text: "Captured"; Layout.preferredWidth: 70; horizontalAlignment: Text.AlignRight }
                            Label { text: "Payload"; Layout.preferredWidth: 64; horizontalAlignment: Text.AlignRight }
                            Label { text: "Time"; Layout.fillWidth: true }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            height: 1
                            color: "#e2e8f0"
                        }

                        Repeater {
                            model: root.sequencePreviewModel

                            delegate: RowLayout {
                                required property var modelData
                                Layout.fillWidth: true
                                spacing: 12

                                Label { text: modelData.packetNumber; Layout.preferredWidth: 34 }
                                Label { text: modelData.direction; Layout.preferredWidth: 48 }
                                Label { text: modelData.deltaTimeText; Layout.preferredWidth: 90 }
                                Label { text: modelData.capturedLength; Layout.preferredWidth: 70; horizontalAlignment: Text.AlignRight }
                                Label { text: modelData.payloadLength; Layout.preferredWidth: 64; horizontalAlignment: Text.AlignRight }
                                Label { text: modelData.timestampText; Layout.fillWidth: true; color: "#475569" }
                            }
                        }
                    }
                }
            }
        }
    }
}
