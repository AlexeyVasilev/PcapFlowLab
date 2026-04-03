import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    readonly property int blockPadding: 12
    readonly property int blockSpacing: 12
    readonly property int sectionSpacing: 8
    readonly property int rowSpacing: 8
    readonly property int histogramRowSpacing: 8
    readonly property int histogramColumnSpacing: 8
    readonly property int histogramBarHeight: 18

    component AnalysisSectionFrame: Frame {
        id: sectionFrame

        default property alias sectionContent: sectionLayout.data

        Layout.fillWidth: true
        padding: 0
        implicitHeight: sectionLayout.implicitHeight + (root.blockPadding * 3)

        background: Rectangle {
            color: "#ffffff"
            border.color: "#d8dee9"
            radius: 6
        }

        ColumnLayout {
            id: sectionLayout
            x: root.blockPadding
            y: root.blockPadding
            width: Math.max(0, parent.width - (root.blockPadding * 2))
            spacing: root.sectionSpacing
        }
    }

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
    property var interArrivalHistogramModel: []
    property var packetSizeHistogramModel: []
    property var sequencePreviewModel: []

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: root.blockSpacing

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

            ScrollView {
                id: analysisResultScroll
                objectName: "analysisResultContent"
                anchors.fill: parent
                clip: true
                visible: root.analysisAvailable && !root.analysisLoading

                ScrollBar.vertical.policy: ScrollBar.AsNeeded

                ColumnLayout {
                    width: analysisResultScroll.availableWidth
                    spacing: root.blockSpacing

                    AnalysisSectionFrame {
                        Label {
                            text: "Overview"
                            font.bold: true
                        }

                        GridLayout {
                            width: parent.width
                            columns: 2
                            columnSpacing: 16
                            rowSpacing: root.rowSpacing

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

                    AnalysisSectionFrame {
                        Label {
                            text: "Inter-arrival Histogram"
                            font.bold: true
                        }

                        Repeater {
                            model: root.interArrivalHistogramModel

                            delegate: RowLayout {
                                required property var modelData
                                width: parent.width
                                spacing: root.histogramColumnSpacing

                                Label {
                                    text: modelData.bucketLabel
                                    Layout.preferredWidth: 84
                                    Layout.alignment: Qt.AlignVCenter
                                }

                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.topMargin: 2
                                    Layout.bottomMargin: 2
                                    implicitHeight: root.histogramBarHeight
                                    radius: 4
                                    color: "#f8fafc"
                                    border.color: "#dbe3ee"

                                    Rectangle {
                                        anchors.left: parent.left
                                        anchors.top: parent.top
                                        anchors.bottom: parent.bottom
                                        width: parent.width * (root.totalPackets > 1 ? modelData.packetCount / (root.totalPackets - 1) : 0)
                                        radius: 4
                                        color: modelData.packetCount > 0 ? "#38bdf8" : "transparent"
                                    }
                                }

                                Label {
                                    text: modelData.packetCount
                                    Layout.preferredWidth: 40
                                    Layout.alignment: Qt.AlignVCenter
                                    horizontalAlignment: Text.AlignRight
                                }
                            }
                        }
                    }

                    AnalysisSectionFrame {
                        Label {
                            text: "Packet Size Histogram"
                            font.bold: true
                        }

                        Repeater {
                            model: root.packetSizeHistogramModel

                            delegate: RowLayout {
                                required property var modelData
                                width: parent.width
                                spacing: root.histogramColumnSpacing

                                Label {
                                    text: modelData.bucketLabel
                                    Layout.preferredWidth: 84
                                    Layout.alignment: Qt.AlignVCenter
                                }

                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.topMargin: 2
                                    Layout.bottomMargin: 2
                                    implicitHeight: root.histogramBarHeight
                                    radius: 4
                                    color: "#f1f5f9"
                                    border.color: "#dbe3ee"

                                    Rectangle {
                                        anchors.left: parent.left
                                        anchors.top: parent.top
                                        anchors.bottom: parent.bottom
                                        width: parent.width * (root.totalPackets > 0 ? modelData.packetCount / root.totalPackets : 0)
                                        radius: 4
                                        color: modelData.packetCount > 0 ? "#60a5fa" : "transparent"
                                    }
                                }

                                Label {
                                    text: modelData.packetCount
                                    Layout.preferredWidth: 40
                                    Layout.alignment: Qt.AlignVCenter
                                    horizontalAlignment: Text.AlignRight
                                }
                            }
                        }
                    }

                    AnalysisSectionFrame {
                        Label {
                            text: "Timeline"
                            font.bold: true
                        }

                        GridLayout {
                            width: parent.width
                            columns: 2
                            columnSpacing: 16
                            rowSpacing: root.rowSpacing

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

                    AnalysisSectionFrame {
                        Label {
                            text: "Directional"
                            font.bold: true
                        }

                        GridLayout {
                            width: parent.width
                            columns: 3
                            columnSpacing: 16
                            rowSpacing: root.rowSpacing

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

                    AnalysisSectionFrame {
                        Label {
                            text: "Sequence Preview"
                            font.bold: true
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: root.histogramColumnSpacing

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
                                width: parent.width
                                spacing: root.histogramColumnSpacing

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
