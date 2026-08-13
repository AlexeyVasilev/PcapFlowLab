import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var tcpFlowCount: 0
    property var tcpPacketCount: 0
    property string tcpCapturedBytesText: ""
    property string tcpOriginalBytesText: ""
    property var udpFlowCount: 0
    property var udpPacketCount: 0
    property string udpCapturedBytesText: ""
    property string udpOriginalBytesText: ""
    property var sctpFlowCount: 0
    property var sctpPacketCount: 0
    property string sctpCapturedBytesText: ""
    property string sctpOriginalBytesText: ""
    property var otherFlowCount: 0
    property var otherPacketCount: 0
    property string otherCapturedBytesText: ""
    property string otherOriginalBytesText: ""
    property var ipv4FlowCount: 0
    property var ipv4PacketCount: 0
    property string ipv4CapturedBytesText: ""
    property string ipv4OriginalBytesText: ""
    property var ipv6FlowCount: 0
    property var ipv6PacketCount: 0
    property string ipv6CapturedBytesText: ""
    property string ipv6OriginalBytesText: ""
    property bool hasCapture: false

    readonly property int tableRowHeight: 26
    readonly property int tableHeaderHeight: 28
    readonly property int tablePadding: 8
    readonly property int tableColumnSpacing: 12
    readonly property var protocolSummaryBaseColumnWidths: [92, 118, 126, 126, 126]
    readonly property var protocolSummaryMinColumnWidths: [64, 72, 80, 92, 92]
    readonly property real protocolSummaryStackThreshold: 940

    function groupInteger(value) {
        const digits = Math.max(0, Math.round(Number(value || 0))).toString()
        return digits.replace(/\B(?=(\d{3})+(?!\d))/g, " ")
    }

    function resolvedFiveColumnWidths(availableWidth, baseWidths, minWidths) {
        const spacingAndPadding = (tableColumnSpacing * 4) + (tablePadding * 2)
        const targetWidth = Math.max(0, Math.floor(Number(availableWidth || 0) - spacingAndPadding))
        const base = baseWidths.slice()
        const mins = minWidths.slice()
        const baseTotal = base.reduce((sum, value) => sum + value, 0)
        const minTotal = mins.reduce((sum, value) => sum + value, 0)

        if (targetWidth >= baseTotal)
            return base

        if (targetWidth <= minTotal) {
            const scale = minTotal > 0 ? targetWidth / minTotal : 1
            const scaled = mins.map((value) => Math.max(24, Math.floor(value * scale)))
            const scaledTotal = scaled.reduce((sum, value) => sum + value, 0)
            scaled[scaled.length - 1] += Math.max(0, targetWidth - scaledTotal)
            return scaled
        }

        const flexes = base.map((value, index) => value - mins[index])
        const flexTotal = flexes.reduce((sum, value) => sum + value, 0)
        const extra = targetWidth - minTotal
        const resolved = mins.map((value, index) => {
            if (flexTotal <= 0)
                return value
            return Math.floor(value + ((extra * flexes[index]) / flexTotal))
        })
        const resolvedTotal = resolved.reduce((sum, value) => sum + value, 0)
        resolved[resolved.length - 1] += Math.max(0, targetWidth - resolvedTotal)
        return resolved
    }

    component SectionFrame: Frame {
        default property alias sectionContent: sectionLayout.data

        Layout.fillWidth: true
        Layout.minimumWidth: 0
        padding: 0
        readonly property real sectionContentWidth: Math.max(0, width - 20)

        background: Rectangle {
            color: "#ffffff"
            border.color: "#d8dee9"
            radius: 6
        }

        ColumnLayout {
            id: sectionLayout
            anchors.fill: parent
            anchors.margins: 10
            Layout.minimumWidth: 0
            spacing: 8
        }
    }

    component FiveColumnHeader: Rectangle {
        required property string firstTitle
        required property string secondTitle
        required property string thirdTitle
        required property string fourthTitle
        required property string fifthTitle
        required property var columnWidths

        Layout.fillWidth: true
        Layout.minimumWidth: 0
        width: parent ? parent.width : 0
        height: root.tableHeaderHeight
        radius: 4
        color: "#f8fafc"
        border.color: "#e2e8f0"

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: root.tablePadding
            anchors.rightMargin: root.tablePadding
            spacing: root.tableColumnSpacing

            Label {
                Layout.preferredWidth: parent.parent.columnWidths[0]
                Layout.minimumWidth: parent.parent.columnWidths[0]
                Layout.maximumWidth: parent.parent.columnWidths[0]
                text: parent.parent.firstTitle
                font.bold: true
                color: "#334155"
                elide: Text.ElideRight
            }

            Label {
                Layout.preferredWidth: parent.parent.columnWidths[1]
                Layout.minimumWidth: parent.parent.columnWidths[1]
                Layout.maximumWidth: parent.parent.columnWidths[1]
                horizontalAlignment: Text.AlignRight
                text: parent.parent.secondTitle
                font.bold: true
                color: "#334155"
                elide: Text.ElideLeft
            }

            Label {
                Layout.preferredWidth: parent.parent.columnWidths[2]
                Layout.minimumWidth: parent.parent.columnWidths[2]
                Layout.maximumWidth: parent.parent.columnWidths[2]
                horizontalAlignment: Text.AlignRight
                text: parent.parent.thirdTitle
                font.bold: true
                color: "#334155"
                elide: Text.ElideLeft
            }

            Label {
                Layout.preferredWidth: parent.parent.columnWidths[3]
                Layout.minimumWidth: parent.parent.columnWidths[3]
                Layout.maximumWidth: parent.parent.columnWidths[3]
                horizontalAlignment: Text.AlignRight
                text: parent.parent.fourthTitle
                font.bold: true
                color: "#334155"
                elide: Text.ElideLeft
            }

            Label {
                Layout.preferredWidth: parent.parent.columnWidths[4]
                Layout.minimumWidth: parent.parent.columnWidths[4]
                Layout.maximumWidth: parent.parent.columnWidths[4]
                horizontalAlignment: Text.AlignRight
                text: parent.parent.fifthTitle
                font.bold: true
                color: "#334155"
                elide: Text.ElideLeft
            }
        }
    }

    component FiveColumnRow: Rectangle {
        required property string firstText
        required property string secondText
        required property string thirdText
        required property string fourthText
        required property string fifthText
        required property var columnWidths
        required property int rowIndex
        required property color firstColor

        Layout.fillWidth: true
        Layout.minimumWidth: 0
        width: parent ? parent.width : 0
        height: root.tableRowHeight
        radius: 4
        color: rowIndex % 2 === 0 ? "transparent" : "#f8fafc"

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: root.tablePadding
            anchors.rightMargin: root.tablePadding
            spacing: root.tableColumnSpacing

            Label {
                Layout.preferredWidth: parent.parent.columnWidths[0]
                Layout.minimumWidth: parent.parent.columnWidths[0]
                Layout.maximumWidth: parent.parent.columnWidths[0]
                text: parent.parent.firstText
                color: parent.parent.firstColor
                elide: Text.ElideRight
            }

            Label {
                Layout.preferredWidth: parent.parent.columnWidths[1]
                Layout.minimumWidth: parent.parent.columnWidths[1]
                Layout.maximumWidth: parent.parent.columnWidths[1]
                horizontalAlignment: Text.AlignRight
                text: parent.parent.secondText
                color: "#334155"
                elide: Text.ElideLeft
            }

            Label {
                Layout.preferredWidth: parent.parent.columnWidths[2]
                Layout.minimumWidth: parent.parent.columnWidths[2]
                Layout.maximumWidth: parent.parent.columnWidths[2]
                horizontalAlignment: Text.AlignRight
                text: parent.parent.thirdText
                color: "#334155"
                elide: Text.ElideLeft
            }

            Label {
                Layout.preferredWidth: parent.parent.columnWidths[3]
                Layout.minimumWidth: parent.parent.columnWidths[3]
                Layout.maximumWidth: parent.parent.columnWidths[3]
                horizontalAlignment: Text.AlignRight
                text: parent.parent.fourthText
                color: "#334155"
                elide: Text.ElideLeft
            }

            Label {
                Layout.preferredWidth: parent.parent.columnWidths[4]
                Layout.minimumWidth: parent.parent.columnWidths[4]
                Layout.maximumWidth: parent.parent.columnWidths[4]
                horizontalAlignment: Text.AlignRight
                text: parent.parent.fifthText
                color: "#334155"
                elide: Text.ElideLeft
            }
        }
    }

    padding: 0
    clip: true

    background: Rectangle {
        color: "#f8fafc"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        id: contentLayout
        anchors.fill: parent
        anchors.margins: 10
        Layout.minimumWidth: 0
        spacing: 10

        Label {
            text: "Protocol Summary"
            font.pixelSize: 18
            font.bold: true
            color: "#0f172a"
        }

        GridLayout {
            readonly property bool stacked: width > 0 && width < root.protocolSummaryStackThreshold
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            columns: stacked ? 1 : 2
            columnSpacing: 10
            rowSpacing: 10

            SectionFrame {
                id: transportSection
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                Layout.alignment: Qt.AlignTop

                Label {
                    text: "Transport"
                    font.bold: true
                    font.pixelSize: 16
                }

                FiveColumnHeader {
                    firstTitle: "Protocol"
                    secondTitle: "Flows"
                    thirdTitle: "Packets"
                    fourthTitle: "Captured"
                    fifthTitle: "Original"
                    columnWidths: root.resolvedFiveColumnWidths(
                        transportSection.sectionContentWidth,
                        root.protocolSummaryBaseColumnWidths,
                        root.protocolSummaryMinColumnWidths
                    )
                }

                Repeater {
                    model: [
                        { rowIndex: 0, name: "TCP", flows: root.tcpFlowCount, packets: root.tcpPacketCount, capturedText: root.tcpCapturedBytesText, originalText: root.tcpOriginalBytesText },
                        { rowIndex: 1, name: "UDP", flows: root.udpFlowCount, packets: root.udpPacketCount, capturedText: root.udpCapturedBytesText, originalText: root.udpOriginalBytesText },
                        { rowIndex: 2, name: "SCTP", flows: root.sctpFlowCount, packets: root.sctpPacketCount, capturedText: root.sctpCapturedBytesText, originalText: root.sctpOriginalBytesText },
                        { rowIndex: 3, name: "Other", flows: root.otherFlowCount, packets: root.otherPacketCount, capturedText: root.otherCapturedBytesText, originalText: root.otherOriginalBytesText }
                    ]

                    delegate: FiveColumnRow {
                        required property var modelData
                        firstText: modelData.name
                        secondText: root.hasCapture ? root.groupInteger(modelData.flows) : "-"
                        thirdText: root.hasCapture ? root.groupInteger(modelData.packets) : "-"
                        fourthText: root.hasCapture ? modelData.capturedText : "-"
                        fifthText: root.hasCapture ? modelData.originalText : "-"
                        columnWidths: root.resolvedFiveColumnWidths(
                            transportSection.sectionContentWidth,
                            root.protocolSummaryBaseColumnWidths,
                            root.protocolSummaryMinColumnWidths
                        )
                        rowIndex: modelData.rowIndex
                        firstColor: "#0f172a"
                    }
                }
            }

            SectionFrame {
                id: familySection
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                Layout.alignment: Qt.AlignTop

                Label {
                    text: "Family"
                    font.bold: true
                    font.pixelSize: 16
                }

                FiveColumnHeader {
                    firstTitle: "Family"
                    secondTitle: "Flows"
                    thirdTitle: "Packets"
                    fourthTitle: "Captured"
                    fifthTitle: "Original"
                    columnWidths: root.resolvedFiveColumnWidths(
                        familySection.sectionContentWidth,
                        root.protocolSummaryBaseColumnWidths,
                        root.protocolSummaryMinColumnWidths
                    )
                }

                Repeater {
                    model: [
                        { rowIndex: 0, name: "IPv4", flows: root.ipv4FlowCount, packets: root.ipv4PacketCount, capturedText: root.ipv4CapturedBytesText, originalText: root.ipv4OriginalBytesText },
                        { rowIndex: 1, name: "IPv6", flows: root.ipv6FlowCount, packets: root.ipv6PacketCount, capturedText: root.ipv6CapturedBytesText, originalText: root.ipv6OriginalBytesText }
                    ]

                    delegate: FiveColumnRow {
                        required property var modelData
                        firstText: modelData.name
                        secondText: root.hasCapture ? root.groupInteger(modelData.flows) : "-"
                        thirdText: root.hasCapture ? root.groupInteger(modelData.packets) : "-"
                        fourthText: root.hasCapture ? modelData.capturedText : "-"
                        fifthText: root.hasCapture ? modelData.originalText : "-"
                        columnWidths: root.resolvedFiveColumnWidths(
                            familySection.sectionContentWidth,
                            root.protocolSummaryBaseColumnWidths,
                            root.protocolSummaryMinColumnWidths
                        )
                        rowIndex: modelData.rowIndex
                        firstColor: "#0f172a"
                    }
                }
            }
        }
    }
}
