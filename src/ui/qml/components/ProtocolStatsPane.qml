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

    readonly property int transportNameColumnWidth: 92
    readonly property int transportFlowsColumnWidth: 118
    readonly property int transportPacketsColumnWidth: 126
    readonly property int transportCapturedColumnWidth: 126
    readonly property int transportOriginalColumnWidth: 126
    readonly property int transportTableWidth: transportNameColumnWidth + transportFlowsColumnWidth + transportPacketsColumnWidth + transportCapturedColumnWidth + transportOriginalColumnWidth + (tableColumnSpacing * 4) + (tablePadding * 2)

    readonly property int familyNameColumnWidth: 92
    readonly property int familyFlowsColumnWidth: 118
    readonly property int familyPacketsColumnWidth: 126
    readonly property int familyCapturedColumnWidth: 126
    readonly property int familyOriginalColumnWidth: 126
    readonly property int familyTableWidth: familyNameColumnWidth + familyFlowsColumnWidth + familyPacketsColumnWidth + familyCapturedColumnWidth + familyOriginalColumnWidth + (tableColumnSpacing * 4) + (tablePadding * 2)

    function groupInteger(value) {
        const digits = Math.max(0, Math.round(Number(value || 0))).toString()
        return digits.replace(/\B(?=(\d{3})+(?!\d))/g, " ")
    }

    component SectionFrame: Frame {
        default property alias sectionContent: sectionLayout.data

        Layout.fillWidth: true
        padding: 0

        background: Rectangle {
            color: "#ffffff"
            border.color: "#d8dee9"
            radius: 6
        }

        ColumnLayout {
            id: sectionLayout
            anchors.fill: parent
            anchors.margins: 10
            spacing: 8
        }
    }

    component FiveColumnHeader: Rectangle {
        required property string firstTitle
        required property string secondTitle
        required property string thirdTitle
        required property string fourthTitle
        required property string fifthTitle
        required property int firstWidth
        required property int secondWidth
        required property int thirdWidth
        required property int fourthWidth
        required property int fifthWidth
        required property int tableWidth

        width: Math.min(tableWidth, parent ? parent.width : tableWidth)
        height: root.tableHeaderHeight
        radius: 4
        color: "#f8fafc"
        border.color: "#e2e8f0"

        Item {
            anchors.fill: parent
            anchors.leftMargin: root.tablePadding
            anchors.rightMargin: root.tablePadding

            Label {
                x: 0
                width: parent.parent.firstWidth
                anchors.verticalCenter: parent.verticalCenter
                text: parent.parent.firstTitle
                font.bold: true
                color: "#334155"
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing
                width: parent.parent.secondWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.secondTitle
                font.bold: true
                color: "#334155"
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing
                width: parent.parent.thirdWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.thirdTitle
                font.bold: true
                color: "#334155"
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing + parent.parent.thirdWidth + root.tableColumnSpacing
                width: parent.parent.fourthWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.fourthTitle
                font.bold: true
                color: "#334155"
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing + parent.parent.thirdWidth + root.tableColumnSpacing + parent.parent.fourthWidth + root.tableColumnSpacing
                width: parent.parent.fifthWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.fifthTitle
                font.bold: true
                color: "#334155"
            }
        }
    }

    component FiveColumnRow: Rectangle {
        required property string firstText
        required property string secondText
        required property string thirdText
        required property string fourthText
        required property string fifthText
        required property int firstWidth
        required property int secondWidth
        required property int thirdWidth
        required property int fourthWidth
        required property int fifthWidth
        required property int tableWidth
        required property int rowIndex
        required property color firstColor

        width: Math.min(tableWidth, parent ? parent.width : tableWidth)
        height: root.tableRowHeight
        radius: 4
        color: rowIndex % 2 === 0 ? "transparent" : "#f8fafc"

        Item {
            anchors.fill: parent
            anchors.leftMargin: root.tablePadding
            anchors.rightMargin: root.tablePadding

            Label {
                x: 0
                width: parent.parent.firstWidth
                anchors.verticalCenter: parent.verticalCenter
                text: parent.parent.firstText
                color: parent.parent.firstColor
                elide: Text.ElideRight
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing
                width: parent.parent.secondWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.secondText
                color: "#334155"
                elide: Text.ElideLeft
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing
                width: parent.parent.thirdWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.thirdText
                color: "#334155"
                elide: Text.ElideLeft
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing + parent.parent.thirdWidth + root.tableColumnSpacing
                width: parent.parent.fourthWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.fourthText
                color: "#334155"
                elide: Text.ElideLeft
            }

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing + parent.parent.thirdWidth + root.tableColumnSpacing + parent.parent.fourthWidth + root.tableColumnSpacing
                width: parent.parent.fifthWidth
                anchors.verticalCenter: parent.verticalCenter
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
        spacing: 10

        Label {
            text: "Protocol Summary"
            font.pixelSize: 18
            font.bold: true
            color: "#0f172a"
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 10

            SectionFrame {
                Layout.fillWidth: true
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
                    firstWidth: root.transportNameColumnWidth
                    secondWidth: root.transportFlowsColumnWidth
                    thirdWidth: root.transportPacketsColumnWidth
                    fourthWidth: root.transportCapturedColumnWidth
                    fifthWidth: root.transportOriginalColumnWidth
                    tableWidth: root.transportTableWidth
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
                        firstWidth: root.transportNameColumnWidth
                        secondWidth: root.transportFlowsColumnWidth
                        thirdWidth: root.transportPacketsColumnWidth
                        fourthWidth: root.transportCapturedColumnWidth
                        fifthWidth: root.transportOriginalColumnWidth
                        tableWidth: root.transportTableWidth
                        rowIndex: modelData.rowIndex
                        firstColor: "#0f172a"
                    }
                }
            }

            SectionFrame {
                Layout.fillWidth: true
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
                    firstWidth: root.familyNameColumnWidth
                    secondWidth: root.familyFlowsColumnWidth
                    thirdWidth: root.familyPacketsColumnWidth
                    fourthWidth: root.familyCapturedColumnWidth
                    fifthWidth: root.familyOriginalColumnWidth
                    tableWidth: root.familyTableWidth
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
                        firstWidth: root.familyNameColumnWidth
                        secondWidth: root.familyFlowsColumnWidth
                        thirdWidth: root.familyPacketsColumnWidth
                        fourthWidth: root.familyCapturedColumnWidth
                        fifthWidth: root.familyOriginalColumnWidth
                        tableWidth: root.familyTableWidth
                        rowIndex: modelData.rowIndex
                        firstColor: "#0f172a"
                    }
                }
            }
        }
    }
}
