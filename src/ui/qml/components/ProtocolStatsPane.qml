import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root
    implicitHeight: contentLayout.implicitHeight + 20
    clip: true

    property var tcpFlowCount: 0
    property var tcpPacketCount: 0
    property var tcpCapturedBytes: 0
    property var tcpOriginalBytes: 0
    property var udpFlowCount: 0
    property var udpPacketCount: 0
    property var udpCapturedBytes: 0
    property var udpOriginalBytes: 0
    property var otherFlowCount: 0
    property var otherPacketCount: 0
    property var otherCapturedBytes: 0
    property var otherOriginalBytes: 0
    property var ipv4FlowCount: 0
    property var ipv4PacketCount: 0
    property var ipv4CapturedBytes: 0
    property var ipv4OriginalBytes: 0
    property var ipv6FlowCount: 0
    property var ipv6PacketCount: 0
    property var ipv6CapturedBytes: 0
    property var ipv6OriginalBytes: 0
    property var quicTotalFlows: 0
    property var quicWithSni: 0
    property var quicWithoutSni: 0
    property var quicVersionV1: 0
    property var quicVersionDraft29: 0
    property var quicVersionV2: 0
    property var quicVersionUnknown: 0
    property var tlsTotalFlows: 0
    property var tlsWithSni: 0
    property var tlsWithoutSni: 0
    property var tlsVersion12: 0
    property var tlsVersion13: 0
    property var tlsVersionUnknown: 0
    property var protocolHintDistribution: []
    property int statisticsMode: 0
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

    readonly property int hintGroupColumnWidth: 92
    readonly property int hintProtocolColumnWidth: 180
    readonly property int hintFlowsColumnWidth: 110
    readonly property int hintPacketsColumnWidth: 118
    readonly property int hintCapturedColumnWidth: 118
    readonly property int hintOriginalColumnWidth: 118
    readonly property int hintTableWidth: hintGroupColumnWidth + hintProtocolColumnWidth + hintFlowsColumnWidth + hintPacketsColumnWidth + hintCapturedColumnWidth + hintOriginalColumnWidth + (tableColumnSpacing * 5) + (tablePadding * 2)

    function groupInteger(value) {
        const digits = Math.max(0, Math.round(Number(value || 0))).toString()
        return digits.replace(/\B(?=(\d{3})+(?!\d))/g, " ")
    }

    function trimTrailingZeros(text) {
        return text.replace(/\.0$/, "").replace(/(\.\d*[1-9])0+$/, "$1")
    }

    function formatBytes(value) {
        const units = ["B", "KB", "MB", "GB", "TB"]
        var scaled = Math.max(0, Number(value || 0))
        var unitIndex = 0
        while (scaled >= 1024 && unitIndex + 1 < units.length) {
            scaled /= 1024
            unitIndex += 1
        }

        var numberText = ""
        if (unitIndex === 0) {
            numberText = groupInteger(Math.round(scaled))
        } else {
            numberText = trimTrailingZeros(scaled.toFixed(1)).replace(/\B(?=(\d{3})+(?!\d))/g, " ")
        }

        return numberText + " " + units[unitIndex]
    }

    function formatShare(part, total) {
        const numericPart = Number(part || 0)
        const numericTotal = Number(total || 0)
        if (numericPart <= 0 || numericTotal <= 0)
            return "0%"

        const percent = (numericPart * 100.0) / numericTotal
        if (percent < 0.01)
            return "<0.01%"
        if (percent < 1.0)
            return percent.toFixed(2) + "%"
        return Math.round(percent) + "%"
    }

    function formatFlowPercentageAndCount(part, total) {
        if (Number(part || 0) <= 0 || Number(total || 0) <= 0)
            return "0% (0 flows)"
        return formatShare(part, total) + " (" + groupInteger(part) + " flows)"
    }

    function totalHintFlows() {
        if (!protocolHintDistribution || protocolHintDistribution.length === 0)
            return 0

        let total = 0
        for (let index = 0; index < protocolHintDistribution.length; ++index)
            total += protocolHintDistribution[index]["flows"] || 0
        return total
    }

    function totalHintPackets() {
        if (!protocolHintDistribution || protocolHintDistribution.length === 0)
            return 0

        let total = 0
        for (let index = 0; index < protocolHintDistribution.length; ++index)
            total += protocolHintDistribution[index]["packets"] || 0
        return total
    }

    function totalHintCapturedBytes() {
        if (!protocolHintDistribution || protocolHintDistribution.length === 0)
            return 0

        let total = 0
        for (let index = 0; index < protocolHintDistribution.length; ++index)
            total += protocolHintDistribution[index]["capturedBytes"] || 0
        return total
    }

    function totalHintOriginalBytes() {
        if (!protocolHintDistribution || protocolHintDistribution.length === 0)
            return 0

        let total = 0
        for (let index = 0; index < protocolHintDistribution.length; ++index)
            total += protocolHintDistribution[index]["originalBytes"] || 0
        return total
    }

    function formatHintCell(value, total, isBytes) {
        const formattedValue = isBytes ? formatBytes(value) : groupInteger(value)
        return formattedValue + " (" + formatShare(value, total) + ")"
    }

    function totalTransportFlows() {
        return Number(tcpFlowCount || 0) + Number(udpFlowCount || 0) + Number(otherFlowCount || 0)
    }

    function totalTransportPackets() {
        return Number(tcpPacketCount || 0) + Number(udpPacketCount || 0) + Number(otherPacketCount || 0)
    }

    function totalTransportCapturedBytes() {
        return Number(tcpCapturedBytes || 0) + Number(udpCapturedBytes || 0) + Number(otherCapturedBytes || 0)
    }

    function totalTransportOriginalBytes() {
        return Number(tcpOriginalBytes || 0) + Number(udpOriginalBytes || 0) + Number(otherOriginalBytes || 0)
    }

    function totalIpFlows() {
        return Number(ipv4FlowCount || 0) + Number(ipv6FlowCount || 0)
    }

    function totalIpPackets() {
        return Number(ipv4PacketCount || 0) + Number(ipv6PacketCount || 0)
    }

    function totalIpCapturedBytes() {
        return Number(ipv4CapturedBytes || 0) + Number(ipv6CapturedBytes || 0)
    }

    function totalIpOriginalBytes() {
        return Number(ipv4OriginalBytes || 0) + Number(ipv6OriginalBytes || 0)
    }

    function protocolHintGroup(title) {
        if (title === "Possible TLS" || title === "Possible QUIC")
            return "Possible"
        if (title === "Unknown")
            return "Unknown"
        return "Confirmed"
    }

    component SectionFrame: Frame {
        id: sectionFrame

        default property alias sectionContent: sectionLayout.data

        Layout.fillWidth: true
        implicitHeight: sectionLayout.implicitHeight + 20
        padding: 0
        clip: true

        background: Rectangle {
            color: "#ffffff"
            border.color: "#d8dee9"
            radius: 6
        }

        ColumnLayout {
            id: sectionLayout
            anchors.fill: parent
            anchors.margins: 10
            spacing: 6
        }
    }

    component CompactMetricLabel: Label {
        Layout.fillWidth: true
        color: "#334155"
        wrapMode: Text.NoWrap
        elide: Text.ElideRight
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

    component SixColumnHeader: Rectangle {
        required property string firstTitle
        required property string secondTitle
        required property string thirdTitle
        required property string fourthTitle
        required property string fifthTitle
        required property string sixthTitle
        required property int firstWidth
        required property int secondWidth
        required property int thirdWidth
        required property int fourthWidth
        required property int fifthWidth
        required property int sixthWidth
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

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing + parent.parent.thirdWidth + root.tableColumnSpacing + parent.parent.fourthWidth + root.tableColumnSpacing + parent.parent.fifthWidth + root.tableColumnSpacing
                width: parent.parent.sixthWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.sixthTitle
                font.bold: true
                color: "#334155"
            }
        }
    }

    component SixColumnRow: Rectangle {
        required property string firstText
        required property string secondText
        required property string thirdText
        required property string fourthText
        required property string fifthText
        required property string sixthText
        required property int firstWidth
        required property int secondWidth
        required property int thirdWidth
        required property int fourthWidth
        required property int fifthWidth
        required property int sixthWidth
        required property int tableWidth
        required property int rowIndex
        required property color firstColor
        required property color secondColor

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
                text: parent.parent.secondText
                color: parent.parent.secondColor
                elide: Text.ElideRight
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

            Label {
                x: parent.parent.firstWidth + root.tableColumnSpacing + parent.parent.secondWidth + root.tableColumnSpacing + parent.parent.thirdWidth + root.tableColumnSpacing + parent.parent.fourthWidth + root.tableColumnSpacing + parent.parent.fifthWidth + root.tableColumnSpacing
                width: parent.parent.sixthWidth
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: parent.parent.sixthText
                color: "#334155"
                elide: Text.ElideLeft
            }
        }
    }

    padding: 0
    background: Rectangle {
        color: "#f8fafc"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        id: contentLayout
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: 10
        spacing: 10

        Label {
            text: "Protocol Summary"
            font.bold: true
            font.pixelSize: 17
        }

        SectionFrame {
            FiveColumnHeader {
                firstTitle: "Transport"
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

            FiveColumnRow {
                firstText: "TCP"
                secondText: root.hasCapture ? root.formatHintCell(root.tcpFlowCount || 0, root.totalTransportFlows(), false) : "-"
                thirdText: root.hasCapture ? root.formatHintCell(root.tcpPacketCount || 0, root.totalTransportPackets(), false) : "-"
                fourthText: root.hasCapture ? root.formatHintCell(root.tcpCapturedBytes || 0, root.totalTransportCapturedBytes(), true) : "-"
                fifthText: root.hasCapture ? root.formatHintCell(root.tcpOriginalBytes || 0, root.totalTransportOriginalBytes(), true) : "-"
                firstWidth: root.transportNameColumnWidth
                secondWidth: root.transportFlowsColumnWidth
                thirdWidth: root.transportPacketsColumnWidth
                fourthWidth: root.transportCapturedColumnWidth
                fifthWidth: root.transportOriginalColumnWidth
                tableWidth: root.transportTableWidth
                rowIndex: 0
                firstColor: "#0f172a"
            }

            FiveColumnRow {
                firstText: "UDP"
                secondText: root.hasCapture ? root.formatHintCell(root.udpFlowCount || 0, root.totalTransportFlows(), false) : "-"
                thirdText: root.hasCapture ? root.formatHintCell(root.udpPacketCount || 0, root.totalTransportPackets(), false) : "-"
                fourthText: root.hasCapture ? root.formatHintCell(root.udpCapturedBytes || 0, root.totalTransportCapturedBytes(), true) : "-"
                fifthText: root.hasCapture ? root.formatHintCell(root.udpOriginalBytes || 0, root.totalTransportOriginalBytes(), true) : "-"
                firstWidth: root.transportNameColumnWidth
                secondWidth: root.transportFlowsColumnWidth
                thirdWidth: root.transportPacketsColumnWidth
                fourthWidth: root.transportCapturedColumnWidth
                fifthWidth: root.transportOriginalColumnWidth
                tableWidth: root.transportTableWidth
                rowIndex: 1
                firstColor: "#0f172a"
            }

            FiveColumnRow {
                firstText: "Other"
                secondText: root.hasCapture ? root.formatHintCell(root.otherFlowCount || 0, root.totalTransportFlows(), false) : "-"
                thirdText: root.hasCapture ? root.formatHintCell(root.otherPacketCount || 0, root.totalTransportPackets(), false) : "-"
                fourthText: root.hasCapture ? root.formatHintCell(root.otherCapturedBytes || 0, root.totalTransportCapturedBytes(), true) : "-"
                fifthText: root.hasCapture ? root.formatHintCell(root.otherOriginalBytes || 0, root.totalTransportOriginalBytes(), true) : "-"
                firstWidth: root.transportNameColumnWidth
                secondWidth: root.transportFlowsColumnWidth
                thirdWidth: root.transportPacketsColumnWidth
                fourthWidth: root.transportCapturedColumnWidth
                fifthWidth: root.transportOriginalColumnWidth
                tableWidth: root.transportTableWidth
                rowIndex: 2
                firstColor: "#0f172a"
            }
        }

        SectionFrame {
            FiveColumnHeader {
                firstTitle: "Family"
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

            FiveColumnRow {
                firstText: "IPv4"
                secondText: root.hasCapture ? root.formatHintCell(root.ipv4FlowCount || 0, root.totalIpFlows(), false) : "-"
                thirdText: root.hasCapture ? root.formatHintCell(root.ipv4PacketCount || 0, root.totalIpPackets(), false) : "-"
                fourthText: root.hasCapture ? root.formatHintCell(root.ipv4CapturedBytes || 0, root.totalIpCapturedBytes(), true) : "-"
                fifthText: root.hasCapture ? root.formatHintCell(root.ipv4OriginalBytes || 0, root.totalIpOriginalBytes(), true) : "-"
                firstWidth: root.transportNameColumnWidth
                secondWidth: root.transportFlowsColumnWidth
                thirdWidth: root.transportPacketsColumnWidth
                fourthWidth: root.transportCapturedColumnWidth
                fifthWidth: root.transportOriginalColumnWidth
                tableWidth: root.transportTableWidth
                rowIndex: 0
                firstColor: "#0f172a"
            }

            FiveColumnRow {
                firstText: "IPv6"
                secondText: root.hasCapture ? root.formatHintCell(root.ipv6FlowCount || 0, root.totalIpFlows(), false) : "-"
                thirdText: root.hasCapture ? root.formatHintCell(root.ipv6PacketCount || 0, root.totalIpPackets(), false) : "-"
                fourthText: root.hasCapture ? root.formatHintCell(root.ipv6CapturedBytes || 0, root.totalIpCapturedBytes(), true) : "-"
                fifthText: root.hasCapture ? root.formatHintCell(root.ipv6OriginalBytes || 0, root.totalIpOriginalBytes(), true) : "-"
                firstWidth: root.transportNameColumnWidth
                secondWidth: root.transportFlowsColumnWidth
                thirdWidth: root.transportPacketsColumnWidth
                fourthWidth: root.transportCapturedColumnWidth
                fifthWidth: root.transportOriginalColumnWidth
                tableWidth: root.transportTableWidth
                rowIndex: 1
                firstColor: "#0f172a"
            }
        }

        SectionFrame {
            Label {
                text: "Detected Protocol Hints"
                font.bold: true
            }

            SixColumnHeader {
                firstTitle: "Group"
                secondTitle: "Protocol"
                thirdTitle: "Flows"
                fourthTitle: "Packets"
                fifthTitle: "Captured"
                sixthTitle: "Original"
                firstWidth: root.hintGroupColumnWidth
                secondWidth: root.hintProtocolColumnWidth
                thirdWidth: root.hintFlowsColumnWidth
                fourthWidth: root.hintPacketsColumnWidth
                fifthWidth: root.hintCapturedColumnWidth
                sixthWidth: root.hintOriginalColumnWidth
                tableWidth: root.hintTableWidth
            }

            Repeater {
                model: root.protocolHintDistribution

                delegate: Rectangle {
                    width: Math.min(root.hintTableWidth, parent ? parent.width : root.hintTableWidth)
                    height: root.tableRowHeight
                    radius: 4
                    color: index % 2 === 0 ? "transparent" : "#f8fafc"

                    Item {
                        anchors.fill: parent
                        anchors.leftMargin: root.tablePadding
                        anchors.rightMargin: root.tablePadding

                        Label {
                            x: 0
                            width: root.hintGroupColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            text: root.protocolHintGroup(modelData["title"] || "")
                            color: "#64748b"
                            elide: Text.ElideRight
                        }

                        Label {
                            x: root.hintGroupColumnWidth + root.tableColumnSpacing
                            width: root.hintProtocolColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            text: modelData["title"] || ""
                            color: "#0f172a"
                            elide: Text.ElideRight
                        }

                        Label {
                            x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing
                            width: root.hintFlowsColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            horizontalAlignment: Text.AlignRight
                            text: root.hasCapture
                                ? root.formatHintCell(modelData["flows"] || 0, root.totalHintFlows(), false)
                                : "-"
                            color: "#334155"
                            elide: Text.ElideLeft
                        }

                        Label {
                            x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing + root.hintFlowsColumnWidth + root.tableColumnSpacing
                            width: root.hintPacketsColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            horizontalAlignment: Text.AlignRight
                            text: root.hasCapture
                                ? root.formatHintCell(modelData["packets"] || 0, root.totalHintPackets(), false)
                                : "-"
                            color: "#334155"
                            elide: Text.ElideLeft
                        }

                        Label {
                            x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing + root.hintFlowsColumnWidth + root.tableColumnSpacing + root.hintPacketsColumnWidth + root.tableColumnSpacing
                            width: root.hintCapturedColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            horizontalAlignment: Text.AlignRight
                            text: root.hasCapture
                                ? root.formatHintCell(modelData["capturedBytes"] || 0, root.totalHintCapturedBytes(), true)
                                : "-"
                            color: "#334155"
                            elide: Text.ElideLeft
                        }

                        Label {
                            x: root.hintGroupColumnWidth + root.tableColumnSpacing + root.hintProtocolColumnWidth + root.tableColumnSpacing + root.hintFlowsColumnWidth + root.tableColumnSpacing + root.hintPacketsColumnWidth + root.tableColumnSpacing + root.hintCapturedColumnWidth + root.tableColumnSpacing
                            width: root.hintOriginalColumnWidth
                            anchors.verticalCenter: parent.verticalCenter
                            horizontalAlignment: Text.AlignRight
                            text: root.hasCapture
                                ? root.formatHintCell(modelData["originalBytes"] || 0, root.totalHintOriginalBytes(), true)
                                : "-"
                            color: "#334155"
                            elide: Text.ElideLeft
                        }
                    }
                }
            }
        }

        RowLayout {
            id: quicTlsRow
            Layout.fillWidth: true
            spacing: 10

            SectionFrame {
                id: quicSection
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop

                Label {
                    text: "QUIC"
                    font.bold: true
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "Flows: " + root.groupInteger(root.quicTotalFlows) : "Flows: -"
                }

                Label {
                    text: "Initial recognising (flow-based)"
                    font.bold: true
                    font.pixelSize: 12
                    color: "#475569"
                }

                CompactMetricLabel {
                    text: root.hasCapture
                        ? "Recognised Initial: " + root.formatFlowPercentageAndCount(root.quicWithSni, root.quicTotalFlows)
                        : "Recognised Initial: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture
                        ? "Unrecognised: " + root.formatFlowPercentageAndCount(root.quicWithoutSni, root.quicTotalFlows)
                        : "Unrecognised: -"
                }

                Label {
                    text: "Version"
                    font.bold: true
                    font.pixelSize: 12
                    color: "#475569"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "v1: " + root.groupInteger(root.quicVersionV1) : "v1: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "draft-29: " + root.groupInteger(root.quicVersionDraft29) : "draft-29: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "v2: " + root.groupInteger(root.quicVersionV2) : "v2: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "Version unavailable: " + root.groupInteger(root.quicVersionUnknown) : "Version unavailable: -"
                }
            }

            SectionFrame {
                id: tlsSection
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop

                Label {
                    text: "TLS"
                    font.bold: true
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "Flows: " + root.groupInteger(root.tlsTotalFlows) : "Flows: -"
                }

                Label {
                    text: "SNI (flow-based)"
                    font.bold: true
                    font.pixelSize: 12
                    color: "#475569"
                }

                CompactMetricLabel {
                    text: root.hasCapture
                        ? "With SNI: " + root.formatFlowPercentageAndCount(root.tlsWithSni, root.tlsTotalFlows)
                        : "With SNI: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture
                        ? "Without SNI: " + root.formatFlowPercentageAndCount(root.tlsWithoutSni, root.tlsTotalFlows)
                        : "Without SNI: -"
                }

                Label {
                    text: "Version"
                    font.bold: true
                    font.pixelSize: 12
                    color: "#475569"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "TLS 1.2: " + root.groupInteger(root.tlsVersion12) : "TLS 1.2: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "TLS 1.3: " + root.groupInteger(root.tlsVersion13) : "TLS 1.3: -"
                }

                CompactMetricLabel {
                    text: root.hasCapture ? "Version unavailable: " + root.groupInteger(root.tlsVersionUnknown) : "Version unavailable: -"
                }
            }
        }
    }
}
