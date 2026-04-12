import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var packetModel: null
    property var selectedPacketIndex: -1
    property bool packetsLoading: false
    property bool packetsPartiallyLoaded: false
    property var loadedPacketRowCount: 0
    property var totalPacketRowCount: 0
    property bool canLoadMorePackets: false
    readonly property string forwardDirection: "A\u2192B"
    readonly property string reverseDirection: "B\u2192A"

    signal packetSelected(var packetIndex)
    signal loadMoreRequested()

    function syncCurrentSelection() {
        if (!packetListView.model || !root.packetModel) {
            packetListView.currentIndex = -1
            return
        }

        packetListView.currentIndex = root.packetModel.rowForPacketIndex(root.selectedPacketIndex)
    }

    function isTruncated(capturedLength, originalLength) {
        return capturedLength !== originalLength
    }

    function rowBackgroundColor(index, capturedLength, originalLength, isSelected) {
        if (isSelected) {
            return "#dbeafe"
        }

        if (isTruncated(capturedLength, originalLength)) {
            return "#fff8db"
        }

        return index % 2 === 0 ? "#ffffff" : "#f8fafc"
    }

    function directionBackgroundColor(directionText, isSelected) {
        if (isSelected) {
            return "transparent"
        }

        if (directionText === root.forwardDirection) {
            return "#e8f5ee"
        }

        if (directionText === root.reverseDirection) {
            return "#eaf2ff"
        }

        return "transparent"
    }

    function directionTextColor(directionText, isSelected) {
        if (isSelected) {
            return "#0f172a"
        }

        if (directionText === root.forwardDirection) {
            return "#2f6f4f"
        }

        if (directionText === root.reverseDirection) {
            return "#315b91"
        }

        return "#0f172a"
    }

    function capturedBackgroundColor(isIpFragmented, isSelected) {
        if (isSelected || !isIpFragmented) {
            return "transparent"
        }

        return "#fff6d6"
    }

    function capturedTextColor(isIpFragmented, isSelected) {
        if (isSelected) {
            return "#0f172a"
        }

        return isIpFragmented ? "#8a6a12" : "#0f172a"
    }

    function flagTone(flagsText, payloadLength) {
        if (!flagsText || flagsText.length === 0) {
            return "default"
        }

        if ((flagsText === "ACK" || flagsText === "A") && payloadLength === 0) {
            return "default"
        }

        if (flagsText.indexOf("RST") >= 0 || flagsText === "R") {
            return "rst"
        }

        if (flagsText.indexOf("SYN") >= 0 || flagsText === "S" || flagsText === "SA") {
            return "syn"
        }

        if (flagsText.indexOf("FIN") >= 0 || flagsText === "F") {
            return "fin"
        }

        return "default"
    }

    function flagBackgroundColor(flagsText, payloadLength, isSelected) {
        if (isSelected) {
            return "transparent"
        }

        switch (flagTone(flagsText, payloadLength)) {
        case "syn":
            return "#e8f5ee"
        case "fin":
            return "#eef2f7"
        case "rst":
            return "#fdecec"
        default:
            return "transparent"
        }
    }

    function flagTextColor(flagsText, payloadLength, isSelected) {
        if (isSelected) {
            return "#0f172a"
        }

        switch (flagTone(flagsText, payloadLength)) {
        case "syn":
            return "#2f6f4f"
        case "fin":
            return "#475569"
        case "rst":
            return "#9f1239"
        default:
            return "#0f172a"
        }
    }

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    onPacketModelChanged: syncCurrentSelection()
    onSelectedPacketIndexChanged: syncCurrentSelection()

    ColumnLayout {
        anchors.fill: parent
        spacing: 8

        Label {
            text: "Packets"
            font.pixelSize: 18
            font.bold: true
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: "#e2e8f0"
        }

        RowLayout {
            Layout.fillWidth: true
            visible: root.packetsLoading || root.totalPacketRowCount > 0
            spacing: 8

            Label {
                Layout.fillWidth: true
                color: "#6b7280"
                text: root.packetsLoading
                    ? "Loading packet list..."
                    : root.packetsPartiallyLoaded
                        ? "Showing %1 of %2 packets".arg(root.loadedPacketRowCount).arg(root.totalPacketRowCount)
                        : "Showing all %1 packets".arg(root.totalPacketRowCount)
            }

            Button {
                text: "Load more"
                visible: root.canLoadMorePackets
                enabled: root.canLoadMorePackets && !root.packetsLoading
                onClicked: root.loadMoreRequested()
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 10

            Label {
                text: "#"
                font.bold: true
                Layout.preferredWidth: 50
                horizontalAlignment: Text.AlignRight
            }

            Label {
                text: "Direction"
                font.bold: true
                Layout.preferredWidth: 68
                horizontalAlignment: Text.AlignHCenter
            }

            Label {
                text: "Time"
                font.bold: true
                Layout.preferredWidth: 126
            }

            Label {
                text: "Captured"
                font.bold: true
                Layout.preferredWidth: 72
                horizontalAlignment: Text.AlignRight
            }

            Label {
                text: "Payload"
                font.bold: true
                Layout.preferredWidth: 68
                horizontalAlignment: Text.AlignRight
            }

            Label {
                text: "Flags"
                font.bold: true
                Layout.fillWidth: true
            }

            Label {
                text: "Marker"
                font.bold: true
                Layout.preferredWidth: 168
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: "#f8fafc"
            border.color: "#e2e8f0"
            radius: 6

            ListView {
                id: packetListView

                anchors.fill: parent
                anchors.margins: 1
                clip: true
                model: root.packetModel
                currentIndex: -1
                onCountChanged: root.syncCurrentSelection()
                onModelChanged: root.syncCurrentSelection()

                ScrollBar.vertical: ScrollBar {
                    policy: ScrollBar.AsNeeded
                    visible: packetListView.contentHeight > packetListView.height
                }

                delegate: Rectangle {
                    required property int index
                    required property var rowNumber
                    required property var packetIndex
                    required property string directionText
                    required property string timestamp
                    required property int capturedLength
                    required property int originalLength
                    required property int payloadLength
                    required property bool isIpFragmented
                    required property bool suspectedTcpRetransmission
                    required property string tcpFlagsText

                    readonly property bool selected: index === packetListView.currentIndex

                    width: packetListView.width
                    height: 34
                    color: root.rowBackgroundColor(index, capturedLength, originalLength, selected)

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 8
                        anchors.rightMargin: 8
                        spacing: 10

                        Text {
                            text: rowNumber
                            Layout.preferredWidth: 50
                            horizontalAlignment: Text.AlignRight
                            verticalAlignment: Text.AlignVCenter
                        }

                        Rectangle {
                            Layout.preferredWidth: 68
                            implicitHeight: 24
                            radius: 4
                            color: root.directionBackgroundColor(directionText, selected)
                            border.width: color === "transparent" ? 0 : 1
                            border.color: color === "transparent" ? "transparent" : Qt.darker(color, 1.08)

                            Text {
                                anchors.centerIn: parent
                                width: parent.width
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                                text: directionText
                                font.family: "Consolas"
                                color: root.directionTextColor(directionText, selected)
                            }
                        }

                        Text {
                            text: timestamp
                            Layout.preferredWidth: 126
                            font.family: "Consolas"
                            verticalAlignment: Text.AlignVCenter
                        }

                        Rectangle {
                            Layout.preferredWidth: 72
                            implicitHeight: 24
                            radius: 4
                            color: root.capturedBackgroundColor(isIpFragmented, selected)
                            border.width: color === "transparent" ? 0 : 1
                            border.color: color === "transparent" ? "transparent" : Qt.darker(color, 1.08)

                            Text {
                                anchors.centerIn: parent
                                width: parent.width - 12
                                horizontalAlignment: Text.AlignRight
                                verticalAlignment: Text.AlignVCenter
                                text: capturedLength
                                color: root.capturedTextColor(isIpFragmented, selected)
                            }
                        }

                        Text {
                            text: payloadLength
                            Layout.preferredWidth: 68
                            horizontalAlignment: Text.AlignRight
                            verticalAlignment: Text.AlignVCenter
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: 24
                            radius: 4
                            color: root.flagBackgroundColor(tcpFlagsText, payloadLength, selected)
                            border.width: color === "transparent" ? 0 : 1
                            border.color: color === "transparent" ? "transparent" : Qt.darker(color, 1.08)

                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.left: parent.left
                                anchors.leftMargin: 8
                                anchors.right: parent.right
                                anchors.rightMargin: 8
                                text: tcpFlagsText
                                font.family: "Consolas"
                                color: root.flagTextColor(tcpFlagsText, payloadLength, selected)
                                elide: Text.ElideRight
                            }

                            ToolTip.visible: flagsHoverArea.containsMouse && tcpFlagsText.length > 0
                            ToolTip.text: tcpFlagsText

                            MouseArea {
                                id: flagsHoverArea
                                anchors.fill: parent
                                acceptedButtons: Qt.NoButton
                                hoverEnabled: true
                            }
                        }

                        Rectangle {
                            Layout.preferredWidth: 168
                            implicitHeight: 24
                            radius: 4
                            color: suspectedTcpRetransmission && !selected ? "#fff1cc" : "transparent"
                            border.width: color === "transparent" ? 0 : 1
                            border.color: color === "transparent" ? "transparent" : "#d6b55a"

                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.left: parent.left
                                anchors.leftMargin: 8
                                anchors.right: parent.right
                                anchors.rightMargin: 8
                                text: suspectedTcpRetransmission ? "Suspected retransmission" : ""
                                color: selected ? "#0f172a" : "#8a6a12"
                                elide: Text.ElideRight
                                font.pixelSize: 11
                            }

                            ToolTip.visible: markerHoverArea.containsMouse && suspectedTcpRetransmission
                            ToolTip.text: "Suspected retransmission"

                            MouseArea {
                                id: markerHoverArea
                                anchors.fill: parent
                                acceptedButtons: Qt.NoButton
                                hoverEnabled: true
                            }
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: {
                            packetListView.currentIndex = index
                            root.packetSelected(packetIndex)
                        }
                    }
                }
            }

            Label {
                anchors.centerIn: parent
                visible: !root.packetsLoading && packetListView.count === 0
                color: "#64748b"
                text: "Select a flow to inspect packets"
            }
        }
    }
}
