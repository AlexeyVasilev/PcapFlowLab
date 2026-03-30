import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var packetModel: null
    property var selectedPacketIndex: -1
    readonly property string forwardDirection: "A\u2192B"
    readonly property string reverseDirection: "B\u2192A"

    signal packetSelected(var packetIndex)

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
        spacing: 10

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
            spacing: 12

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
                    required property string tcpFlagsText

                    readonly property bool selected: index === packetListView.currentIndex

                    width: packetListView.width
                    height: 38
                    color: root.rowBackgroundColor(index, capturedLength, originalLength, selected)

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 10
                        anchors.rightMargin: 10
                        spacing: 12

                        Text {
                            text: rowNumber
                            Layout.preferredWidth: 50
                            horizontalAlignment: Text.AlignRight
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
                visible: packetListView.count === 0
                color: "#64748b"
                text: "No packets for selected flow"
            }
        }
    }
}
