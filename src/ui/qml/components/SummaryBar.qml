import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var packetCount: 0
    property var flowCount: 0
    property var capturedBytes: 0
    property string capturedBytesText: ""
    property var originalBytes: 0
    property string originalBytesText: ""
    property bool hasCapture: false

    function groupInteger(value) {
        const digits = Math.max(0, Math.round(Number(value || 0))).toString()
        return digits.replace(/\B(?=(\d{3})+(?!\d))/g, " ")
    }

    component StatChip: Frame {
        id: chip

        required property string title
        required property string valueText

        Layout.fillWidth: true
        padding: 10

        background: Rectangle {
            color: "#ffffff"
            border.color: "#d8dee9"
            radius: 6
        }

        ColumnLayout {
            id: chipLayout
            anchors.fill: parent
            spacing: 3

            Label {
                text: chip.title
                color: "#64748b"
                font.pixelSize: 12
            }

            Label {
                text: chip.valueText
                font.bold: true
                font.pixelSize: 18
                color: "#0f172a"
            }
        }
    }

    padding: 0
    background: Rectangle {
        color: "#f8fafc"
        border.color: "#d8dee9"
        radius: 8
    }

    RowLayout {
        anchors.fill: parent
        anchors.margins: 8
        spacing: 10

        StatChip {
            title: "Packets"
            valueText: root.hasCapture ? root.groupInteger(root.packetCount) : "-"
        }

        StatChip {
            title: "Flows"
            valueText: root.hasCapture ? root.groupInteger(root.flowCount) : "-"
        }

        StatChip {
            title: "Original bytes"
            valueText: root.hasCapture ? root.originalBytesText : "-"
        }

        StatChip {
            title: "Captured bytes"
            valueText: root.hasCapture ? root.capturedBytesText : "-"
        }
    }
}
