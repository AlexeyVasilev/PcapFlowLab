import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var packetCount: 0
    property var flowCount: 0
    property var totalBytes: 0
    property bool hasCapture: false

    background: Rectangle {
        color: "#f8fafc"
        border.color: "#d8dee9"
        radius: 8
    }

    RowLayout {
        anchors.fill: parent
        spacing: 24

        Label {
            text: root.hasCapture ? "Packets: " + root.packetCount : "Packets: -"
        }

        Label {
            text: root.hasCapture ? "Flows: " + root.flowCount : "Flows: -"
        }

        Label {
            text: root.hasCapture ? "Bytes: " + root.totalBytes : "Bytes: -"
        }
    }
}

