import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var flowCount: 0

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label {
            text: "Flows"
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

            Label {
                text: "Family / Protocol"
                font.bold: true
                Layout.fillWidth: true
            }

            Label {
                text: "Packets"
                font.bold: true
            }

            Label {
                text: "Bytes"
                font.bold: true
            }
        }

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: "#64748b"
            text: root.flowCount > 0
                ? "Flow table integration is next. The current session already exposes " + root.flowCount + " flows through C++."
                : "Flow table integration is next. Load a capture or index to populate the first model."
        }
    }
}

