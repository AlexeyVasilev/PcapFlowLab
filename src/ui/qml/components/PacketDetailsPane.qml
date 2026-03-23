import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label {
            text: "Packet Details"
            font.pixelSize: 18
            font.bold: true
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: "#e2e8f0"
        }

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: "#64748b"
            text: "Packet details and hex view integration is next. This pane will attach to the existing lazy packet access and on-demand decode services."
        }
    }
}
