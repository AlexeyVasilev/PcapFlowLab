import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property bool httpUsePathAsServiceHint: false

    signal httpUsePathAsServiceHintChangedByUser(bool enabled)

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ScrollView {
        anchors.fill: parent
        anchors.margins: 8
        clip: true

        ColumnLayout {
            width: parent.width
            spacing: 12

            Label {
                text: "Settings"
                font.pixelSize: 18
                font.bold: true
            }

            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: "#475569"
                text: "Settings are applied when opening a capture. They do not retroactively reanalyze the current capture or index."
            }

            CheckBox {
                text: "HTTP: use request path as service hint when Host is missing"
                checked: root.httpUsePathAsServiceHint
                onToggled: root.httpUsePathAsServiceHintChangedByUser(checked)
            }

            Item {
                Layout.fillHeight: true
            }
        }
    }
}
