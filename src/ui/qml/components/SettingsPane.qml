import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property bool httpUsePathAsServiceHint: false
    property bool usePossibleTlsQuic: false
    property bool showWiresharkFilterForSelectedFlow: true

    signal httpUsePathAsServiceHintChangedByUser(bool enabled)
    signal usePossibleTlsQuicChangedByUser(bool enabled)
    signal showWiresharkFilterForSelectedFlowChangedByUser(bool enabled)

    implicitWidth: 560
    implicitHeight: contentColumn.implicitHeight + 24

    ColumnLayout {
        id: contentColumn
        anchors.fill: parent
        anchors.margins: 12
        spacing: 12

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: "#475569"
            text: "Settings control how new captures are interpreted and how current results are presented."
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4

            CheckBox {
                Layout.fillWidth: true
                text: "HTTP: use request path as service hint when Host is missing"
                checked: root.httpUsePathAsServiceHint
                onToggled: root.httpUsePathAsServiceHintChangedByUser(checked)
            }

            Label {
                Layout.fillWidth: true
                Layout.leftMargin: 28
                wrapMode: Text.WordWrap
                color: "#64748b"
                font.pixelSize: 12
                text: "Applied when opening a capture or index"
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4

            CheckBox {
                Layout.fillWidth: true
                text: "Use possible TLS/QUIC"
                checked: root.usePossibleTlsQuic
                onToggled: root.usePossibleTlsQuicChangedByUser(checked)
            }

            Label {
                Layout.fillWidth: true
                Layout.leftMargin: 28
                wrapMode: Text.WordWrap
                color: "#64748b"
                font.pixelSize: 12
                text: "Applied immediately to the current view and statistics"
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4

            CheckBox {
                Layout.fillWidth: true
                text: "Show Wireshark filter for selected flow"
                checked: root.showWiresharkFilterForSelectedFlow
                onToggled: root.showWiresharkFilterForSelectedFlowChangedByUser(checked)
            }

            Label {
                Layout.fillWidth: true
                Layout.leftMargin: 28
                wrapMode: Text.WordWrap
                color: "#64748b"
                font.pixelSize: 12
                text: "Applied immediately to the selected-flow view"
            }
        }

        Item {
            Layout.fillHeight: true
        }
    }
}
