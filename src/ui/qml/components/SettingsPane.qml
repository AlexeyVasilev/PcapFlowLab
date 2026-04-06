import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property bool httpUsePathAsServiceHint: false
    property bool usePossibleTlsQuic: false

    signal httpUsePathAsServiceHintChangedByUser(bool enabled)
    signal usePossibleTlsQuicChangedByUser(bool enabled)

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
            text: "Most settings are applied when opening a capture. Possible TLS/QUIC fallback updates the current view immediately because it only uses existing flow metadata."
        }

        CheckBox {
            Layout.fillWidth: true
            text: "HTTP: use request path as service hint when Host is missing"
            checked: root.httpUsePathAsServiceHint
            onToggled: root.httpUsePathAsServiceHintChangedByUser(checked)
        }

        CheckBox {
            Layout.fillWidth: true
            text: "Use possible TLS/QUIC"
            checked: root.usePossibleTlsQuic
            onToggled: root.usePossibleTlsQuicChangedByUser(checked)
        }

        Item {
            Layout.fillHeight: true
        }
    }
}
