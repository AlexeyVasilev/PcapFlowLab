import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property string title: ""
    property string summaryText: ""
    property bool expanded: false
    default property alias sectionContent: contentColumn.data

    signal expandedChangedByUser(bool expanded)

    Layout.fillWidth: true
    padding: 0

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 10
        spacing: 10

        Button {
            id: headerButton
            objectName: root.title.length > 0 ? root.title.replace(/\s+/g, "") + "ToggleButton" : ""
            Layout.fillWidth: true
            flat: true
            focusPolicy: Qt.StrongFocus
            Accessible.name: root.title

            onClicked: root.expandedChangedByUser(!root.expanded)

            contentItem: RowLayout {
                spacing: 10

                Label {
                    text: root.expanded ? "\u25BC" : "\u25B6"
                    color: "#475569"
                    font.pixelSize: 12
                    Layout.alignment: Qt.AlignVCenter
                }

                Label {
                    Layout.fillWidth: true
                    text: root.title
                    font.pixelSize: 16
                    font.bold: true
                    color: "#0f172a"
                    elide: Text.ElideRight
                }

                Label {
                    visible: root.summaryText.length > 0
                    text: root.summaryText
                    color: "#64748b"
                    font.pixelSize: 12
                    elide: Text.ElideRight
                }
            }

            background: Rectangle {
                radius: 6
                color: headerButton.down
                    ? "#e2e8f0"
                    : (headerButton.hovered ? "#f8fafc" : "transparent")
                border.color: headerButton.activeFocus ? "#93c5fd" : "transparent"
                border.width: headerButton.activeFocus ? 1 : 0
            }
        }

        ColumnLayout {
            id: contentColumn
            Layout.fillWidth: true
            visible: root.expanded
            spacing: 10
        }
    }
}
