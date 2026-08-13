import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property string title: ""
    property string summaryText: ""
    property string toggleObjectName: ""
    property bool expanded: false
    default property alias sectionContent: contentColumn.data

    signal expandedChangedByUser(bool expanded)

    Layout.fillWidth: true
    Layout.minimumWidth: 0
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
            objectName: root.toggleObjectName
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            flat: true
            focusPolicy: Qt.StrongFocus
            Accessible.name: root.title

            onClicked: root.expandedChangedByUser(!root.expanded)

            contentItem: RowLayout {
                anchors.fill: parent
                spacing: 10

                Label {
                    text: root.expanded ? "\u25BC" : "\u25B6"
                    color: "#475569"
                    font.pixelSize: 12
                    Layout.alignment: Qt.AlignVCenter
                }

                Label {
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                    text: root.title
                    font.pixelSize: 16
                    font.bold: true
                    color: "#0f172a"
                    elide: Text.ElideRight
                }

                Label {
                    visible: root.summaryText.length > 0
                    Layout.minimumWidth: 0
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
            Layout.minimumWidth: 0
            visible: root.expanded
            spacing: 10
        }
    }
}
