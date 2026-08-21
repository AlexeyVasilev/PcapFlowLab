import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root

    property string title: ""
    property string summaryText: ""
    property bool expanded: false
    property bool sectionEnabled: true
    property bool contentEnabled: true
    property string sectionObjectName: ""
    property string collapseButtonObjectName: ""
    property string enabledCheckBoxObjectName: ""
    property string contentObjectName: ""
    property string collapseToolTipText: expanded ? "Collapse " + title : "Expand " + title

    signal toggleRequested()
    signal sectionEnabledToggled(bool checked)

    default property alias sectionContent: contentColumn.data

    objectName: sectionObjectName
    radius: 8
    color: "white"
    border.color: "#dbe4f0"
    implicitHeight: cardLayout.implicitHeight + 28

    ColumnLayout {
        id: cardLayout
        x: 14
        y: 14
        width: parent.width - 28
        spacing: 10

        RowLayout {
            Layout.fillWidth: true
            spacing: 8

            ToolButton {
                objectName: collapseButtonObjectName
                text: root.expanded ? "\u25be" : "\u25b8"
                onClicked: root.toggleRequested()
                ToolTip.visible: hovered
                ToolTip.text: root.collapseToolTipText
            }

            Button {
                Layout.fillWidth: true
                flat: true
                padding: 0
                horizontalPadding: 0
                verticalPadding: 0
                onClicked: root.toggleRequested()

                background: Item {}

                contentItem: RowLayout {
                    spacing: 10

                    Label {
                        text: root.title
                        color: "#0f172a"
                        font.pixelSize: 14
                        font.bold: true
                    }

                    Label {
                        Layout.fillWidth: true
                        text: root.summaryText
                        visible: text.length > 0
                        color: "#64748b"
                        font.pixelSize: 12
                        elide: Text.ElideRight
                    }
                }
            }

            CheckBox {
                objectName: enabledCheckBoxObjectName
                text: "Enabled"
                checked: root.sectionEnabled
                onToggled: root.sectionEnabledToggled(checked)
            }
        }

        Item {
            id: contentWrapper
            objectName: contentObjectName
            Layout.fillWidth: true
            Layout.preferredHeight: visible ? implicitHeight : 0
            implicitHeight: contentColumn.implicitHeight
            visible: root.expanded

            ColumnLayout {
                id: contentColumn
                anchors.left: parent.left
                anchors.right: parent.right
                spacing: 10
                enabled: root.contentEnabled
                opacity: root.contentEnabled ? 1.0 : 0.55
            }
        }
    }
}
