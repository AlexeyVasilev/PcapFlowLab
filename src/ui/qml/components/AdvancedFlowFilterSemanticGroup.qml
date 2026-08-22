import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root

    property string title: ""
    property color titleColor: "#475569"
    property color fillColor: "transparent"
    property color strokeColor: "transparent"
    property string contentObjectName: ""
    property string actionText: ""
    property string actionObjectName: ""
    property bool actionVisible: false

    signal actionTriggered()

    default property alias contentData: contentColumn.data

    radius: 6
    color: fillColor
    border.color: strokeColor
    implicitHeight: contentColumn.implicitHeight + 14

    ColumnLayout {
        id: contentColumn
        objectName: root.contentObjectName
        anchors.fill: parent
        anchors.margins: 7
        spacing: 6

        RowLayout {
            Layout.fillWidth: true
            spacing: 6

            Label {
                text: root.title
                color: root.titleColor
                font.pixelSize: 12
                font.bold: true
            }

            Item {
                Layout.fillWidth: true
            }

            Button {
                objectName: root.actionObjectName
                visible: root.actionVisible
                text: root.actionText
                flat: true
                padding: 2
                onClicked: root.actionTriggered()
            }
        }
    }
}
