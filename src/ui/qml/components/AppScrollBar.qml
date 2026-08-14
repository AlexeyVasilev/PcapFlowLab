import QtQuick
import QtQuick.Controls

ScrollBar {
    id: root

    readonly property bool verticalBar: orientation === Qt.Vertical
    readonly property bool overflowVisible: policy !== ScrollBar.AlwaysOff && size < 1.0
    readonly property real thickness: 11

    implicitWidth: verticalBar ? thickness : 0
    implicitHeight: verticalBar ? 0 : thickness
    visible: overflowVisible
    interactive: overflowVisible
    hoverEnabled: overflowVisible
    padding: 1

    contentItem: Rectangle {
        radius: root.verticalBar ? width / 2 : height / 2
        color: root.pressed
            ? "#6b7f95"
            : root.hovered
                ? "#8196ad"
                : "#97aabd"
        opacity: root.overflowVisible ? 1 : 0
    }

    background: Rectangle {
        radius: root.verticalBar ? width / 2 : height / 2
        color: "#edf2f7"
        border.color: "#d8e2ee"
        border.width: 1
        opacity: root.overflowVisible ? 1 : 0
    }
}
