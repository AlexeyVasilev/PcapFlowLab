import QtQuick
import QtQuick.Controls

ToolButton {
    id: root

    property string accessibleLabel: "Remove rule"
    property string tooltipText: "Remove rule"

    text: "\u00d7"
    font.pixelSize: 15
    padding: 2
    implicitWidth: 24
    implicitHeight: 24

    Accessible.name: accessibleLabel
    ToolTip.visible: hovered
    ToolTip.text: tooltipText
}
