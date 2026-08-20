import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    objectName: "advancedFlowFilterProtocolPathSelectorDialog"

    property var selector: null
    signal selectRequested()

    readonly property real tablePadding: 10
    readonly property real indentWidth: 18
    readonly property real labelColumnWidth: 520
    readonly property real flowsColumnWidth: 120
    readonly property real packetsColumnWidth: 120
    readonly property real originalBytesColumnWidth: 140
    readonly property real tableColumnSpacing: 16
    readonly property real tableWidth: tablePadding
        + labelColumnWidth
        + tableColumnSpacing
        + flowsColumnWidth
        + tableColumnSpacing
        + packetsColumnWidth
        + tableColumnSpacing
        + originalBytesColumnWidth
        + tablePadding
    readonly property int rowHeight: 34

    width: 1040
    height: 720
    modal: true
    focus: true
    title: "Select Protocol Path"
    closePolicy: Popup.CloseOnEscape

    onClosed: {
        if (selector) {
            selector.clearSelection()
        }
    }

    contentItem: Item {
        implicitWidth: 1040
        implicitHeight: selectorContentLayout.implicitHeight + 24

        ColumnLayout {
            id: selectorContentLayout
            anchors.fill: parent
            anchors.margins: 18
            spacing: 14

            Rectangle {
                color: "#f8fafc"
                border.color: "#cbd5e1"
                radius: 6
                implicitHeight: modeButtonLayout.implicitHeight + 4
                implicitWidth: modeButtonLayout.implicitWidth + 8

                RowLayout {
                    id: modeButtonLayout
                    anchors.fill: parent
                    anchors.margins: 2
                    spacing: 2

                    ButtonGroup {
                        id: selectorModeButtonGroup
                    }

                    Button {
                        objectName: "advancedFlowFilterProtocolPathKindOverviewModeButton"
                        text: "Kind overview"
                        checkable: true
                        checked: root.selector ? root.selector.mode === 0 : false
                        enabled: root.selector ? root.selector.hasCapture : false
                        ButtonGroup.group: selectorModeButtonGroup
                        onClicked: {
                            if (root.selector && root.selector.mode !== 0) {
                                root.selector.setMode(0)
                            }
                        }
                    }

                    Button {
                        objectName: "advancedFlowFilterProtocolPathIdentityTreeModeButton"
                        text: "Identity tree"
                        checkable: true
                        checked: root.selector ? root.selector.mode === 1 : false
                        enabled: root.selector ? root.selector.hasCapture : false
                        ButtonGroup.group: selectorModeButtonGroup
                        onClicked: {
                            if (root.selector && root.selector.mode !== 1) {
                                root.selector.setMode(1)
                            }
                        }
                    }

                    Button {
                        objectName: "advancedFlowFilterProtocolPathTerminalPathsModeButton"
                        text: "Terminal paths"
                        checkable: true
                        checked: root.selector ? root.selector.mode === 2 : false
                        enabled: root.selector ? root.selector.hasCapture : false
                        ButtonGroup.group: selectorModeButtonGroup
                        onClicked: {
                            if (root.selector && root.selector.mode !== 2) {
                                root.selector.setMode(2)
                            }
                        }
                    }
                }
            }

            Label {
                objectName: "advancedFlowFilterProtocolPathSelectorStatusLabel"
                Layout.fillWidth: true
                visible: text.length > 0
                text: root.selector ? root.selector.statusText : ""
                color: "#64748b"
                font.pixelSize: 12
                wrapMode: Text.WordWrap
            }

            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 36
                radius: 6
                color: "#f8fafc"
                border.color: "#dbe4f0"

                Item {
                    anchors.fill: parent
                    anchors.leftMargin: root.tablePadding
                    anchors.rightMargin: root.tablePadding

                    Label {
                        x: 0
                        width: root.labelColumnWidth
                        anchors.verticalCenter: parent.verticalCenter
                        text: "Path / Layer"
                        color: "#334155"
                        font.bold: true
                        elide: Text.ElideRight
                    }

                    Label {
                        x: root.labelColumnWidth + root.tableColumnSpacing
                        width: root.flowsColumnWidth
                        anchors.verticalCenter: parent.verticalCenter
                        horizontalAlignment: Text.AlignRight
                        text: "Flows"
                        color: "#334155"
                        font.bold: true
                    }

                    Label {
                        x: root.labelColumnWidth + root.tableColumnSpacing + root.flowsColumnWidth + root.tableColumnSpacing
                        width: root.packetsColumnWidth
                        anchors.verticalCenter: parent.verticalCenter
                        horizontalAlignment: Text.AlignRight
                        text: "Packets"
                        color: "#334155"
                        font.bold: true
                    }

                    Label {
                        x: root.labelColumnWidth + root.tableColumnSpacing + root.flowsColumnWidth + root.tableColumnSpacing
                            + root.packetsColumnWidth + root.tableColumnSpacing
                        width: root.originalBytesColumnWidth
                        anchors.verticalCenter: parent.verticalCenter
                        horizontalAlignment: Text.AlignRight
                        text: "Original Bytes"
                        color: "#334155"
                        font.bold: true
                    }
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                color: "#ffffff"
                border.color: "#dbe4f0"
                radius: 6
                clip: true

                ListView {
                    id: selectorListView
                    objectName: "advancedFlowFilterProtocolPathSelectorListView"
                    anchors.fill: parent
                    anchors.margins: 1
                    clip: true
                    model: root.selector ? root.selector.statsModel : null
                    boundsBehavior: Flickable.StopAtBounds
                    reuseItems: true
                    cacheBuffer: root.rowHeight * 16

                    ScrollBar.vertical: AppScrollBar {
                        policy: selectorListView.contentHeight > selectorListView.height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
                    }

                    delegate: Rectangle {
                        required property string layerText
                        required property string pathText
                        required property string flowCountText
                        required property string packetCountText
                        required property string originalByteCountText
                        required property var nodeId
                        required property int depth
                        required property int rowIndex
                        required property bool selected
                        required property string tooltipText

                        width: selectorListView.width
                        height: root.rowHeight
                        color: selected ? "#e0f2fe" : (rowIndex % 2 === 0 ? "transparent" : "#f8fafc")

                        Item {
                            anchors.fill: parent
                            anchors.leftMargin: root.tablePadding
                            anchors.rightMargin: root.tablePadding

                            Label {
                                x: Math.max(0, depth) * root.indentWidth
                                width: Math.max(0, root.labelColumnWidth - x)
                                anchors.verticalCenter: parent.verticalCenter
                                text: layerText
                                color: "#0f172a"
                                elide: Text.ElideRight

                                ToolTip.visible: selectorRowHoverHandler.hovered
                                    && tooltipText.length > 0
                                    && implicitWidth > width + 1
                                ToolTip.text: tooltipText
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    if (root.selector) {
                                        root.selector.selectNode(nodeId)
                                    }
                                }
                            }

                            HoverHandler {
                                id: selectorRowHoverHandler
                            }

                            Label {
                                x: root.labelColumnWidth + root.tableColumnSpacing
                                width: root.flowsColumnWidth
                                anchors.verticalCenter: parent.verticalCenter
                                horizontalAlignment: Text.AlignRight
                                text: flowCountText
                                color: "#334155"
                                elide: Text.ElideLeft
                            }

                            Label {
                                x: root.labelColumnWidth + root.tableColumnSpacing + root.flowsColumnWidth + root.tableColumnSpacing
                                width: root.packetsColumnWidth
                                anchors.verticalCenter: parent.verticalCenter
                                horizontalAlignment: Text.AlignRight
                                text: packetCountText
                                color: "#334155"
                                elide: Text.ElideLeft
                            }

                            Label {
                                x: root.labelColumnWidth + root.tableColumnSpacing + root.flowsColumnWidth + root.tableColumnSpacing
                                    + root.packetsColumnWidth + root.tableColumnSpacing
                                width: root.originalBytesColumnWidth
                                anchors.verticalCenter: parent.verticalCenter
                                horizontalAlignment: Text.AlignRight
                                text: originalByteCountText
                                color: "#334155"
                                elide: Text.ElideLeft
                            }
                        }
                    }
                }
            }
        }
    }

    footer: DialogButtonBox {
        contentItem: RowLayout {
            spacing: 8

            Item {
                Layout.fillWidth: true
            }

            Button {
                objectName: "advancedFlowFilterProtocolPathSelectorCancelButton"
                text: "Cancel"
                onClicked: root.close()
            }

            Button {
                objectName: "advancedFlowFilterProtocolPathSelectorSelectButton"
                text: "Select"
                highlighted: true
                enabled: root.selector ? root.selector.selectionAvailable : false
                onClicked: root.selectRequested()
            }
        }
    }
}
