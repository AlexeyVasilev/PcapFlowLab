import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root

    signal exportRequested(
        int flowScopeMode,
        int baseSelectionMode,
        string packetCountText,
        string originalBytesText,
        bool includeLastPacket,
        bool includeEveryKthPacket,
        string everyKText
    )

    modal: true
    focus: true
    title: "Smart Export"
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
    standardButtons: Dialog.Ok | Dialog.Cancel

    property int flowScopeMode: currentFlowRadio.checked ? 0 : selectedFlowsRadio.checked ? 1 : unselectedFlowsRadio.checked ? 2 : 3
    property int baseSelectionMode: allPacketsRadio.checked ? 0 : firstNPacketsRadio.checked ? 1 : 2
    readonly property bool extrasEnabled: !allPacketsRadio.checked

    onAccepted: {
        exportRequested(
            flowScopeMode,
            baseSelectionMode,
            packetCountField.text,
            originalBytesField.text,
            includeLastPacketCheck.checked,
            includeEveryKthPacketCheck.checked,
            everyKField.text
        )
        close()
    }
    onRejected: close()

    contentItem: Item {
        implicitWidth: 560
        implicitHeight: contentLayout.implicitHeight + 24

        ColumnLayout {
            id: contentLayout
            anchors.fill: parent
            anchors.margins: 18
            spacing: 14

            GroupBox {
                Layout.fillWidth: true
                title: "Flows to export"

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 8

                    RadioButton {
                        id: currentFlowRadio
                        text: "Current flow"
                        checked: true
                    }

                    RadioButton {
                        id: selectedFlowsRadio
                        text: "Selected flows"
                    }

                    RadioButton {
                        id: unselectedFlowsRadio
                        text: "Unselected flows"
                    }

                    RadioButton {
                        id: allFlowsRadio
                        text: "All flows"
                    }
                }
            }

            GroupBox {
                Layout.fillWidth: true
                title: "Base packet selection"

                GridLayout {
                    anchors.fill: parent
                    columns: 2
                    columnSpacing: 12
                    rowSpacing: 8

                    RadioButton {
                        id: allPacketsRadio
                        text: "All packets"
                        checked: true
                        onToggled: {
                            if (checked) {
                                includeLastPacketCheck.checked = false
                                includeEveryKthPacketCheck.checked = false
                            }
                        }
                    }

                    Item {
                        Layout.fillWidth: true
                        implicitHeight: 1
                    }

                    RadioButton {
                        id: firstNPacketsRadio
                        text: "First N packets"
                    }

                    TextField {
                        id: packetCountField
                        Layout.fillWidth: true
                        enabled: firstNPacketsRadio.checked
                        placeholderText: "Packet count"
                        text: "30"
                    }

                    RadioButton {
                        id: firstMBytesRadio
                        text: "First M original bytes"
                    }

                    TextField {
                        id: originalBytesField
                        Layout.fillWidth: true
                        enabled: firstMBytesRadio.checked
                        placeholderText: "Original bytes"
                        text: "50000"
                    }

                    Item {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        implicitHeight: thresholdHint.implicitHeight

                        Label {
                            id: thresholdHint
                            anchors.fill: parent
                            text: "Include the packet that crosses the threshold."
                            color: "#64748b"
                            wrapMode: Text.WordWrap
                            font.pixelSize: 12
                        }
                    }
                }
            }

            GroupBox {
                Layout.fillWidth: true
                title: "Additional packet retention"

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 8

                    CheckBox {
                        id: includeLastPacketCheck
                        enabled: root.extrasEnabled
                        text: "Include last packet"
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 12

                        CheckBox {
                            id: includeEveryKthPacketCheck
                            enabled: root.extrasEnabled
                            text: "Include every K-th packet after the base prefix"
                        }

                        TextField {
                            id: everyKField
                            Layout.preferredWidth: 120
                            enabled: root.extrasEnabled && includeEveryKthPacketCheck.checked
                            placeholderText: "K"
                            text: "10"
                        }
                    }

                    Label {
                        Layout.fillWidth: true
                        text: root.extrasEnabled
                            ? "Packets are exported when they match the base rule or one of the enabled extras."
                            : "Additional retention is disabled when base mode is All packets."
                        color: "#64748b"
                        wrapMode: Text.WordWrap
                        font.pixelSize: 12
                    }
                }
            }
        }
    }
}
