import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root

    property var protocolCatalog: []
    readonly property var categoryOrder: [
        "link_and_encapsulation",
        "network",
        "transport",
        "tunnels_and_overlays",
        "security",
        "application"
    ]

    function rowsForCategory(categoryId) {
        return (protocolCatalog || []).filter(function(row) {
            return row.categoryId === categoryId
        })
    }

    function categoryLabel(categoryId) {
        const rows = rowsForCategory(categoryId)
        return rows.length > 0 ? rows[0].categoryLabel : ""
    }

    function badgeFill(statusId) {
        switch (statusId) {
        case "yes":
            return "#eefbf3"
        case "partial":
            return "#fff7e6"
        case "no":
            return "#e5e7eb"
        default:
            return "#f1f5f9"
        }
    }

    function badgeBorder(statusId) {
        switch (statusId) {
        case "yes":
            return "#b7e4c7"
        case "partial":
            return "#f2d7a6"
        case "no":
            return "#cbd5e1"
        default:
            return "#d8dee9"
        }
    }

    function badgeText(statusId) {
        return "#0f172a"
    }

    width: 1120
    height: 760
    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
    title: "Supported Protocols"

    contentItem: ScrollView {
        clip: true
        contentWidth: availableWidth
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

        ColumnLayout {
            width: parent.width
            spacing: 14

            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: "#475569"
                text: "Recognition means the protocol is recognized in flow classification, detected protocol, protocol path, or protocol-aware inspection. Service means the protocol can provide meaningful Service text for a flow."
            }

            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: "#475569"
                text: "Packet Summary means structured protocol details are available in Packet Details -> Summary. Stream means protocol-aware semantic items are available in the selected-flow Stream. Partial means useful support exists with known limitations. N/A means the capability is not meaningful for that protocol."
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 10

                Repeater {
                    model: [
                        { stableId: "yes", label: "Yes" },
                        { stableId: "partial", label: "Partial" },
                        { stableId: "no", label: "No" },
                        { stableId: "not_applicable", label: "N/A" }
                    ]

                    delegate: Rectangle {
                        required property var modelData

                        radius: 10
                        color: root.badgeFill(modelData.stableId)
                        border.color: root.badgeBorder(modelData.stableId)
                        border.width: 1
                        implicitHeight: 28
                        implicitWidth: labelItem.implicitWidth + 18

                        Label {
                            id: labelItem
                            anchors.centerIn: parent
                            text: modelData.label
                            color: root.badgeText(modelData.stableId)
                            font.pixelSize: 12
                            font.bold: false
                        }
                    }
                }
            }

            Repeater {
                model: root.categoryOrder

                delegate: ColumnLayout {
                    required property string modelData

                    visible: root.rowsForCategory(modelData).length > 0
                    Layout.fillWidth: true
                    spacing: 8

                    Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: 34
                        radius: 8
                        color: "#f8fafc"
                        border.color: "#e2e8f0"

                        Label {
                            anchors.fill: parent
                            anchors.leftMargin: 12
                            verticalAlignment: Text.AlignVCenter
                            text: root.categoryLabel(modelData)
                            color: "#0f172a"
                            font.pixelSize: 14
                            font.bold: true
                        }
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 6
                        columnSpacing: 10
                        rowSpacing: 8

                        Label { text: "Protocol"; font.bold: true; color: "#334155"; Layout.preferredWidth: 180 }
                        Label { text: "Recognition"; font.bold: true; color: "#334155"; Layout.preferredWidth: 110 }
                        Label { text: "Service"; font.bold: true; color: "#334155"; Layout.preferredWidth: 100 }
                        Label { text: "Packet Summary"; font.bold: true; color: "#334155"; Layout.preferredWidth: 130 }
                        Label { text: "Stream"; font.bold: true; color: "#334155"; Layout.preferredWidth: 100 }
                        Label { text: "Notes"; font.bold: true; color: "#334155"; Layout.fillWidth: true }

                        Repeater {
                            model: root.rowsForCategory(modelData)

                            delegate: Item {
                                required property var modelData
                                Layout.fillWidth: true
                                Layout.columnSpan: 6
                                implicitHeight: rowLayout.implicitHeight + 8

                                RowLayout {
                                    id: rowLayout
                                    anchors.fill: parent
                                    spacing: 10

                                    Label {
                                        text: modelData.protocol
                                        color: "#0f172a"
                                        font.bold: true
                                        Layout.preferredWidth: 180
                                        wrapMode: Text.WordWrap
                                    }

                                    Repeater {
                                        model: [
                                            { stableId: modelData.recognitionStatusId, label: modelData.recognitionStatusLabel, width: 110 },
                                            { stableId: modelData.serviceStatusId, label: modelData.serviceStatusLabel, width: 100 },
                                            { stableId: modelData.packetSummaryStatusId, label: modelData.packetSummaryStatusLabel, width: 130 },
                                            { stableId: modelData.streamStatusId, label: modelData.streamStatusLabel, width: 100 }
                                        ]

                                        delegate: Rectangle {
                                            required property var modelData
                                            Layout.preferredWidth: modelData.width
                                            implicitHeight: 28
                                            radius: 10
                                            color: root.badgeFill(modelData.stableId)
                                            border.color: root.badgeBorder(modelData.stableId)
                                            border.width: 1

                                            Label {
                                                anchors.centerIn: parent
                                                text: modelData.label
                                                color: root.badgeText(modelData.stableId)
                                                font.pixelSize: 12
                                                font.bold: false
                                            }
                                        }
                                    }

                                    Label {
                                        text: modelData.notes
                                        color: "#475569"
                                        wrapMode: Text.WordWrap
                                        Layout.fillWidth: true
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    footer: DialogButtonBox {
        standardButtons: DialogButtonBox.Ok
        onAccepted: root.close()
    }
}
