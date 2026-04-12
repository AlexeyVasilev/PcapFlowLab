import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var packetDetailsModel: null

    function isStreamItemDetails() {
        return !!root.packetDetailsModel && root.packetDetailsModel.streamItemDetails
    }

    function detailsTitle() {
        if (!root.packetDetailsModel) {
            return "Packet Details"
        }

        return root.packetDetailsModel.detailsTitle
    }

    function emptyText() {
        return "Select a packet or stream item to inspect details"
    }

    function summaryText() {
        if (!root.packetDetailsModel || !root.packetDetailsModel.hasPacket) {
            return root.emptyText()
        }

        return root.packetDetailsModel.summaryText
    }

    function headerPrimaryText() {
        if (!root.packetDetailsModel || !root.packetDetailsModel.hasPacket) {
            return ""
        }

        return root.packetDetailsModel.headerPrimaryText
    }

    function headerSecondaryText() {
        if (!root.packetDetailsModel || !root.packetDetailsModel.hasPacket) {
            return ""
        }

        return root.packetDetailsModel.headerSecondaryText
    }

    function badgeText() {
        if (!root.packetDetailsModel || !root.packetDetailsModel.hasPacket) {
            return ""
        }

        return root.packetDetailsModel.badgeText
    }

    function payloadTabTitle() {
        if (!root.packetDetailsModel || !root.packetDetailsModel.hasPacket) {
            return "Payload"
        }

        return root.packetDetailsModel.payloadTabTitle
    }

    function warningBlockText(summary) {
        const marker = "\n\nWarnings\n"
        const start = summary.indexOf(marker)
        if (start < 0) {
            return ""
        }

        const contentStart = start + marker.length
        const nextSection = summary.indexOf("\n\n", contentStart)
        const warningLines = nextSection >= 0
            ? summary.slice(contentStart, nextSection)
            : summary.slice(contentStart)
        return warningLines.trim()
    }

    function summaryBodyText(summary) {
        const marker = "\n\nWarnings\n"
        const start = summary.indexOf(marker)
        if (start < 0) {
            return summary
        }

        const contentStart = start + marker.length
        const nextSection = summary.indexOf("\n\n", contentStart)
        if (nextSection < 0) {
            return summary.slice(0, start)
        }

        return summary.slice(0, start) + summary.slice(nextSection)
    }

    component TextPane: Rectangle {
        property string viewText: ""
        property bool monospace: false

        color: "#f8fafc"
        border.color: "#e2e8f0"
        radius: 6

        ScrollView {
            anchors.fill: parent
            anchors.margins: 1
            clip: true

            TextArea {
                readOnly: true
                selectByMouse: true
                wrapMode: monospace ? TextEdit.NoWrap : TextEdit.Wrap
                font.family: monospace ? "Consolas" : ""
                font.pixelSize: monospace ? 12 : 13
                padding: 8
                text: viewText
            }
        }
    }

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 6

        Label {
            text: root.detailsTitle()
            font.pixelSize: 18
            font.bold: true
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: "#e2e8f0"
        }

        Rectangle {
            Layout.fillWidth: true
            visible: root.isStreamItemDetails() && root.headerPrimaryText().length > 0
            color: "#f8fafc"
            border.color: "#dbe4ee"
            radius: 8
            implicitHeight: headerColumn.implicitHeight + 20

            ColumnLayout {
                id: headerColumn
                anchors.fill: parent
                anchors.margins: 8
                spacing: 3

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 8

                    Label {
                        Layout.fillWidth: true
                        text: root.headerPrimaryText()
                        font.pixelSize: 15
                        font.bold: true
                        color: "#0f172a"
                        elide: Text.ElideRight
                    }

                    Rectangle {
                        visible: root.badgeText().length > 0
                        color: "#e8eef8"
                        border.color: "#c8d7ea"
                        radius: 10
                        implicitWidth: badgeLabel.implicitWidth + 14
                        implicitHeight: badgeLabel.implicitHeight + 6

                        Label {
                            id: badgeLabel
                            anchors.centerIn: parent
                            text: root.badgeText()
                            color: "#355070"
                            font.pixelSize: 11
                            font.bold: true
                        }
                    }
                }

                Label {
                    Layout.fillWidth: true
                    text: root.headerSecondaryText()
                    color: "#475569"
                    font.pixelSize: 13
                    elide: Text.ElideRight
                }
            }
        }

        TabBar {
            id: packetTabs
            Layout.fillWidth: true
            visible: !root.isStreamItemDetails()
            spacing: 6

            background: Rectangle {
                color: "transparent"
            }

            TabButton {
                text: "Summary"
                implicitHeight: 34

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                    font.bold: parent.checked
                    color: parent.checked ? "#0f172a" : "#64748b"
                }

                background: Rectangle {
                    radius: 6
                    color: parent.checked
                        ? "#ffffff"
                        : parent.hovered
                            ? "#f8fafc"
                            : "#f1f5f9"
                    border.color: parent.checked ? "#cbd5e1" : "#e2e8f0"
                }
            }

            TabButton {
                text: "Raw"
                implicitHeight: 34

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                    font.bold: parent.checked
                    color: parent.checked ? "#0f172a" : "#64748b"
                }

                background: Rectangle {
                    radius: 6
                    color: parent.checked
                        ? "#ffffff"
                        : parent.hovered
                            ? "#f8fafc"
                            : "#f1f5f9"
                    border.color: parent.checked ? "#cbd5e1" : "#e2e8f0"
                }
            }

            TabButton {
                text: root.payloadTabTitle()
                implicitHeight: 34

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                    font.bold: parent.checked
                    color: parent.checked ? "#0f172a" : "#64748b"
                }

                background: Rectangle {
                    radius: 6
                    color: parent.checked
                        ? "#ffffff"
                        : parent.hovered
                            ? "#f8fafc"
                            : "#f1f5f9"
                    border.color: parent.checked ? "#cbd5e1" : "#e2e8f0"
                }
            }

            TabButton {
                text: "Protocol"
                implicitHeight: 34

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                    font.bold: parent.checked
                    color: parent.checked ? "#0f172a" : "#64748b"
                }

                background: Rectangle {
                    radius: 6
                    color: parent.checked
                        ? "#ffffff"
                        : parent.hovered
                            ? "#f8fafc"
                            : "#f1f5f9"
                    border.color: parent.checked ? "#cbd5e1" : "#e2e8f0"
                }
            }
        }

        TabBar {
            id: streamTabs
            Layout.fillWidth: true
            visible: root.isStreamItemDetails()
            spacing: 6

            background: Rectangle {
                color: "transparent"
            }

            TabButton {
                text: "Summary"
                implicitHeight: 34

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                    font.bold: parent.checked
                    color: parent.checked ? "#0f172a" : "#64748b"
                }

                background: Rectangle {
                    radius: 6
                    color: parent.checked
                        ? "#ffffff"
                        : parent.hovered
                            ? "#f8fafc"
                            : "#f1f5f9"
                    border.color: parent.checked ? "#cbd5e1" : "#e2e8f0"
                }
            }

            TabButton {
                text: root.payloadTabTitle()
                implicitHeight: 34

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                    font.bold: parent.checked
                    color: parent.checked ? "#0f172a" : "#64748b"
                }

                background: Rectangle {
                    radius: 6
                    color: parent.checked
                        ? "#ffffff"
                        : parent.hovered
                            ? "#f8fafc"
                            : "#f1f5f9"
                    border.color: parent.checked ? "#cbd5e1" : "#e2e8f0"
                }
            }

            TabButton {
                text: "Protocol"
                implicitHeight: 34

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
                    font.bold: parent.checked
                    color: parent.checked ? "#0f172a" : "#64748b"
                }

                background: Rectangle {
                    radius: 6
                    color: parent.checked
                        ? "#ffffff"
                        : parent.hovered
                            ? "#f8fafc"
                            : "#f1f5f9"
                    border.color: parent.checked ? "#cbd5e1" : "#e2e8f0"
                }
            }
        }

        StackLayout {
            visible: !root.isStreamItemDetails()
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: packetTabs.currentIndex

            Rectangle {
                color: "transparent"

                readonly property string summary: root.summaryText()
                readonly property string warningText: root.warningBlockText(summary)
                readonly property string bodyText: root.summaryBodyText(summary)

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 8

                    Rectangle {
                        Layout.fillWidth: true
                        visible: parent.parent.warningText.length > 0
                        color: "#fff6d6"
                        border.color: "#e7d38d"
                        radius: 6
                        implicitHeight: warningLabel.implicitHeight + 16

                        Text {
                            id: warningLabel
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: 7
                            wrapMode: Text.Wrap
                            color: "#7a5d10"
                            text: parent.parent.parent.warningText.length > 0
                                ? "Warnings\n" + parent.parent.parent.warningText
                                : ""
                        }
                    }

                    TextPane {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        viewText: parent.parent.bodyText
                    }
                }
            }

            TextPane {
                monospace: true
                viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                    ? root.packetDetailsModel.hexText
                    : root.emptyText()
            }

            TextPane {
                monospace: true
                viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                    ? root.packetDetailsModel.payloadText
                    : root.emptyText()
            }

            TextPane {
                viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                    ? root.packetDetailsModel.protocolText
                    : root.emptyText()
            }
        }

        StackLayout {
            visible: root.isStreamItemDetails()
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: streamTabs.currentIndex

            Rectangle {
                color: "transparent"

                readonly property string summary: root.summaryText()
                readonly property string warningText: root.warningBlockText(summary)
                readonly property string bodyText: root.summaryBodyText(summary)

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 8

                    Rectangle {
                        Layout.fillWidth: true
                        visible: parent.parent.warningText.length > 0
                        color: "#fff6d6"
                        border.color: "#e7d38d"
                        radius: 6
                        implicitHeight: streamWarningLabel.implicitHeight + 16

                        Text {
                            id: streamWarningLabel
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: 7
                            wrapMode: Text.Wrap
                            color: "#7a5d10"
                            text: parent.parent.parent.warningText.length > 0
                                ? "Warnings\n" + parent.parent.parent.warningText
                                : ""
                        }
                    }

                    TextPane {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        viewText: parent.parent.bodyText
                    }
                }
            }

            TextPane {
                monospace: true
                viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                    ? root.packetDetailsModel.payloadText
                    : root.emptyText()
            }

            TextPane {
                viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                    ? root.packetDetailsModel.protocolText
                    : root.emptyText()
            }
        }
    }
}
