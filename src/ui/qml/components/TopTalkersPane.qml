import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var topEndpointsModel: null
    property var topPortsModel: null
    property bool hasCapture: false

    signal endpointActivated(string endpointText)
    signal portActivated(int port)

    function groupInteger(value) {
        const digits = Math.max(0, Math.round(Number(value || 0))).toString()
        return digits.replace(/\B(?=(\d{3})+(?!\d))/g, " ")
    }

    function trimTrailingZeros(text) {
        return text.replace(/\.0$/, "").replace(/(\.\d*[1-9])0+$/, "$1")
    }

    function formatBytes(value) {
        const units = ["B", "KB", "MB", "GB", "TB"]
        var scaled = Math.max(0, Number(value || 0))
        var unitIndex = 0
        while (scaled >= 1024 && unitIndex + 1 < units.length) {
            scaled /= 1024
            unitIndex += 1
        }

        var numberText = ""
        if (unitIndex === 0) {
            numberText = groupInteger(Math.round(scaled))
        } else {
            numberText = trimTrailingZeros(scaled.toFixed(1)).replace(/\B(?=(\d{3})+(?!\d))/g, " ")
        }

        return numberText + " " + units[unitIndex]
    }

    component TableFrame: Frame {
        id: tableFrame

        required property string title
        required property var viewModel
        required property string emptyText
        required property bool endpointTable
        readonly property int listRightGutter: tableScrollBar.visible ? tableScrollBar.width + 10 : 0

        Layout.fillWidth: true
        Layout.fillHeight: true
        padding: 0

        background: Rectangle {
            color: "#ffffff"
            border.color: "#d8dee9"
            radius: 6
        }

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 10
            spacing: 8

            Label {
                text: tableFrame.title
                font.bold: true
                font.pixelSize: 16
            }

            Rectangle {
                Layout.fillWidth: true
                height: 30
                radius: 4
                color: "#f8fafc"
                border.color: "#e2e8f0"

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 8
                    anchors.rightMargin: 8 + tableFrame.listRightGutter
                    spacing: 12

                    Label {
                        Layout.fillWidth: true
                        text: tableFrame.endpointTable ? "Endpoint" : "Port"
                        font.bold: true
                        color: "#334155"
                    }

                    Label {
                        Layout.preferredWidth: 92
                        horizontalAlignment: Text.AlignRight
                        text: "Packets"
                        font.bold: true
                        color: "#334155"
                    }

                    Label {
                        Layout.preferredWidth: 104
                        horizontalAlignment: Text.AlignRight
                        text: "Bytes"
                        font.bold: true
                        color: "#334155"
                    }
                }
            }

            ListView {
                id: tableListView
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: tableFrame.viewModel

                ScrollBar.vertical: ScrollBar {
                    id: tableScrollBar
                    policy: ScrollBar.AsNeeded
                }

                delegate: Rectangle {
                    required property string itemLabel
                    required property var packets
                    required property var bytes

                    width: tableListView.width
                    height: 34
                    radius: 4
                    color: rowMouseArea.pressed
                        ? "#e2e8f0"
                        : (rowMouseArea.containsMouse
                            ? "#f1f5f9"
                            : (index % 2 === 0 ? "transparent" : "#f8fafc"))

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 8
                        anchors.rightMargin: 8 + tableFrame.listRightGutter
                        spacing: 12

                        Label {
                            Layout.fillWidth: true
                            text: itemLabel
                            elide: tableFrame.endpointTable ? Text.ElideMiddle : Text.ElideRight
                            color: "#0f172a"
                        }

                        Label {
                            Layout.preferredWidth: 92
                            horizontalAlignment: Text.AlignRight
                            text: root.groupInteger(packets)
                            color: "#0f172a"
                        }

                        Label {
                            Layout.preferredWidth: 104
                            horizontalAlignment: Text.AlignRight
                            text: root.formatBytes(bytes)
                            color: "#0f172a"
                        }
                    }

                    MouseArea {
                        id: rowMouseArea
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            if (tableFrame.endpointTable)
                                root.endpointActivated(itemLabel)
                            else
                                root.portActivated(Number(itemLabel))
                        }
                    }
                }
            }

            Label {
                visible: root.hasCapture && tableListView.count === 0
                text: tableFrame.emptyText
                color: "#64748b"
            }
        }
    }

    padding: 0
    background: Rectangle {
        color: "#f8fafc"
        border.color: "#d8dee9"
        radius: 8
    }

    RowLayout {
        anchors.fill: parent
        anchors.margins: 10
        spacing: 10

        TableFrame {
            title: "Top Endpoints"
            viewModel: root.topEndpointsModel
            emptyText: "No endpoint data"
            endpointTable: true
        }

        TableFrame {
            title: "Top Ports"
            viewModel: root.topPortsModel
            emptyText: "No port data"
            endpointTable: false
        }
    }
}
