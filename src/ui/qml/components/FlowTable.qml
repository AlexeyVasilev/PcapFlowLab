import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var flowModel: null
    property int selectedFlowIndex: -1
    property string filterText: ""
    property int sortColumn: 0
    property bool sortAscending: true

    signal flowSelected(int flowIndex)
    signal filterTextEdited(string text)
    signal sortRequested(int column)

    function sortIndicator(column) {
        if (root.sortColumn !== column) {
            return ""
        }

        return root.sortAscending ? " ^" : " v"
    }

    function resetSelectionIfNeeded() {
        if (!flowListView.model || flowListView.count === 0 || root.selectedFlowIndex < 0) {
            flowListView.currentIndex = -1
        }
    }

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    onFlowModelChanged: resetSelectionIfNeeded()
    onSelectedFlowIndexChanged: resetSelectionIfNeeded()

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label {
            text: "Flows"
            font.pixelSize: 18
            font.bold: true
        }

        TextField {
            id: filterField
            Layout.fillWidth: true
            placeholderText: "Filter by protocol, family, or endpoint"
            text: root.filterText
            onTextEdited: function() {
                root.filterTextEdited(text)
            }
        }

        Connections {
            target: root

            function onFilterTextChanged() {
                if (filterField.text !== root.filterText) {
                    filterField.text = root.filterText
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: "#e2e8f0"
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Button {
                text: "Index" + root.sortIndicator(0)
                Layout.preferredWidth: 70
                onClicked: root.sortRequested(0)
            }

            Button {
                text: "Family" + root.sortIndicator(1)
                Layout.preferredWidth: 78
                onClicked: root.sortRequested(1)
            }

            Button {
                text: "Protocol" + root.sortIndicator(2)
                Layout.preferredWidth: 90
                onClicked: root.sortRequested(2)
            }

            Button {
                text: "Endpoint A" + root.sortIndicator(3)
                Layout.fillWidth: true
                Layout.preferredWidth: 180
                onClicked: root.sortRequested(3)
            }

            Button {
                text: "Endpoint B" + root.sortIndicator(4)
                Layout.fillWidth: true
                Layout.preferredWidth: 180
                onClicked: root.sortRequested(4)
            }

            Button {
                text: "Packets" + root.sortIndicator(5)
                Layout.preferredWidth: 90
                onClicked: root.sortRequested(5)
            }

            Button {
                text: "Bytes" + root.sortIndicator(6)
                Layout.preferredWidth: 90
                onClicked: root.sortRequested(6)
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: "#f8fafc"
            border.color: "#e2e8f0"
            radius: 6

            ListView {
                id: flowListView

                anchors.fill: parent
                anchors.margins: 1
                clip: true
                model: root.flowModel
                currentIndex: -1
                onCountChanged: root.resetSelectionIfNeeded()
                onModelChanged: root.resetSelectionIfNeeded()

                delegate: Rectangle {
                    required property int index
                    required property int flowIndex
                    required property string family
                    required property string protocol
                    required property string endpointA
                    required property string endpointB
                    required property string packets
                    required property string bytes

                    width: flowListView.width
                    height: 40
                    color: index === flowListView.currentIndex
                        ? "#dbeafe"
                        : (index % 2 === 0 ? "#ffffff" : "#f8fafc")

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 10
                        anchors.rightMargin: 10
                        spacing: 12

                        Label {
                            text: flowIndex
                            Layout.preferredWidth: 52
                            horizontalAlignment: Text.AlignRight
                        }

                        Label {
                            text: family
                            Layout.preferredWidth: 60
                        }

                        Label {
                            text: protocol
                            Layout.preferredWidth: 72
                        }

                        Label {
                            text: endpointA
                            Layout.fillWidth: true
                            Layout.preferredWidth: 180
                            elide: Text.ElideMiddle
                        }

                        Label {
                            text: endpointB
                            Layout.fillWidth: true
                            Layout.preferredWidth: 180
                            elide: Text.ElideMiddle
                        }

                        Label {
                            text: packets
                            Layout.preferredWidth: 72
                            horizontalAlignment: Text.AlignRight
                        }

                        Label {
                            text: bytes
                            Layout.preferredWidth: 84
                            horizontalAlignment: Text.AlignRight
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: {
                            flowListView.currentIndex = index
                            root.flowSelected(flowIndex)
                        }
                    }
                }
            }

            Label {
                anchors.centerIn: parent
                visible: flowListView.count === 0
                color: "#64748b"
                text: "No flows loaded"
            }
        }
    }
}

