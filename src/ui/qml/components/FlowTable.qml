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
            placeholderText: "Filter by protocol, hint, service, address, or port"
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
            spacing: 10

            Button { text: "Index" + root.sortIndicator(0); Layout.preferredWidth: 64; onClicked: root.sortRequested(0) }
            Button { text: "Family" + root.sortIndicator(1); Layout.preferredWidth: 74; onClicked: root.sortRequested(1) }
            Button { text: "Protocol" + root.sortIndicator(2); Layout.preferredWidth: 86; onClicked: root.sortRequested(2) }
            Button { text: "Proto Hint" + root.sortIndicator(3); Layout.preferredWidth: 98; onClicked: root.sortRequested(3) }
            Button { text: "Service" + root.sortIndicator(4); Layout.fillWidth: true; Layout.preferredWidth: 220; onClicked: root.sortRequested(4) }
            Button { text: "Frag" + root.sortIndicator(5); Layout.preferredWidth: 64; onClicked: root.sortRequested(5) }
            Button { text: "Address A" + root.sortIndicator(6); Layout.fillWidth: true; Layout.preferredWidth: 180; onClicked: root.sortRequested(6) }
            Button { text: "Port A" + root.sortIndicator(7); Layout.preferredWidth: 78; onClicked: root.sortRequested(7) }
            Button { text: "Address B" + root.sortIndicator(8); Layout.fillWidth: true; Layout.preferredWidth: 180; onClicked: root.sortRequested(8) }
            Button { text: "Port B" + root.sortIndicator(9); Layout.preferredWidth: 78; onClicked: root.sortRequested(9) }
            Button { text: "Packets" + root.sortIndicator(10); Layout.preferredWidth: 86; onClicked: root.sortRequested(10) }
            Button { text: "Bytes" + root.sortIndicator(11); Layout.preferredWidth: 92; onClicked: root.sortRequested(11) }
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
                    required property string protocolHint
                    required property string serviceHint
                    required property string fragmentedPacketCount
                    required property string addressA
                    required property int portA
                    required property string addressB
                    required property int portB
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
                        spacing: 10

                        Label { text: flowIndex; Layout.preferredWidth: 46; horizontalAlignment: Text.AlignRight }
                        Label { text: family; Layout.preferredWidth: 58 }
                        Label { text: protocol; Layout.preferredWidth: 66 }
                        Label { text: protocolHint; Layout.preferredWidth: 78; elide: Text.ElideRight }
                        Label { text: serviceHint; Layout.fillWidth: true; Layout.preferredWidth: 220; elide: Text.ElideRight }
                        Label { text: fragmentedPacketCount; Layout.preferredWidth: 48; horizontalAlignment: Text.AlignHCenter }
                        Label { text: addressA; Layout.fillWidth: true; Layout.preferredWidth: 180; elide: Text.ElideMiddle }
                        Label { text: portA; Layout.preferredWidth: 62; horizontalAlignment: Text.AlignRight }
                        Label { text: addressB; Layout.fillWidth: true; Layout.preferredWidth: 180; elide: Text.ElideMiddle }
                        Label { text: portB; Layout.preferredWidth: 62; horizontalAlignment: Text.AlignRight }
                        Label { text: packets; Layout.preferredWidth: 68; horizontalAlignment: Text.AlignRight }
                        Label { text: bytes; Layout.preferredWidth: 80; horizontalAlignment: Text.AlignRight }
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
