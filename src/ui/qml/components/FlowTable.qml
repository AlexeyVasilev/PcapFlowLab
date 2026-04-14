import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var flowModel: null
    property int selectedFlowIndex: -1
    property string filterText: ""
    property string wiresharkFilterText: ""
    property bool wiresharkFilterVisible: false
    property int sortColumn: 0
    property bool sortAscending: true

    signal flowSelected(int flowIndex)
    signal filterTextEdited(string text)
    signal copyWiresharkFilterRequested()
    signal sortRequested(int column)
    signal sendFlowToAnalysisRequested()

    function sortIndicator(column) {
        if (root.sortColumn !== column) {
            return ""
        }

        return root.sortAscending ? " ^" : " v"
    }

    function syncSelectedFlowRow() {
        if (!flowListView.model || flowListView.count === 0 || root.selectedFlowIndex < 0 || !root.flowModel) {
            flowListView.currentIndex = -1
            return
        }

        const selectedRow = root.flowModel.rowForFlowIndex(root.selectedFlowIndex)
        flowListView.currentIndex = selectedRow

        if (selectedRow < 0 || !root.visible) {
            return
        }

        Qt.callLater(function() {
            if (root.visible && flowListView.currentIndex === selectedRow) {
                flowListView.positionViewAtIndex(selectedRow, ListView.Contain)
            }
        })
    }

    function fragBackgroundColor(hasFragmentedPackets, isSelected) {
        if (isSelected || !hasFragmentedPackets) {
            return "transparent"
        }

        return "#fff6d6"
    }

    function fragTextColor(hasFragmentedPackets, isSelected) {
        if (isSelected) {
            return "#0f172a"
        }

        return hasFragmentedPackets ? "#8a6a12" : "#0f172a"
    }

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    onFlowModelChanged: syncSelectedFlowRow()
    onSelectedFlowIndexChanged: syncSelectedFlowRow()
    onVisibleChanged: {
        if (visible) {
            syncSelectedFlowRow()
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 8

        Label {
            text: "Flows"
            font.pixelSize: 18
            font.bold: true
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 6

            TextField {
                id: filterField
                Layout.fillWidth: true
                placeholderText: "Filter by protocol, hint, service, address, or port"
                text: root.filterText
                onTextEdited: function() {
                    root.filterTextEdited(text)
                }
            }

            Button {
                text: "Send flow to Analysis"
                enabled: root.selectedFlowIndex >= 0
                onClicked: root.sendFlowToAnalysisRequested()
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.rightMargin: flowListView.rightGutter
            spacing: 8
            visible: root.wiresharkFilterVisible

            Label {
                text: "Wireshark filter"
                color: "#475569"
            }

            TextField {
                id: wiresharkFilterField
                Layout.fillWidth: true
                readOnly: true
                selectByMouse: true
                text: root.wiresharkFilterText
                font.family: "Consolas"
                padding: 8
                ToolTip.visible: hovered && text.length > 0
                ToolTip.text: text
            }

            Button {
                text: "Copy"
                onClicked: root.copyWiresharkFilterRequested()
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
            spacing: 8

            Label { text: "Sel"; Layout.preferredWidth: 42; horizontalAlignment: Text.AlignHCenter }
            Button { text: "Index" + root.sortIndicator(0); Layout.preferredWidth: 64; onClicked: root.sortRequested(0) }
            Button { text: "Family" + root.sortIndicator(1); Layout.preferredWidth: 74; onClicked: root.sortRequested(1) }
            Button { text: "Protocol" + root.sortIndicator(2); Layout.preferredWidth: 86; onClicked: root.sortRequested(2) }
            Button { text: "Proto Hint" + root.sortIndicator(3); Layout.preferredWidth: 98; onClicked: root.sortRequested(3) }
            Button { text: "Service" + root.sortIndicator(4); Layout.fillWidth: true; Layout.preferredWidth: 220; onClicked: root.sortRequested(4) }
            Button { text: "Address A" + root.sortIndicator(6); Layout.fillWidth: true; Layout.preferredWidth: 180; onClicked: root.sortRequested(6) }
            Button { text: "Port A" + root.sortIndicator(7); Layout.preferredWidth: 78; onClicked: root.sortRequested(7) }
            Button { text: "Address B" + root.sortIndicator(8); Layout.fillWidth: true; Layout.preferredWidth: 180; onClicked: root.sortRequested(8) }
            Button { text: "Port B" + root.sortIndicator(9); Layout.preferredWidth: 78; onClicked: root.sortRequested(9) }
            Button { text: "Frag" + root.sortIndicator(5); Layout.preferredWidth: 64; onClicked: root.sortRequested(5) }
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
                readonly property int rightGutter: flowScrollBar.visible ? flowScrollBar.width + 10 : 0

                anchors.fill: parent
                anchors.margins: 1
                clip: true
                model: root.flowModel
                currentIndex: -1
                onCountChanged: root.syncSelectedFlowRow()
                onModelChanged: root.syncSelectedFlowRow()

                ScrollBar.vertical: ScrollBar {
                    id: flowScrollBar
                    policy: ScrollBar.AsNeeded
                    visible: flowListView.contentHeight > flowListView.height
                }

                delegate: Rectangle {
                    id: flowRow
                    required property int index
                    required property int flowIndex
                    required property bool flowChecked
                    required property string family
                    required property string protocol
                    required property string protocolHint
                    required property string serviceHint
                    required property bool hasFragmentedPackets
                    required property string fragmentedPacketCount
                    required property string addressA
                    required property int portA
                    required property string addressB
                    required property int portB
                    required property string packets
                    required property string bytes

                    readonly property bool selected: index === flowListView.currentIndex

                    onFlowCheckedChanged: {
                        if (selectionCheckBox.checked !== flowChecked) {
                            selectionCheckBox.checked = flowChecked
                        }
                    }

                    width: flowListView.width
                    height: 36
                    color: selected
                        ? "#dbeafe"
                        : (index % 2 === 0 ? "#ffffff" : "#f8fafc")

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 8
                        anchors.rightMargin: 8 + flowListView.rightGutter
                        spacing: 8

                        Item {
                            Layout.preferredWidth: 42
                            Layout.fillHeight: true

                            CheckBox {
                                id: selectionCheckBox
                                anchors.centerIn: parent
                                checked: flowChecked
                                onToggled: function() {
                                    if (root.flowModel && checked !== flowChecked) {
                                        root.flowModel.setFlowChecked(flowIndex, checked)
                                    }
                                }
                            }
                        }

                        Text {
                            text: flowIndex
                            Layout.preferredWidth: 46
                            horizontalAlignment: Text.AlignRight
                            verticalAlignment: Text.AlignVCenter
                        }
                        Text {
                            text: family
                            Layout.preferredWidth: 58
                            verticalAlignment: Text.AlignVCenter
                        }
                        Text {
                            text: protocol
                            Layout.preferredWidth: 66
                            verticalAlignment: Text.AlignVCenter
                        }
                        Item {
                            Layout.preferredWidth: 78
                            implicitHeight: protocolHintLabel.implicitHeight

                            Label {
                                id: protocolHintLabel
                                anchors.fill: parent
                                text: protocolHint
                                elide: Text.ElideRight
                                verticalAlignment: Text.AlignVCenter
                            }

                            MouseArea {
                                id: protocolHintHoverArea
                                anchors.fill: parent
                                acceptedButtons: Qt.NoButton
                                hoverEnabled: true
                            }

                            ToolTip.visible: protocolHintHoverArea.containsMouse && protocolHintLabel.truncated
                            ToolTip.text: protocolHintLabel.text
                        }
                        Item {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 220
                            implicitHeight: serviceHintLabel.implicitHeight

                            Label {
                                id: serviceHintLabel
                                anchors.fill: parent
                                text: serviceHint
                                elide: Text.ElideRight
                                verticalAlignment: Text.AlignVCenter
                            }

                            MouseArea {
                                id: serviceHintHoverArea
                                anchors.fill: parent
                                acceptedButtons: Qt.NoButton
                                hoverEnabled: true
                            }

                            ToolTip.visible: serviceHintHoverArea.containsMouse && serviceHintLabel.truncated
                            ToolTip.text: serviceHintLabel.text
                        }

                        Item {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 180
                            implicitHeight: addressALabel.implicitHeight

                            Label {
                                id: addressALabel
                                anchors.fill: parent
                                text: addressA
                                elide: Text.ElideMiddle
                                verticalAlignment: Text.AlignVCenter
                            }

                            MouseArea {
                                id: addressAHoverArea
                                anchors.fill: parent
                                acceptedButtons: Qt.NoButton
                                hoverEnabled: true
                            }

                            ToolTip.visible: addressAHoverArea.containsMouse && addressALabel.truncated
                            ToolTip.text: addressALabel.text
                        }
                        Text {
                            text: portA
                            Layout.preferredWidth: 62
                            horizontalAlignment: Text.AlignRight
                            verticalAlignment: Text.AlignVCenter
                        }
                        Item {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 180
                            implicitHeight: addressBLabel.implicitHeight

                            Label {
                                id: addressBLabel
                                anchors.fill: parent
                                text: addressB
                                elide: Text.ElideMiddle
                                verticalAlignment: Text.AlignVCenter
                            }

                            MouseArea {
                                id: addressBHoverArea
                                anchors.fill: parent
                                acceptedButtons: Qt.NoButton
                                hoverEnabled: true
                            }

                            ToolTip.visible: addressBHoverArea.containsMouse && addressBLabel.truncated
                            ToolTip.text: addressBLabel.text
                        }
                        Text {
                            text: portB
                            Layout.preferredWidth: 62
                            horizontalAlignment: Text.AlignRight
                            verticalAlignment: Text.AlignVCenter
                        }
                        Rectangle {
                            Layout.preferredWidth: 48
                            implicitHeight: 24
                            radius: 4
                            color: root.fragBackgroundColor(hasFragmentedPackets, selected)
                            border.width: color === "transparent" ? 0 : 1
                            border.color: color === "transparent" ? "transparent" : Qt.darker(color, 1.08)

                            Text {
                                anchors.centerIn: parent
                                width: parent.width
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                                text: fragmentedPacketCount
                                color: root.fragTextColor(hasFragmentedPackets, selected)
                            }
                        }
                        Text {
                            text: packets
                            Layout.preferredWidth: 68
                            horizontalAlignment: Text.AlignRight
                            verticalAlignment: Text.AlignVCenter
                        }
                        Text {
                            text: bytes
                            Layout.preferredWidth: 80
                            horizontalAlignment: Text.AlignRight
                            verticalAlignment: Text.AlignVCenter
                        }
                    }

                    MouseArea {
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.leftMargin: 52
                        hoverEnabled: true
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
