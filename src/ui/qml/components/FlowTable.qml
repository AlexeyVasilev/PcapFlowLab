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
    property bool unrecognizedPacketsSelected: false
    property int unrecognizedPacketCount: 0
    property int sortColumn: 0
    property bool sortAscending: true
    readonly property int tableRowSpacing: 6
    readonly property int tableContentLeftMargin: 6
    readonly property int tableContentRightMargin: 6
    readonly property int selectionColumnWidth: 42
    readonly property int indexColumnWidth: 64
    readonly property int familyColumnWidth: 74
    readonly property int protocolColumnWidth: 86
    readonly property int protocolHintColumnWidth: 98
    readonly property int serviceColumnWidth: 200
    readonly property int endpointColumnWidth: 220
    readonly property int endpointAddressSlotWidth: 136
    readonly property int endpointPortWidth: 44
    readonly property int endpointSeparatorWidth: 10
    readonly property int fragColumnWidth: 56
    readonly property int packetsColumnWidth: 86
    readonly property int bytesColumnWidth: 92

    signal flowSelected(int flowIndex)
    signal filterTextEdited(string text)
    signal copyWiresharkFilterRequested()
    signal sortRequested(int column)
    signal sendFlowToAnalysisRequested()
    signal unrecognizedPacketsRequested()

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

    function formatEndpoint(address, port) {
        const trimmedAddress = address ? String(address).trim() : ""
        const numericPort = Number(port)
        const hasPort = Number.isFinite(numericPort) && numericPort > 0

        if (trimmedAddress.length === 0) {
            return ""
        }

        const displayAddress = trimmedAddress.indexOf(":") >= 0
            ? "[" + trimmedAddress + "]"
            : trimmedAddress

        return hasPort
            ? displayAddress + "  :  " + numericPort
            : displayAddress
    }

    function endpointHasPort(port) {
        const numericPort = Number(port)
        return Number.isFinite(numericPort) && numericPort > 0
    }

    function endpointDisplayAddress(address, port) {
        const trimmedAddress = address ? String(address).trim() : ""
        if (trimmedAddress.length === 0) {
            return ""
        }

        if (root.endpointHasPort(port) && trimmedAddress.indexOf(":") >= 0) {
            return "[" + trimmedAddress + "]"
        }

        return trimmedAddress
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
        spacing: 6

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
            objectName: "wiresharkFilterRow"
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

        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: root.tableContentLeftMargin
            Layout.rightMargin: root.tableContentRightMargin + flowListView.rightGutter
            spacing: root.tableRowSpacing

            Label { text: "Sel"; Layout.preferredWidth: root.selectionColumnWidth; horizontalAlignment: Text.AlignHCenter }
            Button { text: "Index" + root.sortIndicator(0); Layout.preferredWidth: root.indexColumnWidth; onClicked: root.sortRequested(0) }
            Button { text: "Family" + root.sortIndicator(1); Layout.preferredWidth: root.familyColumnWidth; onClicked: root.sortRequested(1) }
            Button { text: "Protocol" + root.sortIndicator(2); Layout.preferredWidth: root.protocolColumnWidth; onClicked: root.sortRequested(2) }
            Button { text: "Proto Hint" + root.sortIndicator(3); Layout.preferredWidth: root.protocolHintColumnWidth; onClicked: root.sortRequested(3) }
            Button { text: "Service" + root.sortIndicator(4); Layout.fillWidth: true; Layout.preferredWidth: root.serviceColumnWidth; onClicked: root.sortRequested(4) }
            Button { text: "Endpoint A" + root.sortIndicator(6); Layout.fillWidth: true; Layout.preferredWidth: root.endpointColumnWidth; onClicked: root.sortRequested(6) }
            Button { text: "Endpoint B" + root.sortIndicator(8); Layout.fillWidth: true; Layout.preferredWidth: root.endpointColumnWidth; onClicked: root.sortRequested(8) }
            Button { text: "Frag" + root.sortIndicator(5); Layout.preferredWidth: root.fragColumnWidth; onClicked: root.sortRequested(5) }
            Button { text: "Packets" + root.sortIndicator(10); Layout.preferredWidth: root.packetsColumnWidth; onClicked: root.sortRequested(10) }
            Button { text: "Bytes" + root.sortIndicator(11); Layout.preferredWidth: root.bytesColumnWidth; onClicked: root.sortRequested(11) }
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
                    policy: flowListView.contentHeight > flowListView.height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
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
                    readonly property bool endpointAHasPort: root.endpointHasPort(portA)
                    readonly property bool endpointBHasPort: root.endpointHasPort(portB)
                    readonly property string endpointAAddressText: root.endpointDisplayAddress(addressA, portA)
                    readonly property string endpointBAddressText: root.endpointDisplayAddress(addressB, portB)
                    readonly property string endpointAText: root.formatEndpoint(addressA, portA)
                    readonly property string endpointBText: root.formatEndpoint(addressB, portB)

                    onFlowCheckedChanged: {
                        if (selectionCheckBox.checked !== flowChecked) {
                            selectionCheckBox.checked = flowChecked
                        }
                    }

                    width: flowListView.width
                    height: 32
                    color: selected
                        ? "#dbeafe"
                        : (index % 2 === 0 ? "#ffffff" : "#f8fafc")

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: root.tableContentLeftMargin
                        anchors.rightMargin: root.tableContentRightMargin + flowListView.rightGutter
                        spacing: root.tableRowSpacing

                        Item {
                            Layout.preferredWidth: root.selectionColumnWidth
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
                            text: flowIndex + 1
                            Layout.preferredWidth: root.indexColumnWidth
                            horizontalAlignment: Text.AlignRight
                            verticalAlignment: Text.AlignVCenter
                        }
                        Text {
                            text: family
                            Layout.preferredWidth: root.familyColumnWidth
                            verticalAlignment: Text.AlignVCenter
                        }
                        Text {
                            text: protocol
                            Layout.preferredWidth: root.protocolColumnWidth
                            verticalAlignment: Text.AlignVCenter
                        }
                        Item {
                            Layout.preferredWidth: root.protocolHintColumnWidth
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
                            Layout.preferredWidth: root.serviceColumnWidth
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
                            Layout.preferredWidth: root.endpointColumnWidth
                            implicitHeight: endpointARow.implicitHeight

                            RowLayout {
                                id: endpointARow
                                anchors.left: parent.left
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: 0

                                Label {
                                    id: endpointALabel
                                    Layout.preferredWidth: root.endpointAddressSlotWidth
                                    text: endpointAAddressText
                                    font.family: "Consolas"
                                    elide: Text.ElideMiddle
                                    verticalAlignment: Text.AlignVCenter
                                }

                                Label {
                                    visible: endpointAHasPort
                                    Layout.preferredWidth: root.endpointSeparatorWidth
                                    horizontalAlignment: Text.AlignHCenter
                                    text: ":"
                                    font.family: "Consolas"
                                    color: "#64748b"
                                }

                                Label {
                                    visible: endpointAHasPort
                                    Layout.preferredWidth: root.endpointPortWidth
                                    horizontalAlignment: Text.AlignRight
                                    text: portA
                                    font.family: "Consolas"
                                    color: "#0f172a"
                                }
                            }

                            MouseArea {
                                id: endpointAHoverArea
                                anchors.fill: parent
                                acceptedButtons: Qt.NoButton
                                hoverEnabled: true
                            }

                            ToolTip.visible: endpointAHoverArea.containsMouse && endpointALabel.truncated
                            ToolTip.text: endpointAText
                        }
                        Item {
                            Layout.fillWidth: true
                            Layout.preferredWidth: root.endpointColumnWidth
                            implicitHeight: endpointBRow.implicitHeight

                            RowLayout {
                                id: endpointBRow
                                anchors.left: parent.left
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: 0

                                Label {
                                    id: endpointBLabel
                                    Layout.preferredWidth: root.endpointAddressSlotWidth
                                    text: endpointBAddressText
                                    font.family: "Consolas"
                                    elide: Text.ElideMiddle
                                    verticalAlignment: Text.AlignVCenter
                                }

                                Label {
                                    visible: endpointBHasPort
                                    Layout.preferredWidth: root.endpointSeparatorWidth
                                    horizontalAlignment: Text.AlignHCenter
                                    text: ":"
                                    font.family: "Consolas"
                                    color: "#64748b"
                                }

                                Label {
                                    visible: endpointBHasPort
                                    Layout.preferredWidth: root.endpointPortWidth
                                    horizontalAlignment: Text.AlignRight
                                    text: portB
                                    font.family: "Consolas"
                                    color: "#0f172a"
                                }
                            }

                            MouseArea {
                                id: endpointBHoverArea
                                anchors.fill: parent
                                acceptedButtons: Qt.NoButton
                                hoverEnabled: true
                            }

                            ToolTip.visible: endpointBHoverArea.containsMouse && endpointBLabel.truncated
                            ToolTip.text: endpointBText
                        }
                        Rectangle {
                            Layout.preferredWidth: root.fragColumnWidth
                            implicitHeight: 20
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
                            Layout.preferredWidth: root.packetsColumnWidth
                            horizontalAlignment: Text.AlignRight
                            verticalAlignment: Text.AlignVCenter
                        }
                        Text {
                            text: bytes
                            Layout.preferredWidth: root.bytesColumnWidth
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

        Rectangle {
            Layout.fillWidth: true
            visible: root.unrecognizedPacketCount > 0
            color: root.unrecognizedPacketsSelected ? "#dbeafe" : "#f8fafc"
            border.color: root.unrecognizedPacketsSelected ? "#93c5fd" : "#d8dee9"
            border.width: 1
            radius: 6
            implicitHeight: 40

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 12
                anchors.rightMargin: 12
                spacing: 10

                Label {
                    Layout.fillWidth: true
                    text: "Unrecognized packets list (%1 packets)".arg(root.unrecognizedPacketCount)
                    font.bold: true
                    color: "#0f172a"
                    elide: Text.ElideRight
                }

                Label {
                    text: "Inspect packets that could not be assigned to a normal flow"
                    color: "#64748b"
                    visible: parent.width >= 520
                    elide: Text.ElideRight
                }
            }

            MouseArea {
                anchors.fill: parent
                onClicked: root.unrecognizedPacketsRequested()
            }
        }
    }
}
