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
    readonly property int rowClickLeftMargin: root.tableContentLeftMargin + root.selectionColumnWidth + root.tableRowSpacing - 2
    readonly property int indexColumnWidth: 64
    readonly property int familyColumnWidth: 74
    readonly property int protocolColumnWidth: 86
    readonly property int protocolHintColumnWidth: 98
    readonly property int serviceColumnWidth: 180
    readonly property int endpointColumnWidth: Math.ceil(endpointTextMetrics.width) + 16
    readonly property int fragColumnWidth: 56
    readonly property int packetsColumnWidth: 86
    readonly property int bytesColumnWidth: 92
    readonly property int flowTableColumnCount: 11
    readonly property int flowTableBaseWidth:
        root.tableContentLeftMargin
        + root.tableContentRightMargin
        + root.selectionColumnWidth
        + root.indexColumnWidth
        + root.familyColumnWidth
        + root.protocolColumnWidth
        + root.protocolHintColumnWidth
        + root.serviceColumnWidth
        + root.endpointColumnWidth
        + root.endpointColumnWidth
        + root.fragColumnWidth
        + root.packetsColumnWidth
        + root.bytesColumnWidth
        + root.tableRowSpacing * (root.flowTableColumnCount - 1)
    readonly property int flowTableContentWidth: root.flowTableBaseWidth + flowListView.rightGutter

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

        const displayAddress = hasPort && trimmedAddress.indexOf(":") >= 0
            ? "[" + trimmedAddress + "]"
            : trimmedAddress

        return hasPort
            ? displayAddress + " : " + numericPort
            : displayAddress
    }

    function maxHorizontalOffset() {
        return Math.max(0, flowTableScroller.contentWidth - flowTableScroller.width)
    }

    function scrollHorizontally(delta) {
        const maxOffset = root.maxHorizontalOffset()
        if (maxOffset <= 0 || delta === 0) {
            return false
        }

        const nextX = Math.max(0, Math.min(flowTableScroller.contentX - delta, maxOffset))
        if (Math.abs(nextX - flowTableScroller.contentX) < 0.5) {
            return false
        }

        flowTableScroller.contentX = nextX
        return true
    }

    background: Rectangle {
        color: "#ffffff"
        border.color: "#d8dee9"
        radius: 8
    }

    TextMetrics {
        id: endpointTextMetrics
        font.family: "Consolas"
        text: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff] : 65535"
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

        Item {
            id: flowTableViewport
            Layout.fillWidth: true
            Layout.fillHeight: true

            Flickable {
                id: flowTableScroller
                anchors.fill: parent
                clip: true
                contentWidth: root.flowTableContentWidth
                contentHeight: 1
                flickableDirection: Flickable.HorizontalFlick
                boundsBehavior: Flickable.StopAtBounds

                ScrollBar.horizontal: ScrollBar {
                    id: flowTableHorizontalScrollBar
                    policy: flowTableScroller.contentWidth > flowTableScroller.width ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
                }
            }

            MouseArea {
                anchors.fill: parent
                acceptedButtons: Qt.NoButton

                onWheel: function(wheel) {
                    const horizontalDelta = wheel.pixelDelta.x !== 0
                        ? wheel.pixelDelta.x
                        : wheel.angleDelta.x !== 0
                            ? wheel.angleDelta.x / 8
                            : (wheel.modifiers & Qt.ShiftModifier) && wheel.angleDelta.y !== 0
                                ? wheel.angleDelta.y / 8
                                : 0

                    if (horizontalDelta !== 0 && root.scrollHorizontally(horizontalDelta)) {
                        wheel.accepted = true
                    } else {
                        wheel.accepted = false
                    }
                }
            }

            Item {
                anchors.fill: parent

                Item {
                    id: flowHeaderContainer
                    width: parent.width
                    height: flowHeaderRow.implicitHeight
                    clip: true

                    Item {
                        x: -flowTableScroller.contentX
                        width: root.flowTableContentWidth
                        height: parent.height

                        RowLayout {
                            id: flowHeaderRow
                            anchors.fill: parent
                            anchors.leftMargin: root.tableContentLeftMargin
                            anchors.rightMargin: root.tableContentRightMargin + flowListView.rightGutter
                            spacing: root.tableRowSpacing

                            Label { text: "Sel"; Layout.preferredWidth: root.selectionColumnWidth; horizontalAlignment: Text.AlignHCenter }
                            Button { text: "Index" + root.sortIndicator(0); Layout.preferredWidth: root.indexColumnWidth; onClicked: root.sortRequested(0) }
                            Button { text: "Family" + root.sortIndicator(1); Layout.preferredWidth: root.familyColumnWidth; onClicked: root.sortRequested(1) }
                            Button { text: "Protocol" + root.sortIndicator(2); Layout.preferredWidth: root.protocolColumnWidth; onClicked: root.sortRequested(2) }
                            Button { text: "Proto Hint" + root.sortIndicator(3); Layout.preferredWidth: root.protocolHintColumnWidth; onClicked: root.sortRequested(3) }
                            Button { text: "Service" + root.sortIndicator(4); Layout.preferredWidth: root.serviceColumnWidth; Layout.minimumWidth: root.serviceColumnWidth; Layout.maximumWidth: root.serviceColumnWidth; onClicked: root.sortRequested(4) }
                            Button { text: "Endpoint A" + root.sortIndicator(6); Layout.preferredWidth: root.endpointColumnWidth; Layout.minimumWidth: root.endpointColumnWidth; Layout.maximumWidth: root.endpointColumnWidth; onClicked: root.sortRequested(6) }
                            Button { text: "Endpoint B" + root.sortIndicator(8); Layout.preferredWidth: root.endpointColumnWidth; Layout.minimumWidth: root.endpointColumnWidth; Layout.maximumWidth: root.endpointColumnWidth; onClicked: root.sortRequested(8) }
                            Button { text: "Frag" + root.sortIndicator(5); Layout.preferredWidth: root.fragColumnWidth; onClicked: root.sortRequested(5) }
                            Button { text: "Packets" + root.sortIndicator(10); Layout.preferredWidth: root.packetsColumnWidth; onClicked: root.sortRequested(10) }
                            Button { text: "Bytes" + root.sortIndicator(11); Layout.preferredWidth: root.bytesColumnWidth; onClicked: root.sortRequested(11) }
                        }
                    }
                }

                Rectangle {
                    id: flowBodyContainer
                    y: flowHeaderContainer.height
                    width: parent.width
                    height: Math.max(0, parent.height - flowHeaderContainer.height - (flowTableHorizontalScrollBar.visible ? flowTableHorizontalScrollBar.height : 0))
                    color: "#f8fafc"
                    border.color: "#e2e8f0"
                    radius: 6

                    ListView {
                        id: flowListView
                        readonly property int rightGutter: Math.max(flowScrollBar.implicitWidth, 12) + 10

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
                            readonly property string endpointAText: root.formatEndpoint(addressA, portA)
                            readonly property string endpointBText: root.formatEndpoint(addressB, portB)

                            onFlowCheckedChanged: {
                                if (selectionCheckBox.checked !== flowChecked) {
                                    selectionCheckBox.checked = flowChecked
                                }
                            }

                            width: flowListView.width
                            height: 32
                            clip: true
                            color: selected
                                ? "#dbeafe"
                                : (index % 2 === 0 ? "#ffffff" : "#f8fafc")

                            Item {
                                x: -flowTableScroller.contentX
                                width: root.flowTableContentWidth
                                height: parent.height

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
                                        clip: true

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
                                        Layout.preferredWidth: root.serviceColumnWidth
                                        Layout.minimumWidth: root.serviceColumnWidth
                                        Layout.maximumWidth: root.serviceColumnWidth
                                        implicitHeight: serviceHintLabel.implicitHeight
                                        clip: true

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
                                        Layout.preferredWidth: root.endpointColumnWidth
                                        Layout.minimumWidth: root.endpointColumnWidth
                                        Layout.maximumWidth: root.endpointColumnWidth
                                        implicitHeight: endpointALabel.implicitHeight
                                        clip: true

                                        Label {
                                            id: endpointALabel
                                            anchors.fill: parent
                                            text: endpointAText
                                            font.family: "Consolas"
                                            elide: Text.ElideRight
                                            verticalAlignment: Text.AlignVCenter
                                        }

                                        MouseArea {
                                            id: endpointAHoverArea
                                            anchors.fill: parent
                                            acceptedButtons: Qt.NoButton
                                            hoverEnabled: true
                                        }

                                        ToolTip.visible: endpointAHoverArea.containsMouse
                                            && endpointAText.length > 0
                                            && endpointALabel.implicitWidth > endpointALabel.width + 1
                                        ToolTip.text: endpointAText
                                    }
                                    Item {
                                        Layout.preferredWidth: root.endpointColumnWidth
                                        Layout.minimumWidth: root.endpointColumnWidth
                                        Layout.maximumWidth: root.endpointColumnWidth
                                        implicitHeight: endpointBLabel.implicitHeight
                                        clip: true

                                        Label {
                                            id: endpointBLabel
                                            anchors.fill: parent
                                            text: endpointBText
                                            font.family: "Consolas"
                                            elide: Text.ElideRight
                                            verticalAlignment: Text.AlignVCenter
                                        }

                                        MouseArea {
                                            id: endpointBHoverArea
                                            anchors.fill: parent
                                            acceptedButtons: Qt.NoButton
                                            hoverEnabled: true
                                        }

                                        ToolTip.visible: endpointBHoverArea.containsMouse
                                            && endpointBText.length > 0
                                            && endpointBLabel.implicitWidth > endpointBLabel.width + 1
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
                            }

                            MouseArea {
                                anchors.top: parent.top
                                anchors.bottom: parent.bottom
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.leftMargin: root.rowClickLeftMargin
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
