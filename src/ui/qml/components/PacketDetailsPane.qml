import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Frame {
    id: root

    property var packetDetailsModel: null
    property var packetDetailsController: null
    property var summaryExpansionProfiles: ({})

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

    function summaryLayers() {
        if (!root.packetDetailsModel || !root.packetDetailsModel.hasPacket) {
            return []
        }

        const layers = root.packetDetailsModel.summaryLayers
        return root.decorateSummaryLayers(root.normalizeSummaryLayers(layers && layers.length !== undefined ? layers : []))
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

    function normalizePacketTabIndex(index) {
        return index === 1 ? 1 : 0
    }

    function normalizeStreamTabIndex(index) {
        return index === 1 ? 1 : 0
    }

    function packetByteViews() {
        if (!root.packetDetailsModel || !root.packetDetailsModel.hasPacket) {
            return []
        }

        const descriptors = root.packetDetailsModel.packetByteViewDescriptors
        const items = []
        for (let index = 0; index < descriptors.length; ++index) {
            const descriptor = descriptors[index]
            const depth = descriptor && descriptor["depth"] !== undefined && descriptor["depth"] !== null
                ? Number(descriptor["depth"])
                : 0
            const label = descriptor && descriptor["label"] !== undefined && descriptor["label"] !== null
                ? String(descriptor["label"])
                : ""
            items.push({
                "stableId": descriptor && descriptor["stableId"] !== undefined && descriptor["stableId"] !== null
                    ? String(descriptor["stableId"])
                    : "",
                "label": label,
                "displayLabel": `${"  ".repeat(Math.max(0, depth))}${label}`,
                "depth": depth,
                "state": descriptor && descriptor["state"] !== undefined && descriptor["state"] !== null
                    ? String(descriptor["state"])
                    : "",
                "statusText": descriptor && descriptor["statusText"] !== undefined && descriptor["statusText"] !== null
                    ? String(descriptor["statusText"])
                    : ""
            })
        }
        return items
    }

    function packetByteViewCurrentIndex() {
        if (!root.packetDetailsModel || !root.packetDetailsModel.hasPacket) {
            return -1
        }

        const selectedId = root.packetDetailsModel.selectedPacketByteViewId
        const items = root.packetByteViews()
        for (let index = 0; index < items.length; ++index) {
            if (items[index].stableId === selectedId) {
                return index
            }
        }
        return items.length > 0 ? 0 : -1
    }

    function buildSummaryLayerOccurrences(layers) {
        const occurrences = {}

        function visit(layerList) {
            for (let index = 0; index < layerList.length; ++index) {
                const layer = layerList[index]
                const layerId = layer && layer["id"] !== undefined && layer["id"] !== null
                    ? String(layer["id"])
                    : ""
                if (layerId.length === 0) {
                    continue
                }

                occurrences[layerId] = (occurrences[layerId] || 0) + 1
                const children = layer && layer["children"] && layer["children"].length !== undefined
                    ? layer["children"]
                    : []
                if (children.length > 0) {
                    visit(children)
                }
            }
        }

        visit(layers)
        return occurrences
    }

    function summaryLayerIdentity(layerId, occurrenceIndex, totalCount) {
        if (layerId === "warnings") {
            return "warnings"
        }
        if (layerId !== "vlan" && totalCount <= 1) {
            return layerId
        }
        return layerId + "#" + occurrenceIndex
    }

    function summaryLayerSignature(layers) {
        const occurrences = root.buildSummaryLayerOccurrences(layers)
        const nextIndexes = {}
        const keys = []

        function visit(layerList) {
            for (let index = 0; index < layerList.length; ++index) {
                const layer = layerList[index]
                const layerId = layer && layer["id"] !== undefined && layer["id"] !== null
                    ? String(layer["id"])
                    : ""
                if (layerId.length === 0) {
                    continue
                }

                const occurrenceIndex = nextIndexes[layerId] || 0
                nextIndexes[layerId] = occurrenceIndex + 1
                const identity = root.summaryLayerIdentity(layerId, occurrenceIndex, occurrences[layerId] || 1)
                if (identity !== "warnings") {
                    keys.push(identity)
                }

                const children = layer && layer["children"] && layer["children"].length !== undefined
                    ? layer["children"]
                    : []
                if (children.length > 0) {
                    visit(children)
                }
            }
        }

        visit(layers)
        return keys.join("|")
    }

    function summaryExpansionProfile(signature) {
        if (!signature || !root.summaryExpansionProfiles || root.summaryExpansionProfiles[signature] === undefined) {
            return null
        }

        return root.summaryExpansionProfiles[signature]
    }

    function collectExpandedSummaryLayerKeys(layers) {
        const expandedLayerKeys = {}

        function visit(layerList) {
            for (let index = 0; index < layerList.length; ++index) {
                const layer = layerList[index]
                const layerKey = layer && layer["expansion_key"] !== undefined && layer["expansion_key"] !== null
                    ? String(layer["expansion_key"])
                    : ""
                const expandedByDefault = layer && layer["expanded_by_default"] !== undefined && layer["expanded_by_default"] !== null
                    ? Boolean(layer["expanded_by_default"])
                    : true

                if (layerKey.length > 0 && layerKey !== "warnings" && expandedByDefault) {
                    expandedLayerKeys[layerKey] = true
                }

                const children = layer && layer["children"] && layer["children"].length !== undefined
                    ? layer["children"]
                    : []
                if (children.length > 0) {
                    visit(children)
                }
            }
        }

        visit(layers && layers.length !== undefined ? layers : [])
        return expandedLayerKeys
    }

    function rememberSummaryExpansion(signature, layerKey, expanded, isWarning, currentLayers) {
        if (!signature || !layerKey) {
            return
        }

        const profiles = Object.assign({}, root.summaryExpansionProfiles || {})
        let profile = profiles[signature]
        if (!profile) {
            profile = {
                expandedLayerKeys: {},
                hasExpandedLayerProfile: false,
                warningExpanded: undefined
            }
        }

        if (isWarning) {
            profile.warningExpanded = expanded
            if (!profile.hasExpandedLayerProfile) {
                profile.expandedLayerKeys = root.collectExpandedSummaryLayerKeys(currentLayers)
            }
        } else if (expanded) {
            if (!profile.hasExpandedLayerProfile) {
                profile.expandedLayerKeys = root.collectExpandedSummaryLayerKeys(currentLayers)
            }
            profile.hasExpandedLayerProfile = true
            profile.expandedLayerKeys[layerKey] = true
        } else {
            if (!profile.hasExpandedLayerProfile) {
                profile.expandedLayerKeys = root.collectExpandedSummaryLayerKeys(currentLayers)
            }
            profile.hasExpandedLayerProfile = true
            delete profile.expandedLayerKeys[layerKey]
        }

        profiles[signature] = profile
        root.summaryExpansionProfiles = profiles
    }

    function normalizeSummaryFields(fields) {
        const fieldList = fields && fields.length !== undefined ? fields : []
        const normalized = []
        for (let index = 0; index < fieldList.length; ++index) {
            const field = fieldList[index]
            normalized.push({
                "label": field && field["label"] !== undefined && field["label"] !== null
                    ? String(field["label"])
                    : "",
                "value": field && field["value"] !== undefined && field["value"] !== null
                    ? String(field["value"])
                    : ""
            })
        }

        return normalized
    }

    function normalizeSummaryLayers(layers) {
        const layerList = layers && layers.length !== undefined ? layers : []
        const normalized = []

        for (let index = 0; index < layerList.length; ++index) {
            const layer = layerList[index]
            normalized.push({
                "id": layer && layer["id"] !== undefined && layer["id"] !== null
                    ? String(layer["id"])
                    : "",
                "title": layer && layer["title"] !== undefined && layer["title"] !== null
                    ? String(layer["title"])
                    : "",
                "fields": root.normalizeSummaryFields(
                    layer && layer["fields"] && layer["fields"].length !== undefined
                        ? layer["fields"]
                        : []
                ),
                "children": root.normalizeSummaryLayers(
                    layer && layer["children"] && layer["children"].length !== undefined
                        ? layer["children"]
                        : []
                ),
                "expanded_by_default": layer && layer["expanded_by_default"] !== undefined && layer["expanded_by_default"] !== null
                    ? Boolean(layer["expanded_by_default"])
                    : true,
                "warning": layer && layer["warning"] !== undefined && layer["warning"] !== null
                    ? Boolean(layer["warning"])
                    : false,
                "marker_text": layer && layer["marker_text"] !== undefined && layer["marker_text"] !== null
                    ? String(layer["marker_text"])
                    : ""
            })
        }

        return normalized
    }

    function decorateSummaryLayers(layers) {
        const summaryLayers = layers && layers.length !== undefined ? layers : []
        const signature = root.summaryLayerSignature(summaryLayers)
        const profile = root.summaryExpansionProfile(signature)
        const occurrences = root.buildSummaryLayerOccurrences(summaryLayers)
        const nextIndexes = {}

        function decorate(layerList) {
            const result = []
            for (let index = 0; index < layerList.length; ++index) {
                const layer = layerList[index]
                const layerId = layer && layer["id"] !== undefined && layer["id"] !== null
                    ? String(layer["id"])
                    : ""
                if (layerId.length === 0) {
                    continue
                }

                const occurrenceIndex = nextIndexes[layerId] || 0
                nextIndexes[layerId] = occurrenceIndex + 1
                const layerKey = root.summaryLayerIdentity(layerId, occurrenceIndex, occurrences[layerId] || 1)
                const children = layer && layer["children"] && layer["children"].length !== undefined
                    ? decorate(layer["children"])
                    : []

                let expandedByDefault = layer["expanded_by_default"] === undefined || layer["expanded_by_default"] === null
                    ? true
                    : Boolean(layer["expanded_by_default"])

                if (profile) {
                    if (layerKey === "warnings") {
                        expandedByDefault = profile.warningExpanded === undefined
                            ? expandedByDefault
                            : Boolean(profile.warningExpanded)
                    } else if (profile.hasExpandedLayerProfile) {
                        expandedByDefault = !!(profile.expandedLayerKeys && profile.expandedLayerKeys[layerKey])
                    }
                }

                result.push({
                    "id": layerId,
                    "title": layer && layer["title"] !== undefined && layer["title"] !== null
                        ? String(layer["title"])
                        : "",
                    "fields": layer && layer["fields"] && layer["fields"].length !== undefined
                        ? layer["fields"]
                        : [],
                    "children": children,
                    "expanded_by_default": expandedByDefault,
                    "warning": layer && layer["warning"] !== undefined && layer["warning"] !== null
                        ? Boolean(layer["warning"])
                        : false,
                    "marker_text": layer && layer["marker_text"] !== undefined && layer["marker_text"] !== null
                        ? String(layer["marker_text"])
                        : "",
                    "expansion_key": layerKey,
                    "summary_signature": signature
                })
            }
            return result
        }

        return decorate(summaryLayers)
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

    function hasRenderableSummaryLayers(layers) {
        const layerList = layers && layers.length !== undefined ? layers : []

        function visit(items) {
            for (let index = 0; index < items.length; ++index) {
                const layer = items[index]
                const title = layer && layer["title"] !== undefined && layer["title"] !== null
                    ? String(layer["title"]).trim()
                    : ""
                const fields = layer && layer["fields"] && layer["fields"].length !== undefined
                    ? layer["fields"]
                    : []
                const children = layer && layer["children"] && layer["children"].length !== undefined
                    ? layer["children"]
                    : []

                if (title.length > 0 || fields.length > 0) {
                    return true
                }
                if (children.length > 0 && visit(children)) {
                    return true
                }
            }

            return false
        }

        return visit(layerList)
    }

    component TextPane: Rectangle {
        property string viewText: ""
        property bool monospace: false

        color: "#f8fafc"
        border.color: "#e2e8f0"
        radius: 6

        ScrollView {
            id: textPaneScroll
            anchors.fill: parent
            anchors.margins: 1
            clip: true
            ScrollBar.vertical.policy: contentHeight > height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
            ScrollBar.horizontal.policy: contentWidth > width ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff

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

    component SelectableText: TextEdit {
        property color textColor: "#0f172a"
        property bool monospace: false
        property bool bold: false
        property int textWrapMode: TextEdit.NoWrap
        property bool clipOverflow: textWrapMode === TextEdit.NoWrap

        readOnly: true
        activeFocusOnTab: false
        selectByMouse: true
        textFormat: TextEdit.PlainText
        wrapMode: textWrapMode
        clip: clipOverflow
        color: textColor
        font.family: monospace ? "Consolas" : ""
        font.pixelSize: 12
        font.bold: bold
        cursorVisible: false
    }

    component SummaryFieldRow: Item {
        required property var modelData
        readonly property string labelText: modelData && modelData["label"] !== undefined && modelData["label"] !== null
            ? String(modelData["label"])
            : ""
        readonly property string valueText: modelData && modelData["value"] !== undefined && modelData["value"] !== null
            ? String(modelData["value"])
            : ""
        readonly property bool fullWidth: labelText.length === 0
        implicitWidth: rowLayout.implicitWidth
        implicitHeight: rowLayout.implicitHeight

        GridLayout {
            id: rowLayout
            anchors.fill: parent
            columns: fullWidth ? 1 : 2
            columnSpacing: 6
            rowSpacing: 1

            SelectableText {
                visible: !fullWidth
                text: fullWidth ? "" : labelText
                textColor: "#64748b"
            }

            SelectableText {
                Layout.fillWidth: true
                text: valueText
                textColor: "#0f172a"
                textWrapMode: TextEdit.Wrap
            }
        }
    }

    Component {
        id: summaryLayerCardComponent

        Rectangle {
        id: summaryLayerCard
        property var modelData
        readonly property string expansionKey: modelData && modelData["expansion_key"] !== undefined && modelData["expansion_key"] !== null
            ? String(modelData["expansion_key"])
            : ""
        readonly property string summarySignature: modelData && modelData["summary_signature"] !== undefined && modelData["summary_signature"] !== null
            ? String(modelData["summary_signature"])
            : ""
        readonly property string titleText: modelData && modelData["title"] !== undefined && modelData["title"] !== null
            ? String(modelData["title"])
            : ""
        readonly property string markerText: modelData && modelData["marker_text"] !== undefined && modelData["marker_text"] !== null
            ? String(modelData["marker_text"])
            : ""
        readonly property bool warningState: modelData && modelData["warning"] !== undefined && modelData["warning"] !== null
            ? Boolean(modelData["warning"])
            : false
        readonly property var fieldRows: modelData && modelData["fields"] && modelData["fields"].length !== undefined
            ? modelData["fields"]
            : []
        readonly property var childLayers: modelData && modelData["children"] && modelData["children"].length !== undefined
            ? modelData["children"]
            : []
        property bool expanded: !modelData || modelData["expanded_by_default"] === undefined || modelData["expanded_by_default"] === null
            ? true
            : Boolean(modelData["expanded_by_default"])

        color: "#fbfcfe"
        border.color: warningState ? "#f4c97d" : "#dbe4ee"
        radius: 8
        implicitHeight: layerColumn.implicitHeight + 12

        ColumnLayout {
            id: layerColumn
            anchors.fill: parent
            anchors.margins: 6
            spacing: 4

            RowLayout {
                Layout.fillWidth: true
                spacing: 8

                ToolButton {
                    text: summaryLayerCard.expanded ? "\u25be" : "\u25b8"
                    onClicked: {
                        summaryLayerCard.expanded = !summaryLayerCard.expanded
                        root.rememberSummaryExpansion(
                            summaryLayerCard.summarySignature,
                            summaryLayerCard.expansionKey,
                            summaryLayerCard.expanded,
                            summaryLayerCard.warningState,
                            root.summaryLayers()
                        )
                    }
                    padding: 0
                    implicitWidth: 16
                    implicitHeight: 16

                    contentItem: Label {
                        text: parent.text
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                        color: "#475569"
                        font.pixelSize: 12
                    }

                    background: Rectangle {
                        color: "transparent"
                    }
                }

                Item {
                    Layout.fillWidth: true
                    implicitHeight: titleTextItem.implicitHeight
                    clip: true

                    SelectableText {
                        id: titleTextItem
                        anchors.fill: parent
                        text: summaryLayerCard.titleText
                        textColor: "#0f172a"
                        clip: true
                    }

                    HoverHandler {
                        id: titleHoverHandler
                    }

                    ToolTip.visible: titleHoverHandler.hovered && titleTextItem.contentWidth > titleTextItem.width + 1
                    ToolTip.text: summaryLayerCard.titleText
                }

                Rectangle {
                    visible: summaryLayerCard.markerText.length > 0
                    color: summaryLayerCard.warningState ? "#fff4db" : "#e8eef8"
                    border.color: summaryLayerCard.warningState ? "#f0d08b" : "#c8d7ea"
                    radius: 9
                    implicitWidth: markerLabel.implicitWidth + 12
                    implicitHeight: markerLabel.implicitHeight + 4

                    Label {
                        id: markerLabel
                        anchors.centerIn: parent
                        text: summaryLayerCard.markerText
                        color: summaryLayerCard.warningState ? "#8a4d00" : "#355070"
                        font.pixelSize: 11
                        font.bold: true
                    }
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                visible: summaryLayerCard.expanded
                spacing: 4

                Repeater {
                    model: summaryLayerCard.fieldRows

                    delegate: SummaryFieldRow {
                        Layout.fillWidth: true
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    visible: childRepeater.count > 0
                    height: 1
                    color: "#e2e8f0"
                }

                Repeater {
                    id: childRepeater
                    model: summaryLayerCard.childLayers

                    delegate: Loader {
                        required property var modelData
                        Layout.fillWidth: true
                        Layout.leftMargin: 8
                        sourceComponent: summaryLayerCardComponent

                        onLoaded: {
                            if (item) {
                                item.modelData = modelData
                            }
                        }
                    }
                }
            }
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
        spacing: 4

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
                        font.pixelSize: 14
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
            objectName: "packetDetailsPacketTabs"
            Layout.fillWidth: true
            visible: !root.isStreamItemDetails()
            spacing: 4
            onCurrentIndexChanged: {
                const normalizedIndex = root.normalizePacketTabIndex(currentIndex)
                if (currentIndex !== normalizedIndex) {
                    currentIndex = normalizedIndex
                }
            }

            onVisibleChanged: {
                if (visible) {
                    const normalizedIndex = root.normalizePacketTabIndex(currentIndex)
                    if (currentIndex !== normalizedIndex) {
                        currentIndex = normalizedIndex
                    }
                }
            }

            background: Rectangle {
                color: "transparent"
            }

            TabButton {
                objectName: "packetDetailsPacketSummaryTabButton"
                text: "Summary"
                implicitHeight: 30

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 11
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
                objectName: "packetDetailsPacketBytesTabButton"
                text: "Bytes"
                implicitHeight: 28

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 11
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
            objectName: "packetDetailsStreamTabs"
            Layout.fillWidth: true
            visible: root.isStreamItemDetails()
            spacing: 4
            onCurrentIndexChanged: {
                const normalizedIndex = root.normalizeStreamTabIndex(currentIndex)
                if (currentIndex !== normalizedIndex) {
                    currentIndex = normalizedIndex
                }
            }

            onVisibleChanged: {
                if (visible) {
                    const normalizedIndex = root.normalizeStreamTabIndex(currentIndex)
                    if (currentIndex !== normalizedIndex) {
                        currentIndex = normalizedIndex
                    }
                }
            }

            background: Rectangle {
                color: "transparent"
            }

            TabButton {
                objectName: "packetDetailsStreamSummaryTabButton"
                text: "Summary"
                implicitHeight: 28

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 11
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
                objectName: "packetDetailsStreamItemDataTabButton"
                text: "Item Data"
                implicitHeight: 28

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 11
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
                id: packetSummaryPane
                color: "transparent"

                readonly property string summary: root.summaryText()
                readonly property var layers: root.summaryLayers()
                readonly property bool renderableLayers: root.hasRenderableSummaryLayers(layers)
                readonly property string warningText: root.warningBlockText(summary)
                readonly property string bodyText: root.summaryBodyText(summary)

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 4

                    Rectangle {
                        Layout.fillWidth: true
                        visible: !packetSummaryPane.renderableLayers && packetSummaryPane.warningText.length > 0
                        color: "#fff6d6"
                        border.color: "#e7d38d"
                        radius: 6
                        implicitHeight: warningLabel.implicitHeight + 12

                        SelectableText {
                            id: warningLabel
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: 6
                            textColor: "#7a5d10"
                            textWrapMode: TextEdit.Wrap
                            text: packetSummaryPane.warningText.length > 0
                                ? "Warnings\n" + packetSummaryPane.warningText
                                : ""
                        }
                    }

                    ScrollView {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        visible: packetSummaryPane.renderableLayers
                        ScrollBar.vertical.policy: contentHeight > height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
                        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

                        ColumnLayout {
                            width: parent.width
                            spacing: 6

                            Repeater {
                                model: packetSummaryPane.layers

                                delegate: Loader {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    sourceComponent: summaryLayerCardComponent

                                    onLoaded: {
                                        if (item) {
                                            item.modelData = modelData
                                        }
                                    }
                                }
                            }
                        }
                    }

                    TextPane {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        visible: !packetSummaryPane.renderableLayers
                        viewText: packetSummaryPane.bodyText
                    }
                }
            }

            Rectangle {
                color: "transparent"

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 8

                    ComboBox {
                        id: packetByteViewSelector
                        Layout.fillWidth: true
                        model: root.packetByteViews()
                        textRole: "displayLabel"
                        valueRole: "stableId"
                        currentIndex: root.packetByteViewCurrentIndex()
                        enabled: model.length > 0

                        onActivated: function(index) {
                            const item = model[index]
                            if (root.packetDetailsController && item && item.stableId) {
                                root.packetDetailsController.selectPacketByteView(item.stableId)
                            }
                        }
                    }

                    Label {
                        Layout.fillWidth: true
                        visible: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                        text: root.packetDetailsModel
                            ? root.packetDetailsModel.selectedPacketByteViewStatusText
                            : ""
                        color: "#64748b"
                        font.pixelSize: 12
                        wrapMode: Text.Wrap
                    }

                    TextPane {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        monospace: true
                        viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                            ? (root.packetDetailsModel.selectedPacketByteViewAvailable
                                ? root.packetDetailsModel.selectedPacketByteViewText
                                : (root.packetDetailsModel.selectedPacketByteViewText.length > 0
                                    ? root.packetDetailsModel.selectedPacketByteViewText
                                    : (root.packetByteViews().length > 0
                                    ? "Selected byte view is unavailable."
                                    : "No byte views are available for this packet.")))
                            : root.emptyText()
                    }
                }
            }

        }

        StackLayout {
            visible: root.isStreamItemDetails()
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: streamTabs.currentIndex

            Rectangle {
                id: streamSummaryPane
                color: "transparent"

                readonly property string summary: root.summaryText()
                readonly property var layers: root.summaryLayers()
                readonly property bool renderableLayers: root.hasRenderableSummaryLayers(layers)
                readonly property string warningText: root.warningBlockText(summary)
                readonly property string bodyText: root.summaryBodyText(summary)

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 6

                    Rectangle {
                        Layout.fillWidth: true
                        visible: !streamSummaryPane.renderableLayers && streamSummaryPane.warningText.length > 0
                        color: "#fff6d6"
                        border.color: "#e7d38d"
                        radius: 6
                        implicitHeight: streamWarningLabel.implicitHeight + 12

                        SelectableText {
                            id: streamWarningLabel
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: 6
                            textColor: "#7a5d10"
                            textWrapMode: TextEdit.Wrap
                            text: streamSummaryPane.warningText.length > 0
                                ? "Warnings\n" + streamSummaryPane.warningText
                                : ""
                        }
                    }

                    ScrollView {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        visible: streamSummaryPane.renderableLayers
                        ScrollBar.vertical.policy: contentHeight > height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
                        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

                        ColumnLayout {
                            width: parent.width
                            spacing: 6

                            Repeater {
                                model: streamSummaryPane.layers

                                delegate: Loader {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    sourceComponent: summaryLayerCardComponent

                                    onLoaded: {
                                        if (item) {
                                            item.modelData = modelData
                                        }
                                    }
                                }
                            }
                        }
                    }

                    TextPane {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        visible: !streamSummaryPane.renderableLayers
                        viewText: streamSummaryPane.bodyText
                    }
                }
            }

            Rectangle {
                color: "transparent"

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 8

                    Label {
                        Layout.fillWidth: true
                        visible: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                        text: root.packetDetailsModel
                            ? root.packetDetailsModel.streamItemDataStatusText
                            : ""
                        color: "#64748b"
                        font.pixelSize: 12
                        wrapMode: Text.Wrap
                    }

                    TextPane {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        monospace: true
                        viewText: root.packetDetailsModel && root.packetDetailsModel.hasPacket
                            ? root.packetDetailsModel.streamItemDataText
                            : root.emptyText()
                    }
                }
            }

        }
    }
}
