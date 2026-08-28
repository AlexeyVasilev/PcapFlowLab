import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    objectName: "advancedFlowFilterSettingsDialog"

    property var controller: null
    readonly property var editor: root.controller ? root.controller.advancedFlowFilterEditor : null
    readonly property var protocolPathSelector: root.controller ? root.controller.advancedFlowFilterProtocolPathSelector : null
    readonly property int documentReloadRevision: root.editor ? root.editor.documentReloadRevision : 0
    property bool applyingDraft: false
    property var sectionExpansionState: ({})
    readonly property color primaryTextColor: "#0f172a"
    readonly property color secondaryTextColor: "#64748b"
    readonly property color sectionBorderColor: "#dbe4f0"
    readonly property color rowBorderColor: "#e2e8f0"
    readonly property color rowSurfaceColor: palette.base
    readonly property color includeRegionColor: Qt.tint(palette.base, Qt.rgba(0.20, 0.45, 0.88, 0.14))
    readonly property color includeRegionBorderColor: Qt.tint(palette.base, Qt.rgba(0.20, 0.45, 0.88, 0.26))
    readonly property color excludeRegionColor: Qt.tint(palette.base, Qt.rgba(0.74, 0.48, 0.12, 0.10))
    readonly property color excludeRegionBorderColor: Qt.tint(palette.base, Qt.rgba(0.74, 0.48, 0.12, 0.23))
    readonly property color warningTextColor: "#8a4d00"
    readonly property color warningIconFillColor: "#fff4db"
    readonly property color warningIconBorderColor: "#f0d08b"
    readonly property int textButtonHorizontalPadding: 12
    readonly property int compactTextButtonHorizontalPadding: 10
    readonly property int portsSectionId: 6
    readonly property int ipAddressesSectionId: 7
    readonly property int timeSectionId: 8
    readonly property int trafficSectionId: 9
    readonly property int serviceSectionId: 10
    readonly property int protocolPathSectionId: 11
    readonly property int containsLayerSectionId: 12
    readonly property int serviceKnownKind: 0
    readonly property int serviceUnknownKind: 1
    readonly property int containsLayerIdentifierModeAny: 0
    readonly property int containsLayerIdentifierModeExact: 1
    readonly property var allSectionIds: [
        0, 1, 2, 3, 4, 5,
        root.portsSectionId,
        root.ipAddressesSectionId,
        root.timeSectionId,
        root.trafficSectionId,
        root.serviceSectionId,
        root.protocolPathSectionId,
        root.containsLayerSectionId
    ]

    signal initializeDialogState()

    readonly property var sectionDescriptors: [
        { sectionId: 0, title: "Address Family", objectNamePrefix: "AddressFamily" },
        { sectionId: 1, title: "Flow Protocol", objectNamePrefix: "FlowProtocol" },
        { sectionId: 2, title: "Detected Protocol", objectNamePrefix: "DetectedProtocol" },
        { sectionId: 3, title: "TLS Version", objectNamePrefix: "TlsVersion" },
        { sectionId: 4, title: "QUIC Version", objectNamePrefix: "QuicVersion" },
        { sectionId: 5, title: "Observed directions", objectNamePrefix: "Directionality" }
    ]

    function optionIndex(options, value) {
        for (let index = 0; index < options.length; ++index) {
            if (options[index].value === value) {
                return index
            }
        }
        return 0
    }

    function openProtocolPathSelector(exclude, row) {
        if (!root.controller || !root.protocolPathSelector || !root.protocolPathSelector.hasCapture) {
            return
        }

        root.controller.beginAdvancedFlowFilterProtocolPathSelection(exclude, row)
        protocolPathSelectorDialog.open()
    }

    function sectionExpanded(sectionId) {
        const key = String(sectionId)
        if (sectionExpansionState[key] === undefined) {
            return false
        }
        return sectionExpansionState[key]
    }

    function setSectionExpanded(sectionId, expanded) {
        const nextState = Object.assign({}, sectionExpansionState)
        nextState[String(sectionId)] = expanded
        sectionExpansionState = nextState
    }

    function rowRemoveAccessibleLabel(sectionTitle) {
        return "Remove rule from " + sectionTitle
    }

    function protocolPathTooltipText(modelData) {
        return modelData.fullText && modelData.fullText.length > 0
            ? modelData.fullText
            : modelData.compactText
    }

    function compactApplicabilityWarningText(statusText) {
        if (!statusText || statusText.length === 0) {
            return ""
        }

        if (statusText === "Not present in current capture") {
            return "Not present"
        }

        if (statusText === "No current capture.") {
            return "No current capture"
        }

        return statusText
    }

    function hasCompactApplicabilityWarning(statusText) {
        return compactApplicabilityWarningText(statusText) !== statusText
    }

    function initializeSectionExpansionState() {
        const nextState = {}
        for (let index = 0; index < allSectionIds.length; ++index) {
            const sectionId = allSectionIds[index]
            nextState[String(sectionId)] = root.editor
                ? root.editor.sectionHasConfiguredPredicates(sectionId)
                : false
        }
        sectionExpansionState = nextState
    }

    function initializePresentationState() {
        initializeSectionExpansionState()
        initializeDialogState()
    }

    component FilterTextButton: Button {
        leftPadding: root.textButtonHorizontalPadding
        rightPadding: root.textButtonHorizontalPadding
        implicitWidth: Math.max(
            implicitBackgroundWidth + leftInset + rightInset,
            implicitContentWidth + leftPadding + rightPadding
        )
    }

    component FilterFlatTextButton: Button {
        flat: true
        leftPadding: root.compactTextButtonHorizontalPadding
        rightPadding: root.compactTextButtonHorizontalPadding
        implicitWidth: Math.max(
            implicitBackgroundWidth + leftInset + rightInset,
            implicitContentWidth + leftPadding + rightPadding
        )
    }

    width: 920
    height: 700
    modal: true
    focus: true
    title: "Advanced Filter Settings"
    closePolicy: Popup.CloseOnEscape

    onOpened: {
        applyingDraft = false
        if (controller) {
            controller.beginAdvancedFlowFilterEdit()
        }
        initializePresentationState()
    }

    onClosed: {
        protocolPathSelectorDialog.close()
        if (!applyingDraft && controller) {
            controller.cancelAdvancedFlowFilterEdit()
        }
        applyingDraft = false
    }

    onDocumentReloadRevisionChanged: initializePresentationState()

    contentItem: Item {
        implicitWidth: 920
        implicitHeight: contentLayout.implicitHeight + 16

        ColumnLayout {
            id: contentLayout
            anchors.fill: parent
            anchors.margins: 16
            spacing: 8

            RowLayout {
                Layout.fillWidth: true
                spacing: 8

                RowLayout {
                    spacing: 8

                    FilterTextButton {
                        objectName: "advancedFlowFilterOpenFilterButton"
                        text: "Open filter..."
                        enabled: root.controller !== null
                        onClicked: root.controller.openAdvancedFlowFilterFile()
                    }

                    FilterTextButton {
                        objectName: "advancedFlowFilterClearUnsavedChangesButton"
                        text: "Clear unsaved changes"
                        enabled: root.editor ? root.editor.draftClearUnsavedChangesAvailable : false
                        onClicked: {
                            if (root.controller) {
                                root.controller.clearAdvancedFlowFilterUnsavedChanges()
                            }
                        }
                    }
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                    Layout.leftMargin: 8
                    Layout.rightMargin: 8
                    spacing: 0

                    Label {
                        objectName: "advancedFlowFilterIdentityLabel"
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        text: "Filter: " + (root.controller ? root.controller.advancedFlowFilterDisplayName : "Custom filter")
                        color: "#0f172a"
                        font.pixelSize: 15
                        font.bold: true
                        elide: Text.ElideRight
                    }

                    Label {
                        objectName: "advancedFlowFilterIdentityRuleCountLabel"
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        text: root.controller ? root.controller.advancedFlowFilterRuleCountText : "0 rules"
                        color: "#64748b"
                        font.pixelSize: 12
                        elide: Text.ElideRight
                    }
                }

                RowLayout {
                    spacing: 8

                    FilterTextButton {
                        objectName: "advancedFlowFilterSaveButton"
                        text: "Save"
                        enabled: root.controller !== null
                        onClicked: root.controller.saveAdvancedFlowFilterFile()
                    }

                    FilterTextButton {
                        objectName: "advancedFlowFilterSaveAsButton"
                        text: "Save As..."
                        enabled: root.controller !== null
                        onClicked: root.controller.saveAdvancedFlowFilterFileAs()
                    }
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                radius: 10
                color: "#f8fafc"
                border.color: "#dbe4f0"

                ScrollView {
                    id: sectionScrollView
                    readonly property real verticalScrollBarGutter:
                        sectionVerticalScrollBar.policy !== ScrollBar.AlwaysOff
                        ? sectionVerticalScrollBar.width + 4
                        : 0
                    anchors.fill: parent
                    anchors.margins: 1
                    clip: true
                    rightPadding: verticalScrollBarGutter
                    contentWidth: availableWidth

                    ScrollBar.vertical: AppScrollBar {
                        id: sectionVerticalScrollBar
                        parent: sectionScrollView
                        x: sectionScrollView.mirrored ? 0 : sectionScrollView.width - width
                        y: sectionScrollView.topPadding
                        height: sectionScrollView.availableHeight
                        policy: sectionScrollView.contentHeight > sectionScrollView.height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
                    }

                    ColumnLayout {
                        id: sectionColumn
                        width: sectionScrollView.availableWidth
                        spacing: 4

                        Repeater {
                            model: root.sectionDescriptors

                            delegate: AdvancedFlowFilterSection {
                                id: finiteSectionCard
                                required property var modelData

                                readonly property int sectionId: modelData.sectionId
                                readonly property string sectionTitle: modelData.title
                                readonly property string sectionObjectNamePrefix: modelData.objectNamePrefix
                                readonly property bool sectionEnabledState: {
                                    if (!root.controller) {
                                        return false
                                    }
                                    void(root.editor.revision)
                                    return root.editor.sectionEnabled(sectionId)
                                }
                                readonly property var includeOptions: {
                                    if (!root.editor) {
                                        return []
                                    }
                                    void(root.editor.revision)
                                    return root.editor.includeOptions(sectionId)
                                }
                                readonly property var excludeOptions: {
                                    if (!root.editor) {
                                        return []
                                    }
                                    void(root.editor.revision)
                                    return root.editor.excludeOptions(sectionId)
                                }
                                readonly property string sectionSummaryText: {
                                    if (!root.editor) {
                                        return ""
                                    }
                                    void(root.editor.sectionSummaryRevision)
                                    return root.editor.sectionSummaryText(sectionId)
                                }
                                readonly property int documentReloadRevision: root.editor
                                    ? root.editor.documentReloadRevision
                                    : 0

                                sectionObjectName: "advancedFlowFilter" + sectionObjectNamePrefix + "Section"
                                collapseButtonObjectName: "advancedFlowFilter" + sectionObjectNamePrefix + "CollapseButton"
                                enabledCheckBoxObjectName: "advancedFlowFilter" + sectionObjectNamePrefix + "EnabledCheckBox"
                                contentObjectName: "advancedFlowFilter" + sectionObjectNamePrefix + "Content"
                                Layout.fillWidth: true
                                Layout.preferredHeight: implicitHeight
                                title: sectionTitle
                                summaryText: sectionSummaryText
                                expanded: root.sectionExpanded(sectionId)
                                sectionEnabled: sectionEnabledState
                                contentEnabled: sectionEnabledState

                                property bool exclusionsExpanded: false

                                function initializeExclusionsVisibility() {
                                    exclusionsExpanded = root.editor
                                        ? root.editor.sectionHasExclusions(sectionId)
                                        : false
                                }

                                Component.onCompleted: initializeExclusionsVisibility()
                                onDocumentReloadRevisionChanged: initializeExclusionsVisibility()

                                Connections {
                                    target: root

                                    function onInitializeDialogState() {
                                        finiteSectionCard.initializeExclusionsVisibility()
                                    }
                                }

                                onToggleRequested: root.setSectionExpanded(sectionId, !root.sectionExpanded(sectionId))
                                onSectionEnabledToggled: function(checked) {
                                    if (root.editor) {
                                        root.editor.setSectionEnabled(finiteSectionCard.sectionId, checked)
                                    }
                                }

                                Label {
                                    Layout.fillWidth: true
                                    visible: finiteSectionCard.sectionId === 5
                                    text: "A -> B is the direction of the first observed packet in the connection."
                                    color: "#64748b"
                                    font.pixelSize: 12
                                    wrapMode: Text.WordWrap
                                }

                                AdvancedFlowFilterSemanticGroup {
                                    Layout.fillWidth: true
                                    title: "Include"
                                    fillColor: root.includeRegionColor
                                    strokeColor: root.includeRegionBorderColor

                                    Flow {
                                        Layout.fillWidth: true
                                        width: parent.width
                                        spacing: 12

                                        Repeater {
                                            model: finiteSectionCard.includeOptions

                                            delegate: CheckBox {
                                                required property var modelData

                                                objectName: "advancedFlowFilter"
                                                    + finiteSectionCard.sectionObjectNamePrefix
                                                    + "Include"
                                                    + modelData.objectNameSuffix
                                                    + "CheckBox"
                                                text: modelData.label
                                                checked: modelData.checked
                                                onToggled: {
                                                    if (root.editor) {
                                                        root.editor.setOptionChecked(
                                                            finiteSectionCard.sectionId,
                                                            modelData.value,
                                                            false,
                                                            checked
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    visible: !finiteSectionCard.exclusionsExpanded

                                    Item {
                                        Layout.fillWidth: true
                                    }

                                    FilterFlatTextButton {
                                        objectName: "advancedFlowFilter"
                                            + finiteSectionCard.sectionObjectNamePrefix
                                            + "ExclusionsToggleButton"
                                        text: "Exclusions"
                                        padding: 2
                                        onClicked: finiteSectionCard.exclusionsExpanded = true
                                    }
                                }

                                AdvancedFlowFilterSemanticGroup {
                                    objectName: "advancedFlowFilter"
                                        + finiteSectionCard.sectionObjectNamePrefix
                                        + "ExclusionsSection"
                                    Layout.fillWidth: true
                                    visible: finiteSectionCard.exclusionsExpanded
                                    title: "Exclude"
                                    fillColor: root.excludeRegionColor
                                    strokeColor: root.excludeRegionBorderColor
                                    actionVisible: true
                                    actionText: "Hide"
                                    actionObjectName: "advancedFlowFilter"
                                        + finiteSectionCard.sectionObjectNamePrefix
                                        + "HideExclusionsButton"
                                    onActionTriggered: finiteSectionCard.exclusionsExpanded = false

                                    Flow {
                                        Layout.fillWidth: true
                                        width: parent.width
                                        spacing: 12

                                        Repeater {
                                            model: finiteSectionCard.excludeOptions

                                            delegate: CheckBox {
                                                required property var modelData

                                                objectName: "advancedFlowFilter"
                                                    + finiteSectionCard.sectionObjectNamePrefix
                                                    + "Exclude"
                                                    + modelData.objectNameSuffix
                                                    + "CheckBox"
                                                text: modelData.label
                                                checked: modelData.checked
                                                onToggled: {
                                                    if (root.editor) {
                                                        root.editor.setOptionChecked(
                                                            finiteSectionCard.sectionId,
                                                            modelData.value,
                                                            true,
                                                            checked
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        AdvancedFlowFilterSection {
                            id: portsSection
                            readonly property bool sectionEnabledState: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.sectionEnabled(root.portsSectionId)
                            }
                            readonly property var scopeOptions: root.editor ? root.editor.portScopeOptions() : []
                            readonly property var includeRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.portRows(false)
                            }
                            readonly property var excludeRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.portRows(true)
                            }
                            readonly property string sectionSummaryText: {
                                if (!root.editor) {
                                    return ""
                                }
                                void(root.editor.sectionSummaryRevision)
                                return root.editor.sectionSummaryText(root.portsSectionId)
                            }
                            readonly property int documentReloadRevision: root.editor
                                ? root.editor.documentReloadRevision
                                : 0

                            sectionObjectName: "advancedFlowFilterPortsSection"
                            collapseButtonObjectName: "advancedFlowFilterPortsCollapseButton"
                            enabledCheckBoxObjectName: "advancedFlowFilterPortsEnabledCheckBox"
                            contentObjectName: "advancedFlowFilterPortsContent"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            title: "Ports"
                            summaryText: sectionSummaryText
                            expanded: root.sectionExpanded(root.portsSectionId)
                            sectionEnabled: sectionEnabledState
                            contentEnabled: sectionEnabledState

                            property bool exclusionsExpanded: false

                            function initializeExclusionsVisibility() {
                                exclusionsExpanded = root.editor
                                    ? root.editor.sectionHasExclusions(root.portsSectionId)
                                    : false
                            }

                            Component.onCompleted: initializeExclusionsVisibility()
                            onDocumentReloadRevisionChanged: initializeExclusionsVisibility()

                            Connections {
                                target: root

                                function onInitializeDialogState() {
                                    portsSection.initializeExclusionsVisibility()
                                }
                            }

                            onToggleRequested: root.setSectionExpanded(root.portsSectionId, !root.sectionExpanded(root.portsSectionId))
                            onSectionEnabledToggled: function(checked) {
                                if (root.editor) {
                                    root.editor.setSectionEnabled(root.portsSectionId, checked)
                                }
                            }

                            AdvancedFlowFilterSemanticGroup {
                                Layout.fillWidth: true
                                title: "Include"
                                fillColor: root.includeRegionColor
                                strokeColor: root.includeRegionBorderColor

                                Repeater {
                                    model: portsSection.includeRows

                                    delegate: Rectangle {
                                        required property var modelData

                                        Layout.fillWidth: true
                                        implicitHeight: includePortRowLayout.implicitHeight + 8
                                        color: root.rowSurfaceColor
                                        border.color: root.rowBorderColor
                                        radius: 5

                                        RowLayout {
                                            id: includePortRowLayout
                                            anchors.fill: parent
                                            anchors.margins: 4
                                            spacing: 8

                                            ComboBox {
                                                objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "ScopeComboBox"
                                                Layout.preferredWidth: 170
                                                model: portsSection.scopeOptions
                                                textRole: "label"
                                                currentIndex: root.optionIndex(model, modelData.scope)
                                                onActivated: {
                                                    if (root.editor) {
                                                        root.editor.setPortRowScope(false, modelData.row, model[currentIndex].value)
                                                    }
                                                }
                                            }

                                            CheckBox {
                                                objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "RangeCheckBox"
                                                text: "Range"
                                                checked: modelData.rangeEnabled
                                                onToggled: {
                                                    if (root.editor) {
                                                        root.editor.setPortRowRangeEnabled(false, modelData.row, checked)
                                                    }
                                                }
                                            }

                                            Label {
                                                Layout.preferredWidth: 36
                                                text: modelData.rangeEnabled ? "From" : "Port"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "PrimaryTextField"
                                                Layout.preferredWidth: 104
                                                text: modelData.primaryText
                                                placeholderText: modelData.rangeEnabled ? "8000" : "443"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setPortRowPrimaryText(false, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Label {
                                                Layout.preferredWidth: 18
                                                opacity: modelData.rangeEnabled ? 1.0 : 0.0
                                                enabled: modelData.rangeEnabled
                                                text: "To"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "SecondaryTextField"
                                                Layout.preferredWidth: 104
                                                opacity: modelData.rangeEnabled ? 1.0 : 0.0
                                                enabled: modelData.rangeEnabled
                                                text: modelData.secondaryText
                                                placeholderText: "9000"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setPortRowSecondaryText(false, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Item {
                                                Layout.fillWidth: true
                                            }

                                            AdvancedFlowFilterRowRemoveButton {
                                                objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "RemoveButton"
                                                accessibleLabel: root.rowRemoveAccessibleLabel("Ports include")
                                                tooltipText: "Remove rule"
                                                onClicked: {
                                                    if (root.editor) {
                                                        root.editor.removePortRow(false, modelData.row)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                FilterTextButton {
                                    objectName: "advancedFlowFilterPortsAddIncludeButton"
                                    text: "+ Add port"
                                    onClicked: {
                                        if (root.editor) {
                                            root.editor.addPortRow(false)
                                        }
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                visible: !portsSection.exclusionsExpanded

                                Item {
                                    Layout.fillWidth: true
                                }

                                FilterFlatTextButton {
                                    objectName: "advancedFlowFilterPortsExclusionsToggleButton"
                                    text: "Exclusions"
                                    padding: 2
                                    onClicked: portsSection.exclusionsExpanded = true
                                }
                            }

                            AdvancedFlowFilterSemanticGroup {
                                objectName: "advancedFlowFilterPortsExclusionsSection"
                                Layout.fillWidth: true
                                visible: portsSection.exclusionsExpanded
                                title: "Exclude"
                                fillColor: root.excludeRegionColor
                                strokeColor: root.excludeRegionBorderColor
                                actionVisible: true
                                actionText: "Hide"
                                actionObjectName: "advancedFlowFilterPortsHideExclusionsButton"
                                onActionTriggered: portsSection.exclusionsExpanded = false

                                Repeater {
                                    model: portsSection.excludeRows

                                    delegate: Rectangle {
                                        required property var modelData

                                        Layout.fillWidth: true
                                        implicitHeight: excludePortRowLayout.implicitHeight + 8
                                        color: root.rowSurfaceColor
                                        border.color: root.rowBorderColor
                                        radius: 5

                                        RowLayout {
                                            id: excludePortRowLayout
                                            anchors.fill: parent
                                            anchors.margins: 4
                                            spacing: 8

                                            ComboBox {
                                                objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "ScopeComboBox"
                                                Layout.preferredWidth: 170
                                                model: portsSection.scopeOptions
                                                textRole: "label"
                                                currentIndex: root.optionIndex(model, modelData.scope)
                                                onActivated: {
                                                    if (root.editor) {
                                                        root.editor.setPortRowScope(true, modelData.row, model[currentIndex].value)
                                                    }
                                                }
                                            }

                                            CheckBox {
                                                objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "RangeCheckBox"
                                                text: "Range"
                                                checked: modelData.rangeEnabled
                                                onToggled: {
                                                    if (root.editor) {
                                                        root.editor.setPortRowRangeEnabled(true, modelData.row, checked)
                                                    }
                                                }
                                            }

                                            Label {
                                                Layout.preferredWidth: 36
                                                text: modelData.rangeEnabled ? "From" : "Port"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "PrimaryTextField"
                                                Layout.preferredWidth: 104
                                                text: modelData.primaryText
                                                placeholderText: modelData.rangeEnabled ? "1" : "53"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setPortRowPrimaryText(true, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Label {
                                                Layout.preferredWidth: 18
                                                opacity: modelData.rangeEnabled ? 1.0 : 0.0
                                                enabled: modelData.rangeEnabled
                                                text: "To"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "SecondaryTextField"
                                                Layout.preferredWidth: 104
                                                opacity: modelData.rangeEnabled ? 1.0 : 0.0
                                                enabled: modelData.rangeEnabled
                                                text: modelData.secondaryText
                                                placeholderText: "1023"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setPortRowSecondaryText(true, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Item {
                                                Layout.fillWidth: true
                                            }

                                            AdvancedFlowFilterRowRemoveButton {
                                                objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "RemoveButton"
                                                accessibleLabel: root.rowRemoveAccessibleLabel("Ports exclude")
                                                tooltipText: "Remove rule"
                                                onClicked: {
                                                    if (root.editor) {
                                                        root.editor.removePortRow(true, modelData.row)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                FilterTextButton {
                                    objectName: "advancedFlowFilterPortsAddExcludeButton"
                                    text: "+ Add port"
                                    onClicked: {
                                        if (root.editor) {
                                            root.editor.addPortRow(true)
                                        }
                                    }
                                }
                            }
                        }

                        AdvancedFlowFilterSection {
                            id: ipAddressesSection
                            readonly property bool sectionEnabledState: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.sectionEnabled(root.ipAddressesSectionId)
                            }
                            readonly property var scopeOptions: root.editor ? root.editor.addressScopeOptions() : []
                            readonly property var includeRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.addressRows(false)
                            }
                            readonly property var excludeRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.addressRows(true)
                            }
                            readonly property string sectionSummaryText: {
                                if (!root.editor) {
                                    return ""
                                }
                                void(root.editor.sectionSummaryRevision)
                                return root.editor.sectionSummaryText(root.ipAddressesSectionId)
                            }
                            readonly property int documentReloadRevision: root.editor
                                ? root.editor.documentReloadRevision
                                : 0

                            sectionObjectName: "advancedFlowFilterIpAddressesSection"
                            collapseButtonObjectName: "advancedFlowFilterIpAddressesCollapseButton"
                            enabledCheckBoxObjectName: "advancedFlowFilterIpAddressesEnabledCheckBox"
                            contentObjectName: "advancedFlowFilterIpAddressesContent"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            title: "IP addresses"
                            summaryText: sectionSummaryText
                            expanded: root.sectionExpanded(root.ipAddressesSectionId)
                            sectionEnabled: sectionEnabledState
                            contentEnabled: sectionEnabledState

                            property bool exclusionsExpanded: false

                            function initializeExclusionsVisibility() {
                                exclusionsExpanded = root.editor
                                    ? root.editor.sectionHasExclusions(root.ipAddressesSectionId)
                                    : false
                            }

                            Component.onCompleted: initializeExclusionsVisibility()
                            onDocumentReloadRevisionChanged: initializeExclusionsVisibility()

                            Connections {
                                target: root

                                function onInitializeDialogState() {
                                    ipAddressesSection.initializeExclusionsVisibility()
                                }
                            }

                            onToggleRequested: root.setSectionExpanded(root.ipAddressesSectionId, !root.sectionExpanded(root.ipAddressesSectionId))
                            onSectionEnabledToggled: function(checked) {
                                if (root.editor) {
                                    root.editor.setSectionEnabled(root.ipAddressesSectionId, checked)
                                }
                            }

                            AdvancedFlowFilterSemanticGroup {
                                Layout.fillWidth: true
                                title: "Include"
                                fillColor: root.includeRegionColor
                                strokeColor: root.includeRegionBorderColor

                                Repeater {
                                    model: ipAddressesSection.includeRows

                                    delegate: Rectangle {
                                        required property var modelData

                                        Layout.fillWidth: true
                                        implicitHeight: includeAddressRowLayout.implicitHeight + 8
                                        color: root.rowSurfaceColor
                                        border.color: root.rowBorderColor
                                        radius: 5

                                        RowLayout {
                                            id: includeAddressRowLayout
                                            anchors.fill: parent
                                            anchors.margins: 4
                                            spacing: 8

                                            ComboBox {
                                                objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "ScopeComboBox"
                                                Layout.preferredWidth: 170
                                                model: ipAddressesSection.scopeOptions
                                                textRole: "label"
                                                currentIndex: root.optionIndex(model, modelData.scope)
                                                onActivated: {
                                                    if (root.editor) {
                                                        root.editor.setAddressRowScope(false, modelData.row, model[currentIndex].value)
                                                    }
                                                }
                                            }

                                            CheckBox {
                                                objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "SubnetCheckBox"
                                                text: "Subnet"
                                                checked: modelData.subnetEnabled
                                                onToggled: {
                                                    if (root.editor) {
                                                        root.editor.setAddressRowSubnetEnabled(false, modelData.row, checked)
                                                    }
                                                }
                                            }

                                            Label {
                                                Layout.preferredWidth: 52
                                                text: "Address"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "AddressTextField"
                                                Layout.preferredWidth: 220
                                                text: modelData.addressText
                                                placeholderText: modelData.subnetEnabled ? "10.0.0.0" : "192.168.1.10"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setAddressRowAddressText(false, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Label {
                                                Layout.preferredWidth: 36
                                                opacity: modelData.subnetEnabled ? 1.0 : 0.0
                                                enabled: modelData.subnetEnabled
                                                text: "Prefix"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "PrefixTextField"
                                                Layout.preferredWidth: 76
                                                opacity: modelData.subnetEnabled ? 1.0 : 0.0
                                                enabled: modelData.subnetEnabled
                                                text: modelData.prefixText
                                                placeholderText: "24"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setAddressRowPrefixText(false, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Item {
                                                Layout.fillWidth: true
                                            }

                                            AdvancedFlowFilterRowRemoveButton {
                                                objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "RemoveButton"
                                                accessibleLabel: root.rowRemoveAccessibleLabel("IP addresses include")
                                                tooltipText: "Remove rule"
                                                onClicked: {
                                                    if (root.editor) {
                                                        root.editor.removeAddressRow(false, modelData.row)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                FilterTextButton {
                                    objectName: "advancedFlowFilterIpAddressesAddIncludeButton"
                                    text: "+ Add address"
                                    onClicked: {
                                        if (root.editor) {
                                            root.editor.addAddressRow(false)
                                        }
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                visible: !ipAddressesSection.exclusionsExpanded

                                Item {
                                    Layout.fillWidth: true
                                }

                                FilterFlatTextButton {
                                    objectName: "advancedFlowFilterIpAddressesExclusionsToggleButton"
                                    text: "Exclusions"
                                    padding: 2
                                    onClicked: ipAddressesSection.exclusionsExpanded = true
                                }
                            }

                            AdvancedFlowFilterSemanticGroup {
                                objectName: "advancedFlowFilterIpAddressesExclusionsSection"
                                Layout.fillWidth: true
                                visible: ipAddressesSection.exclusionsExpanded
                                title: "Exclude"
                                fillColor: root.excludeRegionColor
                                strokeColor: root.excludeRegionBorderColor
                                actionVisible: true
                                actionText: "Hide"
                                actionObjectName: "advancedFlowFilterIpAddressesHideExclusionsButton"
                                onActionTriggered: ipAddressesSection.exclusionsExpanded = false

                                Repeater {
                                    model: ipAddressesSection.excludeRows

                                    delegate: Rectangle {
                                        required property var modelData

                                        Layout.fillWidth: true
                                        implicitHeight: excludeAddressRowLayout.implicitHeight + 8
                                        color: root.rowSurfaceColor
                                        border.color: root.rowBorderColor
                                        radius: 5

                                        RowLayout {
                                            id: excludeAddressRowLayout
                                            anchors.fill: parent
                                            anchors.margins: 4
                                            spacing: 8

                                            ComboBox {
                                                objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "ScopeComboBox"
                                                Layout.preferredWidth: 170
                                                model: ipAddressesSection.scopeOptions
                                                textRole: "label"
                                                currentIndex: root.optionIndex(model, modelData.scope)
                                                onActivated: {
                                                    if (root.editor) {
                                                        root.editor.setAddressRowScope(true, modelData.row, model[currentIndex].value)
                                                    }
                                                }
                                            }

                                            CheckBox {
                                                objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "SubnetCheckBox"
                                                text: "Subnet"
                                                checked: modelData.subnetEnabled
                                                onToggled: {
                                                    if (root.editor) {
                                                        root.editor.setAddressRowSubnetEnabled(true, modelData.row, checked)
                                                    }
                                                }
                                            }

                                            Label {
                                                Layout.preferredWidth: 52
                                                text: "Address"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "AddressTextField"
                                                Layout.preferredWidth: 220
                                                text: modelData.addressText
                                                placeholderText: modelData.subnetEnabled ? "2001:db8::" : "2001:db8::1"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setAddressRowAddressText(true, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Label {
                                                Layout.preferredWidth: 36
                                                opacity: modelData.subnetEnabled ? 1.0 : 0.0
                                                enabled: modelData.subnetEnabled
                                                text: "Prefix"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "PrefixTextField"
                                                Layout.preferredWidth: 76
                                                opacity: modelData.subnetEnabled ? 1.0 : 0.0
                                                enabled: modelData.subnetEnabled
                                                text: modelData.prefixText
                                                placeholderText: "32"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setAddressRowPrefixText(true, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Item {
                                                Layout.fillWidth: true
                                            }

                                            AdvancedFlowFilterRowRemoveButton {
                                                objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "RemoveButton"
                                                accessibleLabel: root.rowRemoveAccessibleLabel("IP addresses exclude")
                                                tooltipText: "Remove rule"
                                                onClicked: {
                                                    if (root.editor) {
                                                        root.editor.removeAddressRow(true, modelData.row)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                FilterTextButton {
                                    objectName: "advancedFlowFilterIpAddressesAddExcludeButton"
                                    text: "+ Add address"
                                    onClicked: {
                                        if (root.editor) {
                                            root.editor.addAddressRow(true)
                                        }
                                    }
                                }
                            }
                        }

                        AdvancedFlowFilterSection {
                            id: timeSection
                            readonly property bool sectionEnabledState: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.sectionEnabled(root.timeSectionId)
                            }
                            readonly property var rangeRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.timeRangeRows()
                            }
                            readonly property var durationRow: {
                                if (!root.editor) {
                                    return ({})
                                }
                                void(root.editor.revision)
                                return root.editor.timeDurationRow()
                            }
                            readonly property string sectionSummaryText: {
                                if (!root.editor) {
                                    return ""
                                }
                                void(root.editor.sectionSummaryRevision)
                                return root.editor.sectionSummaryText(root.timeSectionId)
                            }

                            sectionObjectName: "advancedFlowFilterTimeSection"
                            collapseButtonObjectName: "advancedFlowFilterTimeCollapseButton"
                            enabledCheckBoxObjectName: "advancedFlowFilterTimeEnabledCheckBox"
                            contentObjectName: "advancedFlowFilterTimeContent"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            title: "Time"
                            summaryText: sectionSummaryText
                            expanded: root.sectionExpanded(root.timeSectionId)
                            sectionEnabled: sectionEnabledState
                            contentEnabled: sectionEnabledState

                            onToggleRequested: root.setSectionExpanded(root.timeSectionId, !root.sectionExpanded(root.timeSectionId))
                            onSectionEnabledToggled: function(checked) {
                                if (root.editor) {
                                    root.editor.setSectionEnabled(root.timeSectionId, checked)
                                }
                            }

                            Label {
                                Layout.fillWidth: true
                                text: "UTC timestamp example: 2026-03-22T12:27:32.000000Z"
                                color: root.secondaryTextColor
                                font.pixelSize: 12
                                wrapMode: Text.WordWrap
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 8

                                Label {
                                    Layout.preferredWidth: 250
                                    text: "Value"
                                    color: "#475569"
                                    font.pixelSize: 12
                                    font.bold: true
                                }

                                Label {
                                    Layout.preferredWidth: 220
                                    text: "From"
                                    color: "#475569"
                                    font.pixelSize: 12
                                    font.bold: true
                                }

                                Label {
                                    Layout.preferredWidth: 220
                                    text: "To"
                                    color: "#475569"
                                    font.pixelSize: 12
                                    font.bold: true
                                }
                            }

                            Repeater {
                                model: timeSection.rangeRows

                                delegate: RowLayout {
                                    required property var modelData

                                    Layout.fillWidth: true
                                    spacing: 8

                                    Label {
                                        Layout.preferredWidth: 250
                                        text: modelData.label
                                        color: "#0f172a"
                                        elide: Text.ElideRight
                                    }

                                    TextField {
                                        objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "FromTextField"
                                        Layout.preferredWidth: 220
                                        text: modelData.fromText
                                        placeholderText: "YYYY-MM-DDTHH:MM:SS.ffffffZ"
                                        onTextEdited: {
                                            if (root.editor) {
                                                root.editor.setTimeRangeFromText(modelData.metricId, text)
                                            }
                                        }
                                    }

                                    TextField {
                                        objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "ToTextField"
                                        Layout.preferredWidth: 220
                                        text: modelData.toText
                                        placeholderText: "YYYY-MM-DDTHH:MM:SS.ffffffZ"
                                        onTextEdited: {
                                            if (root.editor) {
                                                root.editor.setTimeRangeToText(modelData.metricId, text)
                                            }
                                        }
                                    }
                                }
                            }

                            Item {
                                Layout.fillWidth: true
                                implicitHeight: 4
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 8

                                Label {
                                    Layout.preferredWidth: 250
                                    text: "Duration"
                                    color: "#475569"
                                    font.pixelSize: 12
                                    font.bold: true
                                }

                                Label {
                                    Layout.preferredWidth: 120
                                    text: "Minimum"
                                    color: "#475569"
                                    font.pixelSize: 12
                                    font.bold: true
                                }

                                Label {
                                    Layout.preferredWidth: 120
                                    text: "Maximum"
                                    color: "#475569"
                                    font.pixelSize: 12
                                    font.bold: true
                                }

                                Label {
                                    Layout.preferredWidth: 120
                                    text: "Unit"
                                    color: "#475569"
                                    font.pixelSize: 12
                                    font.bold: true
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 8

                                Label {
                                    Layout.preferredWidth: 250
                                    text: timeSection.durationRow.label || "Duration"
                                    color: "#0f172a"
                                    elide: Text.ElideRight
                                }

                                TextField {
                                    objectName: "advancedFlowFilterTimeDurationMinTextField"
                                    Layout.preferredWidth: 120
                                    text: timeSection.durationRow.minText || ""
                                    placeholderText: "0"
                                    onTextEdited: {
                                        if (root.editor) {
                                            root.editor.setTimeDurationMinText(text)
                                        }
                                    }
                                }

                                TextField {
                                    objectName: "advancedFlowFilterTimeDurationMaxTextField"
                                    Layout.preferredWidth: 120
                                    text: timeSection.durationRow.maxText || ""
                                    placeholderText: "100"
                                    onTextEdited: {
                                        if (root.editor) {
                                            root.editor.setTimeDurationMaxText(text)
                                        }
                                    }
                                }

                                ComboBox {
                                    objectName: "advancedFlowFilterTimeDurationUnitComboBox"
                                    Layout.preferredWidth: 120
                                    model: timeSection.durationRow.unitOptions || []
                                    textRole: "label"
                                    currentIndex: root.optionIndex(model, timeSection.durationRow.selectedUnit)
                                    onActivated: {
                                        if (root.editor) {
                                            root.editor.setTimeDurationUnit(model[currentIndex].value)
                                        }
                                    }
                                }
                            }
                        }

                        AdvancedFlowFilterSection {
                            id: trafficSection
                            readonly property bool sectionEnabledState: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.sectionEnabled(root.trafficSectionId)
                            }
                            readonly property var commonRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.commonTrafficRows()
                            }
                            readonly property var packetDistributionIncludeOptions: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.packetDistributionIncludeOptions()
                            }
                            readonly property var packetDistributionExcludeOptions: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.packetDistributionExcludeOptions()
                            }
                            readonly property var dataDistributionIncludeOptions: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.dataDistributionIncludeOptions()
                            }
                            readonly property var dataDistributionExcludeOptions: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.dataDistributionExcludeOptions()
                            }
                            readonly property var directionalPacketRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.directionalPacketTrafficRows()
                            }
                            readonly property var directionalOriginalByteRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.directionalOriginalByteTrafficRows()
                            }
                            readonly property var additionalRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.additionalTrafficRows()
                            }

                            readonly property string sectionSummaryText: {
                                if (!root.editor) {
                                    return ""
                                }
                                void(root.editor.sectionSummaryRevision)
                                return root.editor.sectionSummaryText(root.trafficSectionId)
                            }

                            sectionObjectName: "advancedFlowFilterTrafficSection"
                            collapseButtonObjectName: "advancedFlowFilterTrafficCollapseButton"
                            enabledCheckBoxObjectName: "advancedFlowFilterTrafficEnabledCheckBox"
                            contentObjectName: "advancedFlowFilterTrafficContent"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            title: "Traffic"
                            summaryText: sectionSummaryText
                            expanded: root.sectionExpanded(root.trafficSectionId)
                            sectionEnabled: sectionEnabledState
                            contentEnabled: sectionEnabledState

                            property bool additionalExpanded: false

                            function initializeAdditionalVisibility() {
                                additionalExpanded = root.editor
                                    ? root.editor.trafficAdditionalFiltersExpandedSuggested()
                                    : false
                            }

                            Component.onCompleted: initializeAdditionalVisibility()

                            Connections {
                                target: root

                                function onInitializeDialogState() {
                                    trafficSection.initializeAdditionalVisibility()
                                }
                            }

                            onToggleRequested: root.setSectionExpanded(root.trafficSectionId, !root.sectionExpanded(root.trafficSectionId))
                            onSectionEnabledToggled: function(checked) {
                                if (root.editor) {
                                    root.editor.setSectionEnabled(root.trafficSectionId, checked)
                                }
                            }

                            RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 8

                                        Label {
                                            Layout.preferredWidth: 250
                                            text: "Value"
                                            color: "#475569"
                                            font.pixelSize: 12
                                            font.bold: true
                                        }

                                        Label {
                                            Layout.preferredWidth: 120
                                            text: "Minimum"
                                            color: "#475569"
                                            font.pixelSize: 12
                                            font.bold: true
                                        }

                                        Label {
                                            Layout.preferredWidth: 120
                                            text: "Maximum"
                                            color: "#475569"
                                            font.pixelSize: 12
                                            font.bold: true
                                        }

                                        Label {
                                            Layout.preferredWidth: 120
                                            text: "Unit"
                                            color: "#475569"
                                            font.pixelSize: 12
                                            font.bold: true
                                        }
                            }

                            Repeater {
                                        model: trafficSection.commonRows

                                        delegate: RowLayout {
                                            required property var modelData

                                            Layout.fillWidth: true
                                            spacing: 8

                                            Label {
                                                Layout.preferredWidth: 250
                                                text: modelData.label
                                                color: "#0f172a"
                                                elide: Text.ElideRight
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "MinTextField"
                                                Layout.preferredWidth: 120
                                                text: modelData.minText
                                                placeholderText: "0"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setTrafficMinText(modelData.metricId, text)
                                                    }
                                                }
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "MaxTextField"
                                                Layout.preferredWidth: 120
                                                text: modelData.maxText
                                                placeholderText: "100"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setTrafficMaxText(modelData.metricId, text)
                                                    }
                                                }
                                            }

                                            ComboBox {
                                                objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "UnitComboBox"
                                                Layout.preferredWidth: 120
                                                visible: modelData.hasUnitSelector
                                                model: modelData.unitOptions
                                                textRole: "label"
                                                currentIndex: root.optionIndex(model, modelData.selectedUnit)
                                                onActivated: {
                                                    if (root.editor) {
                                                        root.editor.setTrafficUnit(modelData.metricId, model[currentIndex].value)
                                                    }
                                                }
                                            }

                                            Label {
                                                objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "UnitLabel"
                                                Layout.preferredWidth: 120
                                                visible: !modelData.hasUnitSelector
                                                text: modelData.unitText
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                    }
                                }
                            }

                            FilterTextButton {
                                        objectName: "advancedFlowFilterTrafficAdditionalToggleButton"
                                        text: trafficSection.additionalExpanded
                                            ? "Hide additional traffic filters"
                                            : "+ More traffic filters"
                                        onClicked: trafficSection.additionalExpanded = !trafficSection.additionalExpanded
                            }

                            ColumnLayout {
                                        objectName: "advancedFlowFilterTrafficAdditionalSection"
                                        Layout.fillWidth: true
                                        visible: trafficSection.additionalExpanded
                                        spacing: 8

                                        Repeater {
                                            model: trafficSection.additionalRows

                                            delegate: RowLayout {
                                                required property var modelData

                                                Layout.fillWidth: true
                                                spacing: 8

                                                Label {
                                                    Layout.preferredWidth: 250
                                                    text: modelData.label
                                                    color: "#0f172a"
                                                    elide: Text.ElideRight
                                                }

                                                TextField {
                                                    objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "MinTextField"
                                                    Layout.preferredWidth: 120
                                                    text: modelData.minText
                                                    placeholderText: "0"
                                                    onTextEdited: {
                                                        if (root.editor) {
                                                            root.editor.setTrafficMinText(modelData.metricId, text)
                                                        }
                                                    }
                                                }

                                                TextField {
                                                    objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "MaxTextField"
                                                    Layout.preferredWidth: 120
                                                    text: modelData.maxText
                                                    placeholderText: "100"
                                                    onTextEdited: {
                                                        if (root.editor) {
                                                            root.editor.setTrafficMaxText(modelData.metricId, text)
                                                        }
                                                    }
                                                }

                                                ComboBox {
                                                    objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "UnitComboBox"
                                                    Layout.preferredWidth: 120
                                                    visible: modelData.hasUnitSelector
                                                    model: modelData.unitOptions
                                                    textRole: "label"
                                                    currentIndex: root.optionIndex(model, modelData.selectedUnit)
                                                    onActivated: {
                                                        if (root.editor) {
                                                            root.editor.setTrafficUnit(modelData.metricId, model[currentIndex].value)
                                                        }
                                                    }
                                                }

                                                Label {
                                                    objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "UnitLabel"
                                                    Layout.preferredWidth: 120
                                                    visible: !modelData.hasUnitSelector
                                                    text: modelData.unitText
                                                    color: "#475569"
                                                    verticalAlignment: Text.AlignVCenter
                                                }
                                            }
                                        }

                                        Rectangle {
                                            objectName: "advancedFlowFilterTrafficDirectionalSeparator"
                                            Layout.fillWidth: true
                                            implicitHeight: 1
                                            color: "#e2e8f0"
                                        }

                                        ColumnLayout {
                                            objectName: "advancedFlowFilterTrafficDirectionalCluster"
                                            Layout.fillWidth: true
                                            spacing: 8

                                            Label {
                                                objectName: "advancedFlowFilterTrafficDirectionHelperText"
                                                Layout.fillWidth: true
                                                text: "A -> B is the direction of the first observed packet in the connection."
                                                color: "#64748b"
                                                font.pixelSize: 12
                                                wrapMode: Text.WordWrap
                                            }

                                            AdvancedFlowFilterSemanticGroup {
                                                objectName: "advancedFlowFilterTrafficPacketDistributionGroup"
                                                Layout.fillWidth: true
                                                title: "Packet distribution"
                                                fillColor: root.includeRegionColor
                                                strokeColor: root.includeRegionBorderColor

                                                Label {
                                                    Layout.fillWidth: true
                                                    text: "Include"
                                                    color: "#475569"
                                                    font.pixelSize: 12
                                                    font.bold: true
                                                }

                                                Flow {
                                                    Layout.fillWidth: true
                                                    width: parent.width
                                                    spacing: 12

                                                    Repeater {
                                                        model: trafficSection.packetDistributionIncludeOptions

                                                        delegate: CheckBox {
                                                            required property var modelData

                                                            objectName: "advancedFlowFilterTrafficPacketDistributionInclude"
                                                                + modelData.objectNameSuffix
                                                                + "CheckBox"
                                                            text: modelData.label
                                                            checked: modelData.checked
                                                            onToggled: {
                                                                if (root.editor) {
                                                                    root.editor.setTrafficDistributionOptionChecked(false, modelData.value, false, checked)
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                Label {
                                                    Layout.fillWidth: true
                                                    text: "Exclude"
                                                    color: "#475569"
                                                    font.pixelSize: 12
                                                    font.bold: true
                                                }

                                                Flow {
                                                    Layout.fillWidth: true
                                                    width: parent.width
                                                    spacing: 12

                                                    Repeater {
                                                        model: trafficSection.packetDistributionExcludeOptions

                                                        delegate: CheckBox {
                                                            required property var modelData

                                                            objectName: "advancedFlowFilterTrafficPacketDistributionExclude"
                                                                + modelData.objectNameSuffix
                                                                + "CheckBox"
                                                            text: modelData.label
                                                            checked: modelData.checked
                                                            onToggled: {
                                                                if (root.editor) {
                                                                    root.editor.setTrafficDistributionOptionChecked(false, modelData.value, true, checked)
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            AdvancedFlowFilterSemanticGroup {
                                                objectName: "advancedFlowFilterTrafficDataDistributionGroup"
                                                Layout.fillWidth: true
                                                title: "Data distribution"
                                                fillColor: root.includeRegionColor
                                                strokeColor: root.includeRegionBorderColor

                                                Label {
                                                    Layout.fillWidth: true
                                                    text: "Data distribution uses original packet bytes."
                                                    color: "#64748b"
                                                    font.pixelSize: 12
                                                    wrapMode: Text.WordWrap
                                                }

                                                Label {
                                                    Layout.fillWidth: true
                                                    text: "Include"
                                                    color: "#475569"
                                                    font.pixelSize: 12
                                                    font.bold: true
                                                }

                                                Flow {
                                                    Layout.fillWidth: true
                                                    width: parent.width
                                                    spacing: 12

                                                    Repeater {
                                                        model: trafficSection.dataDistributionIncludeOptions

                                                        delegate: CheckBox {
                                                            required property var modelData

                                                            objectName: "advancedFlowFilterTrafficDataDistributionInclude"
                                                                + modelData.objectNameSuffix
                                                                + "CheckBox"
                                                            text: modelData.label
                                                            checked: modelData.checked
                                                            onToggled: {
                                                                if (root.editor) {
                                                                    root.editor.setTrafficDistributionOptionChecked(true, modelData.value, false, checked)
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                Label {
                                                    Layout.fillWidth: true
                                                    text: "Exclude"
                                                    color: "#475569"
                                                    font.pixelSize: 12
                                                    font.bold: true
                                                }

                                                Flow {
                                                    Layout.fillWidth: true
                                                    width: parent.width
                                                    spacing: 12

                                                    Repeater {
                                                        model: trafficSection.dataDistributionExcludeOptions

                                                        delegate: CheckBox {
                                                            required property var modelData

                                                            objectName: "advancedFlowFilterTrafficDataDistributionExclude"
                                                                + modelData.objectNameSuffix
                                                                + "CheckBox"
                                                            text: modelData.label
                                                            checked: modelData.checked
                                                            onToggled: {
                                                                if (root.editor) {
                                                                    root.editor.setTrafficDistributionOptionChecked(true, modelData.value, true, checked)
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            AdvancedFlowFilterSemanticGroup {
                                                objectName: "advancedFlowFilterTrafficDirectionalPacketsGroup"
                                                Layout.fillWidth: true
                                                title: "Directional packets"
                                                fillColor: root.includeRegionColor
                                                strokeColor: root.includeRegionBorderColor

                                                RowLayout {
                                                    Layout.fillWidth: true
                                                    spacing: 8

                                                    Label {
                                                        Layout.preferredWidth: 250
                                                        text: "Value"
                                                        color: "#475569"
                                                        font.pixelSize: 12
                                                        font.bold: true
                                                    }

                                                    Label {
                                                        Layout.preferredWidth: 120
                                                        text: "Minimum"
                                                        color: "#475569"
                                                        font.pixelSize: 12
                                                        font.bold: true
                                                    }

                                                    Label {
                                                        Layout.preferredWidth: 120
                                                        text: "Maximum"
                                                        color: "#475569"
                                                        font.pixelSize: 12
                                                        font.bold: true
                                                    }

                                                    Label {
                                                        Layout.preferredWidth: 120
                                                        text: "Unit"
                                                        color: "#475569"
                                                        font.pixelSize: 12
                                                        font.bold: true
                                                    }
                                                }

                                                Repeater {
                                                    model: trafficSection.directionalPacketRows

                                                    delegate: RowLayout {
                                                        required property var modelData

                                                        Layout.fillWidth: true
                                                        spacing: 8

                                                        Label {
                                                            Layout.preferredWidth: 250
                                                            text: modelData.label
                                                            color: "#0f172a"
                                                            elide: Text.ElideRight
                                                        }

                                                        TextField {
                                                            objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "MinTextField"
                                                            Layout.preferredWidth: 120
                                                            text: modelData.minText
                                                            placeholderText: "0"
                                                            onTextEdited: {
                                                                if (root.editor) {
                                                                    root.editor.setTrafficMinText(modelData.metricId, text)
                                                                }
                                                            }
                                                        }

                                                        TextField {
                                                            objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "MaxTextField"
                                                            Layout.preferredWidth: 120
                                                            text: modelData.maxText
                                                            placeholderText: "100"
                                                            onTextEdited: {
                                                                if (root.editor) {
                                                                    root.editor.setTrafficMaxText(modelData.metricId, text)
                                                                }
                                                            }
                                                        }

                                                        Label {
                                                            objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "UnitLabel"
                                                            Layout.preferredWidth: 120
                                                            text: modelData.unitText
                                                            color: "#475569"
                                                            verticalAlignment: Text.AlignVCenter
                                                        }
                                                    }
                                                }
                                            }

                                            AdvancedFlowFilterSemanticGroup {
                                                objectName: "advancedFlowFilterTrafficDirectionalOriginalBytesGroup"
                                                Layout.fillWidth: true
                                                title: "Directional original bytes"
                                                fillColor: root.includeRegionColor
                                                strokeColor: root.includeRegionBorderColor

                                                RowLayout {
                                                    Layout.fillWidth: true
                                                    spacing: 8

                                                    Label {
                                                        Layout.preferredWidth: 250
                                                        text: "Value"
                                                        color: "#475569"
                                                        font.pixelSize: 12
                                                        font.bold: true
                                                    }

                                                    Label {
                                                        Layout.preferredWidth: 120
                                                        text: "Minimum"
                                                        color: "#475569"
                                                        font.pixelSize: 12
                                                        font.bold: true
                                                    }

                                                    Label {
                                                        Layout.preferredWidth: 120
                                                        text: "Maximum"
                                                        color: "#475569"
                                                        font.pixelSize: 12
                                                        font.bold: true
                                                    }

                                                    Label {
                                                        Layout.preferredWidth: 120
                                                        text: "Unit"
                                                        color: "#475569"
                                                        font.pixelSize: 12
                                                        font.bold: true
                                                    }
                                                }

                                                Repeater {
                                                    model: trafficSection.directionalOriginalByteRows

                                                    delegate: RowLayout {
                                                        required property var modelData

                                                        Layout.fillWidth: true
                                                        spacing: 8

                                                        Label {
                                                            Layout.preferredWidth: 250
                                                            text: modelData.label
                                                            color: "#0f172a"
                                                            elide: Text.ElideRight
                                                        }

                                                        TextField {
                                                            objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "MinTextField"
                                                            Layout.preferredWidth: 120
                                                            text: modelData.minText
                                                            placeholderText: "0"
                                                            onTextEdited: {
                                                                if (root.editor) {
                                                                    root.editor.setTrafficMinText(modelData.metricId, text)
                                                                }
                                                            }
                                                        }

                                                        TextField {
                                                            objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "MaxTextField"
                                                            Layout.preferredWidth: 120
                                                            text: modelData.maxText
                                                            placeholderText: "100"
                                                            onTextEdited: {
                                                                if (root.editor) {
                                                                    root.editor.setTrafficMaxText(modelData.metricId, text)
                                                                }
                                                            }
                                                        }

                                                        ComboBox {
                                                            objectName: "advancedFlowFilter" + modelData.objectNamePrefix + "UnitComboBox"
                                                            Layout.preferredWidth: 120
                                                            model: modelData.unitOptions
                                                            textRole: "label"
                                                            currentIndex: root.optionIndex(model, modelData.selectedUnit)
                                                            onActivated: {
                                                                if (root.editor) {
                                                                    root.editor.setTrafficUnit(modelData.metricId, model[currentIndex].value)
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                            }
                        }

                        AdvancedFlowFilterSection {
                            id: serviceSection
                            readonly property bool sectionEnabledState: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.sectionEnabled(root.serviceSectionId)
                            }
                            readonly property bool includeKnownChecked: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.serviceStateChecked(false, root.serviceKnownKind)
                            }
                            readonly property bool includeUnknownChecked: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.serviceStateChecked(false, root.serviceUnknownKind)
                            }
                            readonly property bool excludeKnownChecked: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.serviceStateChecked(true, root.serviceKnownKind)
                            }
                            readonly property bool excludeUnknownChecked: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.serviceStateChecked(true, root.serviceUnknownKind)
                            }
                            readonly property bool includeTextRulesEditable: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.serviceTextRulesEditable(false)
                            }
                            readonly property var operatorOptions: root.editor
                                ? root.editor.serviceOperatorOptions()
                                : []
                            readonly property var includeTextRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.serviceTextRows(false)
                            }
                            readonly property var excludeTextRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.serviceTextRows(true)
                            }

                            readonly property string sectionSummaryText: {
                                if (!root.editor) {
                                    return ""
                                }
                                void(root.editor.sectionSummaryRevision)
                                return root.editor.sectionSummaryText(root.serviceSectionId)
                            }
                            readonly property int documentReloadRevision: root.editor
                                ? root.editor.documentReloadRevision
                                : 0

                            sectionObjectName: "advancedFlowFilterServiceSection"
                            collapseButtonObjectName: "advancedFlowFilterServiceCollapseButton"
                            enabledCheckBoxObjectName: "advancedFlowFilterServiceEnabledCheckBox"
                            contentObjectName: "advancedFlowFilterServiceContent"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            title: "Service"
                            summaryText: sectionSummaryText
                            expanded: root.sectionExpanded(root.serviceSectionId)
                            sectionEnabled: sectionEnabledState
                            contentEnabled: sectionEnabledState

                            property bool exclusionsExpanded: false

                            function initializeExclusionsVisibility() {
                                exclusionsExpanded = root.editor
                                    ? root.editor.sectionHasExclusions(root.serviceSectionId)
                                    : false
                            }

                            Component.onCompleted: initializeExclusionsVisibility()
                            onDocumentReloadRevisionChanged: initializeExclusionsVisibility()

                            Connections {
                                target: root

                                function onInitializeDialogState() {
                                    serviceSection.initializeExclusionsVisibility()
                                }
                            }

                            onToggleRequested: root.setSectionExpanded(root.serviceSectionId, !root.sectionExpanded(root.serviceSectionId))
                            onSectionEnabledToggled: function(checked) {
                                if (root.editor) {
                                    root.editor.setSectionEnabled(root.serviceSectionId, checked)
                                }
                            }

                            AdvancedFlowFilterSemanticGroup {
                                Layout.fillWidth: true
                                title: "Include"
                                fillColor: root.includeRegionColor
                                strokeColor: root.includeRegionBorderColor

                                Label {
                                    text: "Recognition"
                                    color: root.secondaryTextColor
                                    font.pixelSize: 12
                                    font.bold: true
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 12

                                    CheckBox {
                                        objectName: "advancedFlowFilterServiceIncludeKnownCheckBox"
                                        text: "Recognized"
                                        checked: serviceSection.includeKnownChecked
                                        onToggled: {
                                            if (root.editor) {
                                                root.editor.setServiceStateChecked(false, root.serviceKnownKind, checked)
                                            }
                                        }
                                    }

                                    CheckBox {
                                        objectName: "advancedFlowFilterServiceIncludeUnknownCheckBox"
                                        text: "Unrecognized"
                                        checked: serviceSection.includeUnknownChecked
                                        onToggled: {
                                            if (root.editor) {
                                                root.editor.setServiceStateChecked(false, root.serviceUnknownKind, checked)
                                            }
                                        }
                                    }
                                }

                                Label {
                                    text: "Text rules"
                                    color: root.secondaryTextColor
                                    font.pixelSize: 12
                                    font.bold: true
                                }

                                Label {
                                    visible: !serviceSection.includeTextRulesEditable
                                    text: "Text rules apply only to recognized services."
                                    color: root.secondaryTextColor
                                    font.pixelSize: 12
                                    wrapMode: Text.WordWrap
                                }

                                Repeater {
                                        model: serviceSection.includeTextRows

                                        delegate: Rectangle {
                                            required property var modelData

                                            Layout.fillWidth: true
                                            implicitHeight: includeServiceRowLayout.implicitHeight + 8
                                            color: root.rowSurfaceColor
                                            border.color: root.rowBorderColor
                                            radius: 5

                                            RowLayout {
                                                id: includeServiceRowLayout
                                                anchors.fill: parent
                                                anchors.margins: 4
                                                spacing: 8

                                                ComboBox {
                                                    objectName: "advancedFlowFilterServiceIncludeRow" + modelData.row + "KindComboBox"
                                                    Layout.preferredWidth: 150
                                                    enabled: serviceSection.includeTextRulesEditable
                                                    model: serviceSection.operatorOptions
                                                    textRole: "label"
                                                    currentIndex: root.optionIndex(model, modelData.kind)
                                                    onActivated: {
                                                        if (root.editor) {
                                                            root.editor.setServiceTextRowKind(false, modelData.row, model[currentIndex].value)
                                                        }
                                                    }
                                                }

                                                CheckBox {
                                                    objectName: "advancedFlowFilterServiceIncludeRow" + modelData.row + "CaseSensitiveCheckBox"
                                                    text: "Case sensitive"
                                                    enabled: serviceSection.includeTextRulesEditable
                                                    checked: modelData.caseSensitive
                                                    onToggled: {
                                                        if (root.editor) {
                                                            root.editor.setServiceTextRowCaseSensitive(false, modelData.row, checked)
                                                        }
                                                    }
                                                }

                                                TextField {
                                                    objectName: "advancedFlowFilterServiceIncludeRow" + modelData.row + "TextField"
                                                    Layout.fillWidth: true
                                                    enabled: serviceSection.includeTextRulesEditable
                                                    text: modelData.text
                                                    placeholderText: "youtube.com"
                                                    onTextEdited: {
                                                        if (root.editor) {
                                                            root.editor.setServiceTextRowText(false, modelData.row, text)
                                                        }
                                                    }
                                                }

                                                AdvancedFlowFilterRowRemoveButton {
                                                    objectName: "advancedFlowFilterServiceIncludeRow" + modelData.row + "RemoveButton"
                                                    accessibleLabel: root.rowRemoveAccessibleLabel("Service include")
                                                    tooltipText: "Remove rule"
                                                    onClicked: {
                                                        if (root.editor) {
                                                            root.editor.removeServiceTextRow(false, modelData.row)
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                }

                                FilterTextButton {
                                        objectName: "advancedFlowFilterServiceAddIncludeRuleButton"
                                        text: "+ Add service rule"
                                        enabled: serviceSection.includeTextRulesEditable
                                        onClicked: {
                                            if (root.editor) {
                                                root.editor.addServiceTextRow(false)
                                            }
                                        }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                visible: !serviceSection.exclusionsExpanded

                                Item {
                                    Layout.fillWidth: true
                                }

                                FilterFlatTextButton {
                                    objectName: "advancedFlowFilterServiceExclusionsToggleButton"
                                    text: "Exclusions"
                                    padding: 2
                                    onClicked: serviceSection.exclusionsExpanded = true
                                }
                            }

                            AdvancedFlowFilterSemanticGroup {
                                        objectName: "advancedFlowFilterServiceExclusionsSection"
                                        Layout.fillWidth: true
                                        visible: serviceSection.exclusionsExpanded
                                        title: "Exclude"
                                        fillColor: root.excludeRegionColor
                                        strokeColor: root.excludeRegionBorderColor
                                        actionVisible: true
                                        actionText: "Hide"
                                        actionObjectName: "advancedFlowFilterServiceHideExclusionsButton"
                                        onActionTriggered: serviceSection.exclusionsExpanded = false

                                Label {
                                            text: "Recognition"
                                            color: root.secondaryTextColor
                                            font.pixelSize: 12
                                            font.bold: true
                                }

                                RowLayout {
                                            Layout.fillWidth: true
                                            spacing: 12

                                            CheckBox {
                                                objectName: "advancedFlowFilterServiceExcludeKnownCheckBox"
                                                text: "Recognized"
                                                checked: serviceSection.excludeKnownChecked
                                                onToggled: {
                                                    if (root.editor) {
                                                        root.editor.setServiceStateChecked(true, root.serviceKnownKind, checked)
                                                    }
                                                }
                                            }

                                            CheckBox {
                                                objectName: "advancedFlowFilterServiceExcludeUnknownCheckBox"
                                                text: "Unrecognized"
                                                checked: serviceSection.excludeUnknownChecked
                                                onToggled: {
                                                    if (root.editor) {
                                                        root.editor.setServiceStateChecked(true, root.serviceUnknownKind, checked)
                                                    }
                                                }
                                            }
                                }

                                Label {
                                            text: "Text rules"
                                            color: root.secondaryTextColor
                                            font.pixelSize: 12
                                            font.bold: true
                                }

                                Repeater {
                                            model: serviceSection.excludeTextRows

                                            delegate: Rectangle {
                                                required property var modelData

                                                Layout.fillWidth: true
                                                implicitHeight: excludeServiceRowLayout.implicitHeight + 8
                                                color: root.rowSurfaceColor
                                                border.color: root.rowBorderColor
                                                radius: 5

                                                RowLayout {
                                                    id: excludeServiceRowLayout
                                                    anchors.fill: parent
                                                    anchors.margins: 4
                                                    spacing: 8

                                                    ComboBox {
                                                        objectName: "advancedFlowFilterServiceExcludeRow" + modelData.row + "KindComboBox"
                                                        Layout.preferredWidth: 150
                                                        model: serviceSection.operatorOptions
                                                        textRole: "label"
                                                        currentIndex: root.optionIndex(model, modelData.kind)
                                                        onActivated: {
                                                            if (root.editor) {
                                                                root.editor.setServiceTextRowKind(true, modelData.row, model[currentIndex].value)
                                                            }
                                                        }
                                                    }

                                                    CheckBox {
                                                        objectName: "advancedFlowFilterServiceExcludeRow" + modelData.row + "CaseSensitiveCheckBox"
                                                        text: "Case sensitive"
                                                        checked: modelData.caseSensitive
                                                        onToggled: {
                                                            if (root.editor) {
                                                                root.editor.setServiceTextRowCaseSensitive(true, modelData.row, checked)
                                                            }
                                                        }
                                                    }

                                                    TextField {
                                                        objectName: "advancedFlowFilterServiceExcludeRow" + modelData.row + "TextField"
                                                        Layout.fillWidth: true
                                                        text: modelData.text
                                                        placeholderText: "api.example.com"
                                                        onTextEdited: {
                                                            if (root.editor) {
                                                                root.editor.setServiceTextRowText(true, modelData.row, text)
                                                            }
                                                        }
                                                    }

                                                    AdvancedFlowFilterRowRemoveButton {
                                                        objectName: "advancedFlowFilterServiceExcludeRow" + modelData.row + "RemoveButton"
                                                        accessibleLabel: root.rowRemoveAccessibleLabel("Service exclude")
                                                        tooltipText: "Remove rule"
                                                        onClicked: {
                                                            if (root.editor) {
                                                                root.editor.removeServiceTextRow(true, modelData.row)
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                }

                                FilterTextButton {
                                            objectName: "advancedFlowFilterServiceAddExcludeRuleButton"
                                            text: "+ Add service rule"
                                            onClicked: {
                                                if (root.editor) {
                                                    root.editor.addServiceTextRow(true)
                                                }
                                            }
                                }
                            }
                        }

                        AdvancedFlowFilterSection {
                            id: protocolPathSection
                            readonly property bool sectionEnabledState: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.sectionEnabled(root.protocolPathSectionId)
                            }
                            readonly property var includeRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.protocolPathRows(false)
                            }
                            readonly property var excludeRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.protocolPathRows(true)
                            }

                            readonly property string sectionSummaryText: {
                                if (!root.editor) {
                                    return ""
                                }
                                void(root.editor.sectionSummaryRevision)
                                return root.editor.sectionSummaryText(root.protocolPathSectionId)
                            }
                            readonly property int documentReloadRevision: root.editor
                                ? root.editor.documentReloadRevision
                                : 0

                            sectionObjectName: "advancedFlowFilterProtocolPathSection"
                            collapseButtonObjectName: "advancedFlowFilterProtocolPathCollapseButton"
                            enabledCheckBoxObjectName: "advancedFlowFilterProtocolPathEnabledCheckBox"
                            contentObjectName: "advancedFlowFilterProtocolPathContent"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            title: "Protocol Path"
                            summaryText: sectionSummaryText
                            expanded: root.sectionExpanded(root.protocolPathSectionId)
                            sectionEnabled: sectionEnabledState
                            contentEnabled: sectionEnabledState

                            property bool exclusionsExpanded: false

                            function initializeExclusionsVisibility() {
                                exclusionsExpanded = root.editor
                                    ? root.editor.sectionHasExclusions(root.protocolPathSectionId)
                                    : false
                            }

                            Component.onCompleted: initializeExclusionsVisibility()
                            onDocumentReloadRevisionChanged: initializeExclusionsVisibility()

                            Connections {
                                target: root

                                function onInitializeDialogState() {
                                    protocolPathSection.initializeExclusionsVisibility()
                                }
                            }

                            onToggleRequested: root.setSectionExpanded(root.protocolPathSectionId, !root.sectionExpanded(root.protocolPathSectionId))
                            onSectionEnabledToggled: function(checked) {
                                if (root.editor) {
                                    root.editor.setSectionEnabled(root.protocolPathSectionId, checked)
                                }
                            }

                            Label {
                                        Layout.fillWidth: true
                                        visible: !(root.protocolPathSelector ? root.protocolPathSelector.hasCapture : false)
                                        text: "Open a capture to select protocol paths."
                                        color: root.secondaryTextColor
                                        font.pixelSize: 12
                                        wrapMode: Text.WordWrap
                            }

                            AdvancedFlowFilterSemanticGroup {
                                Layout.fillWidth: true
                                title: "Include"
                                fillColor: root.includeRegionColor
                                strokeColor: root.includeRegionBorderColor

                                Repeater {
                                    model: protocolPathSection.includeRows

                                    delegate: Rectangle {
                                        required property var modelData

                                        Layout.fillWidth: true
                                        implicitHeight: includeProtocolPathRowLayout.implicitHeight + 8
                                        color: root.rowSurfaceColor
                                        border.color: root.rowBorderColor
                                        radius: 5

                                        RowLayout {
                                            id: includeProtocolPathRowLayout
                                            anchors.fill: parent
                                            anchors.margins: 4
                                            spacing: 8

                                            Label {
                                                objectName: "advancedFlowFilterProtocolPathIncludeRow" + modelData.row + "ModeLabel"
                                                text: "[" + modelData.modeLabel + "]"
                                                color: "#1d4ed8"
                                                font.bold: true
                                            }

                                            Label {
                                                objectName: "advancedFlowFilterProtocolPathIncludeRow" + modelData.row + "TextLabel"
                                                Layout.fillWidth: true
                                                text: modelData.compactText
                                                color: root.primaryTextColor
                                                elide: Text.ElideRight
                                                HoverHandler {
                                                    id: includeProtocolPathTextHoverHandler
                                                }
                                                ToolTip.visible: includeProtocolPathTextHoverHandler.hovered
                                                ToolTip.text: root.protocolPathTooltipText(modelData)
                                            }

                                            Rectangle {
                                                visible: modelData.statusText.length > 0
                                                radius: 4
                                                color: root.warningIconFillColor
                                                border.color: root.warningIconBorderColor
                                                implicitHeight: statusLabel.implicitHeight + 6
                                                implicitWidth: statusLabel.implicitWidth + 10

                                                HoverHandler {
                                                    id: includeProtocolPathStatusHoverHandler
                                                }

                                                ToolTip.visible: includeProtocolPathStatusHoverHandler.hovered
                                                    && root.hasCompactApplicabilityWarning(modelData.statusText)
                                                ToolTip.text: modelData.statusText

                                                Label {
                                                    id: statusLabel
                                                    anchors.centerIn: parent
                                                    text: "\u26A0 " + root.compactApplicabilityWarningText(modelData.statusText)
                                                    color: root.warningTextColor
                                                    font.pixelSize: 11
                                                }
                                            }

                                            FilterTextButton {
                                                objectName: "advancedFlowFilterProtocolPathIncludeRow" + modelData.row + "EditButton"
                                                text: "Edit"
                                                enabled: root.protocolPathSelector ? root.protocolPathSelector.hasCapture : false
                                                onClicked: root.openProtocolPathSelector(false, modelData.row)
                                            }

                                            AdvancedFlowFilterRowRemoveButton {
                                                objectName: "advancedFlowFilterProtocolPathIncludeRow" + modelData.row + "RemoveButton"
                                                accessibleLabel: root.rowRemoveAccessibleLabel("Protocol Path include")
                                                tooltipText: "Remove rule"
                                                onClicked: {
                                                    if (root.controller) {
                                                        root.controller.removeAdvancedFlowFilterProtocolPathRow(false, modelData.row)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                FilterTextButton {
                                    objectName: "advancedFlowFilterProtocolPathAddIncludeButton"
                                    text: "+ Add path"
                                    enabled: root.protocolPathSelector ? root.protocolPathSelector.hasCapture : false
                                    onClicked: root.openProtocolPathSelector(false, -1)
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                visible: !protocolPathSection.exclusionsExpanded

                                Item {
                                    Layout.fillWidth: true
                                }

                                FilterFlatTextButton {
                                    objectName: "advancedFlowFilterProtocolPathExclusionsToggleButton"
                                    text: "Exclusions"
                                    padding: 2
                                    onClicked: protocolPathSection.exclusionsExpanded = true
                                }
                            }

                            AdvancedFlowFilterSemanticGroup {
                                objectName: "advancedFlowFilterProtocolPathExclusionsSection"
                                Layout.fillWidth: true
                                visible: protocolPathSection.exclusionsExpanded
                                title: "Exclude"
                                fillColor: root.excludeRegionColor
                                strokeColor: root.excludeRegionBorderColor
                                actionVisible: true
                                actionText: "Hide"
                                actionObjectName: "advancedFlowFilterProtocolPathHideExclusionsButton"
                                onActionTriggered: protocolPathSection.exclusionsExpanded = false

                                Repeater {
                                    model: protocolPathSection.excludeRows

                                    delegate: Rectangle {
                                        required property var modelData

                                        Layout.fillWidth: true
                                        implicitHeight: excludeProtocolPathRowLayout.implicitHeight + 8
                                        color: root.rowSurfaceColor
                                        border.color: root.rowBorderColor
                                        radius: 5

                                        RowLayout {
                                            id: excludeProtocolPathRowLayout
                                            anchors.fill: parent
                                            anchors.margins: 4
                                            spacing: 8

                                            Label {
                                                objectName: "advancedFlowFilterProtocolPathExcludeRow" + modelData.row + "ModeLabel"
                                                text: "[" + modelData.modeLabel + "]"
                                                color: "#1d4ed8"
                                                font.bold: true
                                            }

                                            Label {
                                                objectName: "advancedFlowFilterProtocolPathExcludeRow" + modelData.row + "TextLabel"
                                                Layout.fillWidth: true
                                                text: modelData.compactText
                                                color: root.primaryTextColor
                                                elide: Text.ElideRight
                                                HoverHandler {
                                                    id: excludeProtocolPathTextHoverHandler
                                                }
                                                ToolTip.visible: excludeProtocolPathTextHoverHandler.hovered
                                                ToolTip.text: root.protocolPathTooltipText(modelData)
                                            }

                                            Rectangle {
                                                visible: modelData.statusText.length > 0
                                                radius: 4
                                                color: root.warningIconFillColor
                                                border.color: root.warningIconBorderColor
                                                implicitHeight: excludeStatusLabel.implicitHeight + 6
                                                implicitWidth: excludeStatusLabel.implicitWidth + 10

                                                HoverHandler {
                                                    id: excludeProtocolPathStatusHoverHandler
                                                }

                                                ToolTip.visible: excludeProtocolPathStatusHoverHandler.hovered
                                                    && root.hasCompactApplicabilityWarning(modelData.statusText)
                                                ToolTip.text: modelData.statusText

                                                Label {
                                                    id: excludeStatusLabel
                                                    anchors.centerIn: parent
                                                    text: "\u26A0 " + root.compactApplicabilityWarningText(modelData.statusText)
                                                    color: root.warningTextColor
                                                    font.pixelSize: 11
                                                }
                                            }

                                            FilterTextButton {
                                                objectName: "advancedFlowFilterProtocolPathExcludeRow" + modelData.row + "EditButton"
                                                text: "Edit"
                                                enabled: root.protocolPathSelector ? root.protocolPathSelector.hasCapture : false
                                                onClicked: root.openProtocolPathSelector(true, modelData.row)
                                            }

                                            AdvancedFlowFilterRowRemoveButton {
                                                objectName: "advancedFlowFilterProtocolPathExcludeRow" + modelData.row + "RemoveButton"
                                                accessibleLabel: root.rowRemoveAccessibleLabel("Protocol Path exclude")
                                                tooltipText: "Remove rule"
                                                onClicked: {
                                                    if (root.controller) {
                                                        root.controller.removeAdvancedFlowFilterProtocolPathRow(true, modelData.row)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                FilterTextButton {
                                    objectName: "advancedFlowFilterProtocolPathAddExcludeButton"
                                    text: "+ Add path"
                                    enabled: root.protocolPathSelector ? root.protocolPathSelector.hasCapture : false
                                    onClicked: root.openProtocolPathSelector(true, -1)
                                }
                            }
                        }

                        AdvancedFlowFilterSection {
                            id: containsLayerSection
                            readonly property bool sectionEnabledState: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.sectionEnabled(root.containsLayerSectionId)
                            }
                            readonly property var layerOptions: root.editor
                                ? root.editor.containsLayerOptions()
                                : []
                            readonly property var identifierModeOptions: root.editor
                                ? root.editor.containsLayerIdentifierModeOptions()
                                : []
                            readonly property var includeRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.containsLayerRows(false)
                            }
                            readonly property var excludeRows: {
                                if (!root.editor) {
                                    return []
                                }
                                void(root.editor.revision)
                                return root.editor.containsLayerRows(true)
                            }
                            readonly property string sectionSummaryText: {
                                if (!root.editor) {
                                    return ""
                                }
                                void(root.editor.sectionSummaryRevision)
                                return root.editor.sectionSummaryText(root.containsLayerSectionId)
                            }
                            readonly property int documentReloadRevision: root.editor
                                ? root.editor.documentReloadRevision
                                : 0

                            sectionObjectName: "advancedFlowFilterContainsLayerSection"
                            collapseButtonObjectName: "advancedFlowFilterContainsLayerCollapseButton"
                            enabledCheckBoxObjectName: "advancedFlowFilterContainsLayerEnabledCheckBox"
                            contentObjectName: "advancedFlowFilterContainsLayerContent"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            title: "Contains Layer"
                            summaryText: sectionSummaryText
                            expanded: root.sectionExpanded(root.containsLayerSectionId)
                            sectionEnabled: sectionEnabledState
                            contentEnabled: sectionEnabledState

                            property bool exclusionsExpanded: false

                            function initializeExclusionsVisibility() {
                                exclusionsExpanded = root.editor
                                    ? root.editor.sectionHasExclusions(root.containsLayerSectionId)
                                    : false
                            }

                            Component.onCompleted: initializeExclusionsVisibility()
                            onDocumentReloadRevisionChanged: initializeExclusionsVisibility()

                            Connections {
                                target: root

                                function onInitializeDialogState() {
                                    containsLayerSection.initializeExclusionsVisibility()
                                }
                            }

                            onToggleRequested: root.setSectionExpanded(root.containsLayerSectionId, !root.sectionExpanded(root.containsLayerSectionId))
                            onSectionEnabledToggled: function(checked) {
                                if (root.editor) {
                                    root.editor.setSectionEnabled(root.containsLayerSectionId, checked)
                                }
                            }

                            AdvancedFlowFilterSemanticGroup {
                                Layout.fillWidth: true
                                title: "Include"
                                fillColor: root.includeRegionColor
                                strokeColor: root.includeRegionBorderColor

                                Repeater {
                                    model: containsLayerSection.includeRows

                                    delegate: Rectangle {
                                        required property var modelData

                                        Layout.fillWidth: true
                                        implicitHeight: includeContainsLayerRowLayout.implicitHeight + 8
                                        color: root.rowSurfaceColor
                                        border.color: root.rowBorderColor
                                        radius: 5

                                        RowLayout {
                                            id: includeContainsLayerRowLayout
                                            anchors.fill: parent
                                            anchors.margins: 4
                                            spacing: 8

                                            ComboBox {
                                                objectName: "advancedFlowFilterContainsLayerIncludeRow" + modelData.row + "LayerComboBox"
                                                Layout.preferredWidth: 170
                                                model: containsLayerSection.layerOptions
                                                textRole: "label"
                                                currentIndex: root.optionIndex(model, modelData.layerKind)
                                                onActivated: {
                                                    if (root.editor) {
                                                        root.editor.setContainsLayerRowKind(false, modelData.row, model[currentIndex].value)
                                                    }
                                                }
                                            }

                                            ComboBox {
                                                objectName: "advancedFlowFilterContainsLayerIncludeRow" + modelData.row + "IdentifierModeComboBox"
                                                Layout.preferredWidth: 130
                                                model: containsLayerSection.identifierModeOptions
                                                textRole: "label"
                                                currentIndex: root.optionIndex(model, modelData.identifierMode)
                                                onActivated: {
                                                    if (root.editor) {
                                                        root.editor.setContainsLayerRowIdentifierMode(false, modelData.row, model[currentIndex].value)
                                                    }
                                                }
                                            }

                                            Label {
                                                objectName: "advancedFlowFilterContainsLayerIncludeRow" + modelData.row + "IdentifierLabel"
                                                visible: modelData.identifierMode === root.containsLayerIdentifierModeExact
                                                text: modelData.identifierLabel
                                                color: "#475569"
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterContainsLayerIncludeRow" + modelData.row + "ExactValueTextField"
                                                Layout.fillWidth: true
                                                visible: modelData.identifierMode === root.containsLayerIdentifierModeExact
                                                text: modelData.exactValueText
                                                placeholderText: modelData.exactValuePlaceholder
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setContainsLayerRowExactValueText(false, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Item {
                                                Layout.fillWidth: modelData.identifierMode !== root.containsLayerIdentifierModeExact
                                            }

                                            Rectangle {
                                                visible: modelData.statusText.length > 0
                                                radius: 4
                                                color: root.warningIconFillColor
                                                border.color: root.warningIconBorderColor
                                                implicitHeight: includeContainsLayerStatusLabel.implicitHeight + 6
                                                implicitWidth: includeContainsLayerStatusLabel.implicitWidth + 10

                                                HoverHandler {
                                                    id: includeContainsLayerStatusHoverHandler
                                                }

                                                ToolTip.visible: includeContainsLayerStatusHoverHandler.hovered
                                                    && root.hasCompactApplicabilityWarning(modelData.statusText)
                                                ToolTip.text: modelData.statusText

                                                Label {
                                                    id: includeContainsLayerStatusLabel
                                                    anchors.centerIn: parent
                                                    objectName: "advancedFlowFilterContainsLayerIncludeRow" + modelData.row + "StatusLabel"
                                                    text: "\u26A0 " + root.compactApplicabilityWarningText(modelData.statusText)
                                                    color: root.warningTextColor
                                                    font.pixelSize: 11
                                                }
                                            }

                                            AdvancedFlowFilterRowRemoveButton {
                                                objectName: "advancedFlowFilterContainsLayerIncludeRow" + modelData.row + "RemoveButton"
                                                accessibleLabel: root.rowRemoveAccessibleLabel("Contains Layer include")
                                                tooltipText: "Remove rule"
                                                onClicked: {
                                                    if (root.editor) {
                                                        root.editor.removeContainsLayerRow(false, modelData.row)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                FilterTextButton {
                                    objectName: "advancedFlowFilterContainsLayerAddIncludeButton"
                                    text: "+ Add layer"
                                    onClicked: {
                                        if (root.editor) {
                                            root.editor.addContainsLayerRow(false)
                                        }
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                visible: !containsLayerSection.exclusionsExpanded

                                Item {
                                    Layout.fillWidth: true
                                }

                                FilterFlatTextButton {
                                    objectName: "advancedFlowFilterContainsLayerExclusionsToggleButton"
                                    text: "Exclusions"
                                    padding: 2
                                    onClicked: containsLayerSection.exclusionsExpanded = true
                                }
                            }

                            AdvancedFlowFilterSemanticGroup {
                                objectName: "advancedFlowFilterContainsLayerExclusionsSection"
                                Layout.fillWidth: true
                                visible: containsLayerSection.exclusionsExpanded
                                title: "Exclude"
                                fillColor: root.excludeRegionColor
                                strokeColor: root.excludeRegionBorderColor
                                actionVisible: true
                                actionText: "Hide"
                                actionObjectName: "advancedFlowFilterContainsLayerHideExclusionsButton"
                                onActionTriggered: containsLayerSection.exclusionsExpanded = false

                                Repeater {
                                    model: containsLayerSection.excludeRows

                                    delegate: Rectangle {
                                        required property var modelData

                                        Layout.fillWidth: true
                                        implicitHeight: excludeContainsLayerRowLayout.implicitHeight + 8
                                        color: root.rowSurfaceColor
                                        border.color: root.rowBorderColor
                                        radius: 5

                                        RowLayout {
                                            id: excludeContainsLayerRowLayout
                                            anchors.fill: parent
                                            anchors.margins: 4
                                            spacing: 8

                                            ComboBox {
                                                objectName: "advancedFlowFilterContainsLayerExcludeRow" + modelData.row + "LayerComboBox"
                                                Layout.preferredWidth: 170
                                                model: containsLayerSection.layerOptions
                                                textRole: "label"
                                                currentIndex: root.optionIndex(model, modelData.layerKind)
                                                onActivated: {
                                                    if (root.editor) {
                                                        root.editor.setContainsLayerRowKind(true, modelData.row, model[currentIndex].value)
                                                    }
                                                }
                                            }

                                            ComboBox {
                                                objectName: "advancedFlowFilterContainsLayerExcludeRow" + modelData.row + "IdentifierModeComboBox"
                                                Layout.preferredWidth: 130
                                                model: containsLayerSection.identifierModeOptions
                                                textRole: "label"
                                                currentIndex: root.optionIndex(model, modelData.identifierMode)
                                                onActivated: {
                                                    if (root.editor) {
                                                        root.editor.setContainsLayerRowIdentifierMode(true, modelData.row, model[currentIndex].value)
                                                    }
                                                }
                                            }

                                            Label {
                                                objectName: "advancedFlowFilterContainsLayerExcludeRow" + modelData.row + "IdentifierLabel"
                                                visible: modelData.identifierMode === root.containsLayerIdentifierModeExact
                                                text: modelData.identifierLabel
                                                color: "#475569"
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterContainsLayerExcludeRow" + modelData.row + "ExactValueTextField"
                                                Layout.fillWidth: true
                                                visible: modelData.identifierMode === root.containsLayerIdentifierModeExact
                                                text: modelData.exactValueText
                                                placeholderText: modelData.exactValuePlaceholder
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setContainsLayerRowExactValueText(true, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Item {
                                                Layout.fillWidth: modelData.identifierMode !== root.containsLayerIdentifierModeExact
                                            }

                                            Rectangle {
                                                visible: modelData.statusText.length > 0
                                                radius: 4
                                                color: root.warningIconFillColor
                                                border.color: root.warningIconBorderColor
                                                implicitHeight: excludeContainsLayerStatusLabel.implicitHeight + 6
                                                implicitWidth: excludeContainsLayerStatusLabel.implicitWidth + 10

                                                HoverHandler {
                                                    id: excludeContainsLayerStatusHoverHandler
                                                }

                                                ToolTip.visible: excludeContainsLayerStatusHoverHandler.hovered
                                                    && root.hasCompactApplicabilityWarning(modelData.statusText)
                                                ToolTip.text: modelData.statusText

                                                Label {
                                                    id: excludeContainsLayerStatusLabel
                                                    anchors.centerIn: parent
                                                    objectName: "advancedFlowFilterContainsLayerExcludeRow" + modelData.row + "StatusLabel"
                                                    text: "\u26A0 " + root.compactApplicabilityWarningText(modelData.statusText)
                                                    color: root.warningTextColor
                                                    font.pixelSize: 11
                                                }
                                            }

                                            AdvancedFlowFilterRowRemoveButton {
                                                objectName: "advancedFlowFilterContainsLayerExcludeRow" + modelData.row + "RemoveButton"
                                                accessibleLabel: root.rowRemoveAccessibleLabel("Contains Layer exclude")
                                                tooltipText: "Remove rule"
                                                onClicked: {
                                                    if (root.editor) {
                                                        root.editor.removeContainsLayerRow(true, modelData.row)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                FilterTextButton {
                                    objectName: "advancedFlowFilterContainsLayerAddExcludeButton"
                                    text: "+ Add layer"
                                    onClicked: {
                                        if (root.editor) {
                                            root.editor.addContainsLayerRow(true)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Label {
                objectName: "advancedFlowFilterValidationLabel"
                Layout.fillWidth: true
                visible: text.length > 0
                text: root.editor ? root.editor.validationText : ""
                color: "#b91c1c"
                font.pixelSize: 12
                wrapMode: Text.WordWrap
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 4
                Layout.bottomMargin: 4
                spacing: 8

                FilterTextButton {
                    objectName: "advancedFlowFilterClearAllButton"
                    text: "Clear all"
                    enabled: root.editor ? root.editor.draftClearAllAvailable : false
                    onClicked: {
                        if (root.controller) {
                            root.controller.clearAdvancedFlowFilter()
                        }
                    }
                }

                Item {
                    Layout.fillWidth: true
                }

                FilterTextButton {
                    objectName: "advancedFlowFilterCancelButton"
                    text: "Cancel"
                    onClicked: root.close()
                }

                FilterTextButton {
                    objectName: "advancedFlowFilterApplyButton"
                    text: "Apply"
                    highlighted: true
                    onClicked: {
                        if (!root.controller) {
                            root.applyingDraft = true
                            root.close()
                            return
                        }

                        if (root.controller.applyAdvancedFlowFilterEdit()) {
                            root.applyingDraft = true
                            root.close()
                        }
                    }
                }
            }
        }
    }

    AdvancedFlowFilterProtocolPathSelectorDialog {
        id: protocolPathSelectorDialog
        parent: root.parent
        x: parent ? Math.round((parent.width - width) / 2) : 0
        y: parent ? Math.round((parent.height - height) / 2) : 0
        selector: root.protocolPathSelector
        onSelectRequested: {
            if (root.controller && root.controller.applyAdvancedFlowFilterProtocolPathSelection()) {
                close()
            }
        }
    }

}
