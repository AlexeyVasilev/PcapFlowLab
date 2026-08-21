import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    objectName: "advancedFlowFilterSettingsDialog"

    property var controller: null
    readonly property var editor: root.controller ? root.controller.advancedFlowFilterEditor : null
    readonly property var protocolPathSelector: root.controller ? root.controller.advancedFlowFilterProtocolPathSelector : null
    property bool applyingDraft: false
    property var sectionExpansionState: ({})
    readonly property int portsSectionId: 6
    readonly property int ipAddressesSectionId: 7
    readonly property int trafficSectionId: 8
    readonly property int serviceSectionId: 9
    readonly property int protocolPathSectionId: 10
    readonly property int containsLayerSectionId: 11
    readonly property int serviceKnownKind: 0
    readonly property int serviceUnknownKind: 1
    readonly property int containsLayerIdentifierModeAny: 0
    readonly property int containsLayerIdentifierModeExact: 1
    readonly property var allSectionIds: [
        0, 1, 2, 3, 4, 5,
        root.portsSectionId,
        root.ipAddressesSectionId,
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
        initializeSectionExpansionState()
        initializeDialogState()
    }

    onClosed: {
        protocolPathSelectorDialog.close()
        if (!applyingDraft && controller) {
            controller.cancelAdvancedFlowFilterEdit()
        }
        applyingDraft = false
    }

    contentItem: Item {
        implicitWidth: 920
        implicitHeight: contentLayout.implicitHeight + 24

        ColumnLayout {
            id: contentLayout
            anchors.fill: parent
            anchors.margins: 18
            spacing: 14

            RowLayout {
                Layout.fillWidth: true
                spacing: 8

                Button {
                    objectName: "advancedFlowFilterOpenFilterButton"
                    text: "Open filter..."
                    enabled: root.controller !== null
                    onClicked: root.controller.openAdvancedFlowFilterFile()
                }

                Button {
                    objectName: "advancedFlowFilterClearUnsavedChangesButton"
                    text: "Clear unsaved changes"
                    enabled: root.editor ? root.editor.draftClearUnsavedChangesAvailable : false
                    onClicked: {
                        if (root.controller) {
                            root.controller.clearAdvancedFlowFilterUnsavedChanges()
                        }
                    }
                }

                Item {
                    Layout.fillWidth: true
                }

                Button {
                    objectName: "advancedFlowFilterSaveButton"
                    text: "Save"
                    enabled: root.controller !== null
                    onClicked: root.controller.saveAdvancedFlowFilterFile()
                }

                Button {
                    objectName: "advancedFlowFilterSaveAsButton"
                    text: "Save As..."
                    enabled: root.controller !== null
                    onClicked: root.controller.saveAdvancedFlowFilterFileAs()
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 4

                Label {
                    objectName: "advancedFlowFilterIdentityLabel"
                    Layout.fillWidth: true
                    text: "Filter: " + (root.controller ? root.controller.advancedFlowFilterDisplayName : "Custom filter")
                    color: "#0f172a"
                    font.pixelSize: 15
                    font.bold: true
                    elide: Text.ElideRight
                }

                Label {
                    objectName: "advancedFlowFilterIdentityRuleCountLabel"
                    Layout.fillWidth: true
                    text: root.controller ? root.controller.advancedFlowFilterRuleCountText : "0 rules"
                    color: "#64748b"
                    font.pixelSize: 12
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
                    anchors.fill: parent
                    anchors.margins: 1
                    clip: true
                    contentWidth: availableWidth

                    ScrollBar.vertical: AppScrollBar {
                        parent: sectionScrollView
                        x: sectionScrollView.mirrored ? 0 : sectionScrollView.width - width
                        y: sectionScrollView.topPadding
                        height: sectionScrollView.availableHeight
                        policy: sectionScrollView.contentHeight > sectionScrollView.height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
                    }

                    ColumnLayout {
                        id: sectionColumn
                        width: sectionScrollView.availableWidth
                        spacing: 12

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
                                    text: "One direction means packets were observed in only one flow direction. Both directions means at least one packet was observed in each direction."
                                    color: "#64748b"
                                    font.pixelSize: 12
                                    wrapMode: Text.WordWrap
                                }

                                Label {
                                    text: "Include"
                                    color: "#475569"
                                    font.pixelSize: 12
                                    font.bold: true
                                }

                                Flow {
                                    Layout.fillWidth: true
                                    width: parent.width
                                    spacing: 16

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

                                Button {
                                    objectName: "advancedFlowFilter"
                                        + finiteSectionCard.sectionObjectNamePrefix
                                        + "ExclusionsToggleButton"
                                    text: finiteSectionCard.exclusionsExpanded ? "Hide exclusions" : "Exclusions"
                                    onClicked: finiteSectionCard.exclusionsExpanded = !finiteSectionCard.exclusionsExpanded
                                }

                                ColumnLayout {
                                    objectName: "advancedFlowFilter"
                                        + finiteSectionCard.sectionObjectNamePrefix
                                        + "ExclusionsSection"
                                    Layout.fillWidth: true
                                    visible: finiteSectionCard.exclusionsExpanded
                                    spacing: 10

                                    Label {
                                        text: "Exclude"
                                        color: "#475569"
                                        font.pixelSize: 12
                                        font.bold: true
                                    }

                                    Flow {
                                        Layout.fillWidth: true
                                        width: parent.width
                                        spacing: 16

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

                            Label {
                                text: "Include"
                                color: "#475569"
                                font.pixelSize: 12
                                font.bold: true
                            }

                            Repeater {
                                model: portsSection.includeRows

                                delegate: Rectangle {
                                    required property var modelData

                                    Layout.fillWidth: true
                                    implicitHeight: includePortRowFlow.implicitHeight + 12
                                    color: "#f8fafc"
                                    border.color: "#e2e8f0"
                                    radius: 6

                                    Flow {
                                        id: includePortRowFlow
                                        x: 10
                                        y: 6
                                        width: parent.width - 20
                                        spacing: 8

                                        ComboBox {
                                            objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "ScopeComboBox"
                                            width: 170
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
                                            text: modelData.rangeEnabled ? "From" : "Port"
                                            color: "#475569"
                                            verticalAlignment: Text.AlignVCenter
                                        }

                                        TextField {
                                            objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "PrimaryTextField"
                                            width: 96
                                            text: modelData.primaryText
                                            placeholderText: modelData.rangeEnabled ? "8000" : "443"
                                            onTextEdited: {
                                                if (root.editor) {
                                                    root.editor.setPortRowPrimaryText(false, modelData.row, text)
                                                }
                                            }
                                        }

                                        Label {
                                            visible: modelData.rangeEnabled
                                            text: "To"
                                            color: "#475569"
                                            verticalAlignment: Text.AlignVCenter
                                        }

                                        TextField {
                                            objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "SecondaryTextField"
                                            visible: modelData.rangeEnabled
                                            width: 96
                                            text: modelData.secondaryText
                                            placeholderText: "9000"
                                            onTextEdited: {
                                                if (root.editor) {
                                                    root.editor.setPortRowSecondaryText(false, modelData.row, text)
                                                }
                                            }
                                        }

                                        Button {
                                            objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "RemoveButton"
                                            text: "Remove"
                                            onClicked: {
                                                if (root.editor) {
                                                    root.editor.removePortRow(false, modelData.row)
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            Button {
                                objectName: "advancedFlowFilterPortsAddIncludeButton"
                                text: "+ Add port"
                                onClicked: {
                                    if (root.editor) {
                                        root.editor.addPortRow(false)
                                    }
                                }
                            }

                            Button {
                                objectName: "advancedFlowFilterPortsExclusionsToggleButton"
                                text: portsSection.exclusionsExpanded ? "Hide exclusions" : "Exclusions"
                                onClicked: portsSection.exclusionsExpanded = !portsSection.exclusionsExpanded
                            }

                            ColumnLayout {
                                objectName: "advancedFlowFilterPortsExclusionsSection"
                                Layout.fillWidth: true
                                visible: portsSection.exclusionsExpanded
                                spacing: 10

                                Label {
                                    text: "Exclude"
                                    color: "#475569"
                                    font.pixelSize: 12
                                    font.bold: true
                                }

                                Repeater {
                                    model: portsSection.excludeRows

                                    delegate: Rectangle {
                                        required property var modelData

                                        Layout.fillWidth: true
                                        implicitHeight: excludePortRowFlow.implicitHeight + 12
                                        color: "#f8fafc"
                                        border.color: "#e2e8f0"
                                        radius: 6

                                        Flow {
                                            id: excludePortRowFlow
                                            x: 10
                                            y: 6
                                            width: parent.width - 20
                                            spacing: 8

                                            ComboBox {
                                                objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "ScopeComboBox"
                                                width: 170
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
                                                text: modelData.rangeEnabled ? "From" : "Port"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "PrimaryTextField"
                                                width: 96
                                                text: modelData.primaryText
                                                placeholderText: modelData.rangeEnabled ? "1" : "53"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setPortRowPrimaryText(true, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Label {
                                                visible: modelData.rangeEnabled
                                                text: "To"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "SecondaryTextField"
                                                visible: modelData.rangeEnabled
                                                width: 96
                                                text: modelData.secondaryText
                                                placeholderText: "1023"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setPortRowSecondaryText(true, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Button {
                                                objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "RemoveButton"
                                                text: "Remove"
                                                onClicked: {
                                                    if (root.editor) {
                                                        root.editor.removePortRow(true, modelData.row)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                Button {
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

                            Label {
                                text: "Include"
                                color: "#475569"
                                font.pixelSize: 12
                                font.bold: true
                            }

                            Repeater {
                                model: ipAddressesSection.includeRows

                                delegate: Rectangle {
                                    required property var modelData

                                    Layout.fillWidth: true
                                    implicitHeight: includeAddressRowFlow.implicitHeight + 12
                                    color: "#f8fafc"
                                    border.color: "#e2e8f0"
                                    radius: 6

                                    Flow {
                                        id: includeAddressRowFlow
                                        x: 10
                                        y: 6
                                        width: parent.width - 20
                                        spacing: 8

                                        ComboBox {
                                            objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "ScopeComboBox"
                                            width: 170
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
                                            text: "Address"
                                            color: "#475569"
                                            verticalAlignment: Text.AlignVCenter
                                        }

                                        TextField {
                                            objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "AddressTextField"
                                            width: 220
                                            text: modelData.addressText
                                            placeholderText: modelData.subnetEnabled ? "10.0.0.0" : "192.168.1.10"
                                            onTextEdited: {
                                                if (root.editor) {
                                                    root.editor.setAddressRowAddressText(false, modelData.row, text)
                                                }
                                            }
                                        }

                                        Label {
                                            visible: modelData.subnetEnabled
                                            text: "Prefix"
                                            color: "#475569"
                                            verticalAlignment: Text.AlignVCenter
                                        }

                                        TextField {
                                            objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "PrefixTextField"
                                            visible: modelData.subnetEnabled
                                            width: 76
                                            text: modelData.prefixText
                                            placeholderText: "24"
                                            onTextEdited: {
                                                if (root.editor) {
                                                    root.editor.setAddressRowPrefixText(false, modelData.row, text)
                                                }
                                            }
                                        }

                                        Button {
                                            objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "RemoveButton"
                                            text: "Remove"
                                            onClicked: {
                                                if (root.editor) {
                                                    root.editor.removeAddressRow(false, modelData.row)
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            Button {
                                objectName: "advancedFlowFilterIpAddressesAddIncludeButton"
                                text: "+ Add address"
                                onClicked: {
                                    if (root.editor) {
                                        root.editor.addAddressRow(false)
                                    }
                                }
                            }

                            Button {
                                objectName: "advancedFlowFilterIpAddressesExclusionsToggleButton"
                                text: ipAddressesSection.exclusionsExpanded ? "Hide exclusions" : "Exclusions"
                                onClicked: ipAddressesSection.exclusionsExpanded = !ipAddressesSection.exclusionsExpanded
                            }

                            ColumnLayout {
                                objectName: "advancedFlowFilterIpAddressesExclusionsSection"
                                Layout.fillWidth: true
                                visible: ipAddressesSection.exclusionsExpanded
                                spacing: 10

                                Label {
                                    text: "Exclude"
                                    color: "#475569"
                                    font.pixelSize: 12
                                    font.bold: true
                                }

                                Repeater {
                                    model: ipAddressesSection.excludeRows

                                    delegate: Rectangle {
                                        required property var modelData

                                        Layout.fillWidth: true
                                        implicitHeight: excludeAddressRowFlow.implicitHeight + 12
                                        color: "#f8fafc"
                                        border.color: "#e2e8f0"
                                        radius: 6

                                        Flow {
                                            id: excludeAddressRowFlow
                                            x: 10
                                            y: 6
                                            width: parent.width - 20
                                            spacing: 8

                                            ComboBox {
                                                objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "ScopeComboBox"
                                                width: 170
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
                                                text: "Address"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "AddressTextField"
                                                width: 220
                                                text: modelData.addressText
                                                placeholderText: modelData.subnetEnabled ? "2001:db8::" : "2001:db8::1"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setAddressRowAddressText(true, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Label {
                                                visible: modelData.subnetEnabled
                                                text: "Prefix"
                                                color: "#475569"
                                                verticalAlignment: Text.AlignVCenter
                                            }

                                            TextField {
                                                objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "PrefixTextField"
                                                visible: modelData.subnetEnabled
                                                width: 76
                                                text: modelData.prefixText
                                                placeholderText: "32"
                                                onTextEdited: {
                                                    if (root.editor) {
                                                        root.editor.setAddressRowPrefixText(true, modelData.row, text)
                                                    }
                                                }
                                            }

                                            Button {
                                                objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "RemoveButton"
                                                text: "Remove"
                                                onClicked: {
                                                    if (root.editor) {
                                                        root.editor.removeAddressRow(true, modelData.row)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                Button {
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

                            Button {
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

                            Label {
                                text: "Include"
                                color: "#475569"
                                font.pixelSize: 12
                                font.bold: true
                            }

                            Label {
                                text: "State"
                                color: "#475569"
                                font.pixelSize: 12
                                font.bold: true
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 18

                                CheckBox {
                                    objectName: "advancedFlowFilterServiceIncludeKnownCheckBox"
                                    text: "Known"
                                    checked: serviceSection.includeKnownChecked
                                    onToggled: {
                                        if (root.editor) {
                                            root.editor.setServiceStateChecked(false, root.serviceKnownKind, checked)
                                        }
                                    }
                                }

                                CheckBox {
                                    objectName: "advancedFlowFilterServiceIncludeUnknownCheckBox"
                                    text: "Unknown"
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
                                color: "#475569"
                                font.pixelSize: 12
                                font.bold: true
                            }

                            Repeater {
                                        model: serviceSection.includeTextRows

                                        delegate: Rectangle {
                                            required property var modelData

                                            Layout.fillWidth: true
                                            implicitHeight: includeServiceRowLayout.implicitHeight + 12
                                            color: "#f8fafc"
                                            border.color: "#e2e8f0"
                                            radius: 6

                                            RowLayout {
                                                id: includeServiceRowLayout
                                                anchors.fill: parent
                                                anchors.margins: 6
                                                spacing: 8

                                                ComboBox {
                                                    objectName: "advancedFlowFilterServiceIncludeRow" + modelData.row + "KindComboBox"
                                                    Layout.preferredWidth: 150
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
                                                    text: modelData.text
                                                    placeholderText: "youtube.com"
                                                    onTextEdited: {
                                                        if (root.editor) {
                                                            root.editor.setServiceTextRowText(false, modelData.row, text)
                                                        }
                                                    }
                                                }

                                                Button {
                                                    objectName: "advancedFlowFilterServiceIncludeRow" + modelData.row + "RemoveButton"
                                                    text: "Remove"
                                                    onClicked: {
                                                        if (root.editor) {
                                                            root.editor.removeServiceTextRow(false, modelData.row)
                                                        }
                                                    }
                                                }
                                            }
                                        }
                            }

                            Button {
                                        objectName: "advancedFlowFilterServiceAddIncludeRuleButton"
                                        text: "+ Add service rule"
                                        onClicked: {
                                            if (root.editor) {
                                                root.editor.addServiceTextRow(false)
                                            }
                                        }
                            }

                            Button {
                                        objectName: "advancedFlowFilterServiceExclusionsToggleButton"
                                        text: serviceSection.exclusionsExpanded ? "Hide exclusions" : "Exclusions"
                                        onClicked: serviceSection.exclusionsExpanded = !serviceSection.exclusionsExpanded
                            }

                            ColumnLayout {
                                        objectName: "advancedFlowFilterServiceExclusionsSection"
                                        Layout.fillWidth: true
                                        visible: serviceSection.exclusionsExpanded
                                        spacing: 10

                                Label {
                                            text: "Exclude"
                                            color: "#475569"
                                            font.pixelSize: 12
                                            font.bold: true
                                }

                                Label {
                                            text: "State"
                                            color: "#475569"
                                            font.pixelSize: 12
                                            font.bold: true
                                }

                                RowLayout {
                                            Layout.fillWidth: true
                                            spacing: 18

                                            CheckBox {
                                                objectName: "advancedFlowFilterServiceExcludeKnownCheckBox"
                                                text: "Known"
                                                checked: serviceSection.excludeKnownChecked
                                                onToggled: {
                                                    if (root.editor) {
                                                        root.editor.setServiceStateChecked(true, root.serviceKnownKind, checked)
                                                    }
                                                }
                                            }

                                            CheckBox {
                                                objectName: "advancedFlowFilterServiceExcludeUnknownCheckBox"
                                                text: "Unknown"
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
                                            color: "#475569"
                                            font.pixelSize: 12
                                            font.bold: true
                                }

                                Repeater {
                                            model: serviceSection.excludeTextRows

                                            delegate: Rectangle {
                                                required property var modelData

                                                Layout.fillWidth: true
                                                implicitHeight: excludeServiceRowLayout.implicitHeight + 12
                                                color: "#f8fafc"
                                                border.color: "#e2e8f0"
                                                radius: 6

                                                RowLayout {
                                                    id: excludeServiceRowLayout
                                                    anchors.fill: parent
                                                    anchors.margins: 6
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

                                                    Button {
                                                        objectName: "advancedFlowFilterServiceExcludeRow" + modelData.row + "RemoveButton"
                                                        text: "Remove"
                                                        onClicked: {
                                                            if (root.editor) {
                                                                root.editor.removeServiceTextRow(true, modelData.row)
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                }

                                Button {
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
                                        color: "#64748b"
                                        font.pixelSize: 12
                                        wrapMode: Text.WordWrap
                            }

                            Label {
                                        text: "Include"
                                        color: "#475569"
                                        font.pixelSize: 12
                                        font.bold: true
                            }

                            Repeater {
                                        model: protocolPathSection.includeRows

                                        delegate: Rectangle {
                                            required property var modelData

                                            Layout.fillWidth: true
                                            implicitHeight: includeProtocolPathColumn.implicitHeight + 12
                                            color: "#f8fafc"
                                            border.color: "#e2e8f0"
                                            radius: 6

                                            ColumnLayout {
                                                id: includeProtocolPathColumn
                                                anchors.fill: parent
                                                anchors.margins: 6
                                                spacing: 4

                                                RowLayout {
                                                    Layout.fillWidth: true
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
                                                        color: "#0f172a"
                                                        elide: Text.ElideRight
                                                    }

                                                    Button {
                                                        objectName: "advancedFlowFilterProtocolPathIncludeRow" + modelData.row + "EditButton"
                                                        text: "Edit"
                                                        enabled: root.protocolPathSelector ? root.protocolPathSelector.hasCapture : false
                                                        onClicked: root.openProtocolPathSelector(false, modelData.row)
                                                    }

                                                    Button {
                                                        objectName: "advancedFlowFilterProtocolPathIncludeRow" + modelData.row + "RemoveButton"
                                                        text: "Remove"
                                                        onClicked: {
                                                            if (root.controller) {
                                                                root.controller.removeAdvancedFlowFilterProtocolPathRow(false, modelData.row)
                                                            }
                                                        }
                                                    }
                                                }

                                                Label {
                                                    objectName: "advancedFlowFilterProtocolPathIncludeRow" + modelData.row + "StatusLabel"
                                                    Layout.fillWidth: true
                                                    visible: text.length > 0
                                                    text: modelData.statusText
                                                    color: "#b45309"
                                                    font.pixelSize: 12
                                                    wrapMode: Text.WordWrap
                                                }
                                            }
                                        }
                            }

                            Button {
                                        objectName: "advancedFlowFilterProtocolPathAddIncludeButton"
                                        text: "+ Add path"
                                        enabled: root.protocolPathSelector ? root.protocolPathSelector.hasCapture : false
                                        onClicked: root.openProtocolPathSelector(false, -1)
                            }

                            Button {
                                        objectName: "advancedFlowFilterProtocolPathExclusionsToggleButton"
                                        text: protocolPathSection.exclusionsExpanded ? "Hide exclusions" : "Exclusions"
                                        onClicked: protocolPathSection.exclusionsExpanded = !protocolPathSection.exclusionsExpanded
                            }

                            ColumnLayout {
                                        objectName: "advancedFlowFilterProtocolPathExclusionsSection"
                                        Layout.fillWidth: true
                                        visible: protocolPathSection.exclusionsExpanded
                                        spacing: 10

                                Label {
                                            text: "Exclude"
                                            color: "#475569"
                                            font.pixelSize: 12
                                            font.bold: true
                                }

                                Repeater {
                                            model: protocolPathSection.excludeRows

                                            delegate: Rectangle {
                                                required property var modelData

                                                Layout.fillWidth: true
                                                implicitHeight: excludeProtocolPathColumn.implicitHeight + 12
                                                color: "#f8fafc"
                                                border.color: "#e2e8f0"
                                                radius: 6

                                                ColumnLayout {
                                                    id: excludeProtocolPathColumn
                                                    anchors.fill: parent
                                                    anchors.margins: 6
                                                    spacing: 4

                                                    RowLayout {
                                                        Layout.fillWidth: true
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
                                                            color: "#0f172a"
                                                            elide: Text.ElideRight
                                                        }

                                                        Button {
                                                            objectName: "advancedFlowFilterProtocolPathExcludeRow" + modelData.row + "EditButton"
                                                            text: "Edit"
                                                            enabled: root.protocolPathSelector ? root.protocolPathSelector.hasCapture : false
                                                            onClicked: root.openProtocolPathSelector(true, modelData.row)
                                                        }

                                                        Button {
                                                            objectName: "advancedFlowFilterProtocolPathExcludeRow" + modelData.row + "RemoveButton"
                                                            text: "Remove"
                                                            onClicked: {
                                                                if (root.controller) {
                                                                    root.controller.removeAdvancedFlowFilterProtocolPathRow(true, modelData.row)
                                                                }
                                                            }
                                                        }
                                                    }

                                                    Label {
                                                        objectName: "advancedFlowFilterProtocolPathExcludeRow" + modelData.row + "StatusLabel"
                                                        Layout.fillWidth: true
                                                        visible: text.length > 0
                                                        text: modelData.statusText
                                                        color: "#b45309"
                                                        font.pixelSize: 12
                                                        wrapMode: Text.WordWrap
                                                    }
                                                }
                                            }
                                }

                                Button {
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

                            Label {
                                        text: "Include"
                                        color: "#475569"
                                        font.pixelSize: 12
                                        font.bold: true
                            }

                            Repeater {
                                        model: containsLayerSection.includeRows

                                        delegate: Rectangle {
                                            required property var modelData

                                            Layout.fillWidth: true
                                            implicitHeight: includeContainsLayerColumn.implicitHeight + 12
                                            color: "#f8fafc"
                                            border.color: "#e2e8f0"
                                            radius: 6

                                            ColumnLayout {
                                                id: includeContainsLayerColumn
                                                anchors.fill: parent
                                                anchors.margins: 6
                                                spacing: 4

                                                RowLayout {
                                                    Layout.fillWidth: true
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

                                                    Button {
                                                        objectName: "advancedFlowFilterContainsLayerIncludeRow" + modelData.row + "RemoveButton"
                                                        text: "Remove"
                                                        onClicked: {
                                                            if (root.editor) {
                                                                root.editor.removeContainsLayerRow(false, modelData.row)
                                                            }
                                                        }
                                                    }
                                                }

                                                Label {
                                                    objectName: "advancedFlowFilterContainsLayerIncludeRow" + modelData.row + "StatusLabel"
                                                    Layout.fillWidth: true
                                                    visible: text.length > 0
                                                    text: modelData.statusText
                                                    color: "#b45309"
                                                    font.pixelSize: 12
                                                    wrapMode: Text.WordWrap
                                                }
                                            }
                                        }
                            }

                            Button {
                                        objectName: "advancedFlowFilterContainsLayerAddIncludeButton"
                                        text: "+ Add layer"
                                        onClicked: {
                                            if (root.editor) {
                                                root.editor.addContainsLayerRow(false)
                                            }
                                        }
                            }

                            Button {
                                        objectName: "advancedFlowFilterContainsLayerExclusionsToggleButton"
                                        text: containsLayerSection.exclusionsExpanded ? "Hide exclusions" : "Exclusions"
                                        onClicked: containsLayerSection.exclusionsExpanded = !containsLayerSection.exclusionsExpanded
                            }

                            ColumnLayout {
                                        objectName: "advancedFlowFilterContainsLayerExclusionsSection"
                                        Layout.fillWidth: true
                                        visible: containsLayerSection.exclusionsExpanded
                                        spacing: 10

                                Label {
                                            text: "Exclude"
                                            color: "#475569"
                                            font.pixelSize: 12
                                            font.bold: true
                                }

                                Repeater {
                                            model: containsLayerSection.excludeRows

                                            delegate: Rectangle {
                                                required property var modelData

                                                Layout.fillWidth: true
                                                implicitHeight: excludeContainsLayerColumn.implicitHeight + 12
                                                color: "#f8fafc"
                                                border.color: "#e2e8f0"
                                                radius: 6

                                                ColumnLayout {
                                                    id: excludeContainsLayerColumn
                                                    anchors.fill: parent
                                                    anchors.margins: 6
                                                    spacing: 4

                                                    RowLayout {
                                                        Layout.fillWidth: true
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

                                                        Button {
                                                            objectName: "advancedFlowFilterContainsLayerExcludeRow" + modelData.row + "RemoveButton"
                                                            text: "Remove"
                                                            onClicked: {
                                                                if (root.editor) {
                                                                    root.editor.removeContainsLayerRow(true, modelData.row)
                                                                }
                                                            }
                                                        }
                                                    }

                                                    Label {
                                                        objectName: "advancedFlowFilterContainsLayerExcludeRow" + modelData.row + "StatusLabel"
                                                        Layout.fillWidth: true
                                                        visible: text.length > 0
                                                        text: modelData.statusText
                                                        color: "#b45309"
                                                        font.pixelSize: 12
                                                        wrapMode: Text.WordWrap
                                                    }
                                                }
                                            }
                                }

                                Button {
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

    footer: DialogButtonBox {
        contentItem: RowLayout {
            spacing: 8

            Button {
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

            Button {
                objectName: "advancedFlowFilterCancelButton"
                text: "Cancel"
                onClicked: root.close()
            }

            Button {
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
