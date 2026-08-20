import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    objectName: "advancedFlowFilterSettingsDialog"

    property var controller: null
    readonly property var editor: root.controller ? root.controller.advancedFlowFilterEditor : null
    property bool applyingDraft: false
    readonly property int portsSectionId: 6
    readonly property int ipAddressesSectionId: 7
    readonly property int trafficSectionId: 8
    readonly property int serviceSectionId: 9
    readonly property int serviceKnownKind: 0
    readonly property int serviceUnknownKind: 1

    signal initializeDialogState()

    readonly property var sectionDescriptors: [
        { sectionId: 0, title: "Address family", objectNamePrefix: "AddressFamily" },
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
        initializeDialogState()
    }

    onClosed: {
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
                    enabled: false
                }

                Button {
                    objectName: "advancedFlowFilterClearUnsavedChangesButton"
                    text: "Clear unsaved changes"
                    enabled: false
                }

                Item {
                    Layout.fillWidth: true
                }

                Button {
                    objectName: "advancedFlowFilterSaveButton"
                    text: "Save"
                    enabled: false
                }

                Button {
                    objectName: "advancedFlowFilterSaveAsButton"
                    text: "Save As..."
                    enabled: false
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

                            delegate: Rectangle {
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

                                objectName: "advancedFlowFilter" + sectionObjectNamePrefix + "Section"
                                Layout.fillWidth: true
                                Layout.preferredHeight: implicitHeight
                                implicitHeight: finiteSectionCardLayout.implicitHeight + 28
                                radius: 8
                                color: "white"
                                border.color: "#dbe4f0"

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

                                ColumnLayout {
                                    id: finiteSectionCardLayout
                                    x: 14
                                    y: 14
                                    width: parent.width - 28
                                    spacing: 10

                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 10

                                        Label {
                                            Layout.fillWidth: true
                                            text: finiteSectionCard.sectionTitle
                                            color: "#0f172a"
                                            font.pixelSize: 14
                                            font.bold: true
                                        }

                                        CheckBox {
                                            objectName: "advancedFlowFilter" + finiteSectionCard.sectionObjectNamePrefix + "EnabledCheckBox"
                                            text: "Enabled"
                                            checked: finiteSectionCard.sectionEnabledState
                                            onToggled: {
                                                if (root.editor) {
                                                    root.editor.setSectionEnabled(finiteSectionCard.sectionId, checked)
                                                }
                                            }
                                        }
                                    }

                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 10
                                        enabled: finiteSectionCard.sectionEnabledState
                                        opacity: finiteSectionCard.sectionEnabledState ? 1.0 : 0.55

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

                                        GridLayout {
                                            Layout.fillWidth: true
                                            columns: 2
                                            columnSpacing: 20
                                            rowSpacing: 8

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

                                            GridLayout {
                                                Layout.fillWidth: true
                                                columns: 2
                                                columnSpacing: 20
                                                rowSpacing: 8

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
                            }
                        }

                        Rectangle {
                            id: portsSection
                            readonly property bool sectionEnabledState: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.sectionEnabled(root.portsSectionId)
                            }
                            readonly property var scopeOptions: root.editor
                                ? root.editor.portScopeOptions()
                                : []
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

                            objectName: "advancedFlowFilterPortsSection"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            implicitHeight: portsSectionLayout.implicitHeight + 28
                            radius: 8
                            color: "white"
                            border.color: "#dbe4f0"

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

                            ColumnLayout {
                                id: portsSectionLayout
                                x: 14
                                y: 14
                                width: parent.width - 28
                                spacing: 10

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 10

                                    Label {
                                        Layout.fillWidth: true
                                        text: "Ports"
                                        color: "#0f172a"
                                        font.pixelSize: 14
                                        font.bold: true
                                    }

                                    CheckBox {
                                        objectName: "advancedFlowFilterPortsEnabledCheckBox"
                                        text: "Enabled"
                                        checked: portsSection.sectionEnabledState
                                        onToggled: {
                                            if (root.editor) {
                                                root.editor.setSectionEnabled(root.portsSectionId, checked)
                                            }
                                        }
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 10
                                    enabled: portsSection.sectionEnabledState
                                    opacity: portsSection.sectionEnabledState ? 1.0 : 0.55

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
                                                    text: modelData.rangeEnabled ? "From"
                                                                                : "Port"
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
                                                        text: modelData.rangeEnabled ? "From"
                                                                                    : "Port"
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
                            }
                        }

                        Rectangle {
                            id: ipAddressesSection
                            readonly property bool sectionEnabledState: {
                                if (!root.editor) {
                                    return false
                                }
                                void(root.editor.revision)
                                return root.editor.sectionEnabled(root.ipAddressesSectionId)
                            }
                            readonly property var scopeOptions: root.editor
                                ? root.editor.addressScopeOptions()
                                : []
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

                            objectName: "advancedFlowFilterIpAddressesSection"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            implicitHeight: ipAddressesSectionLayout.implicitHeight + 28
                            radius: 8
                            color: "white"
                            border.color: "#dbe4f0"

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

                            ColumnLayout {
                                id: ipAddressesSectionLayout
                                x: 14
                                y: 14
                                width: parent.width - 28
                                spacing: 10

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 10

                                    Label {
                                        Layout.fillWidth: true
                                        text: "IP addresses"
                                        color: "#0f172a"
                                        font.pixelSize: 14
                                        font.bold: true
                                    }

                                    CheckBox {
                                        objectName: "advancedFlowFilterIpAddressesEnabledCheckBox"
                                        text: "Enabled"
                                        checked: ipAddressesSection.sectionEnabledState
                                        onToggled: {
                                            if (root.editor) {
                                                root.editor.setSectionEnabled(root.ipAddressesSectionId, checked)
                                            }
                                        }
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 10
                                    enabled: ipAddressesSection.sectionEnabledState
                                    opacity: ipAddressesSection.sectionEnabledState ? 1.0 : 0.55

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
                            }
                        }

                        Rectangle {
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

                            objectName: "advancedFlowFilterTrafficSection"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            implicitHeight: trafficSectionLayout.implicitHeight + 28
                            radius: 8
                            color: "white"
                            border.color: "#dbe4f0"

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

                            ColumnLayout {
                                id: trafficSectionLayout
                                x: 14
                                y: 14
                                width: parent.width - 28
                                spacing: 10

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 10

                                    Label {
                                        Layout.fillWidth: true
                                        text: "Traffic"
                                        color: "#0f172a"
                                        font.pixelSize: 14
                                        font.bold: true
                                    }

                                    CheckBox {
                                        objectName: "advancedFlowFilterTrafficEnabledCheckBox"
                                        text: "Enabled"
                                        checked: trafficSection.sectionEnabledState
                                        onToggled: {
                                            if (root.editor) {
                                                root.editor.setSectionEnabled(root.trafficSectionId, checked)
                                            }
                                        }
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 10
                                    enabled: trafficSection.sectionEnabledState
                                    opacity: trafficSection.sectionEnabledState ? 1.0 : 0.55

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
                            }
                        }

                        Rectangle {
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

                            objectName: "advancedFlowFilterServiceSection"
                            Layout.fillWidth: true
                            Layout.preferredHeight: implicitHeight
                            implicitHeight: serviceSectionLayout.implicitHeight + 28
                            radius: 8
                            color: "white"
                            border.color: "#dbe4f0"

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

                            ColumnLayout {
                                id: serviceSectionLayout
                                x: 14
                                y: 14
                                width: parent.width - 28
                                spacing: 10

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 10

                                    Label {
                                        Layout.fillWidth: true
                                        text: "Service"
                                        color: "#0f172a"
                                        font.pixelSize: 14
                                        font.bold: true
                                    }

                                    CheckBox {
                                        objectName: "advancedFlowFilterServiceEnabledCheckBox"
                                        text: "Enabled"
                                        checked: serviceSection.sectionEnabledState
                                        onToggled: {
                                            if (root.editor) {
                                                root.editor.setSectionEnabled(root.serviceSectionId, checked)
                                            }
                                        }
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 10
                                    enabled: serviceSection.sectionEnabledState
                                    opacity: serviceSection.sectionEnabledState ? 1.0 : 0.55

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

    footer: DialogButtonBox {
        contentItem: RowLayout {
            spacing: 8

            Button {
                objectName: "advancedFlowFilterClearAllButton"
                text: "Clear all"
                enabled: root.editor ? root.editor.draftClearAllAvailable : false
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
