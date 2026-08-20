import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    objectName: "advancedFlowFilterSettingsDialog"

    property var controller: null
    property bool applyingDraft: false
    readonly property int portsSectionId: 6
    readonly property int ipAddressesSectionId: 7

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
                                    void(root.controller.advancedFlowFilterEditorRevision)
                                    return root.controller.advancedFlowFilterSectionEnabled(sectionId)
                                }
                                readonly property var includeOptions: {
                                    if (!root.controller) {
                                        return []
                                    }
                                    void(root.controller.advancedFlowFilterEditorRevision)
                                    return root.controller.advancedFlowFilterIncludeOptions(sectionId)
                                }
                                readonly property var excludeOptions: {
                                    if (!root.controller) {
                                        return []
                                    }
                                    void(root.controller.advancedFlowFilterEditorRevision)
                                    return root.controller.advancedFlowFilterExcludeOptions(sectionId)
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
                                    exclusionsExpanded = root.controller
                                        ? root.controller.advancedFlowFilterSectionHasExclusions(sectionId)
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
                                                if (root.controller) {
                                                    root.controller.setAdvancedFlowFilterSectionEnabled(finiteSectionCard.sectionId, checked)
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
                                                        if (root.controller) {
                                                            root.controller.setAdvancedFlowFilterOptionChecked(
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
                                                            if (root.controller) {
                                                                root.controller.setAdvancedFlowFilterOptionChecked(
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
                                if (!root.controller) {
                                    return false
                                }
                                void(root.controller.advancedFlowFilterEditorRevision)
                                return root.controller.advancedFlowFilterSectionEnabled(root.portsSectionId)
                            }
                            readonly property var scopeOptions: root.controller
                                ? root.controller.advancedFlowFilterPortScopeOptions()
                                : []
                            readonly property var includeRows: {
                                if (!root.controller) {
                                    return []
                                }
                                void(root.controller.advancedFlowFilterEditorRevision)
                                return root.controller.advancedFlowFilterPortRows(false)
                            }
                            readonly property var excludeRows: {
                                if (!root.controller) {
                                    return []
                                }
                                void(root.controller.advancedFlowFilterEditorRevision)
                                return root.controller.advancedFlowFilterPortRows(true)
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
                                exclusionsExpanded = root.controller
                                    ? root.controller.advancedFlowFilterSectionHasExclusions(root.portsSectionId)
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
                                            if (root.controller) {
                                                root.controller.setAdvancedFlowFilterSectionEnabled(root.portsSectionId, checked)
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
                                                        if (root.controller) {
                                                            root.controller.setAdvancedFlowFilterPortRowScope(false, modelData.row, model[currentIndex].value)
                                                        }
                                                    }
                                                }

                                                CheckBox {
                                                    objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "RangeCheckBox"
                                                    text: "Range"
                                                    checked: modelData.rangeEnabled
                                                    onToggled: {
                                                        if (root.controller) {
                                                            root.controller.setAdvancedFlowFilterPortRowRangeEnabled(false, modelData.row, checked)
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
                                                        if (root.controller) {
                                                            root.controller.setAdvancedFlowFilterPortRowPrimaryText(false, modelData.row, text)
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
                                                        if (root.controller) {
                                                            root.controller.setAdvancedFlowFilterPortRowSecondaryText(false, modelData.row, text)
                                                        }
                                                    }
                                                }

                                                Button {
                                                    objectName: "advancedFlowFilterPortsIncludeRow" + modelData.row + "RemoveButton"
                                                    text: "Remove"
                                                    onClicked: {
                                                        if (root.controller) {
                                                            root.controller.removeAdvancedFlowFilterPortRow(false, modelData.row)
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
                                            if (root.controller) {
                                                root.controller.addAdvancedFlowFilterPortRow(false)
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
                                                            if (root.controller) {
                                                                root.controller.setAdvancedFlowFilterPortRowScope(true, modelData.row, model[currentIndex].value)
                                                            }
                                                        }
                                                    }

                                                    CheckBox {
                                                        objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "RangeCheckBox"
                                                        text: "Range"
                                                        checked: modelData.rangeEnabled
                                                        onToggled: {
                                                            if (root.controller) {
                                                                root.controller.setAdvancedFlowFilterPortRowRangeEnabled(true, modelData.row, checked)
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
                                                            if (root.controller) {
                                                                root.controller.setAdvancedFlowFilterPortRowPrimaryText(true, modelData.row, text)
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
                                                            if (root.controller) {
                                                                root.controller.setAdvancedFlowFilterPortRowSecondaryText(true, modelData.row, text)
                                                            }
                                                        }
                                                    }

                                                    Button {
                                                        objectName: "advancedFlowFilterPortsExcludeRow" + modelData.row + "RemoveButton"
                                                        text: "Remove"
                                                        onClicked: {
                                                            if (root.controller) {
                                                                root.controller.removeAdvancedFlowFilterPortRow(true, modelData.row)
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
                                                if (root.controller) {
                                                    root.controller.addAdvancedFlowFilterPortRow(true)
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
                                if (!root.controller) {
                                    return false
                                }
                                void(root.controller.advancedFlowFilterEditorRevision)
                                return root.controller.advancedFlowFilterSectionEnabled(root.ipAddressesSectionId)
                            }
                            readonly property var scopeOptions: root.controller
                                ? root.controller.advancedFlowFilterAddressScopeOptions()
                                : []
                            readonly property var includeRows: {
                                if (!root.controller) {
                                    return []
                                }
                                void(root.controller.advancedFlowFilterEditorRevision)
                                return root.controller.advancedFlowFilterAddressRows(false)
                            }
                            readonly property var excludeRows: {
                                if (!root.controller) {
                                    return []
                                }
                                void(root.controller.advancedFlowFilterEditorRevision)
                                return root.controller.advancedFlowFilterAddressRows(true)
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
                                exclusionsExpanded = root.controller
                                    ? root.controller.advancedFlowFilterSectionHasExclusions(root.ipAddressesSectionId)
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
                                            if (root.controller) {
                                                root.controller.setAdvancedFlowFilterSectionEnabled(root.ipAddressesSectionId, checked)
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
                                                        if (root.controller) {
                                                            root.controller.setAdvancedFlowFilterAddressRowScope(false, modelData.row, model[currentIndex].value)
                                                        }
                                                    }
                                                }

                                                CheckBox {
                                                    objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "SubnetCheckBox"
                                                    text: "Subnet"
                                                    checked: modelData.subnetEnabled
                                                    onToggled: {
                                                        if (root.controller) {
                                                            root.controller.setAdvancedFlowFilterAddressRowSubnetEnabled(false, modelData.row, checked)
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
                                                        if (root.controller) {
                                                            root.controller.setAdvancedFlowFilterAddressRowAddressText(false, modelData.row, text)
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
                                                        if (root.controller) {
                                                            root.controller.setAdvancedFlowFilterAddressRowPrefixText(false, modelData.row, text)
                                                        }
                                                    }
                                                }

                                                Button {
                                                    objectName: "advancedFlowFilterIpAddressesIncludeRow" + modelData.row + "RemoveButton"
                                                    text: "Remove"
                                                    onClicked: {
                                                        if (root.controller) {
                                                            root.controller.removeAdvancedFlowFilterAddressRow(false, modelData.row)
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
                                            if (root.controller) {
                                                root.controller.addAdvancedFlowFilterAddressRow(false)
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
                                                            if (root.controller) {
                                                                root.controller.setAdvancedFlowFilterAddressRowScope(true, modelData.row, model[currentIndex].value)
                                                            }
                                                        }
                                                    }

                                                    CheckBox {
                                                        objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "SubnetCheckBox"
                                                        text: "Subnet"
                                                        checked: modelData.subnetEnabled
                                                        onToggled: {
                                                            if (root.controller) {
                                                                root.controller.setAdvancedFlowFilterAddressRowSubnetEnabled(true, modelData.row, checked)
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
                                                            if (root.controller) {
                                                                root.controller.setAdvancedFlowFilterAddressRowAddressText(true, modelData.row, text)
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
                                                            if (root.controller) {
                                                                root.controller.setAdvancedFlowFilterAddressRowPrefixText(true, modelData.row, text)
                                                            }
                                                        }
                                                    }

                                                    Button {
                                                        objectName: "advancedFlowFilterIpAddressesExcludeRow" + modelData.row + "RemoveButton"
                                                        text: "Remove"
                                                        onClicked: {
                                                            if (root.controller) {
                                                                root.controller.removeAdvancedFlowFilterAddressRow(true, modelData.row)
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
                                                if (root.controller) {
                                                    root.controller.addAdvancedFlowFilterAddressRow(true)
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
                text: root.controller ? root.controller.advancedFlowFilterEditorValidationText : ""
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
                enabled: root.controller ? root.controller.advancedFlowFilterDraftClearAllAvailable() : false
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
