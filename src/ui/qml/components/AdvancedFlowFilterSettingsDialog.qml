import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    objectName: "advancedFlowFilterSettingsDialog"

    property var controller: null
    property bool applyingDraft: false

    signal initializeDialogState()

    readonly property var sectionDescriptors: [
        { sectionId: 0, title: "Address family", objectNamePrefix: "AddressFamily" },
        { sectionId: 1, title: "Flow Protocol", objectNamePrefix: "FlowProtocol" },
        { sectionId: 2, title: "Detected Protocol", objectNamePrefix: "DetectedProtocol" },
        { sectionId: 3, title: "TLS Version", objectNamePrefix: "TlsVersion" },
        { sectionId: 4, title: "QUIC Version", objectNamePrefix: "QuicVersion" },
        { sectionId: 5, title: "Observed directions", objectNamePrefix: "Directionality" }
    ]

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
                                id: sectionCard
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
                                implicitHeight: sectionCardLayout.implicitHeight + 28
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
                                        sectionCard.initializeExclusionsVisibility()
                                    }
                                }

                                ColumnLayout {
                                    id: sectionCardLayout
                                    x: 14
                                    y: 14
                                    width: parent.width - 28
                                    spacing: 10

                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 10

                                        Label {
                                            Layout.fillWidth: true
                                            text: sectionCard.sectionTitle
                                            color: "#0f172a"
                                            font.pixelSize: 14
                                            font.bold: true
                                        }

                                        CheckBox {
                                            objectName: "advancedFlowFilter" + sectionCard.sectionObjectNamePrefix + "EnabledCheckBox"
                                            text: "Enabled"
                                            checked: sectionCard.sectionEnabledState
                                            onToggled: {
                                                if (root.controller) {
                                                    root.controller.setAdvancedFlowFilterSectionEnabled(sectionCard.sectionId, checked)
                                                }
                                            }
                                        }
                                    }

                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 10
                                        enabled: sectionCard.sectionEnabledState
                                        opacity: sectionCard.sectionEnabledState ? 1.0 : 0.55

                                        Label {
                                            Layout.fillWidth: true
                                            visible: sectionCard.sectionId === 5
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
                                                model: sectionCard.includeOptions

                                                delegate: CheckBox {
                                                    required property var modelData

                                                    objectName: "advancedFlowFilter"
                                                        + sectionCard.sectionObjectNamePrefix
                                                        + "Include"
                                                        + modelData.objectNameSuffix
                                                        + "CheckBox"
                                                    text: modelData.label
                                                    checked: modelData.checked
                                                    onToggled: {
                                                        if (root.controller) {
                                                            root.controller.setAdvancedFlowFilterOptionChecked(
                                                                sectionCard.sectionId,
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
                                                + sectionCard.sectionObjectNamePrefix
                                                + "ExclusionsToggleButton"
                                            text: sectionCard.exclusionsExpanded ? "Hide exclusions" : "Exclusions"
                                            onClicked: sectionCard.exclusionsExpanded = !sectionCard.exclusionsExpanded
                                        }

                                        ColumnLayout {
                                            objectName: "advancedFlowFilter"
                                                + sectionCard.sectionObjectNamePrefix
                                                + "ExclusionsSection"
                                            Layout.fillWidth: true
                                            visible: sectionCard.exclusionsExpanded
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
                                                    model: sectionCard.excludeOptions

                                                    delegate: CheckBox {
                                                        required property var modelData

                                                        objectName: "advancedFlowFilter"
                                                            + sectionCard.sectionObjectNamePrefix
                                                            + "Exclude"
                                                            + modelData.objectNameSuffix
                                                            + "CheckBox"
                                                        text: modelData.label
                                                        checked: modelData.checked
                                                        onToggled: {
                                                            if (root.controller) {
                                                                root.controller.setAdvancedFlowFilterOptionChecked(
                                                                    sectionCard.sectionId,
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
                    }
                }
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
