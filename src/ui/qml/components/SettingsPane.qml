import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property bool httpUsePathAsServiceHint: false
    property bool usePossibleTlsQuic: false
    property bool ignoreVlanAndMplsLayersWhenGroupingFlows: false
    property bool ignoreGtpuTeidsWhenGroupingInnerFlows: false
    property bool validateSelectedPacketChecksums: false
    property bool showWiresharkFilterForSelectedFlow: true
    property bool showProtocolPathColumn: true
    property bool showFragmentedPacketCountColumn: false

    signal httpUsePathAsServiceHintChangedByUser(bool enabled)
    signal usePossibleTlsQuicChangedByUser(bool enabled)
    signal ignoreVlanAndMplsLayersWhenGroupingFlowsChangedByUser(bool enabled)
    signal ignoreGtpuTeidsWhenGroupingInnerFlowsChangedByUser(bool enabled)
    signal validateSelectedPacketChecksumsChangedByUser(bool enabled)
    signal showWiresharkFilterForSelectedFlowChangedByUser(bool enabled)
    signal showProtocolPathColumnChangedByUser(bool enabled)
    signal showFragmentedPacketCountColumnChangedByUser(bool enabled)

    implicitWidth: 640
    implicitHeight: 440

    ColumnLayout {
        id: contentColumn
        anchors.fill: parent
        anchors.margins: 12
        spacing: 10

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: "#475569"
            text: "Settings control how new captures are interpreted and how current results are presented."
        }

        TabBar {
            id: settingsTabs
            objectName: "settingsTabs"
            Layout.preferredWidth: implicitWidth
            spacing: 4

            background: Rectangle {
                color: "transparent"
            }

            TabButton {
                text: "View & Inspection"
                implicitHeight: 28
                implicitWidth: Math.max(148, contentItem.implicitWidth + 24)

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
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
                text: "Capture Processing"
                implicitHeight: 28
                implicitWidth: Math.max(146, contentItem.implicitWidth + 24)

                contentItem: Label {
                    text: parent.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.pixelSize: 12
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
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: settingsTabs.currentIndex

            ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                contentWidth: availableWidth
                ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

                ColumnLayout {
                    width: parent.width
                    spacing: 10

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        CheckBox {
                            Layout.fillWidth: true
                            text: "Use possible TLS/QUIC"
                            checked: root.usePossibleTlsQuic
                            onToggled: root.usePossibleTlsQuicChangedByUser(checked)
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.leftMargin: 28
                            wrapMode: Text.WordWrap
                            color: "#64748b"
                            font.pixelSize: 12
                            text: "Applied immediately to the current flows, statistics, and analysis views."
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        CheckBox {
                            objectName: "showWiresharkFilterForSelectedFlowCheckBox"
                            Layout.fillWidth: true
                            text: "Show Wireshark filter for selected flow"
                            checked: root.showWiresharkFilterForSelectedFlow
                            onToggled: root.showWiresharkFilterForSelectedFlowChangedByUser(checked)
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.leftMargin: 28
                            wrapMode: Text.WordWrap
                            color: "#64748b"
                            font.pixelSize: 12
                            text: "Applied immediately to the selected-flow view."
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        CheckBox {
                            objectName: "showProtocolPathColumnCheckBox"
                            Layout.fillWidth: true
                            text: "Show Protocol Path column in the flow table"
                            checked: root.showProtocolPathColumn
                            onToggled: root.showProtocolPathColumnChangedByUser(checked)
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.leftMargin: 28
                            wrapMode: Text.WordWrap
                            color: "#64748b"
                            font.pixelSize: 12
                            text: "Applied immediately."
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        CheckBox {
                            objectName: "showFragmentedPacketCountColumnCheckBox"
                            Layout.fillWidth: true
                            text: "Show fragmented packet count column in the flow table"
                            checked: root.showFragmentedPacketCountColumn
                            onToggled: root.showFragmentedPacketCountColumnChangedByUser(checked)
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.leftMargin: 28
                            wrapMode: Text.WordWrap
                            color: "#64748b"
                            font.pixelSize: 12
                            text: "Applied immediately."
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        CheckBox {
                            Layout.fillWidth: true
                            text: "Validate IPv4/TCP/UDP checksums for selected packet"
                            checked: root.validateSelectedPacketChecksums
                            onToggled: root.validateSelectedPacketChecksumsChangedByUser(checked)
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.leftMargin: 28
                            wrapMode: Text.WordWrap
                            color: "#64748b"
                            font.pixelSize: 12
                            text: "Applied immediately to Packet Details when source bytes are available."
                        }
                    }

                    Item { height: 1 }
                }
            }

            ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                contentWidth: availableWidth
                ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

                ColumnLayout {
                    width: parent.width
                    spacing: 10

                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: "#475569"
                        text: "These settings affect how captures are interpreted when opened."
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        CheckBox {
                            Layout.fillWidth: true
                            text: "HTTP: use request path as service hint when Host is missing"
                            checked: root.httpUsePathAsServiceHint
                            onToggled: root.httpUsePathAsServiceHintChangedByUser(checked)
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.leftMargin: 28
                            wrapMode: Text.WordWrap
                            color: "#64748b"
                            font.pixelSize: 12
                            text: "Applied on the next capture or index open."
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        CheckBox {
                            objectName: "ignoreVlanAndMplsLayersWhenGroupingFlowsCheckBox"
                            Layout.fillWidth: true
                            text: "Ignore VLAN and MPLS layers when grouping flows"
                            checked: root.ignoreVlanAndMplsLayersWhenGroupingFlows
                            onToggled: root.ignoreVlanAndMplsLayersWhenGroupingFlowsChangedByUser(checked)
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.leftMargin: 28
                            wrapMode: Text.WordWrap
                            color: "#64748b"
                            font.pixelSize: 12
                            text: "Applied when importing a capture. Existing indexes keep their stored flow grouping."
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        CheckBox {
                            objectName: "ignoreGtpuTeidsWhenGroupingInnerFlowsCheckBox"
                            Layout.fillWidth: true
                            text: "Ignore GTP-U TEIDs when grouping inner flows"
                            checked: root.ignoreGtpuTeidsWhenGroupingInnerFlows
                            onToggled: root.ignoreGtpuTeidsWhenGroupingInnerFlowsChangedByUser(checked)
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.leftMargin: 28
                            wrapMode: Text.WordWrap
                            color: "#64748b"
                            font.pixelSize: 12
                            text: "Applied when importing a capture. Existing indexes keep their stored flow grouping."
                        }
                    }

                    Item { height: 1 }
                }
            }
        }
    }
}
