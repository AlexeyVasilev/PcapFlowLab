import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property bool hasCapture: false
    property var packetCount: 0
    property var flowCount: 0
    property var totalBytes: 0
    property var tcpFlowCount: 0
    property var tcpPacketCount: 0
    property var tcpTotalBytes: 0
    property var udpFlowCount: 0
    property var udpPacketCount: 0
    property var udpTotalBytes: 0
    property var otherFlowCount: 0
    property var otherPacketCount: 0
    property var otherTotalBytes: 0
    property var ipv4FlowCount: 0
    property var ipv6FlowCount: 0
    property var quicTotalFlows: 0
    property var quicWithSni: 0
    property var quicWithoutSni: 0
    property var quicVersionV1: 0
    property var quicVersionDraft29: 0
    property var quicVersionV2: 0
    property var quicVersionUnknown: 0
    property var tlsTotalFlows: 0
    property var tlsWithSni: 0
    property var tlsWithoutSni: 0
    property var tlsVersion12: 0
    property var tlsVersion13: 0
    property var tlsVersionUnknown: 0
    property var topEndpointsModel: null
    property var topPortsModel: null

    signal endpointActivated(string endpointText)
    signal portActivated(int port)

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: root.width
            spacing: 12

            SummaryBar {
                Layout.fillWidth: true
                packetCount: root.packetCount
                flowCount: root.flowCount
                totalBytes: root.totalBytes
                hasCapture: root.hasCapture
            }

            ProtocolStatsPane {
                Layout.fillWidth: true
                hasCapture: root.hasCapture
                tcpFlowCount: root.tcpFlowCount
                tcpPacketCount: root.tcpPacketCount
                tcpTotalBytes: root.tcpTotalBytes
                udpFlowCount: root.udpFlowCount
                udpPacketCount: root.udpPacketCount
                udpTotalBytes: root.udpTotalBytes
                otherFlowCount: root.otherFlowCount
                otherPacketCount: root.otherPacketCount
                otherTotalBytes: root.otherTotalBytes
                ipv4FlowCount: root.ipv4FlowCount
                ipv6FlowCount: root.ipv6FlowCount
                quicTotalFlows: root.quicTotalFlows
                quicWithSni: root.quicWithSni
                quicWithoutSni: root.quicWithoutSni
                quicVersionV1: root.quicVersionV1
                quicVersionDraft29: root.quicVersionDraft29
                quicVersionV2: root.quicVersionV2
                quicVersionUnknown: root.quicVersionUnknown
                tlsTotalFlows: root.tlsTotalFlows
                tlsWithSni: root.tlsWithSni
                tlsWithoutSni: root.tlsWithoutSni
                tlsVersion12: root.tlsVersion12
                tlsVersion13: root.tlsVersion13
                tlsVersionUnknown: root.tlsVersionUnknown
            }

            TopTalkersPane {
                Layout.fillWidth: true
                Layout.preferredHeight: 260
                hasCapture: root.hasCapture
                topEndpointsModel: root.topEndpointsModel
                topPortsModel: root.topPortsModel
                onEndpointActivated: function(endpointText) {
                    root.endpointActivated(endpointText)
                }
                onPortActivated: function(port) {
                    root.portActivated(port)
                }
            }
        }
    }
}

