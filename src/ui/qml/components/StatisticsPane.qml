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
    property var ipv4PacketCount: 0
    property var ipv4TotalBytes: 0
    property var ipv6FlowCount: 0
    property var ipv6PacketCount: 0
    property var ipv6TotalBytes: 0
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
    property var protocolHintDistribution: []
    property int statisticsMode: 0
    property var topEndpointsModel: null
    property var topPortsModel: null
    readonly property bool showTopTalkers: root.hasCapture && Number(root.flowCount || 0) > 30

    signal endpointActivated(string endpointText)
    signal portActivated(int port)
    signal statisticsModeChangedByUser(int mode)

    ScrollView {
        anchors.fill: parent
        clip: true
        ScrollBar.vertical.policy: contentHeight > height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
        ScrollBar.horizontal.policy: contentWidth > width ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff

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
                ipv4PacketCount: root.ipv4PacketCount
                ipv4TotalBytes: root.ipv4TotalBytes
                ipv6FlowCount: root.ipv6FlowCount
                ipv6PacketCount: root.ipv6PacketCount
                ipv6TotalBytes: root.ipv6TotalBytes
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
                protocolHintDistribution: root.protocolHintDistribution
                statisticsMode: root.statisticsMode
            }

            TopTalkersPane {
                Layout.fillWidth: true
                Layout.preferredHeight: root.showTopTalkers ? 260 : 0
                visible: root.showTopTalkers
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
