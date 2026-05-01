import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property bool hasCapture: false
    property var packetCount: 0
    property var flowCount: 0
    property var capturedBytes: 0
    property var originalBytes: 0
    property var tcpFlowCount: 0
    property var tcpPacketCount: 0
    property var tcpCapturedBytes: 0
    property var tcpOriginalBytes: 0
    property var udpFlowCount: 0
    property var udpPacketCount: 0
    property var udpCapturedBytes: 0
    property var udpOriginalBytes: 0
    property var otherFlowCount: 0
    property var otherPacketCount: 0
    property var otherCapturedBytes: 0
    property var otherOriginalBytes: 0
    property var ipv4FlowCount: 0
    property var ipv4PacketCount: 0
    property var ipv4CapturedBytes: 0
    property var ipv4OriginalBytes: 0
    property var ipv6FlowCount: 0
    property var ipv6PacketCount: 0
    property var ipv6CapturedBytes: 0
    property var ipv6OriginalBytes: 0
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
        id: statisticsScroll
        anchors.fill: parent
        clip: true
        contentWidth: statisticsContent.width
        contentHeight: statisticsContent.implicitHeight
        ScrollBar.vertical.policy: contentHeight > height ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
        ScrollBar.horizontal.policy: contentWidth > width ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff

        Item {
            id: statisticsContent
            width: statisticsScroll.availableWidth
            implicitHeight: statisticsColumn.implicitHeight

            ColumnLayout {
                id: statisticsColumn
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                spacing: 12

                SummaryBar {
                    Layout.fillWidth: true
                    packetCount: root.packetCount
                    flowCount: root.flowCount
                    capturedBytes: root.capturedBytes
                    originalBytes: root.originalBytes
                    hasCapture: root.hasCapture
                }

                ProtocolStatsPane {
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    hasCapture: root.hasCapture
                    tcpFlowCount: root.tcpFlowCount
                    tcpPacketCount: root.tcpPacketCount
                    tcpCapturedBytes: root.tcpCapturedBytes
                    tcpOriginalBytes: root.tcpOriginalBytes
                    udpFlowCount: root.udpFlowCount
                    udpPacketCount: root.udpPacketCount
                    udpCapturedBytes: root.udpCapturedBytes
                    udpOriginalBytes: root.udpOriginalBytes
                    otherFlowCount: root.otherFlowCount
                    otherPacketCount: root.otherPacketCount
                    otherCapturedBytes: root.otherCapturedBytes
                    otherOriginalBytes: root.otherOriginalBytes
                    ipv4FlowCount: root.ipv4FlowCount
                    ipv4PacketCount: root.ipv4PacketCount
                    ipv4CapturedBytes: root.ipv4CapturedBytes
                    ipv4OriginalBytes: root.ipv4OriginalBytes
                    ipv6FlowCount: root.ipv6FlowCount
                    ipv6PacketCount: root.ipv6PacketCount
                    ipv6CapturedBytes: root.ipv6CapturedBytes
                    ipv6OriginalBytes: root.ipv6OriginalBytes
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
}
