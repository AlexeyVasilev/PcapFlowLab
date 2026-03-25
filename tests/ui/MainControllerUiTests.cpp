#include <limits>
#include <stdexcept>
#include <string>

#include <QApplication>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "ui/app/FlowListModel.h"
#include "ui/app/MainController.h"
#include "ui/app/PacketListModel.h"

namespace {

void expect_true(const bool condition, const char* expression, const char* file, const int line) {
    if (condition) {
        return;
    }

    throw std::runtime_error(std::string(file) + ':' + std::to_string(line) + " expectation failed: " + expression);
}

#define UI_EXPECT(expr) expect_true((expr), #expr, __FILE__, __LINE__)

}  // namespace

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    using namespace pfl;
    using namespace pfl::tests;

    const auto tcp_ab = make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80, 5, 0x12);
    const auto udp_cd = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);
    const auto capture_path = write_temp_pcap(
        "pfl_ui_drilldown.pcap",
        make_classic_pcap({
            {100, tcp_ab},
            {200, udp_cd},
        })
    );

    MainController controller {};
    UI_EXPECT(controller.openCaptureFile(QString::fromStdWString(capture_path.wstring())));
    UI_EXPECT(controller.flowFilterText().isEmpty());
    UI_EXPECT(controller.currentTabIndex() == 0);

    controller.setSelectedFlowIndex(0);
    auto* packet_model = qobject_cast<PacketListModel*>(controller.packetModel());
    UI_EXPECT(packet_model != nullptr);
    UI_EXPECT(packet_model->rowCount() == 1);

    const auto packet_index_model = packet_model->index(0, 0);
    UI_EXPECT(packet_index_model.isValid());
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::PayloadLengthRole).toUInt() == 5U);
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::TcpFlagsTextRole).toString() == QStringLiteral("ACK|SYN"));

    controller.setCurrentTabIndex(1);
    controller.setSelectedPacketIndex(0);
    controller.drillDownToEndpoint(QStringLiteral("10.0.0.1:1111"));

    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.flowFilterText() == QStringLiteral("10.0.0.1:1111"));
    UI_EXPECT(controller.selectedFlowIndex() == -1);
    UI_EXPECT(controller.selectedPacketIndex() == std::numeric_limits<qulonglong>::max());

    auto* flow_model = qobject_cast<FlowListModel*>(controller.flowModel());
    UI_EXPECT(flow_model != nullptr);
    UI_EXPECT(flow_model->rowCount() == 1);

    controller.setCurrentTabIndex(1);
    controller.drillDownToPort(53U);

    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.flowFilterText() == QStringLiteral("53"));
    UI_EXPECT(flow_model->rowCount() == 1);

    return 0;
}
