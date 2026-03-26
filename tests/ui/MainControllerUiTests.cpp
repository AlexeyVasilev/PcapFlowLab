#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <QApplication>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "cli/CliImportMode.h"
#include "ui/app/FlowListModel.h"
#include "ui/app/MainController.h"
#include "ui/app/PacketDetailsViewModel.h"
#include "ui/app/PacketListModel.h"

namespace {

void expect_true(const bool condition, const char* expression, const char* file, const int line) {
    if (condition) {
        return;
    }

    throw std::runtime_error(std::string(file) + ':' + std::to_string(line) + " expectation failed: " + expression);
}

std::vector<std::uint8_t> make_http_request_payload() {
    constexpr char request[] =
        "GET / HTTP/1.1\r\n"
        "Host: ui.example\r\n"
        "User-Agent: PFL\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1);
}

std::vector<std::uint8_t> make_dns_query_payload() {
    std::vector<std::uint8_t> payload {};
    pfl::tests::append_be16(payload, 0x1234);
    pfl::tests::append_be16(payload, 0x0100);
    pfl::tests::append_be16(payload, 1);
    pfl::tests::append_be16(payload, 0);
    pfl::tests::append_be16(payload, 0);
    pfl::tests::append_be16(payload, 0);
    payload.push_back(3);
    payload.insert(payload.end(), {'a', 'p', 'i'});
    payload.push_back(7);
    payload.insert(payload.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e'});
    payload.push_back(0);
    pfl::tests::append_be16(payload, 1);
    pfl::tests::append_be16(payload, 1);
    return payload;
}

#define UI_EXPECT(expr) expect_true((expr), #expr, __FILE__, __LINE__)

}  // namespace

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    using namespace pfl;
    using namespace pfl::tests;

    const auto http_flow = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80, make_http_request_payload(), 0x12);
    const auto dns_flow = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53, make_dns_query_payload());
    const auto generic_tcp = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6), 2222, 443, 5, 0x18);

    const auto capture_path = write_temp_pcap(
        "pfl_ui_drilldown.pcap",
        make_classic_pcap({
            {100, http_flow},
            {200, dns_flow},
            {300, generic_tcp},
        })
    );

    MainController controller {};
    UI_EXPECT(controller.captureOpenMode() == kCliFastImportModeIndex);
    controller.setCaptureOpenMode(kCliDeepImportModeIndex);
    UI_EXPECT(controller.captureOpenMode() == kCliDeepImportModeIndex);
    UI_EXPECT(controller.openCaptureFile(QString::fromStdWString(capture_path.wstring())));
    UI_EXPECT(controller.flowFilterText().isEmpty());
    UI_EXPECT(controller.currentTabIndex() == 0);

    CaptureSession index_session {};
    UI_EXPECT(index_session.open_capture(capture_path));
    const auto index_path = std::filesystem::temp_directory_path() / "pfl_ui_mode_test.idx";
    std::error_code remove_error {};
    std::filesystem::remove(index_path, remove_error);
    UI_EXPECT(index_session.save_index(index_path));

    controller.setCaptureOpenMode(kCliDeepImportModeIndex);
    UI_EXPECT(controller.openIndexFile(QString::fromStdWString(index_path.wstring())));
    UI_EXPECT(controller.captureOpenMode() == kCliDeepImportModeIndex);
    UI_EXPECT(controller.flowCount() == 3U);
    UI_EXPECT(controller.openCaptureFile(QString::fromStdWString(capture_path.wstring())));

    auto* flow_model = qobject_cast<FlowListModel*>(controller.flowModel());
    UI_EXPECT(flow_model != nullptr);
    UI_EXPECT(flow_model->rowCount() == 3);

    bool sawHttp = false;
    bool sawDns = false;
    for (int row = 0; row < flow_model->rowCount(); ++row) {
        const auto index = flow_model->index(row, 0);
        const auto hint = flow_model->data(index, FlowListModel::ProtocolHintRole).toString();
        const auto service = flow_model->data(index, FlowListModel::ServiceHintRole).toString();

        if (hint == QStringLiteral("HTTP")) {
            sawHttp = true;
            UI_EXPECT(service == QStringLiteral("ui.example"));
            const auto addressA = flow_model->data(index, FlowListModel::AddressARole).toString();
            const auto portA = flow_model->data(index, FlowListModel::PortARole).toUInt();
            const auto addressB = flow_model->data(index, FlowListModel::AddressBRole).toString();
            const auto portB = flow_model->data(index, FlowListModel::PortBRole).toUInt();
            UI_EXPECT(
                (addressA == QStringLiteral("10.0.0.1") && portA == 1111U) ||
                (addressB == QStringLiteral("10.0.0.1") && portB == 1111U)
            );
        }

        if (hint == QStringLiteral("DNS")) {
            sawDns = true;
            UI_EXPECT(service == QStringLiteral("api.example"));
            const auto portA = flow_model->data(index, FlowListModel::PortARole).toUInt();
            const auto portB = flow_model->data(index, FlowListModel::PortBRole).toUInt();
            UI_EXPECT(portA == 53U || portB == 53U);
        }
    }
    UI_EXPECT(sawHttp);
    UI_EXPECT(sawDns);

    controller.setFlowFilterText(QStringLiteral("ui.example"));
    UI_EXPECT(flow_model->rowCount() == 1);
    UI_EXPECT(flow_model->data(flow_model->index(0, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("HTTP"));

    controller.setFlowFilterText(QStringLiteral("53"));
    UI_EXPECT(flow_model->rowCount() == 1);
    UI_EXPECT(flow_model->data(flow_model->index(0, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("DNS"));

    controller.setFlowFilterText(QStringLiteral(""));
    UI_EXPECT(flow_model->rowCount() == 3);

    controller.sortFlows(3);
    UI_EXPECT(controller.flowSortColumn() == 3);
    UI_EXPECT(controller.flowSortAscending());

    controller.sortFlows(4);
    UI_EXPECT(controller.flowSortColumn() == 4);
    UI_EXPECT(controller.flowSortAscending());

    controller.sortFlows(4);
    UI_EXPECT(!controller.flowSortAscending());

    controller.setFlowFilterText(QStringLiteral("ui.example"));
    UI_EXPECT(flow_model->rowCount() == 1);
    controller.setSelectedFlowIndex(flow_model->data(flow_model->index(0, 0), FlowListModel::FlowIndexRole).toInt());

    auto* packet_model = qobject_cast<PacketListModel*>(controller.packetModel());
    UI_EXPECT(packet_model != nullptr);
    UI_EXPECT(packet_model->rowCount() == 1);

    const auto packet_index_model = packet_model->index(0, 0);
    UI_EXPECT(packet_index_model.isValid());
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::DirectionTextRole).toString() == QString::fromUtf8("A\xE2\x86\x92" "B"));
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::PayloadLengthRole).toUInt() == make_http_request_payload().size());
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::TcpFlagsTextRole).toString() == QStringLiteral("ACK|SYN"));

    controller.setSelectedPacketIndex(0);
    auto* details_model = qobject_cast<PacketDetailsViewModel*>(controller.packetDetailsModel());
    UI_EXPECT(details_model != nullptr);
    UI_EXPECT(details_model->hasPacket());
    UI_EXPECT(details_model->payloadText().contains(QStringLiteral("47 45 54 20 2f")));
    UI_EXPECT(!details_model->protocolText().isEmpty());

    controller.setCurrentTabIndex(1);
    controller.drillDownToEndpoint(QStringLiteral("10.0.0.1:1111"));

    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.flowFilterText() == QStringLiteral("10.0.0.1:1111"));
    UI_EXPECT(controller.selectedFlowIndex() == -1);
    UI_EXPECT(controller.selectedPacketIndex() == std::numeric_limits<qulonglong>::max());
    UI_EXPECT(details_model->payloadText().isEmpty());
    UI_EXPECT(flow_model->rowCount() == 1);

    controller.setCurrentTabIndex(1);
    controller.drillDownToPort(53U);

    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.flowFilterText() == QStringLiteral("53"));
    UI_EXPECT(flow_model->rowCount() == 1);
    UI_EXPECT(flow_model->data(flow_model->index(0, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("DNS"));

    const auto tls_capture_path = std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "tls" / "tls_client_hello_1.pcap";
    MainController deep_controller {};
    deep_controller.setCaptureOpenMode(kCliDeepImportModeIndex);
    UI_EXPECT(deep_controller.openCaptureFile(QString::fromStdWString(tls_capture_path.wstring())));
    deep_controller.setSelectedFlowIndex(0);
    deep_controller.setSelectedPacketIndex(0);
    auto* deep_details_model = qobject_cast<PacketDetailsViewModel*>(deep_controller.packetDetailsModel());
    UI_EXPECT(deep_details_model != nullptr);
    UI_EXPECT(deep_details_model->protocolText().contains(QStringLiteral("TLS")));
    UI_EXPECT(deep_details_model->protocolText().contains(QStringLiteral("auth.split.io")));

    return 0;
}


