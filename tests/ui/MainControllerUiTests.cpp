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
#include "ui/app/StreamListModel.h"

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

std::vector<std::uint8_t> make_http_request_without_host_payload() {
    constexpr char request[] =
        "GET /fallback/ui HTTP/1.1\r\n"
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

std::vector<std::uint8_t> make_classic_pcap_with_lengths(
    const std::uint32_t ts_usec,
    const std::vector<std::uint8_t>& captured_packet,
    const std::uint32_t original_length
) {
    std::vector<std::uint8_t> bytes {};
    pfl::tests::append_le32(bytes, 0xa1b2c3d4U);
    pfl::tests::append_le16(bytes, 2U);
    pfl::tests::append_le16(bytes, 4U);
    pfl::tests::append_le32(bytes, 0U);
    pfl::tests::append_le32(bytes, 0U);
    pfl::tests::append_le32(bytes, 65535U);
    pfl::tests::append_le32(bytes, 1U);
    pfl::tests::append_le32(bytes, 1U);
    pfl::tests::append_le32(bytes, ts_usec);
    pfl::tests::append_le32(bytes, static_cast<std::uint32_t>(captured_packet.size()));
    pfl::tests::append_le32(bytes, original_length);
    bytes.insert(bytes.end(), captured_packet.begin(), captured_packet.end());
    return bytes;
}

#define UI_EXPECT(expr) expect_true((expr), #expr, __FILE__, __LINE__)

int find_flow_index_by_protocol_hint(pfl::FlowListModel* model, const QString& hint) {
    for (int row = 0; row < model->rowCount(); ++row) {
        const auto index = model->index(row, 0);
        if (model->data(index, pfl::FlowListModel::ProtocolHintRole).toString() == hint) {
            return model->data(index, pfl::FlowListModel::FlowIndexRole).toInt();
        }
    }

    return -1;
}

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
    UI_EXPECT(!controller.canSaveIndex());
    UI_EXPECT(!controller.canExportSelectedFlow());
    UI_EXPECT(!controller.hasSourceCapture());
    UI_EXPECT(!controller.openedFromIndex());
    UI_EXPECT(!controller.canAttachSourceCapture());
    UI_EXPECT(controller.statusText().isEmpty());
    UI_EXPECT(controller.captureOpenMode() == kCliFastImportModeIndex);
    controller.setCaptureOpenMode(kCliDeepImportModeIndex);
    UI_EXPECT(controller.captureOpenMode() == kCliDeepImportModeIndex);
    UI_EXPECT(controller.openCaptureFile(QString::fromStdWString(capture_path.wstring())));
    UI_EXPECT(controller.canSaveIndex());
    UI_EXPECT(controller.hasSourceCapture());
    UI_EXPECT(!controller.openedFromIndex());
    UI_EXPECT(!controller.canAttachSourceCapture());
    UI_EXPECT(!controller.canExportSelectedFlow());
    UI_EXPECT(controller.flowFilterText().isEmpty());
    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.statusText().isEmpty());

    const auto saved_index_path = std::filesystem::temp_directory_path() / "pfl_ui_saved_analysis.idx";
    std::error_code remove_error {};
    std::filesystem::remove(saved_index_path, remove_error);
    UI_EXPECT(controller.saveAnalysisIndex(QString::fromStdWString(saved_index_path.wstring())));
    UI_EXPECT(std::filesystem::exists(saved_index_path));
    UI_EXPECT(controller.statusText() == QStringLiteral("Analysis index saved successfully."));
    UI_EXPECT(!controller.statusIsError());

    const auto no_selection_export_path = std::filesystem::temp_directory_path() / "pfl_ui_no_selection_export.pcap";
    std::filesystem::remove(no_selection_export_path, remove_error);
    UI_EXPECT(!controller.exportSelectedFlow(QString::fromStdWString(no_selection_export_path.wstring())));
    UI_EXPECT(controller.statusText() == QStringLiteral("No flow selected for export."));
    UI_EXPECT(controller.statusIsError());
    UI_EXPECT(!std::filesystem::exists(no_selection_export_path));

    CaptureSession index_session {};
    UI_EXPECT(index_session.open_capture(capture_path));
    const auto index_path = std::filesystem::temp_directory_path() / "pfl_ui_mode_test.idx";
    std::filesystem::remove(index_path, remove_error);
    UI_EXPECT(index_session.save_index(index_path));

    const auto moved_capture_path = std::filesystem::temp_directory_path() / "pfl_ui_mode_test_source.gone.pcap";
    const auto mismatched_attach_path = std::filesystem::temp_directory_path() / "pfl_ui_mode_test_source_mismatch.pcap";
    std::filesystem::remove(moved_capture_path, remove_error);
    std::filesystem::remove(mismatched_attach_path, remove_error);
    std::filesystem::rename(capture_path, moved_capture_path);

    controller.setCaptureOpenMode(kCliDeepImportModeIndex);
    UI_EXPECT(controller.openIndexFile(QString::fromStdWString(index_path.wstring())));
    UI_EXPECT(controller.captureOpenMode() == kCliDeepImportModeIndex);
    UI_EXPECT(controller.openedFromIndex());
    UI_EXPECT(!controller.hasSourceCapture());
    UI_EXPECT(controller.canAttachSourceCapture());
    UI_EXPECT(!controller.canSaveIndex());
    UI_EXPECT(controller.flowCount() == 3U);

    auto mismatched_capture_bytes = make_classic_pcap({
        {100, http_flow},
        {200, dns_flow},
        {300, generic_tcp},
    });
    mismatched_capture_bytes.back() ^= 0xFFU;
    {
        std::ofstream mismatched_stream(mismatched_attach_path, std::ios::binary | std::ios::trunc);
        mismatched_stream.write(reinterpret_cast<const char*>(mismatched_capture_bytes.data()), static_cast<std::streamsize>(mismatched_capture_bytes.size()));
    }
    std::filesystem::last_write_time(mismatched_attach_path, std::filesystem::last_write_time(moved_capture_path));

    UI_EXPECT(!controller.attachSourceCapture(QString::fromStdWString(mismatched_attach_path.wstring())));
    UI_EXPECT(controller.openedFromIndex());
    UI_EXPECT(!controller.hasSourceCapture());
    UI_EXPECT(controller.canAttachSourceCapture());
    UI_EXPECT(controller.statusIsError());

    UI_EXPECT(controller.attachSourceCapture(QString::fromStdWString(moved_capture_path.wstring())));
    UI_EXPECT(controller.openedFromIndex());
    UI_EXPECT(controller.hasSourceCapture());
    UI_EXPECT(!controller.canAttachSourceCapture());
    UI_EXPECT(controller.canSaveIndex());
    UI_EXPECT(!controller.statusIsError());

    UI_EXPECT(controller.openCaptureFile(QString::fromStdWString(moved_capture_path.wstring())));

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

    controller.sortFlows(5);
    UI_EXPECT(controller.flowSortColumn() == 5);
    UI_EXPECT(controller.flowSortAscending());

    controller.sortFlows(5);
    UI_EXPECT(!controller.flowSortAscending());

    controller.setFlowFilterText(QStringLiteral("ui.example"));
    UI_EXPECT(flow_model->rowCount() == 1);
    controller.setSelectedFlowIndex(flow_model->data(flow_model->index(0, 0), FlowListModel::FlowIndexRole).toInt());
    UI_EXPECT(controller.canExportSelectedFlow());

    const auto exported_flow_path = std::filesystem::temp_directory_path() / "pfl_ui_selected_flow_export.pcap";
    std::filesystem::remove(exported_flow_path, remove_error);
    UI_EXPECT(controller.exportSelectedFlow(QString::fromStdWString(exported_flow_path.wstring())));
    UI_EXPECT(std::filesystem::exists(exported_flow_path));
    UI_EXPECT(controller.statusText() == QStringLiteral("Flow exported successfully."));
    UI_EXPECT(!controller.statusIsError());

    CaptureSession exported_flow_session {};
    UI_EXPECT(exported_flow_session.open_capture(exported_flow_path));
    UI_EXPECT(exported_flow_session.summary().packet_count == 1U);
    UI_EXPECT(exported_flow_session.summary().flow_count == 1U);

    auto* packet_model = qobject_cast<PacketListModel*>(controller.packetModel());
    UI_EXPECT(packet_model != nullptr);
    UI_EXPECT(packet_model->rowCount() == 1);

    const auto packet_index_model = packet_model->index(0, 0);
    UI_EXPECT(packet_index_model.isValid());
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::RowNumberRole).toUInt() == 1U);
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::DirectionTextRole).toString() == QString::fromUtf8("A\xE2\x86\x92" "B"));
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::PayloadLengthRole).toUInt() == make_http_request_payload().size());
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::OriginalLengthRole).toUInt() == http_flow.size());
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::TcpFlagsTextRole).toString() == QStringLiteral("ACK|SYN"));

    controller.setSelectedPacketIndex(0);
    auto* details_model = qobject_cast<PacketDetailsViewModel*>(controller.packetDetailsModel());
    UI_EXPECT(details_model != nullptr);
    UI_EXPECT(details_model->hasPacket());
    UI_EXPECT(details_model->summaryText().contains(QStringLiteral("Packet index in file: 0")));
    UI_EXPECT(details_model->payloadText().contains(QStringLiteral("47 45 54 20 2f")));
    UI_EXPECT(!details_model->protocolText().isEmpty());

    controller.setCurrentTabIndex(1);
    controller.drillDownToEndpoint(QStringLiteral("10.0.0.1:1111"));

    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.flowFilterText() == QStringLiteral("10.0.0.1:1111"));
    UI_EXPECT(controller.selectedFlowIndex() == -1);
    UI_EXPECT(!controller.canExportSelectedFlow());
    UI_EXPECT(controller.selectedPacketIndex() == std::numeric_limits<qulonglong>::max());
    UI_EXPECT(details_model->payloadText().isEmpty());
    UI_EXPECT(flow_model->rowCount() == 1);

    controller.setCurrentTabIndex(1);
    controller.drillDownToPort(53U);

    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.flowFilterText() == QStringLiteral("53"));
    UI_EXPECT(flow_model->rowCount() == 1);
    UI_EXPECT(flow_model->data(flow_model->index(0, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("DNS"));

    const auto hostless_http_capture_path = write_temp_pcap(
        "pfl_ui_http_settings.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 43000, 80, make_http_request_without_host_payload(), 0x18)},
        })
    );

    MainController settings_controller {};
    UI_EXPECT(!settings_controller.httpUsePathAsServiceHint());
    UI_EXPECT(settings_controller.openCaptureFile(QString::fromStdWString(hostless_http_capture_path.wstring())));
    auto* settings_flow_model = qobject_cast<FlowListModel*>(settings_controller.flowModel());
    UI_EXPECT(settings_flow_model != nullptr);
    UI_EXPECT(settings_flow_model->rowCount() == 1);
    UI_EXPECT(settings_flow_model->data(settings_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString().isEmpty());

    settings_controller.setHttpUsePathAsServiceHint(true);
    UI_EXPECT(settings_controller.httpUsePathAsServiceHint());
    UI_EXPECT(settings_flow_model->data(settings_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString().isEmpty());

    UI_EXPECT(settings_controller.openCaptureFile(QString::fromStdWString(hostless_http_capture_path.wstring())));
    UI_EXPECT(settings_flow_model->rowCount() == 1);
    UI_EXPECT(settings_flow_model->data(settings_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString() == QStringLiteral("/fallback/ui"));

    MainController stream_controller {};
    UI_EXPECT(stream_controller.openCaptureFile(QString::fromStdWString(moved_capture_path.wstring())));
    auto* stream_flow_model = qobject_cast<FlowListModel*>(stream_controller.flowModel());
    auto* stream_model = qobject_cast<StreamListModel*>(stream_controller.streamModel());
    UI_EXPECT(stream_flow_model != nullptr);
    UI_EXPECT(stream_model != nullptr);
    UI_EXPECT(stream_model->rowCount() == 0);

    const int http_stream_flow_index = find_flow_index_by_protocol_hint(stream_flow_model, QStringLiteral("HTTP"));
    const int dns_stream_flow_index = find_flow_index_by_protocol_hint(stream_flow_model, QStringLiteral("DNS"));
    UI_EXPECT(http_stream_flow_index >= 0);
    UI_EXPECT(dns_stream_flow_index >= 0);

    stream_controller.setSelectedFlowIndex(http_stream_flow_index);
    UI_EXPECT(stream_model->rowCount() == 1);
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::DirectionTextRole).toString() == QString::fromUtf8("A\xE2\x86\x92" "B"));
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TCP Payload"));
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::ByteCountRole).toUInt() == make_http_request_payload().size());
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::PacketCountRole).toUInt() == 1U);

    stream_controller.setSelectedFlowIndex(dns_stream_flow_index);
    UI_EXPECT(stream_model->rowCount() == 1);
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::LabelRole).toString() == QStringLiteral("UDP Payload"));
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::ByteCountRole).toUInt() == make_dns_query_payload().size());

    stream_controller.setSelectedFlowIndex(-1);
    UI_EXPECT(stream_model->rowCount() == 0);

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

    const auto full_truncated_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(172, 16, 0, 1), ipv4(172, 16, 0, 2), 34567, 8080, make_http_request_payload(), 0x18);
    const auto captured_truncated_packet = std::vector<std::uint8_t>(full_truncated_packet.begin(), full_truncated_packet.end() - 4);
    const auto truncated_capture_path = write_temp_pcap(
        "pfl_ui_truncated_packet.pcap",
        make_classic_pcap_with_lengths(100U, captured_truncated_packet, static_cast<std::uint32_t>(full_truncated_packet.size()))
    );

    MainController truncated_controller {};
    UI_EXPECT(truncated_controller.openCaptureFile(QString::fromStdWString(truncated_capture_path.wstring())));
    truncated_controller.setSelectedFlowIndex(0);
    auto* truncated_packet_model = qobject_cast<PacketListModel*>(truncated_controller.packetModel());
    UI_EXPECT(truncated_packet_model != nullptr);
    UI_EXPECT(truncated_packet_model->rowCount() == 1);
    const auto truncated_index = truncated_packet_model->index(0, 0);
    UI_EXPECT(truncated_packet_model->data(truncated_index, PacketListModel::CapturedLengthRole).toUInt() == captured_truncated_packet.size());
    UI_EXPECT(truncated_packet_model->data(truncated_index, PacketListModel::OriginalLengthRole).toUInt() == full_truncated_packet.size());

    truncated_controller.setSelectedPacketIndex(0);
    auto* truncated_details_model = qobject_cast<PacketDetailsViewModel*>(truncated_controller.packetDetailsModel());
    UI_EXPECT(truncated_details_model != nullptr);
    UI_EXPECT(truncated_details_model->summaryText().contains(QStringLiteral("Warnings")));
    UI_EXPECT(truncated_details_model->summaryText().contains(QStringLiteral("Packet is truncated in capture")));
    UI_EXPECT(truncated_details_model->summaryText().contains(QStringLiteral("Captured Length: %1").arg(captured_truncated_packet.size())));
    UI_EXPECT(truncated_details_model->summaryText().contains(QStringLiteral("Original Length: %1").arg(full_truncated_packet.size())));
    const auto fragmented_packet = make_ethernet_ipv4_fragment_packet(
        ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2), 6, 0x2000U, {0x16, 0x03, 0x03, 0x00, 0x10});
    const auto fragmented_capture_path = write_temp_pcap(
        "pfl_ui_fragmented_packet.pcap",
        make_classic_pcap({
            {100, fragmented_packet},
            {200, make_ethernet_ipv4_tcp_packet(ipv4(192, 0, 2, 10), ipv4(192, 0, 2, 20), 2222, 443)},
        })
    );

    MainController fragmented_controller {};
    UI_EXPECT(fragmented_controller.openCaptureFile(QString::fromStdWString(fragmented_capture_path.wstring())));
    auto* fragmented_flow_model = qobject_cast<FlowListModel*>(fragmented_controller.flowModel());
    UI_EXPECT(fragmented_flow_model != nullptr);
    UI_EXPECT(fragmented_flow_model->rowCount() == 2);

    bool saw_fragmented_flow = false;
    for (int row = 0; row < fragmented_flow_model->rowCount(); ++row) {
        const auto index = fragmented_flow_model->index(row, 0);
        if (fragmented_flow_model->data(index, FlowListModel::HasFragmentedPacketsRole).toBool()) {
            saw_fragmented_flow = true;
            UI_EXPECT(fragmented_flow_model->data(index, FlowListModel::FragmentedPacketCountRole).toString() == QStringLiteral("1"));
            fragmented_controller.setSelectedFlowIndex(
                fragmented_flow_model->data(index, FlowListModel::FlowIndexRole).toInt()
            );
            break;
        }
    }
    UI_EXPECT(saw_fragmented_flow);

    auto* fragmented_packet_model = qobject_cast<PacketListModel*>(fragmented_controller.packetModel());
    UI_EXPECT(fragmented_packet_model != nullptr);
    UI_EXPECT(fragmented_packet_model->rowCount() == 1);
    UI_EXPECT(fragmented_packet_model->data(fragmented_packet_model->index(0, 0), PacketListModel::IsIpFragmentedRole).toBool());

    fragmented_controller.setSelectedPacketIndex(0);
    auto* fragmented_details_model = qobject_cast<PacketDetailsViewModel*>(fragmented_controller.packetDetailsModel());
    UI_EXPECT(fragmented_details_model != nullptr);
    UI_EXPECT(fragmented_details_model->summaryText().contains(QStringLiteral("Warnings")));
    UI_EXPECT(fragmented_details_model->summaryText().contains(QStringLiteral("Packet is IP-fragmented")));

    return 0;
}


