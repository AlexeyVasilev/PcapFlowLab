#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/SelectedPacketSummaryPreparation.h"
#include "app/session/SessionFormatting.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

#if defined(PFL_ENABLE_PENDING_DNS_INSPECTION_TESTS)

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    return *packet;
}

const session_detail::PacketSummaryLayer* find_summary_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    const auto it = std::find_if(layers.begin(), layers.end(), [&](const auto& layer) {
        return layer.id == id;
    });
    return it != layers.end() ? &(*it) : nullptr;
}

const session_detail::PacketSummaryField* find_summary_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto it = std::find_if(layer.fields.begin(), layer.fields.end(), [&](const auto& field) {
        return field.label == label;
    });
    return it != layer.fields.end() ? &(*it) : nullptr;
}

std::string require_summary_field_value(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto* field = find_summary_field(layer, label);
    PFL_REQUIRE(field != nullptr);
    return field->value;
}

const session_detail::PacketSummaryField* find_descendant_summary_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    if (const auto* field = find_summary_field(layer, label); field != nullptr) {
        return field;
    }

    for (const auto& child : layer.children) {
        if (const auto* descendant = find_descendant_summary_field(child, label); descendant != nullptr) {
            return descendant;
        }
    }
    return nullptr;
}

struct SelectedPacketTransportPayloadLengths {
    std::optional<std::uint32_t> captured_transport_payload_length {};
    std::optional<std::uint32_t> original_transport_payload_length {};
};

SelectedPacketTransportPayloadLengths resolve_selected_packet_transport_payload_lengths(
    CaptureSession& session,
    const PacketRef& packet
) {
    return SelectedPacketTransportPayloadLengths {
        .captured_transport_payload_length = std::optional<std::uint32_t> {packet.payload_length},
        .original_transport_payload_length =
            session_detail::derive_original_transport_payload_length_from_headers(session, packet),
    };
}

struct SelectedPacketFlowContext {
    std::optional<std::size_t> flow_index {};
    std::optional<std::uint64_t> flow_packet_index {};
    std::optional<std::size_t> loaded_packet_window_count {};
};

SelectedPacketFlowContext resolve_selected_packet_flow_context(
    CaptureSession& session,
    const PacketRef& packet
) {
    SelectedPacketFlowContext context {};
    const auto flow_rows = session.list_flows();
    for (const auto& flow_row : flow_rows) {
        const auto packet_rows = session.list_flow_packets(flow_row.index);
        const auto packet_it = std::find_if(packet_rows.begin(), packet_rows.end(), [&](const PacketRow& row) {
            return row.packet_index == packet.packet_index;
        });
        if (packet_it == packet_rows.end()) {
            continue;
        }

        context.flow_index = flow_row.index;
        PFL_REQUIRE(packet_it->row_number > 0U);
        context.flow_packet_index = packet_it->row_number - 1U;
        context.loaded_packet_window_count = packet_rows.size();
        break;
    }

    return context;
}

session_detail::SelectedPacketSummaryPreparation prepare_selected_packet_summary_with_production_lengths(
    CaptureSession& session,
    const PacketDetails& details,
    const PacketRef& packet,
    const std::optional<std::size_t> flow_index,
    const std::optional<std::uint64_t> flow_packet_index,
    const std::optional<std::size_t> loaded_packet_window_count
) {
    const auto payload_lengths = resolve_selected_packet_transport_payload_lengths(session, packet);
    return session_detail::prepare_selected_packet_summary(
        session,
        details,
        packet,
        flow_index,
        flow_packet_index,
        loaded_packet_window_count,
        payload_lengths.captured_transport_payload_length,
        payload_lengths.original_transport_payload_length
    );
}

std::vector<session_detail::PacketSummaryLayer> build_fixture_summary_layers(
    const std::filesystem::path& relative_fixture_path
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_fixture_path)));
    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    const auto flow_context = resolve_selected_packet_flow_context(session, packet);
    auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
        session,
        *details,
        packet,
        flow_context.flow_index,
        flow_context.flow_packet_index,
        flow_context.loaded_packet_window_count
    );
    return session_detail::build_packet_summary_layers(*details, packet, packet_summary_preparation.make_options());
}

#endif

void expect_flow_hint_fixture(
    const std::filesystem::path& relative_fixture_path,
    const std::string& expected_protocol_hint,
    const std::optional<std::string>& expected_service_hint
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_fixture_path)));
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].protocol_hint == expected_protocol_hint);
    if (expected_service_hint.has_value()) {
        PFL_EXPECT(rows[0].service_hint == *expected_service_hint);
    } else {
        PFL_EXPECT(rows[0].service_hint.empty());
    }
}

void expect_current_default_dns_baseline() {
    expect_flow_hint_fixture(
        "parsing/dns/dns_request_1.pcap",
        "dns",
        std::optional<std::string> {"gsp85-ssl.ls.apple.com"}
    );
    expect_flow_hint_fixture(
        "parsing/dns/dns_response_2.pcap",
        "dns",
        std::optional<std::string> {"_dns.resolver.arpa"}
    );
}

void expect_current_default_mdns_detector_scope() {
    expect_flow_hint_fixture("parsing/mdns/01_mdns_ipv4_ptr_query.pcap", "mdns", std::nullopt);
    expect_flow_hint_fixture("parsing/mdns/02_mdns_ipv6_ptr_query.pcap", "mdns", std::nullopt);
    expect_flow_hint_fixture("parsing/mdns/12_mdns_wrong_port_negative.pcap", "", std::nullopt);
    expect_flow_hint_fixture("parsing/mdns/13_mdns_wrong_multicast_destination_negative.pcap", "", std::nullopt);
}

#if defined(PFL_ENABLE_PENDING_DNS_INSPECTION_TESTS)

void expect_pending_dns_summary_contracts() {
    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/03_dns_ipv4_a_query.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Transaction ID") == "0x1001");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Opcode") == "Query");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Question Count") == "1");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Answer Count") == "0");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/04_dns_ipv4_a_response_compressed.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Transaction ID") == "0x1002");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Response Code") == "NoError (0)");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Answer Count") == "1");
        PFL_REQUIRE(find_descendant_summary_field(*dns_layer, "IPv4 Address") != nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/07_dns_ipv4_cname_response_compressed.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Answer Count") == "1");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Compression") == "Used");
        const auto* cname_target = find_descendant_summary_field(*dns_layer, "CNAME Target");
        PFL_REQUIRE(cname_target != nullptr);
        PFL_EXPECT(cname_target->value == "real.example.test");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/08_dns_ipv4_multiple_answers_response.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Answer Count") == "2");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/09_dns_ipv4_nxdomain_response.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Response Code") == "NXDOMAIN (3)");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Answer Count") == "0");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/15_dns_ipv4_malformed_pointer_oob.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(dns_layer->warning);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Compression Error") == "Pointer outside message bounds");
    }
}

void expect_pending_mdns_summary_contracts() {
    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/01_mdns_ipv4_ptr_query.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(mdns_layer->title.find("Multicast Domain Name System") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*mdns_layer, "Message Type") == "Query");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/04_mdns_ipv4_dns_sd_response.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*mdns_layer, "Answer Count") == "1");
        PFL_EXPECT(require_summary_field_value(*mdns_layer, "Additional Count") == "3");
        const auto* ptr_target = find_descendant_summary_field(*mdns_layer, "PTR Target");
        const auto* srv_target = find_descendant_summary_field(*mdns_layer, "SRV Target");
        const auto* txt0 = find_descendant_summary_field(*mdns_layer, "TXT[0]");
        const auto* ipv4_address = find_descendant_summary_field(*mdns_layer, "IPv4 Address");
        PFL_REQUIRE(ptr_target != nullptr);
        PFL_REQUIRE(srv_target != nullptr);
        PFL_REQUIRE(txt0 != nullptr);
        PFL_REQUIRE(ipv4_address != nullptr);
        PFL_EXPECT(ptr_target->value == "Example Device._demo-service._tcp.local");
        PFL_EXPECT(srv_target->value == "example-device.local");
        PFL_EXPECT(txt0->value == "id=demo");
        PFL_EXPECT(ipv4_address->value == "192.0.2.44");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/08_mdns_ipv4_cache_flush_response.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        const auto* cache_flush = find_descendant_summary_field(*mdns_layer, "Cache Flush");
        PFL_REQUIRE(cache_flush != nullptr);
        PFL_EXPECT(cache_flush->value == "true");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/09_mdns_ipv4_qu_question.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        const auto* qu = find_descendant_summary_field(*mdns_layer, "Unicast Response Requested");
        PFL_REQUIRE(qu != nullptr);
        PFL_EXPECT(qu->value == "true");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/10_mdns_ipv4_truncated_message.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(mdns_layer->warning);
        PFL_EXPECT(require_summary_field_value(*mdns_layer, "Warning") == "DNS message truncated");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/11_mdns_ipv4_malformed_pointer.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(mdns_layer->warning);
        PFL_EXPECT(require_summary_field_value(*mdns_layer, "Compression Error") == "Pointer outside message bounds");
    }
}

#endif

}  // namespace

void run_dns_pcap_fixture_tests() {
    expect_current_default_dns_baseline();
    expect_current_default_mdns_detector_scope();

#if defined(PFL_ENABLE_PENDING_DNS_INSPECTION_TESTS)
    expect_pending_dns_summary_contracts();
    expect_pending_mdns_summary_contracts();
#endif
}

}  // namespace pfl::tests
