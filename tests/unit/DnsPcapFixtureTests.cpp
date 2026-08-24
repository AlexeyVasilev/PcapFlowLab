#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "PcapTestUtils.h"
#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SelectedPacketSummaryPreparation.h"
#include "app/session/SessionFlowHelpers.h"
#include "app/session/SessionFormatting.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

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

const session_detail::PacketSummaryLayer* find_summary_child(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& id
) {
    const auto it = std::find_if(layer.children.begin(), layer.children.end(), [&](const auto& child) {
        return child.id == id;
    });
    return it != layer.children.end() ? &(*it) : nullptr;
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

const session_detail::PacketSummaryLayer* require_summary_child(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& id
) {
    const auto* child = find_summary_child(layer, id);
    PFL_REQUIRE(child != nullptr);
    return child;
}

std::string require_descendant_summary_field_value(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto* field = find_descendant_summary_field(layer, label);
    PFL_REQUIRE(field != nullptr);
    return field->value;
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
        .captured_transport_payload_length =
            session_detail::derive_captured_transport_payload_length_from_headers(session, packet),
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

std::vector<session_detail::PacketSummaryLayer> build_fixture_summary_layers_without_flow_context(
    const std::filesystem::path& relative_fixture_path
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_fixture_path)));
    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
        session,
        *details,
        packet,
        std::nullopt,
        std::nullopt,
        std::nullopt
    );
    return session_detail::build_packet_summary_layers(*details, packet, packet_summary_preparation.make_options());
}

std::vector<session_detail::PacketSummaryLayer> build_summary_layers_for_packet_bytes(
    const std::string& file_name,
    const std::vector<std::uint8_t>& packet_bytes
) {
    const auto capture_path = write_temp_pcap(
        file_name,
        make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
            {100U, packet_bytes},
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));
    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
        session,
        *details,
        packet,
        std::nullopt,
        std::nullopt,
        std::nullopt
    );
    return session_detail::build_packet_summary_layers(*details, packet, packet_summary_preparation.make_options());
}

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
    expect_flow_hint_fixture(
        "parsing/mdns/01_mdns_ipv4_ptr_query.pcap",
        "mdns",
        std::optional<std::string> {"_demo-service._tcp.local"}
    );
    expect_flow_hint_fixture(
        "parsing/mdns/02_mdns_ipv6_ptr_query.pcap",
        "mdns",
        std::optional<std::string> {"_demo-service._tcp.local"}
    );
    expect_flow_hint_fixture(
        "parsing/mdns/03_mdns_ipv4_ptr_response.pcap",
        "mdns",
        std::optional<std::string> {"_demo-service._tcp.local"}
    );
    expect_flow_hint_fixture(
        "parsing/mdns/04_mdns_ipv4_dns_sd_response.pcap",
        "mdns",
        std::optional<std::string> {"_demo-service._tcp.local"}
    );
    expect_flow_hint_fixture("parsing/mdns/10_mdns_ipv4_truncated_message.pcap", "mdns", std::nullopt);
    expect_flow_hint_fixture("parsing/mdns/11_mdns_ipv4_malformed_pointer.pcap", "mdns", std::nullopt);
    expect_flow_hint_fixture("parsing/mdns/12_mdns_wrong_port_negative.pcap", "", std::nullopt);
    expect_flow_hint_fixture("parsing/mdns/13_mdns_wrong_multicast_destination_negative.pcap", "", std::nullopt);
}

void expect_mdns_display_text() {
    PFL_EXPECT(session_detail::format_flow_protocol_hint_display("mdns") == "mDNS");
    PFL_EXPECT(session_detail::format_flow_protocol_hint_display("dns") == "DNS");
}

void expect_dns_summary_contracts() {
    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/03_dns_ipv4_a_query.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(dns_layer->title == "Domain Name System, Query");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Transaction ID") == "0x1001");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Opcode") == "Standard query (0)");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Questions") == "1");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Answers") == "0");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "QName") == "a-query.example.test");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "QType") == "A (1)");
        const auto* questions_layer = require_summary_child(*dns_layer, "dns_questions");
        PFL_REQUIRE(questions_layer->children.size() == 1U);
        PFL_EXPECT(questions_layer->children[0].title == "a-query.example.test");
        PFL_EXPECT(require_summary_field_value(questions_layer->children[0], "Type") == "A (1)");
        PFL_EXPECT(require_summary_field_value(questions_layer->children[0], "Class") == "IN (1)");
        PFL_EXPECT(find_descendant_summary_field(*dns_layer, "Unicast Response Requested") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/04_dns_ipv4_a_response_compressed.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(dns_layer->title == "Domain Name System, Response");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Transaction ID") == "0x1002");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Response Code") == "No error (0)");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Answers") == "1");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "QName") == "www.example.test");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "QType") == "A (1)");
        const auto* answers_layer = require_summary_child(*dns_layer, "dns_answers");
        PFL_REQUIRE(answers_layer->children.size() == 1U);
        PFL_EXPECT(require_summary_field_value(answers_layer->children[0], "Address") == "192.0.2.44");
        PFL_EXPECT(find_descendant_summary_field(*dns_layer, "Cache Flush") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/07_dns_ipv4_cname_response_compressed.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Answers") == "1");
        const auto* cname_target = find_descendant_summary_field(*dns_layer, "Canonical Name");
        PFL_REQUIRE(cname_target != nullptr);
        PFL_EXPECT(cname_target->value == "real.example.test");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/08_dns_ipv4_multiple_answers_response.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Answers") == "2");
        const auto* answers_layer = require_summary_child(*dns_layer, "dns_answers");
        PFL_REQUIRE(answers_layer->children.size() == 2U);
        PFL_EXPECT(require_summary_field_value(answers_layer->children[0], "Address") == "192.0.2.80");
        PFL_EXPECT(require_summary_field_value(answers_layer->children[1], "Address") == "192.0.2.81");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/09_dns_ipv4_nxdomain_response.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Response Code") == "NXDOMAIN (3)");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Answers") == "0");
        PFL_EXPECT(find_summary_child(*dns_layer, "dns_answers") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/10_dns_ipv4_https_query.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "QType") == "HTTPS (65)");
        const auto* questions_layer = require_summary_child(*dns_layer, "dns_questions");
        PFL_REQUIRE(questions_layer->children.size() == 1U);
        PFL_EXPECT(require_summary_field_value(questions_layer->children[0], "Type") == "HTTPS (65)");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/12_dns_ipv4_srv_response.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        const auto* srv_target = find_descendant_summary_field(*dns_layer, "Target");
        PFL_REQUIRE(srv_target != nullptr);
        PFL_EXPECT(require_descendant_summary_field_value(*dns_layer, "Priority") == "0");
        PFL_EXPECT(require_descendant_summary_field_value(*dns_layer, "Weight") == "0");
        PFL_EXPECT(require_descendant_summary_field_value(*dns_layer, "Port") == "12345");
        PFL_EXPECT(srv_target->value == "service-host.example.test");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/13_dns_ipv4_txt_response.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(require_descendant_summary_field_value(*dns_layer, "TXT[0]") == "path=/demo");
        PFL_EXPECT(require_descendant_summary_field_value(*dns_layer, "TXT[1]") == "ver=1");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/17_dns_ipv4_unknown_rr_response.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        const auto* answers_layer = require_summary_child(*dns_layer, "dns_answers");
        PFL_REQUIRE(answers_layer->children.size() == 1U);
        PFL_EXPECT(require_summary_field_value(answers_layer->children[0], "Type") == "Unknown (65280)");
        PFL_EXPECT(require_summary_field_value(answers_layer->children[0], "RDATA Length") == "4");
        PFL_EXPECT(require_summary_field_value(answers_layer->children[0], "RDATA Status") == "Opaque / not parsed");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/15_dns_ipv4_malformed_pointer_oob.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(dns_layer->warning);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Warning") == "DNS message malformed");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Questions") == "1");
        PFL_EXPECT(find_summary_child(*dns_layer, "dns_questions") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/14_dns_ipv4_truncated_message.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(dns_layer->title == "Domain Name System, Query");
        PFL_EXPECT(find_summary_field(*dns_layer, "Transaction ID") != nullptr);
        PFL_EXPECT(find_summary_field(*dns_layer, "Flags") != nullptr);
        PFL_EXPECT(find_summary_field(*dns_layer, "Opcode") != nullptr);
        PFL_EXPECT(dns_layer->warning);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Warning") == "DNS message truncated");
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Questions") == "1");
        PFL_EXPECT(find_summary_child(*dns_layer, "dns_questions") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/dns/16_dns_ipv4_malformed_pointer_loop.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(dns_layer->warning);
        PFL_EXPECT(require_summary_field_value(*dns_layer, "Warning") == "DNS message malformed");
        PFL_EXPECT(find_summary_child(*dns_layer, "dns_questions") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }
}

void expect_mdns_summary_contracts() {
    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/01_mdns_ipv4_ptr_query.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(mdns_layer->title == "Multicast Domain Name System, Query");
        PFL_EXPECT(require_summary_field_value(*mdns_layer, "Message Type") == "Query");
        PFL_EXPECT(require_descendant_summary_field_value(*mdns_layer, "Class") == "IN (1)");
        PFL_EXPECT(require_descendant_summary_field_value(*mdns_layer, "Unicast Response Requested") == "No");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/02_mdns_ipv6_ptr_query.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(mdns_layer->title == "Multicast Domain Name System, Query");
        const auto* questions_layer = require_summary_child(*mdns_layer, "dns_questions");
        PFL_REQUIRE(questions_layer->children.size() == 1U);
        PFL_EXPECT(questions_layer->children[0].title == "_demo-service._tcp.local");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/03_mdns_ipv4_ptr_response.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(mdns_layer->title == "Multicast Domain Name System, Response");
        PFL_EXPECT(require_descendant_summary_field_value(*mdns_layer, "PTR Target") == "Example Device._demo-service._tcp.local");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/04_mdns_ipv4_dns_sd_response.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*mdns_layer, "Answers") == "1");
        PFL_EXPECT(require_summary_field_value(*mdns_layer, "Additional RRs") == "3");
        const auto* ptr_target = find_descendant_summary_field(*mdns_layer, "PTR Target");
        const auto* srv_target = find_descendant_summary_field(*mdns_layer, "Target");
        const auto* txt0 = find_descendant_summary_field(*mdns_layer, "TXT[0]");
        const auto* ipv4_address = find_descendant_summary_field(*mdns_layer, "Address");
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
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/05_mdns_ipv6_dns_sd_response_aaaa.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(require_descendant_summary_field_value(*mdns_layer, "Address") == "2001:db8::44");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/06_mdns_ipv4_multiple_questions.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        const auto* questions_layer = require_summary_child(*mdns_layer, "dns_questions");
        PFL_REQUIRE(questions_layer->children.size() == 2U);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/07_mdns_ipv4_multiple_answers.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        const auto* answers_layer = require_summary_child(*mdns_layer, "dns_answers");
        PFL_REQUIRE(answers_layer->children.size() == 2U);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/08_mdns_ipv4_cache_flush_response.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        const auto* cache_flush = find_descendant_summary_field(*mdns_layer, "Cache Flush");
        PFL_REQUIRE(cache_flush != nullptr);
        PFL_EXPECT(cache_flush->value == "Yes");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/09_mdns_ipv4_qu_question.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        const auto* qu = find_descendant_summary_field(*mdns_layer, "Unicast Response Requested");
        PFL_REQUIRE(qu != nullptr);
        PFL_EXPECT(qu->value == "Yes");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/10_mdns_ipv4_truncated_message.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(mdns_layer->warning);
        PFL_EXPECT(require_summary_field_value(*mdns_layer, "Warning") == "DNS message truncated");
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/mdns/11_mdns_ipv4_malformed_pointer.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(mdns_layer->warning);
        PFL_EXPECT(require_summary_field_value(*mdns_layer, "Warning") == "DNS message malformed");
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }
}

void expect_dns_mdns_presentation_isolation() {
    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/mdns/09_mdns_ipv4_qu_question.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        session_detail::PacketSummaryOptions options {};
        options.dns_summary_presentation_kind = session_detail::DnsSummaryPresentationKind::dns;
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet, options);
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(find_descendant_summary_field(*dns_layer, "Unicast Response Requested") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/mdns/08_mdns_ipv4_cache_flush_response.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        session_detail::PacketSummaryOptions options {};
        options.dns_summary_presentation_kind = session_detail::DnsSummaryPresentationKind::dns;
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet, options);
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(find_descendant_summary_field(*dns_layer, "Cache Flush") == nullptr);
    }
}

void expect_dns_mdns_summary_context_without_flow_lookup() {
    {
        const auto summary_layers = build_fixture_summary_layers_without_flow_context("parsing/dns/03_dns_ipv4_a_query.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(dns_layer->title == "Domain Name System, Query");
        PFL_EXPECT(find_summary_layer(summary_layers, "mdns") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers_without_flow_context("parsing/mdns/01_mdns_ipv4_ptr_query.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(mdns_layer->title == "Multicast Domain Name System, Query");
        PFL_EXPECT(find_summary_layer(summary_layers, "dns") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers_without_flow_context("parsing/mdns/02_mdns_ipv6_ptr_query.pcap");
        const auto* mdns_layer = find_summary_layer(summary_layers, "mdns");
        PFL_REQUIRE(mdns_layer != nullptr);
        PFL_EXPECT(mdns_layer->title == "Multicast Domain Name System, Query");
    }

    {
        const auto summary_layers =
            build_fixture_summary_layers_without_flow_context("parsing/mdns/12_mdns_wrong_port_negative.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(dns_layer->title.find("Domain Name System") != std::string::npos);
        PFL_EXPECT(find_summary_layer(summary_layers, "mdns") == nullptr);
    }

    {
        const auto summary_layers =
            build_fixture_summary_layers_without_flow_context("parsing/mdns/13_mdns_wrong_multicast_destination_negative.pcap");
        const auto* dns_layer = find_summary_layer(summary_layers, "dns");
        PFL_REQUIRE(dns_layer != nullptr);
        PFL_EXPECT(dns_layer->title.find("Domain Name System") != std::string::npos);
        PFL_EXPECT(find_summary_layer(summary_layers, "mdns") == nullptr);
    }
}

void expect_non_dns_udp_payload_stays_non_dns() {
    const auto packet_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 0, 50, 1),
        ipv4(10, 0, 50, 2),
        54050,
        40050,
        std::vector<std::uint8_t> {
            0x10U, 0x01U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U,
            0xdeU, 0xadU, 0xbeU, 0xefU,
        }
    );
    const auto summary_layers =
        build_summary_layers_for_packet_bytes("pfl_non_dns_udp_summary_negative.pcap", packet_bytes);
    PFL_EXPECT(find_summary_layer(summary_layers, "dns") == nullptr);
    PFL_EXPECT(find_summary_layer(summary_layers, "mdns") == nullptr);
}

}  // namespace

void run_dns_pcap_fixture_tests() {
    expect_current_default_dns_baseline();
    expect_current_default_mdns_detector_scope();
    expect_mdns_display_text();
    expect_dns_summary_contracts();
    expect_mdns_summary_contracts();
    expect_dns_mdns_presentation_isolation();
    expect_dns_mdns_summary_context_without_flow_lookup();
    expect_non_dns_udp_payload_stays_non_dns();
}

}  // namespace pfl::tests
