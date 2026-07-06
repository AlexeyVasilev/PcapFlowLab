#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SessionFormatting.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

bool row_matches_tuple(
    const FlowRow& row,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    if (row.family != family || row.protocol_text != protocol) {
        return false;
    }

    const bool forward_match =
        row.address_a == address_a &&
        row.port_a == port_a &&
        row.address_b == address_b &&
        row.port_b == port_b;
    const bool reverse_match =
        row.address_a == address_b &&
        row.port_a == port_b &&
        row.address_b == address_a &&
        row.port_b == port_a;
    return forward_match || reverse_match;
}

const FlowRow* find_flow_by_tuple(
    const std::vector<FlowRow>& rows,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    for (const auto& row : rows) {
        if (row_matches_tuple(row, family, protocol, address_a, port_a, address_b, port_b)) {
            return &row;
        }
    }
    return nullptr;
}

const session_detail::PacketSummaryLayer* find_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    for (const auto& layer : layers) {
        if (layer.id == id) {
            return &layer;
        }
        if (const auto* child = find_layer(layer.children, id); child != nullptr) {
            return child;
        }
    }
    return nullptr;
}

const session_detail::PacketSummaryLayer* find_top_level_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    for (const auto& layer : layers) {
        if (layer.id == id) {
            return &layer;
        }
    }
    return nullptr;
}

std::size_t find_top_level_layer_index(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    for (std::size_t index = 0U; index < layers.size(); ++index) {
        if (layers[index].id == id) {
            return index;
        }
    }
    return layers.size();
}

bool layer_has_field_containing(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label,
    const std::string& fragment
) {
    for (const auto& field : layer.fields) {
        if (field.label == label && field.value.find(fragment) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool layer_has_field_label(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    return std::any_of(layer.fields.begin(), layer.fields.end(), [&](const auto& field) {
        return field.label == label;
    });
}

bool title_contains_all(
    const session_detail::PacketSummaryLayer& layer,
    const std::initializer_list<std::string> fragments
) {
    for (const auto& fragment : fragments) {
        if (layer.title.find(fragment) == std::string::npos) {
            return false;
        }
    }
    return true;
}

std::string format_hex_value(const std::uint32_t value, const int width = 0) {
    std::ostringstream builder {};
    builder << "0x" << std::hex << std::nouppercase;
    if (width > 0) {
        builder << std::setw(width) << std::setfill('0');
    }
    builder << value;
    return builder.str();
}

void expect_inner_flow_present(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b,
    const std::uint64_t expected_packet_count
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    const auto* flow = find_flow_by_tuple(rows, family, protocol, address_a, port_a, address_b, port_b);
    PFL_EXPECT(flow != nullptr);
    if (flow == nullptr) {
        return;
    }

    PFL_EXPECT(flow->packet_count == expected_packet_count);
}

void expect_inner_flow_absent(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    const auto* flow = find_flow_by_tuple(rows, family, protocol, address_a, port_a, address_b, port_b);
    PFL_EXPECT(flow == nullptr);
}

void expect_gtpu_packet_details_present(
    const std::filesystem::path& relative_path,
    const std::uint64_t packet_index,
    const std::uint32_t expected_teid,
    const std::string& expected_inner_network_layer_id,
    const std::string& expected_inner_transport_layer_id,
    const std::string& expected_inner_source,
    const std::string& expected_inner_destination,
    const std::string& expected_inner_source_port,
    const std::string& expected_inner_destination_port
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());

    PFL_EXPECT(details->has_udp);
    PFL_EXPECT(details->has_gtpu);
    PFL_EXPECT(details->gtpu.present);
    PFL_EXPECT(details->gtpu.version == 1U);
    PFL_EXPECT(details->gtpu.protocol_type_flag_set);
    PFL_EXPECT(details->gtpu.message_type == 0xFFU);
    PFL_EXPECT(details->gtpu.teid == expected_teid);
    PFL_EXPECT(details->gtpu.has_inner_packet);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* udp_layer = find_layer(summary_layers, "udp");
    PFL_REQUIRE(udp_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*udp_layer, "Destination Port", "2152"));

    const auto* gtpu_layer = find_layer(summary_layers, "gtpu");
    PFL_REQUIRE(gtpu_layer != nullptr);
    PFL_EXPECT(title_contains_all(*gtpu_layer, {"GTP-U", format_hex_value(expected_teid, 8)}));
    PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "Flags", "0x"));
    PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "Flags", "Version 1"));
    PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "Flags", "PT set"));
    PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "Message Type", "T-PDU (0xff)"));
    PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "TEID", format_hex_value(expected_teid, 8)));
    PFL_EXPECT(!layer_has_field_label(*gtpu_layer, "Version"));
    PFL_EXPECT(!layer_has_field_label(*gtpu_layer, "PT Flag"));
    PFL_EXPECT(!layer_has_field_label(*gtpu_layer, "Optional Fields Present"));
    if (!details->gtpu.sequence_number_flag_set) {
        PFL_EXPECT(!layer_has_field_label(*gtpu_layer, "S Flag"));
    }
    if (!details->gtpu.npdu_number_flag_set) {
        PFL_EXPECT(!layer_has_field_label(*gtpu_layer, "PN Flag"));
    }
    if (!details->gtpu.extension_header_flag_set) {
        PFL_EXPECT(!layer_has_field_label(*gtpu_layer, "E Flag"));
    }
    PFL_EXPECT(gtpu_layer->children.empty());

    const auto gtpu_index = find_top_level_layer_index(summary_layers, "gtpu");
    const auto inner_network_index = find_top_level_layer_index(summary_layers, expected_inner_network_layer_id);
    const auto inner_transport_index = find_top_level_layer_index(summary_layers, expected_inner_transport_layer_id);
    PFL_REQUIRE(gtpu_index < summary_layers.size());
    PFL_REQUIRE(inner_network_index < summary_layers.size());
    PFL_REQUIRE(inner_transport_index < summary_layers.size());
    PFL_EXPECT(gtpu_index < inner_network_index);
    PFL_EXPECT(inner_network_index < inner_transport_index);

    const auto* inner_network_layer = find_top_level_layer(summary_layers, expected_inner_network_layer_id);
    PFL_REQUIRE(inner_network_layer != nullptr);
    if (expected_inner_network_layer_id == "ipv4-inner") {
        PFL_EXPECT(title_contains_all(*inner_network_layer, {
            "Inner IPv4",
            expected_inner_source,
            expected_inner_destination,
        }));
    } else if (expected_inner_network_layer_id == "ipv6-inner") {
        PFL_EXPECT(title_contains_all(*inner_network_layer, {
            "Inner IPv6",
            expected_inner_source,
            expected_inner_destination,
        }));
    }

    const auto* inner_transport_layer = find_top_level_layer(summary_layers, expected_inner_transport_layer_id);
    PFL_REQUIRE(inner_transport_layer != nullptr);
    if (expected_inner_transport_layer_id == "tcp-inner") {
        PFL_EXPECT(title_contains_all(*inner_transport_layer, {"Inner TCP", "Src Port:", "Dst Port:"}));
    } else if (expected_inner_transport_layer_id == "udp-inner") {
        PFL_EXPECT(title_contains_all(*inner_transport_layer, {"Inner UDP", "Src Port:", "Dst Port:"}));
    }
    PFL_EXPECT(title_contains_all(*inner_transport_layer, {
        expected_inner_source_port,
        expected_inner_destination_port,
    }));

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Protocol: GTP-U") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Flags: 0x") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Version: ") == std::string::npos);
    PFL_EXPECT(protocol_text.find("PT Flag: ") == std::string::npos);
    PFL_EXPECT(protocol_text.find("Optional Fields Present: ") == std::string::npos);
    if (!details->gtpu.sequence_number_flag_set) {
        PFL_EXPECT(protocol_text.find("S Flag: Not set") == std::string::npos);
    }
    if (!details->gtpu.npdu_number_flag_set) {
        PFL_EXPECT(protocol_text.find("PN Flag: Not set") == std::string::npos);
    }
    if (!details->gtpu.extension_header_flag_set) {
        PFL_EXPECT(protocol_text.find("E Flag: Not set") == std::string::npos);
    }
    PFL_EXPECT(protocol_text.find("Message Type: T-PDU (0xff)") != std::string::npos);
    PFL_EXPECT(protocol_text.find("TEID: " + format_hex_value(expected_teid, 8)) != std::string::npos);
    const auto expected_transport_text =
        expected_inner_transport_layer_id == "tcp-inner" ? std::string {"TCP"} :
        expected_inner_transport_layer_id == "udp-inner" ? std::string {"UDP"} :
        expected_inner_transport_layer_id;
    if (expected_inner_network_layer_id == "ipv4-inner") {
        PFL_EXPECT(protocol_text.find("Inner Payload: IPv4") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Inner IPv4: " + expected_transport_text) != std::string::npos);
    } else if (expected_inner_network_layer_id == "ipv6-inner") {
        PFL_EXPECT(protocol_text.find("Inner Payload: IPv6") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Inner IPv6: " + expected_transport_text) != std::string::npos);
    }
}

void expect_gtpu_warning_packet_details(
    const std::filesystem::path& relative_path,
    const std::initializer_list<std::string> expected_gtpu_title_fragments,
    const std::initializer_list<std::string> expected_protocol_fragments,
    const bool expect_gtpu_layer_warning,
    const bool expect_inner_ipv4,
    const bool expect_inner_ipv6,
    const bool expect_inner_udp,
    const bool expect_inner_tcp
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_udp);
    PFL_EXPECT(details->has_gtpu);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* gtpu_layer = find_layer(summary_layers, "gtpu");
    PFL_REQUIRE(gtpu_layer != nullptr);
    PFL_EXPECT(title_contains_all(*gtpu_layer, expected_gtpu_title_fragments));
    PFL_EXPECT(gtpu_layer->warning == expect_gtpu_layer_warning);

    const auto* inner_ipv4_layer = find_top_level_layer(summary_layers, "ipv4-inner");
    PFL_EXPECT((inner_ipv4_layer != nullptr) == expect_inner_ipv4);
    if (expect_inner_ipv4 && inner_ipv4_layer != nullptr) {
        PFL_EXPECT(inner_ipv4_layer->title.find("Inner IPv4") != std::string::npos);
    }
    const auto* inner_ipv6_layer = find_top_level_layer(summary_layers, "ipv6-inner");
    PFL_EXPECT((inner_ipv6_layer != nullptr) == expect_inner_ipv6);
    if (expect_inner_ipv6 && inner_ipv6_layer != nullptr) {
        PFL_EXPECT(inner_ipv6_layer->title.find("Inner IPv6") != std::string::npos);
    }
    const auto* inner_udp_layer = find_top_level_layer(summary_layers, "udp-inner");
    PFL_EXPECT((inner_udp_layer != nullptr) == expect_inner_udp);
    const auto* inner_tcp_layer = find_top_level_layer(summary_layers, "tcp-inner");
    PFL_EXPECT((inner_tcp_layer != nullptr) == expect_inner_tcp);

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Protocol: GTP-U") != std::string::npos);
    for (const auto& fragment : expected_protocol_fragments) {
        PFL_EXPECT(protocol_text.find(fragment) != std::string::npos);
    }
}

void run_gtpu_positive_fixture_tests() {
    expect_inner_flow_present(
        "parsing/gtpu/01_gtpu_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/02_gtpu_inner_ipv4_udp.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "10.60.0.10",
        53760U,
        "10.60.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/03_gtpu_inner_ipv6_tcp.pcap",
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0060:0000:0000:0000:0000:0010",
        49660U,
        "2001:0db8:0060:0000:0000:0000:0000:0020",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/04_gtpu_inner_ipv6_udp.pcap",
        FlowAddressFamily::ipv6,
        "UDP",
        "2001:0db8:0060:0000:0000:0000:0000:0010",
        53760U,
        "2001:0db8:0060:0000:0000:0000:0000:0020",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/11_gtpu_inner_ipv4_tcp_bidirectional.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        2U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/12_gtpu_same_outer_tuple_different_inner_flows.pcap")));
        const auto rows = session.list_flows();
        const auto* first_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            10021U,
            "10.60.0.20",
            443U
        );
        const auto* second_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            10022U,
            "10.60.0.20",
            443U
        );
        PFL_EXPECT(first_flow != nullptr);
        PFL_EXPECT(second_flow != nullptr);
        if (first_flow != nullptr) {
            PFL_EXPECT(first_flow->packet_count == 1U);
        }
        if (second_flow != nullptr) {
            PFL_EXPECT(second_flow->packet_count == 1U);
        }
    }

    expect_inner_flow_present(
        "parsing/gtpu/13_gtpu_outer_ipv6_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        1U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/15_gtpu_teid_boundary_values.pcap")));
        const auto rows = session.list_flows();
        const auto* first_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            49660U,
            "10.60.0.20",
            443U
        );
        const auto* second_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.11",
            10021U,
            "10.60.0.21",
            443U
        );
        PFL_EXPECT(first_flow != nullptr);
        PFL_EXPECT(second_flow != nullptr);
    }

    expect_inner_flow_present(
        "parsing/gtpu/16_gtpu_with_sequence_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/17_gtpu_with_npdu_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/18_gtpu_with_extension_header_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        1U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap")));
        const auto rows = session.list_flows();
        const auto* flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            49660U,
            "10.60.0.20",
            443U
        );
        PFL_EXPECT(flow != nullptr);
        if (flow != nullptr) {
            PFL_EXPECT(flow->packet_count == 2U);
        }
        // Known branch limitation: TEID is not yet part of flow identity, so
        // identical inner tuples from different TEIDs may merge into one flow.
    }
}

}  // namespace

void run_gtpu_pcap_fixture_tests() {
    run_gtpu_positive_fixture_tests();

    expect_inner_flow_absent(
        "parsing/gtpu/05_gtpu_truncated_base_header.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/06_gtpu_invalid_version.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/07_gtpu_unsupported_message_type.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/08_gtpu_truncated_inner_ipv4.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/09_gtpu_truncated_inner_ipv6.pcap",
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0060:0000:0000:0000:0000:0010",
        49660U,
        "2001:0db8:0060:0000:0000:0000:0000:0020",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/10_gtpu_unknown_inner_payload.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/14_gtpu_wrong_udp_port_valid_gtpu_payload.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/19_gtpu_truncated_optional_header.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/20_gtpu_truncated_extension_header.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_gtpu_warning_packet_details(
        "parsing/gtpu/05_gtpu_truncated_base_header.pcap",
        {"GTP-U", "malformed"},
        {"Available Header Bytes: 6 / 8", "Warning: GTP-U header is truncated."},
        true,
        false,
        false,
        false,
        false
    );

    expect_gtpu_warning_packet_details(
        "parsing/gtpu/06_gtpu_invalid_version.pcap",
        {"GTP-U", "invalid"},
        {"Flags: 0x", "Version 2", "Warning: GTP-U version is not supported."},
        true,
        false,
        false,
        false,
        false
    );

    expect_gtpu_warning_packet_details(
        "parsing/gtpu/07_gtpu_unsupported_message_type.pcap",
        {"GTP-U", "unsupported message type"},
        {"Message Type: Echo Request (0x01)", "Warning: GTP-U message type is not supported."},
        true,
        false,
        false,
        false,
        false
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/07_gtpu_unsupported_message_type.pcap")));
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
        const auto* gtpu_layer = find_layer(summary_layers, "gtpu");
        PFL_REQUIRE(gtpu_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "Message Type", "Echo Request (0x01)"));
    }

    expect_gtpu_warning_packet_details(
        "parsing/gtpu/08_gtpu_truncated_inner_ipv4.pcap",
        {"GTP-U", "0x01020304"},
        {"Inner Payload: IPv4", "Inner IPv4: TCP", "Warning: Inner IPv4 packet is truncated."},
        false,
        true,
        false,
        false,
        false
    );

    expect_gtpu_warning_packet_details(
        "parsing/gtpu/09_gtpu_truncated_inner_ipv6.pcap",
        {"GTP-U", "0x01020304"},
        {"Inner Payload: IPv6", "Inner IPv6: TCP", "Warning: Inner IPv6 packet is truncated."},
        false,
        false,
        true,
        false,
        false
    );

    expect_gtpu_warning_packet_details(
        "parsing/gtpu/10_gtpu_unknown_inner_payload.pcap",
        {"GTP-U", "unknown inner payload"},
        {"Inner Payload: Unknown", "Warning: GTP-U inner payload type is not supported."},
        true,
        false,
        false,
        false,
        false
    );

    expect_gtpu_warning_packet_details(
        "parsing/gtpu/19_gtpu_truncated_optional_header.pcap",
        {"GTP-U", "malformed"},
        {"Warning: GTP-U optional header is truncated."},
        true,
        false,
        false,
        false,
        false
    );

    expect_gtpu_warning_packet_details(
        "parsing/gtpu/20_gtpu_truncated_extension_header.pcap",
        {"GTP-U", "malformed"},
        {"Next Extension Header Type: MBMS Support Indication (0x01)", "Warning: GTP-U extension header chain is truncated."},
        true,
        false,
        false,
        false,
        false
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/20_gtpu_truncated_extension_header.pcap")));
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
        const auto* gtpu_layer = find_layer(summary_layers, "gtpu");
        PFL_REQUIRE(gtpu_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(
            *gtpu_layer,
            "Next Extension Header Type",
            "MBMS Support Indication (0x01)"
        ));
    }

    expect_gtpu_packet_details_present(
        "parsing/gtpu/01_gtpu_inner_ipv4_tcp.pcap",
        0U,
        0x01020304U,
        "ipv4-inner",
        "tcp-inner",
        "10.60.0.10",
        "10.60.0.20",
        "49660",
        "443"
    );

    expect_gtpu_packet_details_present(
        "parsing/gtpu/02_gtpu_inner_ipv4_udp.pcap",
        0U,
        0x01020304U,
        "ipv4-inner",
        "udp-inner",
        "10.60.0.10",
        "10.60.0.20",
        "53760",
        "443"
    );

    expect_gtpu_packet_details_present(
        "parsing/gtpu/03_gtpu_inner_ipv6_tcp.pcap",
        0U,
        0x01020304U,
        "ipv6-inner",
        "tcp-inner",
        "2001:0db8:0060:0000:0000:0000:0000:0010",
        "2001:0db8:0060:0000:0000:0000:0000:0020",
        "49660",
        "443"
    );

    expect_gtpu_packet_details_present(
        "parsing/gtpu/04_gtpu_inner_ipv6_udp.pcap",
        0U,
        0x01020304U,
        "ipv6-inner",
        "udp-inner",
        "2001:0db8:0060:0000:0000:0000:0000:0010",
        "2001:0db8:0060:0000:0000:0000:0000:0020",
        "53760",
        "443"
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/15_gtpu_teid_boundary_values.pcap")));

        const auto first_packet = session.find_packet(0U);
        PFL_REQUIRE(first_packet.has_value());
        const auto first_details = session.read_packet_details(*first_packet);
        PFL_REQUIRE(first_details.has_value());
        PFL_EXPECT(first_details->has_gtpu);
        PFL_EXPECT(first_details->gtpu.teid == 0U);
        const auto first_layers = session_detail::build_packet_summary_layers(*first_details, *first_packet);
        const auto* first_gtpu_layer = find_layer(first_layers, "gtpu");
        PFL_REQUIRE(first_gtpu_layer != nullptr);
        PFL_EXPECT(title_contains_all(*first_gtpu_layer, {"GTP-U", "0x00000000"}));

        const auto second_packet = session.find_packet(1U);
        PFL_REQUIRE(second_packet.has_value());
        const auto second_details = session.read_packet_details(*second_packet);
        PFL_REQUIRE(second_details.has_value());
        PFL_EXPECT(second_details->has_gtpu);
        PFL_EXPECT(second_details->gtpu.teid == 0xFFFFFFFFU);
        const auto second_layers = session_detail::build_packet_summary_layers(*second_details, *second_packet);
        const auto* second_gtpu_layer = find_layer(second_layers, "gtpu");
        PFL_REQUIRE(second_gtpu_layer != nullptr);
        PFL_EXPECT(title_contains_all(*second_gtpu_layer, {"GTP-U", "0xffffffff"}));
    }

    expect_gtpu_packet_details_present(
        "parsing/gtpu/16_gtpu_with_sequence_inner_ipv4_tcp.pcap",
        0U,
        0x01020304U,
        "ipv4-inner",
        "tcp-inner",
        "10.60.0.10",
        "10.60.0.20",
        "49660",
        "443"
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/16_gtpu_with_sequence_inner_ipv4_tcp.pcap")));
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_gtpu);
        PFL_EXPECT(details->gtpu.sequence_number_flag_set);
        PFL_EXPECT(details->gtpu.sequence_number_present);
        PFL_EXPECT(details->gtpu.sequence_number == 0x1234U);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
        const auto* gtpu_layer = find_layer(summary_layers, "gtpu");
        PFL_REQUIRE(gtpu_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "S Flag", "Set"));
        PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "Sequence Number", "0x1234"));
    }

    expect_gtpu_packet_details_present(
        "parsing/gtpu/17_gtpu_with_npdu_inner_ipv4_tcp.pcap",
        0U,
        0x01020304U,
        "ipv4-inner",
        "tcp-inner",
        "10.60.0.10",
        "10.60.0.20",
        "49660",
        "443"
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/17_gtpu_with_npdu_inner_ipv4_tcp.pcap")));
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_gtpu);
        PFL_EXPECT(details->gtpu.npdu_number_flag_set);
        PFL_EXPECT(details->gtpu.npdu_number_present);
        PFL_EXPECT(details->gtpu.npdu_number == 0x5AU);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
        const auto* gtpu_layer = find_layer(summary_layers, "gtpu");
        PFL_REQUIRE(gtpu_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "PN Flag", "Set"));
        PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "N-PDU Number", "0x5a"));
    }

    expect_gtpu_packet_details_present(
        "parsing/gtpu/18_gtpu_with_extension_header_inner_ipv4_tcp.pcap",
        0U,
        0x01020304U,
        "ipv4-inner",
        "tcp-inner",
        "10.60.0.10",
        "10.60.0.20",
        "49660",
        "443"
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/18_gtpu_with_extension_header_inner_ipv4_tcp.pcap")));
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_gtpu);
        PFL_EXPECT(details->gtpu.extension_header_flag_set);
        PFL_EXPECT(details->gtpu.next_extension_header_type_present);
        PFL_EXPECT(details->gtpu.next_extension_header_type == 0x85U);
        PFL_EXPECT(details->gtpu.extension_headers_skipped_bytes == 4U);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
        const auto* gtpu_layer = find_layer(summary_layers, "gtpu");
        PFL_REQUIRE(gtpu_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "E Flag", "Set"));
        PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "Next Extension Header Type", "PDU Session Container (0x85)"));
        PFL_EXPECT(layer_has_field_containing(*gtpu_layer, "Extension Headers Skipped", "4 bytes"));
        const auto protocol_text = session.read_packet_protocol_details_text(*packet);
        PFL_EXPECT(protocol_text.find("Next Extension Header Type: PDU Session Container (0x85)") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/14_gtpu_wrong_udp_port_valid_gtpu_payload.pcap")));
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(!details->has_gtpu);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
        PFL_EXPECT(find_layer(summary_layers, "gtpu") == nullptr);
        const auto protocol_text = session.read_packet_protocol_details_text(*packet);
        PFL_EXPECT(protocol_text.find("GTP-U") == std::string::npos);
    }
}

}  // namespace pfl::tests
