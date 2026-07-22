#include <algorithm>
#include <array>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/ProtocolPath.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

const ProtocolPath* require_protocol_path(const CaptureSession& session, const ProtocolPathId protocol_path_id) {
    PFL_REQUIRE(protocol_path_id != kInvalidProtocolPathId);
    const auto* path = session.state().protocol_path_registry.find(protocol_path_id);
    PFL_REQUIRE(path != nullptr);
    return path;
}

std::string require_flow_protocol_path_text(const CaptureSession& session, const FlowRow& row) {
    return format_protocol_path(*require_protocol_path(session, row.protocol_path_id));
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    return *packet;
}

constexpr std::array<std::string_view, 31> kExpectedGtpuFixtureFiles {{
    "01_gtpu_inner_ipv4_tcp.pcap",
    "02_gtpu_inner_ipv4_udp.pcap",
    "03_gtpu_inner_ipv6_tcp.pcap",
    "04_gtpu_inner_ipv6_udp.pcap",
    "05_gtpu_truncated_base_header.pcap",
    "06_gtpu_invalid_version.pcap",
    "07_gtpu_unsupported_message_type.pcap",
    "08_gtpu_truncated_inner_ipv4.pcap",
    "09_gtpu_truncated_inner_ipv6.pcap",
    "10_gtpu_unknown_inner_payload.pcap",
    "11_gtpu_inner_ipv4_tcp_bidirectional.pcap",
    "12_gtpu_same_outer_tuple_different_inner_flows.pcap",
    "13_gtpu_outer_ipv6_inner_ipv4_tcp.pcap",
    "14_gtpu_wrong_udp_port_valid_gtpu_payload.pcap",
    "15_gtpu_teid_boundary_values.pcap",
    "16_gtpu_with_sequence_inner_ipv4_tcp.pcap",
    "17_gtpu_with_npdu_inner_ipv4_tcp.pcap",
    "18_gtpu_with_extension_header_inner_ipv4_tcp.pcap",
    "19_gtpu_truncated_optional_header.pcap",
    "20_gtpu_truncated_extension_header.pcap",
    "21_gtpu_same_inner_tuple_different_teid.pcap",
    "22_gtpu_udp_port_direction_matrix.pcap",
    "23_gtpu_control_message_matrix.pcap",
    "24_gtpu_flag_matrix_inner_ipv4_tcp.pcap",
    "25_gtpu_outer_tagged_contexts.pcap",
    "26_gtpu_outer_ipv6_inner_ipv6_udp.pcap",
    "27_gtpu_linux_sll_inner_ipv4_udp.pcap",
    "28_gtpu_linux_sll2_inner_ipv6_tcp.pcap",
    "29_gtpu_nested_overlay_udp_terminal.pcap",
    "30_gtpu_outer_ipv4_fragmentation.pcap",
    "31_gtpu_outer_ipv6_fragmentation.pcap",
}};

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto file_name : kExpectedGtpuFixtureFiles) {
        names.emplace(file_name);
    }
    return names;
}

std::set<std::string> actual_fixture_file_names() {
    std::set<std::string> names {};
    const auto dir = fixture_path("parsing/gtpu");
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        if (entry.path().extension() == ".pcap") {
            names.emplace(entry.path().filename().string());
        }
    }
    return names;
}

void expect_gtpu_fixture_directory_matches_contract() {
    PFL_EXPECT(actual_fixture_file_names() == expected_fixture_file_names());
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

const FlowRow* require_flow_by_tuple(
    const std::vector<FlowRow>& rows,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    const auto* row = find_flow_by_tuple(rows, family, protocol, address_a, port_a, address_b, port_b);
    PFL_REQUIRE(row != nullptr);
    return row;
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

void expect_outer_udp_flow(
    const CaptureSession& session,
    const std::vector<FlowRow>& rows,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b,
    const std::uint64_t expected_packet_count,
    const std::string& expected_protocol_path
) {
    const auto* row = require_flow_by_tuple(
        rows,
        FlowAddressFamily::ipv4,
        "UDP",
        address_a,
        port_a,
        address_b,
        port_b
    );
    PFL_EXPECT(row->packet_count == expected_packet_count);
    PFL_EXPECT(require_flow_protocol_path_text(session, *row) == expected_protocol_path);
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

void run_gtpu_supported_inner_flow_tests() {
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
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/12_gtpu_same_outer_tuple_different_inner_flows.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/12_gtpu_same_outer_tuple_different_inner_flows.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

        const auto* first_flow = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            10021U,
            "10.60.0.20",
            443U
        );
        PFL_EXPECT(first_flow->packet_count == 1U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *first_flow) ==
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP");

        const auto* second_flow = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            10022U,
            "10.60.0.20",
            443U
        );
        PFL_EXPECT(second_flow->packet_count == 1U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *second_flow) ==
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/15_gtpu_teid_boundary_values.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/15_gtpu_teid_boundary_values.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);

        const auto* first_flow = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            49660U,
            "10.60.0.20",
            443U
        );
        PFL_EXPECT(require_flow_protocol_path_text(session, *first_flow) ==
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x00000000) -> IPv4 -> TCP");

        const auto* second_flow = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.11",
            10021U,
            "10.60.0.21",
            443U
        );
        PFL_EXPECT(require_flow_protocol_path_text(session, *second_flow) ==
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0xffffffff) -> IPv4 -> TCP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);
        PFL_EXPECT(std::all_of(rows.begin(), rows.end(), [](const FlowRow& row) {
            return row.family == FlowAddressFamily::ipv4 &&
                row.protocol_text == "TCP" &&
                row.address_a == "10.60.0.10" &&
                row.port_a == 49660U &&
                row.address_b == "10.60.0.20" &&
                row.port_b == 443U &&
                row.packet_count == 1U;
        }));

        std::set<std::string> observed_paths {};
        for (const auto& row : rows) {
            observed_paths.emplace(require_flow_protocol_path_text(session, row));
        }
        const std::set<std::string> expected_paths {
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP",
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x11223344) -> IPv4 -> TCP",
        };
        PFL_EXPECT(observed_paths == expected_paths);
    }
}

void run_gtpu_port_and_header_matrix_tests() {
    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/22_gtpu_udp_port_direction_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/22_gtpu_udp_port_direction_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);

        expect_outer_udp_flow(
            session,
            rows,
            "203.0.113.60",
            2152U,
            "203.0.113.61",
            55024U,
            1U,
            "EthernetII -> IPv4 -> UDP"
        );

        const auto* inner_tcp = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            49660U,
            "10.60.0.20",
            443U
        );
        PFL_EXPECT(inner_tcp->packet_count == 1U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *inner_tcp) ==
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP");

        const auto packet0 = require_packet(session, 0U);
        const auto packet0_details = session.read_packet_details(packet0);
        PFL_REQUIRE(packet0_details.has_value());
        PFL_EXPECT(packet0_details->has_udp);
        PFL_EXPECT(!packet0_details->has_gtpu);

        const auto packet1 = require_packet(session, 1U);
        const auto packet1_details = session.read_packet_details(packet1);
        PFL_REQUIRE(packet1_details.has_value());
        PFL_EXPECT(packet1_details->has_gtpu);
        PFL_EXPECT(packet1_details->gtpu.teid == 0x01020304U);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/24_gtpu_flag_matrix_inner_ipv4_tcp.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/24_gtpu_flag_matrix_inner_ipv4_tcp.pcap")));
        PFL_EXPECT(session.summary().packet_count == 6U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);

        expect_outer_udp_flow(
            session,
            rows,
            "203.0.113.60",
            55040U,
            "203.0.113.61",
            2152U,
            1U,
            "EthernetII -> IPv4 -> UDP"
        );

        const auto* inner_tcp = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            49660U,
            "10.60.0.20",
            443U
        );
        PFL_EXPECT(inner_tcp->packet_count == 5U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *inner_tcp) ==
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP");

        const auto packet0 = require_packet(session, 0U);
        const auto pt_clear = session.read_packet_details(packet0);
        PFL_REQUIRE(pt_clear.has_value());
        PFL_EXPECT(pt_clear->has_gtpu);
        PFL_EXPECT(!pt_clear->gtpu.protocol_type_flag_set);
        PFL_EXPECT(!pt_clear->gtpu.has_inner_packet);
        PFL_EXPECT(session.read_packet_protocol_details_text(packet0).find(
            "Warning: GTP-U PT flag is not set") != std::string::npos);

        const auto packet1 = require_packet(session, 1U);
        const auto reserved_bit_set = session.read_packet_details(packet1);
        PFL_REQUIRE(reserved_bit_set.has_value());
        PFL_EXPECT(reserved_bit_set->has_gtpu);
        PFL_EXPECT(reserved_bit_set->gtpu.flags == 0x38U);
        PFL_EXPECT(reserved_bit_set->gtpu.has_inner_packet);

        const auto packet2 = require_packet(session, 2U);
        const auto s_and_pn = session.read_packet_details(packet2);
        PFL_REQUIRE(s_and_pn.has_value());
        PFL_EXPECT(s_and_pn->has_gtpu);
        PFL_EXPECT(s_and_pn->gtpu.sequence_number_flag_set);
        PFL_EXPECT(s_and_pn->gtpu.npdu_number_flag_set);
        PFL_EXPECT(!s_and_pn->gtpu.extension_header_flag_set);
        PFL_EXPECT(s_and_pn->gtpu.sequence_number == 0x1235U);
        PFL_EXPECT(s_and_pn->gtpu.npdu_number == 0x5BU);

        const auto packet3 = require_packet(session, 3U);
        const auto s_and_e = session.read_packet_details(packet3);
        PFL_REQUIRE(s_and_e.has_value());
        PFL_EXPECT(s_and_e->has_gtpu);
        PFL_EXPECT(s_and_e->gtpu.sequence_number_flag_set);
        PFL_EXPECT(!s_and_e->gtpu.npdu_number_flag_set);
        PFL_EXPECT(s_and_e->gtpu.extension_header_flag_set);
        PFL_EXPECT(s_and_e->gtpu.next_extension_header_type == 0x85U);
        PFL_EXPECT(s_and_e->gtpu.extension_headers_skipped_bytes == 4U);

        const auto packet4 = require_packet(session, 4U);
        const auto pn_and_e = session.read_packet_details(packet4);
        PFL_REQUIRE(pn_and_e.has_value());
        PFL_EXPECT(pn_and_e->has_gtpu);
        PFL_EXPECT(!pn_and_e->gtpu.sequence_number_flag_set);
        PFL_EXPECT(pn_and_e->gtpu.npdu_number_flag_set);
        PFL_EXPECT(pn_and_e->gtpu.extension_header_flag_set);
        PFL_EXPECT(pn_and_e->gtpu.npdu_number == 0x5CU);
        PFL_EXPECT(pn_and_e->gtpu.extension_headers_skipped_bytes == 4U);

        const auto packet5 = require_packet(session, 5U);
        const auto s_pn_e = session.read_packet_details(packet5);
        PFL_REQUIRE(s_pn_e.has_value());
        PFL_EXPECT(s_pn_e->has_gtpu);
        PFL_EXPECT(s_pn_e->gtpu.sequence_number_flag_set);
        PFL_EXPECT(s_pn_e->gtpu.npdu_number_flag_set);
        PFL_EXPECT(s_pn_e->gtpu.extension_header_flag_set);
        PFL_EXPECT(s_pn_e->gtpu.sequence_number == 0x1237U);
        PFL_EXPECT(s_pn_e->gtpu.npdu_number == 0x5DU);
        PFL_EXPECT(s_pn_e->gtpu.next_extension_header_type == 0x85U);
    }
}

void run_gtpu_outer_carrier_and_nested_flow_tests() {
    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/25_gtpu_outer_tagged_contexts.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/25_gtpu_outer_tagged_contexts.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 3U);

        std::set<std::string> observed_paths {};
        for (const auto& row : rows) {
            PFL_EXPECT(row.packet_count == 1U);
            observed_paths.emplace(require_flow_protocol_path_text(session, row));
        }
        const std::set<std::string> expected_paths {
            "EthernetII -> VLAN(vid=201) -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP",
            "EthernetII -> VLAN(vid=551) -> VLAN(vid=552) -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP",
            "EthernetII -> VLAN(vid=701) -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP",
        };
        PFL_EXPECT(observed_paths == expected_paths);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/26_gtpu_outer_ipv6_inner_ipv6_udp.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/26_gtpu_outer_ipv6_inner_ipv6_udp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv6,
            "UDP",
            "2001:0db8:0060:0000:0000:0000:0000:0010",
            53760U,
            "2001:0db8:0060:0000:0000:0000:0000:0020",
            443U
        );
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "EthernetII -> IPv6 -> UDP -> GTP-U(teid=0x01020324) -> IPv6 -> UDP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/27_gtpu_linux_sll_inner_ipv4_udp.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/27_gtpu_linux_sll_inner_ipv4_udp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "UDP",
            "10.60.0.10",
            53760U,
            "10.60.0.20",
            443U
        );
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "LinuxSll -> IPv4 -> UDP -> GTP-U(teid=0x01020354) -> IPv4 -> UDP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/28_gtpu_linux_sll2_inner_ipv6_tcp.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/28_gtpu_linux_sll2_inner_ipv6_tcp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv6,
            "TCP",
            "2001:0db8:0060:0000:0000:0000:0000:0010",
            49660U,
            "2001:0db8:0060:0000:0000:0000:0000:0020",
            443U
        );
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "LinuxSll2 -> IPv6 -> UDP -> GTP-U(teid=0x01020364) -> IPv6 -> TCP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/29_gtpu_nested_overlay_udp_terminal.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/29_gtpu_nested_overlay_udp_terminal.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 3U);

        const auto* gtpu_like = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "UDP",
            "10.60.0.10",
            53760U,
            "10.60.0.20",
            2152U
        );
        PFL_EXPECT(require_flow_protocol_path_text(session, *gtpu_like) ==
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020374) -> IPv4 -> UDP");

        const auto* vxlan_like = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "UDP",
            "10.60.0.10",
            53760U,
            "10.60.0.20",
            4789U
        );
        PFL_EXPECT(require_flow_protocol_path_text(session, *vxlan_like) ==
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020375) -> IPv4 -> UDP");

        const auto* geneve_like = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "UDP",
            "10.60.0.10",
            53760U,
            "10.60.0.20",
            6081U
        );
        PFL_EXPECT(require_flow_protocol_path_text(session, *geneve_like) ==
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020376) -> IPv4 -> UDP");
    }
}

void run_gtpu_outer_udp_fallback_tests() {
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

    struct OuterUdpFallbackExpectation {
        const char* fixture {};
        std::uint16_t src_port {0};
    };

    for (const auto& expectation : std::array<OuterUdpFallbackExpectation, 8> {{
            {"parsing/gtpu/05_gtpu_truncated_base_header.pcap", 55004U},
            {"parsing/gtpu/06_gtpu_invalid_version.pcap", 55005U},
            {"parsing/gtpu/07_gtpu_unsupported_message_type.pcap", 55006U},
            {"parsing/gtpu/08_gtpu_truncated_inner_ipv4.pcap", 55007U},
            {"parsing/gtpu/09_gtpu_truncated_inner_ipv6.pcap", 55008U},
            {"parsing/gtpu/10_gtpu_unknown_inner_payload.pcap", 55009U},
            {"parsing/gtpu/19_gtpu_truncated_optional_header.pcap", 55020U},
            {"parsing/gtpu/20_gtpu_truncated_extension_header.pcap", 55021U},
        }}) {
        const ScopedTestContext fixture_context {std::string {"fixture="} + expectation.fixture};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.fixture)));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        expect_outer_udp_flow(
            session,
            rows,
            "203.0.113.60",
            expectation.src_port,
            "203.0.113.61",
            2152U,
            1U,
            "EthernetII -> IPv4 -> UDP"
        );
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/14_gtpu_wrong_udp_port_valid_gtpu_payload.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/14_gtpu_wrong_udp_port_valid_gtpu_payload.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        expect_outer_udp_flow(
            session,
            rows,
            "203.0.113.60",
            55014U,
            "203.0.113.61",
            2162U,
            1U,
            "EthernetII -> IPv4 -> UDP"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(!details->has_gtpu);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(find_layer(summary_layers, "gtpu") == nullptr);
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("GTP-U") == std::string::npos);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/23_gtpu_control_message_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/23_gtpu_control_message_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 6U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 6U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

        const std::array<std::uint8_t, 6> message_types {{0x01U, 0x02U, 0x1AU, 0xFEU, 0x1FU, 0x7AU}};
        for (std::size_t index = 0U; index < message_types.size(); ++index) {
            const auto src_port = static_cast<std::uint16_t>(55030U + index);
            expect_outer_udp_flow(
                session,
                rows,
                "203.0.113.60",
                src_port,
                "203.0.113.61",
                2152U,
                1U,
                "EthernetII -> IPv4 -> UDP"
            );

            const auto packet = require_packet(session, static_cast<std::uint64_t>(index));
            const auto details = session.read_packet_details(packet);
            PFL_REQUIRE(details.has_value());
            PFL_EXPECT(details->has_gtpu);
            PFL_EXPECT(details->gtpu.message_type == message_types[index]);
            PFL_EXPECT(details->gtpu.unsupported_message_type);
            PFL_EXPECT(!details->gtpu.has_inner_packet);

            const auto protocol_text = session.read_packet_protocol_details_text(packet);
            PFL_EXPECT(protocol_text.find("Warning: GTP-U message type is not supported.") != std::string::npos);
            const auto expected_message_type_text = message_types[index] == 0x01U
                ? std::string {"Echo Request (0x01)"}
                : format_hex_value(message_types[index], 2);
            PFL_EXPECT(protocol_text.find("Message Type: " + expected_message_type_text) != std::string::npos);
        }
    }
}

void run_gtpu_fragmentation_contract_tests() {
    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/30_gtpu_outer_ipv4_fragmentation.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/30_gtpu_outer_ipv4_fragmentation.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 2U);
        PFL_EXPECT(rows[0].has_fragmented_packets);
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "EthernetII -> IPv4");
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(!details->has_gtpu);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/gtpu/31_gtpu_outer_ipv6_fragmentation.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/31_gtpu_outer_ipv6_fragmentation.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 2U);
        PFL_EXPECT(rows[0].has_fragmented_packets);
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "EthernetII -> IPv6");
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(!details->has_gtpu);
    }
}

void run_gtpu_packet_details_contract_tests() {
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

    expect_gtpu_packet_details_present(
        "parsing/gtpu/26_gtpu_outer_ipv6_inner_ipv6_udp.pcap",
        0U,
        0x01020324U,
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

        const auto first_packet = require_packet(session, 0U);
        const auto first_details = session.read_packet_details(first_packet);
        PFL_REQUIRE(first_details.has_value());
        PFL_EXPECT(first_details->has_gtpu);
        PFL_EXPECT(first_details->gtpu.teid == 0U);
        const auto first_layers = session_detail::build_packet_summary_layers(*first_details, first_packet);
        const auto* first_gtpu_layer = find_layer(first_layers, "gtpu");
        PFL_REQUIRE(first_gtpu_layer != nullptr);
        PFL_EXPECT(title_contains_all(*first_gtpu_layer, {"GTP-U", "0x00000000"}));

        const auto second_packet = require_packet(session, 1U);
        const auto second_details = session.read_packet_details(second_packet);
        PFL_REQUIRE(second_details.has_value());
        PFL_EXPECT(second_details->has_gtpu);
        PFL_EXPECT(second_details->gtpu.teid == 0xFFFFFFFFU);
        const auto second_layers = session_detail::build_packet_summary_layers(*second_details, second_packet);
        const auto* second_gtpu_layer = find_layer(second_layers, "gtpu");
        PFL_REQUIRE(second_gtpu_layer != nullptr);
        PFL_EXPECT(title_contains_all(*second_gtpu_layer, {"GTP-U", "0xffffffff"}));
    }
}

}  // namespace

void run_gtpu_pcap_fixture_tests() {
    expect_gtpu_fixture_directory_matches_contract();
    run_gtpu_supported_inner_flow_tests();
    run_gtpu_port_and_header_matrix_tests();
    run_gtpu_outer_carrier_and_nested_flow_tests();
    run_gtpu_outer_udp_fallback_tests();
    run_gtpu_fragmentation_contract_tests();
    run_gtpu_packet_details_contract_tests();
}

}  // namespace pfl::tests
