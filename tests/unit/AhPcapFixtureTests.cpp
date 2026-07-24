#include <algorithm>
#include <array>
#include <initializer_list>
#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "PcapTestUtils.h"
#include "TestSupport.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/ProtocolPath.h"

namespace pfl::tests {

namespace {

struct AhFixtureExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
    std::uint64_t expected_flow_count;
    std::string_view expected_protocol_text;
    std::string_view expected_protocol_path;
};

constexpr std::array<AhFixtureExpectation, 20> kAhFixtureExpectations {{
    {"01_ipv4_ah_tcp.pcap", 1U, 1U, "TCP", "EthernetII -> IPv4 -> AH(spi=0x11111111) -> TCP"},
    {"02_ipv4_ah_udp.pcap", 1U, 1U, "UDP", "EthernetII -> IPv4 -> AH(spi=0x11111111) -> UDP"},
    {"03_ipv6_ah_tcp.pcap", 1U, 1U, "TCP", "EthernetII -> IPv6 -> AH(spi=0x11111111) -> TCP"},
    {"04_ipv6_ah_udp.pcap", 1U, 1U, "UDP", "EthernetII -> IPv6 -> AH(spi=0x11111111) -> UDP"},
    {"05_ipv4_ah_same_tuple_different_spi.pcap", 2U, 2U, "TCP", ""},
    {"06_ipv4_ah_same_spi_two_packets.pcap", 2U, 1U, "UDP", "EthernetII -> IPv4 -> AH(spi=0x11111111) -> UDP"},
    {"07_ipv6_ah_same_tuple_different_spi.pcap", 2U, 2U, "UDP", ""},
    {"08_ipv4_ah_same_spi_different_sequence.pcap", 2U, 1U, "TCP", "EthernetII -> IPv4 -> AH(spi=0x11111111) -> TCP"},
    {"09_outer_vlan_ipv4_ah_udp.pcap", 1U, 1U, "UDP", "EthernetII -> VLAN(vid=770) -> IPv4 -> AH(spi=0x11111111) -> UDP"},
    {"10_outer_qinq_ipv4_ah_tcp.pcap", 1U, 1U, "TCP", "EthernetII -> VLAN(vid=771) -> VLAN(vid=772) -> IPv4 -> AH(spi=0x11111111) -> TCP"},
    {"11_ipv6_hop_by_hop_ah_udp.pcap", 1U, 1U, "UDP", "EthernetII -> IPv6 -> AH(spi=0x11111111) -> UDP"},
    {"12_ipv4_ah_inner_ipv4_udp.pcap", 1U, 1U, "UDP", "EthernetII -> IPv4 -> AH(spi=0x11111111) -> IPv4 -> UDP"},
    {"13_ipv4_ah_inner_ipv6_tcp.pcap", 1U, 1U, "TCP", "EthernetII -> IPv4 -> AH(spi=0x11111111) -> IPv6 -> TCP"},
    {"14_ipv6_ah_inner_ipv4_udp.pcap", 1U, 1U, "UDP", "EthernetII -> IPv6 -> AH(spi=0x11111111) -> IPv4 -> UDP"},
    {"15_ipv6_ah_inner_ipv6_tcp.pcap", 1U, 1U, "TCP", "EthernetII -> IPv6 -> AH(spi=0x11111111) -> IPv6 -> TCP"},
    {"16_ah_truncated_fixed_header.pcap", 1U, 0U, "", ""},
    {"17_ah_invalid_payload_length_too_small.pcap", 1U, 0U, "", ""},
    {"18_ah_payload_length_exceeds_packet.pcap", 1U, 0U, "", ""},
    {"19_ah_truncated_icv.pcap", 1U, 0U, "", ""},
    {"20_ah_unsupported_next_header.pcap", 1U, 0U, "", ""},
}};

constexpr std::array<std::string_view, 15> kSupportedAhFixturesNow {{
    "01_ipv4_ah_tcp.pcap",
    "02_ipv4_ah_udp.pcap",
    "03_ipv6_ah_tcp.pcap",
    "04_ipv6_ah_udp.pcap",
    "05_ipv4_ah_same_tuple_different_spi.pcap",
    "06_ipv4_ah_same_spi_two_packets.pcap",
    "07_ipv6_ah_same_tuple_different_spi.pcap",
    "08_ipv4_ah_same_spi_different_sequence.pcap",
    "09_outer_vlan_ipv4_ah_udp.pcap",
    "10_outer_qinq_ipv4_ah_tcp.pcap",
    "11_ipv6_hop_by_hop_ah_udp.pcap",
    "12_ipv4_ah_inner_ipv4_udp.pcap",
    "13_ipv4_ah_inner_ipv6_tcp.pcap",
    "14_ipv6_ah_inner_ipv4_udp.pcap",
    "15_ipv6_ah_inner_ipv6_tcp.pcap",
}};

constexpr std::array<std::string_view, 5> kMalformedOrUnsupportedAhFixturesNow {{
    "16_ah_truncated_fixed_header.pcap",
    "17_ah_invalid_payload_length_too_small.pcap",
    "18_ah_payload_length_exceeds_packet.pcap",
    "19_ah_truncated_icv.pcap",
    "20_ah_unsupported_next_header.pcap",
}};

std::filesystem::path fixture_dir() {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "ah";
}

std::filesystem::path fixture_path(std::string_view file_name) {
    return fixture_dir() / std::filesystem::path(file_name);
}

std::vector<std::uint8_t> make_ipv4_ah_udp_packet_with_payload(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> bytes {
        0x02, 0x00, 0x00, 0x00, 0x70, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x70, 0x01,
        0x08, 0x00,
        0x45, 0x00,
    };

    append_be16(bytes, static_cast<std::uint16_t>(20U + 24U + 8U + payload.size()));
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    bytes.push_back(64U);
    bytes.push_back(51U);
    append_be16(bytes, 0U);
    append_be32(bytes, ipv4(192, 0, 2, 70));
    append_be32(bytes, ipv4(198, 51, 100, 70));

    bytes.push_back(17U);
    bytes.push_back(4U);
    append_be16(bytes, 0U);
    append_be32(bytes, 0x11111111U);
    append_be32(bytes, 1U);
    bytes.insert(bytes.end(), {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab
    });

    append_be16(bytes, 53700U);
    append_be16(bytes, 443U);
    append_be16(bytes, static_cast<std::uint16_t>(8U + payload.size()));
    append_be16(bytes, 0U);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::filesystem::path make_truncated_ah_udp_payload_capture() {
    const auto full_packet = make_ipv4_ah_udp_packet_with_payload({
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b
    });
    auto captured_packet = full_packet;
    captured_packet.resize(full_packet.size() - 8U);

    return write_temp_pcap(
        "pfl_ah_truncated_udp_payload.pcap",
        make_classic_pcap_with_captured_lengths({
            {
                .ts_usec = 100U,
                .captured_bytes = captured_packet,
                .original_length = static_cast<std::uint32_t>(full_packet.size()),
            },
        })
    );
}

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto& expectation : kAhFixtureExpectations) {
        names.emplace(expectation.file_name);
    }
    return names;
}

std::set<std::string> actual_fixture_file_names() {
    std::set<std::string> names {};
    if (!std::filesystem::exists(fixture_dir())) {
        return names;
    }

    for (const auto& entry : std::filesystem::directory_iterator(fixture_dir())) {
        if (!entry.is_regular_file()) {
            continue;
        }
        if (entry.path().extension() == ".pcap") {
            names.emplace(entry.path().filename().string());
        }
    }
    return names;
}

const AhFixtureExpectation& require_expectation(std::string_view file_name) {
    const auto found = std::find_if(kAhFixtureExpectations.begin(), kAhFixtureExpectations.end(), [&](const auto& expectation) {
        return expectation.file_name == file_name;
    });
    PFL_REQUIRE(found != kAhFixtureExpectations.end());
    return *found;
}

std::optional<std::string> protocol_path_text_for_row(
    const CaptureSession& session,
    const FlowRow& row
) {
    if (row.protocol_path_id == kInvalidProtocolPathId) {
        return std::nullopt;
    }

    const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
    if (path == nullptr) {
        return std::nullopt;
    }

    return format_protocol_path(*path);
}

bool row_protocol_path_contains_all(
    const CaptureSession& session,
    const FlowRow& row,
    std::initializer_list<std::string_view> fragments
) {
    const auto path_text = protocol_path_text_for_row(session, row);
    if (!path_text.has_value()) {
        return false;
    }

    return std::all_of(fragments.begin(), fragments.end(), [&](const auto fragment) {
        return path_text->find(fragment) != std::string::npos;
    });
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
    return std::any_of(layer.fields.begin(), layer.fields.end(), [&](const auto& field) {
        return field.label == label && field.value.find(fragment) != std::string::npos;
    });
}

const session_detail::PacketSummaryField* find_summary_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto found = std::find_if(layer.fields.begin(), layer.fields.end(), [&](const auto& field) {
        return field.label == label;
    });
    return found != layer.fields.end() ? &*found : nullptr;
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

void expect_ah_expectation_filenames_are_unique() {
    PFL_EXPECT(expected_fixture_file_names().size() == kAhFixtureExpectations.size());
}

void expect_ah_fixture_files_exist() {
    for (const auto& expectation : kAhFixtureExpectations) {
        PFL_EXPECT(std::filesystem::exists(fixture_path(expectation.file_name)));
    }
}

void expect_ah_expectation_table_covers_all_fixtures() {
    PFL_EXPECT(expected_fixture_file_names() == actual_fixture_file_names());
}

void expect_ah_fixtures_import_without_crash() {
    for (const auto& expectation : kAhFixtureExpectations) {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path(expectation.file_name)));
    }
}

void expect_ah_fixtures_have_expected_total_packets_and_accounting() {
    for (const auto& expectation : kAhFixtureExpectations) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.total_packets_seen == storage.recognized_packets + storage.unrecognized_packets);
    }
}

void expect_supported_ah_fixtures_decode() {
    for (const auto fixture_name : kSupportedAhFixturesNow) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
        PFL_EXPECT(storage.unrecognized_packets == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == static_cast<std::size_t>(expectation.expected_flow_count));

        if (expectation.expected_flow_count == 1U) {
            PFL_REQUIRE(rows.size() == 1U);
            PFL_EXPECT(rows[0].protocol_text == expectation.expected_protocol_text);
            PFL_EXPECT(rows[0].protocol_path_id != kInvalidProtocolPathId);
        } else if (!expectation.expected_protocol_text.empty()) {
            PFL_EXPECT(std::all_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
                return row.protocol_text == expectation.expected_protocol_text;
            }));
        }
    }
}

void expect_outer_qinq_ah_path_decodes() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("10_outer_qinq_ipv4_ah_tcp.pcap")));
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].protocol_text == "TCP");
    PFL_REQUIRE(rows[0].protocol_path_id != kInvalidProtocolPathId);
    PFL_EXPECT(row_protocol_path_contains_all(session, rows[0], {
        "EthernetII",
        "VLAN(vid=771)",
        "VLAN(vid=772)",
        "IPv4",
        "AH(spi=0x11111111)",
        "TCP",
    }));
}

void expect_wrapped_ah_paths_have_valid_identity() {
    struct WrappedCase {
        std::string_view file_name;
        std::string_view expected_protocol_text;
    };

    constexpr std::array<WrappedCase, 2> cases {{
        {"09_outer_vlan_ipv4_ah_udp.pcap", "UDP"},
        {"11_ipv6_hop_by_hop_ah_udp.pcap", "UDP"},
    }};

    for (const auto& test_case : cases) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_text == test_case.expected_protocol_text);
        PFL_REQUIRE(rows[0].protocol_path_id != kInvalidProtocolPathId);
        PFL_EXPECT(row_protocol_path_contains_all(session, rows[0], {
            "AH(spi=0x11111111)",
            test_case.expected_protocol_text,
        }));
    }
}

void expect_ah_spi_splits_identity() {
    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("05_ipv4_ah_same_tuple_different_spi.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return row_protocol_path_contains_all(session, row, {"IPv4", "AH(spi=0x11111111)", "TCP"});
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return row_protocol_path_contains_all(session, row, {"IPv4", "AH(spi=0x22222222)", "TCP"});
        }));
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("07_ipv6_ah_same_tuple_different_spi.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return row_protocol_path_contains_all(session, row, {"IPv6", "AH(spi=0x11111111)", "UDP"});
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return row_protocol_path_contains_all(session, row, {"IPv6", "AH(spi=0x22222222)", "UDP"});
        }));
    }
}

void expect_ah_tunnel_mode_fixtures_decode_and_present_inner_transport() {
    struct TunnelCase {
        std::string_view file_name;
        std::string_view expected_protocol_text;
        std::string_view expected_path_text;
        std::string expected_outer_layer_id;
        std::string expected_inner_layer_id;
        std::string expected_inner_transport_layer_id;
        std::string expected_next_header_fragment;
        std::string expected_inner_heading;
        std::string expected_source_address;
        std::string expected_destination_address;
        std::uint16_t expected_src_port;
        std::uint16_t expected_dst_port;
    };

    const std::array<TunnelCase, 4> cases {{
        {
            "12_ipv4_ah_inner_ipv4_udp.pcap",
            "UDP",
            "EthernetII -> IPv4 -> AH(spi=0x11111111) -> IPv4 -> UDP",
            "ipv4",
            "ipv4-inner",
            "udp-inner",
            "IPv4 (4)",
            "Inner IPv4:",
            "10.70.0.10",
            "10.70.0.20",
            53700U,
            443U,
        },
        {
            "13_ipv4_ah_inner_ipv6_tcp.pcap",
            "TCP",
            "EthernetII -> IPv4 -> AH(spi=0x11111111) -> IPv6 -> TCP",
            "ipv4",
            "ipv6-inner",
            "tcp-inner",
            "IPv6 (41)",
            "Inner IPv6:",
            "2001:0db8:0071:0000:0000:0000:0000:0010",
            "2001:0db8:0071:0000:0000:0000:0000:0020",
            49170U,
            443U,
        },
        {
            "14_ipv6_ah_inner_ipv4_udp.pcap",
            "UDP",
            "EthernetII -> IPv6 -> AH(spi=0x11111111) -> IPv4 -> UDP",
            "ipv6",
            "ipv4-inner",
            "udp-inner",
            "IPv4 (4)",
            "Inner IPv4:",
            "10.70.0.10",
            "10.70.0.20",
            53700U,
            443U,
        },
        {
            "15_ipv6_ah_inner_ipv6_tcp.pcap",
            "TCP",
            "EthernetII -> IPv6 -> AH(spi=0x11111111) -> IPv6 -> TCP",
            "ipv6",
            "ipv6-inner",
            "tcp-inner",
            "IPv6 (41)",
            "Inner IPv6:",
            "2001:0db8:0071:0000:0000:0000:0000:0010",
            "2001:0db8:0071:0000:0000:0000:0000:0020",
            49170U,
            443U,
        },
    }};

    for (const auto& test_case : cases) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == 1U);
        PFL_EXPECT(storage.recognized_packets == 1U);
        PFL_EXPECT(storage.unrecognized_packets == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_text == test_case.expected_protocol_text);
        const auto path_text = protocol_path_text_for_row(session, rows[0]);
        PFL_REQUIRE(path_text.has_value());
        PFL_EXPECT(*path_text == test_case.expected_path_text);

        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_ah);
        PFL_REQUIRE(details->ah.has_inner_packet);
        PFL_REQUIRE(details->ah.inner_packet != nullptr);
        PFL_EXPECT(!details->has_tcp);
        PFL_EXPECT(!details->has_udp);

        const auto layers = session_detail::build_packet_summary_layers(*details, *packet);
        const auto* outer_layer = find_top_level_layer(layers, test_case.expected_outer_layer_id);
        const auto* ah_layer = find_top_level_layer(layers, "ah");
        const auto* inner_network_layer = find_top_level_layer(layers, test_case.expected_inner_layer_id);
        const auto* inner_transport_layer = find_top_level_layer(layers, test_case.expected_inner_transport_layer_id);
        PFL_REQUIRE(outer_layer != nullptr);
        PFL_REQUIRE(ah_layer != nullptr);
        PFL_REQUIRE(inner_network_layer != nullptr);
        PFL_REQUIRE(inner_transport_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*ah_layer, "Next Header", test_case.expected_next_header_fragment));
        PFL_EXPECT(layer_has_field_containing(
            *ah_layer,
            "Inner Payload",
            test_case.expected_inner_layer_id == "ipv4-inner" ? "IPv4" : "IPv6"
        ));

        const auto outer_index = find_top_level_layer_index(layers, test_case.expected_outer_layer_id);
        const auto ah_index = find_top_level_layer_index(layers, "ah");
        const auto inner_network_index = find_top_level_layer_index(layers, test_case.expected_inner_layer_id);
        const auto inner_transport_index = find_top_level_layer_index(layers, test_case.expected_inner_transport_layer_id);
        PFL_REQUIRE(outer_index < layers.size());
        PFL_REQUIRE(ah_index < layers.size());
        PFL_REQUIRE(inner_network_index < layers.size());
        PFL_REQUIRE(inner_transport_index < layers.size());
        PFL_EXPECT(outer_index < ah_index);
        PFL_EXPECT(ah_index < inner_network_index);
        PFL_EXPECT(inner_network_index < inner_transport_index);

        PFL_EXPECT(inner_network_layer->title.find(test_case.expected_source_address) != std::string::npos);
        PFL_EXPECT(inner_network_layer->title.find(test_case.expected_destination_address) != std::string::npos);
        PFL_EXPECT(inner_transport_layer->title.find(std::to_string(test_case.expected_src_port)) != std::string::npos);
        PFL_EXPECT(inner_transport_layer->title.find(std::to_string(test_case.expected_dst_port)) != std::string::npos);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {});
        PFL_EXPECT(protocol_text.find("Protocol: AH") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Next Header: " + test_case.expected_next_header_fragment) != std::string::npos);
        PFL_EXPECT(protocol_text.find(test_case.expected_inner_heading) != std::string::npos);
        PFL_EXPECT(protocol_text.find("Source Address: " + test_case.expected_source_address) != std::string::npos);
        PFL_EXPECT(protocol_text.find("Destination Address: " + test_case.expected_destination_address) != std::string::npos);
        PFL_EXPECT(protocol_text.find("Source Port: " + std::to_string(test_case.expected_src_port)) != std::string::npos);
        PFL_EXPECT(protocol_text.find("Destination Port: " + std::to_string(test_case.expected_dst_port)) != std::string::npos);
        if (test_case.expected_inner_transport_layer_id == "udp-inner") {
            PFL_EXPECT(protocol_text.find("Payload Length: 4 bytes") != std::string::npos);
        } else {
            PFL_EXPECT(protocol_text.find("Payload Length: 0 bytes") != std::string::npos);
        }
    }
}

void expect_malformed_or_unsupported_ah_fixtures_remain_conservative() {
    for (const auto fixture_name : kMalformedOrUnsupportedAhFixturesNow) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == 1U);
        PFL_EXPECT(storage.recognized_packets == 0U);
        PFL_EXPECT(storage.unrecognized_packets == 1U);
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    }
}

void expect_direct_ah_packet_details_summary_and_protocol_text() {
    struct PositiveCase {
        std::string_view file_name;
        std::string expected_network_layer_id;
        std::string expected_transport_layer_id;
        std::string expected_network_title_fragment;
        std::string expected_transport_title_fragment;
        std::string expected_next_header_fragment;
        std::string expected_protocol_text_fragment;
    };

    const std::array<PositiveCase, 5> cases {{
        {"01_ipv4_ah_tcp.pcap", "ipv4", "tcp", "IPv4", "TCP", "TCP (6)", "Protocol: AH"},
        {"02_ipv4_ah_udp.pcap", "ipv4", "udp", "IPv4", "UDP", "UDP (17)", "Protocol: AH"},
        {"03_ipv6_ah_tcp.pcap", "ipv6", "tcp", "IPv6", "TCP", "TCP (6)", "Protocol: AH"},
        {"04_ipv6_ah_udp.pcap", "ipv6", "udp", "IPv6", "UDP", "UDP (17)", "Protocol: AH"},
        {"11_ipv6_hop_by_hop_ah_udp.pcap", "ipv6", "udp", "IPv6", "UDP", "UDP (17)", "Protocol: AH"},
    }};

    for (const auto& test_case : cases) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);

        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_ah);

        const auto layers = session_detail::build_packet_summary_layers(*details, *packet);
        const auto* ah_layer = find_top_level_layer(layers, "ah");
        const auto* network_layer = find_top_level_layer(layers, test_case.expected_network_layer_id);
        const auto* transport_layer = find_top_level_layer(layers, test_case.expected_transport_layer_id);
        PFL_REQUIRE(ah_layer != nullptr);
        PFL_REQUIRE(network_layer != nullptr);
        PFL_REQUIRE(transport_layer != nullptr);

        PFL_EXPECT(title_contains_all(*ah_layer, {"AH", "SPI: 0x11111111"}));
        PFL_EXPECT(layer_has_field_containing(*ah_layer, "Next Header", test_case.expected_next_header_fragment));
        PFL_EXPECT(layer_has_field_containing(*ah_layer, "Payload Length", "4"));
        PFL_EXPECT(layer_has_field_containing(*ah_layer, "SPI", "0x11111111"));
        PFL_EXPECT(layer_has_field_containing(*ah_layer, "Sequence Number", "0x00000001"));
        PFL_EXPECT(layer_has_field_containing(*ah_layer, "Header Length", "24 bytes"));
        PFL_EXPECT(layer_has_field_containing(*ah_layer, "ICV Length", "12 bytes"));

        const auto network_index = find_top_level_layer_index(layers, test_case.expected_network_layer_id);
        const auto ah_index = find_top_level_layer_index(layers, "ah");
        const auto transport_index = find_top_level_layer_index(layers, test_case.expected_transport_layer_id);
        PFL_REQUIRE(network_index < layers.size());
        PFL_REQUIRE(ah_index < layers.size());
        PFL_REQUIRE(transport_index < layers.size());
        PFL_EXPECT(network_index < ah_index);
        PFL_EXPECT(ah_index < transport_index);

        PFL_EXPECT(network_layer->title.find(test_case.expected_network_title_fragment) != std::string::npos);
        PFL_EXPECT(transport_layer->title.find(test_case.expected_transport_title_fragment) != std::string::npos);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {});
        PFL_EXPECT(protocol_text.find(test_case.expected_protocol_text_fragment) != std::string::npos);
        PFL_EXPECT(protocol_text.find("Next Header: " + test_case.expected_next_header_fragment) != std::string::npos);
        PFL_EXPECT(protocol_text.find("Payload Length: 4") != std::string::npos);
        PFL_EXPECT(protocol_text.find("SPI: 0x11111111") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Sequence Number: 0x00000001 (1)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Header Length: 24 bytes") != std::string::npos);
        PFL_EXPECT(protocol_text.find("ICV Length: 12 bytes") != std::string::npos);
    }
}

void expect_ah_effective_packet_payload_lengths_follow_terminal_transport() {
    struct PayloadCase {
        std::string_view file_name;
        std::uint32_t expected_payload_length;
        bool expect_syn_flag {false};
    };

    const std::array<PayloadCase, 8> cases {{
        {"01_ipv4_ah_tcp.pcap", 0U, true},
        {"02_ipv4_ah_udp.pcap", 4U, false},
        {"03_ipv6_ah_tcp.pcap", 0U, false},
        {"04_ipv6_ah_udp.pcap", 4U, false},
        {"12_ipv4_ah_inner_ipv4_udp.pcap", 4U, false},
        {"13_ipv4_ah_inner_ipv6_tcp.pcap", 0U, false},
        {"14_ipv6_ah_inner_ipv4_udp.pcap", 4U, false},
        {"15_ipv6_ah_inner_ipv6_tcp.pcap", 0U, false},
    }};

    for (const auto& test_case : cases) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));

        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        PFL_EXPECT(packet->payload_length == test_case.expected_payload_length);

        const auto captured_payload_length =
            session_detail::derive_captured_transport_payload_length_from_headers(session, *packet);
        PFL_REQUIRE(captured_payload_length.has_value());
        PFL_EXPECT(*captured_payload_length == test_case.expected_payload_length);

        const auto original_payload_length =
            session_detail::derive_original_transport_payload_length_from_headers(session, *packet);
        PFL_REQUIRE(original_payload_length.has_value());
        PFL_EXPECT(*original_payload_length == test_case.expected_payload_length);

        const auto raw_rows = session.list_flow_packets(0U);
        PFL_REQUIRE(raw_rows.size() == 1U);
        PFL_EXPECT(raw_rows[0].payload_length == test_case.expected_payload_length);

        auto enriched_rows = raw_rows;
        session_detail::apply_original_transport_payload_lengths(session, enriched_rows);
        PFL_REQUIRE(enriched_rows.size() == 1U);
        PFL_EXPECT(enriched_rows[0].payload_length == test_case.expected_payload_length);

        if (test_case.expect_syn_flag) {
            PFL_EXPECT(enriched_rows[0].tcp_flags_text.find("SYN") != std::string::npos);
        }
    }
}

void expect_ah_selected_packet_summary_payload_lengths() {
    struct DirectCase {
        std::string_view file_name;
        std::string transport_layer_id;
        std::uint32_t expected_payload_length;
        std::optional<std::uint32_t> expected_captured_frame_length {};
        bool expect_syn_flag {false};
    };

    const std::array<DirectCase, 6> cases {{
        {"01_ipv4_ah_tcp.pcap", "tcp", 0U, std::nullopt, true},
        {"02_ipv4_ah_udp.pcap", "udp", 4U, std::nullopt, false},
        {"03_ipv6_ah_tcp.pcap", "tcp", 0U, std::nullopt, false},
        {"04_ipv6_ah_udp.pcap", "udp", 4U, std::nullopt, false},
        {"09_outer_vlan_ipv4_ah_udp.pcap", "udp", 4U, std::nullopt, false},
        {"10_outer_qinq_ipv4_ah_tcp.pcap", "tcp", 0U, 86U, true},
    }};

    for (const auto& test_case : cases) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));

        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_ah);

        const auto original_payload_length =
            session_detail::derive_original_transport_payload_length_from_headers(session, *packet);
        PFL_REQUIRE(original_payload_length.has_value());
        PFL_EXPECT(*original_payload_length == test_case.expected_payload_length);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet, {
            .source_capture_accessible = true,
            .transport_payload_length = std::optional<std::uint32_t> {packet->payload_length},
            .original_transport_payload_length = original_payload_length,
            .protocol_details_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {}),
        });

        const auto* frame_layer = find_top_level_layer(summary_layers, "frame");
        const auto* transport_layer = find_top_level_layer(summary_layers, test_case.transport_layer_id);
        const auto* ah_layer = find_top_level_layer(summary_layers, "ah");
        PFL_REQUIRE(frame_layer != nullptr);
        PFL_REQUIRE(transport_layer != nullptr);
        PFL_REQUIRE(ah_layer != nullptr);

        if (test_case.expected_captured_frame_length.has_value()) {
            const auto* captured_length_field = find_summary_field(*frame_layer, "Captured Length");
            PFL_REQUIRE(captured_length_field != nullptr);
            PFL_EXPECT(captured_length_field->value == std::to_string(*test_case.expected_captured_frame_length) + " bytes");
        }

        const auto* payload_length_field = find_summary_field(*transport_layer, "Payload Length");
        const auto* captured_payload_length_field = find_summary_field(*transport_layer, "Captured Payload Length");
        const auto* original_payload_length_field = find_summary_field(*transport_layer, "Original Payload Length");
        PFL_REQUIRE(payload_length_field != nullptr);
        PFL_EXPECT(payload_length_field->value == std::to_string(test_case.expected_payload_length) + " bytes");
        PFL_EXPECT(captured_payload_length_field == nullptr);
        PFL_EXPECT(original_payload_length_field == nullptr);

        PFL_EXPECT(layer_has_field_containing(*ah_layer, "Payload Length", "4"));
        PFL_EXPECT(layer_has_field_containing(*ah_layer, "Header Length", "24 bytes"));

        if (test_case.expect_syn_flag) {
            PFL_EXPECT(layer_has_field_containing(*transport_layer, "Flags", "SYN"));
        }
    }
}

void expect_ah_tunnel_mode_selected_packet_effective_payload_lengths() {
    struct TunnelCase {
        std::string_view file_name;
        std::string transport_layer_id;
        std::uint32_t expected_payload_length;
        bool expect_tcp {false};
        bool expect_udp {false};
    };

    const std::array<TunnelCase, 4> cases {{
        {"12_ipv4_ah_inner_ipv4_udp.pcap", "udp-inner", 4U, false, true},
        {"13_ipv4_ah_inner_ipv6_tcp.pcap", "tcp-inner", 0U, true, false},
        {"14_ipv6_ah_inner_ipv4_udp.pcap", "udp-inner", 4U, false, true},
        {"15_ipv6_ah_inner_ipv6_tcp.pcap", "tcp-inner", 0U, true, false},
    }};

    for (const auto& test_case : cases) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));

        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_ah);
        PFL_REQUIRE(details->ah.has_inner_packet);
        PFL_REQUIRE(details->ah.inner_packet != nullptr);

        const auto original_payload_length =
            session_detail::derive_original_transport_payload_length_from_headers(session, *packet);
        PFL_REQUIRE(original_payload_length.has_value());
        PFL_EXPECT(*original_payload_length == test_case.expected_payload_length);

        PFL_EXPECT(details->has_tcp == false);
        PFL_EXPECT(details->has_udp == false);
        PFL_EXPECT(details->ah.inner_packet->has_tcp == test_case.expect_tcp);
        PFL_EXPECT(details->ah.inner_packet->has_udp == test_case.expect_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet, {
            .source_capture_accessible = true,
            .transport_payload_length = std::optional<std::uint32_t> {packet->payload_length},
            .original_transport_payload_length = original_payload_length,
            .protocol_details_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {}),
        });
        const auto* inner_transport_layer = find_top_level_layer(summary_layers, test_case.transport_layer_id);
        PFL_REQUIRE(inner_transport_layer != nullptr);
        const auto* payload_length_field = find_summary_field(*inner_transport_layer, "Payload Length");
        const auto* captured_payload_length_field = find_summary_field(*inner_transport_layer, "Captured Payload Length");
        const auto* original_payload_length_field = find_summary_field(*inner_transport_layer, "Original Payload Length");
        PFL_REQUIRE(payload_length_field != nullptr);
        PFL_EXPECT(payload_length_field->value == std::to_string(test_case.expected_payload_length) + " bytes");
        PFL_EXPECT(captured_payload_length_field == nullptr);
        PFL_EXPECT(original_payload_length_field == nullptr);
    }
}

void expect_conservative_ah_packet_details_for_malformed_or_unsupported_cases() {
    struct NegativeCase {
        std::string_view file_name;
        std::vector<std::string> required_summary_fragments;
        std::vector<std::string> required_protocol_fragments;
        std::vector<std::string> forbidden_protocol_fragments;
    };

    const std::array<NegativeCase, 5> cases {{
        {
            "16_ah_truncated_fixed_header.pcap",
            {"AH", "malformed"},
            {"Protocol: AH", "Available Header Bytes: 10 / ", "Warning: AH header is truncated."},
            {}
        },
        {
            "17_ah_invalid_payload_length_too_small.pcap",
            {"AH", "malformed"},
            {"Protocol: AH", "Next Header: TCP (6)", "Payload Length: 0", "Header Length: 8 bytes", "Warning: AH computed header length is invalid."},
            {"Warning: AH next header is not supported.", "Protocol: TCP", "Source Port:"}
        },
        {
            "18_ah_payload_length_exceeds_packet.pcap",
            {"AH", "malformed"},
            {"Protocol: AH", "Available Header Bytes: 36 / 40", "Warning: AH header is truncated."},
            {}
        },
        {
            "19_ah_truncated_icv.pcap",
            {"AH", "malformed"},
            {
                "Protocol: AH",
                "Next Header: UDP (17)",
                "Payload Length: 4",
                "SPI: 0x11111111",
                "Sequence Number: 0x00000001 (1)",
                "Header Length: 24 bytes",
                "Required Fixed Header Bytes: 12",
                "ICV Length: 12 bytes",
                "Available Header Bytes: 20 / 24",
                "Available ICV Bytes: 8 / 12",
                "Warning: AH header is truncated."
            },
            {"Protocol: UDP", "Source Port:"}
        },
        {
            "20_ah_unsupported_next_header.pcap",
            {"AH", "unsupported next header"},
            {"Protocol: AH", "Next Header: 99", "Warning: AH next header is not supported."},
            {}
        },
    }};

    for (const auto& test_case : cases) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));
        PFL_REQUIRE(session.unrecognized_packet_count() == 1U);

        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        const auto packet = session.find_packet(rows[0].packet_index);
        PFL_REQUIRE(packet.has_value());

        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        if (details->has_ah) {
            const auto layers = session_detail::build_packet_summary_layers(*details, *packet);
            if (test_case.file_name == "17_ah_invalid_payload_length_too_small.pcap") {
                PFL_EXPECT(details->ah.malformed);
                PFL_EXPECT(!details->ah.truncated);
                PFL_EXPECT(details->ah.header_length == 8U);
                PFL_EXPECT(details->ah.next_header == 6U);
                PFL_EXPECT(details->has_tcp == false);
                PFL_EXPECT(details->has_udp == false);
            }
            if (test_case.file_name == "19_ah_truncated_icv.pcap") {
                PFL_EXPECT(details->has_ipv6);
                PFL_EXPECT(details->ipv6.next_header == 51U);
                PFL_EXPECT(details->ipv6.payload_length == 20U);
                PFL_EXPECT(details->ah.truncated);
                PFL_EXPECT(!details->ah.malformed);
                PFL_EXPECT(details->ah.next_header == 17U);
                PFL_EXPECT(details->ah.payload_length == 4U);
                PFL_EXPECT(details->ah.header_length == 24U);
                PFL_EXPECT(details->ah.available_header_bytes == 20U);
                PFL_EXPECT(details->ah.icv_length == 12U);
                PFL_EXPECT(details->ah.available_icv_bytes == 8U);
                PFL_EXPECT(details->has_udp == false);
                const auto* ipv6_layer = find_top_level_layer(layers, "ipv6");
                PFL_REQUIRE(ipv6_layer != nullptr);
                PFL_EXPECT(layer_has_field_containing(*ipv6_layer, "Next Header", "AH (51)"));
                const auto frame_index = find_top_level_layer_index(layers, "frame");
                const auto ethernet_index = find_top_level_layer_index(layers, "ethernet");
                const auto* ah_layer_order = find_top_level_layer(layers, "ah");
                PFL_REQUIRE(ah_layer_order != nullptr);
                const auto ipv6_index = find_top_level_layer_index(layers, "ipv6");
                const auto ah_index = find_top_level_layer_index(layers, "ah");
                PFL_REQUIRE(frame_index < layers.size());
                PFL_REQUIRE(ethernet_index < layers.size());
                PFL_REQUIRE(ipv6_index < layers.size());
                PFL_REQUIRE(ah_index < layers.size());
                PFL_EXPECT(frame_index < ethernet_index);
                PFL_EXPECT(ethernet_index < ipv6_index);
                PFL_EXPECT(ipv6_index < ah_index);
                PFL_EXPECT(find_top_level_layer(layers, "udp") == nullptr);
                PFL_EXPECT(find_top_level_layer(layers, "udp-inner") == nullptr);
            }
            const auto* ah_layer = find_top_level_layer(layers, "ah");
            PFL_REQUIRE(ah_layer != nullptr);
            for (const auto& fragment : test_case.required_summary_fragments) {
                PFL_EXPECT(ah_layer->title.find(fragment) != std::string::npos);
            }
            if (test_case.file_name == "17_ah_invalid_payload_length_too_small.pcap") {
                PFL_EXPECT(layer_has_field_containing(*ah_layer, "Next Header", "TCP (6)"));
                PFL_EXPECT(!layer_has_field_containing(*ah_layer, "Warning", "AH next header is not supported"));
            }
            if (test_case.file_name == "19_ah_truncated_icv.pcap") {
                PFL_EXPECT(layer_has_field_containing(*ah_layer, "Next Header", "UDP (17)"));
                PFL_EXPECT(layer_has_field_containing(*ah_layer, "Required Fixed Header Bytes", "12"));
                PFL_EXPECT(layer_has_field_containing(*ah_layer, "Available ICV Bytes", "8 / 12"));
            }
        }

        const auto protocol_text = details->has_ah
            ? session_detail::build_basic_protocol_details_text(*details).value_or(std::string {})
            : session.read_packet_protocol_details_text(*packet);
        if (details->has_ah) {
            for (const auto& fragment : test_case.required_protocol_fragments) {
                PFL_EXPECT(protocol_text.find(fragment) != std::string::npos);
            }
            for (const auto& fragment : test_case.forbidden_protocol_fragments) {
                PFL_EXPECT(protocol_text.find(fragment) == std::string::npos);
            }
        } else {
            PFL_EXPECT(!protocol_text.empty());
        }
    }
}

void expect_truncated_ah_udp_preserves_captured_and_original_payload_lengths() {
    const auto capture_path = make_truncated_ah_udp_payload_capture();

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(capture_path));

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_text == "UDP");

        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        PFL_EXPECT(packet->payload_length == 4U);

        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_ah);
        PFL_REQUIRE(details->has_udp);

        const auto captured_payload_length =
            session_detail::derive_captured_transport_payload_length_from_headers(session, *packet);
        const auto original_payload_length =
            session_detail::derive_original_transport_payload_length_from_headers(session, *packet);
        PFL_REQUIRE(captured_payload_length.has_value());
        PFL_REQUIRE(original_payload_length.has_value());
        PFL_EXPECT(*captured_payload_length == 4U);
        PFL_EXPECT(*original_payload_length == 12U);
        PFL_EXPECT(*captured_payload_length < *original_payload_length);

        const auto raw_rows = session.list_flow_packets(0U);
        PFL_REQUIRE(raw_rows.size() == 1U);
        PFL_EXPECT(raw_rows[0].payload_length == 4U);

        auto enriched_rows = raw_rows;
        session_detail::apply_original_transport_payload_lengths(session, enriched_rows);
        PFL_REQUIRE(enriched_rows.size() == 1U);
        PFL_EXPECT(enriched_rows[0].payload_length == 12U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet, {
            .source_capture_accessible = true,
            .transport_payload_length = captured_payload_length,
            .original_transport_payload_length = original_payload_length,
            .protocol_details_text = session.read_packet_protocol_details_text(*packet),
        });
        const auto* udp_layer = find_top_level_layer(summary_layers, "udp");
        PFL_REQUIRE(udp_layer != nullptr);
        PFL_EXPECT(find_summary_field(*udp_layer, "Payload Length") == nullptr);
        const auto* captured_payload_field = find_summary_field(*udp_layer, "Captured Payload Length");
        const auto* original_payload_field = find_summary_field(*udp_layer, "Original Payload Length");
        PFL_REQUIRE(captured_payload_field != nullptr);
        PFL_REQUIRE(original_payload_field != nullptr);
        PFL_EXPECT(captured_payload_field->value == "4 bytes");
        PFL_EXPECT(original_payload_field->value == "12 bytes");
    }

    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(capture_path);
    PFL_REQUIRE(open_result.opened);

    const auto frontend_flows = adapter.get_flows();
    PFL_REQUIRE(frontend_flows.size() == 1U);
    const auto selection = adapter.select_flow(frontend_flows[0].flow_index);
    PFL_REQUIRE(selection.selected);

    const auto frontend_packets = adapter.get_selected_flow_packets(0U, 4U);
    PFL_REQUIRE(frontend_packets.packets.size() == 1U);
    const auto frontend_details = adapter.get_selected_flow_packet_details(
        frontend_packets.packets[0].packet_index,
        frontend_packets.packets[0].row_number
    );
    PFL_REQUIRE(frontend_details.details_available);
    PFL_EXPECT(frontend_details.payload_length == 4U);

    const auto* frontend_udp_layer = find_top_level_layer(frontend_details.summary_layers, "udp");
    PFL_REQUIRE(frontend_udp_layer != nullptr);
    const auto* frontend_captured_payload_field =
        find_summary_field(*frontend_udp_layer, "Captured Payload Length");
    const auto* frontend_original_payload_field =
        find_summary_field(*frontend_udp_layer, "Original Payload Length");
    PFL_REQUIRE(frontend_captured_payload_field != nullptr);
    PFL_REQUIRE(frontend_original_payload_field != nullptr);
    PFL_EXPECT(frontend_captured_payload_field->value == "4 bytes");
    PFL_EXPECT(frontend_original_payload_field->value == "12 bytes");
}

}  // namespace

void run_ah_pcap_fixture_tests() {
    expect_ah_expectation_filenames_are_unique();
    expect_ah_fixture_files_exist();
    expect_ah_expectation_table_covers_all_fixtures();
    expect_ah_fixtures_import_without_crash();
    expect_ah_fixtures_have_expected_total_packets_and_accounting();
    expect_supported_ah_fixtures_decode();
    expect_outer_qinq_ah_path_decodes();
    expect_wrapped_ah_paths_have_valid_identity();
    expect_ah_spi_splits_identity();
    expect_ah_tunnel_mode_fixtures_decode_and_present_inner_transport();
    expect_malformed_or_unsupported_ah_fixtures_remain_conservative();
    expect_direct_ah_packet_details_summary_and_protocol_text();
    expect_ah_effective_packet_payload_lengths_follow_terminal_transport();
    expect_ah_selected_packet_summary_payload_lengths();
    expect_ah_tunnel_mode_selected_packet_effective_payload_lengths();
    expect_conservative_ah_packet_details_for_malformed_or_unsupported_cases();
    expect_truncated_ah_udp_preserves_captured_and_original_payload_lengths();
}

}  // namespace pfl::tests

