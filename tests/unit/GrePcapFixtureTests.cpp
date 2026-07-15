#include <algorithm>
#include <array>
#include <filesystem>
#include <initializer_list>
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

constexpr bool kEnableGreParserExpectationTests = false;

struct GreFixtureExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
    std::uint64_t expected_future_flow_count;
    std::string_view expected_future_protocol_path;
    bool is_positive_decode_fixture;
};

constexpr std::array<GreFixtureExpectation, 22> kGreFixtureExpectations {{
    {"01_gre_ipv4_tcp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv4 -> TCP", true},
    {"02_gre_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv4 -> UDP", true},
    {"03_gre_ipv6_tcp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv6 -> TCP", true},
    {"04_gre_ipv6_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv6 -> UDP", true},
    {"05_ipv6_outer_gre_ipv4_tcp.pcap", 1U, 1U, "EthernetII -> IPv6 -> GRE -> IPv4 -> TCP", true},
    {"06_ipv6_outer_gre_ipv6_udp.pcap", 1U, 1U, "EthernetII -> IPv6 -> GRE -> IPv6 -> UDP", true},
    {"07_gre_key_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP", true},
    {"08_gre_sequence_ipv4_tcp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv4 -> TCP", true},
    {"09_gre_checksum_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv4 -> UDP", true},
    {"10_gre_checksum_key_sequence_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP", true},
    {"11_gre_teb_ethernet_ipv4_tcp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> EthernetII -> IPv4 -> TCP", true},
    {"12_gre_teb_ethernet_vlan_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> EthernetII -> VLAN(vid=130) -> IPv4 -> UDP", true},
    {"13_outer_vlan_gre_ipv4_udp.pcap", 1U, 1U, "EthernetII -> VLAN(vid=330) -> IPv4 -> GRE -> IPv4 -> UDP", true},
    {"14_outer_qinq_gre_ipv4_tcp.pcap", 1U, 1U, "EthernetII -> VLAN(vid=331) -> VLAN(vid=330) -> IPv4 -> GRE -> IPv4 -> TCP", true},
    {"15_gre_mpls_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> MPLS(label=16030) -> IPv4 -> UDP", true},
    {"16_gre_unknown_protocol_type.pcap", 1U, 0U, "", false},
    {"17_gre_version1_pptp_like_unsupported.pcap", 1U, 0U, "", false},
    {"18_gre_truncated_base_header.pcap", 1U, 0U, "", false},
    {"19_gre_truncated_key_field.pcap", 1U, 0U, "", false},
    {"20_gre_truncated_inner_ipv4.pcap", 1U, 0U, "", false},
    {"21_gre_same_inner_tuple_different_keys.pcap", 2U, 2U, "", true},
    {"22_gre_same_inner_tuple_same_key_two_packets.pcap", 2U, 1U, "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP", true},
}};

constexpr std::array<std::string_view, 17> kSupportedGreFixturesNow {{
    "01_gre_ipv4_tcp.pcap",
    "02_gre_ipv4_udp.pcap",
    "03_gre_ipv6_tcp.pcap",
    "04_gre_ipv6_udp.pcap",
    "05_ipv6_outer_gre_ipv4_tcp.pcap",
    "06_ipv6_outer_gre_ipv6_udp.pcap",
    "07_gre_key_ipv4_udp.pcap",
    "08_gre_sequence_ipv4_tcp.pcap",
    "09_gre_checksum_ipv4_udp.pcap",
    "10_gre_checksum_key_sequence_ipv4_udp.pcap",
    "11_gre_teb_ethernet_ipv4_tcp.pcap",
    "12_gre_teb_ethernet_vlan_ipv4_udp.pcap",
    "13_outer_vlan_gre_ipv4_udp.pcap",
    "14_outer_qinq_gre_ipv4_tcp.pcap",
    "15_gre_mpls_ipv4_udp.pcap",
    "21_gre_same_inner_tuple_different_keys.pcap",
    "22_gre_same_inner_tuple_same_key_two_packets.pcap",
}};

constexpr std::array<std::string_view, 5> kUnsupportedGreFixturesNow {{
    "16_gre_unknown_protocol_type.pcap",
    "17_gre_version1_pptp_like_unsupported.pcap",
    "18_gre_truncated_base_header.pcap",
    "19_gre_truncated_key_field.pcap",
    "20_gre_truncated_inner_ipv4.pcap",
}};

std::filesystem::path fixture_dir() {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "gre";
}

std::filesystem::path fixture_path(std::string_view file_name) {
    return fixture_dir() / std::filesystem::path(file_name);
}

const GreFixtureExpectation& require_expectation(std::string_view file_name) {
    const auto found = std::find_if(kGreFixtureExpectations.begin(), kGreFixtureExpectations.end(), [&](const auto& expectation) {
        return expectation.file_name == file_name;
    });
    PFL_REQUIRE(found != kGreFixtureExpectations.end());
    return *found;
}

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto& expectation : kGreFixtureExpectations) {
        names.emplace(expectation.file_name);
    }
    return names;
}

std::set<std::string> actual_fixture_file_names() {
    std::set<std::string> names {};
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

void expect_gre_fixture_files_exist() {
    for (const auto& expectation : kGreFixtureExpectations) {
        PFL_EXPECT(std::filesystem::exists(fixture_path(expectation.file_name)));
    }
}

void expect_gre_future_expectation_table_covers_all_fixtures() {
    PFL_EXPECT(expected_fixture_file_names() == actual_fixture_file_names());
}

void expect_gre_fixtures_import_without_crash() {
    for (const auto& expectation : kGreFixtureExpectations) {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path(expectation.file_name)));
    }
}

void expect_gre_fixtures_have_expected_total_packet_records() {
    for (const auto& expectation : kGreFixtureExpectations) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.total_packets_seen == storage.recognized_packets + storage.unrecognized_packets);
    }
}

void expect_supported_gre_v0_ip_fixtures_decode() {
    for (const auto fixture_name : kSupportedGreFixturesNow) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
        PFL_EXPECT(storage.unrecognized_packets == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        PFL_EXPECT(session.summary().packet_count == expectation.expected_total_packets);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == static_cast<std::size_t>(expectation.expected_future_flow_count));

        if (fixture_name == "21_gre_same_inner_tuple_different_keys.pcap") {
            bool found_first_key = false;
            bool found_second_key = false;
            for (const auto& row : rows) {
                if (row.protocol_path_id == kInvalidProtocolPathId) {
                    continue;
                }
                const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
                if (path == nullptr) {
                    continue;
                }
                const auto formatted = format_protocol_path(*path);
                found_first_key = found_first_key || formatted == "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP";
                found_second_key = found_second_key || formatted == "EthernetII -> IPv4 -> GRE(key=0x22222222) -> IPv4 -> UDP";
            }
            PFL_EXPECT(found_first_key);
            PFL_EXPECT(found_second_key);
            continue;
        }

        const auto expected_path = require_expectation(fixture_name).expected_future_protocol_path;
        const bool found_expected_path = std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            if (row.protocol_path_id == kInvalidProtocolPathId) {
                return false;
            }
            const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
            return path != nullptr && format_protocol_path(*path) == expected_path;
        });
        PFL_EXPECT(found_expected_path);

        if (fixture_name == "22_gre_same_inner_tuple_same_key_two_packets.pcap") {
            PFL_REQUIRE(rows.size() == 1U);
            PFL_EXPECT(rows[0].packet_count == 2U);
        }
    }
}

void expect_unsupported_gre_payloads_remain_unrecognized() {
    for (const auto fixture_name : kUnsupportedGreFixturesNow) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets == 0U);
        PFL_EXPECT(storage.unrecognized_packets == expectation.expected_total_packets);
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == static_cast<std::size_t>(expectation.expected_total_packets));
    }
}

void expect_gre_truncated_fixtures_import_without_crash() {
    constexpr std::array<std::string_view, 3> truncated_fixtures {{
        "18_gre_truncated_base_header.pcap",
        "19_gre_truncated_key_field.pcap",
        "20_gre_truncated_inner_ipv4.pcap",
    }};

    for (const auto fixture_name : truncated_fixtures) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));
        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == 1U);
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    }
}

void expect_gre_direct_ip_packet_details_present(
    const std::filesystem::path& relative_path,
    const std::string& expected_inner_network_layer_id,
    const std::string& expected_inner_transport_layer_id,
    const std::string& expected_inner_source,
    const std::string& expected_inner_destination,
    const std::string& expected_inner_source_port,
    const std::string& expected_inner_destination_port,
    const std::string& expected_protocol_type_fragment,
    const bool expect_checksum,
    const bool expect_key,
    const bool expect_sequence,
    const std::string& expected_key_fragment = {},
    const std::string& expected_sequence_fragment = {}
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path.string())));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_gre);
    PFL_EXPECT(details->gre.present);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* gre_layer = find_layer(summary_layers, "gre");
    PFL_REQUIRE(gre_layer != nullptr);
    PFL_EXPECT(title_contains_all(*gre_layer, {"GRE"}));
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Protocol Type", expected_protocol_type_fragment));
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Checksum Present", expect_checksum ? "Yes" : "No"));
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Key Present", expect_key ? "Yes" : "No"));
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Sequence Present", expect_sequence ? "Yes" : "No"));
    PFL_EXPECT(gre_layer->children.empty());
    if (expect_checksum) {
        PFL_EXPECT(layer_has_field_label(*gre_layer, "Checksum"));
    }
    if (expect_key) {
        PFL_EXPECT(layer_has_field_label(*gre_layer, "Key"));
    }
    if (expect_sequence) {
        PFL_EXPECT(layer_has_field_label(*gre_layer, "Sequence Number"));
    }
    if (!expected_key_fragment.empty()) {
        PFL_EXPECT(layer_has_field_containing(*gre_layer, "Key", expected_key_fragment));
    }
    if (!expected_sequence_fragment.empty()) {
        PFL_EXPECT(layer_has_field_containing(*gre_layer, "Sequence Number", expected_sequence_fragment));
    }

    const auto* inner_network_layer = find_top_level_layer(summary_layers, expected_inner_network_layer_id);
    const auto* inner_transport_layer = find_top_level_layer(summary_layers, expected_inner_transport_layer_id);
    PFL_REQUIRE(inner_network_layer != nullptr);
    PFL_REQUIRE(inner_transport_layer != nullptr);

    const auto gre_index = find_top_level_layer_index(summary_layers, "gre");
    const auto inner_network_index = find_top_level_layer_index(summary_layers, expected_inner_network_layer_id);
    const auto inner_transport_index = find_top_level_layer_index(summary_layers, expected_inner_transport_layer_id);
    PFL_REQUIRE(gre_index < summary_layers.size());
    PFL_REQUIRE(inner_network_index < summary_layers.size());
    PFL_REQUIRE(inner_transport_index < summary_layers.size());
    PFL_EXPECT(gre_index < inner_network_index);
    PFL_EXPECT(inner_network_index < inner_transport_index);

    if (expected_inner_network_layer_id == "ipv4-inner") {
        PFL_EXPECT(title_contains_all(*inner_network_layer, {
            "Inner IPv4",
            expected_inner_source,
            expected_inner_destination,
        }));
    } else {
        PFL_EXPECT(title_contains_all(*inner_network_layer, {
            "Inner IPv6",
            expected_inner_source,
            expected_inner_destination,
        }));
    }

    if (expected_inner_transport_layer_id == "tcp-inner") {
        PFL_EXPECT(title_contains_all(*inner_transport_layer, {
            "Inner TCP",
            expected_inner_source_port,
            expected_inner_destination_port,
        }));
    } else {
        PFL_EXPECT(title_contains_all(*inner_transport_layer, {
            "Inner UDP",
            expected_inner_source_port,
            expected_inner_destination_port,
        }));
    }

    const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
    PFL_REQUIRE(protocol_text.has_value());
    PFL_EXPECT(protocol_text->find("Protocol: GRE") != std::string::npos);
    PFL_EXPECT(protocol_text->find("Protocol Type: " + expected_protocol_type_fragment) != std::string::npos);
    if (!expected_key_fragment.empty()) {
        PFL_EXPECT(protocol_text->find("Key: " + expected_key_fragment) != std::string::npos);
    }
    if (!expected_sequence_fragment.empty()) {
        PFL_EXPECT(protocol_text->find("Sequence Number: " + expected_sequence_fragment) != std::string::npos);
    }
}

void expect_gre_teb_packet_details_present(
    const std::filesystem::path& relative_path,
    const std::string& expected_inner_transport_layer_id,
    const bool expect_inner_vlan
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path.string())));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_gre);
    PFL_EXPECT(details->gre.has_inner_ethernet);
    PFL_EXPECT(details->has_inner_ethernet);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* gre_layer = find_layer(summary_layers, "gre");
    PFL_REQUIRE(gre_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Protocol Type", "Transparent Ethernet Bridging"));
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Inner Payload", "Ethernet"));

    const auto* inner_ethernet_layer = find_top_level_layer(summary_layers, "ethernet-inner");
    PFL_REQUIRE(inner_ethernet_layer != nullptr);
    PFL_EXPECT(title_contains_all(*inner_ethernet_layer, {
        "Inner Ethernet II",
        "02:00:00:00:31:01",
        "02:00:00:00:31:02",
    }));

    const auto gre_index = find_top_level_layer_index(summary_layers, "gre");
    const auto inner_ethernet_index = find_top_level_layer_index(summary_layers, "ethernet-inner");
    PFL_REQUIRE(gre_index < summary_layers.size());
    PFL_REQUIRE(inner_ethernet_index < summary_layers.size());
    PFL_EXPECT(gre_index < inner_ethernet_index);

    const auto* inner_network_layer = find_top_level_layer(summary_layers, "ipv4-inner");
    const auto inner_network_index = find_top_level_layer_index(summary_layers, "ipv4-inner");
    PFL_REQUIRE(inner_network_layer != nullptr);
    PFL_REQUIRE(inner_network_index < summary_layers.size());

    if (expect_inner_vlan) {
        const auto* inner_vlan_layer = find_top_level_layer(summary_layers, "vlan-inner");
        const auto inner_vlan_index = find_top_level_layer_index(summary_layers, "vlan-inner");
        PFL_REQUIRE(inner_vlan_layer != nullptr);
        PFL_REQUIRE(inner_vlan_index < summary_layers.size());
        PFL_EXPECT(title_contains_all(*inner_vlan_layer, {"Inner VLAN", "130"}));
        PFL_EXPECT(inner_ethernet_index < inner_vlan_index);
        PFL_EXPECT(inner_vlan_index < inner_network_index);
    } else {
        PFL_EXPECT(inner_ethernet_index < inner_network_index);
    }

    const auto* inner_transport_layer = find_top_level_layer(summary_layers, expected_inner_transport_layer_id);
    const auto inner_transport_index = find_top_level_layer_index(summary_layers, expected_inner_transport_layer_id);
    PFL_REQUIRE(inner_transport_layer != nullptr);
    PFL_REQUIRE(inner_transport_index < summary_layers.size());
    PFL_EXPECT(inner_network_index < inner_transport_index);

    const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
    PFL_REQUIRE(protocol_text.has_value());
    PFL_EXPECT(protocol_text->find("Inner Payload: Ethernet") != std::string::npos);
    PFL_EXPECT(protocol_text->find("Inner IPv4:") != std::string::npos);
}

void expect_gre_mpls_packet_details_present() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("15_gre_mpls_ipv4_udp.pcap")));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_gre);
    PFL_EXPECT(details->gre.has_inner_packet);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* gre_layer = find_layer(summary_layers, "gre");
    const auto* mpls_layer = find_top_level_layer(summary_layers, "mpls");
    const auto* inner_network_layer = find_top_level_layer(summary_layers, "ipv4-inner");
    const auto* inner_transport_layer = find_top_level_layer(summary_layers, "udp-inner");
    PFL_REQUIRE(gre_layer != nullptr);
    PFL_REQUIRE(mpls_layer != nullptr);
    PFL_REQUIRE(inner_network_layer != nullptr);
    PFL_REQUIRE(inner_transport_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Protocol Type", "MPLS Unicast"));
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Inner Payload", "MPLS"));
    PFL_EXPECT(title_contains_all(*mpls_layer, {"MPLS Label", "16030"}));

    const auto gre_index = find_top_level_layer_index(summary_layers, "gre");
    const auto mpls_index = find_top_level_layer_index(summary_layers, "mpls");
    const auto inner_network_index = find_top_level_layer_index(summary_layers, "ipv4-inner");
    const auto inner_transport_index = find_top_level_layer_index(summary_layers, "udp-inner");
    PFL_REQUIRE(gre_index < summary_layers.size());
    PFL_REQUIRE(mpls_index < summary_layers.size());
    PFL_REQUIRE(inner_network_index < summary_layers.size());
    PFL_REQUIRE(inner_transport_index < summary_layers.size());
    PFL_EXPECT(gre_index < mpls_index);
    PFL_EXPECT(mpls_index < inner_network_index);
    PFL_EXPECT(inner_network_index < inner_transport_index);

    const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
    PFL_REQUIRE(protocol_text.has_value());
    PFL_EXPECT(protocol_text->find("Inner Payload: MPLS") != std::string::npos);
    PFL_EXPECT(protocol_text->find("MPLS Top Label: 16030") != std::string::npos);
}

void expect_gre_warning_packet_details(
    const std::filesystem::path& relative_path,
    const std::initializer_list<std::string> expected_title_fragments,
    const std::initializer_list<std::string> expected_protocol_fragments,
    const std::initializer_list<std::string> forbidden_protocol_fragments = {},
    const bool expect_inner_network_layer = false,
    const bool expect_gre_layer_warning = true
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path.string())));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_gre);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* gre_layer = find_layer(summary_layers, "gre");
    PFL_REQUIRE(gre_layer != nullptr);
    PFL_EXPECT(title_contains_all(*gre_layer, expected_title_fragments));
    PFL_EXPECT(gre_layer->warning == expect_gre_layer_warning);

    const auto* inner_ipv4_layer = find_top_level_layer(summary_layers, "ipv4-inner");
    const auto* inner_ipv6_layer = find_top_level_layer(summary_layers, "ipv6-inner");
    if (expect_inner_network_layer) {
        PFL_EXPECT(inner_ipv4_layer != nullptr || inner_ipv6_layer != nullptr);
    } else {
        PFL_EXPECT(inner_ipv4_layer == nullptr);
        PFL_EXPECT(inner_ipv6_layer == nullptr);
    }

    const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
    PFL_REQUIRE(protocol_text.has_value());
    for (const auto& fragment : expected_protocol_fragments) {
        PFL_EXPECT(protocol_text->find(fragment) != std::string::npos);
    }
    for (const auto& fragment : forbidden_protocol_fragments) {
        PFL_EXPECT(protocol_text->find(fragment) == std::string::npos);
    }
}

void expect_gre_version1_packet_details_are_conservative() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("17_gre_version1_pptp_like_unsupported.pcap")));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_gre);
    PFL_EXPECT(details->gre.version == 1U);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* gre_layer = find_layer(summary_layers, "gre");
    PFL_REQUIRE(gre_layer != nullptr);
    PFL_EXPECT(title_contains_all(*gre_layer, {"GRE", "unsupported version"}));
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Protocol Type", "0x880b"));
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Payload Length", "4"));
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Call ID", "66"));
    PFL_EXPECT(layer_has_field_containing(*gre_layer, "Sequence Number", "0x01020304"));
    PFL_EXPECT(!layer_has_field_label(*gre_layer, "Key"));
    PFL_EXPECT(!layer_has_field_label(*gre_layer, "Key Present"));

    const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
    PFL_REQUIRE(protocol_text.has_value());
    PFL_EXPECT(protocol_text->find("Protocol: GRE") != std::string::npos);
    PFL_EXPECT(protocol_text->find("Version: 1") != std::string::npos);
    PFL_EXPECT(protocol_text->find("Protocol Type: 0x880b") != std::string::npos);
    PFL_EXPECT(protocol_text->find("Payload Length: 4") != std::string::npos);
    PFL_EXPECT(protocol_text->find("Call ID: 66") != std::string::npos);
    PFL_EXPECT(protocol_text->find("Sequence Number: 0x01020304") != std::string::npos);
    PFL_EXPECT(protocol_text->find("Warning: GRE version is not supported.") != std::string::npos);
    PFL_EXPECT(protocol_text->find("Key: ") == std::string::npos);
    PFL_EXPECT(protocol_text->find("Key Present: ") == std::string::npos);
}

void expect_gre_packet_details_summary_and_protocol_text() {
    expect_gre_direct_ip_packet_details_present(
        "01_gre_ipv4_tcp.pcap",
        "ipv4-inner",
        "tcp-inner",
        "10.30.0.10",
        "10.30.0.20",
        "49152",
        "443",
        "IPv4 (0x0800)",
        false,
        false,
        false
    );
    expect_gre_direct_ip_packet_details_present(
        "05_ipv6_outer_gre_ipv4_tcp.pcap",
        "ipv4-inner",
        "tcp-inner",
        "10.30.0.10",
        "10.30.0.20",
        "49152",
        "443",
        "IPv4 (0x0800)",
        false,
        false,
        false
    );
    expect_gre_direct_ip_packet_details_present(
        "07_gre_key_ipv4_udp.pcap",
        "ipv4-inner",
        "udp-inner",
        "10.30.0.10",
        "10.30.0.20",
        "53530",
        "443",
        "IPv4 (0x0800)",
        false,
        true,
        false,
        "0x11111111"
    );
    expect_gre_direct_ip_packet_details_present(
        "08_gre_sequence_ipv4_tcp.pcap",
        "ipv4-inner",
        "tcp-inner",
        "10.30.0.10",
        "10.30.0.20",
        "49152",
        "443",
        "IPv4 (0x0800)",
        false,
        false,
        true,
        {},
        "0x01020304"
    );
    expect_gre_direct_ip_packet_details_present(
        "09_gre_checksum_ipv4_udp.pcap",
        "ipv4-inner",
        "udp-inner",
        "10.30.0.10",
        "10.30.0.20",
        "53530",
        "443",
        "IPv4 (0x0800)",
        true,
        false,
        false
    );
    expect_gre_direct_ip_packet_details_present(
        "10_gre_checksum_key_sequence_ipv4_udp.pcap",
        "ipv4-inner",
        "udp-inner",
        "10.30.0.10",
        "10.30.0.20",
        "53530",
        "443",
        "IPv4 (0x0800)",
        true,
        true,
        true,
        "0x11111111"
    );
    expect_gre_teb_packet_details_present("11_gre_teb_ethernet_ipv4_tcp.pcap", "tcp-inner", false);
    expect_gre_teb_packet_details_present("12_gre_teb_ethernet_vlan_ipv4_udp.pcap", "udp-inner", true);
    expect_gre_mpls_packet_details_present();
}

void expect_gre_warning_packet_details_are_conservative() {
    expect_gre_warning_packet_details(
        "16_gre_unknown_protocol_type.pcap",
        {"GRE", "unsupported protocol type"},
        {"Protocol: GRE", "Warning: GRE protocol type is not supported."},
        {"Warning: GRE inner payload type is not supported."}
    );
    expect_gre_version1_packet_details_are_conservative();
    expect_gre_warning_packet_details(
        "18_gre_truncated_base_header.pcap",
        {"GRE", "malformed"},
        {"Protocol: GRE", "Warning: GRE base header is truncated."},
        {}
    );
    expect_gre_warning_packet_details(
        "19_gre_truncated_key_field.pcap",
        {"GRE", "malformed"},
        {"Protocol: GRE", "Warning: GRE optional fields are truncated."},
        {}
    );
    expect_gre_warning_packet_details(
        "20_gre_truncated_inner_ipv4.pcap",
        {"GRE"},
        {"Protocol: GRE", "Warning: Inner IPv4 packet is truncated."},
        {},
        true,
        false
    );
}

void run_future_gre_parser_expectation_tests() {
    // Keep this opt-in until the intentionally unsupported GRE cases in this fixture set
    // gain stronger positive expectations.
    for (const auto& expectation : kGreFixtureExpectations) {
        if (expectation.expected_future_flow_count == 0U) {
            continue;
        }

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == static_cast<std::size_t>(expectation.expected_future_flow_count));

        if (!expectation.expected_future_protocol_path.empty()) {
            const bool found_expected_path = std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
                if (row.protocol_path_id == kInvalidProtocolPathId) {
                    return false;
                }
                const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
                return path != nullptr && format_protocol_path(*path) == expectation.expected_future_protocol_path;
            });
            PFL_EXPECT(found_expected_path);
        }
    }
}

}  // namespace

void run_gre_pcap_fixture_tests() {
    expect_gre_fixture_files_exist();
    expect_gre_future_expectation_table_covers_all_fixtures();
    expect_gre_fixtures_import_without_crash();
    expect_gre_fixtures_have_expected_total_packet_records();
    expect_supported_gre_v0_ip_fixtures_decode();
    expect_unsupported_gre_payloads_remain_unrecognized();
    expect_gre_truncated_fixtures_import_without_crash();
    expect_gre_packet_details_summary_and_protocol_text();
    expect_gre_warning_packet_details_are_conservative();

    if constexpr (kEnableGreParserExpectationTests) {
        run_future_gre_parser_expectation_tests();
    }
}

}  // namespace pfl::tests
