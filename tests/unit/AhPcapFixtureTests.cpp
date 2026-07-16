#include <algorithm>
#include <array>
#include <initializer_list>
#include <cstdint>
#include <filesystem>
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
    {"12_ipv4_ah_inner_ipv4_udp.pcap", 1U, 0U, "", ""},
    {"13_ipv4_ah_inner_ipv6_tcp.pcap", 1U, 0U, "", ""},
    {"14_ipv6_ah_inner_ipv4_udp.pcap", 1U, 0U, "", ""},
    {"15_ipv6_ah_inner_ipv6_tcp.pcap", 1U, 0U, "", ""},
    {"16_ah_truncated_fixed_header.pcap", 1U, 0U, "", ""},
    {"17_ah_invalid_payload_length_too_small.pcap", 1U, 0U, "", ""},
    {"18_ah_payload_length_exceeds_packet.pcap", 1U, 0U, "", ""},
    {"19_ah_truncated_icv.pcap", 1U, 0U, "", ""},
    {"20_ah_unsupported_next_header.pcap", 1U, 0U, "", ""},
}};

constexpr std::array<std::string_view, 11> kSupportedAhFixturesNow {{
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
}};

constexpr std::array<std::string_view, 4> kDeferredTunnelModeFixturesNow {{
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

void expect_deferred_ah_tunnel_mode_fixtures_remain_conservative() {
    for (const auto fixture_name : kDeferredTunnelModeFixturesNow) {
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
        PFL_EXPECT(protocol_text.find("SPI: 0x11111111") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Sequence Number: 0x00000001 (1)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Header Length: 24 bytes") != std::string::npos);
        PFL_EXPECT(protocol_text.find("ICV Length: 12 bytes") != std::string::npos);
    }
}

void expect_conservative_ah_packet_details_for_malformed_or_unsupported_cases() {
    struct NegativeCase {
        std::string_view file_name;
        std::vector<std::string> required_summary_fragments;
        std::vector<std::string> required_protocol_fragments;
    };

    const std::array<NegativeCase, 5> cases {{
        {
            "16_ah_truncated_fixed_header.pcap",
            {"AH", "malformed"},
            {"Protocol: AH", "Available Header Bytes: 10 / ", "Warning: AH header is truncated."}
        },
        {
            "17_ah_invalid_payload_length_too_small.pcap",
            {"AH", "malformed"},
            {"Protocol: AH", "Payload Length: 0", "Warning: AH computed header length is invalid."}
        },
        {
            "18_ah_payload_length_exceeds_packet.pcap",
            {"AH", "malformed"},
            {"Protocol: AH", "Available Header Bytes: 36 / 40", "Warning: AH header is truncated."}
        },
        {
            "19_ah_truncated_icv.pcap",
            {"AH", "malformed"},
            {"Protocol: AH", "Available Header Bytes: 20 / 24", "Warning: AH header is truncated."}
        },
        {
            "20_ah_unsupported_next_header.pcap",
            {"AH", "unsupported next header"},
            {"Protocol: AH", "Next Header: 99", "Warning: AH next header is not supported."}
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
            const auto* ah_layer = find_top_level_layer(layers, "ah");
            PFL_REQUIRE(ah_layer != nullptr);
            for (const auto& fragment : test_case.required_summary_fragments) {
                PFL_EXPECT(ah_layer->title.find(fragment) != std::string::npos);
            }
        }

        const auto protocol_text = details->has_ah
            ? session_detail::build_basic_protocol_details_text(*details).value_or(std::string {})
            : session.read_packet_protocol_details_text(*packet);
        if (details->has_ah) {
            for (const auto& fragment : test_case.required_protocol_fragments) {
                PFL_EXPECT(protocol_text.find(fragment) != std::string::npos);
            }
        } else {
            PFL_EXPECT(!protocol_text.empty());
        }
    }
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
    expect_deferred_ah_tunnel_mode_fixtures_remain_conservative();
    expect_malformed_or_unsupported_ah_fixtures_remain_conservative();
    expect_direct_ah_packet_details_summary_and_protocol_text();
    expect_conservative_ah_packet_details_for_malformed_or_unsupported_cases();
}

}  // namespace pfl::tests
