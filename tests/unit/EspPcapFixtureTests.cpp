#include <algorithm>
#include <array>
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

struct EspFixtureExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
    std::uint64_t expected_flow_count;
    std::string_view expected_protocol_path;
    bool is_direct_protocol50_fixture;
    bool is_nat_t_staged_fixture;
};

constexpr std::array<EspFixtureExpectation, 18> kEspFixtureExpectations {{
    {"01_ipv4_esp_basic.pcap", 1U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"02_ipv6_esp_basic.pcap", 1U, 1U, "EthernetII -> IPv6 -> ESP(spi=0x01020304)", true, false},
    {"03_ipv4_esp_same_hosts_different_spi.pcap", 2U, 2U, "", true, false},
    {"04_ipv4_esp_same_spi_two_packets.pcap", 2U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"05_ipv6_esp_same_hosts_different_spi.pcap", 2U, 2U, "", true, false},
    {"06_outer_vlan_ipv4_esp.pcap", 1U, 1U, "EthernetII -> VLAN(vid=550) -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"07_outer_qinq_ipv4_esp.pcap", 1U, 1U, "EthernetII -> VLAN(vid=551) -> VLAN(vid=552) -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"08_ipv4_esp_large_opaque_payload.pcap", 1U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"09_ipv4_esp_minimal_header_only.pcap", 1U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"10_ipv4_esp_truncated_header.pcap", 1U, 0U, "", true, false},
    {"11_ipv4_esp_truncated_spi_only.pcap", 1U, 0U, "", true, false},
    {"12_ipv6_esp_truncated_header.pcap", 1U, 0U, "", true, false},
    {"13_ipv4_esp_zero_spi.pcap", 1U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x00000000)", true, false},
    {"14_ipv4_esp_high_spi_value.pcap", 1U, 1U, "EthernetII -> IPv4 -> ESP(spi=0xffffffff)", true, false},
    {"15_ipv4_esp_sequence_wrapish_values.pcap", 2U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"16_udp4500_nat_t_esp_non_ike_marker.pcap", 1U, 0U, "", false, true},
    {"17_udp4500_nat_t_ike_marker_staged.pcap", 1U, 0U, "", false, true},
    {"18_ipv4_esp_two_directions_different_spi.pcap", 2U, 2U, "", true, false},
}};

constexpr std::array<std::string_view, 13> kSupportedEspFixturesNow {{
    "01_ipv4_esp_basic.pcap",
    "02_ipv6_esp_basic.pcap",
    "03_ipv4_esp_same_hosts_different_spi.pcap",
    "04_ipv4_esp_same_spi_two_packets.pcap",
    "05_ipv6_esp_same_hosts_different_spi.pcap",
    "06_outer_vlan_ipv4_esp.pcap",
    "07_outer_qinq_ipv4_esp.pcap",
    "08_ipv4_esp_large_opaque_payload.pcap",
    "09_ipv4_esp_minimal_header_only.pcap",
    "13_ipv4_esp_zero_spi.pcap",
    "14_ipv4_esp_high_spi_value.pcap",
    "15_ipv4_esp_sequence_wrapish_values.pcap",
    "18_ipv4_esp_two_directions_different_spi.pcap",
}};

constexpr std::array<std::string_view, 3> kTruncatedEspFixturesNow {{
    "10_ipv4_esp_truncated_header.pcap",
    "11_ipv4_esp_truncated_spi_only.pcap",
    "12_ipv6_esp_truncated_header.pcap",
}};

constexpr std::array<std::string_view, 2> kNatTEspFixturesNow {{
    "16_udp4500_nat_t_esp_non_ike_marker.pcap",
    "17_udp4500_nat_t_ike_marker_staged.pcap",
}};

std::filesystem::path fixture_dir() {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "esp";
}

std::filesystem::path fixture_path(std::string_view file_name) {
    return fixture_dir() / std::filesystem::path(file_name);
}

const EspFixtureExpectation& require_expectation(std::string_view file_name) {
    const auto found = std::find_if(kEspFixtureExpectations.begin(), kEspFixtureExpectations.end(), [&](const auto& expectation) {
        return expectation.file_name == file_name;
    });
    PFL_REQUIRE(found != kEspFixtureExpectations.end());
    return *found;
}

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto& expectation : kEspFixtureExpectations) {
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

bool has_normal_tcp_udp_flow(const std::vector<FlowRow>& rows) {
    return std::any_of(rows.begin(), rows.end(), [](const FlowRow& row) {
        return row.protocol_text == "TCP" || row.protocol_text == "UDP";
    });
}

bool all_rows_are_esp(const std::vector<FlowRow>& rows) {
    return std::all_of(rows.begin(), rows.end(), [](const FlowRow& row) {
        return row.protocol_text == "ESP";
    });
}

bool has_protocol_path(const CaptureSession& session, const FlowRow& row, const std::string_view expected_path) {
    if (row.protocol_path_id == kInvalidProtocolPathId) {
        return false;
    }

    const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
    return path != nullptr && format_protocol_path(*path) == expected_path;
}

const FlowRow* find_flow_with_protocol_path(const CaptureSession& session, const std::vector<FlowRow>& rows, const std::string_view expected_path) {
    const auto found = std::find_if(rows.begin(), rows.end(), [&](const FlowRow& row) {
        return has_protocol_path(session, row, expected_path);
    });
    return found != rows.end() ? &*found : nullptr;
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

void expect_esp_fixture_files_exist() {
    for (const auto& expectation : kEspFixtureExpectations) {
        PFL_EXPECT(std::filesystem::exists(fixture_path(expectation.file_name)));
    }
}

void expect_esp_expectation_table_covers_all_fixtures() {
    PFL_EXPECT(expected_fixture_file_names() == actual_fixture_file_names());
}

void expect_esp_fixtures_import_without_crash() {
    for (const auto& expectation : kEspFixtureExpectations) {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path(expectation.file_name)));
    }
}

void expect_esp_fixtures_have_expected_total_packet_records() {
    for (const auto& expectation : kEspFixtureExpectations) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.total_packets_seen == storage.recognized_packets + storage.unrecognized_packets);
    }
}

void expect_supported_esp_fixtures_decode() {
    for (const auto fixture_name : kSupportedEspFixturesNow) {
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
        PFL_EXPECT(rows.size() == static_cast<std::size_t>(expectation.expected_flow_count));
        PFL_EXPECT(!has_normal_tcp_udp_flow(rows));
        PFL_EXPECT(all_rows_are_esp(rows));

        if (!expectation.expected_protocol_path.empty()) {
            const bool found_expected_path = std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
                return has_protocol_path(session, row, expectation.expected_protocol_path);
            });
            PFL_EXPECT(found_expected_path);
        }
    }
}

void expect_esp_spi_splits_identity() {
    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("03_ipv4_esp_same_hosts_different_spi.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return has_protocol_path(session, row, "EthernetII -> IPv4 -> ESP(spi=0x01020304)");
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return has_protocol_path(session, row, "EthernetII -> IPv4 -> ESP(spi=0x11121314)");
        }));
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("05_ipv6_esp_same_hosts_different_spi.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return has_protocol_path(session, row, "EthernetII -> IPv6 -> ESP(spi=0x01020304)");
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return has_protocol_path(session, row, "EthernetII -> IPv6 -> ESP(spi=0x11121314)");
        }));
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("18_ipv4_esp_two_directions_different_spi.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return has_protocol_path(session, row, "EthernetII -> IPv4 -> ESP(spi=0x01020304)");
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return has_protocol_path(session, row, "EthernetII -> IPv4 -> ESP(spi=0x21222324)");
        }));
    }
}

void expect_esp_same_spi_groups_and_sequence_does_not_split() {
    for (const auto fixture_name : {"04_ipv4_esp_same_spi_two_packets.pcap", "15_ipv4_esp_sequence_wrapish_values.pcap"}) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_text == "ESP");
        PFL_EXPECT(rows[0].packet_count == 2U);
        PFL_EXPECT(rows[0].protocol_path_id != kInvalidProtocolPathId);
    }
}

void expect_outer_qinq_fixture_decodes_as_esp() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("07_outer_qinq_ipv4_esp.pcap")));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == 1U);
    PFL_EXPECT(storage.recognized_packets == 1U);
    PFL_EXPECT(storage.unrecognized_packets == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);

    const auto* row = find_flow_with_protocol_path(
        session,
        rows,
        "EthernetII -> VLAN(vid=551) -> VLAN(vid=552) -> IPv4 -> ESP(spi=0x01020304)");
    PFL_REQUIRE(row != nullptr);
    PFL_EXPECT(row->family == FlowAddressFamily::ipv4);
    PFL_EXPECT(row->protocol_text == "ESP");
    PFL_EXPECT(row->packet_count == 1U);
    PFL_EXPECT(row->protocol_hint.empty());
    PFL_EXPECT(row->service_hint.empty());
}

void expect_truncated_esp_fixtures_remain_conservative() {
    for (const auto fixture_name : kTruncatedEspFixturesNow) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets == 0U);
        PFL_EXPECT(storage.unrecognized_packets == expectation.expected_total_packets);
        PFL_EXPECT(session.unrecognized_packet_count() == expectation.expected_total_packets);
        PFL_EXPECT(session.list_flows().empty());
    }
}

void expect_esp_nat_t_fixtures_remain_staged() {
    for (const auto fixture_name : kNatTEspFixturesNow) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(expectation.is_nat_t_staged_fixture);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.total_packets_seen == storage.recognized_packets + storage.unrecognized_packets);
    }
}

void expect_esp_packet_details_summary() {
    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("01_ipv4_esp_basic.pcap")));

        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_esp);
        PFL_EXPECT(!details->esp.header_truncated);
        PFL_EXPECT(details->esp.available_header_bytes == 8U);
        PFL_EXPECT(details->esp.spi == 0x01020304U);
        PFL_EXPECT(details->esp.sequence_number == 1U);

        const auto layers = session_detail::build_packet_summary_layers(*details, *packet);
        const auto* esp_layer = find_top_level_layer(layers, "esp");
        PFL_REQUIRE(esp_layer != nullptr);
        PFL_EXPECT(esp_layer->title == "ESP, SPI: 0x01020304");
        PFL_EXPECT(layer_has_field_containing(*esp_layer, "SPI", "0x01020304"));
        PFL_EXPECT(layer_has_field_containing(*esp_layer, "Sequence Number", "0x00000001"));
        PFL_EXPECT(layer_has_field_containing(*esp_layer, "Opaque Payload Length", "bytes"));

        const auto protocol_text = session.read_packet_protocol_details_text(*packet);
        PFL_EXPECT(protocol_text.find("Protocol: ESP") != std::string::npos);
        PFL_EXPECT(protocol_text.find("SPI: 0x01020304") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Sequence Number: 0x00000001 (1)") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("09_ipv4_esp_minimal_header_only.pcap")));

        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_esp);
        PFL_EXPECT(details->esp.opaque_payload_length == 0U);

        const auto layers = session_detail::build_packet_summary_layers(*details, *packet);
        const auto* esp_layer = find_top_level_layer(layers, "esp");
        PFL_REQUIRE(esp_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*esp_layer, "Opaque Payload Length", "0 bytes"));
    }
}

}  // namespace

void run_esp_pcap_fixture_tests() {
    expect_esp_fixture_files_exist();
    expect_esp_expectation_table_covers_all_fixtures();
    expect_esp_fixtures_import_without_crash();
    expect_esp_fixtures_have_expected_total_packet_records();
    expect_supported_esp_fixtures_decode();
    expect_esp_spi_splits_identity();
    expect_esp_same_spi_groups_and_sequence_does_not_split();
    expect_outer_qinq_fixture_decodes_as_esp();
    expect_truncated_esp_fixtures_remain_conservative();
    expect_esp_nat_t_fixtures_remain_staged();
    expect_esp_packet_details_summary();
}

}  // namespace pfl::tests
