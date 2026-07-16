#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

struct EoipFixtureExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
};

constexpr std::array<EoipFixtureExpectation, 18> kEoipFixtureExpectations {{
    {"01_ipv4_eoip_inner_ipv4_udp.pcap", 1U},
    {"02_ipv4_eoip_inner_ipv4_tcp.pcap", 1U},
    {"03_ipv4_eoip_inner_ipv6_udp.pcap", 1U},
    {"04_ipv4_eoip_inner_vlan_ipv4_udp.pcap", 1U},
    {"05_ipv4_eoip_inner_qinq_ipv6_tcp.pcap", 1U},
    {"06_outer_vlan_ipv4_eoip_inner_ipv4_udp.pcap", 1U},
    {"07_outer_vlan_mpls2_ipv4_eoip_inner_vlan_ipv4_udp.pcap", 1U},
    {"08_same_inner_tuple_different_tunnel_ids.pcap", 2U},
    {"09_same_tunnel_id_different_inner_payload_lengths.pcap", 2U},
    {"10_same_tunnel_id_two_packets.pcap", 2U},
    {"11_max_tunnel_id.pcap", 1U},
    {"12_truncated_eoip_key_word.pcap", 1U},
    {"13_eoip_payload_length_exceeds_available.pcap", 1U},
    {"14_eoip_payload_length_smaller_than_inner_frame.pcap", 1U},
    {"15_eoip_missing_key_bit.pcap", 1U},
    {"16_gre_v1_unsupported_protocol_type.pcap", 1U},
    {"17_eoip_truncated_inner_ethernet.pcap", 1U},
    {"18_eoip_truncated_inner_vlan.pcap", 1U},
}};

constexpr std::uint32_t kPcapMagic = 0xA1B2C3D4U;
constexpr std::uint32_t kLinkTypeEthernet = 1U;
constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
constexpr std::uint16_t kEtherType8021ad = 0x88A8U;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;
constexpr std::uint16_t kEtherTypeMpls = 0x8847U;
constexpr std::uint8_t kIpv4ProtocolGre = 47U;

struct ParsedFrame {
    std::vector<std::uint8_t> bytes {};
    std::vector<std::uint16_t> outer_vlan_ids {};
    std::vector<std::pair<std::uint32_t, bool>> mpls_labels {};
    std::size_t ipv4_offset {0U};
    std::size_t gre_offset {0U};
};

std::filesystem::path fixture_dir() {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "eoip";
}

std::filesystem::path fixture_path(std::string_view file_name) {
    return fixture_dir() / std::filesystem::path(file_name);
}

std::uint16_t read_be16(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) | bytes[offset + 1U]);
}

std::uint32_t read_be32(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

std::uint32_t read_le32(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}

std::vector<std::vector<std::uint8_t>> parse_pcap_records(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    PFL_REQUIRE(stream.good());
    const std::vector<std::uint8_t> bytes {
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>()
    };
    PFL_REQUIRE(bytes.size() >= 24U);
    PFL_EXPECT(read_le32(bytes, 0U) == kPcapMagic);
    PFL_EXPECT(read_le32(bytes, 20U) == kLinkTypeEthernet);

    std::vector<std::vector<std::uint8_t>> records {};
    std::size_t offset = 24U;
    while (offset + 16U <= bytes.size()) {
        const auto incl_len = static_cast<std::size_t>(read_le32(bytes, offset + 8U));
        offset += 16U;
        PFL_REQUIRE(offset + incl_len <= bytes.size());
        records.emplace_back(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.begin() + static_cast<std::ptrdiff_t>(offset + incl_len));
        offset += incl_len;
    }
    return records;
}

ParsedFrame parse_outer_frame(const std::vector<std::uint8_t>& bytes) {
    PFL_REQUIRE(bytes.size() >= 34U);
    ParsedFrame frame {.bytes = bytes};
    auto ether_type = read_be16(frame.bytes, 12U);
    std::size_t offset = 14U;
    while (ether_type == kEtherTypeVlan || ether_type == kEtherType8021ad) {
        PFL_REQUIRE(offset + 4U <= frame.bytes.size());
        frame.outer_vlan_ids.push_back(static_cast<std::uint16_t>(read_be16(frame.bytes, offset) & 0x0FFFU));
        ether_type = read_be16(frame.bytes, offset + 2U);
        offset += 4U;
    }

    if (ether_type == kEtherTypeMpls) {
        while (true) {
            PFL_REQUIRE(offset + 4U <= frame.bytes.size());
            const auto word = read_be32(frame.bytes, offset);
            const auto label = static_cast<std::uint32_t>((word >> 12U) & 0xFFFFFU);
            const auto bos = ((word >> 8U) & 0x1U) == 1U;
            frame.mpls_labels.push_back({label, bos});
            offset += 4U;
            if (bos) {
                break;
            }
        }
        ether_type = kEtherTypeIpv4;
    }

    PFL_REQUIRE(ether_type == kEtherTypeIpv4);
    frame.ipv4_offset = offset;
    const auto ihl = static_cast<std::size_t>((frame.bytes[frame.ipv4_offset] & 0x0FU) * 4U);
    frame.gre_offset = frame.ipv4_offset + ihl;
    return frame;
}

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto& expectation : kEoipFixtureExpectations) {
        names.emplace(expectation.file_name);
    }
    return names;
}

std::set<std::string> actual_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto& entry : std::filesystem::directory_iterator(fixture_dir())) {
        if (entry.is_regular_file() && entry.path().extension() == ".pcap") {
            names.emplace(entry.path().filename().string());
        }
    }
    return names;
}

void expect_fixture_files_exist() {
    for (const auto& expectation : kEoipFixtureExpectations) {
        PFL_EXPECT(std::filesystem::exists(fixture_path(expectation.file_name)));
    }
}

void expect_expectation_filenames_are_unique() {
    PFL_EXPECT(expected_fixture_file_names().size() == kEoipFixtureExpectations.size());
}

void expect_expectation_table_covers_fixture_directory() {
    PFL_EXPECT(expected_fixture_file_names() == actual_fixture_file_names());
}

void expect_fixtures_import_without_crash() {
    for (const auto& expectation : kEoipFixtureExpectations) {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path(expectation.file_name)));
    }
}

void expect_total_packet_accounting() {
    for (const auto& expectation : kEoipFixtureExpectations) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));
        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets + storage.unrecognized_packets == storage.total_packets_seen);
    }
}

void expect_fixture_01_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("01_ipv4_eoip_inner_ipv4_udp.pcap"));
    PFL_REQUIRE(records.size() == 1U);
    const auto frame = parse_outer_frame(records[0]);
    PFL_EXPECT(frame.bytes[frame.ipv4_offset + 9U] == kIpv4ProtocolGre);
    PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0x2001U);
    PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == 0x6400U);
    const auto declared_payload_length = read_be16(frame.bytes, frame.gre_offset + 4U);
    const auto actual_inner_length = frame.bytes.size() - (frame.gre_offset + 8U);
    PFL_EXPECT(declared_payload_length == actual_inner_length);
    PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 6U) == 6400U);
    const auto inner_offset = frame.gre_offset + 8U;
    PFL_EXPECT(read_be16(frame.bytes, inner_offset + 12U) == kEtherTypeIpv4);
}

void expect_fixture_04_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("04_ipv4_eoip_inner_vlan_ipv4_udp.pcap"));
    PFL_REQUIRE(records.size() == 1U);
    const auto frame = parse_outer_frame(records[0]);
    const auto inner_offset = frame.gre_offset + 8U;
    PFL_EXPECT(read_be16(frame.bytes, inner_offset + 12U) == kEtherTypeVlan);
    PFL_EXPECT((read_be16(frame.bytes, inner_offset + 14U) & 0x0FFFU) == 1806U);
    PFL_EXPECT(read_be16(frame.bytes, inner_offset + 16U) == kEtherTypeIpv4);
}

void expect_fixture_05_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("05_ipv4_eoip_inner_qinq_ipv6_tcp.pcap"));
    PFL_REQUIRE(records.size() == 1U);
    const auto frame = parse_outer_frame(records[0]);
    const auto inner_offset = frame.gre_offset + 8U;
    PFL_EXPECT(read_be16(frame.bytes, inner_offset + 12U) == kEtherType8021ad);
    PFL_EXPECT((read_be16(frame.bytes, inner_offset + 14U) & 0x0FFFU) == 1807U);
    PFL_EXPECT(read_be16(frame.bytes, inner_offset + 16U) == kEtherTypeVlan);
    PFL_EXPECT((read_be16(frame.bytes, inner_offset + 18U) & 0x0FFFU) == 1808U);
    PFL_EXPECT(read_be16(frame.bytes, inner_offset + 20U) == kEtherTypeIpv6);
}

void expect_fixture_07_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("07_outer_vlan_mpls2_ipv4_eoip_inner_vlan_ipv4_udp.pcap"));
    PFL_REQUIRE(records.size() == 1U);
    const auto frame = parse_outer_frame(records[0]);
    PFL_EXPECT(frame.outer_vlan_ids == std::vector<std::uint16_t> {406U});
    PFL_REQUIRE(frame.mpls_labels.size() == 2U);
    PFL_EXPECT(frame.mpls_labels[0].first == 56474U);
    PFL_EXPECT(frame.mpls_labels[0].second == false);
    PFL_EXPECT(frame.mpls_labels[1].first == 477436U);
    PFL_EXPECT(frame.mpls_labels[1].second == true);
    PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 4U) == frame.bytes.size() - (frame.gre_offset + 8U));
    PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 6U) == 6400U);
    const auto inner_offset = frame.gre_offset + 8U;
    PFL_EXPECT(read_be16(frame.bytes, inner_offset + 12U) == kEtherTypeVlan);
    PFL_EXPECT((read_be16(frame.bytes, inner_offset + 14U) & 0x0FFFU) == 3918U);
    PFL_EXPECT(read_be16(frame.bytes, inner_offset + 16U) == kEtherTypeIpv4);
    const auto inner_ipv4_offset = inner_offset + 18U;
    PFL_EXPECT((frame.bytes[inner_ipv4_offset] >> 4U) == 4U);
    const auto inner_udp_offset = inner_ipv4_offset + 20U;
    PFL_EXPECT(read_be16(frame.bytes, inner_udp_offset) == 12366U);
    PFL_EXPECT(read_be16(frame.bytes, inner_udp_offset + 2U) == 12406U);
}

void expect_fixture_08_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("08_same_inner_tuple_different_tunnel_ids.pcap"));
    PFL_REQUIRE(records.size() == 2U);
    const auto first = parse_outer_frame(records[0]);
    const auto second = parse_outer_frame(records[1]);
    PFL_EXPECT(read_be16(first.bytes, first.gre_offset + 6U) == 6400U);
    PFL_EXPECT(read_be16(second.bytes, second.gre_offset + 6U) == 6401U);
}

void expect_fixture_09_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("09_same_tunnel_id_different_inner_payload_lengths.pcap"));
    PFL_REQUIRE(records.size() == 2U);
    const auto first = parse_outer_frame(records[0]);
    const auto second = parse_outer_frame(records[1]);
    PFL_EXPECT(read_be16(first.bytes, first.gre_offset + 6U) == 6400U);
    PFL_EXPECT(read_be16(second.bytes, second.gre_offset + 6U) == 6400U);
    const auto first_length = read_be16(first.bytes, first.gre_offset + 4U);
    const auto second_length = read_be16(second.bytes, second.gre_offset + 4U);
    PFL_EXPECT(first_length != second_length);
    PFL_EXPECT(first_length == first.bytes.size() - (first.gre_offset + 8U));
    PFL_EXPECT(second_length == second.bytes.size() - (second.gre_offset + 8U));
}

void expect_malformed_fixture_layouts() {
    {
        const auto records = parse_pcap_records(fixture_path("12_truncated_eoip_key_word.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT(frame.bytes.size() - frame.gre_offset < 8U);
    }
    {
        const auto records = parse_pcap_records(fixture_path("13_eoip_payload_length_exceeds_available.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 4U) > frame.bytes.size() - (frame.gre_offset + 8U));
    }
    {
        const auto records = parse_pcap_records(fixture_path("14_eoip_payload_length_smaller_than_inner_frame.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        const auto declared_payload_length = read_be16(frame.bytes, frame.gre_offset + 4U);
        const auto actual_inner_length = frame.bytes.size() - (frame.gre_offset + 8U);
        PFL_EXPECT(declared_payload_length < actual_inner_length);
        PFL_EXPECT(declared_payload_length < 14U);
    }
    {
        const auto records = parse_pcap_records(fixture_path("15_eoip_missing_key_bit.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT((read_be16(frame.bytes, frame.gre_offset) & 0x2000U) == 0U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == 0x6400U);
    }
    {
        const auto records = parse_pcap_records(fixture_path("16_gre_v1_unsupported_protocol_type.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0x2001U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == 0x1234U);
    }
    {
        const auto records = parse_pcap_records(fixture_path("17_eoip_truncated_inner_ethernet.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 4U) < 14U);
    }
    {
        const auto records = parse_pcap_records(fixture_path("18_eoip_truncated_inner_vlan.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        const auto inner_offset = frame.gre_offset + 8U;
        PFL_EXPECT(read_be16(frame.bytes, inner_offset + 12U) == kEtherTypeVlan);
        PFL_EXPECT(frame.bytes.size() - inner_offset == 16U);
    }
}

}  // namespace

void run_eoip_pcap_fixture_tests() {
    expect_fixture_files_exist();
    expect_expectation_filenames_are_unique();
    expect_expectation_table_covers_fixture_directory();
    expect_fixtures_import_without_crash();
    expect_total_packet_accounting();
    expect_fixture_01_wire_layout();
    expect_fixture_04_wire_layout();
    expect_fixture_05_wire_layout();
    expect_fixture_07_wire_layout();
    expect_fixture_08_wire_layout();
    expect_fixture_09_wire_layout();
    expect_malformed_fixture_layouts();
}

}  // namespace pfl::tests
