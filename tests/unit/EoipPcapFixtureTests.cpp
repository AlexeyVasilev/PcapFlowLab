#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <sstream>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/ProtocolPath.h"

namespace pfl::tests {

namespace {

struct EoipFixtureExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
};

enum class PositiveEoipExpectationKind : std::uint8_t {
    single_flow,
    split_by_tunnel_id,
    same_tunnel_payload_length_variation,
    same_tunnel_two_packets,
};

struct PositiveEoipParserExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
    std::uint64_t expected_flow_count;
    PositiveEoipExpectationKind kind;
    FlowAddressFamily family;
    std::string_view protocol_text;
    std::string_view address_a;
    std::uint16_t port_a;
    std::string_view address_b;
    std::uint16_t port_b;
    std::string_view expected_protocol_path;
    std::string_view alternate_protocol_path;
    std::uint64_t expected_flow_packet_count;
    std::array<std::uint32_t, 2> expected_payload_lengths {};
    std::size_t expected_payload_length_count {0U};
    bool expect_tcp_syn {false};
};

constexpr std::array<EoipFixtureExpectation, 32> kEoipFixtureExpectations {{
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
    {"19_ipv4_eoip_inner_llc_snap_ipv4_udp.pcap", 1U},
    {"20_ipv6_gre_v1_k_6400_inner_ipv4_udp_not_eoip.pcap", 1U},
    {"21_ipv4_gre_v0_inner_ipv4_udp_not_eoip.pcap", 1U},
    {"22_ipv4_gre_v0_teb_inner_ipv4_udp_not_eoip.pcap", 1U},
    {"23_ipv4_gre_v0_key_looks_like_eoip_word_inner_ipv4_udp.pcap", 1U},
    {"24_ipv4_gre_v0_6400_wrong_version_key.pcap", 1U},
    {"25_ipv4_gre_v1_checksum_key_6400_not_eoip.pcap", 1U},
    {"26_same_tunnel_same_inner_tuple_different_outer_ipv4_endpoints.pcap", 2U},
    {"27_same_tunnel_same_inner_tuple_different_outer_vlan_metadata.pcap", 2U},
    {"28_ipv4_eoip_first_fragment_mf_complete_inner.pcap", 1U},
    {"29_ipv4_eoip_nonfirst_fragment_valid_looking_bytes_captrunc.pcap", 2U},
    {"30_ipv4_eoip_inner_unsupported_ethernet_payloads.pcap", 5U},
    {"31_ipv4_eoip_nested_eoip_not_continued.pcap", 1U},
    {"32_same_tunnel_same_inner_frame_different_frame_length.pcap", 2U},
}};

constexpr std::array<PositiveEoipParserExpectation, 13> kPositiveEoipParserExpectations {{
    {
        "01_ipv4_eoip_inner_ipv4_udp.pcap",
        1U,
        1U,
        PositiveEoipExpectationKind::single_flow,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.80.0.10",
        53800U,
        "10.80.0.20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP",
        "",
        1U,
        {4U, 0U},
        1U,
        false,
    },
    {
        "02_ipv4_eoip_inner_ipv4_tcp.pcap",
        1U,
        1U,
        PositiveEoipExpectationKind::single_flow,
        FlowAddressFamily::ipv4,
        "TCP",
        "10.80.0.10",
        49180U,
        "10.80.0.20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> TCP",
        "",
        1U,
        {0U, 0U},
        1U,
        true,
    },
    {
        "03_ipv4_eoip_inner_ipv6_udp.pcap",
        1U,
        1U,
        PositiveEoipExpectationKind::single_flow,
        FlowAddressFamily::ipv6,
        "UDP",
        "2001:db8:81::10",
        53800U,
        "2001:db8:81::20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv6 -> UDP",
        "",
        1U,
        {4U, 0U},
        1U,
        false,
    },
    {
        "04_ipv4_eoip_inner_vlan_ipv4_udp.pcap",
        1U,
        1U,
        PositiveEoipExpectationKind::single_flow,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.80.0.10",
        53800U,
        "10.80.0.20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> VLAN(vid=1806) -> IPv4 -> UDP",
        "",
        1U,
        {4U, 0U},
        1U,
        false,
    },
    {
        "05_ipv4_eoip_inner_qinq_ipv6_tcp.pcap",
        1U,
        1U,
        PositiveEoipExpectationKind::single_flow,
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:db8:81::10",
        49180U,
        "2001:db8:81::20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> VLAN(vid=1807) -> VLAN(vid=1808) -> IPv6 -> TCP",
        "",
        1U,
        {0U, 0U},
        1U,
        true,
    },
    {
        "06_outer_vlan_ipv4_eoip_inner_ipv4_udp.pcap",
        1U,
        1U,
        PositiveEoipExpectationKind::single_flow,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.80.0.10",
        53800U,
        "10.80.0.20",
        443U,
        "EthernetII -> VLAN(vid=806) -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP",
        "",
        1U,
        {4U, 0U},
        1U,
        false,
    },
    {
        "07_outer_vlan_mpls2_ipv4_eoip_inner_vlan_ipv4_udp.pcap",
        1U,
        1U,
        PositiveEoipExpectationKind::single_flow,
        FlowAddressFamily::ipv4,
        "UDP",
        "172.16.72.2",
        12366U,
        "172.19.0.242",
        12406U,
        "EthernetII -> VLAN(vid=406) -> MPLS(label=56474) -> MPLS(label=477436) -> IPv4 -> GRE(key=0x00000019) -> EthernetII -> VLAN(vid=3918) -> IPv4 -> UDP",
        "",
        1U,
        {4U, 0U},
        1U,
        false,
    },
    {
        "08_same_inner_tuple_different_tunnel_ids.pcap",
        2U,
        2U,
        PositiveEoipExpectationKind::split_by_tunnel_id,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.80.0.10",
        53800U,
        "10.80.0.20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP",
        "EthernetII -> IPv4 -> GRE(key=0x00001901) -> EthernetII -> IPv4 -> UDP",
        1U,
        {4U, 0U},
        1U,
        false,
    },
    {
        "09_same_tunnel_id_different_inner_payload_lengths.pcap",
        2U,
        1U,
        PositiveEoipExpectationKind::same_tunnel_payload_length_variation,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.80.0.10",
        53800U,
        "10.80.0.20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP",
        "",
        2U,
        {4U, 12U},
        2U,
        false,
    },
    {
        "10_same_tunnel_id_two_packets.pcap",
        2U,
        1U,
        PositiveEoipExpectationKind::same_tunnel_two_packets,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.80.0.10",
        53800U,
        "10.80.0.20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP",
        "",
        2U,
        {4U, 4U},
        2U,
        false,
    },
    {
        "11_max_tunnel_id.pcap",
        1U,
        1U,
        PositiveEoipExpectationKind::single_flow,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.80.0.10",
        53800U,
        "10.80.0.20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x0000ffff) -> EthernetII -> IPv4 -> UDP",
        "",
        1U,
        {4U, 0U},
        1U,
        false,
    },
    {
        "19_ipv4_eoip_inner_llc_snap_ipv4_udp.pcap",
        1U,
        1U,
        PositiveEoipExpectationKind::single_flow,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.80.0.10",
        53800U,
        "10.80.0.20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP",
        "",
        1U,
        {4U, 0U},
        1U,
        false,
    },
    {
        "32_same_tunnel_same_inner_frame_different_frame_length.pcap",
        2U,
        1U,
        PositiveEoipExpectationKind::same_tunnel_two_packets,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.80.0.10",
        53800U,
        "10.80.0.20",
        443U,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP",
        "",
        2U,
        {4U, 4U},
        2U,
        false,
    },
}};

constexpr std::array<std::string_view, 7> kMalformedEoipFixturesNow {{
    "12_truncated_eoip_key_word.pcap",
    "13_eoip_payload_length_exceeds_available.pcap",
    "14_eoip_payload_length_smaller_than_inner_frame.pcap",
    "15_eoip_missing_key_bit.pcap",
    "16_gre_v1_unsupported_protocol_type.pcap",
    "17_eoip_truncated_inner_ethernet.pcap",
    "18_eoip_truncated_inner_vlan.pcap",
}};

constexpr std::uint32_t kPcapMagic = 0xA1B2C3D4U;
constexpr std::uint32_t kLinkTypeEthernet = 1U;
constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
constexpr std::uint16_t kEtherType8021ad = 0x88A8U;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;
constexpr std::uint16_t kEtherTypeMpls = 0x8847U;
constexpr std::uint16_t kEtherTypePppoeSession = 0x8864U;
constexpr std::uint16_t kEtherTypePbb = 0x88E7U;
constexpr std::uint16_t kEtherTypeMacsec = 0x88E5U;
constexpr std::uint8_t kIpv4ProtocolGre = 47U;

struct ParsedFrame {
    std::vector<std::uint8_t> bytes {};
    std::vector<std::uint16_t> outer_vlan_ids {};
    std::vector<std::pair<std::uint32_t, bool>> mpls_labels {};
    std::size_t ipv4_offset {0U};
    std::size_t gre_offset {0U};
};

struct ParsedPcapRecord {
    std::uint32_t incl_len {0U};
    std::uint32_t orig_len {0U};
    std::vector<std::uint8_t> data {};
};

std::filesystem::path fixture_dir() {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "eoip";
}

std::filesystem::path fixture_path(std::string_view file_name) {
    return fixture_dir() / std::filesystem::path(file_name);
}

const PositiveEoipParserExpectation& require_positive_expectation(std::string_view file_name) {
    const auto found = std::find_if(
        kPositiveEoipParserExpectations.begin(),
        kPositiveEoipParserExpectations.end(),
        [&](const auto& expectation) {
            return expectation.file_name == file_name;
        });
    PFL_REQUIRE(found != kPositiveEoipParserExpectations.end());
    return *found;
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    return *packet;
}

std::uint16_t read_be16(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) | bytes[offset + 1U]);
}

std::uint16_t read_le16(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) |
                                      (static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U));
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
        records.emplace_back(
            bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            bytes.begin() + static_cast<std::ptrdiff_t>(offset + incl_len));
        offset += incl_len;
    }
    return records;
}

std::vector<ParsedPcapRecord> parse_pcap_records_with_headers(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    PFL_REQUIRE(stream.good());
    const std::vector<std::uint8_t> bytes {
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>()
    };
    PFL_REQUIRE(bytes.size() >= 24U);
    PFL_EXPECT(read_le32(bytes, 0U) == kPcapMagic);
    PFL_EXPECT(read_le32(bytes, 20U) == kLinkTypeEthernet);

    std::vector<ParsedPcapRecord> records {};
    std::size_t offset = 24U;
    while (offset + 16U <= bytes.size()) {
        const auto incl_len = read_le32(bytes, offset + 8U);
        const auto orig_len = read_le32(bytes, offset + 12U);
        offset += 16U;
        PFL_REQUIRE(offset + incl_len <= bytes.size());
        records.push_back(ParsedPcapRecord {
            .incl_len = incl_len,
            .orig_len = orig_len,
            .data = std::vector<std::uint8_t> {
                bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                bytes.begin() + static_cast<std::ptrdiff_t>(offset + incl_len)
            },
        });
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

bool row_matches_tuple(
    const FlowRow& row,
    const FlowAddressFamily family,
    const std::string_view protocol_text,
    const std::string_view address_a,
    const std::uint16_t port_a,
    const std::string_view address_b,
    const std::uint16_t port_b
) {
    if (row.family != family || row.protocol_text != protocol_text) {
        return false;
    }

    const auto canonicalize_address = [&](const std::string_view address) -> std::string {
        if (family != FlowAddressFamily::ipv6) {
            return std::string {address};
        }

        const auto parse_hex_group = [](const std::string_view group) -> std::optional<std::uint16_t> {
            if (group.empty() || group.size() > 4U) {
                return std::nullopt;
            }

            std::uint16_t value = 0U;
            for (const char ch : group) {
                value = static_cast<std::uint16_t>(value << 4U);
                if (ch >= '0' && ch <= '9') {
                    value = static_cast<std::uint16_t>(value | static_cast<std::uint16_t>(ch - '0'));
                } else if (ch >= 'a' && ch <= 'f') {
                    value = static_cast<std::uint16_t>(value | static_cast<std::uint16_t>(ch - 'a' + 10));
                } else if (ch >= 'A' && ch <= 'F') {
                    value = static_cast<std::uint16_t>(value | static_cast<std::uint16_t>(ch - 'A' + 10));
                } else {
                    return std::nullopt;
                }
            }

            return value;
        };

        const auto parse_groups = [&](const std::string_view text) -> std::optional<std::vector<std::uint16_t>> {
            std::vector<std::uint16_t> groups {};
            std::size_t start = 0U;
            while (start < text.size()) {
                const auto separator = text.find(':', start);
                const auto group = text.substr(start, separator == std::string_view::npos ? text.size() - start
                                                                                         : separator - start);
                const auto parsed = parse_hex_group(group);
                if (!parsed.has_value()) {
                    return std::nullopt;
                }
                groups.push_back(*parsed);
                if (separator == std::string_view::npos) {
                    break;
                }
                start = separator + 1U;
            }
            return groups;
        };

        std::array<std::uint8_t, 16> bytes {};
        const auto double_colon = address.find("::");
        std::vector<std::uint16_t> groups {};
        if (double_colon == std::string_view::npos) {
            const auto parsed = parse_groups(address);
            if (!parsed.has_value() || parsed->size() != 8U) {
                return std::string {address};
            }
            groups = std::move(*parsed);
        } else {
            const auto prefix_text = address.substr(0U, double_colon);
            const auto suffix_text = address.substr(double_colon + 2U);
            const auto prefix = prefix_text.empty() ? std::optional<std::vector<std::uint16_t>> {std::vector<std::uint16_t> {}}
                                                    : parse_groups(prefix_text);
            const auto suffix = suffix_text.empty() ? std::optional<std::vector<std::uint16_t>> {std::vector<std::uint16_t> {}}
                                                    : parse_groups(suffix_text);
            if (!prefix.has_value() || !suffix.has_value() || prefix->size() + suffix->size() > 8U) {
                return std::string {address};
            }

            groups = *prefix;
            groups.resize(8U - suffix->size(), 0U);
            groups.insert(groups.end(), suffix->begin(), suffix->end());
        }

        for (std::size_t index = 0U; index < groups.size(); ++index) {
            bytes[index * 2U] = static_cast<std::uint8_t>(groups[index] >> 8U);
            bytes[index * 2U + 1U] = static_cast<std::uint8_t>(groups[index] & 0xFFU);
        }

        return session_detail::format_ipv6_address(bytes);
    };

    const auto expected_address_a = canonicalize_address(address_a);
    const auto expected_address_b = canonicalize_address(address_b);

    const bool forward_match =
        row.address_a == expected_address_a &&
        row.port_a == port_a &&
        row.address_b == expected_address_b &&
        row.port_b == port_b;
    const bool reverse_match =
        row.address_a == expected_address_b &&
        row.port_a == port_b &&
        row.address_b == expected_address_a &&
        row.port_b == port_a;
    return forward_match || reverse_match;
}

const FlowRow* find_flow_by_tuple(
    const std::vector<FlowRow>& rows,
    const FlowAddressFamily family,
    const std::string_view protocol_text,
    const std::string_view address_a,
    const std::uint16_t port_a,
    const std::string_view address_b,
    const std::uint16_t port_b
) {
    const auto found = std::find_if(rows.begin(), rows.end(), [&](const FlowRow& row) {
        return row_matches_tuple(row, family, protocol_text, address_a, port_a, address_b, port_b);
    });
    return found == rows.end() ? nullptr : &(*found);
}

bool has_protocol_path(const CaptureSession& session, const FlowRow& row, const std::string_view expected_path) {
    if (row.protocol_path_id == kInvalidProtocolPathId) {
        return false;
    }

    const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
    return path != nullptr && format_protocol_path(*path) == expected_path;
}

std::string require_flow_protocol_path_text(const CaptureSession& session, const FlowRow& row) {
    PFL_REQUIRE(row.protocol_path_id != kInvalidProtocolPathId);
    const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
    PFL_REQUIRE(path != nullptr);
    return format_protocol_path(*path);
}

const FlowRow* find_flow_with_protocol_path(
    const CaptureSession& session,
    const std::vector<FlowRow>& rows,
    const std::string_view expected_path
) {
    const auto found = std::find_if(rows.begin(), rows.end(), [&](const FlowRow& row) {
        return has_protocol_path(session, row, expected_path);
    });
    return found == rows.end() ? nullptr : &(*found);
}

const session_detail::PacketSummaryLayer* find_top_level_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id,
    const std::size_t occurrence = 0U
) {
    std::size_t seen = 0U;
    for (const auto& layer : layers) {
        if (layer.id != id) {
            continue;
        }
        if (seen == occurrence) {
            return &layer;
        }
        ++seen;
    }
    return nullptr;
}

std::size_t count_top_level_layers(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    return static_cast<std::size_t>(std::count_if(layers.begin(), layers.end(), [&](const auto& layer) {
        return layer.id == id;
    }));
}

std::string format_hex16_for_test(const std::uint16_t value) {
    std::ostringstream stream {};
    stream << "0x" << std::hex << std::nouppercase << std::setw(4) << std::setfill('0') << value;
    return stream.str();
}

std::string format_hex32_for_test(const std::uint32_t value) {
    std::ostringstream stream {};
    stream << "0x" << std::hex << std::nouppercase << std::setw(8) << std::setfill('0') << value;
    return stream.str();
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

bool layer_has_field_containing(
    const session_detail::PacketSummaryLayer& layer,
    const std::string_view label,
    const std::string_view fragment
) {
    const auto found = std::find_if(layer.fields.begin(), layer.fields.end(), [&](const auto& field) {
        return field.label == label && field.value.find(fragment) != std::string::npos;
    });
    return found != layer.fields.end();
}

void expect_top_level_layers_present(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::vector<std::string>& expected_ids
) {
    for (const auto& expected_id : expected_ids) {
        PFL_REQUIRE(find_top_level_layer(layers, expected_id) != nullptr);
    }
}

void expect_payload_lengths(
    const std::vector<PacketRow>& packet_rows,
    const std::array<std::uint32_t, 2>& expected_payload_lengths,
    const std::size_t expected_count
) {
    PFL_REQUIRE(packet_rows.size() == expected_count);
    for (std::size_t index = 0U; index < expected_count; ++index) {
        PFL_EXPECT(packet_rows[index].payload_length == expected_payload_lengths[index]);
    }
}

std::vector<PacketRow> effective_flow_packet_rows(CaptureSession& session, const std::size_t flow_index) {
    auto rows = session.list_flow_packets(flow_index);
    session_detail::apply_original_transport_payload_lengths(session, rows);
    return rows;
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
    PFL_EXPECT(frame.bytes[frame.gre_offset + 6U] == 0x00U);
    PFL_EXPECT(frame.bytes[frame.gre_offset + 7U] == 0x19U);
    PFL_EXPECT(read_le16(frame.bytes, frame.gre_offset + 6U) == 6400U);
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
    PFL_EXPECT(frame.bytes[frame.gre_offset + 6U] == 0x19U);
    PFL_EXPECT(frame.bytes[frame.gre_offset + 7U] == 0x00U);
    PFL_EXPECT(read_le16(frame.bytes, frame.gre_offset + 6U) == 25U);
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
    PFL_EXPECT(first.bytes[first.gre_offset + 6U] == 0x00U);
    PFL_EXPECT(first.bytes[first.gre_offset + 7U] == 0x19U);
    PFL_EXPECT(read_le16(first.bytes, first.gre_offset + 6U) == 6400U);
    PFL_EXPECT(second.bytes[second.gre_offset + 6U] == 0x01U);
    PFL_EXPECT(second.bytes[second.gre_offset + 7U] == 0x19U);
    PFL_EXPECT(read_le16(second.bytes, second.gre_offset + 6U) == 6401U);
}

void expect_fixture_09_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("09_same_tunnel_id_different_inner_payload_lengths.pcap"));
    PFL_REQUIRE(records.size() == 2U);
    const auto first = parse_outer_frame(records[0]);
    const auto second = parse_outer_frame(records[1]);
    PFL_EXPECT(first.bytes[first.gre_offset + 6U] == 0x00U);
    PFL_EXPECT(first.bytes[first.gre_offset + 7U] == 0x19U);
    PFL_EXPECT(read_le16(first.bytes, first.gre_offset + 6U) == 6400U);
    PFL_EXPECT(second.bytes[second.gre_offset + 6U] == 0x00U);
    PFL_EXPECT(second.bytes[second.gre_offset + 7U] == 0x19U);
    PFL_EXPECT(read_le16(second.bytes, second.gre_offset + 6U) == 6400U);
    const auto first_length = read_be16(first.bytes, first.gre_offset + 4U);
    const auto second_length = read_be16(second.bytes, second.gre_offset + 4U);
    PFL_EXPECT(first_length != second_length);
    PFL_EXPECT(first_length == first.bytes.size() - (first.gre_offset + 8U));
    PFL_EXPECT(second_length == second.bytes.size() - (second.gre_offset + 8U));
}

void expect_fixture_11_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("11_max_tunnel_id.pcap"));
    PFL_REQUIRE(records.size() == 1U);
    const auto frame = parse_outer_frame(records[0]);
    PFL_EXPECT(frame.bytes[frame.gre_offset + 6U] == 0xFFU);
    PFL_EXPECT(frame.bytes[frame.gre_offset + 7U] == 0xFFU);
    PFL_EXPECT(read_le16(frame.bytes, frame.gre_offset + 6U) == 65535U);
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

void expect_fixture_19_llc_snap_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("19_ipv4_eoip_inner_llc_snap_ipv4_udp.pcap"));
    PFL_REQUIRE(records.size() == 1U);
    const auto frame = parse_outer_frame(records[0]);
    PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0x2001U);
    PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == 0x6400U);

    const auto inner_offset = frame.gre_offset + 8U;
    const auto inner_length = read_be16(frame.bytes, inner_offset + 12U);
    PFL_EXPECT(inner_length < 0x0600U);
    PFL_EXPECT(frame.bytes[inner_offset + 14U] == 0xaaU);
    PFL_EXPECT(frame.bytes[inner_offset + 15U] == 0xaaU);
    PFL_EXPECT(frame.bytes[inner_offset + 16U] == 0x03U);
    PFL_EXPECT(read_be16(frame.bytes, inner_offset + 20U) == kEtherTypeIpv4);
}

void expect_gre_eoip_ambiguity_wire_layouts() {
    {
        const auto records = parse_pcap_records(fixture_path("20_ipv6_gre_v1_k_6400_inner_ipv4_udp_not_eoip.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto& bytes = records[0];
        PFL_REQUIRE(bytes.size() >= 62U);
        PFL_EXPECT(read_be16(bytes, 12U) == kEtherTypeIpv6);
        PFL_EXPECT(bytes[20U] == kIpv4ProtocolGre);
        PFL_EXPECT(read_be16(bytes, 54U) == 0x2001U);
        PFL_EXPECT(read_be16(bytes, 56U) == 0x6400U);
        PFL_EXPECT(read_be32(bytes, 58U) == 0x002e0019U);
    }
    {
        const auto records = parse_pcap_records(fixture_path("21_ipv4_gre_v0_inner_ipv4_udp_not_eoip.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0x0000U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == kEtherTypeIpv4);
    }
    {
        const auto records = parse_pcap_records(fixture_path("22_ipv4_gre_v0_teb_inner_ipv4_udp_not_eoip.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0x0000U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == 0x6558U);
    }
    {
        const auto records = parse_pcap_records(fixture_path("23_ipv4_gre_v0_key_looks_like_eoip_word_inner_ipv4_udp.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0x2000U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == kEtherTypeIpv4);
        PFL_EXPECT(read_be32(frame.bytes, frame.gre_offset + 4U) == 0x002e0019U);
    }
    {
        const auto records = parse_pcap_records(fixture_path("24_ipv4_gre_v0_6400_wrong_version_key.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0x2000U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == 0x6400U);
        PFL_EXPECT(read_be32(frame.bytes, frame.gre_offset + 4U) == 0xdeadbeefU);
    }
    {
        const auto records = parse_pcap_records(fixture_path("25_ipv4_gre_v1_checksum_key_6400_not_eoip.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0xa001U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == 0x6400U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 4U) == 0x1234U);
        PFL_EXPECT(read_be32(frame.bytes, frame.gre_offset + 8U) == 0x002e0019U);
    }
}

void expect_fixture_26_and_27_identity_wire_layouts() {
    {
        const auto records = parse_pcap_records(fixture_path("26_same_tunnel_same_inner_tuple_different_outer_ipv4_endpoints.pcap"));
        PFL_REQUIRE(records.size() == 2U);
        const auto first = parse_outer_frame(records[0]);
        const auto second = parse_outer_frame(records[1]);
        PFL_EXPECT(read_le16(first.bytes, first.gre_offset + 6U) == 6400U);
        PFL_EXPECT(read_le16(second.bytes, second.gre_offset + 6U) == 6400U);
        PFL_EXPECT(read_be32(first.bytes, first.ipv4_offset + 12U) != read_be32(second.bytes, second.ipv4_offset + 12U));
        PFL_EXPECT(read_be32(first.bytes, first.ipv4_offset + 16U) != read_be32(second.bytes, second.ipv4_offset + 16U));
    }
    {
        const auto records = parse_pcap_records(fixture_path("27_same_tunnel_same_inner_tuple_different_outer_vlan_metadata.pcap"));
        PFL_REQUIRE(records.size() == 2U);
        const auto first = parse_outer_frame(records[0]);
        const auto second = parse_outer_frame(records[1]);
        PFL_EXPECT(first.outer_vlan_ids.empty());
        PFL_EXPECT(second.outer_vlan_ids == std::vector<std::uint16_t> {806U});
        PFL_EXPECT(read_le16(first.bytes, first.gre_offset + 6U) == 6400U);
        PFL_EXPECT(read_le16(second.bytes, second.gre_offset + 6U) == 6400U);
    }
}

void expect_fragmentation_fixture_wire_layouts() {
    {
        const auto records = parse_pcap_records(fixture_path("28_ipv4_eoip_first_fragment_mf_complete_inner.pcap"));
        PFL_REQUIRE(records.size() == 1U);
        const auto frame = parse_outer_frame(records[0]);
        PFL_EXPECT(read_be16(frame.bytes, frame.ipv4_offset + 6U) == 0x2000U);
        PFL_EXPECT(frame.bytes[frame.ipv4_offset + 9U] == kIpv4ProtocolGre);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0x2001U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == 0x6400U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 4U) == frame.bytes.size() - (frame.gre_offset + 8U));
        PFL_EXPECT(read_le16(frame.bytes, frame.gre_offset + 6U) == 6400U);
    }
    {
        const auto records = parse_pcap_records_with_headers(
            fixture_path("29_ipv4_eoip_nonfirst_fragment_valid_looking_bytes_captrunc.pcap")
        );
        PFL_REQUIRE(records.size() == 2U);

        const auto first = parse_outer_frame(records[0].data);
        PFL_EXPECT(records[0].incl_len == records[0].orig_len);
        PFL_EXPECT(read_be16(first.bytes, first.ipv4_offset + 6U) == 0x2001U);
        PFL_EXPECT(read_be16(first.bytes, first.gre_offset) == 0x2001U);
        PFL_EXPECT(read_be16(first.bytes, first.gre_offset + 2U) == 0x6400U);
        PFL_EXPECT(read_le16(first.bytes, first.gre_offset + 6U) == 6400U);

        const auto second = parse_outer_frame(records[1].data);
        PFL_EXPECT(records[1].incl_len < records[1].orig_len);
        PFL_EXPECT(read_be16(second.bytes, second.ipv4_offset + 6U) == 0x0002U);
        PFL_EXPECT(read_be16(second.bytes, second.gre_offset) == 0x2001U);
        PFL_EXPECT(read_be16(second.bytes, second.gre_offset + 2U) == 0x6400U);
        PFL_EXPECT(read_le16(second.bytes, second.gre_offset + 6U) == 6400U);
    }
}

void expect_unsupported_inner_ethernet_fixture_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("30_ipv4_eoip_inner_unsupported_ethernet_payloads.pcap"));
    PFL_REQUIRE(records.size() == 5U);
    const std::array<std::uint16_t, 5> expected_inner_types {{
        kEtherTypePppoeSession,
        kEtherTypeMpls,
        kEtherTypePbb,
        kEtherTypeMacsec,
        0x1234U,
    }};
    const std::array<std::uint16_t, 5> expected_frame_lengths {{
        59U,
        57U,
        72U,
        74U,
        18U,
    }};

    for (std::size_t index = 0U; index < records.size(); ++index) {
        const auto frame = parse_outer_frame(records[index]);
        const auto inner_offset = frame.gre_offset + 8U;
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0x2001U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == 0x6400U);
        PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 4U) == expected_frame_lengths[index]);
        PFL_EXPECT(read_le16(frame.bytes, frame.gre_offset + 6U) == 6400U);
        PFL_EXPECT(read_be16(frame.bytes, inner_offset + 12U) == expected_inner_types[index]);
    }
}

void expect_fixture_31_nested_eoip_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("31_ipv4_eoip_nested_eoip_not_continued.pcap"));
    PFL_REQUIRE(records.size() == 1U);
    const auto frame = parse_outer_frame(records[0]);
    const auto inner_offset = frame.gre_offset + 8U;
    const auto inner_ipv4_offset = inner_offset + 14U;
    PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset) == 0x2001U);
    PFL_EXPECT(read_be16(frame.bytes, frame.gre_offset + 2U) == 0x6400U);
    PFL_EXPECT(read_le16(frame.bytes, frame.gre_offset + 6U) == 6400U);
    PFL_EXPECT(read_be16(frame.bytes, inner_offset + 12U) == kEtherTypeIpv4);
    PFL_EXPECT(frame.bytes[inner_ipv4_offset + 9U] == kIpv4ProtocolGre);
}

void expect_fixture_32_wire_layout() {
    const auto records = parse_pcap_records(fixture_path("32_same_tunnel_same_inner_frame_different_frame_length.pcap"));
    PFL_REQUIRE(records.size() == 2U);
    const auto first = parse_outer_frame(records[0]);
    const auto second = parse_outer_frame(records[1]);
    PFL_EXPECT(read_be16(first.bytes, first.gre_offset + 4U) == 46U);
    PFL_EXPECT(read_be16(second.bytes, second.gre_offset + 4U) == 50U);
    PFL_EXPECT(read_le16(first.bytes, first.gre_offset + 6U) == 6400U);
    PFL_EXPECT(read_le16(second.bytes, second.gre_offset + 6U) == 6400U);
    PFL_EXPECT(read_be32(first.bytes, first.gre_offset + 4U) == 0x002e0019U);
    PFL_EXPECT(read_be32(second.bytes, second.gre_offset + 4U) == 0x00320019U);
    PFL_EXPECT(read_be16(first.bytes, first.gre_offset + 4U) != read_be16(second.bytes, second.gre_offset + 4U));
    PFL_EXPECT(
        std::vector<std::uint8_t>(first.bytes.begin() + static_cast<std::ptrdiff_t>(first.gre_offset + 8U), first.bytes.end()) !=
        std::vector<std::uint8_t>(second.bytes.begin() + static_cast<std::ptrdiff_t>(second.gre_offset + 8U), second.bytes.end())
    );
}

void expect_positive_single_flow_fixture(const PositiveEoipParserExpectation& expectation) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
    PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
    PFL_EXPECT(storage.unrecognized_packets == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);
    PFL_EXPECT(session.summary().packet_count == expectation.expected_total_packets);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == expectation.expected_flow_count);

    const auto* row = find_flow_by_tuple(
        rows,
        expectation.family,
        expectation.protocol_text,
        expectation.address_a,
        expectation.port_a,
        expectation.address_b,
        expectation.port_b);
    PFL_REQUIRE(row != nullptr);
    PFL_EXPECT(row->packet_count == expectation.expected_flow_packet_count);
    PFL_EXPECT(has_protocol_path(session, *row, expectation.expected_protocol_path));

    const auto packet_rows = effective_flow_packet_rows(session, row->index);
    expect_payload_lengths(packet_rows, expectation.expected_payload_lengths, expectation.expected_payload_length_count);
    if (expectation.expect_tcp_syn) {
        PFL_REQUIRE(!packet_rows.empty());
        PFL_EXPECT(packet_rows[0].tcp_flags_text.find("SYN") != std::string::npos);
    }
}

void expect_positive_fixture_08_splits_on_tunnel_id() {
    const auto& expectation = require_positive_expectation("08_same_inner_tuple_different_tunnel_ids.pcap");
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
    PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
    PFL_EXPECT(storage.unrecognized_packets == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == expectation.expected_flow_count);

    const auto* first = find_flow_with_protocol_path(session, rows, expectation.expected_protocol_path);
    const auto* second = find_flow_with_protocol_path(session, rows, expectation.alternate_protocol_path);
    PFL_REQUIRE(first != nullptr);
    PFL_REQUIRE(second != nullptr);
    PFL_EXPECT(first != second);
    PFL_EXPECT(row_matches_tuple(
        *first,
        expectation.family,
        expectation.protocol_text,
        expectation.address_a,
        expectation.port_a,
        expectation.address_b,
        expectation.port_b));
    PFL_EXPECT(row_matches_tuple(
        *second,
        expectation.family,
        expectation.protocol_text,
        expectation.address_a,
        expectation.port_a,
        expectation.address_b,
        expectation.port_b));
    PFL_EXPECT(first->packet_count == 1U);
    PFL_EXPECT(second->packet_count == 1U);

    const auto first_packets = effective_flow_packet_rows(session, first->index);
    const auto second_packets = effective_flow_packet_rows(session, second->index);
    PFL_REQUIRE(first_packets.size() == 1U);
    PFL_REQUIRE(second_packets.size() == 1U);
    PFL_EXPECT(first_packets[0].payload_length == 4U);
    PFL_EXPECT(second_packets[0].payload_length == 4U);
}

void expect_positive_fixture_09_payload_length_does_not_split_identity() {
    const auto& expectation = require_positive_expectation("09_same_tunnel_id_different_inner_payload_lengths.pcap");
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
    PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
    PFL_EXPECT(storage.unrecognized_packets == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == expectation.expected_flow_count);

    const auto* row = find_flow_by_tuple(
        rows,
        expectation.family,
        expectation.protocol_text,
        expectation.address_a,
        expectation.port_a,
        expectation.address_b,
        expectation.port_b);
    PFL_REQUIRE(row != nullptr);
    PFL_EXPECT(row->packet_count == 2U);
    PFL_EXPECT(has_protocol_path(session, *row, expectation.expected_protocol_path));

    const auto packet_rows = effective_flow_packet_rows(session, row->index);
    expect_payload_lengths(packet_rows, expectation.expected_payload_lengths, expectation.expected_payload_length_count);
}

void expect_positive_fixture_10_same_tunnel_id_two_packets_group() {
    const auto& expectation = require_positive_expectation("10_same_tunnel_id_two_packets.pcap");
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
    PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
    PFL_EXPECT(storage.unrecognized_packets == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == expectation.expected_flow_count);
    const auto* row = find_flow_by_tuple(
        rows,
        expectation.family,
        expectation.protocol_text,
        expectation.address_a,
        expectation.port_a,
        expectation.address_b,
        expectation.port_b);
    PFL_REQUIRE(row != nullptr);
    PFL_EXPECT(row->packet_count == 2U);
    PFL_EXPECT(has_protocol_path(session, *row, expectation.expected_protocol_path));

    const auto packet_rows = effective_flow_packet_rows(session, row->index);
    expect_payload_lengths(packet_rows, expectation.expected_payload_lengths, expectation.expected_payload_length_count);
}

void expect_positive_parser_expectations() {
    for (const auto& expectation : kPositiveEoipParserExpectations) {
        switch (expectation.kind) {
        case PositiveEoipExpectationKind::single_flow:
            expect_positive_single_flow_fixture(expectation);
            break;
        case PositiveEoipExpectationKind::split_by_tunnel_id:
            expect_positive_fixture_08_splits_on_tunnel_id();
            break;
        case PositiveEoipExpectationKind::same_tunnel_payload_length_variation:
            expect_positive_fixture_09_payload_length_does_not_split_identity();
            break;
        case PositiveEoipExpectationKind::same_tunnel_two_packets:
            expect_positive_fixture_10_same_tunnel_id_two_packets_group();
            break;
        }
    }
}

void expect_malformed_eoip_fixtures_remain_conservative() {
    for (const auto fixture_name : kMalformedEoipFixturesNow) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {fixture_name}};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));
        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == 1U);
        PFL_EXPECT(storage.recognized_packets == 0U);
        PFL_EXPECT(storage.unrecognized_packets == 1U);
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        PFL_EXPECT(session.list_flows().empty());
    }
}

void expect_fixture_19_llc_snap_continuation() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("19_ipv4_eoip_inner_llc_snap_ipv4_udp.pcap")));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == 1U);
    PFL_EXPECT(storage.recognized_packets == 1U);
    PFL_EXPECT(storage.unrecognized_packets == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    const auto* row = find_flow_by_tuple(
        rows,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.80.0.10",
        53800U,
        "10.80.0.20",
        443U
    );
    PFL_REQUIRE(row != nullptr);
    PFL_EXPECT(
        require_flow_protocol_path_text(session, *row) ==
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP"
    );

    const auto packet_rows = effective_flow_packet_rows(session, row->index);
    PFL_REQUIRE(packet_rows.size() == 1U);
    PFL_EXPECT(packet_rows[0].payload_length == 4U);

    const auto details = session.read_packet_details(require_packet(session, 0U));
    PFL_REQUIRE(details.has_value());
    PFL_REQUIRE(details->has_gre);
    PFL_EXPECT(details->gre.is_eoip);
    PFL_EXPECT(details->has_inner_ethernet);
    PFL_EXPECT(details->inner_ethernet.uses_length_field);

    const auto protocol_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {});
    PFL_EXPECT(protocol_text.find("Protocol: GRE / EoIP") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Inner Length: ") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Inner Payload: IPv4") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Inner UDP:") != std::string::npos);
}

void expect_missing_key_and_unsupported_v1_do_not_claim_eoip() {
    struct Case {
        std::string_view file_name;
        std::vector<std::string> required_fragments;
        std::vector<std::string> forbidden_fragments;
    };

    const std::array<Case, 2> cases {{
        {
            "15_eoip_missing_key_bit.pcap",
            {"Protocol: GRE", "Warning: EoIP requires the GRE key bit."},
            {"Protocol: GRE / EoIP", "Tunnel ID:", "Identity Key:", "Warning: GRE version is not supported.", "Warning: GRE protocol type is not supported."},
        },
        {
            "16_gre_v1_unsupported_protocol_type.pcap",
            {"Protocol: GRE", "Key Present: Yes", "Raw GRE Key: 0xdeadbeef", "Warning: GRE protocol type is not supported."},
            {"Protocol: GRE / EoIP", "Tunnel ID:", "Payload Length:", "Call ID:", "Warning: GRE version is not supported.", "EoIP Frame Length:"},
        },
    }};

    for (const auto& test_case : cases) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_gre);
        PFL_EXPECT(!details->gre.is_eoip);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {});
        for (const auto& fragment : test_case.required_fragments) {
            PFL_EXPECT(protocol_text.find(fragment) != std::string::npos);
        }
        for (const auto& fragment : test_case.forbidden_fragments) {
            PFL_EXPECT(protocol_text.find(fragment) == std::string::npos);
        }
    }
}

void expect_gre_ambiguity_recognized_flows_do_not_claim_eoip() {
    struct Case {
        std::string_view file_name;
        std::string_view expected_protocol_path;
        std::vector<std::string> required_protocol_fragments;
        std::vector<std::string> forbidden_protocol_fragments;
    };

    const std::array<Case, 3> cases {{
        {
            "21_ipv4_gre_v0_inner_ipv4_udp_not_eoip.pcap",
            "EthernetII -> IPv4 -> GRE -> IPv4 -> UDP",
            {"Protocol: GRE", "Protocol Type: IPv4 (0x0800)", "Inner Payload: IPv4", "Inner UDP:"},
            {"Protocol: GRE / EoIP", "Tunnel ID:", "Identity Key:", "EoIP Frame Length:"},
        },
        {
            "22_ipv4_gre_v0_teb_inner_ipv4_udp_not_eoip.pcap",
            "EthernetII -> IPv4 -> GRE -> EthernetII -> IPv4 -> UDP",
            {"Protocol: GRE", "Protocol Type: Transparent Ethernet Bridging (0x6558)", "Inner Payload: Ethernet", "Inner UDP:"},
            {"Protocol: GRE / EoIP", "Tunnel ID:", "Identity Key:", "EoIP Frame Length:"},
        },
        {
            "23_ipv4_gre_v0_key_looks_like_eoip_word_inner_ipv4_udp.pcap",
            "EthernetII -> IPv4 -> GRE(key=0x002e0019) -> IPv4 -> UDP",
            {"Protocol: GRE", "Key: 0x002e0019", "Protocol Type: IPv4 (0x0800)", "Inner UDP:"},
            {"Protocol: GRE / EoIP", "Tunnel ID:", "Identity Key:", "EoIP Frame Length:"},
        },
    }};

    for (const auto& test_case : cases) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {test_case.file_name}};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == 1U);
        PFL_EXPECT(storage.recognized_packets == 1U);
        PFL_EXPECT(storage.unrecognized_packets == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        const auto* row = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "UDP",
            "10.80.0.10",
            53800U,
            "10.80.0.20",
            443U
        );
        PFL_REQUIRE(row != nullptr);
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) == test_case.expected_protocol_path);

        const auto details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_gre);
        PFL_EXPECT(!details->gre.is_eoip);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {});
        for (const auto& fragment : test_case.required_protocol_fragments) {
            PFL_EXPECT(protocol_text.find(fragment) != std::string::npos);
        }
        for (const auto& fragment : test_case.forbidden_protocol_fragments) {
            PFL_EXPECT(protocol_text.find(fragment) == std::string::npos);
        }
    }
}

void expect_gre_ambiguity_no_flow_cases_do_not_claim_eoip() {
    struct Case {
        std::string_view file_name;
        std::vector<std::string> required_protocol_fragments;
        std::vector<std::string> forbidden_protocol_fragments;
    };

    const std::array<Case, 3> cases {{
        {
            "20_ipv6_gre_v1_k_6400_inner_ipv4_udp_not_eoip.pcap",
            {"Protocol: GRE", "Raw GRE Key: 0x002e0019", "Warning: GRE protocol type is not supported."},
            {"Protocol: GRE / EoIP", "Tunnel ID:", "Identity Key:", "EoIP Frame Length:", "Warning: GRE version is not supported."},
        },
        {
            "24_ipv4_gre_v0_6400_wrong_version_key.pcap",
            {"Protocol: GRE", "Key: 0xdeadbeef", "Warning: GRE protocol type is not supported."},
            {"Protocol: GRE / EoIP", "Tunnel ID:", "Identity Key:", "EoIP Frame Length:", "Warning: GRE version is not supported."},
        },
        {
            "25_ipv4_gre_v1_checksum_key_6400_not_eoip.pcap",
            {"Protocol: GRE", "Checksum: 0x1234", "Raw GRE Key: 0x002e0019", "Warning: GRE protocol type is not supported."},
            {"Protocol: GRE / EoIP", "Tunnel ID:", "Identity Key:", "EoIP Frame Length:", "Warning: GRE version is not supported."},
        },
    }};

    for (const auto& test_case : cases) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {test_case.file_name}};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == 1U);
        PFL_EXPECT(storage.recognized_packets == 0U);
        PFL_EXPECT(storage.unrecognized_packets == 1U);
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        PFL_EXPECT(session.list_flows().empty());

        const auto details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_gre);
        PFL_EXPECT(!details->gre.is_eoip);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {});
        for (const auto& fragment : test_case.required_protocol_fragments) {
            PFL_EXPECT(protocol_text.find(fragment) != std::string::npos);
        }
        for (const auto& fragment : test_case.forbidden_protocol_fragments) {
            PFL_EXPECT(protocol_text.find(fragment) == std::string::npos);
        }
    }
}

void expect_outer_address_change_does_not_split_eoip_identity() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("26_same_tunnel_same_inner_tuple_different_outer_ipv4_endpoints.pcap")));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == 2U);
    PFL_EXPECT(storage.recognized_packets == 2U);
    PFL_EXPECT(storage.unrecognized_packets == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    const auto& row = rows[0];
    PFL_EXPECT(row.family == FlowAddressFamily::ipv4);
    PFL_EXPECT(row.protocol_text == "UDP");
    PFL_EXPECT(row.packet_count == 2U);
    PFL_EXPECT(
        require_flow_protocol_path_text(session, row) ==
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP"
    );

    const auto packet_rows = effective_flow_packet_rows(session, row.index);
    PFL_REQUIRE(packet_rows.size() == 2U);
    PFL_EXPECT(packet_rows[0].payload_length == 4U);
    PFL_EXPECT(packet_rows[1].payload_length == 4U);
}

void expect_outer_vlan_metadata_stays_in_physical_identity() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("27_same_tunnel_same_inner_tuple_different_outer_vlan_metadata.pcap")));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == 2U);
    PFL_EXPECT(storage.recognized_packets == 2U);
    PFL_EXPECT(storage.unrecognized_packets == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 2U);

    const auto* direct_row = find_flow_with_protocol_path(
        session,
        rows,
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP"
    );
    const auto* vlan_row = find_flow_with_protocol_path(
        session,
        rows,
        "EthernetII -> VLAN(vid=806) -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP"
    );
    PFL_REQUIRE(direct_row != nullptr);
    PFL_REQUIRE(vlan_row != nullptr);
    PFL_EXPECT(direct_row != vlan_row);
    PFL_EXPECT(row_matches_tuple(*direct_row, FlowAddressFamily::ipv4, "UDP", "10.80.0.10", 53800U, "10.80.0.20", 443U));
    PFL_EXPECT(row_matches_tuple(*vlan_row, FlowAddressFamily::ipv4, "UDP", "10.80.0.10", 53800U, "10.80.0.20", 443U));
    PFL_EXPECT(direct_row->packet_count == 1U);
    PFL_EXPECT(vlan_row->packet_count == 1U);
}

void expect_outer_ipv4_fragmented_eoip_packets_do_not_continue() {
    struct Case {
        std::string_view file_name;
        std::size_t expected_packets;
        std::array<std::uint16_t, 2> expected_fragment_fields {};
        bool has_captrunc {false};
    };

    const std::array<Case, 2> cases {{
        {
            "28_ipv4_eoip_first_fragment_mf_complete_inner.pcap",
            1U,
            {0x2000U, 0U},
            false,
        },
        {
            "29_ipv4_eoip_nonfirst_fragment_valid_looking_bytes_captrunc.pcap",
            2U,
            {0x2001U, 0x0002U},
            true,
        },
    }};

    for (const auto& test_case : cases) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {test_case.file_name}};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));
        const auto records = parse_pcap_records(fixture_path(test_case.file_name));
        PFL_REQUIRE(records.size() == test_case.expected_packets);

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == test_case.expected_packets);
        PFL_EXPECT(storage.recognized_packets == 0U);
        PFL_EXPECT(storage.unrecognized_packets == test_case.expected_packets);
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == test_case.expected_packets);
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);

        for (std::size_t packet_index = 0U; packet_index < test_case.expected_packets; ++packet_index) {
            const auto frame = parse_outer_frame(records[packet_index]);
            const auto details = session.read_packet_details(require_packet(session, packet_index));
            PFL_REQUIRE(details.has_value());
            PFL_EXPECT(details->has_ipv4);
            PFL_EXPECT(!details->has_gre);
            PFL_EXPECT(details->ipv4.protocol == kIpv4ProtocolGre);
            PFL_EXPECT(read_be16(frame.bytes, frame.ipv4_offset + 6U) == test_case.expected_fragment_fields[packet_index]);

            const auto summary_layers = session_detail::build_packet_summary_layers(*details, require_packet(session, packet_index));
            PFL_REQUIRE(find_top_level_layer(summary_layers, "ipv4") != nullptr);
            PFL_EXPECT(find_top_level_layer(summary_layers, "gre") == nullptr);
            PFL_EXPECT(find_top_level_layer(summary_layers, "ethernet-inner") == nullptr);
        }

        if (test_case.has_captrunc) {
            const auto records = parse_pcap_records_with_headers(fixture_path(test_case.file_name));
            PFL_REQUIRE(records.size() == 2U);
            PFL_EXPECT(records[1].incl_len < records[1].orig_len);
            const auto captrunc_details = session.read_packet_details(require_packet(session, 1U));
            PFL_REQUIRE(captrunc_details.has_value());
            PFL_EXPECT(captrunc_details->ipv4.available_packet_bytes < captrunc_details->ipv4.total_length);
        }
    }
}

void expect_unsupported_inner_ethernet_continuations_remain_no_flow() {
    struct Case {
        std::size_t packet_index;
        std::uint16_t expected_inner_ether_type;
        bool expect_mpls;
        bool expect_ipv4;
        bool expect_udp;
        bool expect_no_deeper_layers;
    };

    const std::array<Case, 5> cases {{
        {0U, kEtherTypePppoeSession, false, true, true, false},
        {1U, kEtherTypeMpls, true, true, true, false},
        {2U, kEtherTypePbb, false, true, true, false},
        {3U, kEtherTypeMacsec, false, false, false, true},
        {4U, 0x1234U, false, false, false, true},
    }};

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("30_ipv4_eoip_inner_unsupported_ethernet_payloads.pcap")));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == cases.size());
    PFL_EXPECT(storage.recognized_packets == 0U);
    PFL_EXPECT(storage.unrecognized_packets == cases.size());
    PFL_EXPECT(session.summary().packet_count == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == cases.size());
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);

    for (const auto& test_case : cases) {
        const ScopedTestContext packet_context {"packet=" + std::to_string(test_case.packet_index)};
        const auto packet = require_packet(session, test_case.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_gre);
        PFL_EXPECT(details->gre.is_eoip);
        PFL_EXPECT(details->gre.eoip_tunnel_id == 6400U);
        PFL_EXPECT(details->gre.has_inner_ethernet);
        PFL_EXPECT(details->gre.has_inner_packet);
        PFL_REQUIRE(details->gre.inner_packet != nullptr);
        PFL_EXPECT(details->gre.inner_packet->has_inner_ethernet);
        PFL_EXPECT(details->gre.inner_packet->inner_ethernet.ether_type == test_case.expected_inner_ether_type);
        PFL_EXPECT(details->gre.inner_packet->has_mpls == test_case.expect_mpls);
        PFL_EXPECT(details->gre.inner_packet->has_ipv4 == test_case.expect_ipv4);
        PFL_EXPECT(details->gre.inner_packet->has_udp == test_case.expect_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_REQUIRE(find_top_level_layer(summary_layers, "gre") != nullptr);
        PFL_REQUIRE(find_top_level_layer(summary_layers, "ethernet-inner") != nullptr);
        PFL_EXPECT(count_top_level_layers(summary_layers, "mpls") == (test_case.expect_mpls ? 1U : 0U));
        PFL_EXPECT(count_top_level_layers(summary_layers, "ipv4-inner") == (test_case.expect_ipv4 ? 1U : 0U));
        PFL_EXPECT(count_top_level_layers(summary_layers, "udp-inner") == (test_case.expect_udp ? 1U : 0U));
        PFL_EXPECT(count_top_level_layers(summary_layers, "pppoe") == 0U);
        PFL_EXPECT(count_top_level_layers(summary_layers, "pbb") == 0U);
        PFL_EXPECT(count_top_level_layers(summary_layers, "macsec") == 0U);

        if (test_case.expect_no_deeper_layers) {
            PFL_EXPECT(!details->gre.inner_packet->has_ipv4);
            PFL_EXPECT(!details->gre.inner_packet->has_udp);
        }
    }
}

void expect_nested_eoip_is_not_continued() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("31_ipv4_eoip_nested_eoip_not_continued.pcap")));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == 1U);
    PFL_EXPECT(storage.recognized_packets == 0U);
    PFL_EXPECT(storage.unrecognized_packets == 1U);
    PFL_EXPECT(session.summary().packet_count == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_REQUIRE(details->has_gre);
    PFL_EXPECT(details->gre.is_eoip);
    PFL_REQUIRE(details->gre.inner_packet != nullptr);
    PFL_EXPECT(details->gre.inner_packet->has_inner_ethernet);
    PFL_EXPECT(details->gre.inner_packet->inner_ethernet.ether_type == kEtherTypeIpv4);
    PFL_EXPECT(details->gre.inner_packet->has_ipv4);
    PFL_EXPECT(details->gre.inner_packet->ipv4.protocol == kIpv4ProtocolGre);
    PFL_EXPECT(!details->gre.inner_packet->has_udp);
    PFL_EXPECT(!details->gre.inner_packet->has_tcp);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    PFL_EXPECT(count_top_level_layers(summary_layers, "gre") == 1U);
    PFL_EXPECT(count_top_level_layers(summary_layers, "ethernet-inner") == 1U);
    PFL_EXPECT(count_top_level_layers(summary_layers, "ipv4-inner") == 1U);
    PFL_EXPECT(count_top_level_layers(summary_layers, "udp-inner") == 0U);

    const auto protocol_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {});
    PFL_EXPECT(protocol_text.find("Protocol: GRE / EoIP") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Tunnel ID: 6400") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Tunnel ID: 4660") == std::string::npos);
}

void expect_frame_length_does_not_split_same_inner_frame_identity() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("32_same_tunnel_same_inner_frame_different_frame_length.pcap")));

    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.total_packets_seen == 2U);
    PFL_EXPECT(storage.recognized_packets == 2U);
    PFL_EXPECT(storage.unrecognized_packets == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);
    PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].packet_count == 2U);
    PFL_EXPECT(
        require_flow_protocol_path_text(session, rows[0]) ==
        "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP"
    );

    const auto packet_rows = effective_flow_packet_rows(session, rows[0].index);
    PFL_REQUIRE(packet_rows.size() == 2U);
    PFL_EXPECT(packet_rows[0].payload_length == 4U);
    PFL_EXPECT(packet_rows[1].payload_length == 4U);

    const auto first_packet = require_packet(session, 0U);
    const auto second_packet = require_packet(session, 1U);
    const auto first_details = session.read_packet_details(first_packet);
    const auto second_details = session.read_packet_details(second_packet);
    PFL_REQUIRE(first_details.has_value());
    PFL_REQUIRE(second_details.has_value());
    PFL_REQUIRE(first_details->has_gre);
    PFL_REQUIRE(second_details->has_gre);
    PFL_EXPECT(first_details->gre.key == 0x002e0019U);
    PFL_EXPECT(second_details->gre.key == 0x00320019U);
    PFL_EXPECT(first_details->gre.eoip_tunnel_id == 6400U);
    PFL_EXPECT(second_details->gre.eoip_tunnel_id == 6400U);
    PFL_EXPECT(first_details->gre.eoip_frame_length == 46U);
    PFL_EXPECT(second_details->gre.eoip_frame_length == 50U);

    const auto first_payload = session.read_selected_flow_transport_payload(rows[0].index, first_packet);
    const auto second_payload = session.read_selected_flow_transport_payload(rows[0].index, second_packet);
    PFL_EXPECT(first_payload.empty());
    PFL_EXPECT(first_payload == second_payload);
}

void expect_tunnel_id_path_representation_contract() {
    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("07_outer_vlan_mpls2_ipv4_eoip_inner_vlan_ipv4_udp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
        PFL_EXPECT(
            require_flow_protocol_path_text(session, rows[0]) ==
            "EthernetII -> VLAN(vid=406) -> MPLS(label=56474) -> MPLS(label=477436) -> IPv4 -> GRE(key=0x00000019) -> EthernetII -> VLAN(vid=3918) -> IPv4 -> UDP"
        );

        const auto details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_gre);
        PFL_EXPECT(details->gre.key == 0x00321900U);
        PFL_EXPECT(details->gre.eoip_tunnel_id == 25U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("08_same_inner_tuple_different_tunnel_ids.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);
        PFL_REQUIRE(find_flow_with_protocol_path(
            session,
            rows,
            "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP"
        ) != nullptr);
        PFL_REQUIRE(find_flow_with_protocol_path(
            session,
            rows,
            "EthernetII -> IPv4 -> GRE(key=0x00001901) -> EthernetII -> IPv4 -> UDP"
        ) != nullptr);
    }
}

void expect_representative_eoip_presentation_contracts() {
    struct PresentationCase {
        std::string_view file_name;
        std::vector<std::string> expected_layer_ids;
        std::size_t expected_inner_vlan_layer_count;
        std::size_t expected_mpls_layer_count;
        std::uint16_t expected_tunnel_id;
        std::uint16_t expected_frame_length;
        std::uint32_t expected_raw_key;
        std::uint32_t expected_identity_key;
        std::optional<std::uint32_t> expected_udp_payload_length;
    };

    const std::array<PresentationCase, 5> cases {{
        {
            "01_ipv4_eoip_inner_ipv4_udp.pcap",
            {"frame", "ethernet", "ipv4", "gre", "ethernet-inner", "ipv4-inner", "udp-inner"},
            0U,
            0U,
            6400U,
            46U,
            0x002e0019U,
            0x00001900U,
            4U,
        },
        {
            "04_ipv4_eoip_inner_vlan_ipv4_udp.pcap",
            {"frame", "ethernet", "ipv4", "gre", "ethernet-inner", "vlan-inner", "ipv4-inner", "udp-inner"},
            1U,
            0U,
            6400U,
            50U,
            0x00320019U,
            0x00001900U,
            4U,
        },
        {
            "05_ipv4_eoip_inner_qinq_ipv6_tcp.pcap",
            {"frame", "ethernet", "ipv4", "gre", "ethernet-inner", "vlan-inner", "vlan-inner", "ipv6-inner", "tcp-inner"},
            2U,
            0U,
            6400U,
            82U,
            0x00520019U,
            0x00001900U,
            std::nullopt,
        },
        {
            "07_outer_vlan_mpls2_ipv4_eoip_inner_vlan_ipv4_udp.pcap",
            {"frame", "ethernet", "vlan", "mpls", "mpls", "ipv4", "gre", "ethernet-inner", "vlan-inner", "ipv4-inner", "udp-inner"},
            1U,
            2U,
            25U,
            50U,
            0x00321900U,
            0x00000019U,
            4U,
        },
        {
            "11_max_tunnel_id.pcap",
            {"frame", "ethernet", "ipv4", "gre", "ethernet-inner", "ipv4-inner", "udp-inner"},
            0U,
            0U,
            65535U,
            46U,
            0x002effffU,
            0x0000ffffU,
            4U,
        },
    }};

    for (const auto& test_case : cases) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_gre);
        PFL_EXPECT(details->gre.is_eoip);
        PFL_EXPECT(details->gre.has_key);
        PFL_EXPECT(details->gre.key == test_case.expected_raw_key);
        PFL_EXPECT(details->gre.eoip_tunnel_id == test_case.expected_tunnel_id);
        PFL_EXPECT(details->gre.eoip_frame_length == test_case.expected_frame_length);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_top_level_layers_present(summary_layers, test_case.expected_layer_ids);
        PFL_EXPECT(count_top_level_layers(summary_layers, "vlan-inner") == test_case.expected_inner_vlan_layer_count);
        PFL_EXPECT(count_top_level_layers(summary_layers, "mpls") == test_case.expected_mpls_layer_count);

        const auto* gre_layer = find_top_level_layer(summary_layers, "gre");
        const auto* inner_ethernet_layer = find_top_level_layer(summary_layers, "ethernet-inner");
        PFL_REQUIRE(gre_layer != nullptr);
        PFL_REQUIRE(inner_ethernet_layer != nullptr);
        PFL_EXPECT(gre_layer->title.find("GRE") != std::string::npos);
        PFL_EXPECT(title_contains_all(*inner_ethernet_layer, {"Inner Ethernet"}));
        PFL_EXPECT(layer_has_field_containing(*gre_layer, "Key Present", "Yes"));
        PFL_EXPECT(layer_has_field_containing(*gre_layer, "Raw GRE Key", format_hex32_for_test(test_case.expected_raw_key)));
        PFL_EXPECT(layer_has_field_containing(*gre_layer, "EoIP Frame Length", std::to_string(test_case.expected_frame_length) + " bytes"));
        PFL_EXPECT(layer_has_field_containing(*gre_layer, "Tunnel ID", std::to_string(test_case.expected_tunnel_id)));
        PFL_EXPECT(layer_has_field_containing(
            *gre_layer,
            "Identity Key",
            format_hex32_for_test(test_case.expected_identity_key)
        ));

        if (test_case.expected_udp_payload_length.has_value()) {
            const auto* udp_layer = find_top_level_layer(summary_layers, "udp-inner");
            PFL_REQUIRE(udp_layer != nullptr);
            PFL_EXPECT(layer_has_field_containing(
                *udp_layer,
                "Payload Length",
                std::to_string(*test_case.expected_udp_payload_length) + " bytes"
            ));
        }

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {});
        PFL_EXPECT(protocol_text.find("Protocol: GRE / EoIP") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Key Present: Yes") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Raw GRE Key: " + format_hex32_for_test(test_case.expected_raw_key))
            != std::string::npos);
        PFL_EXPECT(protocol_text.find("EoIP Frame Length: " + std::to_string(test_case.expected_frame_length) + " bytes")
            != std::string::npos);
        PFL_EXPECT(protocol_text.find(
            "Tunnel ID: " + std::to_string(test_case.expected_tunnel_id) + " (" +
            format_hex16_for_test(test_case.expected_tunnel_id) + ')'
        ) != std::string::npos);
        PFL_EXPECT(protocol_text.find("Identity Key: " + format_hex32_for_test(test_case.expected_identity_key))
            != std::string::npos);
        if (test_case.expected_udp_payload_length.has_value()) {
            PFL_EXPECT(protocol_text.find("Inner UDP:") != std::string::npos);
            PFL_EXPECT(protocol_text.find(
                "Payload Length: " + std::to_string(*test_case.expected_udp_payload_length) + " bytes"
            ) != std::string::npos);
        }
    }
}

void expect_fixture_09_distinguishes_raw_key_from_identity_key() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("09_same_tunnel_id_different_inner_payload_lengths.pcap")));

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_REQUIRE(session.list_flow_packets(rows[0].index).size() == 2U);

    const auto first_details = session.read_packet_details(require_packet(session, 0U));
    const auto second_details = session.read_packet_details(require_packet(session, 1U));
    PFL_REQUIRE(first_details.has_value());
    PFL_REQUIRE(second_details.has_value());
    PFL_REQUIRE(first_details->has_gre);
    PFL_REQUIRE(second_details->has_gre);
    PFL_EXPECT(first_details->gre.key == 0x002e0019U);
    PFL_EXPECT(second_details->gre.key == 0x00360019U);
    PFL_EXPECT(first_details->gre.key != second_details->gre.key);
    PFL_EXPECT(first_details->gre.eoip_tunnel_id == 6400U);
    PFL_EXPECT(second_details->gre.eoip_tunnel_id == 6400U);

    const auto first_text = session_detail::build_basic_protocol_details_text(*first_details).value_or(std::string {});
    const auto second_text = session_detail::build_basic_protocol_details_text(*second_details).value_or(std::string {});
    PFL_EXPECT(first_text.find("Raw GRE Key: 0x002e0019") != std::string::npos);
    PFL_EXPECT(second_text.find("Raw GRE Key: 0x00360019") != std::string::npos);
    PFL_EXPECT(first_text.find("Identity Key: 0x00001900") != std::string::npos);
    PFL_EXPECT(second_text.find("Identity Key: 0x00001900") != std::string::npos);
    PFL_EXPECT(first_text.find("Payload Length: 4 bytes") != std::string::npos);
    PFL_EXPECT(second_text.find("Payload Length: 12 bytes") != std::string::npos);
}

void expect_representative_malformed_eoip_detail_warnings() {
    struct MalformedCase {
        std::string_view file_name;
        bool expect_eoip;
        bool expect_eoip_header_truncated;
        bool expect_declared_frame_exceeds_available;
        bool expect_inner_ethernet_truncated;
        bool expect_inner_vlan_truncated;
        std::vector<std::string> required_protocol_fragments;
    };

    const std::array<MalformedCase, 5> cases {{
        {
            "12_truncated_eoip_key_word.pcap",
            true,
            true,
            false,
            false,
            false,
            {"Warning: EoIP header is truncated."},
        },
        {
            "13_eoip_payload_length_exceeds_available.pcap",
            true,
            false,
            true,
            false,
            false,
            {"Warning: EoIP payload length exceeds available inner frame bytes."},
        },
        {
            "14_eoip_payload_length_smaller_than_inner_frame.pcap",
            true,
            false,
            false,
            true,
            false,
            {"Warning: Inner Ethernet header is truncated."},
        },
        {
            "17_eoip_truncated_inner_ethernet.pcap",
            true,
            false,
            false,
            true,
            false,
            {"Warning: Inner Ethernet header is truncated."},
        },
        {
            "18_eoip_truncated_inner_vlan.pcap",
            true,
            false,
            false,
            false,
            true,
            {"Warning: Inner VLAN header is truncated."},
        },
    }};

    for (const auto& test_case : cases) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(test_case.file_name)));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->has_gre);
        PFL_EXPECT(details->gre.is_eoip == test_case.expect_eoip);
        PFL_EXPECT(details->gre.eoip_header_truncated == test_case.expect_eoip_header_truncated);
        PFL_EXPECT(
            details->gre.eoip_declared_frame_exceeds_available == test_case.expect_declared_frame_exceeds_available
        );
        PFL_EXPECT(details->gre.inner_ethernet_truncated == test_case.expect_inner_ethernet_truncated);
        PFL_EXPECT(details->gre.inner_vlan_truncated == test_case.expect_inner_vlan_truncated);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {});
        if (test_case.expect_eoip) {
            PFL_EXPECT(protocol_text.find("Protocol: GRE / EoIP") != std::string::npos);
        }
        for (const auto& fragment : test_case.required_protocol_fragments) {
            PFL_EXPECT(protocol_text.find(fragment) != std::string::npos);
        }

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        if (test_case.file_name == "14_eoip_payload_length_smaller_than_inner_frame.pcap") {
            const auto* inner_ethernet_layer = find_top_level_layer(summary_layers, "ethernet-inner");
            PFL_REQUIRE(inner_ethernet_layer != nullptr);
            PFL_EXPECT(layer_has_field_containing(*inner_ethernet_layer, "Available Header Bytes", "10 / 14"));
            PFL_EXPECT(layer_has_field_containing(*inner_ethernet_layer, "Destination", ":"));
            PFL_EXPECT(!layer_has_field_containing(*inner_ethernet_layer, "Source", ":"));
            PFL_EXPECT(!layer_has_field_containing(*inner_ethernet_layer, "Type", "0x"));
            PFL_EXPECT(find_top_level_layer(summary_layers, "ipv4-inner") == nullptr);
            PFL_EXPECT(find_top_level_layer(summary_layers, "udp-inner") == nullptr);
            PFL_EXPECT(protocol_text.find("Inner EtherType:") == std::string::npos);
            PFL_EXPECT(protocol_text.find("Inner IPv4:") == std::string::npos);
            PFL_EXPECT(protocol_text.find("Inner UDP:") == std::string::npos);
        }

        if (test_case.file_name == "18_eoip_truncated_inner_vlan.pcap") {
            const auto* vlan_layer = find_top_level_layer(summary_layers, "vlan-inner");
            PFL_REQUIRE(vlan_layer != nullptr);
            PFL_EXPECT(vlan_layer->title.find("Inner VLAN, ID: 1806") != std::string::npos);
            PFL_EXPECT(layer_has_field_containing(*vlan_layer, "Available Header Bytes", "2 / 4"));
            PFL_EXPECT(layer_has_field_containing(*vlan_layer, "VLAN ID", "1806"));
            PFL_EXPECT(protocol_text.find("Inner VLAN: 1806") != std::string::npos);
            PFL_EXPECT(protocol_text.find("Available Header Bytes: 2 / 4") != std::string::npos);
        }
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
    expect_fixture_11_wire_layout();
    expect_fixture_19_llc_snap_wire_layout();
    expect_gre_eoip_ambiguity_wire_layouts();
    expect_fixture_26_and_27_identity_wire_layouts();
    expect_fragmentation_fixture_wire_layouts();
    expect_unsupported_inner_ethernet_fixture_wire_layout();
    expect_fixture_31_nested_eoip_wire_layout();
    expect_fixture_32_wire_layout();
    expect_malformed_fixture_layouts();

    expect_positive_parser_expectations();
    expect_malformed_eoip_fixtures_remain_conservative();
    expect_fixture_19_llc_snap_continuation();
    expect_missing_key_and_unsupported_v1_do_not_claim_eoip();
    expect_gre_ambiguity_recognized_flows_do_not_claim_eoip();
    expect_gre_ambiguity_no_flow_cases_do_not_claim_eoip();
    expect_outer_address_change_does_not_split_eoip_identity();
    expect_outer_vlan_metadata_stays_in_physical_identity();
    expect_outer_ipv4_fragmented_eoip_packets_do_not_continue();
    expect_unsupported_inner_ethernet_continuations_remain_no_flow();
    expect_nested_eoip_is_not_continued();
    expect_frame_length_does_not_split_same_inner_frame_identity();
    expect_tunnel_id_path_representation_contract();
    expect_representative_eoip_presentation_contracts();
    expect_fixture_09_distinguishes_raw_key_from_identity_key();
    expect_representative_malformed_eoip_detail_warnings();
}

}  // namespace pfl::tests
