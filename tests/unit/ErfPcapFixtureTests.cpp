#include "TestSupport.h"

#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "core/domain/PacketRef.h"
#include "core/domain/ProtocolPath.h"
#include "core/io/LinkType.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace pfl::tests {
namespace {

constexpr std::uint32_t kLinkTypeErfForFixture = 197U;
constexpr std::size_t kPcapGlobalHeaderSize = 24U;
constexpr std::size_t kPcapPacketHeaderSize = 16U;
constexpr std::size_t kErfGenericHeaderSize = 16U;
constexpr std::size_t kErfTypeEthMetadataSize = 2U;
constexpr std::uint8_t kErfTypeExtensionPresent = 0x80U;
constexpr std::uint8_t kErfBaseTypeEth = 0x02U;
constexpr std::uint16_t kErfClientTcpPort = 50123U;
constexpr std::uint16_t kErfServerTlsPort = 443U;

std::filesystem::path fixture_path(const std::string_view file_name) {
    return std::filesystem::path(__FILE__).parent_path().parent_path()
        / "data" / "parsing" / "erf" / std::string(file_name);
}

bool contains_text(const std::string& text, const std::string_view needle) {
    return text.find(needle) != std::string::npos;
}

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    PFL_REQUIRE(stream.is_open());
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

std::uint16_t read_be16(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    PFL_REQUIRE(offset + 2U <= bytes.size());
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U)
                                      | static_cast<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t read_be32(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    PFL_REQUIRE(offset + 4U <= bytes.size());
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U)
        | (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U)
        | (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U)
        | static_cast<std::uint32_t>(bytes[offset + 3U]);
}

std::uint32_t read_le32(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    PFL_REQUIRE(offset + 4U <= bytes.size());
    return static_cast<std::uint32_t>(bytes[offset])
        | (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U)
        | (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U)
        | (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}

struct ParsedPcapPacket {
    std::uint32_t link_type {};
    std::uint32_t captured_length {};
    std::uint32_t original_length {};
    std::vector<std::uint8_t> payload {};
};

ParsedPcapPacket read_single_packet_fixture(const std::string_view file_name) {
    const auto bytes = read_file_bytes(fixture_path(file_name));
    PFL_REQUIRE(bytes.size() >= kPcapGlobalHeaderSize + kPcapPacketHeaderSize);

    ParsedPcapPacket packet {};
    packet.link_type = read_le32(bytes, 20U);
    packet.captured_length = read_le32(bytes, kPcapGlobalHeaderSize + 8U);
    packet.original_length = read_le32(bytes, kPcapGlobalHeaderSize + 12U);

    const auto payload_offset = kPcapGlobalHeaderSize + kPcapPacketHeaderSize;
    PFL_REQUIRE(payload_offset + packet.captured_length <= bytes.size());
    packet.payload.assign(
        bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset + packet.captured_length));
    return packet;
}

std::uint8_t erf_base_type(const ParsedPcapPacket& packet) {
    PFL_REQUIRE(packet.payload.size() >= kErfGenericHeaderSize);
    return static_cast<std::uint8_t>(packet.payload[8U] & ~kErfTypeExtensionPresent);
}

bool erf_has_extension_header(const ParsedPcapPacket& packet) {
    PFL_REQUIRE(packet.payload.size() >= kErfGenericHeaderSize);
    return (packet.payload[8U] & kErfTypeExtensionPresent) != 0U;
}

std::size_t erf_network_payload_offset(const std::vector<std::uint8_t>& payload) {
    PFL_REQUIRE(payload.size() >= kErfGenericHeaderSize);
    PFL_REQUIRE(static_cast<std::uint8_t>(payload[8U] & ~kErfTypeExtensionPresent) == kErfBaseTypeEth);

    auto offset = kErfGenericHeaderSize;
    if ((payload[8U] & kErfTypeExtensionPresent) != 0U) {
        bool has_more_extensions = true;
        while (has_more_extensions) {
            PFL_REQUIRE(offset + 8U <= payload.size());
            has_more_extensions = (payload[offset] & kErfTypeExtensionPresent) != 0U;
            offset += 8U;
        }
    }

    offset += kErfTypeEthMetadataSize;
    PFL_REQUIRE(offset <= payload.size());
    return offset;
}

std::vector<std::uint8_t> erf_network_payload(const ParsedPcapPacket& packet) {
    const auto offset = erf_network_payload_offset(packet.payload);
    return {
        packet.payload.begin() + static_cast<std::ptrdiff_t>(offset),
        packet.payload.end(),
    };
}

std::uint16_t erf_record_length(const ParsedPcapPacket& packet) {
    return read_be16(packet.payload, 10U);
}

std::uint16_t erf_wire_length(const ParsedPcapPacket& packet) {
    return read_be16(packet.payload, 14U);
}

const PacketRef& require_packet(CaptureSession& session, const std::size_t index) {
    auto packet = session.find_packet(index);
    PFL_REQUIRE(packet.has_value());
    return *packet;
}

ProtocolId flow_protocol_id(const FlowRow& row) {
    return std::visit([](const auto& key) { return key.protocol; }, row.key);
}

std::string require_protocol_path_text(const CaptureSession& session, const FlowRow& row) {
    const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
    PFL_REQUIRE(path != nullptr);
    return format_protocol_path(*path);
}

void expect_erf_wire_fixture_contract() {
    const auto reference = read_single_packet_fixture("00_reference_ethernet_ipv4_tcp.pcap");
    const auto erf_ipv4_tcp = read_single_packet_fixture("01_erf_eth_ipv4_tcp.pcap");
    const auto erf_ipv6_udp = read_single_packet_fixture("02_erf_eth_ipv6_udp.pcap");
    const auto erf_vlan_ipv4_udp = read_single_packet_fixture("03_erf_eth_vlan_ipv4_udp.pcap");
    const auto erf_tls = read_single_packet_fixture("04_erf_eth_ipv4_tcp_tls_client_hello.pcap");
    const auto erf_with_extension = read_single_packet_fixture("05_erf_eth_extension_header_ipv4_tcp.pcap");
    const auto erf_truncated_network = read_single_packet_fixture("06_erf_eth_truncated_network_packet.pcap");
    const auto erf_unsupported = read_single_packet_fixture("07_erf_unsupported_record_type.pcap");
    const auto erf_truncated_base = read_single_packet_fixture("08_erf_truncated_base_header.pcap");
    const auto erf_truncated_extension = read_single_packet_fixture("09_erf_truncated_extension_header.pcap");

    PFL_EXPECT(reference.link_type == kLinkTypeEthernet);
    PFL_EXPECT(reference.captured_length == 120U);
    PFL_EXPECT(reference.original_length == 120U);

    const std::vector<const ParsedPcapPacket*> valid_type_eth {
        &erf_ipv4_tcp,
        &erf_ipv6_udp,
        &erf_vlan_ipv4_udp,
        &erf_tls,
        &erf_with_extension,
        &erf_truncated_network,
    };
    for (const auto* packet : valid_type_eth) {
        PFL_REQUIRE(packet != nullptr);
        PFL_EXPECT(packet->link_type == kLinkTypeErfForFixture);
        PFL_EXPECT(erf_base_type(*packet) == kErfBaseTypeEth);
    }

    PFL_EXPECT(erf_network_payload(erf_ipv4_tcp) == reference.payload);
    PFL_EXPECT(!erf_has_extension_header(erf_ipv4_tcp));
    PFL_EXPECT(erf_record_length(erf_ipv4_tcp) == erf_ipv4_tcp.payload.size());
    PFL_EXPECT(erf_wire_length(erf_ipv4_tcp) == reference.payload.size());

    PFL_EXPECT(erf_record_length(erf_ipv6_udp) == 138U);
    PFL_EXPECT(erf_wire_length(erf_ipv6_udp) == 120U);
    PFL_EXPECT(erf_record_length(erf_vlan_ipv4_udp) == 114U);
    PFL_EXPECT(erf_wire_length(erf_vlan_ipv4_udp) == 96U);
    PFL_EXPECT(erf_record_length(erf_tls) == 168U);
    PFL_EXPECT(erf_wire_length(erf_tls) == 150U);

    PFL_EXPECT(erf_has_extension_header(erf_with_extension));
    PFL_EXPECT(erf_with_extension.payload[16U] == 0x10U);
    PFL_EXPECT(read_be32(erf_with_extension.payload, 20U) == 0x04'05'06'07U);
    PFL_EXPECT(erf_network_payload_offset(erf_with_extension.payload) == 26U);
    PFL_EXPECT(erf_record_length(erf_with_extension) == 129U);
    PFL_EXPECT(erf_wire_length(erf_with_extension) == 103U);

    PFL_EXPECT(erf_record_length(erf_truncated_network) == 80U);
    PFL_EXPECT(erf_wire_length(erf_truncated_network) == 175U);
    PFL_EXPECT(erf_network_payload(erf_truncated_network).size() == 62U);
    PFL_EXPECT(erf_network_payload(erf_truncated_network).size() < erf_wire_length(erf_truncated_network));

    PFL_EXPECT(erf_unsupported.link_type == kLinkTypeErfForFixture);
    PFL_REQUIRE(erf_unsupported.payload.size() >= kErfGenericHeaderSize);
    PFL_EXPECT(erf_base_type(erf_unsupported) == 0x01U);
    PFL_EXPECT(erf_record_length(erf_unsupported) == 51U);
    PFL_EXPECT(erf_wire_length(erf_unsupported) == 35U);

    PFL_EXPECT(erf_truncated_base.link_type == kLinkTypeErfForFixture);
    PFL_EXPECT(erf_truncated_base.captured_length == 8U);
    PFL_EXPECT(erf_truncated_base.original_length == kErfGenericHeaderSize);
    PFL_EXPECT(erf_truncated_base.payload.size() == 8U);

    PFL_EXPECT(erf_truncated_extension.link_type == kLinkTypeErfForFixture);
    PFL_REQUIRE(erf_truncated_extension.payload.size() == 20U);
    PFL_EXPECT(erf_has_extension_header(erf_truncated_extension));
    PFL_EXPECT(erf_record_length(erf_truncated_extension) == 110U);
}

void expect_reference_ethernet_fixture_opens() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("00_reference_ethernet_ipv4_tcp.pcap")));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto stats = session.packet_statistics();
    PFL_EXPECT(stats.total_packet_count == 1U);
    PFL_EXPECT(stats.total_captured_bytes == 120U);
    PFL_EXPECT(stats.total_original_bytes == 120U);
    PFL_EXPECT(stats.truncated_packet_count == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    const auto& row = rows.front();
    PFL_EXPECT(row.address_a == "192.0.2.200");
    PFL_EXPECT(row.port_a == kErfClientTcpPort);
    PFL_EXPECT(row.address_b == "192.0.2.210");
    PFL_EXPECT(row.port_b == kErfServerTlsPort);
    PFL_EXPECT(flow_protocol_id(row) == ProtocolId::tcp);
    PFL_EXPECT(row.packet_count == 1U);
    PFL_EXPECT(row.total_bytes == 120U);
    PFL_EXPECT(require_protocol_path_text(session, row) == "EthernetII -> IPv4 -> TCP");

    const auto& packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == kLinkTypeEthernet);
    PFL_EXPECT(packet.byte_offset == 40U);
    PFL_EXPECT(packet.captured_length == 120U);
    PFL_EXPECT(packet.original_length == 120U);
}

void expect_current_erf_link_type_is_rejected() {
    CaptureSession session {};
    PFL_EXPECT(!session.open_capture(fixture_path("01_erf_eth_ipv4_tcp.pcap")));
    PFL_EXPECT(!session.has_capture());
    PFL_EXPECT(session.summary().packet_count == 0U);
    PFL_EXPECT(session.summary().flow_count == 0U);
    PFL_EXPECT(contains_text(session.last_open_error_text(), "unsupported capture link type"));
}

void document_future_erf_transition_targets() {
    // TODO(ERF support): Future implementation pass transition:
    // 01: open LINKTYPE_ERF TYPE_ETH, emit one IPv4/TCP Flow, use Ethernet PacketRef root,
    //     use network lengths 120/120, keep Protocol Path "EthernetII -> IPv4 -> TCP",
    //     keep ERF out of Protocol Path, and match fixture 00 network analytics.
    // 02: continue through Ethernet into IPv6/UDP.
    // 03: continue through Ethernet/VLAN into IPv4/UDP and preserve VLAN VID 420.
    // 04: reuse existing TLS detection and service/SNI "erf.example.test".
    // 05: traverse one bounded ERF extension header before Ethernet; extension bytes are
    //     capture framing and do not enter network length calculations.
    // 06: use captured network length 62 and original network length ERF wlen 175;
    //     existing truncation semantics apply.
    // 07: once ERF root opens, keep unsupported non-TYPE_ETH records conservative and
    //     unrecognized with no fabricated Ethernet Flow.
    // 08/09: once ERF root opens, keep malformed/truncated records bounded,
    //     unrecognized, and non-crashing with no fabricated Flow.
    // Selected-packet target after an ERF envelope model exists:
    //     Frame -> Extensible Record Format -> Ethernet II -> IPv4/IPv6 -> TCP/UDP.
    // ERF remains source-backed capture-envelope metadata, not Protocol Path identity.
}

} // namespace

void run_erf_pcap_fixture_tests() {
    expect_erf_wire_fixture_contract();
    expect_reference_ethernet_fixture_opens();
    expect_current_erf_link_type_is_rejected();
    document_future_erf_transition_targets();
}

} // namespace pfl::tests
