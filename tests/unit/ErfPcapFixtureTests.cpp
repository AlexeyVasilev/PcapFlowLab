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

constexpr std::size_t kPcapGlobalHeaderSize = 24U;
constexpr std::size_t kPcapPacketHeaderSize = 16U;
constexpr std::size_t kErfGenericHeaderSize = 16U;
constexpr std::size_t kErfTypeEthMetadataSize = 2U;
constexpr std::uint32_t kPcapNgSectionHeaderBlockType = 0x0a0d0d0aU;
constexpr std::uint32_t kPcapNgInterfaceDescriptionBlockType = 0x00000001U;
constexpr std::uint32_t kPcapNgEnhancedPacketBlockType = 0x00000006U;
constexpr std::size_t kPcapNgSectionHeaderBlockLength = 28U;
constexpr std::size_t kPcapNgInterfaceDescriptionBlockLength = 20U;
constexpr std::size_t kPcapNgEnhancedPacketFixedBodyLength = 20U;
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

std::filesystem::path require_fixture_file(const std::string_view file_name) {
    const auto path = fixture_path(file_name);
    PFL_REQUIRE(std::filesystem::exists(path));
    PFL_REQUIRE(std::filesystem::is_regular_file(path));
    return path;
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

std::uint16_t read_le16(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    PFL_REQUIRE(offset + 2U <= bytes.size());
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset])
                                      | (static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U));
}

struct ParsedPcapPacket {
    std::uint32_t link_type {};
    std::uint32_t captured_length {};
    std::uint32_t original_length {};
    std::vector<std::uint8_t> payload {};
};

ParsedPcapPacket read_single_packet_path(const std::filesystem::path& path);

ParsedPcapPacket read_single_packet_fixture(const std::string_view file_name) {
    return read_single_packet_path(require_fixture_file(file_name));
}

ParsedPcapPacket read_single_packet_path(const std::filesystem::path& path) {
    const auto bytes = read_file_bytes(path);
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

ParsedPcapPacket read_single_packet_pcapng_fixture(const std::string_view file_name) {
    const auto bytes = read_file_bytes(require_fixture_file(file_name));
    PFL_REQUIRE(bytes.size() >= kPcapNgSectionHeaderBlockLength + kPcapNgInterfaceDescriptionBlockLength + 32U);

    std::size_t offset = 0U;
    PFL_REQUIRE(read_le32(bytes, offset) == kPcapNgSectionHeaderBlockType);
    const auto section_length = read_le32(bytes, offset + 4U);
    PFL_REQUIRE(section_length == kPcapNgSectionHeaderBlockLength);
    PFL_REQUIRE(read_le32(bytes, offset + section_length - 4U) == section_length);
    offset += section_length;

    PFL_REQUIRE(read_le32(bytes, offset) == kPcapNgInterfaceDescriptionBlockType);
    const auto interface_length = read_le32(bytes, offset + 4U);
    PFL_REQUIRE(interface_length == kPcapNgInterfaceDescriptionBlockLength);
    const auto link_type = read_le16(bytes, offset + 8U);
    PFL_REQUIRE(read_le32(bytes, offset + interface_length - 4U) == interface_length);
    offset += interface_length;

    PFL_REQUIRE(read_le32(bytes, offset) == kPcapNgEnhancedPacketBlockType);
    const auto enhanced_packet_length = read_le32(bytes, offset + 4U);
    const auto body_offset = offset + 8U;
    const auto interface_id = read_le32(bytes, body_offset);
    const auto captured_length = read_le32(bytes, body_offset + 12U);
    const auto original_length = read_le32(bytes, body_offset + 16U);
    const auto payload_offset = body_offset + kPcapNgEnhancedPacketFixedBodyLength;
    const auto padding_length = (4U - (captured_length % 4U)) % 4U;
    PFL_REQUIRE(payload_offset + captured_length <= bytes.size());
    PFL_REQUIRE(offset + enhanced_packet_length <= bytes.size());
    PFL_REQUIRE(enhanced_packet_length == 12U + kPcapNgEnhancedPacketFixedBodyLength + captured_length + padding_length);
    PFL_REQUIRE(read_le32(bytes, offset + enhanced_packet_length - 4U) == enhanced_packet_length);
    PFL_EXPECT(interface_id == 0U);

    ParsedPcapPacket packet {};
    packet.link_type = link_type;
    packet.captured_length = captured_length;
    packet.original_length = original_length;
    packet.payload.assign(
        bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset + captured_length));
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

PacketRef require_packet(CaptureSession& session, const std::size_t index) {
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
    const auto pcapng_erf_ipv4_tcp =
        read_single_packet_pcapng_fixture("10_pcapng_erf_eth_ipv4_tcp_real_style.pcapng");

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
        PFL_EXPECT(packet->link_type == kLinkTypeErf);
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

    PFL_EXPECT(erf_unsupported.link_type == kLinkTypeErf);
    PFL_REQUIRE(erf_unsupported.payload.size() >= kErfGenericHeaderSize);
    PFL_EXPECT(erf_base_type(erf_unsupported) == 0x01U);
    PFL_EXPECT(erf_record_length(erf_unsupported) == 51U);
    PFL_EXPECT(erf_wire_length(erf_unsupported) == 35U);

    PFL_EXPECT(erf_truncated_base.link_type == kLinkTypeErf);
    PFL_EXPECT(erf_truncated_base.captured_length == 8U);
    PFL_EXPECT(erf_truncated_base.original_length == kErfGenericHeaderSize);
    PFL_EXPECT(erf_truncated_base.payload.size() == 8U);

    PFL_EXPECT(erf_truncated_extension.link_type == kLinkTypeErf);
    PFL_REQUIRE(erf_truncated_extension.payload.size() == 20U);
    PFL_EXPECT(erf_has_extension_header(erf_truncated_extension));
    PFL_EXPECT(erf_record_length(erf_truncated_extension) == 110U);

    PFL_EXPECT(pcapng_erf_ipv4_tcp.link_type == kLinkTypeErf);
    PFL_EXPECT(pcapng_erf_ipv4_tcp.captured_length == erf_ipv4_tcp.captured_length);
    PFL_EXPECT(pcapng_erf_ipv4_tcp.original_length == erf_ipv4_tcp.original_length);
    PFL_EXPECT(erf_base_type(pcapng_erf_ipv4_tcp) == kErfBaseTypeEth);
    PFL_REQUIRE(pcapng_erf_ipv4_tcp.payload.size() >= kErfGenericHeaderSize + kErfTypeEthMetadataSize);
    PFL_EXPECT(pcapng_erf_ipv4_tcp.payload[9U] == 0x06U);
    PFL_EXPECT(pcapng_erf_ipv4_tcp.payload[16U] == 0x48U);
    PFL_EXPECT(pcapng_erf_ipv4_tcp.payload[17U] == 0x21U);
    PFL_EXPECT(erf_record_length(pcapng_erf_ipv4_tcp) == pcapng_erf_ipv4_tcp.payload.size());
    PFL_EXPECT(erf_wire_length(pcapng_erf_ipv4_tcp) == reference.payload.size());
    PFL_EXPECT(erf_network_payload(pcapng_erf_ipv4_tcp) == reference.payload);
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

void expect_erf_ipv4_tcp_matches_reference_network_semantics() {
    CaptureSession reference_session {};
    PFL_REQUIRE(reference_session.open_capture(fixture_path("00_reference_ethernet_ipv4_tcp.pcap")));

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("01_erf_eth_ipv4_tcp.pcap")));
    PFL_EXPECT(session.summary().packet_count == reference_session.summary().packet_count);
    PFL_EXPECT(session.summary().flow_count == reference_session.summary().flow_count);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto reference_stats = reference_session.packet_statistics();
    const auto stats = session.packet_statistics();
    PFL_EXPECT(stats.total_packet_count == reference_stats.total_packet_count);
    PFL_EXPECT(stats.total_captured_bytes == reference_stats.total_captured_bytes);
    PFL_EXPECT(stats.total_original_bytes == reference_stats.total_original_bytes);
    PFL_EXPECT(stats.truncated_packet_count == reference_stats.truncated_packet_count);

    const auto reference_rows = reference_session.list_flows();
    const auto rows = session.list_flows();
    PFL_REQUIRE(reference_rows.size() == 1U);
    PFL_REQUIRE(rows.size() == 1U);
    const auto& reference_row = reference_rows.front();
    const auto& row = rows.front();
    PFL_EXPECT(row.address_a == reference_row.address_a);
    PFL_EXPECT(row.port_a == reference_row.port_a);
    PFL_EXPECT(row.address_b == reference_row.address_b);
    PFL_EXPECT(row.port_b == reference_row.port_b);
    PFL_EXPECT(flow_protocol_id(row) == flow_protocol_id(reference_row));
    PFL_EXPECT(row.packet_count == reference_row.packet_count);
    PFL_EXPECT(row.total_bytes == reference_row.total_bytes);
    PFL_EXPECT(row.protocol_hint == reference_row.protocol_hint);
    PFL_EXPECT(row.service_hint == reference_row.service_hint);
    PFL_EXPECT(require_protocol_path_text(session, row) == "EthernetII -> IPv4 -> TCP");

    const auto& packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == kLinkTypeEthernet);
    PFL_EXPECT(packet.byte_offset == 58U);
    PFL_EXPECT(packet.captured_length == 120U);
    PFL_EXPECT(packet.original_length == 120U);

    const auto reference_packet_bytes = reference_session.read_packet_data(require_packet(reference_session, 0U));
    const auto packet_bytes = session.read_packet_data(packet);
    PFL_EXPECT(packet_bytes == reference_packet_bytes);
}

void expect_pcapng_erf_ipv4_tcp_matches_reference_network_semantics() {
    CaptureSession reference_session {};
    PFL_REQUIRE(reference_session.open_capture(fixture_path("00_reference_ethernet_ipv4_tcp.pcap")));

    CaptureSession classic_erf_session {};
    PFL_REQUIRE(classic_erf_session.open_capture(fixture_path("01_erf_eth_ipv4_tcp.pcap")));

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("10_pcapng_erf_eth_ipv4_tcp_real_style.pcapng")));
    PFL_EXPECT(session.summary().packet_count == reference_session.summary().packet_count);
    PFL_EXPECT(session.summary().packet_count == classic_erf_session.summary().packet_count);
    PFL_EXPECT(session.summary().flow_count == reference_session.summary().flow_count);
    PFL_EXPECT(session.summary().flow_count == classic_erf_session.summary().flow_count);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto reference_rows = reference_session.list_flows();
    const auto classic_erf_rows = classic_erf_session.list_flows();
    const auto rows = session.list_flows();
    PFL_REQUIRE(reference_rows.size() == 1U);
    PFL_REQUIRE(classic_erf_rows.size() == 1U);
    PFL_REQUIRE(rows.size() == 1U);
    const auto& reference_row = reference_rows.front();
    const auto& classic_erf_row = classic_erf_rows.front();
    const auto& row = rows.front();
    PFL_EXPECT(row.family == reference_row.family);
    PFL_EXPECT(row.family == classic_erf_row.family);
    PFL_EXPECT(row.address_a == reference_row.address_a);
    PFL_EXPECT(row.port_a == reference_row.port_a);
    PFL_EXPECT(row.address_b == reference_row.address_b);
    PFL_EXPECT(row.port_b == reference_row.port_b);
    PFL_EXPECT(flow_protocol_id(row) == flow_protocol_id(reference_row));
    PFL_EXPECT(flow_protocol_id(row) == flow_protocol_id(classic_erf_row));
    PFL_EXPECT(row.packet_count == reference_row.packet_count);
    PFL_EXPECT(row.total_bytes == reference_row.total_bytes);
    PFL_EXPECT(row.total_bytes == classic_erf_row.total_bytes);
    PFL_EXPECT(require_protocol_path_text(session, row) == "EthernetII -> IPv4 -> TCP");

    const auto reference_packet = require_packet(reference_session, 0U);
    const auto packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == kLinkTypeEthernet);
    PFL_EXPECT(packet.byte_offset == 94U);
    PFL_EXPECT(packet.captured_length == reference_packet.captured_length);
    PFL_EXPECT(packet.original_length == reference_packet.original_length);

    const auto reference_packet_bytes = reference_session.read_packet_data(reference_packet);
    const auto packet_bytes = session.read_packet_data(packet);
    PFL_EXPECT(packet_bytes == reference_packet_bytes);
}

void expect_erf_ipv6_udp_fixture_opens() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("02_erf_eth_ipv6_udp.pcap")));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    const auto& row = rows.front();
    PFL_EXPECT(row.family == FlowAddressFamily::ipv6);
    PFL_EXPECT(row.address_a == "2001:db8:50::10");
    PFL_EXPECT(row.port_a == 50124U);
    PFL_EXPECT(row.address_b == "2001:db8:50::20");
    PFL_EXPECT(row.port_b == 4443U);
    PFL_EXPECT(flow_protocol_id(row) == ProtocolId::udp);
    PFL_EXPECT(row.packet_count == 1U);
    PFL_EXPECT(row.total_bytes == 120U);
    PFL_EXPECT(require_protocol_path_text(session, row) == "EthernetII -> IPv6 -> UDP");

    const auto& packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == kLinkTypeEthernet);
    PFL_EXPECT(packet.byte_offset == 58U);
    PFL_EXPECT(packet.captured_length == 120U);
    PFL_EXPECT(packet.original_length == 120U);
}

void expect_erf_vlan_fixture_opens() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("03_erf_eth_vlan_ipv4_udp.pcap")));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    const auto& row = rows.front();
    PFL_EXPECT(flow_protocol_id(row) == ProtocolId::udp);
    PFL_EXPECT(row.packet_count == 1U);
    PFL_EXPECT(row.total_bytes == 96U);
    const auto path_text = require_protocol_path_text(session, row);
    PFL_EXPECT(contains_text(path_text, "EthernetII"));
    PFL_EXPECT(contains_text(path_text, "VLAN"));
    PFL_EXPECT(contains_text(path_text, "420"));
    PFL_EXPECT(contains_text(path_text, "IPv4"));
    PFL_EXPECT(contains_text(path_text, "UDP"));

    const auto& packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == kLinkTypeEthernet);
    PFL_EXPECT(packet.captured_length == 96U);
    PFL_EXPECT(packet.original_length == 96U);

    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_REQUIRE(details->vlan_tags.size() == 1U);
    const auto vlan_id = static_cast<std::uint16_t>(details->vlan_tags.front().tci & 0x0fffU);
    PFL_EXPECT(vlan_id == 420U);
}

void expect_erf_tls_fixture_uses_existing_detection() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("04_erf_eth_ipv4_tcp_tls_client_hello.pcap")));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    const auto& row = rows.front();
    PFL_EXPECT(flow_protocol_id(row) == ProtocolId::tcp);
    PFL_EXPECT(row.protocol_hint == "tls");
    PFL_EXPECT(row.service_hint == "erf.example.test");
    PFL_EXPECT(row.total_bytes == 150U);
    PFL_EXPECT(require_protocol_path_text(session, row) == "EthernetII -> IPv4 -> TCP");

    const auto& packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == kLinkTypeEthernet);
    PFL_EXPECT(packet.captured_length == 150U);
    PFL_EXPECT(packet.original_length == 150U);
}

void expect_erf_extension_header_fixture_opens() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("05_erf_eth_extension_header_ipv4_tcp.pcap")));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    const auto& row = rows.front();
    PFL_EXPECT(flow_protocol_id(row) == ProtocolId::tcp);
    PFL_EXPECT(row.total_bytes == 103U);
    PFL_EXPECT(require_protocol_path_text(session, row) == "EthernetII -> IPv4 -> TCP");

    const auto& packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == kLinkTypeEthernet);
    PFL_EXPECT(packet.byte_offset == 66U);
    PFL_EXPECT(packet.captured_length == 103U);
    PFL_EXPECT(packet.original_length == 103U);
}

void expect_erf_network_truncation_uses_network_lengths() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("06_erf_eth_truncated_network_packet.pcap")));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto stats = session.packet_statistics();
    PFL_EXPECT(stats.total_captured_bytes == 62U);
    PFL_EXPECT(stats.total_original_bytes == 175U);
    PFL_EXPECT(stats.truncated_packet_count == 1U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows.front().total_bytes == 175U);
    PFL_EXPECT(require_protocol_path_text(session, rows.front()) == "EthernetII -> IPv4 -> TCP");

    const auto& packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == kLinkTypeEthernet);
    PFL_EXPECT(packet.captured_length == 62U);
    PFL_EXPECT(packet.original_length == 175U);
}

void expect_malformed_or_unsupported_erf_records_are_unrecognized() {
    const std::vector<std::string_view> fixture_names {
        "07_erf_unsupported_record_type.pcap",
        "08_erf_truncated_base_header.pcap",
        "09_erf_truncated_extension_header.pcap",
    };

    for (const auto fixture_name : fixture_names) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.summary().flow_count == 0U);
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);

        const auto rows = session.list_unrecognized_packets();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows.front().packet_index == 0U);
        const auto packet = session.find_packet(rows.front().packet_index);
        PFL_REQUIRE(packet.has_value());
        PFL_EXPECT(packet->data_link_type == kLinkTypeErf);
    }
}

void expect_erf_flow_export_writes_normalized_ethernet(
    const std::string_view source_fixture,
    const std::string_view output_name
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(source_fixture)));

    const auto output_path = std::filesystem::temp_directory_path() / std::string(output_name);
    std::filesystem::remove(output_path);
    PFL_REQUIRE(session.export_flow_to_pcap(0U, output_path));

    const auto exported_packet = read_single_packet_path(output_path);
    PFL_EXPECT(exported_packet.link_type == kLinkTypeEthernet);
    PFL_EXPECT(exported_packet.captured_length == 120U);
    PFL_EXPECT(exported_packet.original_length == 120U);
    PFL_EXPECT(exported_packet.payload == read_single_packet_fixture("00_reference_ethernet_ipv4_tcp.pcap").payload);

    CaptureSession exported_session {};
    PFL_REQUIRE(exported_session.open_capture(output_path));
    PFL_EXPECT(exported_session.summary().packet_count == 1U);
    PFL_EXPECT(exported_session.summary().flow_count == 1U);
    const auto rows = exported_session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(require_protocol_path_text(exported_session, rows.front()) == "EthernetII -> IPv4 -> TCP");
}

} // namespace

void run_erf_pcap_fixture_tests() {
    expect_erf_wire_fixture_contract();
    expect_reference_ethernet_fixture_opens();
    expect_erf_ipv4_tcp_matches_reference_network_semantics();
    expect_pcapng_erf_ipv4_tcp_matches_reference_network_semantics();
    expect_erf_ipv6_udp_fixture_opens();
    expect_erf_vlan_fixture_opens();
    expect_erf_tls_fixture_uses_existing_detection();
    expect_erf_extension_header_fixture_opens();
    expect_erf_network_truncation_uses_network_lengths();
    expect_malformed_or_unsupported_erf_records_are_unrecognized();
    expect_erf_flow_export_writes_normalized_ethernet(
        "01_erf_eth_ipv4_tcp.pcap",
        "pfl_erf_classic_export_normalized_ethernet.pcap");
    expect_erf_flow_export_writes_normalized_ethernet(
        "10_pcapng_erf_eth_ipv4_tcp_real_style.pcapng",
        "pfl_erf_pcapng_export_normalized_ethernet.pcap");
}

} // namespace pfl::tests
