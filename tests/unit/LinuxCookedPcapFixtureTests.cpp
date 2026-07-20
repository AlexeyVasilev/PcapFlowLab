#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/PacketRef.h"
#include "core/io/LinkType.h"
#include "core/io/PcapReader.h"
#include "core/services/PacketDetailsService.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    return *packet;
}

RawPcapPacket require_raw_fixture_packet(const std::filesystem::path& relative_path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(fixture_path(relative_path)));
    PFL_REQUIRE(reader.data_link_type() == kLinkTypeLinuxSll || reader.data_link_type() == kLinkTypeLinuxSll2);
    const auto packet = reader.read_next();
    PFL_REQUIRE(packet.has_value());
    PFL_EXPECT(!reader.read_next().has_value());
    return *packet;
}

std::optional<PacketDetails> decode_fixture_packet_details(const RawPcapPacket& packet) {
    PacketDetailsService details_service {};
    return details_service.decode(packet.bytes, PacketRef {
        .packet_index = packet.packet_index,
        .byte_offset = packet.data_offset,
        .data_link_type = packet.data_link_type,
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
        .ts_sec = packet.ts_sec,
        .ts_usec = packet.ts_usec,
    });
}

std::string require_flow_protocol_path_text(const CaptureSession& session, const FlowRow& row) {
    PFL_REQUIRE(row.protocol_path_id != kInvalidProtocolPathId);
    const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
    PFL_REQUIRE(path != nullptr);
    return format_protocol_path(*path);
}

std::uint16_t read_be16(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
        static_cast<std::uint16_t>(bytes[offset + 1U])
    );
}

std::uint32_t ipv4_value(const std::uint8_t a, const std::uint8_t b, const std::uint8_t c, const std::uint8_t d) {
    return (static_cast<std::uint32_t>(a) << 24U) |
           (static_cast<std::uint32_t>(b) << 16U) |
           (static_cast<std::uint32_t>(c) << 8U) |
           static_cast<std::uint32_t>(d);
}

std::array<std::uint8_t, 16> ipv6_address(std::initializer_list<std::uint8_t> bytes) {
    std::array<std::uint8_t, 16> address {};
    std::size_t index = 0U;
    for (const auto byte : bytes) {
        address[index] = byte;
        ++index;
    }
    return address;
}

void expect_supported_sll_or_sll2_ip_fixture(
    const std::filesystem::path& relative_path,
    const std::uint32_t expected_link_type,
    const FlowAddressFamily expected_family,
    const std::string& expected_protocol_text,
    const std::string& expected_protocol_path,
    const std::uint16_t expected_protocol_type,
    const std::uint16_t expected_hardware_type,
    const std::uint16_t expected_packet_type
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].family == expected_family);
    PFL_EXPECT(rows[0].protocol_text == expected_protocol_text);
    PFL_EXPECT(rows[0].packet_count == 1U);
    PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == expected_protocol_path);

    const auto packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == expected_link_type);

    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_linux_cooked);
    PFL_EXPECT(details->linux_cooked.link_type == expected_link_type);
    PFL_EXPECT(details->linux_cooked.protocol_type == expected_protocol_type);
    PFL_EXPECT(details->linux_cooked.hardware_type == expected_hardware_type);
    PFL_EXPECT(details->linux_cooked.packet_type == expected_packet_type);
}

void expect_supported_sll_arp_fixture() {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path("parsing/linux_cooked/03_sll_arp.pcap")));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].protocol_text == "ARP");
    PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "LinuxSll");

    const auto packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == kLinkTypeLinuxSll);

    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_linux_cooked);
    PFL_EXPECT(details->linux_cooked.protocol_type == 0x0806U);
    PFL_EXPECT(details->linux_cooked.packet_type == 0x0004U);
    PFL_EXPECT(details->linux_cooked.hardware_type == 0x0001U);
    PFL_EXPECT(details->has_arp);
    PFL_EXPECT(details->arp.opcode == 1U);
    const std::array<std::uint8_t, 4> expected_sender_ipv4 {192, 0, 2, 10};
    const std::array<std::uint8_t, 4> expected_target_ipv4 {192, 0, 2, 1};
    PFL_EXPECT(details->arp.sender_ipv4 == expected_sender_ipv4);
    PFL_EXPECT(details->arp.target_ipv4 == expected_target_ipv4);
}

void expect_supported_sll2_arp_fixture() {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path("parsing/linux_cooked/07_sll2_arp.pcap")));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].protocol_text == "ARP");
    PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "LinuxSll2");

    const auto packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == kLinkTypeLinuxSll2);

    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_linux_cooked);
    PFL_EXPECT(details->linux_cooked.protocol_type == 0x0806U);
    PFL_EXPECT(details->linux_cooked.packet_type == 0x0002U);
    PFL_EXPECT(details->linux_cooked.hardware_type == 0x0001U);
    PFL_EXPECT(details->has_arp);
    PFL_EXPECT(details->arp.opcode == 2U);
    const std::array<std::uint8_t, 4> expected_sender_ipv4 {203, 0, 113, 20};
    const std::array<std::uint8_t, 4> expected_target_ipv4 {203, 0, 113, 1};
    PFL_EXPECT(details->arp.sender_ipv4 == expected_sender_ipv4);
    PFL_EXPECT(details->arp.target_ipv4 == expected_target_ipv4);
}

void expect_single_unrecognized_linux_cooked_fixture(
    const std::filesystem::path& relative_path,
    const std::uint32_t expected_link_type,
    const std::string& expected_reason,
    const std::uint16_t expected_protocol_type,
    const std::uint16_t expected_hardware_type,
    const std::uint16_t expected_packet_type,
    const bool expect_capture_truncation = false
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 0U);
    PFL_EXPECT(session.summary().flow_count == 0U);
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);

    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].packet_index == 0U);
    PFL_EXPECT(rows[0].reason_text == expected_reason);

    const auto packet = require_packet(session, 0U);
    PFL_EXPECT(packet.data_link_type == expected_link_type);
    if (expect_capture_truncation) {
        PFL_EXPECT(packet.original_length > packet.captured_length);
    }

    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_linux_cooked);
    PFL_EXPECT(details->linux_cooked.link_type == expected_link_type);
    PFL_EXPECT(details->linux_cooked.protocol_type == expected_protocol_type);
    PFL_EXPECT(details->linux_cooked.hardware_type == expected_hardware_type);
    PFL_EXPECT(details->linux_cooked.packet_type == expected_packet_type);
}

void expect_truncated_root_fixture(
    const std::filesystem::path& relative_path,
    const std::uint32_t expected_link_type,
    const std::size_t expected_captured_length
) {
    const auto raw_packet = require_raw_fixture_packet(relative_path);
    PFL_EXPECT(raw_packet.data_link_type == expected_link_type);
    PFL_EXPECT(raw_packet.bytes.size() == expected_captured_length);

    const auto details = decode_fixture_packet_details(raw_packet);
    PFL_EXPECT(!details.has_value());

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 0U);
    PFL_EXPECT(session.summary().flow_count == 0U);
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
}

void expect_address_length_boundary_fixture(
    const std::filesystem::path& relative_path,
    const std::uint32_t expected_link_type,
    const std::string& expected_protocol_path,
    const std::uint16_t expected_address_length,
    const std::size_t address_length_offset
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == expected_protocol_path);

    const auto raw_packet = require_raw_fixture_packet(relative_path);
    PFL_EXPECT(raw_packet.data_link_type == expected_link_type);
    if (expected_link_type == kLinkTypeLinuxSll) {
        PFL_EXPECT(read_be16(raw_packet.bytes, address_length_offset) == expected_address_length);
    } else {
        PFL_EXPECT(static_cast<std::uint16_t>(raw_packet.bytes[address_length_offset]) == expected_address_length);
    }
}

}  // namespace

void run_linux_cooked_pcap_fixture_tests() {
    expect_supported_sll_or_sll2_ip_fixture(
        "parsing/linux_cooked/01_sll_ipv4_tcp.pcap",
        kLinkTypeLinuxSll,
        FlowAddressFamily::ipv4,
        "TCP",
        "LinuxSll -> IPv4 -> TCP",
        0x0800U,
        0x3456U,
        0x1234U
    );

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/linux_cooked/01_sll_ipv4_tcp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].address_a == "10.24.0.11");
        PFL_EXPECT(rows[0].address_b == "10.24.0.29");
        PFL_EXPECT(rows[0].port_a == 32123U);
        PFL_EXPECT(rows[0].port_b == 443U);
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.src_addr == ipv4_value(10, 24, 0, 11));
        PFL_EXPECT(details->ipv4.dst_addr == ipv4_value(10, 24, 0, 29));
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.src_port == 32123U);
        PFL_EXPECT(details->tcp.dst_port == 443U);
    }

    expect_supported_sll_or_sll2_ip_fixture(
        "parsing/linux_cooked/02_sll_ipv6_udp.pcap",
        kLinkTypeLinuxSll,
        FlowAddressFamily::ipv6,
        "UDP",
        "LinuxSll -> IPv6 -> UDP",
        0x86DDU,
        0x00F1U,
        0x00A1U
    );

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/linux_cooked/02_sll_ipv6_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv6);
        const auto expected_src_addr =
            ipv6_address({0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10});
        const auto expected_dst_addr =
            ipv6_address({0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20});
        PFL_EXPECT(details->ipv6.src_addr == expected_src_addr);
        PFL_EXPECT(details->ipv6.dst_addr == expected_dst_addr);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 53000U);
        PFL_EXPECT(details->udp.dst_port == 161U);
    }

    expect_supported_sll_arp_fixture();

    expect_supported_sll_or_sll2_ip_fixture(
        "parsing/linux_cooked/05_sll2_ipv4_tcp.pcap",
        kLinkTypeLinuxSll2,
        FlowAddressFamily::ipv4,
        "TCP",
        "LinuxSll2 -> IPv4 -> TCP",
        0x0800U,
        0x0F0EU,
        0x007FU
    );

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/linux_cooked/05_sll2_ipv4_tcp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].address_a == "198.51.100.44");
        PFL_EXPECT(rows[0].address_b == "198.51.100.77");
        PFL_EXPECT(rows[0].port_a == 41234U);
        PFL_EXPECT(rows[0].port_b == 8443U);
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.src_addr == ipv4_value(198, 51, 100, 44));
        PFL_EXPECT(details->ipv4.dst_addr == ipv4_value(198, 51, 100, 77));
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.src_port == 41234U);
        PFL_EXPECT(details->tcp.dst_port == 8443U);
    }

    expect_supported_sll_or_sll2_ip_fixture(
        "parsing/linux_cooked/06_sll2_ipv6_udp.pcap",
        kLinkTypeLinuxSll2,
        FlowAddressFamily::ipv6,
        "UDP",
        "LinuxSll2 -> IPv6 -> UDP",
        0x86DDU,
        0x1234U,
        0x0011U
    );

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/linux_cooked/06_sll2_ipv6_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv6);
        const auto expected_src_addr =
            ipv6_address({0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30});
        const auto expected_dst_addr =
            ipv6_address({0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40});
        PFL_EXPECT(details->ipv6.src_addr == expected_src_addr);
        PFL_EXPECT(details->ipv6.dst_addr == expected_dst_addr);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 61000U);
        PFL_EXPECT(details->udp.dst_port == 33434U);
    }

    expect_supported_sll2_arp_fixture();

    expect_single_unrecognized_linux_cooked_fixture(
        "parsing/linux_cooked/04_sll_vlan_ipv4_udp_unsupported.pcap",
        kLinkTypeLinuxSll,
        "Unsupported or malformed packet",
        0x8100U,
        0x7654U,
        0x4321U
    );

    expect_single_unrecognized_linux_cooked_fixture(
        "parsing/linux_cooked/08_sll2_vlan_ipv6_tcp_unsupported.pcap",
        kLinkTypeLinuxSll2,
        "Unsupported or malformed packet",
        0x88A8U,
        0x4242U,
        0x0003U
    );

    expect_truncated_root_fixture(
        "parsing/linux_cooked/09_sll_truncated_header.pcap",
        kLinkTypeLinuxSll,
        8U
    );

    expect_truncated_root_fixture(
        "parsing/linux_cooked/10_sll2_truncated_header.pcap",
        kLinkTypeLinuxSll2,
        12U
    );

    expect_single_unrecognized_linux_cooked_fixture(
        "parsing/linux_cooked/11_sll_unknown_protocol.pcap",
        kLinkTypeLinuxSll,
        "Unsupported or malformed packet",
        0x1234U,
        0x2468U,
        0x1357U
    );

    expect_single_unrecognized_linux_cooked_fixture(
        "parsing/linux_cooked/12_sll2_unknown_protocol.pcap",
        kLinkTypeLinuxSll2,
        "Unsupported or malformed packet",
        0x4321U,
        0x8888U,
        0x0009U
    );

    expect_single_unrecognized_linux_cooked_fixture(
        "parsing/linux_cooked/13_sll_truncated_inner_ipv4.pcap",
        kLinkTypeLinuxSll,
        "IPv4 header truncated",
        0x0800U,
        0x0C0DU,
        0x0A0BU,
        true
    );

    expect_single_unrecognized_linux_cooked_fixture(
        "parsing/linux_cooked/14_sll2_truncated_inner_ipv6.pcap",
        kLinkTypeLinuxSll2,
        "IPv6 header truncated",
        0x86DDU,
        0x1111U,
        0x0005U,
        true
    );

    expect_address_length_boundary_fixture(
        "parsing/linux_cooked/15_sll_addrlen_8_ipv4_udp.pcap",
        kLinkTypeLinuxSll,
        "LinuxSll -> IPv4 -> UDP",
        8U,
        4U
    );

    expect_address_length_boundary_fixture(
        "parsing/linux_cooked/16_sll_addrlen_12_ipv4_tcp.pcap",
        kLinkTypeLinuxSll,
        "LinuxSll -> IPv4 -> TCP",
        12U,
        4U
    );

    expect_address_length_boundary_fixture(
        "parsing/linux_cooked/17_sll2_addrlen_8_ipv4_udp.pcap",
        kLinkTypeLinuxSll2,
        "LinuxSll2 -> IPv4 -> UDP",
        8U,
        11U
    );

    expect_address_length_boundary_fixture(
        "parsing/linux_cooked/18_sll2_addrlen_12_ipv6_udp.pcap",
        kLinkTypeLinuxSll2,
        "LinuxSll2 -> IPv6 -> UDP",
        12U,
        11U
    );
}

}  // namespace pfl::tests
