#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/io/PcapReader.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketPayloadService.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

void expect_payload_view_matches_copy(const PacketPayloadService& payload_service,
                                      std::span<const std::uint8_t> packet_bytes,
                                      const std::uint32_t data_link_type = 1U) {
    const auto copied_payload = payload_service.extract_transport_payload(packet_bytes, data_link_type);
    const auto payload_view = payload_service.extract_transport_payload_view(packet_bytes, data_link_type);

    if (copied_payload.empty()) {
        PFL_EXPECT(!payload_view.found);
        PFL_EXPECT(payload_view.length == 0U);
        PFL_EXPECT(payload_view.payload.empty());
        return;
    }

    PFL_EXPECT(payload_view.found);
    PFL_EXPECT(payload_view.length == copied_payload.size());
    PFL_EXPECT(payload_view.payload.size() == copied_payload.size());
    PFL_EXPECT(payload_view.offset + payload_view.length <= packet_bytes.size());
    PFL_EXPECT(std::vector<std::uint8_t>(payload_view.payload.begin(), payload_view.payload.end()) == copied_payload);
}

std::pair<std::vector<std::uint8_t>, std::uint32_t> read_first_fixture_packet(const std::filesystem::path& relative_path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(fixture_path(relative_path)));

    const auto packet = reader.read_next();
    PFL_EXPECT(packet.has_value());
    PFL_EXPECT(!reader.read_next().has_value());

    return {packet->bytes, packet->data_link_type};
}

}  // namespace

void run_packet_payload_tests() {
    PacketPayloadService payload_service {};
    HexDumpService hex_dump_service {};

    {
        const auto tcp_packet = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443, 5, 0x18);
        const auto payload = payload_service.extract_transport_payload(tcp_packet);
        PFL_EXPECT(payload.size() == 5);
        PFL_EXPECT(payload[0] == static_cast<std::uint8_t>('A'));
        PFL_EXPECT(payload[4] == static_cast<std::uint8_t>('E'));
        expect_payload_view_matches_copy(payload_service, tcp_packet);
    }

    {
        const auto udp_packet = make_ethernet_ipv4_udp_packet_with_payload(
            ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53, 7);
        const auto payload = payload_service.extract_transport_payload(udp_packet);
        PFL_EXPECT(payload.size() == 7);
        PFL_EXPECT(payload[0] == static_cast<std::uint8_t>('a'));
        PFL_EXPECT(payload[6] == static_cast<std::uint8_t>('g'));
        expect_payload_view_matches_copy(payload_service, udp_packet);
    }

    {
        const auto full_udp_packet = make_ethernet_ipv4_udp_packet_with_payload(
            ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6), 54000, 443, 7);
        auto captured_udp_packet = full_udp_packet;
        captured_udp_packet.resize(full_udp_packet.size() - 3U);

        const auto payload = payload_service.extract_transport_payload(captured_udp_packet);
        PFL_EXPECT(payload.size() == 4U);
        PFL_EXPECT(payload[0] == static_cast<std::uint8_t>('a'));
        PFL_EXPECT(payload[3] == static_cast<std::uint8_t>('d'));
        expect_payload_view_matches_copy(payload_service, captured_udp_packet);
    }

    {
        const auto ack_only_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 1000, 2000);
        const auto payload = payload_service.extract_transport_payload(ack_only_packet);
        PFL_EXPECT(payload.empty());
        expect_payload_view_matches_copy(payload_service, ack_only_packet);
    }

    {
        const auto vlan_tcp_packet = add_vlan_tags(
            make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 2, 0, 1), ipv4(10, 2, 0, 2), 2222, 80, 4, 0x18),
            {{0x8100U, 100U}}
        );
        const auto vlan_udp_packet = add_vlan_tags(
            make_ethernet_ipv4_udp_packet_with_payload(ipv4(10, 3, 0, 1), ipv4(10, 3, 0, 2), 3000, 53, 3),
            {{0x88A8U, 10U}, {0x8100U, 20U}}
        );

        const auto tcp_payload = payload_service.extract_transport_payload(vlan_tcp_packet);
        PFL_EXPECT(tcp_payload.size() == 4);
        PFL_EXPECT(tcp_payload[0] == static_cast<std::uint8_t>('A'));

        const auto udp_payload = payload_service.extract_transport_payload(vlan_udp_packet);
        PFL_EXPECT(udp_payload.size() == 3);
        PFL_EXPECT(udp_payload[0] == static_cast<std::uint8_t>('a'));

        expect_payload_view_matches_copy(payload_service, vlan_tcp_packet);
        expect_payload_view_matches_copy(payload_service, vlan_udp_packet);
    }

    {
        const auto arp_packet = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1), 1U);
        const auto arp_payload = payload_service.extract_packet_details_payload(arp_packet);
        PFL_EXPECT(arp_payload.size() == 28U);
        PFL_EXPECT(arp_payload[0] == 0x00U);
        PFL_EXPECT(arp_payload[1] == 0x01U);
        PFL_EXPECT(arp_payload[6] == 0x00U);
        PFL_EXPECT(arp_payload[7] == 0x01U);

        auto padded_arp_packet = arp_packet;
        padded_arp_packet.insert(padded_arp_packet.end(), {0x00U, 0x00U, 0x00U, 0x00U});
        const auto padded_arp_payload = payload_service.extract_packet_details_payload(padded_arp_packet);
        PFL_EXPECT(padded_arp_payload.size() == 28U);

        auto truncated_arp_packet = arp_packet;
        truncated_arp_packet.resize(14U + 18U);
        const auto truncated_arp_payload = payload_service.extract_packet_details_payload(truncated_arp_packet);
        PFL_EXPECT(truncated_arp_payload.size() == 18U);
    }

    {
        auto malformed_tcp = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 4, 0, 1), ipv4(10, 4, 0, 2), 4444, 80, 2, 0x18);
        malformed_tcp[16] = 0x00;
        malformed_tcp[17] = 0x10;
        PFL_EXPECT(payload_service.extract_transport_payload(malformed_tcp).empty());
        expect_payload_view_matches_copy(payload_service, malformed_tcp);

        auto malformed_udp = make_ethernet_ipv4_udp_packet_with_payload(
            ipv4(10, 5, 0, 1), ipv4(10, 5, 0, 2), 5555, 53, 2);
        malformed_udp[38] = 0x00;
        malformed_udp[39] = 0x06;
        PFL_EXPECT(payload_service.extract_transport_payload(malformed_udp).empty());
        expect_payload_view_matches_copy(payload_service, malformed_udp);
    }

    {
        const auto [packet_bytes, data_link_type] = read_first_fixture_packet("parsing/ip_options/03_ipv4_router_alert_udp_payload.pcap");
        expect_payload_view_matches_copy(payload_service, packet_bytes, data_link_type);
    }

    {
        const auto [packet_bytes, data_link_type] = read_first_fixture_packet("parsing/mpls/02_mpls_ipv4_udp_single_label.pcap");
        expect_payload_view_matches_copy(payload_service, packet_bytes, data_link_type);
    }

    {
        auto [packet_bytes, data_link_type] = read_first_fixture_packet("parsing/llc_snap/05_llc_snap_arp.pcap");
        packet_bytes.insert(packet_bytes.end(), {0xdeU, 0xadU, 0xbeU, 0xefU});

        const auto arp_payload = payload_service.extract_packet_details_payload(packet_bytes, data_link_type);
        PFL_EXPECT(arp_payload.size() == 28U);
        PFL_EXPECT(arp_payload[0] == 0x00U);
        PFL_EXPECT(arp_payload[1] == 0x01U);
    }

    {
        const auto path = write_temp_pcap(
            "pfl_packet_payload_session.pcap",
            make_classic_pcap({{
                100,
                make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 6, 0, 1), ipv4(10, 6, 0, 2), 6000, 443, 5, 0x18)
            }})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());

        const auto payload_dump = session.read_packet_payload_hex_dump(*packet);
        PFL_EXPECT(!payload_dump.empty());
        PFL_EXPECT(payload_dump.find("00000000") != std::string::npos);
        PFL_EXPECT(payload_dump.find("41 42 43 44 45") != std::string::npos);

        const auto full_dump = session.read_packet_hex_dump(*packet);
        PFL_EXPECT(full_dump.size() > payload_dump.size());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_packet_payload_arp_session.pcap",
            make_classic_pcap({{
                100,
                make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1), 1U)
            }})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());

        const auto payload_dump = session.read_packet_payload_hex_dump(*packet);
        PFL_EXPECT(payload_dump.find("00000000") != std::string::npos);
        PFL_EXPECT(payload_dump.find("00 01 08 00 06 04 00 01") != std::string::npos);
        PFL_EXPECT(payload_dump.find("00 11 22 33 44 55 0a 0a") != std::string::npos);
        PFL_EXPECT(payload_dump.find("0c 02 66 77 88 99 aa bb") != std::string::npos);
    }

    PFL_EXPECT(hex_dump_service.format(std::span<const std::uint8_t> {}).empty());
}

}  // namespace pfl::tests
