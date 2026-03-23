#include <array>
#include <variant>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/decode/PacketDecoder.h"
#include "core/services/PacketDetailsService.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_protocol_coverage_tests() {
    const auto arp_packet = make_ethernet_arp_packet(ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 1), 1);
    const auto icmp_packet = make_ethernet_ipv4_icmp_packet(ipv4(10, 0, 0, 10), ipv4(10, 0, 0, 20), 8, 0);
    const auto ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    const auto ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
    const auto icmpv6_packet = make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(ipv6_src, ipv6_dst, 128, 0);
    const auto ipv6_udp_packet = make_ethernet_ipv6_udp_with_hop_by_hop_packet(ipv6_src, ipv6_dst, 5353, 53);
    const auto truncated_ipv6_packet = make_truncated_ethernet_ipv6_extension_packet(ipv6_src, ipv6_dst);

    {
        const auto path = write_temp_pcap("pfl_arp_import.pcap", make_classic_pcap({{100, arp_packet}}));
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        PFL_EXPECT(session.summary().flow_count == 1);
        PFL_EXPECT(session.state().ipv4_connections.size() == 1);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(std::holds_alternative<ConnectionKeyV4>(rows[0].key));
        const auto arp_key = std::get<ConnectionKeyV4>(rows[0].key);
        PFL_EXPECT(arp_key.protocol == ProtocolId::arp);
        PFL_EXPECT(arp_key.first.addr == ipv4(192, 168, 1, 1));
        PFL_EXPECT(arp_key.second.addr == ipv4(192, 168, 1, 10));

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.opcode == 1);
        const std::array<std::uint8_t, 4> expected_sender_ipv4 {192, 168, 1, 10};
        const std::array<std::uint8_t, 4> expected_target_ipv4 {192, 168, 1, 1};
        PFL_EXPECT(details->arp.sender_ipv4 == expected_sender_ipv4);
        PFL_EXPECT(details->arp.target_ipv4 == expected_target_ipv4);
    }

    {
        const auto path = write_temp_pcap("pfl_icmp_import.pcap", make_classic_pcap({{100, icmp_packet}}));
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        PFL_EXPECT(session.summary().flow_count == 1);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        const auto icmp_key = std::get<ConnectionKeyV4>(rows[0].key);
        PFL_EXPECT(icmp_key.protocol == ProtocolId::icmp);

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_icmp);
        PFL_EXPECT(details->icmp.type == 8);
        PFL_EXPECT(details->icmp.code == 0);
    }

    {
        const auto path = write_temp_pcap("pfl_icmpv6_import.pcap", make_classic_pcap({{100, icmpv6_packet}}));
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        PFL_EXPECT(session.summary().flow_count == 1);
        PFL_EXPECT(session.state().ipv6_connections.size() == 1);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(std::holds_alternative<ConnectionKeyV6>(rows[0].key));
        const auto key = std::get<ConnectionKeyV6>(rows[0].key);
        PFL_EXPECT(key.protocol == ProtocolId::icmpv6);

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(details->ipv6.next_header == 58);
        PFL_EXPECT(details->has_icmpv6);
        PFL_EXPECT(details->icmpv6.type == 128);
        PFL_EXPECT(details->icmpv6.code == 0);
    }

    {
        const auto path = write_temp_pcap("pfl_ipv6_ext_udp_import.pcap", make_classic_pcap({{100, ipv6_udp_packet}}));
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        PFL_EXPECT(session.summary().flow_count == 1);

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(details->ipv6.next_header == 17);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 5353);
        PFL_EXPECT(details->udp.dst_port == 53);
    }

    {
        PacketDecoder decoder {};
        PacketDetailsService details_service {};
        const RawPcapPacket raw_packet {
            .packet_index = 10,
            .ts_sec = 1,
            .ts_usec = 10,
            .captured_length = static_cast<std::uint32_t>(truncated_ipv6_packet.size()),
            .original_length = static_cast<std::uint32_t>(truncated_ipv6_packet.size()),
            .data_offset = 100,
            .bytes = truncated_ipv6_packet,
        };
        const PacketRef packet_ref {
            .packet_index = 10,
            .byte_offset = 100,
            .captured_length = static_cast<std::uint32_t>(truncated_ipv6_packet.size()),
            .original_length = static_cast<std::uint32_t>(truncated_ipv6_packet.size()),
        };

        const auto decoded = decoder.decode_ethernet(raw_packet);
        PFL_EXPECT(!decoded.has_value());
        PFL_EXPECT(!details_service.decode(truncated_ipv6_packet, packet_ref).has_value());

        const auto path = write_temp_pcap("pfl_ipv6_ext_truncated.pcap", make_classic_pcap({{100, truncated_ipv6_packet}}));
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 0);
        PFL_EXPECT(session.summary().flow_count == 0);
    }
}

}  // namespace pfl::tests
