#include <cstdint>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "core/decode/PacketDecoder.h"
#include "core/domain/PacketRef.h"
#include "core/io/LinkType.h"
#include "core/services/PacketDetailsService.h"

namespace pfl::tests {

namespace {

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_EXPECT(packet.has_value());
    return *packet;
}

}  // namespace

void run_linux_cooked_tests() {
    {
        const auto sll_tcp_packet = make_linux_cooked_sll_packet(
            0x0800U,
            strip_ethernet_header(make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443))
        );
        const auto path = write_temp_pcap(
            "pfl_sll_ipv4_tcp.pcap",
            make_classic_pcap({{100, sll_tcp_packet}}, kLinkTypeLinuxSll)
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        PFL_EXPECT(session.summary().flow_count == 1);

        const auto packet = require_packet(session, 0);
        PFL_EXPECT(packet.data_link_type == kLinkTypeLinuxSll);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_linux_cooked);
        PFL_EXPECT(details->linux_cooked.protocol_type == 0x0800U);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.src_addr == ipv4(10, 0, 0, 1));
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.dst_port == 443);
    }

    {
        const auto sll_udp_packet = make_linux_cooked_sll_packet(
            0x0800U,
            strip_ethernet_header(make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53))
        );
        const auto path = write_temp_pcap(
            "pfl_sll_ipv4_udp.pcap",
            make_classic_pcap({{100, sll_udp_packet}}, kLinkTypeLinuxSll)
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        const auto packet = require_packet(session, 0);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 5353);
        PFL_EXPECT(details->udp.dst_port == 53);
    }

    {
        const auto sll_arp_packet = make_linux_cooked_sll_packet(
            0x0806U,
            strip_ethernet_header(make_ethernet_arp_packet(ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 1), 1))
        );
        const auto path = write_temp_pcap(
            "pfl_sll_arp.pcap",
            make_classic_pcap({{100, sll_arp_packet}}, kLinkTypeLinuxSll)
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        const auto packet = require_packet(session, 0);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_linux_cooked);
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.opcode == 1);
        const std::array<std::uint8_t, 4> expected_sender {192, 168, 1, 10};
        const std::array<std::uint8_t, 4> expected_target {192, 168, 1, 1};
        PFL_EXPECT(details->arp.sender_ipv4 == expected_sender);
        PFL_EXPECT(details->arp.target_ipv4 == expected_target);
    }

    {
        const auto ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
        const auto ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
        const auto sll_icmpv6_packet = make_linux_cooked_sll_packet(
            0x86DDU,
            strip_ethernet_header(make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(ipv6_src, ipv6_dst, 128, 0))
        );
        const auto path = write_temp_pcap(
            "pfl_sll_ipv6_icmpv6.pcap",
            make_classic_pcap({{100, sll_icmpv6_packet}}, kLinkTypeLinuxSll)
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        const auto packet = require_packet(session, 0);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(details->has_icmpv6);
        PFL_EXPECT(details->icmpv6.type == 128);
        PFL_EXPECT(details->icmpv6.code == 0);
    }

    {
        PacketDetailsService details_service {};
        const PacketRef packet_ref {
            .packet_index = 1,
            .byte_offset = 0,
            .data_link_type = kLinkTypeLinuxSll,
            .captured_length = 8,
            .original_length = 8,
        };
        const std::vector<std::uint8_t> truncated_sll {0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x24};
        PFL_EXPECT(!details_service.decode(truncated_sll, packet_ref).has_value());

        CaptureSession session {};
        const auto path = write_temp_pcap(
            "pfl_sll_truncated_header.pcap",
            make_classic_pcap({{100, truncated_sll}}, kLinkTypeLinuxSll)
        );
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 0);
        PFL_EXPECT(session.summary().flow_count == 0);
    }

    {
        PacketDecoder decoder {};
        const auto sll2_tcp_packet = make_linux_cooked_sll2_packet(
            0x0800U,
            strip_ethernet_header(make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 2222, 80))
        );
        const RawPcapPacket raw_packet {
            .packet_index = 9,
            .ts_sec = 1,
            .ts_usec = 0,
            .captured_length = static_cast<std::uint32_t>(sll2_tcp_packet.size()),
            .original_length = static_cast<std::uint32_t>(sll2_tcp_packet.size()),
            .data_offset = 0,
            .data_link_type = kLinkTypeLinuxSll2,
            .bytes = sll2_tcp_packet,
        };

        const auto decoded = decoder.decode(raw_packet);
        PFL_EXPECT(decoded.ipv4.has_value());
        PFL_EXPECT(decoded.ipv4->flow_key.protocol == ProtocolId::tcp);
        PFL_EXPECT(decoded.ipv4->flow_key.src_port == 2222);
        PFL_EXPECT(decoded.ipv4->flow_key.dst_port == 80);
        PFL_EXPECT(decoded.ipv4->packet_ref.data_link_type == kLinkTypeLinuxSll2);
    }
}

}  // namespace pfl::tests


