#include <filesystem>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

void expect_protocol_stats(const ProtocolStats& actual, const ProtocolStats& expected) {
    PFL_EXPECT(actual.flow_count == expected.flow_count);
    PFL_EXPECT(actual.packet_count == expected.packet_count);
    PFL_EXPECT(actual.total_bytes == expected.total_bytes);
}

}  // namespace

void run_protocol_summary_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_ipv4_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);
    const auto arp_packet = make_ethernet_arp_packet(ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6));
    const auto udp_ipv6_packet = make_ethernet_ipv6_udp_with_hop_by_hop_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
        5000,
        53
    );
    const auto icmpv6_packet = make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}),
        128,
        0
    );

    const auto capture_path = write_temp_pcap(
        "pfl_protocol_summary.pcap",
        make_classic_pcap({
            {100, tcp_packet},
            {200, udp_ipv4_packet},
            {300, arp_packet},
            {400, udp_ipv6_packet},
            {500, icmpv6_packet},
        })
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(capture_path));

    const auto summary = session.protocol_summary();
    expect_protocol_stats(summary.tcp, ProtocolStats {1, 1, static_cast<std::uint64_t>(tcp_packet.size())});
    expect_protocol_stats(summary.udp, ProtocolStats {
        2,
        2,
        static_cast<std::uint64_t>(udp_ipv4_packet.size() + udp_ipv6_packet.size())
    });
    expect_protocol_stats(summary.other, ProtocolStats {
        2,
        2,
        static_cast<std::uint64_t>(arp_packet.size() + icmpv6_packet.size())
    });
    expect_protocol_stats(summary.ipv4, ProtocolStats {
        3,
        3,
        static_cast<std::uint64_t>(tcp_packet.size() + udp_ipv4_packet.size() + arp_packet.size())
    });
    expect_protocol_stats(summary.ipv6, ProtocolStats {
        2,
        2,
        static_cast<std::uint64_t>(udp_ipv6_packet.size() + icmpv6_packet.size())
    });

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_protocol_summary.idx";
    std::filesystem::remove(index_path);
    PFL_EXPECT(session.save_index(index_path));

    CaptureSession loaded_session {};
    PFL_EXPECT(loaded_session.load_index(index_path));
    const auto loaded_summary = loaded_session.protocol_summary();

    expect_protocol_stats(loaded_summary.tcp, summary.tcp);
    expect_protocol_stats(loaded_summary.udp, summary.udp);
    expect_protocol_stats(loaded_summary.other, summary.other);
    expect_protocol_stats(loaded_summary.ipv4, summary.ipv4);
    expect_protocol_stats(loaded_summary.ipv6, summary.ipv6);
}

}  // namespace pfl::tests
