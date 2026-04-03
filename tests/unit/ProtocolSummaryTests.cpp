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

std::vector<std::uint8_t> make_ssh_banner_payload() {
    constexpr char banner[] = "SSH-2.0-OpenSSH_9.6\r\n";
    return std::vector<std::uint8_t>(banner, banner + sizeof(banner) - 1);
}

std::vector<std::uint8_t> make_stun_binding_request_payload() {
    std::vector<std::uint8_t> payload {};
    append_be16(payload, 0x0001U);
    append_be16(payload, 0x0000U);
    append_be32(payload, 0x2112A442U);
    payload.insert(payload.end(), {
        0x10, 0x11, 0x12, 0x13,
        0x20, 0x21, 0x22, 0x23,
        0x30, 0x31, 0x32, 0x33,
    });
    return payload;
}

std::vector<std::uint8_t> make_bittorrent_handshake_payload() {
    std::vector<std::uint8_t> payload {};
    payload.push_back(19U);
    payload.insert(payload.end(), {
        'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't',
        ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l',
    });
    payload.insert(payload.end(), 8U, 0x00U);
    for (std::uint8_t index = 0; index < 20U; ++index) {
        payload.push_back(index);
    }
    for (std::uint8_t index = 0; index < 20U; ++index) {
        payload.push_back(static_cast<std::uint8_t>(0x41U + index));
    }
    return payload;
}

std::vector<std::uint8_t> make_smtp_payload() {
    constexpr char greeting[] = "220 mail.example.org ESMTP ready\r\n";
    return std::vector<std::uint8_t>(greeting, greeting + sizeof(greeting) - 1);
}

std::vector<std::uint8_t> make_pop3_payload() {
    constexpr char greeting[] = "+OK POP3 server ready\r\n";
    return std::vector<std::uint8_t>(greeting, greeting + sizeof(greeting) - 1);
}

std::vector<std::uint8_t> make_imap_payload() {
    constexpr char greeting[] = "* OK IMAP4 ready\r\n";
    return std::vector<std::uint8_t>(greeting, greeting + sizeof(greeting) - 1);
}

std::vector<std::uint8_t> make_dhcp_payload() {
    std::vector<std::uint8_t> payload(240U, 0x00U);
    payload[0] = 0x01U;
    payload[236] = 0x63U;
    payload[237] = 0x82U;
    payload[238] = 0x53U;
    payload[239] = 0x63U;
    return payload;
}

std::vector<std::uint8_t> make_mdns_payload() {
    std::vector<std::uint8_t> payload {};
    append_be16(payload, 0x0000U);
    append_be16(payload, 0x0000U);
    append_be16(payload, 0x0001U);
    append_be16(payload, 0x0000U);
    append_be16(payload, 0x0000U);
    append_be16(payload, 0x0000U);
    return payload;
}

}  // namespace

void run_protocol_summary_tests() {
    {
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
        expect_protocol_stats(summary.hint_unknown, ProtocolStats {
            5,
            5,
            static_cast<std::uint64_t>(
                tcp_packet.size() + udp_ipv4_packet.size() + arp_packet.size() + udp_ipv6_packet.size() + icmpv6_packet.size()
            )
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
        expect_protocol_stats(loaded_summary.hint_http, summary.hint_http);
        expect_protocol_stats(loaded_summary.hint_tls, summary.hint_tls);
        expect_protocol_stats(loaded_summary.hint_dns, summary.hint_dns);
        expect_protocol_stats(loaded_summary.hint_quic, summary.hint_quic);
        expect_protocol_stats(loaded_summary.hint_ssh, summary.hint_ssh);
        expect_protocol_stats(loaded_summary.hint_stun, summary.hint_stun);
        expect_protocol_stats(loaded_summary.hint_bittorrent, summary.hint_bittorrent);
        expect_protocol_stats(loaded_summary.hint_dhcp, summary.hint_dhcp);
        expect_protocol_stats(loaded_summary.hint_mdns, summary.hint_mdns);
        expect_protocol_stats(loaded_summary.hint_smtp, summary.hint_smtp);
        expect_protocol_stats(loaded_summary.hint_pop3, summary.hint_pop3);
        expect_protocol_stats(loaded_summary.hint_imap, summary.hint_imap);
        expect_protocol_stats(loaded_summary.hint_mail_protocols, summary.hint_mail_protocols);
        expect_protocol_stats(loaded_summary.hint_unknown, summary.hint_unknown);
    }

    {
        const auto ssh_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 10, 0, 1), ipv4(10, 10, 0, 2), 53022, 22, make_ssh_banner_payload(), 0x18
        );
        const auto stun_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 10, 0, 3), ipv4(10, 10, 0, 4), 51000, 3478, make_stun_binding_request_payload()
        );
        const auto bittorrent_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 10, 0, 5), ipv4(10, 10, 0, 6), 51413, 6881, make_bittorrent_handshake_payload(), 0x18
        );
        const auto unknown_packet = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 10, 0, 7), ipv4(10, 10, 0, 8), 3333, 4444, 12, 0x18
        );

        const auto capture_path = write_temp_pcap(
            "pfl_protocol_summary_cheap_hints.pcap",
            make_classic_pcap({
                {100, ssh_packet},
                {200, stun_packet},
                {300, bittorrent_packet},
                {400, unknown_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path));
        const auto summary = session.protocol_summary();

        expect_protocol_stats(summary.hint_ssh, ProtocolStats {1, 1, static_cast<std::uint64_t>(ssh_packet.size())});
        expect_protocol_stats(summary.hint_stun, ProtocolStats {1, 1, static_cast<std::uint64_t>(stun_packet.size())});
        expect_protocol_stats(summary.hint_bittorrent, ProtocolStats {1, 1, static_cast<std::uint64_t>(bittorrent_packet.size())});
        expect_protocol_stats(summary.hint_unknown, ProtocolStats {1, 1, static_cast<std::uint64_t>(unknown_packet.size())});

        const auto hint_flow_total = summary.hint_http.flow_count + summary.hint_tls.flow_count + summary.hint_dns.flow_count +
            summary.hint_quic.flow_count + summary.hint_ssh.flow_count + summary.hint_stun.flow_count +
            summary.hint_bittorrent.flow_count + summary.hint_mail_protocols.flow_count + summary.hint_dhcp.flow_count + summary.hint_mdns.flow_count + summary.hint_unknown.flow_count;
        const auto hint_packet_total = summary.hint_http.packet_count + summary.hint_tls.packet_count + summary.hint_dns.packet_count +
            summary.hint_quic.packet_count + summary.hint_ssh.packet_count + summary.hint_stun.packet_count +
            summary.hint_bittorrent.packet_count + summary.hint_mail_protocols.packet_count + summary.hint_dhcp.packet_count + summary.hint_mdns.packet_count + summary.hint_unknown.packet_count;
        const auto hint_byte_total = summary.hint_http.total_bytes + summary.hint_tls.total_bytes + summary.hint_dns.total_bytes +
            summary.hint_quic.total_bytes + summary.hint_ssh.total_bytes + summary.hint_stun.total_bytes +
            summary.hint_bittorrent.total_bytes + summary.hint_mail_protocols.total_bytes + summary.hint_dhcp.total_bytes + summary.hint_mdns.total_bytes + summary.hint_unknown.total_bytes;

        PFL_EXPECT(hint_flow_total == session.summary().flow_count);
        PFL_EXPECT(hint_packet_total == session.summary().packet_count);
        PFL_EXPECT(hint_byte_total == session.summary().total_bytes);
    }

    {
        const auto smtp_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 25, 41025, make_smtp_payload(), 0x18
        );
        const auto pop3_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 20, 0, 3), ipv4(10, 20, 0, 4), 110, 40110, make_pop3_payload(), 0x18
        );
        const auto imap_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 20, 0, 5), ipv4(10, 20, 0, 6), 143, 40143, make_imap_payload(), 0x18
        );
        const auto unknown_packet = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 20, 0, 7), ipv4(10, 20, 0, 8), 3333, 4444, 12, 0x18
        );

        const auto capture_path = write_temp_pcap(
            "pfl_protocol_summary_mail_grouping.pcap",
            make_classic_pcap({
                {100, smtp_packet},
                {200, pop3_packet},
                {300, imap_packet},
                {400, unknown_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path));
        const auto summary = session.protocol_summary();

        expect_protocol_stats(summary.hint_smtp, ProtocolStats {1, 1, static_cast<std::uint64_t>(smtp_packet.size())});
        expect_protocol_stats(summary.hint_pop3, ProtocolStats {1, 1, static_cast<std::uint64_t>(pop3_packet.size())});
        expect_protocol_stats(summary.hint_imap, ProtocolStats {1, 1, static_cast<std::uint64_t>(imap_packet.size())});
        expect_protocol_stats(summary.hint_mail_protocols, ProtocolStats {
            3,
            3,
            static_cast<std::uint64_t>(smtp_packet.size() + pop3_packet.size() + imap_packet.size())
        });
        expect_protocol_stats(summary.hint_unknown, ProtocolStats {1, 1, static_cast<std::uint64_t>(unknown_packet.size())});

        PFL_EXPECT(summary.hint_mail_protocols.flow_count == summary.hint_smtp.flow_count + summary.hint_pop3.flow_count + summary.hint_imap.flow_count);
        PFL_EXPECT(summary.hint_mail_protocols.packet_count == summary.hint_smtp.packet_count + summary.hint_pop3.packet_count + summary.hint_imap.packet_count);
        PFL_EXPECT(summary.hint_mail_protocols.total_bytes == summary.hint_smtp.total_bytes + summary.hint_pop3.total_bytes + summary.hint_imap.total_bytes);

        const auto hint_flow_total = summary.hint_http.flow_count + summary.hint_tls.flow_count + summary.hint_dns.flow_count +
            summary.hint_quic.flow_count + summary.hint_ssh.flow_count + summary.hint_stun.flow_count +
            summary.hint_bittorrent.flow_count + summary.hint_mail_protocols.flow_count + summary.hint_dhcp.flow_count + summary.hint_mdns.flow_count + summary.hint_unknown.flow_count;
        const auto hint_packet_total = summary.hint_http.packet_count + summary.hint_tls.packet_count + summary.hint_dns.packet_count +
            summary.hint_quic.packet_count + summary.hint_ssh.packet_count + summary.hint_stun.packet_count +
            summary.hint_bittorrent.packet_count + summary.hint_mail_protocols.packet_count + summary.hint_dhcp.packet_count + summary.hint_mdns.packet_count + summary.hint_unknown.packet_count;
        const auto hint_byte_total = summary.hint_http.total_bytes + summary.hint_tls.total_bytes + summary.hint_dns.total_bytes +
            summary.hint_quic.total_bytes + summary.hint_ssh.total_bytes + summary.hint_stun.total_bytes +
            summary.hint_bittorrent.total_bytes + summary.hint_mail_protocols.total_bytes + summary.hint_dhcp.total_bytes + summary.hint_mdns.total_bytes + summary.hint_unknown.total_bytes;

        PFL_EXPECT(hint_flow_total == session.summary().flow_count);
        PFL_EXPECT(hint_packet_total == session.summary().packet_count);
        PFL_EXPECT(hint_byte_total == session.summary().total_bytes);
    }
    {
        const auto dhcp_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(0, 0, 0, 0), ipv4(255, 255, 255, 255), 68, 67, make_dhcp_payload()
        );
        const auto mdns_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(192, 168, 1, 10), ipv4(224, 0, 0, 251), 5353, 5353, make_mdns_payload()
        );
        const auto unknown_packet = make_ethernet_ipv4_udp_packet_with_payload(
            ipv4(10, 30, 0, 1), ipv4(10, 30, 0, 2), 9999, 9998, 16
        );

        const auto capture_path = write_temp_pcap(
            "pfl_protocol_summary_dhcp_mdns.pcap",
            make_classic_pcap({
                {100, dhcp_packet},
                {200, mdns_packet},
                {300, unknown_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path));
        const auto summary = session.protocol_summary();

        expect_protocol_stats(summary.hint_dhcp, ProtocolStats {1, 1, static_cast<std::uint64_t>(dhcp_packet.size())});
        expect_protocol_stats(summary.hint_mdns, ProtocolStats {1, 1, static_cast<std::uint64_t>(mdns_packet.size())});
        expect_protocol_stats(summary.hint_unknown, ProtocolStats {1, 1, static_cast<std::uint64_t>(unknown_packet.size())});

        const auto hint_flow_total = summary.hint_http.flow_count + summary.hint_tls.flow_count + summary.hint_dns.flow_count +
            summary.hint_quic.flow_count + summary.hint_ssh.flow_count + summary.hint_stun.flow_count +
            summary.hint_bittorrent.flow_count + summary.hint_mail_protocols.flow_count + summary.hint_dhcp.flow_count +
            summary.hint_mdns.flow_count + summary.hint_unknown.flow_count;
        const auto hint_packet_total = summary.hint_http.packet_count + summary.hint_tls.packet_count + summary.hint_dns.packet_count +
            summary.hint_quic.packet_count + summary.hint_ssh.packet_count + summary.hint_stun.packet_count +
            summary.hint_bittorrent.packet_count + summary.hint_mail_protocols.packet_count + summary.hint_dhcp.packet_count +
            summary.hint_mdns.packet_count + summary.hint_unknown.packet_count;
        const auto hint_byte_total = summary.hint_http.total_bytes + summary.hint_tls.total_bytes + summary.hint_dns.total_bytes +
            summary.hint_quic.total_bytes + summary.hint_ssh.total_bytes + summary.hint_stun.total_bytes +
            summary.hint_bittorrent.total_bytes + summary.hint_mail_protocols.total_bytes + summary.hint_dhcp.total_bytes +
            summary.hint_mdns.total_bytes + summary.hint_unknown.total_bytes;

        PFL_EXPECT(hint_flow_total == session.summary().flow_count);
        PFL_EXPECT(hint_packet_total == session.summary().packet_count);
        PFL_EXPECT(hint_byte_total == session.summary().total_bytes);
    }
}

}  // namespace pfl::tests






