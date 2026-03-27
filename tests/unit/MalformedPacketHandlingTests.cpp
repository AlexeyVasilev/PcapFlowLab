#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "core/decode/PacketDecoder.h"
#include "core/services/PacketDetailsService.h"
#include "core/services/PacketPayloadService.h"

namespace pfl::tests {

namespace {

constexpr std::string_view kNoProtocolDetailsMessage = "No protocol-specific details available for this packet.";

RawPcapPacket make_raw_packet(const std::vector<std::uint8_t>& bytes, const std::uint64_t packet_index = 7) {
    return RawPcapPacket {
        .packet_index = packet_index,
        .ts_sec = 1,
        .ts_usec = 10,
        .captured_length = static_cast<std::uint32_t>(bytes.size()),
        .original_length = static_cast<std::uint32_t>(bytes.size()),
        .data_offset = 128,
        .bytes = bytes,
    };
}

PacketRef make_packet_ref(const std::vector<std::uint8_t>& bytes, const std::uint64_t packet_index = 7) {
    return PacketRef {
        .packet_index = packet_index,
        .byte_offset = 128,
        .captured_length = static_cast<std::uint32_t>(bytes.size()),
        .original_length = static_cast<std::uint32_t>(bytes.size()),
        .ts_sec = 1,
        .ts_usec = 10,
    };
}

void expect_safe_failure(
    PacketDecoder& decoder,
    PacketDetailsService& details_service,
    PacketPayloadService& payload_service,
    const std::vector<std::uint8_t>& bytes
) {
    const auto raw_packet = make_raw_packet(bytes);
    const auto packet_ref = make_packet_ref(bytes);
    PFL_EXPECT(!decoder.decode_ethernet(raw_packet).has_value());
    PFL_EXPECT(!details_service.decode(bytes, packet_ref).has_value());
    PFL_EXPECT(payload_service.extract_transport_payload(bytes).empty());
}

}  // namespace

void run_malformed_packet_handling_tests() {
    PacketDecoder decoder {};
    PacketDetailsService details_service {};
    PacketPayloadService payload_service {};

    {
        const std::vector<std::uint8_t> short_ethernet {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
        expect_safe_failure(decoder, details_service, payload_service, short_ethernet);
    }

    {
        auto short_vlan = add_vlan_tags(
            make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1000, 80),
            {{0x8100U, 10U}}
        );
        short_vlan.resize(16);
        expect_safe_failure(decoder, details_service, payload_service, short_vlan);
    }

    {
        auto short_arp = make_ethernet_arp_packet(ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 1), 1);
        short_arp.resize(20);
        expect_safe_failure(decoder, details_service, payload_service, short_arp);
    }

    {
        auto invalid_ihl = make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 1234, 80);
        invalid_ihl[14] = 0x44;
        expect_safe_failure(decoder, details_service, payload_service, invalid_ihl);
    }

    {
        auto short_tcp_header = make_ethernet_ipv4_tcp_packet(ipv4(10, 2, 0, 1), ipv4(10, 2, 0, 2), 2345, 443);
        short_tcp_header.resize(44);
        expect_safe_failure(decoder, details_service, payload_service, short_tcp_header);
    }

    {
        auto invalid_tcp_header_length = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 3, 0, 1), ipv4(10, 3, 0, 2), 3456, 443, 4, 0x18);
        invalid_tcp_header_length[46] = 0x40;
        expect_safe_failure(decoder, details_service, payload_service, invalid_tcp_header_length);
    }

    {
        auto short_udp_header = make_ethernet_ipv4_udp_packet(ipv4(10, 4, 0, 1), ipv4(10, 4, 0, 2), 5353, 53);
        short_udp_header.resize(40);
        expect_safe_failure(decoder, details_service, payload_service, short_udp_header);
    }

    {
        const auto ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
        const auto ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
        const auto malformed_ipv6_extensions = make_truncated_ethernet_ipv6_extension_packet(ipv6_src, ipv6_dst);
        expect_safe_failure(decoder, details_service, payload_service, malformed_ipv6_extensions);
    }

    {
        auto truncated_tcp_payload = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 5, 0, 1), ipv4(10, 5, 0, 2), 4567, 443, 5, 0x18);
        truncated_tcp_payload.resize(truncated_tcp_payload.size() - 2U);
        PFL_EXPECT(payload_service.extract_transport_payload(truncated_tcp_payload).empty());
    }

    {
        const std::vector<std::uint8_t> malformed_dns_payload {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 'w', 'w', 'w',
        };
        const auto packet_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 6, 0, 1), ipv4(8, 8, 8, 8), 53000, 53, malformed_dns_payload);
        const auto capture_path = write_temp_pcap(
            "pfl_malformed_protocol_details.pcap",
            make_classic_pcap({{100, packet_bytes}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(session.read_packet_protocol_details_text(*packet) == kNoProtocolDetailsMessage);
    }
}

}  // namespace pfl::tests
