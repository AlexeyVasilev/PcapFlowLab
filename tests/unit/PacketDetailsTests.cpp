#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/SessionFormatting.h"
#include "app/session/CaptureSession.h"
#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketDetailsService.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_packet_details_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);

    {
        PacketDetailsService service {};
        const PacketRef packet_ref {
            .packet_index = 7,
            .byte_offset = 40,
            .captured_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .original_length = static_cast<std::uint32_t>(tcp_packet.size()),
        };

        const auto details = service.decode(tcp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->ethernet.ether_type == 0x0800);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.src_addr == ipv4(10, 0, 0, 1));
        PFL_EXPECT(details->ipv4.dst_addr == ipv4(10, 0, 0, 2));
        PFL_EXPECT(details->ipv4.protocol == 6);
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.src_port == 12345);
        PFL_EXPECT(details->tcp.dst_port == 443);
        PFL_EXPECT(details->tcp.flags == 0x10);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .transport_payload_length = 0U,
            .original_transport_payload_length = 0U,
        });
        PFL_EXPECT(!summary_layers.empty());
        PFL_EXPECT(summary_layers.front().id == "frame");
        PFL_EXPECT(summary_layers.front().title == "Frame 7");
        PFL_EXPECT(summary_layers.size() >= 4U);
        PFL_EXPECT(summary_layers[1].id == "ethernet");
        PFL_EXPECT(summary_layers[2].id == "ipv4");
        PFL_EXPECT(summary_layers[3].id == "tcp");
        PFL_EXPECT(summary_layers[2].title.find("Internet Protocol Version 4") != std::string::npos);
        PFL_EXPECT(summary_layers[3].title.find("Transmission Control Protocol") != std::string::npos);
        const auto tcp_layer_it = std::find_if(summary_layers.begin(), summary_layers.end(), [](const session_detail::PacketSummaryLayer& layer) {
            return layer.id == "tcp";
        });
        PFL_EXPECT(tcp_layer_it != summary_layers.end());
        const auto source_port_it = std::find_if(tcp_layer_it->fields.begin(), tcp_layer_it->fields.end(), [](const session_detail::PacketSummaryField& field) {
            return field.label == "Source Port" && field.value == "12345";
        });
        PFL_EXPECT(source_port_it != tcp_layer_it->fields.end());
    }

    {
        PacketDetailsService service {};
        const PacketRef packet_ref {
            .packet_index = 8,
            .byte_offset = 80,
            .captured_length = static_cast<std::uint32_t>(udp_packet.size()),
            .original_length = static_cast<std::uint32_t>(udp_packet.size()),
        };

        const auto details = service.decode(udp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.protocol == 17);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 5353);
        PFL_EXPECT(details->udp.dst_port == 53);
        PFL_EXPECT(details->udp.length == 8);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .transport_payload_length = 0U,
            .original_transport_payload_length = 0U,
        });
        PFL_EXPECT(summary_layers.size() >= 4U);
        PFL_EXPECT(summary_layers[0].id == "frame");
        PFL_EXPECT(summary_layers[1].id == "ethernet");
        PFL_EXPECT(summary_layers[2].id == "ipv4");
        PFL_EXPECT(summary_layers[3].id == "udp");
        PFL_EXPECT(summary_layers[3].title.find("User Datagram Protocol") != std::string::npos);
    }

    {
        const auto full_udp_with_payload = make_ethernet_ipv4_udp_packet_with_payload(
            ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6), 54000, 443, 7);
        auto captured_udp_with_payload = full_udp_with_payload;
        captured_udp_with_payload.resize(full_udp_with_payload.size() - 3U);

        PacketDetailsService service {};
        const PacketRef packet_ref {
            .packet_index = 18,
            .byte_offset = 88,
            .captured_length = static_cast<std::uint32_t>(captured_udp_with_payload.size()),
            .original_length = static_cast<std::uint32_t>(full_udp_with_payload.size()),
        };

        const auto details = service.decode(captured_udp_with_payload, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.protocol == 17);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 54000);
        PFL_EXPECT(details->udp.dst_port == 443);
        PFL_EXPECT(details->udp.length == 15);
    }

    {
        PacketDetailsService service {};
        const auto arp_packet = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1), 1U);
        const PacketRef packet_ref {
            .packet_index = 19,
            .byte_offset = 96,
            .captured_length = static_cast<std::uint32_t>(arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(arp_packet.size()),
        };

        const auto details = service.decode(arp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.hardware_type == 1U);
        PFL_EXPECT(details->arp.protocol_type == 0x0800U);
        PFL_EXPECT(details->arp.hardware_size == 6U);
        PFL_EXPECT(details->arp.protocol_size == 4U);
        PFL_EXPECT(details->arp.opcode == 1U);
        PFL_EXPECT(details->arp.sender_hardware_address.size() == 6U);
        PFL_EXPECT(details->arp.sender_protocol_address.size() == 4U);
        PFL_EXPECT(details->arp.target_hardware_address.size() == 6U);
        PFL_EXPECT(details->arp.target_protocol_address.size() == 4U);
        const std::array<std::uint8_t, 4> expected_sender_ipv4 {10U, 10U, 12U, 2U};
        const std::array<std::uint8_t, 4> expected_target_ipv4 {10U, 10U, 12U, 1U};
        PFL_EXPECT(details->arp.sender_ipv4 == expected_sender_ipv4);
        PFL_EXPECT(details->arp.target_ipv4 == expected_target_ipv4);
        PFL_EXPECT(!details->arp.fixed_header_truncated);
        PFL_EXPECT(!details->arp.address_section_truncated);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref);
        const auto arp_layer_it = std::find_if(summary_layers.begin(), summary_layers.end(), [](const session_detail::PacketSummaryLayer& layer) {
            return layer.id == "arp";
        });
        PFL_EXPECT(arp_layer_it != summary_layers.end());
        PFL_EXPECT(arp_layer_it->title.find("Address Resolution Protocol") != std::string::npos);
        const auto opcode_it = std::find_if(arp_layer_it->fields.begin(), arp_layer_it->fields.end(), [](const session_detail::PacketSummaryField& field) {
            return field.label == "Opcode" && field.value == "request (1)";
        });
        PFL_EXPECT(opcode_it != arp_layer_it->fields.end());
        const auto message_it = std::find_if(arp_layer_it->fields.begin(), arp_layer_it->fields.end(), [](const session_detail::PacketSummaryField& field) {
            return field.label == "Message" && field.value == "ARP Request";
        });
        PFL_EXPECT(message_it != arp_layer_it->fields.end());
        const auto detail_it = std::find_if(arp_layer_it->fields.begin(), arp_layer_it->fields.end(), [](const session_detail::PacketSummaryField& field) {
            return field.label.empty() && field.value == "Who has 10.10.12.1? Tell 10.10.12.2";
        });
        PFL_EXPECT(detail_it != arp_layer_it->fields.end());
    }

    {
        PacketDetailsService service {};
        auto padded_arp_packet = make_ethernet_arp_packet(ipv4(10, 10, 12, 1), ipv4(10, 10, 12, 2), 2U);
        padded_arp_packet.insert(padded_arp_packet.end(), {0x00U, 0x00U, 0x00U, 0x00U});
        const PacketRef packet_ref {
            .packet_index = 20,
            .byte_offset = 120,
            .captured_length = static_cast<std::uint32_t>(padded_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(padded_arp_packet.size()),
        };

        const auto details = service.decode(padded_arp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.sender_hardware_address.size() == 6U);
        PFL_EXPECT(details->arp.target_hardware_address.size() == 6U);
        PFL_EXPECT(!details->arp.address_section_truncated);
    }

    {
        PacketDetailsService service {};
        const auto vlan_arp_packet = add_vlan_tags(
            make_ethernet_arp_packet(ipv4(10, 10, 12, 3), ipv4(10, 10, 12, 4), 1U),
            {{0x8100U, 200U}}
        );
        const PacketRef packet_ref {
            .packet_index = 23,
            .byte_offset = 192,
            .captured_length = static_cast<std::uint32_t>(vlan_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(vlan_arp_packet.size()),
        };

        const auto details = service.decode(vlan_arp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->has_vlan);
        const std::array<std::uint8_t, 4> expected_vlan_sender_ipv4 {10U, 10U, 12U, 3U};
        PFL_EXPECT(details->arp.sender_ipv4 == expected_vlan_sender_ipv4);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref);
        PFL_EXPECT(summary_layers.size() >= 4U);
        PFL_EXPECT(summary_layers[0].id == "frame");
        PFL_EXPECT(summary_layers[1].id == "ethernet");
        PFL_EXPECT(summary_layers[2].id == "vlan");
        PFL_EXPECT(summary_layers[3].id == "arp");
        PFL_EXPECT(summary_layers[2].title.find("802.1Q Virtual LAN") != std::string::npos);
    }

    {
        PacketDetailsService service {};
        auto truncated_arp_packet = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1), 1U);
        truncated_arp_packet.resize(truncated_arp_packet.size() - 5U);
        const PacketRef packet_ref {
            .packet_index = 21,
            .byte_offset = 144,
            .captured_length = static_cast<std::uint32_t>(truncated_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(truncated_arp_packet.size() + 5U),
        };

        const auto details = service.decode(truncated_arp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(!details->arp.fixed_header_truncated);
        PFL_EXPECT(details->arp.address_section_truncated);
        PFL_EXPECT(details->arp.target_protocol_address.size() < 4U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref);
        const auto warning_layer_it = std::find_if(summary_layers.begin(), summary_layers.end(), [](const session_detail::PacketSummaryLayer& layer) {
            return layer.id == "warnings";
        });
        PFL_EXPECT(warning_layer_it != summary_layers.end());
        const auto arp_layer_it = std::find_if(summary_layers.begin(), summary_layers.end(), [](const session_detail::PacketSummaryLayer& layer) {
            return layer.id == "arp";
        });
        PFL_EXPECT(arp_layer_it != summary_layers.end());
        PFL_EXPECT(arp_layer_it->warning);
    }

    {
        PacketDetailsService service {};
        auto short_arp_packet = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1), 1U);
        short_arp_packet.resize(14U + 6U);
        const PacketRef packet_ref {
            .packet_index = 22,
            .byte_offset = 168,
            .captured_length = static_cast<std::uint32_t>(short_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(short_arp_packet.size() + 8U),
        };

        const auto details = service.decode(short_arp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.fixed_header_truncated);
    }

    {
        PacketDetailsService service {};
        const auto custom_arp_packet = make_ethernet_arp_packet_with_fields(
            {0x01, 0x02, 0x03},
            {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
            {0x04, 0x05, 0x06},
            {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
            3U,
            7U,
            0x1234U
        );
        const PacketRef packet_ref {
            .packet_index = 24,
            .byte_offset = 216,
            .captured_length = static_cast<std::uint32_t>(custom_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(custom_arp_packet.size()),
        };

        const auto details = service.decode(custom_arp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.hardware_type == 7U);
        PFL_EXPECT(details->arp.protocol_type == 0x1234U);
        PFL_EXPECT(details->arp.hardware_size == 3U);
        PFL_EXPECT(details->arp.protocol_size == 6U);
        PFL_EXPECT(details->arp.opcode == 3U);
        PFL_EXPECT(details->arp.sender_hardware_address.size() == 3U);
        PFL_EXPECT(details->arp.sender_protocol_address.size() == 6U);
        PFL_EXPECT(details->arp.target_hardware_address.size() == 3U);
        PFL_EXPECT(details->arp.target_protocol_address.size() == 6U);
    }

    {
        const auto path = write_temp_pcap("pfl_packet_details_session.pcap", make_classic_pcap({{100, tcp_packet}}));
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.state().ipv4_connections.size() == 1);

        const auto key = make_connection_key(FlowKeyV4 {
            .src_addr = ipv4(10, 0, 0, 1),
            .dst_addr = ipv4(10, 0, 0, 2),
            .src_port = 12345,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        });
        const auto* connection = session.state().ipv4_connections.find(key);
        PFL_EXPECT(connection != nullptr);

        const auto details = session.read_packet_details(connection->flow_a.packets.front());
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->packet_index == 0);
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.dst_port == 443);

        const auto hex_dump = session.read_packet_hex_dump(connection->flow_a.packets.front());
        PFL_EXPECT(!hex_dump.empty());
        PFL_EXPECT(hex_dump.find("00000000") != std::string::npos);
    }

    {
        HexDumpService service {};
        const std::vector<std::uint8_t> bytes {
            0x00, 0x01, 0x41, 0x42, 0x7f, 0x20, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x30, 0x31, 0x32, 0x33,
        };

        const auto dump = service.format(bytes);
        PFL_EXPECT(dump.find("00000000") != std::string::npos);
        PFL_EXPECT(dump.find("00000010") != std::string::npos);
        PFL_EXPECT(dump.find("00 01 41 42 7f 20") != std::string::npos);
        PFL_EXPECT(dump.find("|..AB.") != std::string::npos);
    }

    {
        PacketDetailsService service {};
        const std::vector<std::uint8_t> short_packet {0x00, 0x01, 0x02};
        const PacketRef packet_ref {
            .packet_index = 9,
            .byte_offset = 0,
            .captured_length = 3,
            .original_length = 3,
        };

        PFL_EXPECT(!service.decode(short_packet, packet_ref).has_value());

        HexDumpService hex_dump {};
        PFL_EXPECT(hex_dump.format(std::span<const std::uint8_t> {}).empty());
    }
}

}  // namespace pfl::tests
