#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/SessionFormatting.h"
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

void expect_flow_service_hint(const std::filesystem::path& relative_path, const std::string& expected_service_hint) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].service_hint == expected_service_hint);
}

}  // namespace

void run_arp_pcap_fixture_tests() {
    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/01_arp_request_ipv4.pcap")));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].service_hint == "Who has 10.10.12.1? Tell 10.10.12.2");

        const auto packet = require_packet(session, 0U);
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Protocol: ARP (Address Resolution Protocol)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Hardware Type: Ethernet (1)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Protocol Type: IPv4 (0x0800)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Opcode: request (1)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Sender MAC Address: 02:00:00:00:00:02") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Sender Protocol Address: 10.10.12.2") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Target Protocol Address: 10.10.12.1") != std::string::npos);

        const auto payload_dump = session.read_packet_payload_hex_dump(packet);
        PFL_EXPECT(payload_dump.find("00 01 08 00 06 04 00 01") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/02_arp_reply_ipv4.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].service_hint == "10.10.12.1 is at 02:00:00:00:00:01");

        const auto packet = require_packet(session, 0U);
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Opcode: reply (2)") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/03_arp_request_reply_ipv4.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        const auto first_packet = session.find_packet(0U);
        const auto second_packet = session.find_packet(1U);
        PFL_REQUIRE(first_packet.has_value());
        PFL_REQUIRE(second_packet.has_value());
        PFL_EXPECT(session.read_packet_protocol_details_text(*first_packet).find("Opcode: request (1)") != std::string::npos);
        PFL_EXPECT(session.read_packet_protocol_details_text(*second_packet).find("Opcode: reply (2)") != std::string::npos);
    }

    expect_flow_service_hint("parsing/arp/04_gratuitous_arp_request_ipv4.pcap", "Gratuitous ARP for 10.10.12.1");
    expect_flow_service_hint("parsing/arp/05_gratuitous_arp_reply_ipv4.pcap", "Gratuitous ARP for 10.10.12.1");
    expect_flow_service_hint("parsing/arp/06_arp_probe_ipv4.pcap", "ARP probe for 10.10.12.3");

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/06_arp_probe_ipv4.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Sender Protocol Address: 0.0.0.0") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/07_vlan_arp_request_ipv4.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].service_hint == "Who has 10.10.12.1? Tell 10.10.12.2");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->has_vlan);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(summary_layers.size() >= 4U);
        PFL_EXPECT(summary_layers[0].id == "frame");
        PFL_EXPECT(summary_layers[1].id == "ethernet");
        PFL_EXPECT(summary_layers[2].id == "vlan");
        PFL_EXPECT(summary_layers[3].id == "arp");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/08_arp_request_with_ethernet_padding.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto payload_dump = session.read_packet_payload_hex_dump(packet);
        PFL_EXPECT(payload_dump.find("00 01 08 00 06 04 00 01") != std::string::npos);
        PFL_EXPECT(payload_dump.find("00000020") == std::string::npos);
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/arp/09_truncated_arp_fixed_header.pcap");
        const auto details = decode_fixture_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.fixed_header_truncated);
        PFL_EXPECT(details->arp.sender_hardware_address.empty());
        PFL_EXPECT(details->arp.sender_protocol_address.empty());

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
        PFL_REQUIRE(protocol_text.has_value());
        PFL_EXPECT(protocol_text->find("Warning: ARP fixed header is truncated.") != std::string::npos);
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/arp/10_truncated_arp_address_section.pcap");
        const auto details = decode_fixture_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(!details->arp.fixed_header_truncated);
        PFL_EXPECT(details->arp.address_section_truncated);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
        PFL_REQUIRE(protocol_text.has_value());
        PFL_EXPECT(protocol_text->find("Warning: ARP address section is truncated.") != std::string::npos);
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/arp/11_snaplen_truncated_arp_request.pcap");
        PFL_EXPECT(packet.captured_length < packet.original_length);

        const auto details = decode_fixture_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(!details->arp.fixed_header_truncated);
        PFL_EXPECT(details->arp.address_section_truncated);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, PacketRef {
            .packet_index = packet.packet_index,
            .byte_offset = packet.data_offset,
            .data_link_type = packet.data_link_type,
            .captured_length = packet.captured_length,
            .original_length = packet.original_length,
            .ts_sec = packet.ts_sec,
            .ts_usec = packet.ts_usec,
        });
        const auto arp_layer_it = std::find_if(summary_layers.begin(), summary_layers.end(), [](const session_detail::PacketSummaryLayer& layer) {
            return layer.id == "arp";
        });
        PFL_EXPECT(arp_layer_it != summary_layers.end());
        PFL_EXPECT(arp_layer_it->warning);
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/arp/12_unknown_hardware_type.pcap");
        const auto details = decode_fixture_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.hardware_type == 0x1234U);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
        PFL_REQUIRE(protocol_text.has_value());
        PFL_EXPECT(protocol_text->find("Hardware Type: Unknown (4660)") != std::string::npos);
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/arp/13_unknown_protocol_type_ipv6_lengths.pcap");
        const auto details = decode_fixture_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.protocol_type == 0x86DDU);
        PFL_EXPECT(details->arp.protocol_size == 16U);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
        PFL_REQUIRE(protocol_text.has_value());
        PFL_EXPECT(protocol_text->find("Protocol Type: 0x86dd") != std::string::npos);
        PFL_EXPECT(protocol_text->find("Protocol Size: 16") != std::string::npos);
        PFL_EXPECT(protocol_text->find("Sender Protocol Address: 20:01:0d:b8") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/14_unknown_opcode.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].service_hint == "ARP opcode 42");

        const auto packet = require_packet(session, 0U);
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Opcode: opcode 42") != std::string::npos);
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/arp/15_nonstandard_hlen_plen.pcap");
        const auto details = decode_fixture_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.hardware_size == 4U);
        PFL_EXPECT(details->arp.protocol_size == 2U);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
        PFL_REQUIRE(protocol_text.has_value());
        PFL_EXPECT(protocol_text->find("Hardware Size: 4") != std::string::npos);
        PFL_EXPECT(protocol_text->find("Protocol Size: 2") != std::string::npos);
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/arp/16_rarp_request_opcode_3.pcap");
        const auto details = decode_fixture_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
        PFL_REQUIRE(protocol_text.has_value());
        PFL_EXPECT(protocol_text->find("Opcode: opcode 3") != std::string::npos);
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/arp/17_inarp_request_opcode_8.pcap");
        const auto details = decode_fixture_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
        PFL_REQUIRE(protocol_text.has_value());
        PFL_EXPECT(protocol_text->find("Opcode: opcode 8") != std::string::npos);
    }
}

}  // namespace pfl::tests
