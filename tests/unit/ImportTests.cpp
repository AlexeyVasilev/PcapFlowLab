#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/decode/PacketDecoder.h"
#include "core/domain/CaptureState.h"
#include "core/io/PcapReader.h"
#include "core/services/CaptureImporter.h"

namespace pfl::tests {

namespace {

std::uint32_t ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return (static_cast<std::uint32_t>(a) << 24U) |
           (static_cast<std::uint32_t>(b) << 16U) |
           (static_cast<std::uint32_t>(c) << 8U) |
           static_cast<std::uint32_t>(d);
}

void append_le16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value & 0x00FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0x00FFU));
}

void append_le32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 24U) & 0x000000FFU));
}

void append_be16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0x00FFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0x00FFU));
}

void append_be32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 24U) & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0x000000FFU));
}

std::vector<std::uint8_t> make_ethernet_ipv4_tcp_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port
) {
    std::vector<std::uint8_t> bytes {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        0x45, 0x00,
    };

    append_be16(bytes, 40);
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    bytes.push_back(64);
    bytes.push_back(6);
    append_be16(bytes, 0);
    append_be32(bytes, src_addr);
    append_be32(bytes, dst_addr);
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be32(bytes, 0);
    append_be32(bytes, 0);
    bytes.push_back(0x50);
    bytes.push_back(0x10);
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_ipv4_udp_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port
) {
    std::vector<std::uint8_t> bytes {
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
        0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02,
        0x08, 0x00,
        0x45, 0x00,
    };

    append_be16(bytes, 28);
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    bytes.push_back(64);
    bytes.push_back(17);
    append_be16(bytes, 0);
    append_be32(bytes, src_addr);
    append_be32(bytes, dst_addr);
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be16(bytes, 8);
    append_be16(bytes, 0);
    return bytes;
}

std::vector<std::uint8_t> make_classic_pcap(
    const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>>& packets
) {
    std::vector<std::uint8_t> bytes {};
    append_le32(bytes, 0xa1b2c3d4U);
    append_le16(bytes, 2);
    append_le16(bytes, 4);
    append_le32(bytes, 0);
    append_le32(bytes, 0);
    append_le32(bytes, 65535);
    append_le32(bytes, 1);

    std::uint32_t ts_sec = 1;
    for (const auto& [ts_usec, packet] : packets) {
        append_le32(bytes, ts_sec);
        append_le32(bytes, ts_usec);
        append_le32(bytes, static_cast<std::uint32_t>(packet.size()));
        append_le32(bytes, static_cast<std::uint32_t>(packet.size()));
        bytes.insert(bytes.end(), packet.begin(), packet.end());
        ++ts_sec;
    }

    return bytes;
}

std::filesystem::path write_temp_pcap(const std::string& name, const std::vector<std::uint8_t>& bytes) {
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    stream.close();
    return path;
}

}  // namespace

void run_import_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);

    {
        const auto path = write_temp_pcap("pfl_reader_basic.pcap", make_classic_pcap({{100, tcp_packet}}));
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));
        PFL_EXPECT(reader.data_link_type() == 1);

        const auto packet = reader.read_next();
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(packet->packet_index == 0);
        PFL_EXPECT(packet->captured_length == tcp_packet.size());
        PFL_EXPECT(packet->original_length == tcp_packet.size());
        PFL_EXPECT(packet->data_offset == 40);
        PFL_EXPECT(packet->bytes == tcp_packet);
        PFL_EXPECT(!reader.read_next().has_value());
    }

    {
        PacketDecoder decoder {};
        const RawPcapPacket raw_packet {
            .packet_index = 3,
            .ts_sec = 1,
            .ts_usec = 10,
            .captured_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .original_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .data_offset = 128,
            .bytes = tcp_packet,
        };

        const auto decoded = decoder.decode_ethernet(raw_packet);
        PFL_EXPECT(decoded.ipv4.has_value());
        PFL_EXPECT(!decoded.ipv6.has_value());
        PFL_EXPECT(decoded.ipv4->flow_key.src_addr == ipv4(10, 0, 0, 1));
        PFL_EXPECT(decoded.ipv4->flow_key.dst_addr == ipv4(10, 0, 0, 2));
        PFL_EXPECT(decoded.ipv4->flow_key.src_port == 12345);
        PFL_EXPECT(decoded.ipv4->flow_key.dst_port == 443);
        PFL_EXPECT(decoded.ipv4->flow_key.protocol == ProtocolId::tcp);
        PFL_EXPECT(decoded.ipv4->packet_ref.packet_index == 3);
        PFL_EXPECT(decoded.ipv4->packet_ref.byte_offset == 128);
    }

    {
        PacketDecoder decoder {};
        const RawPcapPacket raw_packet {
            .packet_index = 4,
            .ts_sec = 1,
            .ts_usec = 11,
            .captured_length = static_cast<std::uint32_t>(udp_packet.size()),
            .original_length = static_cast<std::uint32_t>(udp_packet.size()),
            .data_offset = 256,
            .bytes = udp_packet,
        };

        const auto decoded = decoder.decode_ethernet(raw_packet);
        PFL_EXPECT(decoded.ipv4.has_value());
        PFL_EXPECT(decoded.ipv4->flow_key.src_addr == ipv4(10, 0, 0, 3));
        PFL_EXPECT(decoded.ipv4->flow_key.dst_addr == ipv4(10, 0, 0, 4));
        PFL_EXPECT(decoded.ipv4->flow_key.src_port == 5353);
        PFL_EXPECT(decoded.ipv4->flow_key.dst_port == 53);
        PFL_EXPECT(decoded.ipv4->flow_key.protocol == ProtocolId::udp);
    }

    {
        const auto path = write_temp_pcap(
            "pfl_import_counts.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );

        CaptureState state {};
        CaptureImporter importer {};
        PFL_EXPECT(importer.import_pcap(path, state));
        PFL_EXPECT(state.summary.packet_count == 2);
        PFL_EXPECT(state.summary.flow_count == 2);
        PFL_EXPECT(state.ipv4_connections.size() == 2);
    }

    {
        const auto reverse_tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 443, 12345);
        const auto path = write_temp_pcap(
            "pfl_import_reverse_flow.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, reverse_tcp_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 2);
        PFL_EXPECT(session.summary().flow_count == 1);
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
        PFL_EXPECT(connection->has_flow_a);
        PFL_EXPECT(connection->has_flow_b);
        PFL_EXPECT(connection->flow_a.packet_count == 1);
        PFL_EXPECT(connection->flow_b.packet_count == 1);
    }
}

}  // namespace pfl::tests
