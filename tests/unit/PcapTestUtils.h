#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace pfl::tests {

inline std::uint32_t ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return (static_cast<std::uint32_t>(a) << 24U) |
           (static_cast<std::uint32_t>(b) << 16U) |
           (static_cast<std::uint32_t>(c) << 8U) |
           static_cast<std::uint32_t>(d);
}

inline void append_le16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value & 0x00FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0x00FFU));
}

inline void append_le32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 24U) & 0x000000FFU));
}

inline void append_be16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0x00FFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0x00FFU));
}

inline void append_be32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 24U) & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0x000000FFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0x000000FFU));
}

inline std::array<std::uint8_t, 16> ipv6(std::initializer_list<std::uint8_t> bytes) {
    std::array<std::uint8_t, 16> address {};
    std::size_t index = 0;
    for (const auto byte : bytes) {
        address[index] = byte;
        ++index;
    }
    return address;
}

inline std::vector<std::uint8_t> make_ethernet_ipv4_tcp_packet(
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

inline std::vector<std::uint8_t> make_ethernet_ipv4_udp_packet(
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

inline std::vector<std::uint8_t> add_vlan_tags(
    const std::vector<std::uint8_t>& ethernet_packet,
    const std::vector<std::pair<std::uint16_t, std::uint16_t>>& tags
) {
    if (ethernet_packet.size() < 14 || tags.empty()) {
        return ethernet_packet;
    }

    const auto original_ether_type = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(ethernet_packet[12]) << 8U) |
        static_cast<std::uint16_t>(ethernet_packet[13])
    );

    std::vector<std::uint8_t> bytes {};
    bytes.reserve(ethernet_packet.size() + tags.size() * 4U);
    bytes.insert(bytes.end(), ethernet_packet.begin(), ethernet_packet.begin() + 12);
    append_be16(bytes, tags.front().first);

    for (std::size_t index = 0; index < tags.size(); ++index) {
        append_be16(bytes, tags[index].second);
        const auto encapsulated_ether_type = (index + 1U < tags.size()) ? tags[index + 1U].first : original_ether_type;
        append_be16(bytes, encapsulated_ether_type);
    }

    bytes.insert(bytes.end(), ethernet_packet.begin() + 14, ethernet_packet.end());
    return bytes;
}

inline std::vector<std::uint8_t> make_single_tagged_ethernet_ipv4_tcp_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint16_t vlan_tci
) {
    return add_vlan_tags(
        make_ethernet_ipv4_tcp_packet(src_addr, dst_addr, src_port, dst_port),
        {{0x8100U, vlan_tci}}
    );
}

inline std::vector<std::uint8_t> make_double_tagged_ethernet_ipv4_udp_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint16_t outer_tci,
    std::uint16_t inner_tci
) {
    return add_vlan_tags(
        make_ethernet_ipv4_udp_packet(src_addr, dst_addr, src_port, dst_port),
        {{0x88A8U, outer_tci}, {0x8100U, inner_tci}}
    );
}

inline std::vector<std::uint8_t> make_classic_pcap(
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

inline std::filesystem::path write_temp_pcap(const std::string& name, const std::vector<std::uint8_t>& bytes) {
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    stream.close();
    return path;
}

}  // namespace pfl::tests
