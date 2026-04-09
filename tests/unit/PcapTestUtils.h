#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <optional>
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

inline void append_le64(std::vector<std::uint8_t>& bytes, std::uint64_t value) {
    append_le32(bytes, static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
    append_le32(bytes, static_cast<std::uint32_t>(value >> 32U));
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

inline void append_be64(std::vector<std::uint8_t>& bytes, std::uint64_t value) {
    append_be32(bytes, static_cast<std::uint32_t>(value >> 32U));
    append_be32(bytes, static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
}

inline void append_u16(std::vector<std::uint8_t>& bytes, std::uint16_t value, bool little_endian) {
    if (little_endian) {
        append_le16(bytes, value);
    } else {
        append_be16(bytes, value);
    }
}

inline void append_u32(std::vector<std::uint8_t>& bytes, std::uint32_t value, bool little_endian) {
    if (little_endian) {
        append_le32(bytes, value);
    } else {
        append_be32(bytes, value);
    }
}

inline void append_u64(std::vector<std::uint8_t>& bytes, std::uint64_t value, bool little_endian) {
    if (little_endian) {
        append_le64(bytes, value);
    } else {
        append_be64(bytes, value);
    }
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

inline void append_padded_bytes(std::vector<std::uint8_t>& bytes, const std::vector<std::uint8_t>& payload) {
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    while ((bytes.size() % 4U) != 0U) {
        bytes.push_back(0x00);
    }
}

inline void append_pcapng_option(
    std::vector<std::uint8_t>& bytes,
    std::uint16_t code,
    const std::vector<std::uint8_t>& value,
    bool little_endian
) {
    append_u16(bytes, code, little_endian);
    append_u16(bytes, static_cast<std::uint16_t>(value.size()), little_endian);
    bytes.insert(bytes.end(), value.begin(), value.end());
    while ((bytes.size() % 4U) != 0U) {
        bytes.push_back(0x00);
    }
}

inline std::vector<std::uint8_t> make_pcapng_block(
    std::uint32_t block_type,
    const std::vector<std::uint8_t>& body,
    bool little_endian = true
) {
    std::vector<std::uint8_t> bytes {};
    const auto total_length = static_cast<std::uint32_t>(body.size() + 12U);
    append_u32(bytes, block_type, little_endian);
    append_u32(bytes, total_length, little_endian);
    bytes.insert(bytes.end(), body.begin(), body.end());
    append_u32(bytes, total_length, little_endian);
    return bytes;
}

inline std::vector<std::uint8_t> make_pcapng_section_header_block(bool little_endian = true) {
    std::vector<std::uint8_t> body {};
    append_u32(body, 0x1A2B3C4DU, little_endian);
    append_u16(body, 1, little_endian);
    append_u16(body, 0, little_endian);
    append_u64(body, 0xFFFFFFFFFFFFFFFFULL, little_endian);
    return make_pcapng_block(0x0A0D0D0AU, body, little_endian);
}

inline std::vector<std::uint8_t> make_pcapng_interface_description_block(
    std::uint16_t linktype = 1,
    std::uint32_t snaplen = 65535,
    bool little_endian = true,
    std::optional<std::uint8_t> timestamp_resolution = std::nullopt
) {
    std::vector<std::uint8_t> body {};
    append_u16(body, linktype, little_endian);
    append_u16(body, 0, little_endian);
    append_u32(body, snaplen, little_endian);

    if (timestamp_resolution.has_value()) {
        append_pcapng_option(body, 9U, std::vector<std::uint8_t> {*timestamp_resolution}, little_endian);
        append_u16(body, 0U, little_endian);
        append_u16(body, 0U, little_endian);
    }

    return make_pcapng_block(0x00000001U, body, little_endian);
}

inline std::vector<std::uint8_t> make_pcapng_enhanced_packet_block(
    std::uint32_t interface_id,
    std::uint32_t ts_sec,
    std::uint32_t ts_usec,
    const std::vector<std::uint8_t>& packet,
    bool little_endian = true
) {
    const auto timestamp = (static_cast<std::uint64_t>(ts_sec) * 1'000'000ULL) + static_cast<std::uint64_t>(ts_usec);

    std::vector<std::uint8_t> body {};
    append_u32(body, interface_id, little_endian);
    append_u32(body, static_cast<std::uint32_t>(timestamp >> 32U), little_endian);
    append_u32(body, static_cast<std::uint32_t>(timestamp & 0xFFFFFFFFULL), little_endian);
    append_u32(body, static_cast<std::uint32_t>(packet.size()), little_endian);
    append_u32(body, static_cast<std::uint32_t>(packet.size()), little_endian);
    append_padded_bytes(body, packet);
    return make_pcapng_block(0x00000006U, body, little_endian);
}

inline std::vector<std::uint8_t> make_pcapng(const std::vector<std::vector<std::uint8_t>>& blocks) {
    std::vector<std::uint8_t> bytes {};
    for (const auto& block : blocks) {
        bytes.insert(bytes.end(), block.begin(), block.end());
    }
    return bytes;
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

inline std::vector<std::uint8_t> make_ethernet_ipv4_tcp_packet_with_payload(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint16_t payload_length,
    std::uint8_t tcp_flags
) {
    std::vector<std::uint8_t> bytes {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        0x45, 0x00,
    };

    append_be16(bytes, static_cast<std::uint16_t>(40 + payload_length));
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
    bytes.push_back(tcp_flags);
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    append_be16(bytes, 0);

    for (std::uint16_t index2 = 0; index2 < payload_length; ++index2) {
        bytes.push_back(static_cast<std::uint8_t>(0x41U + (index2 % 26U)));
    }

    return bytes;
}

inline std::vector<std::uint8_t> make_ethernet_ipv4_tcp_packet_with_bytes_payload(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    const std::vector<std::uint8_t>& payload,
    std::uint8_t tcp_flags = 0x18
) {
    std::vector<std::uint8_t> bytes {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        0x45, 0x00,
    };

    append_be16(bytes, static_cast<std::uint16_t>(40 + payload.size()));
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
    bytes.push_back(tcp_flags);
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

inline std::vector<std::uint8_t> make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    const std::vector<std::uint8_t>& payload,
    std::uint32_t seq_number,
    std::uint32_t ack_number,
    std::uint8_t tcp_flags = 0x18
) {
    auto bytes = make_ethernet_ipv4_tcp_packet_with_bytes_payload(src_addr, dst_addr, src_port, dst_port, payload, tcp_flags);
    bytes[38] = static_cast<std::uint8_t>((seq_number >> 24U) & 0xFFU);
    bytes[39] = static_cast<std::uint8_t>((seq_number >> 16U) & 0xFFU);
    bytes[40] = static_cast<std::uint8_t>((seq_number >> 8U) & 0xFFU);
    bytes[41] = static_cast<std::uint8_t>(seq_number & 0xFFU);
    bytes[42] = static_cast<std::uint8_t>((ack_number >> 24U) & 0xFFU);
    bytes[43] = static_cast<std::uint8_t>((ack_number >> 16U) & 0xFFU);
    bytes[44] = static_cast<std::uint8_t>((ack_number >> 8U) & 0xFFU);
    bytes[45] = static_cast<std::uint8_t>(ack_number & 0xFFU);
    return bytes;
}

inline std::vector<std::uint8_t> make_ethernet_ipv4_udp_packet_with_bytes_payload(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
        0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02,
        0x08, 0x00,
        0x45, 0x00,
    };

    append_be16(bytes, static_cast<std::uint16_t>(28 + payload.size()));
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    bytes.push_back(64);
    bytes.push_back(17);
    append_be16(bytes, 0);
    append_be32(bytes, src_addr);
    append_be32(bytes, dst_addr);
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be16(bytes, static_cast<std::uint16_t>(8 + payload.size()));
    append_be16(bytes, 0);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

inline std::vector<std::uint8_t> make_ethernet_ipv4_udp_packet_with_payload(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint16_t payload_length
) {
    std::vector<std::uint8_t> bytes {
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
        0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02,
        0x08, 0x00,
        0x45, 0x00,
    };

    append_be16(bytes, static_cast<std::uint16_t>(28 + payload_length));
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    bytes.push_back(64);
    bytes.push_back(17);
    append_be16(bytes, 0);
    append_be32(bytes, src_addr);
    append_be32(bytes, dst_addr);
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be16(bytes, static_cast<std::uint16_t>(8 + payload_length));
    append_be16(bytes, 0);

    for (std::uint16_t index2 = 0; index2 < payload_length; ++index2) {
        bytes.push_back(static_cast<std::uint8_t>(0x61U + (index2 % 26U)));
    }

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

inline std::vector<std::uint8_t> make_ethernet_arp_packet(
    std::uint32_t sender_ipv4,
    std::uint32_t target_ipv4,
    std::uint16_t opcode = 1
) {
    std::vector<std::uint8_t> bytes {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x06,
    };

    append_be16(bytes, 1);
    append_be16(bytes, 0x0800);
    bytes.push_back(6);
    bytes.push_back(4);
    append_be16(bytes, opcode);
    bytes.insert(bytes.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    append_be32(bytes, sender_ipv4);
    bytes.insert(bytes.end(), {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb});
    append_be32(bytes, target_ipv4);
    return bytes;
}

inline std::vector<std::uint8_t> make_ethernet_ipv4_icmp_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint8_t type,
    std::uint8_t code
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
    bytes.push_back(1);
    append_be16(bytes, 0);
    append_be32(bytes, src_addr);
    append_be32(bytes, dst_addr);
    bytes.push_back(type);
    bytes.push_back(code);
    append_be16(bytes, 0);
    append_be32(bytes, 0);
    return bytes;
}

inline std::vector<std::uint8_t> make_ethernet_ipv6_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
);

inline std::vector<std::uint8_t> make_ethernet_ipv4_fragment_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint8_t protocol,
    std::uint16_t flags_fragment,
    const std::vector<std::uint8_t>& payload,
    std::uint8_t ttl = 64
) {
    std::vector<std::uint8_t> bytes {
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
        0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02,
        0x08, 0x00,
        0x45, 0x00,
    };

    append_be16(bytes, static_cast<std::uint16_t>(20 + payload.size()));
    append_be16(bytes, 0);
    append_be16(bytes, flags_fragment);
    bytes.push_back(ttl);
    bytes.push_back(protocol);
    append_be16(bytes, 0);
    append_be32(bytes, src_addr);
    append_be32(bytes, dst_addr);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

inline std::vector<std::uint8_t> make_ipv6_fragment_header(
    std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload,
    std::uint16_t fragment_offset_units = 0,
    bool more_fragments = false,
    std::uint32_t identification = 1
) {
    std::vector<std::uint8_t> bytes {};
    bytes.push_back(next_header);
    bytes.push_back(0x00);

    const std::uint16_t offset_and_flags = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(fragment_offset_units << 3U) |
        static_cast<std::uint16_t>(more_fragments ? 0x0001U : 0x0000U)
    );
    append_be16(bytes, offset_and_flags);
    append_be32(bytes, identification);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

inline std::vector<std::uint8_t> make_ethernet_ipv6_fragment_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    std::uint8_t encapsulated_next_header,
    const std::vector<std::uint8_t>& fragment_payload,
    std::uint16_t fragment_offset_units = 0,
    bool more_fragments = false,
    std::uint32_t identification = 1
) {
    return make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        44,
        make_ipv6_fragment_header(
            encapsulated_next_header,
            fragment_payload,
            fragment_offset_units,
            more_fragments,
            identification
        )
    );
}
inline std::vector<std::uint8_t> make_ethernet_ipv6_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        0x00, 0x24, 0x81, 0xaa, 0xbb, 0xcc,
        0x00, 0x24, 0x81, 0xdd, 0xee, 0xff,
        0x86, 0xdd,
        0x60, 0x00, 0x00, 0x00,
    };

    append_be16(bytes, static_cast<std::uint16_t>(payload.size()));
    bytes.push_back(next_header);
    bytes.push_back(64);
    bytes.insert(bytes.end(), src_addr.begin(), src_addr.end());
    bytes.insert(bytes.end(), dst_addr.begin(), dst_addr.end());
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

inline std::vector<std::uint8_t> make_ipv6_hop_by_hop_extension(
    std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        next_header,
        0x00,
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
    };
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

inline std::vector<std::uint8_t> make_ipv6_udp_segment(
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint16_t payload_length = 0
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be16(bytes, static_cast<std::uint16_t>(8 + payload_length));
    append_be16(bytes, 0);
    for (std::uint16_t index = 0; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(index & 0xFFU));
    }
    return bytes;
}

inline std::vector<std::uint8_t> make_ipv6_icmpv6_message(std::uint8_t type, std::uint8_t code) {
    return std::vector<std::uint8_t> {
        type, code, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
    };
}

inline std::vector<std::uint8_t> make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    std::uint8_t type,
    std::uint8_t code
) {
    return make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        0,
        make_ipv6_hop_by_hop_extension(58, make_ipv6_icmpv6_message(type, code))
    );
}

inline std::vector<std::uint8_t> make_ethernet_ipv6_udp_with_hop_by_hop_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port
) {
    return make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        0,
        make_ipv6_hop_by_hop_extension(17, make_ipv6_udp_segment(src_port, dst_port))
    );
}

inline std::vector<std::uint8_t> make_truncated_ethernet_ipv6_extension_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr
) {
    return make_ethernet_ipv6_packet(src_addr, dst_addr, 0, {58, 1, 0x00});
}

inline std::vector<std::uint8_t> strip_ethernet_header(const std::vector<std::uint8_t>& ethernet_packet) {
    if (ethernet_packet.size() <= 14U) {
        return {};
    }

    return std::vector<std::uint8_t>(ethernet_packet.begin() + 14, ethernet_packet.end());
}

inline std::vector<std::uint8_t> make_linux_cooked_sll_packet(
    std::uint16_t protocol_type,
    const std::vector<std::uint8_t>& network_payload,
    std::uint16_t packet_type = 0,
    std::uint16_t hardware_type = 1,
    std::uint16_t link_address_length = 6
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, packet_type);
    append_be16(bytes, hardware_type);
    append_be16(bytes, link_address_length);
    bytes.insert(bytes.end(), {0x00, 0x24, 0x81, 0xaa, 0xbb, 0xcc, 0x00, 0x00});
    append_be16(bytes, protocol_type);
    bytes.insert(bytes.end(), network_payload.begin(), network_payload.end());
    return bytes;
}

inline std::vector<std::uint8_t> make_linux_cooked_sll2_packet(
    std::uint16_t protocol_type,
    const std::vector<std::uint8_t>& network_payload,
    std::uint8_t packet_type = 0,
    std::uint16_t hardware_type = 1,
    std::uint8_t link_address_length = 6,
    std::uint32_t interface_index = 1
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, protocol_type);
    append_be16(bytes, 0);
    append_be32(bytes, interface_index);
    append_be16(bytes, hardware_type);
    bytes.push_back(packet_type);
    bytes.push_back(link_address_length);
    bytes.insert(bytes.end(), {0x00, 0x24, 0x81, 0xaa, 0xbb, 0xcc, 0x00, 0x00});
    bytes.insert(bytes.end(), network_payload.begin(), network_payload.end());
    return bytes;
}

inline std::vector<std::uint8_t> make_classic_pcap(
    const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>>& packets,
    std::uint32_t linktype
) {
    std::vector<std::uint8_t> bytes {};
    append_le32(bytes, 0xa1b2c3d4U);
    append_le16(bytes, 2);
    append_le16(bytes, 4);
    append_le32(bytes, 0);
    append_le32(bytes, 0);
    append_le32(bytes, 65535);
    append_le32(bytes, linktype);

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

inline std::vector<std::uint8_t> make_classic_pcap(
    const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>>& packets
) {
    return make_classic_pcap(packets, 1U);
}

inline std::filesystem::path write_temp_binary_file(const std::string& name, const std::vector<std::uint8_t>& bytes) {
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    stream.close();
    return path;
}

inline std::filesystem::path write_temp_pcap(const std::string& name, const std::vector<std::uint8_t>& bytes) {
    return write_temp_binary_file(name, bytes);
}

}  // namespace pfl::tests









