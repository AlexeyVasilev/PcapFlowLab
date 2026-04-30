#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "core/io/LinkType.h"

namespace pfl::detail {

inline constexpr std::size_t kEthernetHeaderSize = 14;
inline constexpr std::size_t kLinuxSllHeaderSize = 16;
inline constexpr std::size_t kLinuxSll2HeaderSize = 20;
inline constexpr std::size_t kVlanHeaderSize = 4;
inline constexpr std::size_t kMaxVlanTags = 2;
inline constexpr std::size_t kMaxIpv6ExtensionHeaders = 8;
inline constexpr std::uint16_t kEtherTypeArp = 0x0806U;
inline constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
inline constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;
inline constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
inline constexpr std::uint16_t kEtherTypeQinq = 0x88A8U;
inline constexpr std::uint16_t kArpProtocolTypeIpv4 = 0x0800U;
inline constexpr std::uint8_t kIpProtocolIcmp = 1;
inline constexpr std::uint8_t kIpProtocolTcp = 6;
inline constexpr std::uint8_t kIpProtocolUdp = 17;
inline constexpr std::uint8_t kIpProtocolRouting = 43;
inline constexpr std::uint8_t kIpProtocolFragment = 44;
inline constexpr std::uint8_t kIpProtocolEsp = 50;
inline constexpr std::uint8_t kIpProtocolAh = 51;
inline constexpr std::uint8_t kIpProtocolIcmpV6 = 58;
inline constexpr std::uint8_t kIpProtocolNoNextHeader = 59;
inline constexpr std::uint8_t kIpProtocolDestinationOptions = 60;
inline constexpr std::uint8_t kIpProtocolHopByHop = 0;
inline constexpr std::size_t kIpv4MinimumHeaderSize = 20;
inline constexpr std::size_t kIpv6HeaderSize = 40;
inline constexpr std::size_t kTransportPortsSize = 4;
inline constexpr std::size_t kTcpMinimumHeaderSize = 20;
inline constexpr std::size_t kUdpHeaderSize = 8;

struct LinkLayerPayloadView {
    std::uint16_t protocol_type {0};
    std::size_t payload_offset {0};
    bool is_ethernet {false};
    bool is_linux_cooked {false};
    std::uint16_t cooked_packet_type {0};
    std::uint16_t cooked_hardware_type {0};
};

struct Ipv6PayloadView {
    std::uint8_t next_header {0};
    std::size_t payload_offset {0};
    bool has_fragment_header {false};
};

struct UdpPayloadBounds {
    std::uint16_t datagram_length {0};
    std::size_t payload_offset {0};
    std::size_t payload_length {0};
};

inline std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

inline std::uint32_t read_be32(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
}

inline bool is_vlan_ether_type(const std::uint16_t ether_type) noexcept {
    return ether_type == kEtherTypeVlan || ether_type == kEtherTypeQinq;
}

inline bool is_ipv6_extension_header(const std::uint8_t next_header) noexcept {
    return next_header == kIpProtocolHopByHop ||
           next_header == kIpProtocolRouting ||
           next_header == kIpProtocolFragment ||
           next_header == kIpProtocolDestinationOptions ||
           next_header == kIpProtocolAh;
}

inline std::optional<LinkLayerPayloadView> parse_link_layer_payload(std::span<const std::uint8_t> bytes,
                                                                    const std::uint32_t data_link_type) {
    if (data_link_type == kLinkTypeEthernet) {
        if (bytes.size() < kEthernetHeaderSize) {
            return std::nullopt;
        }

        LinkLayerPayloadView view {
            .protocol_type = read_be16(bytes, 12U),
            .payload_offset = kEthernetHeaderSize,
            .is_ethernet = true,
        };

        std::size_t vlan_count = 0;
        while (is_vlan_ether_type(view.protocol_type)) {
            if (vlan_count == kMaxVlanTags) {
                return std::nullopt;
            }

            if (bytes.size() < view.payload_offset + kVlanHeaderSize) {
                return std::nullopt;
            }

            view.protocol_type = read_be16(bytes, view.payload_offset + 2U);
            view.payload_offset += kVlanHeaderSize;
            ++vlan_count;
        }

        return view;
    }

    if (data_link_type == kLinkTypeLinuxSll) {
        if (bytes.size() < kLinuxSllHeaderSize) {
            return std::nullopt;
        }

        return LinkLayerPayloadView {
            .protocol_type = read_be16(bytes, 14U),
            .payload_offset = kLinuxSllHeaderSize,
            .is_linux_cooked = true,
            .cooked_packet_type = read_be16(bytes, 0U),
            .cooked_hardware_type = read_be16(bytes, 2U),
        };
    }

    if (data_link_type == kLinkTypeLinuxSll2) {
        if (bytes.size() < kLinuxSll2HeaderSize) {
            return std::nullopt;
        }

        return LinkLayerPayloadView {
            .protocol_type = read_be16(bytes, 0U),
            .payload_offset = kLinuxSll2HeaderSize,
            .is_linux_cooked = true,
            .cooked_packet_type = bytes[10U],
            .cooked_hardware_type = read_be16(bytes, 8U),
        };
    }

    return std::nullopt;
}

inline std::optional<Ipv6PayloadView> parse_ipv6_payload(std::span<const std::uint8_t> bytes, const std::size_t ipv6_offset) {
    if (bytes.size() < ipv6_offset + kIpv6HeaderSize) {
        return std::nullopt;
    }

    std::uint8_t next_header = bytes[ipv6_offset + 6U];
    std::size_t payload_offset = ipv6_offset + kIpv6HeaderSize;
    bool has_fragment_header = false;

    for (std::size_t extension_count = 0; extension_count < kMaxIpv6ExtensionHeaders; ++extension_count) {
        if (!is_ipv6_extension_header(next_header)) {
            return Ipv6PayloadView {
                .next_header = next_header,
                .payload_offset = payload_offset,
                .has_fragment_header = has_fragment_header,
            };
        }

        if (bytes.size() < payload_offset + 2U) {
            return std::nullopt;
        }

        if (next_header == kIpProtocolFragment) {
            if (bytes.size() < payload_offset + 8U) {
                return std::nullopt;
            }

            has_fragment_header = true;
            next_header = bytes[payload_offset];
            payload_offset += 8U;
            continue;
        }

        std::size_t header_length = 0;
        if (next_header == kIpProtocolAh) {
            header_length = static_cast<std::size_t>(bytes[payload_offset + 1U] + 2U) * 4U;
        } else {
            header_length = static_cast<std::size_t>(bytes[payload_offset + 1U] + 1U) * 8U;
        }

        if (header_length < 8U || bytes.size() < payload_offset + header_length) {
            return std::nullopt;
        }

        next_header = bytes[payload_offset];
        payload_offset += header_length;
    }

    return std::nullopt;
}

inline std::optional<UdpPayloadBounds> parse_udp_payload_bounds(std::span<const std::uint8_t> bytes,
                                                                const std::size_t udp_offset,
                                                                const std::size_t nominal_packet_end) {
    const auto packet_end = std::min(nominal_packet_end, bytes.size());
    if (udp_offset + kUdpHeaderSize > packet_end) {
        return std::nullopt;
    }

    const auto udp_length = static_cast<std::size_t>(read_be16(bytes, udp_offset + 4U));
    if (udp_length < kUdpHeaderSize || udp_offset + udp_length > nominal_packet_end) {
        return std::nullopt;
    }

    const auto payload_offset = udp_offset + kUdpHeaderSize;
    const auto available_payload_length = (packet_end > payload_offset) ? (packet_end - payload_offset) : 0U;
    return UdpPayloadBounds {
        .datagram_length = static_cast<std::uint16_t>(udp_length),
        .payload_offset = payload_offset,
        .payload_length = std::min(udp_length - kUdpHeaderSize, available_payload_length),
    };
}

}  // namespace pfl::detail
