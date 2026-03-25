#include "core/services/PacketPayloadService.h"

#include <optional>

namespace pfl {

namespace {

constexpr std::size_t kEthernetHeaderSize = 14;
constexpr std::size_t kVlanHeaderSize = 4;
constexpr std::size_t kMaxVlanTags = 2;
constexpr std::size_t kMaxIpv6ExtensionHeaders = 8;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;
constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
constexpr std::uint16_t kEtherTypeQinq = 0x88A8U;
constexpr std::uint8_t kIpProtocolTcp = 6;
constexpr std::uint8_t kIpProtocolUdp = 17;
constexpr std::uint8_t kIpProtocolRouting = 43;
constexpr std::uint8_t kIpProtocolFragment = 44;
constexpr std::uint8_t kIpProtocolAh = 51;
constexpr std::uint8_t kIpProtocolDestinationOptions = 60;
constexpr std::uint8_t kIpProtocolHopByHop = 0;
constexpr std::size_t kIpv4MinimumHeaderSize = 20;
constexpr std::size_t kIpv6HeaderSize = 40;
constexpr std::size_t kTcpMinimumHeaderSize = 20;
constexpr std::size_t kUdpHeaderSize = 8;

struct EthernetPayloadView {
    std::uint16_t ether_type {0};
    std::size_t payload_offset {0};
};

struct Ipv6PayloadView {
    std::uint8_t next_header {0};
    std::size_t payload_offset {0};
};

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

bool is_vlan_ether_type(std::uint16_t ether_type) noexcept {
    return ether_type == kEtherTypeVlan || ether_type == kEtherTypeQinq;
}

bool is_ipv6_extension_header(std::uint8_t next_header) noexcept {
    return next_header == kIpProtocolHopByHop ||
           next_header == kIpProtocolRouting ||
           next_header == kIpProtocolFragment ||
           next_header == kIpProtocolDestinationOptions ||
           next_header == kIpProtocolAh;
}

std::optional<EthernetPayloadView> parse_ethernet_payload(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kEthernetHeaderSize) {
        return std::nullopt;
    }

    EthernetPayloadView view {
        .ether_type = read_be16(bytes, 12),
        .payload_offset = kEthernetHeaderSize,
    };

    std::size_t vlan_count = 0;
    while (is_vlan_ether_type(view.ether_type)) {
        if (vlan_count == kMaxVlanTags) {
            return std::nullopt;
        }

        if (bytes.size() < view.payload_offset + kVlanHeaderSize) {
            return std::nullopt;
        }

        view.ether_type = read_be16(bytes, view.payload_offset + 2);
        view.payload_offset += kVlanHeaderSize;
        ++vlan_count;
    }

    return view;
}

std::optional<Ipv6PayloadView> parse_ipv6_payload(std::span<const std::uint8_t> bytes, std::size_t ipv6_offset) {
    if (bytes.size() < ipv6_offset + kIpv6HeaderSize) {
        return std::nullopt;
    }

    std::uint8_t next_header = bytes[ipv6_offset + 6];
    std::size_t payload_offset = ipv6_offset + kIpv6HeaderSize;

    for (std::size_t extension_count = 0; extension_count < kMaxIpv6ExtensionHeaders; ++extension_count) {
        if (!is_ipv6_extension_header(next_header)) {
            return Ipv6PayloadView {
                .next_header = next_header,
                .payload_offset = payload_offset,
            };
        }

        if (bytes.size() < payload_offset + 2) {
            return std::nullopt;
        }

        if (next_header == kIpProtocolFragment) {
            if (bytes.size() < payload_offset + 8) {
                return std::nullopt;
            }

            const auto fragment_offset_and_flags = read_be16(bytes, payload_offset + 2);
            if ((fragment_offset_and_flags & 0xFFF8U) != 0U) {
                return std::nullopt;
            }

            next_header = bytes[payload_offset];
            payload_offset += 8;
            continue;
        }

        std::size_t header_length = 0;
        if (next_header == kIpProtocolAh) {
            header_length = static_cast<std::size_t>(bytes[payload_offset + 1] + 2U) * 4U;
        } else {
            header_length = static_cast<std::size_t>(bytes[payload_offset + 1] + 1U) * 8U;
        }

        if (header_length < 8 || bytes.size() < payload_offset + header_length) {
            return std::nullopt;
        }

        next_header = bytes[payload_offset];
        payload_offset += header_length;
    }

    return std::nullopt;
}

std::vector<std::uint8_t> copy_payload(std::span<const std::uint8_t> bytes, std::size_t offset, std::size_t length) {
    if (length == 0) {
        return {};
    }

    const auto begin = bytes.begin() + static_cast<std::ptrdiff_t>(offset);
    const auto end = begin + static_cast<std::ptrdiff_t>(length);
    return std::vector<std::uint8_t>(begin, end);
}

}  // namespace

std::vector<std::uint8_t> PacketPayloadService::extract_transport_payload(std::span<const std::uint8_t> packet_bytes) const {
    const auto ethernet = parse_ethernet_payload(packet_bytes);
    if (!ethernet.has_value()) {
        return {};
    }

    if (ethernet->ether_type == kEtherTypeIpv4) {
        const auto ipv4_offset = ethernet->payload_offset;
        if (packet_bytes.size() < ipv4_offset + kIpv4MinimumHeaderSize) {
            return {};
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv4_offset] >> 4U);
        const auto ihl = static_cast<std::size_t>((packet_bytes[ipv4_offset] & 0x0FU) * 4U);
        const auto total_length = static_cast<std::size_t>(read_be16(packet_bytes, ipv4_offset + 2));
        if (version != 4 || ihl < kIpv4MinimumHeaderSize || total_length < ihl) {
            return {};
        }

        const auto packet_end = ipv4_offset + total_length;
        if (packet_bytes.size() < ipv4_offset + ihl || packet_bytes.size() < packet_end) {
            return {};
        }

        const auto flags_fragment = read_be16(packet_bytes, ipv4_offset + 6);
        if ((flags_fragment & 0x3FFFU) != 0U) {
            return {};
        }

        const auto protocol = packet_bytes[ipv4_offset + 9];
        const auto transport_offset = ipv4_offset + ihl;

        if (protocol == kIpProtocolTcp) {
            if (transport_offset + kTcpMinimumHeaderSize > packet_end) {
                return {};
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12] >> 4U) * 4U);
            if (tcp_header_length < kTcpMinimumHeaderSize || transport_offset + tcp_header_length > packet_end) {
                return {};
            }

            return copy_payload(packet_bytes, transport_offset + tcp_header_length, packet_end - (transport_offset + tcp_header_length));
        }

        if (protocol == kIpProtocolUdp) {
            if (transport_offset + kUdpHeaderSize > packet_end) {
                return {};
            }

            const auto udp_length = static_cast<std::size_t>(read_be16(packet_bytes, transport_offset + 4));
            if (udp_length < kUdpHeaderSize || transport_offset + udp_length > packet_end) {
                return {};
            }

            return copy_payload(packet_bytes, transport_offset + kUdpHeaderSize, udp_length - kUdpHeaderSize);
        }

        return {};
    }

    if (ethernet->ether_type == kEtherTypeIpv6) {
        const auto ipv6_offset = ethernet->payload_offset;
        if (packet_bytes.size() < ipv6_offset + kIpv6HeaderSize) {
            return {};
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U);
        if (version != 6) {
            return {};
        }

        const auto ipv6_payload_length = static_cast<std::size_t>(read_be16(packet_bytes, ipv6_offset + 4));
        const auto packet_end = ipv6_offset + kIpv6HeaderSize + ipv6_payload_length;
        if (packet_bytes.size() < packet_end) {
            return {};
        }

        const auto payload = parse_ipv6_payload(packet_bytes, ipv6_offset);
        if (!payload.has_value() || payload->payload_offset > packet_end) {
            return {};
        }

        if (payload->next_header == kIpProtocolTcp) {
            if (payload->payload_offset + kTcpMinimumHeaderSize > packet_end) {
                return {};
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[payload->payload_offset + 12] >> 4U) * 4U);
            if (tcp_header_length < kTcpMinimumHeaderSize || payload->payload_offset + tcp_header_length > packet_end) {
                return {};
            }

            return copy_payload(packet_bytes, payload->payload_offset + tcp_header_length, packet_end - (payload->payload_offset + tcp_header_length));
        }

        if (payload->next_header == kIpProtocolUdp) {
            if (payload->payload_offset + kUdpHeaderSize > packet_end) {
                return {};
            }

            const auto udp_length = static_cast<std::size_t>(read_be16(packet_bytes, payload->payload_offset + 4));
            if (udp_length < kUdpHeaderSize || payload->payload_offset + udp_length > packet_end) {
                return {};
            }

            return copy_payload(packet_bytes, payload->payload_offset + kUdpHeaderSize, udp_length - kUdpHeaderSize);
        }

        return {};
    }

    return {};
}

}  // namespace pfl
