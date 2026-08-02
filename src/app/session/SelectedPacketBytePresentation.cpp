#include "app/session/SelectedPacketBytePresentation.h"

#include <algorithm>
#include <sstream>

#include "core/services/HexDumpService.h"

namespace pfl::session_detail {

namespace {

constexpr std::size_t kMaxViewOccurrence = 0xFFU;
constexpr SelectedPacketByteOwnerId kCapturedPacketOwnerId {
    .kind = SelectedPacketByteOwnerKind::captured_packet,
    .occurrence = 0U,
};

bool equivalent_view(
    const SelectedPacketByteViewDescriptor& existing,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint32_t offset,
    const std::optional<std::uint32_t>& declared_length,
    const std::uint32_t captured_length,
    const bool truncated,
    const std::optional<std::uint64_t>& quic_crypto_stream_offset
) noexcept {
    return existing.parent_id == parent_id &&
        existing.owner_id == owner_id &&
        existing.owner_kind == owner_kind &&
        existing.id.kind == kind &&
        existing.id.scope == scope &&
        existing.offset == offset &&
        existing.declared_length == declared_length &&
        existing.captured_length == captured_length &&
        existing.truncated == truncated &&
        existing.quic_crypto_stream_offset == quic_crypto_stream_offset;
}

std::optional<std::uint32_t> narrow_u32(const std::size_t value) noexcept {
    if (value > 0xFFFFFFFFU) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(value);
}

std::string owner_kind_key(const SelectedPacketByteOwnerKind kind) {
    switch (kind) {
    case SelectedPacketByteOwnerKind::captured_packet:
        return "captured_packet";
    case SelectedPacketByteOwnerKind::quic_initial_plaintext:
        return "quic_initial_plaintext";
    default:
        return "unknown";
    }
}

std::string view_kind_key(const SelectedPacketByteViewKind kind) {
    switch (kind) {
    case SelectedPacketByteViewKind::frame:
        return "frame";
    case SelectedPacketByteViewKind::ethernet_payload:
        return "ethernet_payload";
    case SelectedPacketByteViewKind::vlan_payload:
        return "vlan_payload";
    case SelectedPacketByteViewKind::mpls_payload:
        return "mpls_payload";
    case SelectedPacketByteViewKind::ipv4_payload:
        return "ipv4_payload";
    case SelectedPacketByteViewKind::ipv6_payload:
        return "ipv6_payload";
    case SelectedPacketByteViewKind::tcp_payload:
        return "tcp_payload";
    case SelectedPacketByteViewKind::udp_payload:
        return "udp_payload";
    case SelectedPacketByteViewKind::sctp_payload:
        return "sctp_payload";
    case SelectedPacketByteViewKind::effective_transport_payload:
        return "effective_transport_payload";
    case SelectedPacketByteViewKind::inner_ethernet_payload:
        return "inner_ethernet_payload";
    case SelectedPacketByteViewKind::inner_vlan_payload:
        return "inner_vlan_payload";
    case SelectedPacketByteViewKind::inner_ipv4_payload:
        return "inner_ipv4_payload";
    case SelectedPacketByteViewKind::inner_ipv6_payload:
        return "inner_ipv6_payload";
    case SelectedPacketByteViewKind::inner_tcp_payload:
        return "inner_tcp_payload";
    case SelectedPacketByteViewKind::inner_udp_payload:
        return "inner_udp_payload";
    case SelectedPacketByteViewKind::inner_sctp_payload:
        return "inner_sctp_payload";
    case SelectedPacketByteViewKind::gre_payload:
        return "gre_payload";
    case SelectedPacketByteViewKind::eoip_payload:
        return "eoip_payload";
    case SelectedPacketByteViewKind::vxlan_payload:
        return "vxlan_payload";
    case SelectedPacketByteViewKind::geneve_payload:
        return "geneve_payload";
    case SelectedPacketByteViewKind::gtpu_payload:
        return "gtpu_payload";
    case SelectedPacketByteViewKind::ah_payload:
        return "ah_payload";
    case SelectedPacketByteViewKind::esp_protected_payload:
        return "esp_protected_payload";
    case SelectedPacketByteViewKind::quic_initial_packet:
        return "quic_initial_packet";
    case SelectedPacketByteViewKind::quic_zero_rtt_packet:
        return "quic_zero_rtt_packet";
    case SelectedPacketByteViewKind::quic_handshake_packet:
        return "quic_handshake_packet";
    case SelectedPacketByteViewKind::quic_retry_packet:
        return "quic_retry_packet";
    case SelectedPacketByteViewKind::quic_version_negotiation_packet:
        return "quic_version_negotiation_packet";
    case SelectedPacketByteViewKind::quic_protected_packet:
        return "quic_protected_packet";
    case SelectedPacketByteViewKind::quic_initial_protected_payload:
        return "quic_initial_protected_payload";
    case SelectedPacketByteViewKind::quic_initial_plaintext:
        return "quic_initial_plaintext";
    case SelectedPacketByteViewKind::quic_frame:
        return "quic_frame";
    case SelectedPacketByteViewKind::quic_crypto_data:
        return "quic_crypto_data";
    default:
        return "unknown";
    }
}

std::optional<SelectedPacketByteViewKind> parse_view_kind_key(const std::string_view key) {
    constexpr std::pair<std::string_view, SelectedPacketByteViewKind> kKinds[] {
        {"frame", SelectedPacketByteViewKind::frame},
        {"ethernet_payload", SelectedPacketByteViewKind::ethernet_payload},
        {"vlan_payload", SelectedPacketByteViewKind::vlan_payload},
        {"mpls_payload", SelectedPacketByteViewKind::mpls_payload},
        {"ipv4_payload", SelectedPacketByteViewKind::ipv4_payload},
        {"ipv6_payload", SelectedPacketByteViewKind::ipv6_payload},
        {"tcp_payload", SelectedPacketByteViewKind::tcp_payload},
        {"udp_payload", SelectedPacketByteViewKind::udp_payload},
        {"sctp_payload", SelectedPacketByteViewKind::sctp_payload},
        {"effective_transport_payload", SelectedPacketByteViewKind::effective_transport_payload},
        {"inner_ethernet_payload", SelectedPacketByteViewKind::inner_ethernet_payload},
        {"inner_vlan_payload", SelectedPacketByteViewKind::inner_vlan_payload},
        {"inner_ipv4_payload", SelectedPacketByteViewKind::inner_ipv4_payload},
        {"inner_ipv6_payload", SelectedPacketByteViewKind::inner_ipv6_payload},
        {"inner_tcp_payload", SelectedPacketByteViewKind::inner_tcp_payload},
        {"inner_udp_payload", SelectedPacketByteViewKind::inner_udp_payload},
        {"inner_sctp_payload", SelectedPacketByteViewKind::inner_sctp_payload},
        {"gre_payload", SelectedPacketByteViewKind::gre_payload},
        {"eoip_payload", SelectedPacketByteViewKind::eoip_payload},
        {"vxlan_payload", SelectedPacketByteViewKind::vxlan_payload},
        {"geneve_payload", SelectedPacketByteViewKind::geneve_payload},
        {"gtpu_payload", SelectedPacketByteViewKind::gtpu_payload},
        {"ah_payload", SelectedPacketByteViewKind::ah_payload},
        {"esp_protected_payload", SelectedPacketByteViewKind::esp_protected_payload},
        {"quic_initial_packet", SelectedPacketByteViewKind::quic_initial_packet},
        {"quic_zero_rtt_packet", SelectedPacketByteViewKind::quic_zero_rtt_packet},
        {"quic_handshake_packet", SelectedPacketByteViewKind::quic_handshake_packet},
        {"quic_retry_packet", SelectedPacketByteViewKind::quic_retry_packet},
        {"quic_version_negotiation_packet", SelectedPacketByteViewKind::quic_version_negotiation_packet},
        {"quic_protected_packet", SelectedPacketByteViewKind::quic_protected_packet},
        {"quic_initial_protected_payload", SelectedPacketByteViewKind::quic_initial_protected_payload},
        {"quic_initial_plaintext", SelectedPacketByteViewKind::quic_initial_plaintext},
        {"quic_frame", SelectedPacketByteViewKind::quic_frame},
        {"quic_crypto_data", SelectedPacketByteViewKind::quic_crypto_data},
    };

    const auto it = std::find_if(
        std::begin(kKinds),
        std::end(kKinds),
        [&](const auto& entry) {
            return entry.first == key;
        }
    );
    if (it == std::end(kKinds)) {
        return std::nullopt;
    }
    return it->second;
}

std::string base_view_label(const SelectedPacketByteViewDescriptor& descriptor) {
    switch (descriptor.id.kind) {
    case SelectedPacketByteViewKind::frame:
        return "Frame";
    case SelectedPacketByteViewKind::ethernet_payload:
        return "Ethernet Payload";
    case SelectedPacketByteViewKind::vlan_payload:
        return "VLAN Payload";
    case SelectedPacketByteViewKind::mpls_payload:
        return "MPLS Payload";
    case SelectedPacketByteViewKind::ipv4_payload:
        return "IPv4 Payload";
    case SelectedPacketByteViewKind::ipv6_payload:
        return "IPv6 Payload";
    case SelectedPacketByteViewKind::tcp_payload:
        return "TCP Payload";
    case SelectedPacketByteViewKind::udp_payload:
        return "UDP Payload";
    case SelectedPacketByteViewKind::sctp_payload:
        return "SCTP Payload";
    case SelectedPacketByteViewKind::effective_transport_payload:
        return "Transport Payload";
    case SelectedPacketByteViewKind::inner_ethernet_payload:
        return "Inner Ethernet Payload";
    case SelectedPacketByteViewKind::inner_vlan_payload:
        return "Inner VLAN Payload";
    case SelectedPacketByteViewKind::inner_ipv4_payload:
        return "Inner IPv4 Payload";
    case SelectedPacketByteViewKind::inner_ipv6_payload:
        return "Inner IPv6 Payload";
    case SelectedPacketByteViewKind::inner_tcp_payload:
        return "Inner TCP Payload";
    case SelectedPacketByteViewKind::inner_udp_payload:
        return "Inner UDP Payload";
    case SelectedPacketByteViewKind::inner_sctp_payload:
        return "Inner SCTP Payload";
    case SelectedPacketByteViewKind::gre_payload:
        return "GRE Payload";
    case SelectedPacketByteViewKind::eoip_payload:
        return "EoIP Payload";
    case SelectedPacketByteViewKind::vxlan_payload:
        return "VXLAN Payload";
    case SelectedPacketByteViewKind::geneve_payload:
        return "Geneve Payload";
    case SelectedPacketByteViewKind::gtpu_payload:
        return "GTP-U Payload";
    case SelectedPacketByteViewKind::ah_payload:
        return "AH Payload";
    case SelectedPacketByteViewKind::esp_protected_payload:
        return "ESP Protected Payload";
    case SelectedPacketByteViewKind::quic_initial_packet:
        return "QUIC Initial Packet";
    case SelectedPacketByteViewKind::quic_zero_rtt_packet:
        return "QUIC 0-RTT Packet";
    case SelectedPacketByteViewKind::quic_handshake_packet:
        return "QUIC Handshake Packet";
    case SelectedPacketByteViewKind::quic_retry_packet:
        return "QUIC Retry Packet";
    case SelectedPacketByteViewKind::quic_version_negotiation_packet:
        return "QUIC Version Negotiation Packet";
    case SelectedPacketByteViewKind::quic_protected_packet:
        return "QUIC Protected Packet";
    case SelectedPacketByteViewKind::quic_initial_protected_payload:
        return "QUIC Initial Protected Payload";
    case SelectedPacketByteViewKind::quic_initial_plaintext:
        return "QUIC Initial Decrypted Payload";
    case SelectedPacketByteViewKind::quic_frame:
        return descriptor.quic_crypto_stream_offset.has_value() ? "CRYPTO Frame" : "QUIC Frame";
    case SelectedPacketByteViewKind::quic_crypto_data:
        return "CRYPTO Frame Data";
    default:
        return "Bytes";
    }
}

std::string view_label(const SelectedPacketByteViewDescriptor& descriptor) {
    auto label = base_view_label(descriptor);
    if (descriptor.id.occurrence > 0U) {
        label += " #" + std::to_string(static_cast<std::size_t>(descriptor.id.occurrence) + 1U);
    }
    return label;
}

std::string descriptor_state(const SelectedPacketByteViewDescriptor& descriptor) {
    if (descriptor.truncated) {
        return "truncated";
    }
    if (descriptor.declared_length.has_value() && descriptor.captured_length < *descriptor.declared_length) {
        return "partial";
    }
    return "complete";
}

std::optional<SelectedPacketByteOwnerId> append_derived_owner(
    std::vector<SelectedPacketByteDerivedOwner>& owners,
    const SelectedPacketByteOwnerKind kind,
    const std::size_t quic_packet_index,
    std::vector<std::uint8_t> bytes
) {
    if (bytes.empty()) {
        return std::nullopt;
    }

    const auto occurrence_count = static_cast<std::size_t>(std::count_if(
        owners.begin(),
        owners.end(),
        [&](const SelectedPacketByteDerivedOwner& owner) {
            return owner.id.kind == kind;
        }
    ));
    if (occurrence_count > kMaxViewOccurrence) {
        return std::nullopt;
    }

    const SelectedPacketByteOwnerId id {
        .kind = kind,
        .occurrence = static_cast<std::uint8_t>(occurrence_count),
    };
    owners.push_back(SelectedPacketByteDerivedOwner {
        .id = id,
        .quic_packet_index = quic_packet_index,
        .bytes = std::move(bytes),
    });
    return id;
}

SelectedPacketByteViewKind quic_packet_view_kind(const QuicPresentationShellType shell_type) noexcept {
    switch (shell_type) {
    case QuicPresentationShellType::initial:
        return SelectedPacketByteViewKind::quic_initial_packet;
    case QuicPresentationShellType::zero_rtt:
        return SelectedPacketByteViewKind::quic_zero_rtt_packet;
    case QuicPresentationShellType::handshake:
        return SelectedPacketByteViewKind::quic_handshake_packet;
    case QuicPresentationShellType::retry:
        return SelectedPacketByteViewKind::quic_retry_packet;
    case QuicPresentationShellType::version_negotiation:
        return SelectedPacketByteViewKind::quic_version_negotiation_packet;
    case QuicPresentationShellType::protected_payload:
    default:
        return SelectedPacketByteViewKind::quic_protected_packet;
    }
}

std::optional<SelectedPacketByteViewId> append_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint32_t owner_byte_length,
    const std::uint32_t offset,
    const std::optional<std::uint32_t>& declared_length,
    const std::uint32_t captured_length,
    const bool truncated,
    const std::optional<std::uint64_t>& quic_crypto_stream_offset = std::nullopt
) {
    if (captured_length == 0U ||
        offset >= owner_byte_length ||
        captured_length > owner_byte_length - offset) {
        return std::nullopt;
    }

    if (std::any_of(views.begin(), views.end(), [&](const SelectedPacketByteViewDescriptor& existing) {
            return equivalent_view(
                existing,
                parent_id,
                owner_id,
                owner_kind,
                kind,
                scope,
                offset,
                declared_length,
                captured_length,
                truncated,
                quic_crypto_stream_offset
            );
        })) {
        return std::nullopt;
    }

    const auto occurrence_count = static_cast<std::size_t>(std::count_if(
        views.begin(),
        views.end(),
        [&](const SelectedPacketByteViewDescriptor& existing) {
            return existing.id.kind == kind && existing.id.scope == scope;
        }
    ));
    if (occurrence_count > kMaxViewOccurrence) {
        return std::nullopt;
    }

    const SelectedPacketByteViewId id {
        .kind = kind,
        .scope = scope,
        .occurrence = static_cast<std::uint8_t>(occurrence_count),
    };
    views.push_back(SelectedPacketByteViewDescriptor {
        .id = id,
        .parent_id = parent_id,
        .owner_id = owner_id,
        .owner_kind = owner_kind,
        .offset = offset,
        .declared_length = declared_length,
        .captured_length = captured_length,
        .truncated = truncated,
        .quic_crypto_stream_offset = quic_crypto_stream_offset,
    });
    return id;
}

std::optional<SelectedPacketByteViewId> append_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint32_t owner_byte_length,
    const PacketByteRange& range
) {
    return append_view(
        views,
        parent_id,
        owner_id,
        owner_kind,
        kind,
        scope,
        owner_byte_length,
        range.offset,
        range.declared_length,
        range.captured_length,
        range.truncated
    );
}

std::optional<SelectedPacketByteViewId> append_tcp_payload_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& parent_range,
    const TcpDetails& tcp,
    const SelectedPacketByteViewKind kind
) {
    const auto header_length = static_cast<std::uint32_t>(tcp.header_length_bytes);
    if (header_length < 20U || header_length >= parent_range.captured_length) {
        return std::nullopt;
    }
    if (parent_range.declared_length.has_value() && *parent_range.declared_length <= header_length) {
        return std::nullopt;
    }

    return append_view(
        views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        kind,
        0U,
        owner_captured_length,
        parent_range.offset + header_length,
        parent_range.declared_length.has_value()
            ? std::optional<std::uint32_t> {*parent_range.declared_length - header_length}
            : std::nullopt,
        parent_range.captured_length - header_length,
        parent_range.truncated
    );
}

std::optional<SelectedPacketByteViewId> append_udp_payload_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& parent_range,
    const UdpDetails& udp,
    const SelectedPacketByteViewKind kind
) {
    constexpr std::uint32_t kUdpHeaderSize = 8U;
    if (udp.length < kUdpHeaderSize || parent_range.captured_length <= kUdpHeaderSize) {
        return std::nullopt;
    }

    const auto declared_payload_length = static_cast<std::uint32_t>(udp.length - kUdpHeaderSize);
    const auto captured_payload_length = std::min<std::uint32_t>(
        declared_payload_length,
        parent_range.captured_length - kUdpHeaderSize
    );
    return append_view(
        views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        kind,
        0U,
        owner_captured_length,
        parent_range.offset + kUdpHeaderSize,
        declared_payload_length,
        captured_payload_length,
        parent_range.truncated || captured_payload_length < declared_payload_length
    );
}

std::optional<SelectedPacketByteViewId> append_sctp_payload_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::uint32_t owner_captured_length,
    const std::optional<PacketByteRange>& payload_range,
    const SelectedPacketByteViewKind kind
) {
    if (!payload_range.has_value()) {
        return std::nullopt;
    }
    return append_view(
        views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        kind,
        0U,
        owner_captured_length,
        *payload_range
    );
}

std::optional<SelectedPacketByteViewId> append_vlan_payload_chain(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    std::optional<SelectedPacketByteViewId> parent_id,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& carrier_range,
    const std::size_t vlan_count,
    const SelectedPacketByteViewKind kind
) {
    constexpr std::uint32_t kVlanHeaderSize = 4U;
    const auto payload_end = carrier_range.offset + carrier_range.captured_length;
    auto current_parent = parent_id;
    for (std::size_t index = 0U; index < vlan_count; ++index) {
        const auto offset = carrier_range.offset + static_cast<std::uint32_t>((index + 1U) * kVlanHeaderSize);
        if (offset >= payload_end) {
            break;
        }
        const auto appended = append_view(
            views,
            current_parent,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            kind,
            0U,
            owner_captured_length,
            offset,
            std::nullopt,
            payload_end - offset,
            false
        );
        if (appended.has_value()) {
            current_parent = appended;
        }
    }
    return current_parent;
}

template <typename InnerPacket>
std::optional<SelectedPacketByteViewId> append_inner_network_branch(
    const InnerPacket& inner,
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::uint32_t owner_captured_length,
    std::optional<SelectedPacketByteViewId> parent_id
) {
    std::optional<PacketByteRange> network_range {};
    auto current_parent = parent_id;

    if (inner.has_ipv4 && inner.ipv4.payload_range.has_value()) {
        network_range = inner.ipv4.payload_range;
        const auto appended = append_view(
            views,
            current_parent,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::inner_ipv4_payload,
            0U,
            owner_captured_length,
            *inner.ipv4.payload_range
        );
        if (appended.has_value()) {
            current_parent = appended;
        }
    } else if (inner.has_ipv6 && inner.ipv6.payload_range.has_value()) {
        network_range = inner.ipv6.payload_range;
        const auto appended = append_view(
            views,
            current_parent,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::inner_ipv6_payload,
            0U,
            owner_captured_length,
            *inner.ipv6.payload_range
        );
        if (appended.has_value()) {
            current_parent = appended;
        }
    }

    if (!network_range.has_value()) {
        return current_parent;
    }

    if (inner.has_tcp) {
        const auto appended = append_tcp_payload_view(
            views,
            current_parent,
            owner_captured_length,
            *network_range,
            inner.tcp,
            SelectedPacketByteViewKind::inner_tcp_payload
        );
        return appended.has_value() ? appended : current_parent;
    }
    if (inner.has_udp) {
        const auto appended = append_udp_payload_view(
            views,
            current_parent,
            owner_captured_length,
            *network_range,
            inner.udp,
            SelectedPacketByteViewKind::inner_udp_payload
        );
        return appended.has_value() ? appended : current_parent;
    }
    if constexpr (requires { inner.has_sctp; inner.sctp.payload_range; }) {
        if (inner.has_sctp) {
            const auto appended = append_sctp_payload_view(
                views,
                current_parent,
                owner_captured_length,
                inner.sctp.payload_range,
                SelectedPacketByteViewKind::inner_sctp_payload
            );
            return appended.has_value() ? appended : current_parent;
        }
    }

    return current_parent;
}

template <typename InnerPacket>
std::optional<SelectedPacketByteViewId> append_inner_ethernet_branch(
    const InnerPacket& inner,
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::uint32_t owner_captured_length,
    const std::optional<SelectedPacketByteViewId>& parent_id
) {
    auto current_parent = parent_id;
    if (inner.has_inner_ethernet && inner.inner_ethernet.payload_range.has_value()) {
        const auto appended = append_view(
            views,
            current_parent,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::inner_ethernet_payload,
            0U,
            owner_captured_length,
            *inner.inner_ethernet.payload_range
        );
        if (appended.has_value()) {
            current_parent = appended;
        }
        current_parent = append_vlan_payload_chain(
            views,
            current_parent,
            owner_captured_length,
            *inner.inner_ethernet.payload_range,
            inner.vlan_tags.size(),
            SelectedPacketByteViewKind::inner_vlan_payload
        );
    }

    if constexpr (requires { inner.has_mpls; inner.mpls_payload_range; }) {
        if (inner.has_mpls && inner.mpls_payload_range.has_value()) {
            const auto appended = append_view(
                views,
                current_parent,
                kCapturedPacketOwnerId,
                SelectedPacketByteOwnerKind::captured_packet,
                SelectedPacketByteViewKind::mpls_payload,
                0U,
                owner_captured_length,
                *inner.mpls_payload_range
            );
            if (appended.has_value()) {
                current_parent = appended;
            }
        }
    }

    return append_inner_network_branch(inner, views, owner_captured_length, current_parent);
}

std::optional<SelectedPacketByteViewId> append_top_level_transport_branch(
    const PacketDetails& details,
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::uint32_t owner_captured_length,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::optional<PacketByteRange>& parent_range
) {
    if (!parent_range.has_value()) {
        return parent_id;
    }

    if (details.has_tcp) {
        const auto appended = append_tcp_payload_view(
            views,
            parent_id,
            owner_captured_length,
            *parent_range,
            details.tcp,
            SelectedPacketByteViewKind::tcp_payload
        );
        return appended.has_value() ? appended : parent_id;
    }
    if (details.has_udp) {
        const auto appended = append_udp_payload_view(
            views,
            parent_id,
            owner_captured_length,
            *parent_range,
            details.udp,
            SelectedPacketByteViewKind::udp_payload
        );
        return appended.has_value() ? appended : parent_id;
    }
    if (details.has_sctp) {
        const auto appended = append_sctp_payload_view(
            views,
            parent_id,
            owner_captured_length,
            details.sctp.payload_range,
            SelectedPacketByteViewKind::sctp_payload
        );
        return appended.has_value() ? appended : parent_id;
    }

    return parent_id;
}

void append_overlay_payload_branches(
    const PacketDetails& details,
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::uint32_t owner_captured_length,
    const std::optional<SelectedPacketByteViewId>& outer_ip_id,
    const std::optional<PacketByteRange>& outer_ip_range,
    const std::optional<SelectedPacketByteViewId>& outer_udp_id
) {
    if (details.has_ah && details.ah.payload_range.has_value() && outer_ip_id.has_value()) {
        const auto ah_id = append_view(
            views,
            outer_ip_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::ah_payload,
            0U,
            owner_captured_length,
            *details.ah.payload_range
        );
        if (details.ah.has_inner_packet && details.ah.inner_packet != nullptr) {
            append_inner_network_branch(*details.ah.inner_packet, views, owner_captured_length, ah_id);
            return;
        }
        append_top_level_transport_branch(
            details,
            views,
            owner_captured_length,
            ah_id,
            details.ah.payload_range
        );
        return;
    }

    if (details.has_gre && details.gre.payload_range.has_value() && outer_ip_id.has_value()) {
        const auto gre_id = append_view(
            views,
            outer_ip_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            details.gre.is_eoip
                ? SelectedPacketByteViewKind::eoip_payload
                : SelectedPacketByteViewKind::gre_payload,
            0U,
            owner_captured_length,
            *details.gre.payload_range
        );
        if (details.gre.has_inner_packet && details.gre.inner_packet != nullptr) {
            append_inner_ethernet_branch(*details.gre.inner_packet, views, owner_captured_length, gre_id);
        }
        return;
    }

    if (details.has_esp && details.esp.protected_payload_range.has_value() && outer_ip_id.has_value()) {
        append_view(
            views,
            outer_ip_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::esp_protected_payload,
            0U,
            owner_captured_length,
            *details.esp.protected_payload_range
        );
        return;
    }

    if (details.has_gtpu && details.gtpu.payload_range.has_value() && outer_udp_id.has_value()) {
        const auto gtpu_id = append_view(
            views,
            outer_udp_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::gtpu_payload,
            0U,
            owner_captured_length,
            *details.gtpu.payload_range
        );
        if (details.gtpu.has_inner_packet && details.gtpu.inner_packet != nullptr) {
            append_inner_network_branch(*details.gtpu.inner_packet, views, owner_captured_length, gtpu_id);
        }
        return;
    }

    if (details.has_vxlan && details.vxlan.payload_range.has_value() && outer_udp_id.has_value()) {
        const auto vxlan_id = append_view(
            views,
            outer_udp_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::vxlan_payload,
            0U,
            owner_captured_length,
            *details.vxlan.payload_range
        );
        if (details.vxlan.has_inner_packet && details.vxlan.inner_packet != nullptr) {
            append_inner_ethernet_branch(*details.vxlan.inner_packet, views, owner_captured_length, vxlan_id);
        }
        return;
    }

    if (details.has_geneve && details.geneve.payload_range.has_value() && outer_udp_id.has_value()) {
        const auto geneve_id = append_view(
            views,
            outer_udp_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::geneve_payload,
            0U,
            owner_captured_length,
            *details.geneve.payload_range
        );
        if (details.geneve.has_inner_packet && details.geneve.inner_packet != nullptr) {
            append_inner_ethernet_branch(*details.geneve.inner_packet, views, owner_captured_length, geneve_id);
        }
        return;
    }

    if (details.has_ip_encapsulation && outer_ip_id.has_value()) {
        auto current_parent = outer_ip_id;
        for (const auto& inner_layer : details.ip_encapsulation.inner_ip_layers) {
            if (inner_layer.has_ipv4 && inner_layer.ipv4.payload_range.has_value()) {
                const auto appended = append_view(
                    views,
                    current_parent,
                    kCapturedPacketOwnerId,
                    SelectedPacketByteOwnerKind::captured_packet,
                    SelectedPacketByteViewKind::inner_ipv4_payload,
                    0U,
                    owner_captured_length,
                    *inner_layer.ipv4.payload_range
                );
                if (appended.has_value()) {
                    current_parent = appended;
                }
            } else if (inner_layer.has_ipv6 && inner_layer.ipv6.payload_range.has_value()) {
                const auto appended = append_view(
                    views,
                    current_parent,
                    kCapturedPacketOwnerId,
                    SelectedPacketByteOwnerKind::captured_packet,
                    SelectedPacketByteViewKind::inner_ipv6_payload,
                    0U,
                    owner_captured_length,
                    *inner_layer.ipv6.payload_range
                );
                if (appended.has_value()) {
                    current_parent = appended;
                }
            }
        }

        if (current_parent.has_value() && !details.ip_encapsulation.inner_ip_layers.empty()) {
            const auto& deepest_layer = details.ip_encapsulation.inner_ip_layers.back();
            const auto deepest_range = deepest_layer.has_ipv4
                ? deepest_layer.ipv4.payload_range
                : deepest_layer.ipv6.payload_range;
            if (details.ip_encapsulation.has_tcp && deepest_range.has_value()) {
                append_tcp_payload_view(
                    views,
                    current_parent,
                    owner_captured_length,
                    *deepest_range,
                    details.ip_encapsulation.tcp,
                    SelectedPacketByteViewKind::inner_tcp_payload
                );
            } else if (details.ip_encapsulation.has_udp && deepest_range.has_value()) {
                append_udp_payload_view(
                    views,
                    current_parent,
                    owner_captured_length,
                    *deepest_range,
                    details.ip_encapsulation.udp,
                    SelectedPacketByteViewKind::inner_udp_payload
                );
            }
        }
    }

    if (!details.has_ah) {
        append_top_level_transport_branch(
            details,
            views,
            owner_captured_length,
            outer_ip_id,
            outer_ip_range
        );
    }
}

std::vector<std::optional<SelectedPacketByteViewId>> append_quic_packet_views(
    SelectedPacketBytePresentation& presentation,
    const QuicPresentationResult& quic_presentation,
    const SelectedPacketByteViewDescriptor* udp_payload_view
) {
    std::vector<std::optional<SelectedPacketByteViewId>> packet_ids(quic_presentation.packets.size());
    if (udp_payload_view == nullptr) {
        return packet_ids;
    }
    const auto udp_payload_id = udp_payload_view->id;

    for (std::size_t packet_index = 0U; packet_index < quic_presentation.packets.size(); ++packet_index) {
        if (packet_index > kMaxViewOccurrence) {
            continue;
        }
        const auto& quic_packet = quic_presentation.packets[packet_index];
        // QUIC parsing retains UDP-payload-relative envelope offsets. Rebase
        // them once here into captured-frame-relative selected-packet bytes.
        const auto packet_offset = narrow_u32(
            static_cast<std::size_t>(udp_payload_view->offset) + quic_packet.udp_payload_offset
        );
        const auto packet_length = narrow_u32(quic_packet.packet_bytes_consumed);
        if (!packet_offset.has_value() || !packet_length.has_value()) {
            continue;
        }

        const auto packet_id = append_view(
            presentation.views,
            udp_payload_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            quic_packet_view_kind(quic_packet.shell_type),
            static_cast<std::uint8_t>(packet_index),
            presentation.owner_captured_length,
            *packet_offset,
            std::optional<std::uint32_t> {*packet_length},
            *packet_length,
            false
        );
        if (!packet_id.has_value()) {
            continue;
        }
        packet_ids[packet_index] = packet_id;

        if (quic_packet.shell_type == QuicPresentationShellType::initial &&
            quic_packet.protected_payload_offset.has_value() &&
            quic_packet.protected_payload_length.has_value()) {
            const auto protected_offset = narrow_u32(
                static_cast<std::size_t>(udp_payload_view->offset) + *quic_packet.protected_payload_offset
            );
            const auto protected_length = narrow_u32(*quic_packet.protected_payload_length);
            if (protected_offset.has_value() && protected_length.has_value()) {
                append_view(
                    presentation.views,
                    packet_id,
                    kCapturedPacketOwnerId,
                    SelectedPacketByteOwnerKind::captured_packet,
                    SelectedPacketByteViewKind::quic_initial_protected_payload,
                    static_cast<std::uint8_t>(packet_index),
                    presentation.owner_captured_length,
                    *protected_offset,
                    std::optional<std::uint32_t> {*protected_length},
                    *protected_length,
                    false
                );
            }
        }
    }
    return packet_ids;
}

void append_quic_initial_plaintext_views(
    SelectedPacketBytePresentation& presentation,
    std::optional<QuicPresentationResult> quic_presentation,
    std::span<const std::optional<SelectedPacketByteViewId>> packet_ids
) {
    if (!quic_presentation.has_value() ||
        !quic_presentation->selected_initial_plaintext_packet_index.has_value() ||
        quic_presentation->selected_initial_plaintext_payload.empty()) {
        return;
    }

    const auto packet_index = *quic_presentation->selected_initial_plaintext_packet_index;
    if (packet_index >= quic_presentation->packets.size() || packet_index > kMaxViewOccurrence) {
        return;
    }

    const auto& quic_packet = quic_presentation->packets[packet_index];
    if (quic_packet.shell_type != QuicPresentationShellType::initial) {
        return;
    }

    const auto owner_id = append_derived_owner(
        presentation.derived_owners,
        SelectedPacketByteOwnerKind::quic_initial_plaintext,
        packet_index,
        std::move(quic_presentation->selected_initial_plaintext_payload)
    );
    if (!owner_id.has_value()) {
        return;
    }

    const auto* owner = presentation.find_derived_owner(*owner_id);
    if (owner == nullptr) {
        return;
    }
    const auto owner_length = narrow_u32(owner->bytes.size());
    if (!owner_length.has_value()) {
        return;
    }

    const auto packet_parent_id =
        packet_index < packet_ids.size()
            ? packet_ids[packet_index]
            : std::nullopt;

    const auto plaintext_id = append_view(
        presentation.views,
        packet_parent_id,
        *owner_id,
        SelectedPacketByteOwnerKind::quic_initial_plaintext,
        SelectedPacketByteViewKind::quic_initial_plaintext,
        static_cast<std::uint8_t>(packet_index),
        *owner_length,
        0U,
        std::optional<std::uint32_t> {*owner_length},
        *owner_length,
        false
    );
    if (!plaintext_id.has_value()) {
        return;
    }

    for (const auto& frame : quic_packet.frames) {
        const auto frame_offset = narrow_u32(frame.frame_offset);
        const auto frame_length = narrow_u32(frame.frame_length);
        if (!frame_offset.has_value() || !frame_length.has_value()) {
            continue;
        }

        const auto frame_id = append_view(
            presentation.views,
            plaintext_id,
            *owner_id,
            SelectedPacketByteOwnerKind::quic_initial_plaintext,
            SelectedPacketByteViewKind::quic_frame,
            static_cast<std::uint8_t>(packet_index),
            *owner_length,
            *frame_offset,
            std::optional<std::uint32_t> {*frame_length},
            *frame_length,
            false,
            frame.crypto_offset
        );
        if (frame.type != QuicPresentationFrameType::crypto ||
            !frame_id.has_value() ||
            !frame.crypto_data_offset_in_plaintext.has_value() ||
            !frame.crypto_length.has_value()) {
            continue;
        }

        const auto crypto_data_offset = narrow_u32(*frame.crypto_data_offset_in_plaintext);
        const auto crypto_data_length = narrow_u32(*frame.crypto_length);
        if (!crypto_data_offset.has_value() || !crypto_data_length.has_value()) {
            continue;
        }

        append_view(
            presentation.views,
            frame_id,
            *owner_id,
            SelectedPacketByteOwnerKind::quic_initial_plaintext,
            SelectedPacketByteViewKind::quic_crypto_data,
            static_cast<std::uint8_t>(packet_index),
            *owner_length,
            *crypto_data_offset,
            std::optional<std::uint32_t> {*crypto_data_length},
            *crypto_data_length,
            false,
            frame.crypto_offset
        );
    }
}

}  // namespace

const SelectedPacketByteViewDescriptor* SelectedPacketBytePresentation::find_view(
    const SelectedPacketByteViewId& id
) const noexcept {
    const auto it = std::find_if(views.begin(), views.end(), [&](const SelectedPacketByteViewDescriptor& view) {
        return view.id == id;
    });
    return it != views.end() ? &(*it) : nullptr;
}

const SelectedPacketByteDerivedOwner* SelectedPacketBytePresentation::find_derived_owner(
    const SelectedPacketByteOwnerId& id
) const noexcept {
    const auto it = std::find_if(
        derived_owners.begin(),
        derived_owners.end(),
        [&](const SelectedPacketByteDerivedOwner& owner) {
            return owner.id == id;
        }
    );
    return it != derived_owners.end() ? &(*it) : nullptr;
}

SelectedPacketBytePresentation build_selected_packet_byte_presentation(
    const PacketDetails& details,
    const PacketRef& packet,
    std::optional<QuicPresentationResult> quic_presentation
) {
    SelectedPacketBytePresentation presentation {};
    presentation.owner_captured_length = packet.captured_length;

    const auto frame_id = append_view(
        presentation.views,
        std::nullopt,
        kCapturedPacketOwnerId,
        presentation.owner_kind,
        SelectedPacketByteViewKind::frame,
        0U,
        presentation.owner_captured_length,
        0U,
        std::optional<std::uint32_t> {packet.original_length},
        packet.captured_length,
        packet.captured_length < packet.original_length
    );

    std::optional<SelectedPacketByteViewId> outer_parent = frame_id;
    std::optional<PacketByteRange> outer_ip_range {};

    if (details.has_ethernet && details.ethernet.payload_range.has_value()) {
        const auto ethernet_id = append_view(
            presentation.views,
            frame_id,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            SelectedPacketByteViewKind::ethernet_payload,
            0U,
            presentation.owner_captured_length,
            *details.ethernet.payload_range
        );
        if (ethernet_id.has_value()) {
            outer_parent = ethernet_id;
        }
        outer_parent = append_vlan_payload_chain(
            presentation.views,
            outer_parent,
            presentation.owner_captured_length,
            *details.ethernet.payload_range,
            details.vlan_tags.size(),
            SelectedPacketByteViewKind::vlan_payload
        );
    }

    if (details.mpls_payload_range.has_value()) {
        const auto mpls_id = append_view(
            presentation.views,
            outer_parent,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            SelectedPacketByteViewKind::mpls_payload,
            0U,
            presentation.owner_captured_length,
            *details.mpls_payload_range
        );
        if (mpls_id.has_value()) {
            outer_parent = mpls_id;
        }
    }

    std::optional<SelectedPacketByteViewId> outer_ip_id {};
    if (details.has_ipv4 && details.ipv4.payload_range.has_value()) {
        outer_ip_range = details.ipv4.payload_range;
        outer_ip_id = append_view(
            presentation.views,
            outer_parent,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            SelectedPacketByteViewKind::ipv4_payload,
            0U,
            presentation.owner_captured_length,
            *details.ipv4.payload_range
        );
    } else if (details.has_ipv6 && details.ipv6.payload_range.has_value()) {
        outer_ip_range = details.ipv6.payload_range;
        outer_ip_id = append_view(
            presentation.views,
            outer_parent,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            SelectedPacketByteViewKind::ipv6_payload,
            0U,
            presentation.owner_captured_length,
            *details.ipv6.payload_range
        );
    }

    std::optional<SelectedPacketByteViewId> outer_udp_id {};
    if (!details.has_ah && details.has_udp && outer_ip_range.has_value()) {
        outer_udp_id = append_udp_payload_view(
            presentation.views,
            outer_ip_id,
            presentation.owner_captured_length,
            *outer_ip_range,
            details.udp,
            SelectedPacketByteViewKind::udp_payload
        );
    }

    append_overlay_payload_branches(
        details,
        presentation.views,
        presentation.owner_captured_length,
        outer_ip_id,
        outer_ip_range,
        outer_udp_id
    );

    const auto* outer_udp_view = outer_udp_id.has_value() ? presentation.find_view(*outer_udp_id) : nullptr;
    const QuicPresentationResult empty_quic_presentation {};
    const auto& quic_presentation_ref =
        quic_presentation.has_value()
            ? *quic_presentation
            : empty_quic_presentation;
    const auto quic_packet_ids = append_quic_packet_views(
        presentation,
        quic_presentation_ref,
        outer_udp_view
    );
    append_quic_initial_plaintext_views(
        presentation,
        std::move(quic_presentation),
        std::span<const std::optional<SelectedPacketByteViewId>>(quic_packet_ids.data(), quic_packet_ids.size())
    );

    return presentation;
}

std::optional<SelectedPacketByteMaterialization> materialize_selected_packet_byte_view(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes
) noexcept {
    const auto* view = presentation.find_view(id);
    if (view == nullptr) {
        return std::nullopt;
    }

    std::span<const std::uint8_t> resolved_owner_bytes {};
    if (view->owner_kind == SelectedPacketByteOwnerKind::captured_packet) {
        if (owner_bytes.size() < presentation.owner_captured_length) {
            return std::nullopt;
        }
        resolved_owner_bytes = owner_bytes;
    } else {
        const auto* owner = presentation.find_derived_owner(view->owner_id);
        if (owner == nullptr) {
            return std::nullopt;
        }
        resolved_owner_bytes = std::span<const std::uint8_t>(owner->bytes.data(), owner->bytes.size());
    }
    if (view->offset > resolved_owner_bytes.size() ||
        view->captured_length > resolved_owner_bytes.size() - view->offset) {
        return std::nullopt;
    }

    return SelectedPacketByteMaterialization {
        .descriptor = view,
        .bytes = resolved_owner_bytes.subspan(view->offset, view->captured_length),
    };
}

std::optional<std::string> format_selected_packet_byte_view_hex_dump(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes,
    const HexDumpService& hex_dump_service
) {
    const auto materialized = materialize_selected_packet_byte_view(presentation, id, owner_bytes);
    if (!materialized.has_value()) {
        return std::nullopt;
    }
    return hex_dump_service.format(materialized->bytes);
}

std::string format_selected_packet_byte_view_stable_id(const SelectedPacketByteViewId& id) {
    std::ostringstream out {};
    out << view_kind_key(id.kind) << ':' << static_cast<unsigned int>(id.scope) << ':' << static_cast<unsigned int>(id.occurrence);
    return out.str();
}

std::optional<SelectedPacketByteViewId> parse_selected_packet_byte_view_stable_id(const std::string_view stable_id) {
    const auto first_separator = stable_id.find(':');
    if (first_separator == std::string_view::npos) {
        return std::nullopt;
    }
    const auto second_separator = stable_id.find(':', first_separator + 1U);
    if (second_separator == std::string_view::npos) {
        return std::nullopt;
    }

    const auto kind_key = stable_id.substr(0U, first_separator);
    const auto parsed_kind = parse_view_kind_key(kind_key);
    if (!parsed_kind.has_value()) {
        return std::nullopt;
    }

    const auto scope_text = stable_id.substr(first_separator + 1U, second_separator - first_separator - 1U);
    const auto occurrence_text = stable_id.substr(second_separator + 1U);
    if (scope_text.empty() || occurrence_text.empty()) {
        return std::nullopt;
    }

    try {
        const auto scope_value = static_cast<unsigned long>(std::stoul(std::string {scope_text}));
        const auto occurrence_value = static_cast<unsigned long>(std::stoul(std::string {occurrence_text}));
        if (scope_value > 0xFFUL || occurrence_value > 0xFFUL) {
            return std::nullopt;
        }

        return SelectedPacketByteViewId {
            .kind = *parsed_kind,
            .scope = static_cast<std::uint8_t>(scope_value),
            .occurrence = static_cast<std::uint8_t>(occurrence_value),
        };
    } catch (...) {
        return std::nullopt;
    }
}

std::vector<SelectedPacketByteViewPresentationDescriptor> build_selected_packet_byte_view_descriptors(
    const SelectedPacketBytePresentation& presentation
) {
    std::vector<SelectedPacketByteViewPresentationDescriptor> descriptors {};
    descriptors.reserve(presentation.views.size());

    auto resolve_depth = [&](const SelectedPacketByteViewDescriptor& view) {
        std::size_t depth = 0U;
        auto parent_id = view.parent_id;
        while (parent_id.has_value()) {
            const auto* parent = presentation.find_view(*parent_id);
            if (parent == nullptr) {
                break;
            }
            ++depth;
            parent_id = parent->parent_id;
        }
        return depth;
    };

    for (const auto& view : presentation.views) {
        descriptors.push_back(SelectedPacketByteViewPresentationDescriptor {
            .stable_id = format_selected_packet_byte_view_stable_id(view.id),
            .label = view_label(view),
            .parent_stable_id = view.parent_id.has_value()
                ? std::optional<std::string> {format_selected_packet_byte_view_stable_id(*view.parent_id)}
                : std::nullopt,
            .depth = resolve_depth(view),
            .owner_kind = owner_kind_key(view.owner_kind),
            .available_length = view.captured_length,
            .declared_length = view.declared_length,
            .state = descriptor_state(view),
            .quic_crypto_stream_offset = view.quic_crypto_stream_offset,
        });
    }

    return descriptors;
}

std::optional<SelectedPacketByteViewContent> format_selected_packet_byte_view_content(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes,
    const HexDumpService& hex_dump_service
) {
    const auto materialized = materialize_selected_packet_byte_view(presentation, id, owner_bytes);
    if (!materialized.has_value() || materialized->descriptor == nullptr) {
        return std::nullopt;
    }

    return SelectedPacketByteViewContent {
        .stable_id = format_selected_packet_byte_view_stable_id(id),
        .label = view_label(*materialized->descriptor),
        .available_length = materialized->descriptor->captured_length,
        .declared_length = materialized->descriptor->declared_length,
        .state = descriptor_state(*materialized->descriptor),
        .formatted_text = hex_dump_service.format(materialized->bytes),
    };
}

}  // namespace pfl::session_detail
