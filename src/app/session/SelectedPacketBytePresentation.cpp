#include "app/session/SelectedPacketBytePresentation.h"

#include <algorithm>

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

}  // namespace pfl::session_detail
