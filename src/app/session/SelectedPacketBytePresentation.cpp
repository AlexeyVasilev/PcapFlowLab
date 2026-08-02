#include "app/session/SelectedPacketBytePresentation.h"

#include <algorithm>

#include "core/services/HexDumpService.h"

namespace pfl::session_detail {

namespace {

constexpr std::size_t kMaxViewOccurrence = 0xFFU;

bool equivalent_view(
    const SelectedPacketByteViewDescriptor& existing,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint32_t offset,
    const std::optional<std::uint32_t>& declared_length,
    const std::uint32_t captured_length,
    const bool truncated
) noexcept {
    return existing.parent_id == parent_id &&
        existing.owner_kind == owner_kind &&
        existing.id.kind == kind &&
        existing.offset == offset &&
        existing.declared_length == declared_length &&
        existing.captured_length == captured_length &&
        existing.truncated == truncated;
}

std::optional<SelectedPacketByteViewId> append_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint32_t owner_captured_length,
    const std::uint32_t offset,
    const std::optional<std::uint32_t>& declared_length,
    const std::uint32_t captured_length,
    const bool truncated
) {
    if (captured_length == 0U ||
        offset >= owner_captured_length ||
        captured_length > owner_captured_length - offset) {
        return std::nullopt;
    }

    if (std::any_of(views.begin(), views.end(), [&](const SelectedPacketByteViewDescriptor& existing) {
            return equivalent_view(
                existing,
                parent_id,
                owner_kind,
                kind,
                offset,
                declared_length,
                captured_length,
                truncated
            );
        })) {
        return std::nullopt;
    }

    const auto occurrence_count = static_cast<std::size_t>(std::count_if(
        views.begin(),
        views.end(),
        [&](const SelectedPacketByteViewDescriptor& existing) {
            return existing.id.kind == kind;
        }
    ));
    if (occurrence_count > kMaxViewOccurrence) {
        return std::nullopt;
    }

    const SelectedPacketByteViewId id {
        .kind = kind,
        .occurrence = static_cast<std::uint8_t>(occurrence_count),
    };
    views.push_back(SelectedPacketByteViewDescriptor {
        .id = id,
        .parent_id = parent_id,
        .owner_kind = owner_kind,
        .offset = offset,
        .declared_length = declared_length,
        .captured_length = captured_length,
        .truncated = truncated,
    });
    return id;
}

std::optional<SelectedPacketByteViewId> append_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& range
) {
    return append_view(
        views,
        parent_id,
        owner_kind,
        kind,
        owner_captured_length,
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
        SelectedPacketByteOwnerKind::captured_packet,
        kind,
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
        SelectedPacketByteOwnerKind::captured_packet,
        kind,
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
        SelectedPacketByteOwnerKind::captured_packet,
        kind,
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
            SelectedPacketByteOwnerKind::captured_packet,
            kind,
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
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::inner_ipv4_payload,
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
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::inner_ipv6_payload,
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
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::inner_ethernet_payload,
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
                SelectedPacketByteOwnerKind::captured_packet,
                SelectedPacketByteViewKind::mpls_payload,
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
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::ah_payload,
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
            SelectedPacketByteOwnerKind::captured_packet,
            details.gre.is_eoip
                ? SelectedPacketByteViewKind::eoip_payload
                : SelectedPacketByteViewKind::gre_payload,
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
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::esp_protected_payload,
            owner_captured_length,
            *details.esp.protected_payload_range
        );
        return;
    }

    if (details.has_gtpu && details.gtpu.payload_range.has_value() && outer_udp_id.has_value()) {
        const auto gtpu_id = append_view(
            views,
            outer_udp_id,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::gtpu_payload,
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
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::vxlan_payload,
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
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::geneve_payload,
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
                    SelectedPacketByteOwnerKind::captured_packet,
                    SelectedPacketByteViewKind::inner_ipv4_payload,
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
                    SelectedPacketByteOwnerKind::captured_packet,
                    SelectedPacketByteViewKind::inner_ipv6_payload,
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

}  // namespace

const SelectedPacketByteViewDescriptor* SelectedPacketBytePresentation::find_view(
    const SelectedPacketByteViewId& id
) const noexcept {
    const auto it = std::find_if(views.begin(), views.end(), [&](const SelectedPacketByteViewDescriptor& view) {
        return view.id == id;
    });
    return it != views.end() ? &(*it) : nullptr;
}

SelectedPacketBytePresentation build_selected_packet_byte_presentation(
    const PacketDetails& details,
    const PacketRef& packet
) {
    SelectedPacketBytePresentation presentation {};
    presentation.owner_captured_length = packet.captured_length;

    const auto frame_id = append_view(
        presentation.views,
        std::nullopt,
        presentation.owner_kind,
        SelectedPacketByteViewKind::frame,
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
            presentation.owner_kind,
            SelectedPacketByteViewKind::ethernet_payload,
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
            presentation.owner_kind,
            SelectedPacketByteViewKind::mpls_payload,
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
            presentation.owner_kind,
            SelectedPacketByteViewKind::ipv4_payload,
            presentation.owner_captured_length,
            *details.ipv4.payload_range
        );
    } else if (details.has_ipv6 && details.ipv6.payload_range.has_value()) {
        outer_ip_range = details.ipv6.payload_range;
        outer_ip_id = append_view(
            presentation.views,
            outer_parent,
            presentation.owner_kind,
            SelectedPacketByteViewKind::ipv6_payload,
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

    return presentation;
}

std::optional<SelectedPacketByteMaterialization> materialize_selected_packet_byte_view(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes
) noexcept {
    const auto* view = presentation.find_view(id);
    if (view == nullptr || view->owner_kind != SelectedPacketByteOwnerKind::captured_packet) {
        return std::nullopt;
    }
    if (owner_bytes.size() < presentation.owner_captured_length) {
        return std::nullopt;
    }
    if (view->offset > owner_bytes.size() || view->captured_length > owner_bytes.size() - view->offset) {
        return std::nullopt;
    }

    return SelectedPacketByteMaterialization {
        .descriptor = view,
        .bytes = owner_bytes.subspan(view->offset, view->captured_length),
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
