#include "app/session/SelectedPacketBytePresentation.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/services/HexDumpService.h"

namespace pfl::session_detail {

namespace {

constexpr std::size_t kMaxViewOccurrence = 0xFFU;

template <typename InnerPacket>
void append_inner_ip_payload_views(
    const InnerPacket& inner,
    const std::uint32_t owner_captured_length,
    std::vector<SelectedPacketByteViewDescriptor>& views
);

bool ranges_match(
    const SelectedPacketByteViewDescriptor& left,
    const SelectedPacketByteOwnerKind owner_kind,
    const std::uint32_t offset,
    const std::optional<std::uint32_t>& declared_length,
    const std::uint32_t captured_length,
    const bool truncated
) noexcept {
    return left.owner_kind == owner_kind &&
        left.offset == offset &&
        left.declared_length == declared_length &&
        left.captured_length == captured_length &&
        left.truncated == truncated;
}

bool append_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint32_t owner_captured_length,
    const std::uint32_t offset,
    const std::optional<std::uint32_t>& declared_length,
    const std::uint32_t captured_length,
    const bool truncated
) {
    if (captured_length == 0U || offset >= owner_captured_length || captured_length > owner_captured_length - offset) {
        return false;
    }

    if (std::any_of(views.begin(), views.end(), [&](const SelectedPacketByteViewDescriptor& existing) {
            return ranges_match(existing, owner_kind, offset, declared_length, captured_length, truncated);
        })) {
        return false;
    }

    const auto occurrence_count = static_cast<std::size_t>(std::count_if(
        views.begin(),
        views.end(),
        [&](const SelectedPacketByteViewDescriptor& existing) {
            return existing.id.kind == kind;
        }
    ));
    if (occurrence_count > kMaxViewOccurrence) {
        return false;
    }

    views.push_back(SelectedPacketByteViewDescriptor {
        .id = SelectedPacketByteViewId {
            .kind = kind,
            .occurrence = static_cast<std::uint8_t>(occurrence_count),
        },
        .owner_kind = owner_kind,
        .offset = offset,
        .declared_length = declared_length,
        .captured_length = captured_length,
        .truncated = truncated,
    });
    return true;
}

bool append_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& range
) {
    return append_view(
        views,
        owner_kind,
        kind,
        owner_captured_length,
        range.offset,
        range.declared_length,
        range.captured_length,
        range.truncated
    );
}

std::optional<std::uint32_t> ethernet_payload_end(
    const PacketDetails& details,
    const PacketRef& packet
) {
    if (!details.has_ethernet || packet.data_link_type != kLinkTypeEthernet ||
        packet.captured_length <= detail::kEthernetHeaderSize) {
        return std::nullopt;
    }

    const auto captured_length = static_cast<std::size_t>(packet.captured_length);
    const auto max_trailer_length = captured_length - detail::kEthernetHeaderSize;
    const auto trailer_length = std::min(details.ethernet.trailer_length, max_trailer_length);
    const auto payload_end = captured_length - trailer_length;
    if (payload_end <= detail::kEthernetHeaderSize || payload_end > 0xFFFFFFFFU) {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(payload_end);
}

void append_top_level_payload_views(
    const PacketDetails& details,
    const PacketRef& packet,
    SelectedPacketBytePresentation& presentation
) {
    append_view(
        presentation.views,
        presentation.owner_kind,
        SelectedPacketByteViewKind::frame,
        presentation.owner_captured_length,
        0U,
        std::optional<std::uint32_t> {packet.original_length},
        packet.captured_length,
        packet.captured_length < packet.original_length
    );

    if (const auto payload_end = ethernet_payload_end(details, packet); payload_end.has_value()) {
        append_view(
            presentation.views,
            presentation.owner_kind,
            SelectedPacketByteViewKind::ethernet_payload,
            presentation.owner_captured_length,
            static_cast<std::uint32_t>(detail::kEthernetHeaderSize),
            std::nullopt,
            *payload_end - static_cast<std::uint32_t>(detail::kEthernetHeaderSize),
            false
        );

        for (std::size_t index = 0U; index < details.vlan_tags.size(); ++index) {
            const auto vlan_payload_offset = static_cast<std::size_t>(detail::kEthernetHeaderSize) +
                ((index + 1U) * detail::kVlanHeaderSize);
            if (vlan_payload_offset >= *payload_end) {
                break;
            }
            append_view(
                presentation.views,
                presentation.owner_kind,
                SelectedPacketByteViewKind::vlan_payload,
                presentation.owner_captured_length,
                static_cast<std::uint32_t>(vlan_payload_offset),
                std::nullopt,
                *payload_end - static_cast<std::uint32_t>(vlan_payload_offset),
                false
            );
        }
    }

    if (details.mpls_payload_range.has_value()) {
        append_view(
            presentation.views,
            presentation.owner_kind,
            SelectedPacketByteViewKind::mpls_payload,
            presentation.owner_captured_length,
            *details.mpls_payload_range
        );
    }

    if (details.has_ipv4 && details.ipv4.payload_range.has_value()) {
        append_view(
            presentation.views,
            presentation.owner_kind,
            SelectedPacketByteViewKind::ipv4_payload,
            presentation.owner_captured_length,
            *details.ipv4.payload_range
        );
    }

    if (details.has_ipv6 && details.ipv6.payload_range.has_value()) {
        append_view(
            presentation.views,
            presentation.owner_kind,
            SelectedPacketByteViewKind::ipv6_payload,
            presentation.owner_captured_length,
            *details.ipv6.payload_range
        );
    }

    if (details.effective_transport_payload.has_value() &&
        details.effective_transport_payload->role == EffectiveTransportRole::top_level) {
        const auto& payload = *details.effective_transport_payload;
        const auto top_level_kind = payload.transport == EffectiveTransportKind::tcp
            ? SelectedPacketByteViewKind::tcp_payload
            : payload.transport == EffectiveTransportKind::udp
                ? SelectedPacketByteViewKind::udp_payload
                : SelectedPacketByteViewKind::effective_transport_payload;
        if (payload.transport != EffectiveTransportKind::unknown) {
            append_view(
                presentation.views,
                presentation.owner_kind,
                top_level_kind,
                presentation.owner_captured_length,
                payload.payload_offset,
                payload.declared_payload_length,
                payload.captured_payload_length,
                payload.payload_truncated
            );
        }
    }

    if (details.has_sctp && details.sctp.payload_range.has_value()) {
        append_view(
            presentation.views,
            presentation.owner_kind,
            SelectedPacketByteViewKind::sctp_payload,
            presentation.owner_captured_length,
            *details.sctp.payload_range
        );
    }

    if (details.effective_transport_payload.has_value()) {
        const auto& payload = *details.effective_transport_payload;
        append_view(
            presentation.views,
            presentation.owner_kind,
            SelectedPacketByteViewKind::effective_transport_payload,
            presentation.owner_captured_length,
            payload.payload_offset,
            payload.declared_payload_length,
            payload.captured_payload_length,
            payload.payload_truncated
        );
    }
}

template <typename InnerPacket>
void append_inner_ip_payload_views(
    const InnerPacket& inner,
    const std::uint32_t owner_captured_length,
    std::vector<SelectedPacketByteViewDescriptor>& views
) {
    if (inner.has_ipv4 && inner.ipv4.payload_range.has_value()) {
        append_view(
            views,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::inner_ipv4_payload,
            owner_captured_length,
            *inner.ipv4.payload_range
        );
    }
    if (inner.has_ipv6 && inner.ipv6.payload_range.has_value()) {
        append_view(
            views,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::inner_ipv6_payload,
            owner_captured_length,
            *inner.ipv6.payload_range
        );
    }
}

void append_inner_payload_views(
    const PacketDetails& details,
    SelectedPacketBytePresentation& presentation
) {
    if (details.has_vxlan && details.vxlan.has_inner_packet && details.vxlan.inner_packet != nullptr) {
        append_inner_ip_payload_views(*details.vxlan.inner_packet, presentation.owner_captured_length, presentation.views);
    }
    if (details.has_geneve && details.geneve.has_inner_packet && details.geneve.inner_packet != nullptr) {
        append_inner_ip_payload_views(*details.geneve.inner_packet, presentation.owner_captured_length, presentation.views);
    }
    if (details.has_gtpu && details.gtpu.has_inner_packet && details.gtpu.inner_packet != nullptr) {
        append_inner_ip_payload_views(*details.gtpu.inner_packet, presentation.owner_captured_length, presentation.views);
    }
    if (details.has_gre && details.gre.has_inner_packet && details.gre.inner_packet != nullptr) {
        append_inner_ip_payload_views(*details.gre.inner_packet, presentation.owner_captured_length, presentation.views);
    }
    if (details.has_ah && details.ah.has_inner_packet && details.ah.inner_packet != nullptr) {
        append_inner_ip_payload_views(*details.ah.inner_packet, presentation.owner_captured_length, presentation.views);
    }
    if (details.has_ip_encapsulation) {
        for (const auto& inner_layer : details.ip_encapsulation.inner_ip_layers) {
            if (inner_layer.has_ipv4 && inner_layer.ipv4.payload_range.has_value()) {
                append_view(
                    presentation.views,
                    presentation.owner_kind,
                    SelectedPacketByteViewKind::inner_ipv4_payload,
                    presentation.owner_captured_length,
                    *inner_layer.ipv4.payload_range
                );
            }
            if (inner_layer.has_ipv6 && inner_layer.ipv6.payload_range.has_value()) {
                append_view(
                    presentation.views,
                    presentation.owner_kind,
                    SelectedPacketByteViewKind::inner_ipv6_payload,
                    presentation.owner_captured_length,
                    *inner_layer.ipv6.payload_range
                );
            }
        }
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
    append_top_level_payload_views(details, packet, presentation);
    append_inner_payload_views(details, presentation);
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
