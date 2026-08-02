#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"
#include "app/session/SessionQuicPresentation.h"

namespace pfl {
class HexDumpService;
}

namespace pfl::session_detail {

enum class SelectedPacketByteOwnerKind : std::uint8_t {
    captured_packet = 0,
    quic_initial_plaintext,
};

struct SelectedPacketByteOwnerId {
    SelectedPacketByteOwnerKind kind {SelectedPacketByteOwnerKind::captured_packet};
    std::uint8_t occurrence {0};

    [[nodiscard]] friend constexpr bool operator==(const SelectedPacketByteOwnerId&, const SelectedPacketByteOwnerId&) = default;
};

enum class SelectedPacketByteViewKind : std::uint8_t {
    frame = 0,
    ethernet_payload,
    vlan_payload,
    mpls_payload,
    ipv4_payload,
    ipv6_payload,
    tcp_payload,
    udp_payload,
    sctp_payload,
    effective_transport_payload,
    inner_ethernet_payload,
    inner_vlan_payload,
    inner_ipv4_payload,
    inner_ipv6_payload,
    inner_tcp_payload,
    inner_udp_payload,
    inner_sctp_payload,
    gre_payload,
    eoip_payload,
    vxlan_payload,
    geneve_payload,
    gtpu_payload,
    ah_payload,
    esp_protected_payload,
    quic_initial_packet,
    quic_zero_rtt_packet,
    quic_handshake_packet,
    quic_retry_packet,
    quic_version_negotiation_packet,
    quic_protected_packet,
    quic_initial_protected_payload,
    quic_initial_plaintext,
    quic_frame,
    quic_crypto_data,
};

struct SelectedPacketByteViewId {
    SelectedPacketByteViewKind kind {SelectedPacketByteViewKind::frame};
    std::uint8_t scope {0};
    std::uint8_t occurrence {0};

    [[nodiscard]] friend constexpr bool operator==(const SelectedPacketByteViewId&, const SelectedPacketByteViewId&) = default;
};

struct SelectedPacketByteDerivedOwner {
    SelectedPacketByteOwnerId id {};
    // Selected QUIC envelope ordinal inside the owning UDP datagram.
    std::size_t quic_packet_index {0U};
    std::vector<std::uint8_t> bytes {};
};

struct SelectedPacketByteViewDescriptor {
    SelectedPacketByteViewId id {};
    std::optional<SelectedPacketByteViewId> parent_id {};
    SelectedPacketByteOwnerId owner_id {};
    SelectedPacketByteOwnerKind owner_kind {SelectedPacketByteOwnerKind::captured_packet};
    std::uint32_t offset {0};
    std::optional<std::uint32_t> declared_length {};
    std::uint32_t captured_length {0};
    bool truncated {false};
    std::optional<std::uint64_t> quic_crypto_stream_offset {};
};

struct SelectedPacketBytePresentation {
    SelectedPacketByteOwnerKind owner_kind {SelectedPacketByteOwnerKind::captured_packet};
    std::uint32_t owner_captured_length {0};
    std::vector<SelectedPacketByteDerivedOwner> derived_owners {};
    std::vector<SelectedPacketByteViewDescriptor> views {};

    [[nodiscard]] const SelectedPacketByteViewDescriptor* find_view(const SelectedPacketByteViewId& id) const noexcept;
    [[nodiscard]] const SelectedPacketByteDerivedOwner* find_derived_owner(const SelectedPacketByteOwnerId& id) const noexcept;
};

struct SelectedPacketByteMaterialization {
    const SelectedPacketByteViewDescriptor* descriptor {nullptr};
    std::span<const std::uint8_t> bytes {};
};

[[nodiscard]] SelectedPacketBytePresentation build_selected_packet_byte_presentation(
    const PacketDetails& details,
    const PacketRef& packet,
    std::optional<QuicPresentationResult> quic_presentation = {}
);

[[nodiscard]] std::optional<SelectedPacketByteMaterialization> materialize_selected_packet_byte_view(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes
) noexcept;

[[nodiscard]] std::optional<std::string> format_selected_packet_byte_view_hex_dump(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes,
    const HexDumpService& hex_dump_service
);

}  // namespace pfl::session_detail
