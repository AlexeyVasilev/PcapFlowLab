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
    arp,
    ipv4_payload,
    ipv6_payload,
    tcp_payload,
    udp_payload,
    sctp_payload,
    icmp,
    icmpv6,
    igmp,
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

enum class SelectedPacketByteViewRole : std::uint8_t {
    protocol_unit = 0,
    payload_fallback,
    derived_value,
};

enum class SelectedPacketByteRangeMode : std::uint8_t {
    whole_unit = 0,
    payload_only,
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
    SelectedPacketByteViewRole role {SelectedPacketByteViewRole::protocol_unit};
    std::uint32_t offset {0};
    std::optional<std::uint32_t> declared_length {};
    std::uint32_t captured_length {0};
    bool truncated {false};
    std::optional<PacketByteRange> payload_range {};
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
    SelectedPacketByteRangeMode mode {SelectedPacketByteRangeMode::whole_unit};
    std::span<const std::uint8_t> bytes {};
};

struct SelectedPacketByteViewPresentationDescriptor {
    std::string stable_id {};
    std::string label {};
    std::optional<std::string> parent_stable_id {};
    std::size_t depth {0U};
    std::string owner_kind {};
    std::string role {};
    std::uint32_t available_length {0U};
    std::optional<std::uint32_t> declared_length {};
    std::string state {};
    bool supports_payload_only {false};
    std::optional<std::uint32_t> payload_available_length {};
    std::optional<std::uint32_t> payload_declared_length {};
    std::optional<std::string> payload_state {};
    std::optional<std::uint64_t> quic_crypto_stream_offset {};
};

struct SelectedPacketByteViewContent {
    std::string stable_id {};
    std::string label {};
    SelectedPacketByteRangeMode mode {SelectedPacketByteRangeMode::whole_unit};
    std::uint32_t available_length {0U};
    std::optional<std::uint32_t> declared_length {};
    std::string state {};
    std::string formatted_text {};
};

[[nodiscard]] SelectedPacketBytePresentation build_selected_packet_byte_presentation(
    const PacketDetails& details,
    const PacketRef& packet,
    std::optional<QuicPresentationResult> quic_presentation = {}
);

[[nodiscard]] std::optional<SelectedPacketByteMaterialization> materialize_selected_packet_byte_view(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes,
    SelectedPacketByteRangeMode mode = SelectedPacketByteRangeMode::whole_unit
) noexcept;

[[nodiscard]] std::optional<std::string> format_selected_packet_byte_view_hex_dump(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes,
    const HexDumpService& hex_dump_service,
    SelectedPacketByteRangeMode mode = SelectedPacketByteRangeMode::whole_unit
);

[[nodiscard]] std::string format_selected_packet_byte_view_stable_id(const SelectedPacketByteViewId& id);
[[nodiscard]] std::optional<SelectedPacketByteViewId> parse_selected_packet_byte_view_stable_id(std::string_view stable_id);
[[nodiscard]] std::vector<SelectedPacketByteViewPresentationDescriptor> build_selected_packet_byte_view_descriptors(
    const SelectedPacketBytePresentation& presentation
);
[[nodiscard]] std::optional<SelectedPacketByteViewContent> format_selected_packet_byte_view_content(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes,
    const HexDumpService& hex_dump_service,
    SelectedPacketByteRangeMode mode = SelectedPacketByteRangeMode::whole_unit
);

}  // namespace pfl::session_detail
