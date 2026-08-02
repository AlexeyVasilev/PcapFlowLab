#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"

namespace pfl {
class HexDumpService;
}

namespace pfl::session_detail {

enum class SelectedPacketByteOwnerKind : std::uint8_t {
    captured_packet = 0,
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
};

struct SelectedPacketByteViewId {
    SelectedPacketByteViewKind kind {SelectedPacketByteViewKind::frame};
    std::uint8_t occurrence {0};

    [[nodiscard]] friend constexpr bool operator==(const SelectedPacketByteViewId&, const SelectedPacketByteViewId&) = default;
};

struct SelectedPacketByteViewDescriptor {
    SelectedPacketByteViewId id {};
    std::optional<SelectedPacketByteViewId> parent_id {};
    SelectedPacketByteOwnerKind owner_kind {SelectedPacketByteOwnerKind::captured_packet};
    std::uint32_t offset {0};
    std::optional<std::uint32_t> declared_length {};
    std::uint32_t captured_length {0};
    bool truncated {false};
};

struct SelectedPacketBytePresentation {
    SelectedPacketByteOwnerKind owner_kind {SelectedPacketByteOwnerKind::captured_packet};
    std::uint32_t owner_captured_length {0};
    std::vector<SelectedPacketByteViewDescriptor> views {};

    [[nodiscard]] const SelectedPacketByteViewDescriptor* find_view(const SelectedPacketByteViewId& id) const noexcept;
};

struct SelectedPacketByteMaterialization {
    const SelectedPacketByteViewDescriptor* descriptor {nullptr};
    std::span<const std::uint8_t> bytes {};
};

[[nodiscard]] SelectedPacketBytePresentation build_selected_packet_byte_presentation(
    const PacketDetails& details,
    const PacketRef& packet
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
