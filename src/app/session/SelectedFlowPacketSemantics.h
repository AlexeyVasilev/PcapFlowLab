#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"

namespace pfl {

class CaptureSession;

}  // namespace pfl

namespace pfl::session_detail {

struct TransientPacketDerivedMetadata {
    std::optional<std::uint32_t> captured_transport_payload_length {};
    std::optional<std::uint32_t> original_transport_payload_length {};
    std::optional<std::uint8_t> tcp_flags {};
    std::optional<bool> is_ip_fragmented {};
};

[[nodiscard]] std::optional<bool> derive_ip_fragmentation_state_from_packet_details(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet,
    const PacketDetails& details
);

[[nodiscard]] TransientPacketDerivedMetadata derive_transient_packet_metadata(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
);

[[nodiscard]] TransientPacketDerivedMetadata derive_transient_packet_metadata(
    const CaptureSession& session,
    const PacketRef& packet
);

[[nodiscard]] std::optional<std::uint32_t> derive_captured_transport_payload_length_from_headers(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
);

[[nodiscard]] std::optional<std::uint32_t> derive_captured_transport_payload_length_from_headers(
    const CaptureSession& session,
    const PacketRef& packet
);

[[nodiscard]] std::optional<std::uint32_t> derive_original_transport_payload_length_from_headers(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
);

[[nodiscard]] std::optional<std::uint32_t> derive_original_transport_payload_length_from_headers(
    const CaptureSession& session,
    const PacketRef& packet
);

void apply_original_transport_payload_lengths(CaptureSession& session, std::vector<PacketRow>& rows);

void populate_transient_packet_row_metadata(CaptureSession& session, std::vector<PacketRow>& rows);

}  // namespace pfl::session_detail
