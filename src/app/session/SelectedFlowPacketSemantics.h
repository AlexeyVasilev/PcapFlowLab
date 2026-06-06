#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/PacketRef.h"

namespace pfl {

class CaptureSession;

}  // namespace pfl

namespace pfl::session_detail {

[[nodiscard]] std::optional<std::uint32_t> derive_transport_payload_length_from_headers(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
);

[[nodiscard]] std::optional<std::uint32_t> derive_transport_payload_length_from_headers(
    const CaptureSession& session,
    const PacketRef& packet
);

void apply_original_transport_payload_lengths(CaptureSession& session, std::vector<PacketRow>& rows);

}  // namespace pfl::session_detail
