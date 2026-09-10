#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "core/dissection/DissectionTypes.h"
#include "core/domain/ProtocolId.h"
#include "core/domain/TerminalTransportPayloadBounds.h"

namespace pfl::dissection {

struct RuntimeDissectionFacts {
    ProtocolId terminal_protocol {ProtocolId::unknown};
    std::optional<std::uint32_t> captured_transport_payload_length {};
    std::optional<std::uint32_t> original_transport_payload_length {};
    std::optional<TerminalTransportPayloadBounds> terminal_transport_payload_bounds {};
    std::optional<std::uint8_t> tcp_flags {};
    std::optional<bool> is_ip_fragmented {};
    ParseStatus final_status {ParseStatus::opaque};
    StopReason stop_reason {StopReason::none};
    std::size_t step_count {0U};
    std::size_t traversed_depth {0U};
};

[[nodiscard]] RuntimeDissectionFacts derive_runtime_dissection_facts(
    std::span<const std::uint8_t> packet_bytes,
    std::uint32_t captured_length,
    std::uint32_t original_length,
    std::uint32_t data_link_type
);

}  // namespace pfl::dissection
