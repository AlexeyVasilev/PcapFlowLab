#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/domain/Direction.h"

namespace pfl {

struct ReassemblyRequest {
    std::size_t flow_index {0};
    Direction direction {Direction::a_to_b};
    std::size_t max_packets {128};
    std::size_t max_bytes {128U * 1024U};
};

enum class ReassemblyQualityFlag : std::uint32_t {
    none = 0,
    packet_order_only = 1U << 0U,
    truncated_by_packet_budget = 1U << 1U,
    truncated_by_byte_budget = 1U << 2U,
    contains_non_payload_packets = 1U << 3U,
    may_contain_transport_gaps = 1U << 4U,
    may_contain_retransmissions = 1U << 5U,
};

struct ReassemblyResult {
    std::vector<std::uint8_t> bytes {};
    std::vector<std::uint64_t> packet_indices {};
    std::uint32_t quality_flags {0};
    std::size_t payload_packets_used {0};
    std::size_t total_packets_seen {0};

    [[nodiscard]] bool empty() const noexcept {
        return bytes.empty();
    }
};

}  // namespace pfl
