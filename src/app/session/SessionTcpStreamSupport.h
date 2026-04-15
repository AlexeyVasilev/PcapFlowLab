#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <vector>

#include "core/domain/PacketRef.h"

namespace pfl {

class CaptureSession;

namespace session_detail {

struct TcpPayloadContribution {
    bool suppress_entire_packet {false};
    std::size_t trim_prefix_bytes {0};
};

struct TcpDirectionalGapState {
    bool tainted_by_gap {false};
    std::uint64_t first_gap_packet_index {0};
};

struct TcpPayloadSuppressionAnalysis {
    std::map<std::uint64_t, TcpPayloadContribution> packet_contributions {};
    TcpDirectionalGapState gap_state_a_to_b {};
    TcpDirectionalGapState gap_state_b_to_a {};
};

std::vector<std::uint64_t> collect_suspected_tcp_retransmission_packet_indices(
    const CaptureSession& session,
    std::size_t flow_index,
    std::span<const PacketRef> flow_a_packets,
    std::span<const PacketRef> flow_b_packets,
    std::size_t max_packets_to_scan
);

TcpPayloadSuppressionAnalysis analyze_selected_flow_tcp_payload_suppression(
    const CaptureSession& session,
    std::size_t flow_index,
    std::span<const PacketRef> flow_a_packets,
    std::span<const PacketRef> flow_b_packets,
    const std::set<std::uint64_t>& exact_duplicate_packet_indices,
    std::size_t prefix_count_a,
    std::size_t prefix_count_b
);

}  // namespace session_detail
}  // namespace pfl
