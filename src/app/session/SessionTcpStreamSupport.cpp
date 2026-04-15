#include "app/session/SessionTcpStreamSupport.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <tuple>

#include "app/session/CaptureSession.h"
#include "core/services/PacketDetailsService.h"

namespace pfl::session_detail {

namespace {

using SuspectedTcpRetransmissionFingerprint = std::tuple<
    std::uint8_t,
    std::uint32_t,
    std::uint32_t,
    std::uint32_t,
    std::uint64_t
>;

struct SeenTcpPayloadCandidate {
    std::uint64_t packet_index {0};
    std::vector<std::uint8_t> payload_bytes {};
};

struct DecodedTcpPayloadPacket {
    PacketRef packet {};
    std::uint64_t sequence_number {0};
    std::uint32_t acknowledgement_number {0};
    std::vector<std::uint8_t> payload_bytes {};
};

struct TcpContributionTracker {
    bool has_contiguous_stream {false};
    bool overlap_tracking_enabled {true};
    std::uint64_t base_sequence {0};
    std::uint64_t next_sequence {0};
    std::uint32_t last_acknowledgement_number {0};
    std::vector<std::uint8_t> contiguous_bytes {};
};

struct TcpDirectionalContributionAnalysis {
    std::map<std::uint64_t, TcpPayloadContribution> contributions {};
    bool tainted_by_gap {false};
    std::uint64_t first_gap_packet_index {0};
};

std::uint64_t stable_payload_hash(std::span<const std::uint8_t> payload) noexcept {
    constexpr std::uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
    constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

    std::uint64_t hash = kFnvOffsetBasis;
    for (const auto byte : payload) {
        hash ^= static_cast<std::uint64_t>(byte);
        hash *= kFnvPrime;
    }

    return hash;
}

std::optional<DecodedTcpPayloadPacket> decode_tcp_payload_packet(
    const CaptureSession& session,
    const std::size_t flow_index,
    const PacketRef& packet,
    PacketDetailsService& details_service
) {
    if (packet.payload_length == 0U) {
        return std::nullopt;
    }

    const auto packet_bytes = session.read_packet_data(packet);
    if (packet_bytes.empty()) {
        return std::nullopt;
    }

    const auto details = details_service.decode(packet_bytes, packet);
    if (!details.has_value() || !details->has_tcp) {
        return std::nullopt;
    }

    auto payload_bytes = session.read_selected_flow_transport_payload(flow_index, packet);
    if (payload_bytes.size() != packet.payload_length || payload_bytes.empty()) {
        return std::nullopt;
    }

    return DecodedTcpPayloadPacket {
        .packet = packet,
        .sequence_number = details->tcp.seq_number,
        .acknowledgement_number = details->tcp.ack_number,
        .payload_bytes = std::move(payload_bytes),
    };
}

TcpDirectionalContributionAnalysis analyze_selected_flow_tcp_payload_suppression_for_direction(
    const CaptureSession& session,
    const std::size_t flow_index,
    std::span<const PacketRef> packets,
    const std::set<std::uint64_t>& exact_duplicate_packet_indices,
    const std::size_t max_packets_to_scan = std::numeric_limits<std::size_t>::max()
) {
    TcpDirectionalContributionAnalysis analysis {};
    PacketDetailsService details_service {};
    TcpContributionTracker tracker {};
    std::size_t processed_packets = 0U;

    const auto mark_gap = [&](const std::uint64_t packet_index) {
        analysis.tainted_by_gap = true;
        analysis.first_gap_packet_index = packet_index;
    };

    for (const auto& packet : packets) {
        if (processed_packets >= max_packets_to_scan) {
            break;
        }
        ++processed_packets;

        const auto decoded = decode_tcp_payload_packet(session, flow_index, packet, details_service);
        if (!decoded.has_value()) {
            continue;
        }

        if (exact_duplicate_packet_indices.contains(packet.packet_index)) {
            analysis.contributions[packet.packet_index].suppress_entire_packet = true;
            continue;
        }

        const auto payload_size = decoded->payload_bytes.size();
        const auto sequence_start = decoded->sequence_number;
        const auto sequence_end = sequence_start + payload_size;

        if (!tracker.has_contiguous_stream) {
            tracker.has_contiguous_stream = true;
            tracker.base_sequence = sequence_start;
            tracker.next_sequence = sequence_end;
            tracker.last_acknowledgement_number = decoded->acknowledgement_number;
            tracker.contiguous_bytes = decoded->payload_bytes;
            continue;
        }

        if (!tracker.overlap_tracking_enabled) {
            continue;
        }

        if (sequence_start == tracker.next_sequence) {
            tracker.next_sequence = sequence_end;
            tracker.last_acknowledgement_number = decoded->acknowledgement_number;
            tracker.contiguous_bytes.insert(
                tracker.contiguous_bytes.end(),
                decoded->payload_bytes.begin(),
                decoded->payload_bytes.end()
            );
            continue;
        }

        if (sequence_start > tracker.next_sequence) {
            tracker.overlap_tracking_enabled = false;
            mark_gap(packet.packet_index);
            break;
        }

        if (sequence_start < tracker.base_sequence) {
            tracker.overlap_tracking_enabled = false;
            continue;
        }

        if (decoded->acknowledgement_number != tracker.last_acknowledgement_number) {
            tracker.overlap_tracking_enabled = false;
            continue;
        }

        const auto overlap_bytes = tracker.next_sequence - sequence_start;
        if (overlap_bytes == 0U || overlap_bytes > payload_size) {
            tracker.overlap_tracking_enabled = false;
            continue;
        }

        const auto start_offset = static_cast<std::size_t>(sequence_start - tracker.base_sequence);
        if (start_offset > tracker.contiguous_bytes.size() || overlap_bytes > tracker.contiguous_bytes.size() - start_offset) {
            tracker.overlap_tracking_enabled = false;
            continue;
        }

        const auto overlap_size = static_cast<std::size_t>(overlap_bytes);
        if (!std::equal(
                decoded->payload_bytes.begin(),
                decoded->payload_bytes.begin() + static_cast<std::ptrdiff_t>(overlap_size),
                tracker.contiguous_bytes.begin() + static_cast<std::ptrdiff_t>(start_offset))) {
            tracker.overlap_tracking_enabled = false;
            continue;
        }

        auto& contribution = analysis.contributions[packet.packet_index];
        if (overlap_size >= payload_size) {
            contribution.suppress_entire_packet = true;
            continue;
        }

        contribution.trim_prefix_bytes = overlap_size;
        tracker.next_sequence = sequence_end;
        tracker.last_acknowledgement_number = decoded->acknowledgement_number;
        tracker.contiguous_bytes.insert(
            tracker.contiguous_bytes.end(),
            decoded->payload_bytes.begin() + static_cast<std::ptrdiff_t>(overlap_size),
            decoded->payload_bytes.end()
        );
    }

    return analysis;
}

}  // namespace

std::vector<std::uint64_t> collect_suspected_tcp_retransmission_packet_indices(
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::span<const PacketRef> flow_a_packets,
    const std::span<const PacketRef> flow_b_packets,
    const std::size_t max_packets_to_scan
) {
    std::map<SuspectedTcpRetransmissionFingerprint, std::vector<SeenTcpPayloadCandidate>> seen_fingerprints {};
    std::vector<std::uint64_t> suspected_packet_indices {};
    PacketDetailsService details_service {};

    auto maybe_mark_packet = [&](const PacketRef& packet, const std::uint8_t direction_id) {
        const auto decoded = decode_tcp_payload_packet(session, flow_index, packet, details_service);
        if (!decoded.has_value()) {
            return;
        }

        const auto payload_hash = stable_payload_hash(decoded->payload_bytes);
        const auto fingerprint = std::make_tuple(
            direction_id,
            static_cast<std::uint32_t>(decoded->sequence_number),
            decoded->acknowledgement_number,
            packet.payload_length,
            payload_hash
        );

        auto& candidates = seen_fingerprints[fingerprint];
        for (const auto& candidate : candidates) {
            if (candidate.payload_bytes == decoded->payload_bytes) {
                suspected_packet_indices.push_back(packet.packet_index);
                return;
            }
        }

        candidates.push_back(SeenTcpPayloadCandidate {
            .packet_index = packet.packet_index,
            .payload_bytes = decoded->payload_bytes,
        });
    };

    std::size_t index_a = 0U;
    std::size_t index_b = 0U;
    std::size_t processed_packets = 0U;
    while ((index_a < flow_a_packets.size() || index_b < flow_b_packets.size()) &&
           processed_packets < max_packets_to_scan) {
        const bool use_a = index_b >= flow_b_packets.size() ||
            (index_a < flow_a_packets.size() &&
             flow_a_packets[index_a].packet_index <= flow_b_packets[index_b].packet_index);

        const auto& packet = use_a ? flow_a_packets[index_a++] : flow_b_packets[index_b++];
        maybe_mark_packet(packet, use_a ? 0U : 1U);
        ++processed_packets;
    }

    return suspected_packet_indices;
}

TcpPayloadSuppressionAnalysis analyze_selected_flow_tcp_payload_suppression(
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::span<const PacketRef> flow_a_packets,
    const std::span<const PacketRef> flow_b_packets,
    const std::set<std::uint64_t>& exact_duplicate_packet_indices,
    const std::size_t prefix_count_a,
    const std::size_t prefix_count_b
) {
    const auto direction_a_analysis = analyze_selected_flow_tcp_payload_suppression_for_direction(
        session,
        flow_index,
        flow_a_packets,
        exact_duplicate_packet_indices,
        prefix_count_a
    );
    const auto direction_b_analysis = analyze_selected_flow_tcp_payload_suppression_for_direction(
        session,
        flow_index,
        flow_b_packets,
        exact_duplicate_packet_indices,
        prefix_count_b
    );

    TcpPayloadSuppressionAnalysis analysis {};
    analysis.packet_contributions = direction_a_analysis.contributions;
    for (const auto& [packet_index, contribution] : direction_b_analysis.contributions) {
        analysis.packet_contributions[packet_index] = contribution;
    }
    analysis.gap_state_a_to_b = TcpDirectionalGapState {
        .tainted_by_gap = direction_a_analysis.tainted_by_gap,
        .first_gap_packet_index = direction_a_analysis.first_gap_packet_index,
    };
    analysis.gap_state_b_to_a = TcpDirectionalGapState {
        .tainted_by_gap = direction_b_analysis.tainted_by_gap,
        .first_gap_packet_index = direction_b_analysis.first_gap_packet_index,
    };
    return analysis;
}

}  // namespace pfl::session_detail
