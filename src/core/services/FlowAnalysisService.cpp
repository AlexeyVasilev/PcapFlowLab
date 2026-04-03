#include "core/services/FlowAnalysisService.h"

#include <algorithm>
#include <optional>

namespace pfl {

namespace {

std::uint64_t packet_timestamp_us(const PacketRef& packet) noexcept {
    return (static_cast<std::uint64_t>(packet.ts_sec) * 1000000ULL) + static_cast<std::uint64_t>(packet.ts_usec);
}

template <typename Flow>
void update_time_bounds(const Flow& flow, std::optional<std::uint64_t>& first_us, std::optional<std::uint64_t>& last_us) {
    for (const auto& packet : flow.packets) {
        const auto timestamp_us = packet_timestamp_us(packet);
        if (!first_us.has_value() || timestamp_us < *first_us) {
            first_us = timestamp_us;
        }
        if (!last_us.has_value() || timestamp_us > *last_us) {
            last_us = timestamp_us;
        }
    }
}

template <typename Connection>
FlowAnalysisResult analyze_connection(const Connection& connection) {
    FlowAnalysisResult result {};
    result.total_packets = connection.packet_count;
    result.total_bytes = connection.total_bytes;
    result.packets_a_to_b = connection.flow_a.packet_count;
    result.packets_b_to_a = connection.flow_b.packet_count;
    result.bytes_a_to_b = connection.flow_a.total_bytes;
    result.bytes_b_to_a = connection.flow_b.total_bytes;
    result.protocol_hint = connection.protocol_hint == FlowProtocolHint::unknown
        ? std::string {}
        : std::string {flow_protocol_hint_text(connection.protocol_hint)};
    result.service_hint = connection.service_hint;

    std::optional<std::uint64_t> first_us {};
    std::optional<std::uint64_t> last_us {};
    update_time_bounds(connection.flow_a, first_us, last_us);
    update_time_bounds(connection.flow_b, first_us, last_us);

    if (first_us.has_value() && last_us.has_value() && *last_us >= *first_us) {
        result.duration_us = *last_us - *first_us;
    }

    return result;
}

}  // namespace

FlowAnalysisResult FlowAnalysisService::analyze(const ConnectionV4& connection) const {
    return analyze_connection(connection);
}

FlowAnalysisResult FlowAnalysisService::analyze(const ConnectionV6& connection) const {
    return analyze_connection(connection);
}

}  // namespace pfl
