#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/CaptureStatisticsSnapshot.h"
#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndexV16.h"
#include "core/services/AnalysisSettings.h"

namespace pfl::session_detail {

struct ListedConnectionRef {
    FlowAddressFamily family {FlowAddressFamily::ipv4};
    const ConnectionV4* ipv4 {nullptr};
    const ConnectionV6* ipv6 {nullptr};
};

struct ProtocolHintStatisticsRow {
    std::string group {};
    std::string protocol_label {};
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};
    std::string flow_count_text {};
    std::string packet_count_text {};
    std::string captured_bytes_text {};
    std::string original_bytes_text {};
};

enum class FlowQuerySortKey : std::uint8_t {
    canonical_index = 0,
    protocol,
    service,
    endpoint_a,
    endpoint_b,
    packets,
    bytes,
};

enum class FlowQuerySortDirection : std::uint8_t {
    ascending = 0,
    descending,
};

struct FlowQuerySortSpec {
    FlowQuerySortKey key {FlowQuerySortKey::canonical_index};
    FlowQuerySortDirection direction {FlowQuerySortDirection::ascending};
};

struct FlowQuery {
    std::optional<std::vector<std::size_t>> selected_flow_indices {};
    std::string text_filter {};
    std::optional<FlowQuerySortSpec> sort {};
    std::optional<std::size_t> limit {};
};

enum class FlowQueryStatus : std::uint8_t {
    ok = 0,
    invalid_flow_index,
    invalid_limit,
};

struct FlowQueryResult {
    FlowQueryStatus status {FlowQueryStatus::ok};
    std::vector<std::size_t> ordered_flow_indices {};
    std::size_t result_count_before_limit {0U};
    std::optional<std::size_t> invalid_flow_index {};
};

std::vector<ListedConnectionRef> list_connections(const CaptureState& state);
std::uint64_t packet_count(const ListedConnectionRef& connection) noexcept;
std::uint64_t captured_bytes(const ListedConnectionRef& connection) noexcept;
std::uint64_t total_bytes(const ListedConnectionRef& connection) noexcept;
ProtocolId protocol_id(const ListedConnectionRef& connection) noexcept;
std::string format_flow_protocol_text(ProtocolId protocol);
FlowProtocolHint effective_protocol_hint(
    FlowProtocolHint confirmed_hint,
    ProtocolId protocol,
    std::uint16_t first_port,
    std::uint16_t second_port,
    const AnalysisSettings& settings
) noexcept;
FlowProtocolHint effective_protocol_hint(const ListedConnectionRef& connection, const AnalysisSettings& settings) noexcept;
void add_protocol_stats(ProtocolStats& stats, const ListedConnectionRef& connection) noexcept;
std::vector<PacketRef> collect_packets(const ConnectionV4& connection);
std::vector<PacketRef> collect_packets(const ConnectionV6& connection);
std::optional<FlowRow> make_flow_row(
    std::size_t index,
    const ListedConnectionRef& connection,
    const AnalysisSettings& settings
);
std::string format_flow_protocol_hint_display(std::string_view value);
[[nodiscard]] bool flow_row_matches_text_filter(const FlowRow& row, std::string_view filter) noexcept;
[[nodiscard]] FlowQueryResult query_flow_indices(
    std::span<const ListedConnectionRef> connections,
    const AnalysisSettings& settings,
    const FlowQuery& query
);
std::string capture_packet_size_bucket_label(const CapturePacketSizeStatisticsBucket& bucket);
std::string format_statistics_bucket_label(
    std::uint64_t lower_bound_inclusive,
    std::optional<std::uint64_t> upper_bound_inclusive
);
std::string format_statistics_count_value(std::uint64_t value);
std::string format_statistics_compact_size_value(std::uint64_t value);
std::string format_statistics_percent_text(double percent);
std::string format_statistics_count_with_percent_text(std::uint64_t count, double percent);
std::string format_statistics_size_with_percent_text(std::uint64_t size, double percent);
std::string format_statistics_size_value(std::uint64_t value);
std::vector<ProtocolHintStatisticsRow> build_protocol_hint_statistics_rows(const CaptureProtocolSummary& summary);
CaptureStatisticsSnapshot make_capture_statistics_snapshot(
    const CapturePacketStatistics& packet_statistics,
    const CaptureGeneralStatistics& general_statistics,
    CaptureStatisticsScope scope
);
CaptureGeneralStatistics build_capture_general_statistics(
    std::span<const ListedConnectionRef> connections,
    std::size_t top_summary_capacity = 20U
);
FlowPacketCountHistogram build_flow_packet_count_histogram(const std::vector<ListedConnectionRef>& connections);
ProtocolPathDisplayStatistics build_protocol_path_display_statistics(
    const CaptureState& state,
    const std::vector<ListedConnectionRef>& connections
);
CaptureIndexV16WritePlanBuildResult build_capture_index_v16_write_plan(
    const CaptureState& state,
    const CaptureIndexV16PacketRefDetailLayoutOptions& options = {}
);
CaptureProtocolPathSummary build_protocol_path_summary_from_display_statistics(
    const ProtocolPathRegistry& registry,
    const ProtocolPathDisplayStatistics& statistics,
    std::uint64_t total_flow_count,
    std::uint64_t total_packet_count,
    std::uint64_t total_original_byte_count,
    ProtocolPathStatisticsMode mode
);
CaptureProtocolPathSummary build_protocol_path_summary(
    const CaptureState& state,
    const std::vector<ListedConnectionRef>& connections,
    ProtocolPathStatisticsMode mode
);

}  // namespace pfl::session_detail
