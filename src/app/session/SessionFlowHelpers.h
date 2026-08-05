#pragma once

#include <string>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/CaptureState.h"
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

std::vector<ListedConnectionRef> list_connections(const CaptureState& state);
std::uint64_t packet_count(const ListedConnectionRef& connection) noexcept;
std::uint64_t captured_bytes(const ListedConnectionRef& connection) noexcept;
std::uint64_t total_bytes(const ListedConnectionRef& connection) noexcept;
ProtocolId protocol_id(const ListedConnectionRef& connection) noexcept;
FlowProtocolHint effective_protocol_hint(const ListedConnectionRef& connection, const AnalysisSettings& settings) noexcept;
void add_protocol_stats(ProtocolStats& stats, const ListedConnectionRef& connection) noexcept;
std::vector<PacketRef> collect_packets(const ConnectionV4& connection);
std::vector<PacketRef> collect_packets(const ConnectionV6& connection);
FlowRow make_flow_row(std::size_t index, const ListedConnectionRef& connection, const AnalysisSettings& settings);
std::string capture_packet_size_bucket_label(const CapturePacketSizeStatisticsBucket& bucket);
std::string format_statistics_count_value(std::uint64_t value);
std::string format_statistics_compact_size_value(std::uint64_t value);
std::string format_statistics_percent_text(double percent);
std::string format_statistics_count_with_percent_text(std::uint64_t count, double percent);
std::string format_statistics_size_with_percent_text(std::uint64_t size, double percent);
std::string format_statistics_size_value(std::uint64_t value);
std::vector<ProtocolHintStatisticsRow> build_protocol_hint_statistics_rows(const CaptureProtocolSummary& summary);
FlowPacketCountHistogram build_flow_packet_count_histogram(const std::vector<ListedConnectionRef>& connections);
CaptureProtocolPathSummary build_protocol_path_summary(
    const CaptureState& state,
    const std::vector<ListedConnectionRef>& connections,
    ProtocolPathStatisticsMode mode
);

}  // namespace pfl::session_detail
