#pragma once

#include <span>
#include <string>

#include "app/frontend/FrontendDtos.h"
#include "app/session/FlowRows.h"
#include "core/domain/ProtocolPath.h"
#include "core/domain/CapturePacketSizeStatistics.h"
#include "core/services/AnalysisSettings.h"

namespace pfl {

[[nodiscard]] FrontendCaptureTimeStatisticsDto build_frontend_capture_time_statistics(
    const CapturePacketStatistics& packet_statistics
);
[[nodiscard]] FrontendCaptureMetricsDto build_frontend_capture_metrics(
    const CapturePacketStatistics& packet_statistics
);
[[nodiscard]] FrontendFlowCharacteristicsDto build_frontend_flow_characteristics(
    const CaptureFlowCharacteristicsStatistics& flow_characteristics
);
[[nodiscard]] FrontendDirectionDistributionDto build_frontend_packet_direction_distribution(
    const CaptureFlowCharacteristicsStatistics& flow_characteristics,
    const FlowDirectionDistributionStatistics& distribution
);
[[nodiscard]] FrontendDirectionDistributionDto build_frontend_original_byte_direction_distribution(
    const CaptureFlowCharacteristicsStatistics& flow_characteristics,
    const FlowDirectionDistributionStatistics& distribution
);
[[nodiscard]] FrontendTcpFlagStatisticsDto build_frontend_tcp_flag_statistics(
    const CaptureTcpFlagStatistics& statistics,
    std::uint64_t total_tcp_packet_count
);
[[nodiscard]] std::string build_frontend_count_with_total_percent_text(
    std::uint64_t count,
    std::uint64_t total_count
);
[[nodiscard]] std::vector<FrontendTopEndpointDto> build_frontend_top_endpoints(
    const CaptureTopSummary& summary
);
[[nodiscard]] std::vector<FrontendTopPortDto> build_frontend_top_ports(
    const CaptureTopSummary& summary
);
[[nodiscard]] std::vector<FrontendTopFlowDto> build_frontend_top_flows(
    std::span<const TopFlowRow> rows,
    const ProtocolPathRegistry& registry,
    const AnalysisSettings& settings
);
[[nodiscard]] std::string build_frontend_statistics_partial_open_warning_text(bool partial_open);

}  // namespace pfl
