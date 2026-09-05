#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include <vector>

#include "app/frontend/FrontendDtos.h"

namespace pfl {

struct FrontendStatisticsReportField {
    std::string name {};
    std::string value {};
};

struct FrontendStatisticsReportTable {
    std::string title {};
    std::vector<std::string> headers {};
    std::vector<std::vector<std::string>> rows {};
};

struct FrontendStatisticsReportSection {
    std::string title {};
    std::vector<FrontendStatisticsReportField> fields {};
    std::vector<std::string> notes {};
    std::vector<FrontendStatisticsReportTable> tables {};
};

struct FrontendStatisticsReportData {
    std::string title {};
    std::vector<FrontendStatisticsReportSection> sections {};
};

struct FrontendStatisticsReportMetadata {
    std::string application_name {};
    std::string application_version {};
    std::string client_name {};
    std::string generated_at_utc {};
    std::string statistics_scope {};
    std::optional<std::uint32_t> index_revision {};
};

struct FrontendStatisticsReportInput {
    FrontendStatisticsReportMetadata metadata {};
    FrontendOverviewDto overview {};
    FrontendCapturePacketSizeStatisticsDto packet_size_statistics {};
    FrontendFlowPacketCountHistogramDto flow_packet_count_histogram {};
    FrontendProtocolHintStatisticsDto protocol_hint_statistics {};
    FrontendQuicTlsStatisticsDto quic_tls_statistics {};
    FrontendTopEndpointPortStatisticsDto top_endpoint_port_statistics {};
    std::vector<FrontendProtocolPathStatsDto> protocol_path_identity_tree {};
};

[[nodiscard]] FrontendStatisticsReportData build_frontend_statistics_report_data(
    const FrontendStatisticsReportInput& input
);
[[nodiscard]] std::string render_frontend_statistics_report_markdown(
    const FrontendStatisticsReportData& report
);
[[nodiscard]] std::string render_frontend_statistics_report_html(
    const FrontendStatisticsReportData& report
);

}  // namespace pfl
