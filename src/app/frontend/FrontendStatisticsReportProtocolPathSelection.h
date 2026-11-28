#pragma once

#include <optional>
#include <string>
#include <utility>

#include "app/frontend/FrontendStatisticsOverview.h"
#include "app/frontend/FrontendStatisticsReport.h"

namespace pfl {

struct FrontendStatisticsReportProtocolPathSelectionResult {
    std::optional<FrontendStatisticsReportProtocolPathTree> tree {};
    std::string error_text {};
};

template <typename SummaryProvider>
[[nodiscard]] FrontendStatisticsReportProtocolPathSelectionResult select_statistics_report_protocol_path_tree(
    SummaryProvider&& request_summary
) {
    auto summary = request_summary(ProtocolPathStatisticsMode::identity_tree_ip_context);
    const bool structural_fallback =
        summary.status == ProtocolPathStatisticsStatus::non_terminal_ip_metadata_unavailable;
    if (structural_fallback) {
        summary = request_summary(ProtocolPathStatisticsMode::identity_tree);
    }

    if (summary.status != ProtocolPathStatisticsStatus::ok) {
        return {
            .error_text = summary.status == ProtocolPathStatisticsStatus::missing_non_terminal_ip_context
                ? "Non-terminal IP context metadata is missing or inconsistent."
                : "Non-terminal IP metadata was not retained because it was ignored when this capture was imported.",
        };
    }

    FrontendStatisticsReportProtocolPathTree tree {
        .mode = structural_fallback
            ? ProtocolPathStatisticsMode::identity_tree
            : ProtocolPathStatisticsMode::identity_tree_ip_context,
        .rows = build_frontend_protocol_path_statistics(summary),
        .notes = {structural_fallback
            ? "Non-terminal IP metadata was not retained because it was ignored when this capture was imported. The report shows the structural Identity Tree without IP context."
            : "IP pairs represent bidirectional Flow identity, not packet direction. Terminal Flow IPs remain undecorated."},
    };
    return {.tree = std::move(tree)};
}

}  // namespace pfl
