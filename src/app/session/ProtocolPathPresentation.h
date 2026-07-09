#pragma once

#include <string>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/ProtocolPath.h"

namespace pfl::session_detail {

struct ProtocolPathLegendEntry {
    std::string short_label {};
    std::string full_name {};
    std::string tooltip {};
    std::string color_key {};
    std::string background_color {};
    std::string border_color {};
    std::string text_color {};
};

struct ProtocolPathPresentation {
    std::string full_text {};
    std::string compact_text {};
    std::vector<ProtocolPathBadgeRow> badges {};
};

[[nodiscard]] ProtocolPathPresentation build_protocol_path_presentation(const ProtocolPath* path);
[[nodiscard]] std::string format_protocol_path_layer_display_text(const LayerKey& layer);
[[nodiscard]] std::vector<ProtocolPathLegendEntry> protocol_path_legend_entries();

}  // namespace pfl::session_detail
