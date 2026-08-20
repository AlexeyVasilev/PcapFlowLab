#pragma once

#include <cstdint>
#include <span>
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

enum class ProtocolPathIdentifierInputFormat : std::uint8_t {
    decimal = 0,
    hexadecimal,
};

struct ProtocolPathContainsLayerDescriptor {
    ProtocolLayerKind kind {ProtocolLayerKind::unknown};
    ProtocolLayerIdentifierKind identifier_kind {ProtocolLayerIdentifierKind::none};
    const char* layer_label {""};
    const char* object_name_suffix {""};
    const char* identifier_label {""};
    ProtocolPathIdentifierInputFormat preferred_input_format {ProtocolPathIdentifierInputFormat::decimal};
    std::uint64_t max_value {0U};
};

[[nodiscard]] ProtocolPathPresentation build_protocol_path_presentation(const ProtocolPath* path);
[[nodiscard]] ProtocolPathPresentation build_protocol_path_presentation(
    const ProtocolPathRegistry& registry,
    ProtocolPathId protocol_path_id
);
[[nodiscard]] std::string protocol_path_compact_text(
    const ProtocolPathRegistry& registry,
    ProtocolPathId protocol_path_id
);
[[nodiscard]] std::string format_protocol_path_layer_display_text(const LayerKey& layer);
[[nodiscard]] std::string format_protocol_path_compact_display_text(const ProtocolPath& path);
[[nodiscard]] std::span<const ProtocolPathContainsLayerDescriptor> protocol_path_contains_layer_descriptors() noexcept;
[[nodiscard]] const ProtocolPathContainsLayerDescriptor* protocol_path_contains_layer_descriptor(
    ProtocolLayerKind kind
) noexcept;
[[nodiscard]] std::string format_protocol_path_identifier_editor_text(
    ProtocolLayerIdentifierKind kind,
    std::uint64_t value
);
[[nodiscard]] std::vector<ProtocolPathLegendEntry> protocol_path_legend_entries();

}  // namespace pfl::session_detail
