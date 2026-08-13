#pragma once

#include <span>
#include <string>
#include <string_view>

namespace pfl::session_detail {

enum class SupportedProtocolCategory {
    link_and_encapsulation,
    network,
    transport,
    tunnels_and_overlays,
    security,
    application,
};

enum class SupportedProtocolCapabilityStatus {
    yes,
    partial,
    no,
    not_applicable,
};

// Product-facing capability rows are intentionally static presentation metadata.
// This catalog describes current user-visible support levels and is not tied to
// runtime parser registration, capture state, or persisted index metadata.
struct SupportedProtocolCategoryDescriptor {
    SupportedProtocolCategory category {SupportedProtocolCategory::link_and_encapsulation};
    std::string_view stable_id {};
    std::string_view display_label {};
};

struct SupportedProtocolStatusDescriptor {
    SupportedProtocolCapabilityStatus status {SupportedProtocolCapabilityStatus::no};
    std::string_view stable_id {};
    std::string_view display_label {};
};

struct SupportedProtocolCatalogRow {
    std::string_view stable_id {};
    std::string_view protocol {};
    SupportedProtocolCategory category {SupportedProtocolCategory::link_and_encapsulation};
    // Recognition covers protocol-aware classification / detected-protocol /
    // protocol-path style exposure, not only raw packet shape matching.
    SupportedProtocolCapabilityStatus recognition {SupportedProtocolCapabilityStatus::no};
    SupportedProtocolCapabilityStatus service {SupportedProtocolCapabilityStatus::no};
    // Generic Data-style fallback is not enough for Packet Summary / Stream.
    SupportedProtocolCapabilityStatus packet_summary {SupportedProtocolCapabilityStatus::no};
    SupportedProtocolCapabilityStatus stream {SupportedProtocolCapabilityStatus::no};
    std::string_view notes {};
};

inline constexpr std::string_view kSupportedProtocolCatalogBeginMarker =
    "<!-- BEGIN USER PROTOCOL CAPABILITY CATALOG -->";
inline constexpr std::string_view kSupportedProtocolCatalogEndMarker =
    "<!-- END USER PROTOCOL CAPABILITY CATALOG -->";

[[nodiscard]] std::span<const SupportedProtocolCategoryDescriptor> supported_protocol_category_descriptors();
[[nodiscard]] std::span<const SupportedProtocolStatusDescriptor> supported_protocol_status_descriptors();
[[nodiscard]] std::span<const SupportedProtocolCatalogRow> supported_protocol_catalog_rows();
[[nodiscard]] std::string_view supported_protocol_category_stable_id(SupportedProtocolCategory category);
[[nodiscard]] std::string_view supported_protocol_category_display_label(SupportedProtocolCategory category);
[[nodiscard]] std::string_view supported_protocol_status_stable_id(SupportedProtocolCapabilityStatus status);
[[nodiscard]] std::string_view supported_protocol_status_display_label(SupportedProtocolCapabilityStatus status);
[[nodiscard]] std::string render_supported_protocol_catalog_markdown_table();
[[nodiscard]] std::string render_supported_protocol_catalog_markdown_table(
    std::span<const SupportedProtocolCatalogRow> rows
);

}  // namespace pfl::session_detail
