#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "app/session/AdvancedFlowFilter.h"
#include "app/session/AdvancedFlowFilterFormat.h"

namespace pfl {

class FrontendSessionAdapter;

enum class FrontendAdvancedFlowQueryStatus : std::uint8_t {
    ok = 0,
    invalid_filter_text,
    invalid_flow_index,
    invalid_limit,
    invalid_advanced_filter,
};

struct FrontendAdvancedFlowTextParseIssue {
    session_detail::AdvancedFlowFilterTextParseStatus status {
        session_detail::AdvancedFlowFilterTextParseStatus::ok
    };
    std::size_t line {0U};
    std::optional<std::size_t> column {};
    std::string key {};
    std::string token {};
    std::string message {};
};

struct FrontendAdvancedFlowQueryResult {
    FrontendAdvancedFlowQueryStatus status {FrontendAdvancedFlowQueryStatus::ok};
    std::vector<std::size_t> ordered_flow_indices {};
    std::size_t result_count_before_limit {0U};
    std::size_t configured_rule_count {0U};
    std::size_t active_rule_count {0U};
    session_detail::AdvancedFlowFilterTextParseStatus parse_status {
        session_detail::AdvancedFlowFilterTextParseStatus::ok
    };
    std::optional<FrontendAdvancedFlowTextParseIssue> parse_issue {};
    session_detail::AdvancedFlowFilterCompileStatus compile_status {
        session_detail::AdvancedFlowFilterCompileStatus::ok
    };
    std::optional<session_detail::AdvancedFlowFilterCompileIssue> compile_issue {};
    std::optional<std::size_t> invalid_flow_index {};
};

enum class FrontendAdvancedFlowFilterStructuredDocumentStatus : std::uint8_t {
    ok = 0,
    invalid_document_update,
    unrepresentable_document,
    invalid_advanced_filter,
    query_failure,
};

struct FrontendAdvancedFlowFilterStructuredUpdateIssue {
    std::string section_id {};
    std::string group {};
    std::string value_id {};
    std::optional<std::size_t> row_index {};
    std::string field_id {};
    std::string message {};
};

struct FrontendAdvancedFlowFilterFiniteOptionDto {
    std::string stable_id {};
    std::string label {};
};

struct FrontendAdvancedFlowFilterFiniteSectionDto {
    bool enabled {true};
    std::vector<std::string> include {};
    std::vector<std::string> exclude {};
};

struct FrontendAdvancedFlowFilterPortRowDto {
    std::string scope_id {};
    bool range_enabled {false};
    std::string primary_text {};
    std::string secondary_text {};
};

struct FrontendAdvancedFlowFilterPortSectionDto {
    bool enabled {true};
    std::vector<FrontendAdvancedFlowFilterPortRowDto> include {};
    std::vector<FrontendAdvancedFlowFilterPortRowDto> exclude {};
};

struct FrontendAdvancedFlowFilterIpAddressRowDto {
    std::string scope_id {};
    bool subnet_enabled {false};
    std::string address_text {};
    std::string prefix_text {};
};

struct FrontendAdvancedFlowFilterIpAddressSectionDto {
    bool enabled {true};
    std::vector<FrontendAdvancedFlowFilterIpAddressRowDto> include {};
    std::vector<FrontendAdvancedFlowFilterIpAddressRowDto> exclude {};
};

struct FrontendAdvancedFlowFilterTrafficRowDto {
    std::string metric_id {};
    std::string unit_id {};
    std::string min_text {};
    std::string max_text {};
};

struct FrontendAdvancedFlowFilterTimeRowDto {
    std::string metric_id {};
    std::string from_text {};
    std::string to_text {};
};

struct FrontendAdvancedFlowFilterTimeSectionDto {
    bool enabled {true};
    std::vector<FrontendAdvancedFlowFilterTimeRowDto> ranges {};
    FrontendAdvancedFlowFilterTrafficRowDto duration {};
};

struct FrontendAdvancedFlowFilterTrafficSectionDto {
    bool enabled {true};
    FrontendAdvancedFlowFilterFiniteSectionDto packet_distribution {};
    FrontendAdvancedFlowFilterFiniteSectionDto data_distribution {};
    std::vector<FrontendAdvancedFlowFilterTrafficRowDto> primary {};
    std::vector<FrontendAdvancedFlowFilterTrafficRowDto> directional_packets {};
    std::vector<FrontendAdvancedFlowFilterTrafficRowDto> directional_original_bytes {};
    std::vector<FrontendAdvancedFlowFilterTrafficRowDto> additional {};
};

struct FrontendAdvancedFlowFilterServiceTextRowDto {
    std::string operator_id {};
    bool case_sensitive {false};
    std::string text {};
};

struct FrontendAdvancedFlowFilterServiceSectionDto {
    bool enabled {true};
    bool include_recognized {false};
    bool include_unrecognized {false};
    std::vector<FrontendAdvancedFlowFilterServiceTextRowDto> include_text {};
    bool exclude_recognized {false};
    bool exclude_unrecognized {false};
    std::vector<FrontendAdvancedFlowFilterServiceTextRowDto> exclude_text {};
};

struct FrontendAdvancedFlowFilterProtocolPathRowDto {
    std::string selector_mode_id {};
    std::string predicate_text {};
    std::string compact_text {};
    std::string full_text {};
    bool applicability_known {false};
    bool applicable {false};
    std::string status_text {};
};

struct FrontendAdvancedFlowFilterProtocolPathSectionDto {
    bool enabled {true};
    std::vector<FrontendAdvancedFlowFilterProtocolPathRowDto> include {};
    std::vector<FrontendAdvancedFlowFilterProtocolPathRowDto> exclude {};
};

struct FrontendAdvancedFlowFilterContainsLayerOptionDto {
    std::string stable_id {};
    std::string label {};
    std::string object_name_suffix {};
    std::string identifier_label {};
    std::string preferred_input_format_id {};
    std::string exact_value_placeholder {};
};

struct FrontendAdvancedFlowFilterContainsLayerRowDto {
    std::string layer_stable_id {};
    std::string identifier_mode_id {};
    std::string exact_value_text {};
    std::string compact_text {};
    bool applicability_known {false};
    bool applicable {false};
    std::string status_text {};
};

struct FrontendAdvancedFlowFilterContainsLayerSectionDto {
    bool enabled {true};
    std::vector<FrontendAdvancedFlowFilterContainsLayerRowDto> include {};
    std::vector<FrontendAdvancedFlowFilterContainsLayerRowDto> exclude {};
};

struct FrontendAdvancedFlowFilterStructuredOptionCatalogDto {
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> address_family {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> flow_protocol {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> detected_protocol {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> tls_version {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> quic_version {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> directionality {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> traffic_distribution {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> endpoint_scope {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> protocol_path_selector_mode {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> contains_layer_identifier_mode {};
    std::vector<FrontendAdvancedFlowFilterContainsLayerOptionDto> contains_layer_kind {};
};

struct FrontendAdvancedFlowFilterStructuredDocumentDto {
    std::string canonical_text {};
    FrontendAdvancedFlowFilterFiniteSectionDto address_family {};
    FrontendAdvancedFlowFilterFiniteSectionDto flow_protocol {};
    FrontendAdvancedFlowFilterFiniteSectionDto detected_protocol {};
    FrontendAdvancedFlowFilterFiniteSectionDto tls_version {};
    FrontendAdvancedFlowFilterFiniteSectionDto quic_version {};
    FrontendAdvancedFlowFilterFiniteSectionDto directionality {};
    FrontendAdvancedFlowFilterPortSectionDto ports {};
    FrontendAdvancedFlowFilterIpAddressSectionDto ip_addresses {};
    FrontendAdvancedFlowFilterTimeSectionDto time {};
    FrontendAdvancedFlowFilterTrafficSectionDto traffic {};
    FrontendAdvancedFlowFilterServiceSectionDto service {};
    FrontendAdvancedFlowFilterProtocolPathSectionDto protocol_path {};
    FrontendAdvancedFlowFilterContainsLayerSectionDto contains_layer {};
    bool has_unsupported_configured_sections {false};
};

struct FrontendAdvancedFlowFilterDocumentWorkflowStateDto {
    std::string canonical_text {};
    std::string source_path {};
    std::string display_name {};
    bool is_file_backed {false};
    bool has_unsaved_changes {false};
    bool has_unsaved_configuration {false};
    bool can_clear_unsaved_changes {false};
    bool clear_available {false};
    std::size_t configured_rule_count {0U};
    std::size_t active_rule_count {0U};
};

struct FrontendAdvancedFlowFilterStructuredDocumentResult {
    FrontendAdvancedFlowFilterStructuredDocumentStatus status {
        FrontendAdvancedFlowFilterStructuredDocumentStatus::ok
    };
    std::optional<FrontendAdvancedFlowFilterStructuredDocumentDto> document {};
    FrontendAdvancedFlowFilterStructuredOptionCatalogDto option_catalog {};
    std::size_t configured_rule_count {0U};
    std::size_t active_rule_count {0U};
    session_detail::AdvancedFlowFilterTextParseStatus parse_status {
        session_detail::AdvancedFlowFilterTextParseStatus::ok
    };
    std::optional<FrontendAdvancedFlowTextParseIssue> parse_issue {};
    session_detail::AdvancedFlowFilterCompileStatus compile_status {
        session_detail::AdvancedFlowFilterCompileStatus::ok
    };
    std::optional<session_detail::AdvancedFlowFilterCompileIssue> compile_issue {};
    std::optional<FrontendAdvancedFlowFilterStructuredUpdateIssue> update_issue {};
    std::string error_text {};
};

[[nodiscard]] std::optional<std::string> format_advanced_flow_filter_protocol_path_predicate_text(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
);

[[nodiscard]] bool encode_advanced_flow_filter_protocol_path_row(
    const FrontendSessionAdapter& adapter,
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate,
    FrontendAdvancedFlowFilterProtocolPathRowDto& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
);

}  // namespace pfl
