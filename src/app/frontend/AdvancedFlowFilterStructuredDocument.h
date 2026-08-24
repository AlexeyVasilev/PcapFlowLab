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

struct FrontendAdvancedFlowFilterStructuredOptionCatalogDto {
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> address_family {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> flow_protocol {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> detected_protocol {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> tls_version {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> quic_version {};
    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto> directionality {};
};

struct FrontendAdvancedFlowFilterStructuredDocumentDto {
    std::string canonical_text {};
    FrontendAdvancedFlowFilterFiniteSectionDto address_family {};
    FrontendAdvancedFlowFilterFiniteSectionDto flow_protocol {};
    FrontendAdvancedFlowFilterFiniteSectionDto detected_protocol {};
    FrontendAdvancedFlowFilterFiniteSectionDto tls_version {};
    FrontendAdvancedFlowFilterFiniteSectionDto quic_version {};
    FrontendAdvancedFlowFilterFiniteSectionDto directionality {};
    bool has_unsupported_configured_sections {false};
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

}  // namespace pfl
