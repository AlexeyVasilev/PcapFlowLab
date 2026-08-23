#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "app/session/AdvancedFlowFilter.h"

namespace pfl::session_detail {

inline constexpr std::size_t kAdvancedFlowFilterMaxFileBytes = 1024U * 1024U;

enum class AdvancedFlowFilterTextParseStatus : std::uint8_t {
    ok = 0,
    missing_format_version,
    duplicate_format_version,
    unsupported_format_version,
    malformed_assignment,
    unknown_key,
    duplicate_scalar_key,
    invalid_value,
    invalid_escape,
    unterminated_string,
    numeric_overflow,
    invalid_enum_token,
    invalid_ip_address,
    invalid_protocol_path_syntax,
};

struct AdvancedFlowFilterTextParseIssue {
    AdvancedFlowFilterTextParseStatus status {AdvancedFlowFilterTextParseStatus::ok};
    std::size_t line {0U};
    std::optional<std::size_t> column {};
    std::string key {};
    std::string token {};
    std::string message {};
};

struct AdvancedFlowFilterTextParseResult {
    AdvancedFlowFilterTextParseStatus status {AdvancedFlowFilterTextParseStatus::ok};
    AdvancedFlowFilterSpec spec {};
    std::optional<AdvancedFlowFilterTextParseIssue> issue {};
};

enum class AdvancedFlowFilterTextFormatStatus : std::uint8_t {
    ok = 0,
    unrepresentable_spec,
};

struct AdvancedFlowFilterTextFormatIssue {
    AdvancedFlowFilterTextFormatStatus status {AdvancedFlowFilterTextFormatStatus::ok};
    std::string category {};
    std::string message {};
};

struct AdvancedFlowFilterTextFormatResult {
    AdvancedFlowFilterTextFormatStatus status {AdvancedFlowFilterTextFormatStatus::ok};
    std::string text {};
    std::optional<AdvancedFlowFilterTextFormatIssue> issue {};
};

[[nodiscard]] AdvancedFlowFilterTextParseResult parse_advanced_flow_filter_text(std::string_view text);

[[nodiscard]] AdvancedFlowFilterTextFormatResult format_advanced_flow_filter_text(
    const AdvancedFlowFilterSpec& spec
);

}  // namespace pfl::session_detail
