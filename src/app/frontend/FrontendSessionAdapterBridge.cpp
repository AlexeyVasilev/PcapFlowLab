#include "app/frontend/FrontendSessionAdapterBridge.h"

#include "app/frontend/FrontendSessionAdapter.h"

#include <cstring>
#include <filesystem>
#include <new>
#include <sstream>
#include <string>
#include <string_view>

namespace {

using pfl::FlowAddressFamily;
using pfl::FrontendSessionAdapter;

constexpr std::string_view kAdapterUnavailableText {"Adapter handle is unavailable."};

std::string json_escape(const std::string_view input) {
    std::string escaped {};
    escaped.reserve(input.size() + 8U);

    for (const auto ch : input) {
        switch (ch) {
        case '\"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20U) {
                std::ostringstream hex {};
                hex << "\\u00";
                constexpr char digits[] = "0123456789abcdef";
                hex << digits[(static_cast<unsigned char>(ch) >> 4U) & 0x0FU];
                hex << digits[static_cast<unsigned char>(ch) & 0x0FU];
                escaped += hex.str();
            } else {
                escaped.push_back(ch);
            }
            break;
        }
    }

    return escaped;
}

std::string json_string(const std::string_view input) {
    return std::string {"\""} + json_escape(input) + "\"";
}

char* make_c_string(const std::string& value) {
    auto* buffer = new (std::nothrow) char[value.size() + 1U];
    if (buffer == nullptr) {
        return nullptr;
    }

    std::memcpy(buffer, value.c_str(), value.size() + 1U);
    return buffer;
}

std::string bool_json(const bool value) {
    return value ? "true" : "false";
}

std::filesystem::path path_from_utf8(const char* path_utf8) {
    if (path_utf8 == nullptr) {
        return {};
    }

    // Rust passes UTF-8 bytes through the C ABI. Keep the C++17/C++20 path-construction
    // differences localized here instead of spreading them across bridge call sites.
#if defined(__cpp_char8_t)
    const auto utf8_path = std::string_view {path_utf8};
    std::u8string utf8_bytes {};
    utf8_bytes.reserve(utf8_path.size());
    for (const auto byte : utf8_path) {
        utf8_bytes.push_back(static_cast<char8_t>(static_cast<unsigned char>(byte)));
    }
    return std::filesystem::path {utf8_bytes};
#else
    return std::filesystem::u8path(path_utf8);
#endif
}

std::string family_to_json(const FlowAddressFamily family) {
    return json_string(family == FlowAddressFamily::ipv6 ? "ipv6" : "ipv4");
}

std::string protocol_stats_json(const pfl::FrontendProtocolStatsDto& stats) {
    std::ostringstream out {};
    out << '{'
        << "\"flow_count\":" << stats.flow_count << ','
        << "\"packet_count\":" << stats.packet_count << ','
        << "\"captured_bytes\":" << stats.captured_bytes << ','
        << "\"captured_bytes_text\":" << json_string(stats.captured_bytes_text) << ','
        << "\"original_bytes\":" << stats.original_bytes << ','
        << "\"original_bytes_text\":" << json_string(stats.original_bytes_text)
        << '}';
    return out.str();
}

std::string protocol_path_badge_json(const pfl::ProtocolPathBadgeRow& badge) {
    std::ostringstream out {};
    out << '{'
        << "\"short_label\":" << json_string(badge.short_label) << ','
        << "\"full_name\":" << json_string(badge.full_name) << ','
        << "\"tooltip\":" << json_string(badge.tooltip) << ','
        << "\"color_key\":" << json_string(badge.color_key) << ','
        << "\"background_color\":" << json_string(badge.background_color) << ','
        << "\"border_color\":" << json_string(badge.border_color) << ','
        << "\"text_color\":" << json_string(badge.text_color)
        << '}';
    return out.str();
}

std::string protocol_path_legend_entry_json(const pfl::FrontendProtocolPathLegendEntryDto& entry) {
    std::ostringstream out {};
    out << '{'
        << "\"short_label\":" << json_string(entry.short_label) << ','
        << "\"full_name\":" << json_string(entry.full_name) << ','
        << "\"tooltip\":" << json_string(entry.tooltip) << ','
        << "\"color_key\":" << json_string(entry.color_key) << ','
        << "\"background_color\":" << json_string(entry.background_color) << ','
        << "\"border_color\":" << json_string(entry.border_color) << ','
        << "\"text_color\":" << json_string(entry.text_color)
        << '}';
    return out.str();
}

std::string supported_protocol_catalog_row_json(const pfl::FrontendSupportedProtocolCatalogRowDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"category_id\":" << json_string(row.category_id) << ','
        << "\"category_label\":" << json_string(row.category_label) << ','
        << "\"protocol_id\":" << json_string(row.protocol_id) << ','
        << "\"protocol\":" << json_string(row.protocol) << ','
        << "\"recognition_status_id\":" << json_string(row.recognition_status_id) << ','
        << "\"recognition_status_label\":" << json_string(row.recognition_status_label) << ','
        << "\"service_status_id\":" << json_string(row.service_status_id) << ','
        << "\"service_status_label\":" << json_string(row.service_status_label) << ','
        << "\"packet_summary_status_id\":" << json_string(row.packet_summary_status_id) << ','
        << "\"packet_summary_status_label\":" << json_string(row.packet_summary_status_label) << ','
        << "\"stream_status_id\":" << json_string(row.stream_status_id) << ','
        << "\"stream_status_label\":" << json_string(row.stream_status_label) << ','
        << "\"notes\":" << json_string(row.notes)
        << '}';
    return out.str();
}

std::string flow_indices_json(const std::vector<std::size_t>& flow_indices) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < flow_indices.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << flow_indices[index];
    }
    out << ']';
    return out.str();
}

std::string optional_size_json(const std::optional<std::size_t>& value) {
    return value.has_value() ? std::to_string(*value) : "null";
}

std::string advanced_flow_query_status_json(const pfl::FrontendAdvancedFlowQueryStatus status) {
    switch (status) {
    case pfl::FrontendAdvancedFlowQueryStatus::ok:
        return json_string("ok");
    case pfl::FrontendAdvancedFlowQueryStatus::invalid_filter_text:
        return json_string("invalid_filter_text");
    case pfl::FrontendAdvancedFlowQueryStatus::invalid_flow_index:
        return json_string("invalid_flow_index");
    case pfl::FrontendAdvancedFlowQueryStatus::invalid_limit:
        return json_string("invalid_limit");
    case pfl::FrontendAdvancedFlowQueryStatus::invalid_advanced_filter:
        return json_string("invalid_advanced_filter");
    }

    return json_string("invalid_advanced_filter");
}

std::string parse_status_json(const pfl::session_detail::AdvancedFlowFilterTextParseStatus status) {
    switch (status) {
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::ok:
        return json_string("ok");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::missing_format_version:
        return json_string("missing_format_version");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::duplicate_format_version:
        return json_string("duplicate_format_version");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::unsupported_format_version:
        return json_string("unsupported_format_version");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::malformed_assignment:
        return json_string("malformed_assignment");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::unknown_key:
        return json_string("unknown_key");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::duplicate_scalar_key:
        return json_string("duplicate_scalar_key");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::invalid_value:
        return json_string("invalid_value");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::invalid_escape:
        return json_string("invalid_escape");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::unterminated_string:
        return json_string("unterminated_string");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::numeric_overflow:
        return json_string("numeric_overflow");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::invalid_enum_token:
        return json_string("invalid_enum_token");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::invalid_ip_address:
        return json_string("invalid_ip_address");
    case pfl::session_detail::AdvancedFlowFilterTextParseStatus::invalid_protocol_path_syntax:
        return json_string("invalid_protocol_path_syntax");
    }

    return json_string("invalid_value");
}

std::string compile_status_json(const pfl::session_detail::AdvancedFlowFilterCompileStatus status) {
    switch (status) {
    case pfl::session_detail::AdvancedFlowFilterCompileStatus::ok:
        return json_string("ok");
    case pfl::session_detail::AdvancedFlowFilterCompileStatus::invalid_numeric_range:
        return json_string("invalid_numeric_range");
    case pfl::session_detail::AdvancedFlowFilterCompileStatus::invalid_protocol_path_predicate:
        return json_string("invalid_protocol_path_predicate");
    case pfl::session_detail::AdvancedFlowFilterCompileStatus::invalid_address_predicate:
        return json_string("invalid_address_predicate");
    case pfl::session_detail::AdvancedFlowFilterCompileStatus::invalid_service_predicate:
        return json_string("invalid_service_predicate");
    case pfl::session_detail::AdvancedFlowFilterCompileStatus::invalid_directionality_predicate:
        return json_string("invalid_directionality_predicate");
    case pfl::session_detail::AdvancedFlowFilterCompileStatus::invalid_traffic_distribution_predicate:
        return json_string("invalid_traffic_distribution_predicate");
    case pfl::session_detail::AdvancedFlowFilterCompileStatus::invalid_address_family_predicate:
        return json_string("invalid_address_family_predicate");
    }

    return json_string("invalid_advanced_filter");
}

std::string parse_issue_json(const std::optional<pfl::FrontendAdvancedFlowTextParseIssue>& issue) {
    if (!issue.has_value()) {
        return "null";
    }

    std::ostringstream out {};
    out << '{'
        << "\"status\":" << parse_status_json(issue->status) << ','
        << "\"line\":" << issue->line << ','
        << "\"column\":" << optional_size_json(issue->column) << ','
        << "\"key\":" << json_string(issue->key) << ','
        << "\"token\":" << json_string(issue->token) << ','
        << "\"message\":" << json_string(issue->message)
        << '}';
    return out.str();
}

std::string compile_issue_json(const std::optional<pfl::session_detail::AdvancedFlowFilterCompileIssue>& issue) {
    if (!issue.has_value()) {
        return "null";
    }

    std::ostringstream out {};
    out << '{'
        << "\"status\":" << compile_status_json(issue->status) << ','
        << "\"category\":" << json_string(issue->category) << ','
        << "\"predicate_index\":" << optional_size_json(issue->predicate_index)
        << '}';
    return out.str();
}

std::string advanced_flow_query_error_text(const pfl::FrontendAdvancedFlowQueryResult& result) {
    switch (result.status) {
    case pfl::FrontendAdvancedFlowQueryStatus::ok:
        return {};
    case pfl::FrontendAdvancedFlowQueryStatus::invalid_filter_text:
        if (result.parse_issue.has_value()) {
            std::ostringstream out {};
            out << "Line " << result.parse_issue->line;
            if (result.parse_issue->column.has_value()) {
                out << ':' << *result.parse_issue->column;
            }
            if (!result.parse_issue->message.empty()) {
                out << ": " << result.parse_issue->message;
            } else {
                out << ": Advanced filter text is invalid.";
            }
            return out.str();
        }
        return "Advanced filter text is invalid.";
    case pfl::FrontendAdvancedFlowQueryStatus::invalid_flow_index:
        if (result.invalid_flow_index.has_value()) {
            return "Candidate flow index is invalid: " + std::to_string(*result.invalid_flow_index) + '.';
        }
        return "Candidate flow index is invalid.";
    case pfl::FrontendAdvancedFlowQueryStatus::invalid_limit:
        return "Advanced filter limit is invalid.";
    case pfl::FrontendAdvancedFlowQueryStatus::invalid_advanced_filter:
        if (result.compile_issue.has_value() && !result.compile_issue->category.empty()) {
            return "Advanced filter is invalid: " + result.compile_issue->category + '.';
        }
        return "Advanced filter is invalid.";
    }

    return "Advanced filter query failed.";
}

std::string advanced_flow_query_result_json(const pfl::FrontendAdvancedFlowQueryResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"status\":" << advanced_flow_query_status_json(result.status) << ','
        << "\"matching_flow_indices\":" << flow_indices_json(result.ordered_flow_indices) << ','
        << "\"result_count_before_limit\":" << result.result_count_before_limit << ','
        << "\"configured_rule_count\":" << result.configured_rule_count << ','
        << "\"active_rule_count\":" << result.active_rule_count << ','
        << "\"parse_status\":" << parse_status_json(result.parse_status) << ','
        << "\"parse_issue\":" << parse_issue_json(result.parse_issue) << ','
        << "\"compile_status\":" << compile_status_json(result.compile_status) << ','
        << "\"compile_issue\":" << compile_issue_json(result.compile_issue) << ','
        << "\"invalid_flow_index\":" << optional_size_json(result.invalid_flow_index) << ','
        << "\"error_text\":" << json_string(advanced_flow_query_error_text(result))
        << '}';
    return out.str();
}

std::string structured_document_status_json(
    const pfl::FrontendAdvancedFlowFilterStructuredDocumentStatus status
) {
    switch (status) {
    case pfl::FrontendAdvancedFlowFilterStructuredDocumentStatus::ok:
        return json_string("ok");
    case pfl::FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_document_update:
        return json_string("invalid_document_update");
    case pfl::FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document:
        return json_string("unrepresentable_document");
    case pfl::FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_advanced_filter:
        return json_string("invalid_advanced_filter");
    case pfl::FrontendAdvancedFlowFilterStructuredDocumentStatus::query_failure:
        return json_string("query_failure");
    }
    return json_string("query_failure");
}

std::string finite_option_json(const pfl::FrontendAdvancedFlowFilterFiniteOptionDto& option) {
    std::ostringstream out {};
    out << '{'
        << "\"stable_id\":" << json_string(option.stable_id) << ','
        << "\"label\":" << json_string(option.label)
        << '}';
    return out.str();
}

std::string finite_option_array_json(const std::vector<pfl::FrontendAdvancedFlowFilterFiniteOptionDto>& options) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < options.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << finite_option_json(options[index]);
    }
    out << ']';
    return out.str();
}

std::string string_array_json(const std::vector<std::string>& values) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << json_string(values[index]);
    }
    out << ']';
    return out.str();
}

std::string structured_section_json(const pfl::FrontendAdvancedFlowFilterFiniteSectionDto& section) {
    std::ostringstream out {};
    out << '{'
        << "\"enabled\":" << bool_json(section.enabled) << ','
        << "\"include\":" << string_array_json(section.include) << ','
        << "\"exclude\":" << string_array_json(section.exclude)
        << '}';
    return out.str();
}

std::string structured_port_row_json(const pfl::FrontendAdvancedFlowFilterPortRowDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"scope_id\":" << json_string(row.scope_id) << ','
        << "\"range_enabled\":" << bool_json(row.range_enabled) << ','
        << "\"primary_text\":" << json_string(row.primary_text) << ','
        << "\"secondary_text\":" << json_string(row.secondary_text)
        << '}';
    return out.str();
}

std::string structured_port_row_array_json(const std::vector<pfl::FrontendAdvancedFlowFilterPortRowDto>& rows) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < rows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << structured_port_row_json(rows[index]);
    }
    out << ']';
    return out.str();
}

std::string structured_port_section_json(const pfl::FrontendAdvancedFlowFilterPortSectionDto& section) {
    std::ostringstream out {};
    out << '{'
        << "\"enabled\":" << bool_json(section.enabled) << ','
        << "\"include\":" << structured_port_row_array_json(section.include) << ','
        << "\"exclude\":" << structured_port_row_array_json(section.exclude)
        << '}';
    return out.str();
}

std::string structured_ip_row_json(const pfl::FrontendAdvancedFlowFilterIpAddressRowDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"scope_id\":" << json_string(row.scope_id) << ','
        << "\"subnet_enabled\":" << bool_json(row.subnet_enabled) << ','
        << "\"address_text\":" << json_string(row.address_text) << ','
        << "\"prefix_text\":" << json_string(row.prefix_text)
        << '}';
    return out.str();
}

std::string structured_ip_row_array_json(const std::vector<pfl::FrontendAdvancedFlowFilterIpAddressRowDto>& rows) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < rows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << structured_ip_row_json(rows[index]);
    }
    out << ']';
    return out.str();
}

std::string structured_ip_section_json(const pfl::FrontendAdvancedFlowFilterIpAddressSectionDto& section) {
    std::ostringstream out {};
    out << '{'
        << "\"enabled\":" << bool_json(section.enabled) << ','
        << "\"include\":" << structured_ip_row_array_json(section.include) << ','
        << "\"exclude\":" << structured_ip_row_array_json(section.exclude)
        << '}';
    return out.str();
}

std::string structured_traffic_row_json(const pfl::FrontendAdvancedFlowFilterTrafficRowDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"metric_id\":" << json_string(row.metric_id) << ','
        << "\"unit_id\":" << json_string(row.unit_id) << ','
        << "\"min_text\":" << json_string(row.min_text) << ','
        << "\"max_text\":" << json_string(row.max_text)
        << '}';
    return out.str();
}

std::string structured_time_row_array_json(const std::vector<pfl::FrontendAdvancedFlowFilterTimeRowDto>& rows) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < rows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        const auto& row = rows[index];
        out << '{'
            << "\"metric_id\":" << json_string(row.metric_id) << ','
            << "\"from_text\":" << json_string(row.from_text) << ','
            << "\"to_text\":" << json_string(row.to_text)
            << '}';
    }
    out << ']';
    return out.str();
}

std::string structured_time_section_json(const pfl::FrontendAdvancedFlowFilterTimeSectionDto& section) {
    std::ostringstream out {};
    out << '{'
        << "\"enabled\":" << bool_json(section.enabled) << ','
        << "\"ranges\":" << structured_time_row_array_json(section.ranges) << ','
        << "\"duration\":" << structured_traffic_row_json(section.duration)
        << '}';
    return out.str();
}

std::string structured_traffic_row_array_json(const std::vector<pfl::FrontendAdvancedFlowFilterTrafficRowDto>& rows) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < rows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << structured_traffic_row_json(rows[index]);
    }
    out << ']';
    return out.str();
}

std::string structured_traffic_section_json(const pfl::FrontendAdvancedFlowFilterTrafficSectionDto& section) {
    std::ostringstream out {};
    out << '{'
        << "\"enabled\":" << bool_json(section.enabled) << ','
        << "\"packet_distribution\":" << structured_section_json(section.packet_distribution) << ','
        << "\"data_distribution\":" << structured_section_json(section.data_distribution) << ','
        << "\"primary\":" << structured_traffic_row_array_json(section.primary) << ','
        << "\"directional_packets\":" << structured_traffic_row_array_json(section.directional_packets) << ','
        << "\"directional_original_bytes\":" << structured_traffic_row_array_json(section.directional_original_bytes) << ','
        << "\"additional\":" << structured_traffic_row_array_json(section.additional)
        << '}';
    return out.str();
}

std::string structured_service_text_row_array_json(
    const std::vector<pfl::FrontendAdvancedFlowFilterServiceTextRowDto>& rows
) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < rows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        const auto& row = rows[index];
        out << '{'
            << "\"operator_id\":" << json_string(row.operator_id) << ','
            << "\"case_sensitive\":" << bool_json(row.case_sensitive) << ','
            << "\"text\":" << json_string(row.text)
            << '}';
    }
    out << ']';
    return out.str();
}

std::string structured_service_section_json(const pfl::FrontendAdvancedFlowFilterServiceSectionDto& section) {
    std::ostringstream out {};
    out << '{'
        << "\"enabled\":" << bool_json(section.enabled) << ','
        << "\"include_recognized\":" << bool_json(section.include_recognized) << ','
        << "\"include_unrecognized\":" << bool_json(section.include_unrecognized) << ','
        << "\"include_text\":" << structured_service_text_row_array_json(section.include_text) << ','
        << "\"exclude_recognized\":" << bool_json(section.exclude_recognized) << ','
        << "\"exclude_unrecognized\":" << bool_json(section.exclude_unrecognized) << ','
        << "\"exclude_text\":" << structured_service_text_row_array_json(section.exclude_text)
        << '}';
    return out.str();
}

std::string structured_protocol_path_row_json(const pfl::FrontendAdvancedFlowFilterProtocolPathRowDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"selector_mode_id\":" << json_string(row.selector_mode_id) << ','
        << "\"predicate_text\":" << json_string(row.predicate_text) << ','
        << "\"compact_text\":" << json_string(row.compact_text) << ','
        << "\"full_text\":" << json_string(row.full_text) << ','
        << "\"applicability_known\":" << bool_json(row.applicability_known) << ','
        << "\"applicable\":" << bool_json(row.applicable) << ','
        << "\"status_text\":" << json_string(row.status_text)
        << '}';
    return out.str();
}

std::string structured_protocol_path_row_array_json(
    const std::vector<pfl::FrontendAdvancedFlowFilterProtocolPathRowDto>& rows
) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < rows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << structured_protocol_path_row_json(rows[index]);
    }
    out << ']';
    return out.str();
}

std::string structured_protocol_path_section_json(const pfl::FrontendAdvancedFlowFilterProtocolPathSectionDto& section) {
    std::ostringstream out {};
    out << '{'
        << "\"enabled\":" << bool_json(section.enabled) << ','
        << "\"include\":" << structured_protocol_path_row_array_json(section.include) << ','
        << "\"exclude\":" << structured_protocol_path_row_array_json(section.exclude)
        << '}';
    return out.str();
}

std::string structured_contains_layer_option_json(const pfl::FrontendAdvancedFlowFilterContainsLayerOptionDto& option) {
    std::ostringstream out {};
    out << '{'
        << "\"stable_id\":" << json_string(option.stable_id) << ','
        << "\"label\":" << json_string(option.label) << ','
        << "\"object_name_suffix\":" << json_string(option.object_name_suffix) << ','
        << "\"identifier_label\":" << json_string(option.identifier_label) << ','
        << "\"preferred_input_format_id\":" << json_string(option.preferred_input_format_id) << ','
        << "\"exact_value_placeholder\":" << json_string(option.exact_value_placeholder)
        << '}';
    return out.str();
}

std::string structured_contains_layer_option_array_json(
    const std::vector<pfl::FrontendAdvancedFlowFilterContainsLayerOptionDto>& options
) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < options.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << structured_contains_layer_option_json(options[index]);
    }
    out << ']';
    return out.str();
}

std::string structured_contains_layer_row_json(const pfl::FrontendAdvancedFlowFilterContainsLayerRowDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"layer_stable_id\":" << json_string(row.layer_stable_id) << ','
        << "\"identifier_mode_id\":" << json_string(row.identifier_mode_id) << ','
        << "\"exact_value_text\":" << json_string(row.exact_value_text) << ','
        << "\"compact_text\":" << json_string(row.compact_text) << ','
        << "\"applicability_known\":" << bool_json(row.applicability_known) << ','
        << "\"applicable\":" << bool_json(row.applicable) << ','
        << "\"status_text\":" << json_string(row.status_text)
        << '}';
    return out.str();
}

std::string structured_contains_layer_row_array_json(
    const std::vector<pfl::FrontendAdvancedFlowFilterContainsLayerRowDto>& rows
) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < rows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << structured_contains_layer_row_json(rows[index]);
    }
    out << ']';
    return out.str();
}

std::string structured_contains_layer_section_json(
    const pfl::FrontendAdvancedFlowFilterContainsLayerSectionDto& section
) {
    std::ostringstream out {};
    out << '{'
        << "\"enabled\":" << bool_json(section.enabled) << ','
        << "\"include\":" << structured_contains_layer_row_array_json(section.include) << ','
        << "\"exclude\":" << structured_contains_layer_row_array_json(section.exclude)
        << '}';
    return out.str();
}

std::string structured_option_catalog_json(
    const pfl::FrontendAdvancedFlowFilterStructuredOptionCatalogDto& catalog
) {
    std::ostringstream out {};
    out << '{'
        << "\"address_family\":" << finite_option_array_json(catalog.address_family) << ','
        << "\"flow_protocol\":" << finite_option_array_json(catalog.flow_protocol) << ','
        << "\"detected_protocol\":" << finite_option_array_json(catalog.detected_protocol) << ','
        << "\"tls_version\":" << finite_option_array_json(catalog.tls_version) << ','
        << "\"quic_version\":" << finite_option_array_json(catalog.quic_version) << ','
        << "\"directionality\":" << finite_option_array_json(catalog.directionality) << ','
        << "\"traffic_distribution\":" << finite_option_array_json(catalog.traffic_distribution) << ','
        << "\"endpoint_scope\":" << finite_option_array_json(catalog.endpoint_scope) << ','
        << "\"protocol_path_selector_mode\":" << finite_option_array_json(catalog.protocol_path_selector_mode) << ','
        << "\"contains_layer_identifier_mode\":"
        << finite_option_array_json(catalog.contains_layer_identifier_mode) << ','
        << "\"contains_layer_kind\":" << structured_contains_layer_option_array_json(catalog.contains_layer_kind)
        << '}';
    return out.str();
}

std::string structured_document_json(
    const std::optional<pfl::FrontendAdvancedFlowFilterStructuredDocumentDto>& document
) {
    if (!document.has_value()) {
        return "null";
    }

    std::ostringstream out {};
    out << '{'
        << "\"canonical_text\":" << json_string(document->canonical_text) << ','
        << "\"address_family\":" << structured_section_json(document->address_family) << ','
        << "\"flow_protocol\":" << structured_section_json(document->flow_protocol) << ','
        << "\"detected_protocol\":" << structured_section_json(document->detected_protocol) << ','
        << "\"tls_version\":" << structured_section_json(document->tls_version) << ','
        << "\"quic_version\":" << structured_section_json(document->quic_version) << ','
        << "\"directionality\":" << structured_section_json(document->directionality) << ','
        << "\"ports\":" << structured_port_section_json(document->ports) << ','
        << "\"ip_addresses\":" << structured_ip_section_json(document->ip_addresses) << ','
        << "\"time\":" << structured_time_section_json(document->time) << ','
        << "\"traffic\":" << structured_traffic_section_json(document->traffic) << ','
        << "\"service\":" << structured_service_section_json(document->service) << ','
        << "\"protocol_path\":" << structured_protocol_path_section_json(document->protocol_path) << ','
        << "\"contains_layer\":" << structured_contains_layer_section_json(document->contains_layer) << ','
        << "\"has_unsupported_configured_sections\":" << bool_json(document->has_unsupported_configured_sections)
        << '}';
    return out.str();
}

std::string advanced_flow_filter_document_workflow_state_json(
    const pfl::FrontendAdvancedFlowFilterDocumentWorkflowStateDto& state
) {
    std::ostringstream out {};
    out << '{'
        << "\"canonical_text\":" << json_string(state.canonical_text) << ','
        << "\"source_path\":" << json_string(state.source_path) << ','
        << "\"display_name\":" << json_string(state.display_name) << ','
        << "\"is_file_backed\":" << bool_json(state.is_file_backed) << ','
        << "\"has_unsaved_changes\":" << bool_json(state.has_unsaved_changes) << ','
        << "\"has_unsaved_configuration\":" << bool_json(state.has_unsaved_configuration) << ','
        << "\"can_clear_unsaved_changes\":" << bool_json(state.can_clear_unsaved_changes) << ','
        << "\"clear_available\":" << bool_json(state.clear_available) << ','
        << "\"configured_rule_count\":" << state.configured_rule_count << ','
        << "\"active_rule_count\":" << state.active_rule_count
        << '}';
    return out.str();
}

std::string structured_update_issue_json(
    const std::optional<pfl::FrontendAdvancedFlowFilterStructuredUpdateIssue>& issue
) {
    if (!issue.has_value()) {
        return "null";
    }

    std::ostringstream out {};
    out << '{'
        << "\"section_id\":" << json_string(issue->section_id) << ','
        << "\"group\":" << json_string(issue->group) << ','
        << "\"value_id\":" << json_string(issue->value_id) << ','
        << "\"row_index\":" << optional_size_json(issue->row_index) << ','
        << "\"field_id\":" << json_string(issue->field_id) << ','
        << "\"message\":" << json_string(issue->message)
        << '}';
    return out.str();
}

std::string structured_document_result_json(
    const pfl::FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    std::ostringstream out {};
    out << '{'
        << "\"status\":" << structured_document_status_json(result.status) << ','
        << "\"document\":" << structured_document_json(result.document) << ','
        << "\"option_catalog\":" << structured_option_catalog_json(result.option_catalog) << ','
        << "\"configured_rule_count\":" << result.configured_rule_count << ','
        << "\"active_rule_count\":" << result.active_rule_count << ','
        << "\"parse_status\":" << parse_status_json(result.parse_status) << ','
        << "\"parse_issue\":" << parse_issue_json(result.parse_issue) << ','
        << "\"compile_status\":" << compile_status_json(result.compile_status) << ','
        << "\"compile_issue\":" << compile_issue_json(result.compile_issue) << ','
        << "\"update_issue\":" << structured_update_issue_json(result.update_issue) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string protocol_path_stats_json(const pfl::FrontendProtocolPathStatsDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"node_id\":" << row.node_id << ','
        << "\"parent_node_id\":" << row.parent_node_id << ','
        << "\"depth\":" << row.depth << ','
        << "\"layer_text\":" << json_string(row.layer_text) << ','
        << "\"path_text\":" << json_string(row.path_text) << ','
        << "\"compact_text\":" << json_string(row.compact_text) << ','
        << "\"advanced_filter_predicate_text\":" << json_string(row.advanced_filter_predicate_text) << ','
        << "\"badges\":[";

    for (std::size_t index = 0; index < row.badges.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << protocol_path_badge_json(row.badges[index]);
    }

    out << "],"
        << "\"has_children\":" << bool_json(row.has_children) << ','
        << "\"is_terminal\":" << bool_json(row.is_terminal) << ','
        << "\"flow_count\":" << row.flow_count << ','
        << "\"packet_count\":" << row.packet_count << ','
        << "\"original_byte_count\":" << row.original_byte_count << ','
        << "\"flow_percent\":" << row.flow_percent << ','
        << "\"packet_percent\":" << row.packet_percent << ','
        << "\"original_byte_percent\":" << row.original_byte_percent << ','
        << "\"flow_count_text\":" << json_string(row.flow_count_text) << ','
        << "\"packet_count_text\":" << json_string(row.packet_count_text) << ','
        << "\"original_byte_count_text\":" << json_string(row.original_byte_count_text)
        << '}';
    return out.str();
}

std::string protocol_path_statistics_json(const std::vector<pfl::FrontendProtocolPathStatsDto>& rows) {
    std::ostringstream out {};
    out << '[';

    for (std::size_t index = 0; index < rows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }

        out << protocol_path_stats_json(rows[index]);
    }

    out << ']';
    return out.str();
}

std::string protocol_path_presentation_json(const pfl::FrontendProtocolPathPresentationDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"protocol_path_id\":" << row.protocol_path_id << ','
        << "\"path_text\":" << json_string(row.path_text) << ','
        << "\"compact_text\":" << json_string(row.compact_text) << ','
        << "\"badges\":[";

    for (std::size_t index = 0; index < row.badges.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << protocol_path_badge_json(row.badges[index]);
    }

    out << "]}";
    return out.str();
}

std::string source_availability_json(const pfl::FrontendSourceAvailabilityDto& source) {
    std::ostringstream out {};
    out << '{'
        << "\"has_source_capture\":" << bool_json(source.has_source_capture) << ','
        << "\"source_capture_accessible\":" << bool_json(source.source_capture_accessible) << ','
        << "\"opened_from_index\":" << bool_json(source.opened_from_index) << ','
        << "\"partial_open\":" << bool_json(source.partial_open) << ','
        << "\"byte_backed_inspection_available\":" << bool_json(source.byte_backed_inspection_available) << ','
        << "\"flow_grouping_ignores_vlan_and_mpls_layers\":" << bool_json(source.flow_grouping_ignores_vlan_and_mpls_layers) << ','
        << "\"flow_grouping_ignores_gtpu_teids\":" << bool_json(source.flow_grouping_ignores_gtpu_teids) << ','
        << "\"active_source_capture_path\":" << json_string(source.active_source_capture_path) << ','
        << "\"expected_source_capture_path\":" << json_string(source.expected_source_capture_path)
        << '}';
    return out.str();
}

std::string packet_summary_field_json(const pfl::session_detail::PacketSummaryField& field) {
    std::ostringstream out {};
    out << '{'
        << "\"label\":" << json_string(field.label) << ','
        << "\"value\":" << json_string(field.value)
        << '}';
    return out.str();
}

std::string packet_summary_layer_json(const pfl::session_detail::PacketSummaryLayer& layer) {
    std::ostringstream out {};
    out << '{'
        << "\"id\":" << json_string(layer.id) << ','
        << "\"title\":" << json_string(layer.title) << ','
        << "\"fields\":[";

    for (std::size_t index = 0; index < layer.fields.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << packet_summary_field_json(layer.fields[index]);
    }

    out << "],"
        << "\"children\":[";

    for (std::size_t index = 0; index < layer.children.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << packet_summary_layer_json(layer.children[index]);
    }

    out << "],"
        << "\"expanded_by_default\":" << bool_json(layer.expanded_by_default) << ','
        << "\"warning\":" << bool_json(layer.warning) << ','
        << "\"marker_text\":" << json_string(layer.marker_text)
        << '}';
    return out.str();
}

std::string packet_byte_view_descriptor_json(const pfl::FrontendPacketDetailsDto::PacketByteViewDescriptor& descriptor) {
    std::ostringstream out {};
    out << '{'
        << "\"stable_id\":" << json_string(descriptor.stable_id) << ','
        << "\"label\":" << json_string(descriptor.label) << ','
        << "\"parent_stable_id\":";
    if (descriptor.parent_stable_id.has_value()) {
        out << json_string(*descriptor.parent_stable_id);
    } else {
        out << "null";
    }
    out << ','
        << "\"depth\":" << descriptor.depth << ','
        << "\"owner_kind\":" << json_string(descriptor.owner_kind) << ','
        << "\"role\":" << json_string(descriptor.role) << ','
        << "\"assembly_kind\":" << json_string(descriptor.assembly_kind) << ','
        << "\"available_length\":" << descriptor.available_length << ','
        << "\"declared_length\":";
    if (descriptor.declared_length.has_value()) {
        out << *descriptor.declared_length;
    } else {
        out << "null";
    }
    out << ','
        << "\"state\":" << json_string(descriptor.state) << ','
        << "\"supports_payload_only\":" << bool_json(descriptor.supports_payload_only) << ','
        << "\"payload_available_length\":";
    if (descriptor.payload_available_length.has_value()) {
        out << *descriptor.payload_available_length;
    } else {
        out << "null";
    }
    out << ','
        << "\"payload_declared_length\":";
    if (descriptor.payload_declared_length.has_value()) {
        out << *descriptor.payload_declared_length;
    } else {
        out << "null";
    }
    out << ','
        << "\"payload_state\":";
    if (descriptor.payload_state.has_value()) {
        out << json_string(*descriptor.payload_state);
    } else {
        out << "null";
    }
    out << ','
        << "\"contributing_unit_count\":";
    if (descriptor.contributing_unit_count.has_value()) {
        out << *descriptor.contributing_unit_count;
    } else {
        out << "null";
    }
    out << ','
        << "\"contributing_unit_kind\":";
    if (descriptor.contributing_unit_kind.has_value()) {
        out << json_string(*descriptor.contributing_unit_kind);
    } else {
        out << "null";
    }
    out << ','
        << "\"quic_crypto_stream_offset\":";
    if (descriptor.quic_crypto_stream_offset.has_value()) {
        out << *descriptor.quic_crypto_stream_offset;
    } else {
        out << "null";
    }
    out << '}';
    return out.str();
}

std::string packet_byte_view_content_json(const pfl::FrontendPacketDetailsDto::PacketByteViewContent& content) {
    std::ostringstream out {};
    out << '{'
        << "\"available\":" << bool_json(content.available) << ','
        << "\"stable_id\":" << json_string(content.stable_id) << ','
        << "\"label\":" << json_string(content.label) << ','
        << "\"mode\":" << json_string(content.mode) << ','
        << "\"assembly_kind\":" << json_string(content.assembly_kind) << ','
        << "\"available_length\":" << content.available_length << ','
        << "\"declared_length\":";
    if (content.declared_length.has_value()) {
        out << *content.declared_length;
    } else {
        out << "null";
    }
    out << ','
        << "\"state\":" << json_string(content.state) << ','
        << "\"contributing_unit_count\":";
    if (content.contributing_unit_count.has_value()) {
        out << *content.contributing_unit_count;
    } else {
        out << "null";
    }
    out << ','
        << "\"contributing_unit_kind\":";
    if (content.contributing_unit_kind.has_value()) {
        out << json_string(*content.contributing_unit_kind);
    } else {
        out << "null";
    }
    out << ','
        << "\"status_text\":" << json_string(content.status_text) << ','
        << "\"formatted_text\":" << json_string(content.formatted_text) << ','
        << "\"unavailable_text\":" << json_string(content.unavailable_text)
        << '}';
    return out.str();
}

std::string stream_item_data_json(const pfl::FrontendStreamItemDto::StreamItemDataDto& item_data) {
    std::ostringstream out {};
    out << '{'
        << "\"available\":" << bool_json(item_data.available) << ','
        << "\"semantic_kind\":" << json_string(item_data.semantic_kind) << ','
        << "\"source_kind\":" << json_string(item_data.source_kind) << ','
        << "\"state\":" << json_string(item_data.state) << ','
        << "\"assembly_kind\":" << json_string(item_data.assembly_kind) << ','
        << "\"available_length\":" << item_data.available_length << ','
        << "\"declared_length\":";
    if (item_data.declared_length.has_value()) {
        out << *item_data.declared_length;
    } else {
        out << "null";
    }
    out << ','
        << "\"contributing_unit_kind\":";
    if (item_data.contributing_unit_kind.has_value()) {
        out << json_string(*item_data.contributing_unit_kind);
    } else {
        out << "null";
    }
    out << ','
        << "\"contributing_unit_count\":";
    if (item_data.contributing_unit_count.has_value()) {
        out << *item_data.contributing_unit_count;
    } else {
        out << "null";
    }
    out << ','
        << "\"logical_offset\":";
    if (item_data.logical_offset.has_value()) {
        out << *item_data.logical_offset;
    } else {
        out << "null";
    }
    out << ','
        << "\"status_text\":" << json_string(item_data.status_text) << ','
        << "\"formatted_text\":" << json_string(item_data.formatted_text) << ','
        << "\"unavailable_text\":" << json_string(item_data.unavailable_text)
        << '}';
    return out.str();
}

std::string open_result_json(const pfl::FrontendOpenResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"opened\":" << bool_json(result.opened) << ','
        << "\"cancelled\":" << bool_json(result.cancelled) << ','
        << "\"opened_from_index\":" << bool_json(result.opened_from_index) << ','
        << "\"partial_open\":" << bool_json(result.partial_open) << ','
        << "\"partial_open_warning_text\":" << json_string(result.partial_open_warning_text) << ','
        << "\"has_source_capture\":" << bool_json(result.has_source_capture) << ','
        << "\"source_capture_accessible\":" << bool_json(result.source_capture_accessible) << ','
        << "\"input_path\":" << json_string(result.input_path) << ','
        << "\"active_source_capture_path\":" << json_string(result.active_source_capture_path) << ','
        << "\"expected_source_capture_path\":" << json_string(result.expected_source_capture_path) << ','
        << "\"error_text\":" << json_string(result.error_text) << ','
        << "\"source_availability\":" << source_availability_json(result.source_availability)
        << '}';
    return out.str();
}

std::string open_start_result_json(const pfl::FrontendOpenStartResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"started\":" << bool_json(result.started) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string open_progress_json(const pfl::FrontendOpenProgressDto& progress) {
    std::ostringstream out {};
    out << '{'
        << "\"in_progress\":" << bool_json(progress.in_progress) << ','
        << "\"cancel_requested\":" << bool_json(progress.cancel_requested) << ','
        << "\"opening_as_index\":" << bool_json(progress.opening_as_index) << ','
        << "\"packets_processed\":" << progress.packets_processed << ','
        << "\"bytes_processed\":" << progress.bytes_processed << ','
        << "\"total_bytes\":" << progress.total_bytes << ','
        << "\"percent\":" << progress.percent << ','
        << "\"input_path\":" << json_string(progress.input_path)
        << '}';
    return out.str();
}

std::string open_poll_result_json(const pfl::FrontendOpenPollResultDto& result) {
    std::ostringstream out {};
    out << '{'
        << "\"ready\":" << bool_json(result.ready) << ','
        << "\"progress\":" << open_progress_json(result.progress) << ','
        << "\"result\":" << open_result_json(result.result)
        << '}';
    return out.str();
}

std::string attach_source_capture_result_json(const pfl::FrontendAttachSourceCaptureResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"attached\":" << bool_json(result.attached) << ','
        << "\"error_text\":" << json_string(result.error_text) << ','
        << "\"source_availability\":" << source_availability_json(result.source_availability)
        << '}';
    return out.str();
}

std::string save_index_result_json(const pfl::FrontendSaveIndexResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"saved\":" << bool_json(result.saved) << ','
        << "\"output_path\":" << json_string(result.output_path) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string settings_json(const pfl::FrontendSettingsDto& settings) {
    std::ostringstream out {};
    out << '{'
        << "\"http_use_path_as_service_hint\":" << bool_json(settings.http_use_path_as_service_hint) << ','
        << "\"use_possible_tls_quic\":" << bool_json(settings.use_possible_tls_quic) << ','
        << "\"ignore_vlan_and_mpls_layers_when_grouping_flows\":" << bool_json(settings.ignore_vlan_and_mpls_layers_when_grouping_flows) << ','
        << "\"ignore_gtpu_teids_when_grouping_inner_flows\":" << bool_json(settings.ignore_gtpu_teids_when_grouping_inner_flows) << ','
        << "\"show_wireshark_filter_for_selected_flow\":" << bool_json(settings.show_wireshark_filter_for_selected_flow) << ','
        << "\"validate_selected_packet_checksums\":" << bool_json(settings.validate_selected_packet_checksums)
        << '}';
    return out.str();
}

std::string export_current_flow_result_json(const pfl::FrontendExportCurrentFlowResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"exported\":" << bool_json(result.exported) << ','
        << "\"output_path\":" << json_string(result.output_path) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string export_selected_flows_result_json(const pfl::FrontendExportSelectedFlowsResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"exported\":" << bool_json(result.exported) << ','
        << "\"output_path\":" << json_string(result.output_path) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string export_all_flows_info_csv_result_json(const pfl::FrontendExportAllFlowsInfoCsvResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"exported\":" << bool_json(result.exported) << ','
        << "\"output_path\":" << json_string(result.output_path) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string export_protocol_path_tree_result_json(const pfl::FrontendExportProtocolPathTreeResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"exported\":" << bool_json(result.exported) << ','
        << "\"output_path\":" << json_string(result.output_path) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string byte_export_format_json(const pfl::FrontendByteExportFormatDto& format) {
    std::ostringstream out {};
    out << '{'
        << "\"stable_id\":" << json_string(format.stable_id) << ','
        << "\"label\":" << json_string(format.label) << ','
        << "\"suggested_extension\":" << json_string(format.suggested_extension) << ','
        << "\"binary_output\":" << bool_json(format.binary_output)
        << '}';
    return out.str();
}

std::string byte_export_formats_json(const std::vector<pfl::FrontendByteExportFormatDto>& formats) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < formats.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << byte_export_format_json(formats[index]);
    }
    out << ']';
    return out.str();
}

std::string byte_export_result_json(const pfl::FrontendByteExportResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"exported\":" << bool_json(result.exported) << ','
        << "\"output_path\":" << json_string(result.output_path) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string smart_export_result_json(const pfl::FrontendSmartExportResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"exported\":" << bool_json(result.exported) << ','
        << "\"output_path\":" << json_string(result.output_path) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string protocol_hint_stats_row_json(const pfl::FrontendProtocolHintStatsDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"group\":" << json_string(row.group) << ','
        << "\"protocol_label\":" << json_string(row.protocol_label) << ','
        << "\"flow_count\":" << row.flow_count << ','
        << "\"flow_count_text\":" << json_string(row.flow_count_text) << ','
        << "\"packet_count\":" << row.packet_count << ','
        << "\"packet_count_text\":" << json_string(row.packet_count_text) << ','
        << "\"captured_bytes\":" << row.captured_bytes << ','
        << "\"captured_bytes_text\":" << json_string(row.captured_bytes_text) << ','
        << "\"original_bytes\":" << row.original_bytes << ','
        << "\"original_bytes_text\":" << json_string(row.original_bytes_text)
        << '}';
    return out.str();
}

std::string top_endpoint_json(const pfl::FrontendTopEndpointDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"endpoint_label\":" << json_string(row.endpoint_label) << ','
        << "\"packet_count\":" << row.packet_count << ','
        << "\"total_bytes\":" << row.total_bytes
        << '}';
    return out.str();
}

std::string top_port_json(const pfl::FrontendTopPortDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"port\":" << row.port << ','
        << "\"packet_count\":" << row.packet_count << ','
        << "\"total_bytes\":" << row.total_bytes
        << '}';
    return out.str();
}

std::string quic_recognition_json(const pfl::QuicRecognitionStats& summary) {
    std::ostringstream out {};
    out << '{'
        << "\"total_flows\":" << summary.total_flows << ','
        << "\"with_sni\":" << summary.with_sni << ','
        << "\"without_sni\":" << summary.without_sni << ','
        << "\"version_v1\":" << summary.version_v1 << ','
        << "\"version_draft29\":" << summary.version_draft29 << ','
        << "\"version_v2\":" << summary.version_v2 << ','
        << "\"version_unknown\":" << summary.version_unknown
        << '}';
    return out.str();
}

std::string tls_recognition_json(const pfl::TlsRecognitionStats& summary) {
    std::ostringstream out {};
    out << '{'
        << "\"total_flows\":" << summary.total_flows << ','
        << "\"with_sni\":" << summary.with_sni << ','
        << "\"without_sni\":" << summary.without_sni << ','
        << "\"version_tls12\":" << summary.version_tls12 << ','
        << "\"version_tls13\":" << summary.version_tls13 << ','
        << "\"version_unknown\":" << summary.version_unknown
        << '}';
    return out.str();
}

std::string capture_packet_size_statistics_bucket_json(const pfl::FrontendCapturePacketSizeStatisticsBucketDto& bucket) {
    std::ostringstream out {};
    out << '{'
        << "\"bucket_id\":" << json_string(bucket.bucket_id) << ','
        << "\"label\":" << json_string(bucket.label) << ','
        << "\"lower_bound_inclusive\":" << bucket.lower_bound_inclusive << ','
        << "\"upper_bound_inclusive\":";
    if (bucket.upper_bound_inclusive.has_value()) {
        out << *bucket.upper_bound_inclusive;
    } else {
        out << "null";
    }
    out << ','
        << "\"packet_count\":" << bucket.packet_count << ','
        << "\"packet_count_text\":" << json_string(bucket.packet_count_text) << ','
        << "\"total_fraction\":" << bucket.total_fraction << ','
        << "\"total_percent_text\":" << json_string(bucket.total_percent_text) << ','
        << "\"normalized_fraction\":" << bucket.normalized_fraction
        << '}';
    return out.str();
}

std::string capture_packet_size_statistics_json(const pfl::FrontendCapturePacketSizeStatisticsDto& statistics) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(statistics.has_capture) << ','
        << "\"total_packet_count\":" << statistics.total_packet_count << ','
        << "\"maximum_bucket_packet_count\":" << statistics.maximum_bucket_packet_count << ','
        << "\"maximum_captured_packet_length\":" << statistics.maximum_captured_packet_length << ','
        << "\"maximum_captured_packet_length_text\":"
        << json_string(statistics.maximum_captured_packet_length_text) << ','
        << "\"buckets\":[";

    for (std::size_t index = 0; index < statistics.buckets.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << capture_packet_size_statistics_bucket_json(statistics.buckets[index]);
    }

    out << "]}";
    return out.str();
}

std::string flow_packet_count_histogram_bucket_json(const pfl::FrontendFlowPacketCountHistogramBucketDto& bucket) {
    std::ostringstream out {};
    out << '{'
        << "\"bucket_id\":" << json_string(bucket.bucket_id) << ','
        << "\"label\":" << json_string(bucket.label) << ','
        << "\"lower_bound_inclusive\":" << bucket.lower_bound_inclusive << ','
        << "\"upper_bound_inclusive\":";
    if (bucket.upper_bound_inclusive.has_value()) {
        out << *bucket.upper_bound_inclusive;
    } else {
        out << "null";
    }
    out << ','
        << "\"flow_count\":" << bucket.flow_count << ','
        << "\"flow_count_with_total_percent_text\":"
        << json_string(bucket.flow_count_with_total_percent_text) << ','
        << "\"original_byte_count\":" << bucket.original_byte_count << ','
        << "\"original_byte_count_text\":" << json_string(bucket.original_byte_count_text) << ','
        << "\"original_byte_count_with_total_percent_text\":"
        << json_string(bucket.original_byte_count_with_total_percent_text) << ','
        << "\"total_flow_fraction\":" << bucket.total_flow_fraction << ','
        << "\"total_original_byte_fraction\":" << bucket.total_original_byte_fraction << ','
        << "\"normalized_flow_fraction\":" << bucket.normalized_flow_fraction << ','
        << "\"normalized_original_byte_fraction\":" << bucket.normalized_original_byte_fraction
        << '}';
    return out.str();
}

std::string input_kind_json(const pfl::FrontendInputKind kind) {
    switch (kind) {
    case pfl::FrontendInputKind::classic_pcap:
        return json_string("pcap");
    case pfl::FrontendInputKind::pcapng:
        return json_string("pcapng");
    case pfl::FrontendInputKind::pcap_flow_lab_index:
        return json_string("pcap_flow_lab_index");
    case pfl::FrontendInputKind::unknown:
    default:
        return json_string("unknown");
    }
}

std::string flow_packet_count_histogram_json(const pfl::FrontendFlowPacketCountHistogramDto& histogram) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(histogram.has_capture) << ','
        << "\"total_flow_count\":" << histogram.total_flow_count << ','
        << "\"total_original_byte_count\":" << histogram.total_original_byte_count << ','
        << "\"maximum_bucket_flow_count\":" << histogram.maximum_bucket_flow_count << ','
        << "\"maximum_bucket_original_byte_count\":" << histogram.maximum_bucket_original_byte_count << ','
        << "\"excluded_zero_packet_flow_count\":" << histogram.excluded_zero_packet_flow_count << ','
        << "\"excluded_zero_packet_original_byte_count\":" << histogram.excluded_zero_packet_original_byte_count << ','
        << "\"buckets\":[";

    for (std::size_t index = 0; index < histogram.buckets.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << flow_packet_count_histogram_bucket_json(histogram.buckets[index]);
    }

    out << "]}";
    return out.str();
}

std::string protocol_hint_statistics_json(const pfl::FrontendProtocolHintStatisticsDto& statistics) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(statistics.has_capture) << ','
        << "\"protocol_hints\":[";

    for (std::size_t index = 0; index < statistics.protocol_hints.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << protocol_hint_stats_row_json(statistics.protocol_hints[index]);
    }

    out << "]}";
    return out.str();
}

std::string quic_tls_statistics_json(const pfl::FrontendQuicTlsStatisticsDto& statistics) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(statistics.has_capture) << ','
        << "\"quic_recognition\":" << quic_recognition_json(statistics.quic_recognition) << ','
        << "\"tls_recognition\":" << tls_recognition_json(statistics.tls_recognition)
        << '}';
    return out.str();
}

std::string top_endpoint_port_statistics_json(const pfl::FrontendTopEndpointPortStatisticsDto& statistics) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(statistics.has_capture) << ','
        << "\"limit\":" << statistics.limit << ','
        << "\"top_endpoints\":[";

    for (std::size_t index = 0; index < statistics.top_endpoints.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << top_endpoint_json(statistics.top_endpoints[index]);
    }

    out << "],"
        << "\"top_ports\":[";

    for (std::size_t index = 0; index < statistics.top_ports.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << top_port_json(statistics.top_ports[index]);
    }

    out << "]}";
    return out.str();
}

std::string overview_json(const pfl::FrontendOverviewDto& overview) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(overview.has_capture) << ','
        << "\"unrecognized_packet_count\":" << overview.unrecognized_packet_count << ','
        << "\"unrecognized_packets\":";
    if (overview.unrecognized_packets.has_value()) {
        out << '{'
            << "\"packet_count\":" << overview.unrecognized_packets->packet_count << ','
            << "\"captured_bytes\":" << overview.unrecognized_packets->captured_bytes << ','
            << "\"original_bytes\":" << overview.unrecognized_packets->original_bytes
            << "},";
    } else {
        out << "null,";
    }
    out
        << "\"summary\":{"
        << "\"packet_count\":" << overview.summary.packet_count << ','
        << "\"flow_count\":" << overview.summary.flow_count << ','
        << "\"captured_bytes\":" << overview.summary.captured_bytes << ','
        << "\"captured_bytes_text\":" << json_string(overview.summary.captured_bytes_text) << ','
        << "\"original_bytes\":" << overview.summary.original_bytes << ','
        << "\"original_bytes_text\":" << json_string(overview.summary.original_bytes_text) << ','
        << "\"total_bytes\":" << overview.summary.total_bytes
        << "},"
        << "\"whole_capture_totals\":{"
        << "\"packet_count\":" << overview.whole_capture_totals.packet_count << ','
        << "\"captured_bytes\":" << overview.whole_capture_totals.captured_bytes << ','
        << "\"captured_bytes_text\":" << json_string(overview.whole_capture_totals.captured_bytes_text) << ','
        << "\"original_bytes\":" << overview.whole_capture_totals.original_bytes << ','
        << "\"original_bytes_text\":" << json_string(overview.whole_capture_totals.original_bytes_text)
        << "},"
        << "\"input_metadata\":{"
        << "\"input_path\":" << json_string(overview.input_metadata.input_path) << ','
        << "\"input_kind\":" << input_kind_json(overview.input_metadata.input_kind) << ','
        << "\"input_file_size\":" << overview.input_metadata.input_file_size << ','
        << "\"source_capture_path\":";
    if (overview.input_metadata.source_capture_path.has_value()) {
        out << json_string(*overview.input_metadata.source_capture_path);
    } else {
        out << "null";
    }
    out << ','
        << "\"source_capture_accessible\":" << bool_json(overview.input_metadata.source_capture_accessible)
        << "},"
        << "\"protocol_summary\":{"
        << "\"tcp\":" << protocol_stats_json(overview.protocol_summary.tcp) << ','
        << "\"udp\":" << protocol_stats_json(overview.protocol_summary.udp) << ','
        << "\"sctp\":" << protocol_stats_json(overview.protocol_summary.sctp) << ','
        << "\"other\":" << protocol_stats_json(overview.protocol_summary.other) << ','
        << "\"ipv4\":" << protocol_stats_json(overview.protocol_summary.ipv4) << ','
        << "\"ipv6\":" << protocol_stats_json(overview.protocol_summary.ipv6)
        << "},"
        << "\"protocol_path_statistics_default_mode\":" << static_cast<int>(overview.protocol_path_statistics_default_mode) << ','
        << "\"protocol_path_presentations\":[";

    for (std::size_t index = 0; index < overview.protocol_path_presentations.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }

        out << protocol_path_presentation_json(overview.protocol_path_presentations[index]);
    }

    out << ']'
        << '}';
    return out.str();
}

std::string flows_json(const std::vector<pfl::FrontendFlowDto>& flows) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < flows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }

        const auto& flow = flows[index];
        out << '{'
            << "\"flow_index\":" << flow.flow_index << ','
            << "\"family\":" << family_to_json(flow.family) << ','
            << "\"protocol_text\":" << json_string(flow.protocol_text) << ','
            << "\"protocol_hint\":" << json_string(flow.protocol_hint) << ','
            << "\"protocol_hint_display\":" << json_string(flow.protocol_hint_display) << ','
            << "\"service_hint\":" << json_string(flow.service_hint) << ','
            << "\"protocol_path_id\":" << flow.protocol_path_id << ','
            << "\"has_fragmented_packets\":" << bool_json(flow.has_fragmented_packets) << ','
            << "\"fragmented_packet_count\":" << flow.fragmented_packet_count << ','
            << "\"address_a\":" << json_string(flow.address_a) << ','
            << "\"port_a\":" << flow.port_a << ','
            << "\"endpoint_a\":" << json_string(flow.endpoint_a) << ','
            << "\"address_b\":" << json_string(flow.address_b) << ','
            << "\"port_b\":" << flow.port_b << ','
            << "\"endpoint_b\":" << json_string(flow.endpoint_b) << ','
            << "\"packet_count\":" << flow.packet_count << ','
            << "\"total_bytes\":" << flow.total_bytes << ','
            << "\"wireshark_display_filter\":" << json_string(flow.wireshark_display_filter)
            << '}';
    }
    out << ']';
    return out.str();
}

std::string flow_json(const pfl::FrontendFlowDto& flow) {
    std::ostringstream out {};
    out << '{'
        << "\"flow_index\":" << flow.flow_index << ','
        << "\"family\":" << family_to_json(flow.family) << ','
        << "\"protocol_text\":" << json_string(flow.protocol_text) << ','
        << "\"protocol_hint\":" << json_string(flow.protocol_hint) << ','
        << "\"protocol_hint_display\":" << json_string(flow.protocol_hint_display) << ','
        << "\"service_hint\":" << json_string(flow.service_hint) << ','
        << "\"protocol_path_id\":" << flow.protocol_path_id << ','
        << "\"has_fragmented_packets\":" << bool_json(flow.has_fragmented_packets) << ','
        << "\"fragmented_packet_count\":" << flow.fragmented_packet_count << ','
        << "\"address_a\":" << json_string(flow.address_a) << ','
        << "\"port_a\":" << flow.port_a << ','
        << "\"endpoint_a\":" << json_string(flow.endpoint_a) << ','
        << "\"address_b\":" << json_string(flow.address_b) << ','
        << "\"port_b\":" << flow.port_b << ','
        << "\"endpoint_b\":" << json_string(flow.endpoint_b) << ','
        << "\"packet_count\":" << flow.packet_count << ','
        << "\"total_bytes\":" << flow.total_bytes << ','
        << "\"wireshark_display_filter\":" << json_string(flow.wireshark_display_filter)
        << '}';
    return out.str();
}

std::string protocol_path_legend_json(const std::vector<pfl::FrontendProtocolPathLegendEntryDto>& legend) {
    std::ostringstream out {};
    out << '[';
    for (std::size_t index = 0; index < legend.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << protocol_path_legend_entry_json(legend[index]);
    }
    out << ']';
    return out.str();
}

std::string supported_protocol_catalog_json(const pfl::FrontendSupportedProtocolCatalogDto& catalog) {
    std::ostringstream out {};
    out << "{\"rows\":[";
    for (std::size_t index = 0; index < catalog.rows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << supported_protocol_catalog_row_json(catalog.rows[index]);
    }
    out << "]}";
    return out.str();
}

std::string packet_result_json(const pfl::FrontendSelectedFlowPacketsResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(result.has_capture) << ','
        << "\"has_selected_flow\":" << bool_json(result.has_selected_flow) << ','
        << "\"flow_index\":" << result.flow_index << ','
        << "\"offset\":" << result.offset << ','
        << "\"limit\":" << result.limit << ','
        << "\"total_count\":" << result.total_count << ','
        << "\"updated_flow\":";

    if (result.updated_flow.has_value()) {
        out << flow_json(*result.updated_flow);
    } else {
        out << "null";
    }

    out << ','
        << "\"packets\":[";

    for (std::size_t index = 0; index < result.packets.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }

        const auto& packet = result.packets[index];
        out << '{'
            << "\"row_number\":" << packet.row_number << ','
            << "\"packet_index\":" << packet.packet_index << ','
            << "\"direction_text\":" << json_string(packet.direction_text) << ','
            << "\"timestamp_text\":" << json_string(packet.timestamp_text) << ','
            << "\"captured_length\":" << packet.captured_length << ','
            << "\"original_length\":" << packet.original_length << ','
            << "\"payload_length\":";
        if (packet.payload_length.has_value()) {
            out << *packet.payload_length;
        } else {
            out << "null";
        }
        out << ','
            << "\"is_ip_fragmented\":";
        if (packet.is_ip_fragmented.has_value()) {
            out << bool_json(*packet.is_ip_fragmented);
        } else {
            out << "null";
        }
        out << ','
            << "\"suspected_tcp_retransmission\":" << bool_json(packet.suspected_tcp_retransmission) << ','
            << "\"tcp_flags_text\":";
        if (packet.tcp_flags_text.has_value()) {
            out << json_string(*packet.tcp_flags_text);
        } else {
            out << "null";
        }
        out << '}';
    }

    out << "]}";
    return out.str();
}

std::string unrecognized_packet_result_json(const pfl::FrontendUnrecognizedPacketsResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(result.has_capture) << ','
        << "\"offset\":" << result.offset << ','
        << "\"limit\":" << result.limit << ','
        << "\"total_count\":" << result.total_count << ','
        << "\"packets\":[";

    for (std::size_t index = 0; index < result.packets.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }

        const auto& packet = result.packets[index];
        out << '{'
            << "\"row_number\":" << packet.row_number << ','
            << "\"packet_index\":" << packet.packet_index << ','
            << "\"timestamp_text\":" << json_string(packet.timestamp_text) << ','
            << "\"captured_length\":" << packet.captured_length << ','
            << "\"original_length\":" << packet.original_length << ','
            << "\"reason_text\":" << json_string(packet.reason_text)
            << '}';
    }

    out << "]}";
    return out.str();
}

std::string stream_item_json(const pfl::FrontendStreamItemDto& item);

std::string stream_result_json(const pfl::FrontendSelectedFlowStreamResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(result.has_capture) << ','
        << "\"has_selected_flow\":" << bool_json(result.has_selected_flow) << ','
        << "\"source_capture_accessible\":" << bool_json(result.source_capture_accessible) << ','
        << "\"stream_available\":" << bool_json(result.stream_available) << ','
        << "\"stream_partially_loaded\":" << bool_json(result.stream_partially_loaded) << ','
        << "\"packet_window_partial\":" << bool_json(result.packet_window_partial) << ','
        << "\"can_load_more\":" << bool_json(result.can_load_more) << ','
        << "\"flow_index\":" << result.flow_index << ','
        << "\"packet_window_count\":" << result.packet_window_count << ','
        << "\"total_flow_packet_count\":" << result.total_flow_packet_count << ','
        << "\"requested_item_limit\":" << result.requested_item_limit << ','
        << "\"loaded_item_count\":" << result.loaded_item_count << ','
        << "\"total_item_count\":" << result.total_item_count << ','
        << "\"unavailable_text\":" << json_string(result.unavailable_text) << ','
        << "\"error_text\":" << json_string(result.error_text) << ','
        << "\"source_availability\":" << source_availability_json(result.source_availability) << ','
        << "\"items\":[";

    for (std::size_t index = 0; index < result.items.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }

        out << stream_item_json(result.items[index]);
    }

    out << "]}";
    return out.str();
}

std::string packet_details_json(const pfl::FrontendPacketDetailsDto& details) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(details.has_capture) << ','
        << "\"has_selected_flow\":" << bool_json(details.has_selected_flow) << ','
        << "\"packet_found\":" << bool_json(details.packet_found) << ','
        << "\"source_capture_accessible\":" << bool_json(details.source_capture_accessible) << ','
        << "\"details_available\":" << bool_json(details.details_available) << ','
        << "\"checksum_validation_enabled\":" << bool_json(details.checksum_validation_enabled) << ','
        << "\"flow_index\":" << details.flow_index << ','
        << "\"packet_index\":" << details.packet_index << ','
        << "\"details_title\":" << json_string(details.details_title) << ','
        << "\"summary_text\":" << json_string(details.summary_text) << ','
        << "\"timestamp_text\":" << json_string(details.timestamp_text) << ','
        << "\"captured_length\":" << details.captured_length << ','
        << "\"original_length\":" << details.original_length << ','
        << "\"payload_length\":" << details.payload_length << ','
        << "\"is_ip_fragmented\":" << bool_json(details.is_ip_fragmented) << ','
        << "\"tcp_flags_text\":" << json_string(details.tcp_flags_text) << ','
        << "\"link_summary_text\":" << json_string(details.link_summary_text) << ','
        << "\"network_summary_text\":" << json_string(details.network_summary_text) << ','
        << "\"transport_summary_text\":" << json_string(details.transport_summary_text) << ','
        << "\"summary_layers\":[";

    for (std::size_t index = 0; index < details.summary_layers.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << packet_summary_layer_json(details.summary_layers[index]);
    }

    out << "],"
        << "\"byte_view_descriptors\":[";

    for (std::size_t index = 0; index < details.byte_view_descriptors.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << packet_byte_view_descriptor_json(details.byte_view_descriptors[index]);
    }

    out << "],"
        << "\"selected_byte_view\":" << packet_byte_view_content_json(details.selected_byte_view) << ','
        << "\"checksum_summary_lines\":[";

    for (std::size_t index = 0; index < details.checksum_summary_lines.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << json_string(details.checksum_summary_lines[index]);
    }

    out << "],"
        << "\"checksum_warning_lines\":[";

    for (std::size_t index = 0; index < details.checksum_warning_lines.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << json_string(details.checksum_warning_lines[index]);
    }

    out << "],"
        << "\"unavailable_text\":" << json_string(details.unavailable_text) << ','
        << "\"error_text\":" << json_string(details.error_text) << ','
        << "\"source_availability\":" << source_availability_json(details.source_availability)
        << '}';
    return out.str();
}

std::string analysis_json(const pfl::FrontendSelectedFlowAnalysisDto& analysis) {
    auto histogram_rows_json = [](const std::vector<pfl::FrontendAnalysisHistogramRowDto>& rows) {
        std::ostringstream rows_out {};
        rows_out << '[';
        for (std::size_t index = 0; index < rows.size(); ++index) {
            if (index != 0U) {
                rows_out << ',';
            }
            const auto& row = rows[index];
            rows_out << '{'
                << "\"bucket_label\":" << json_string(row.bucket_label) << ','
                << "\"count_all\":" << row.count_all << ','
                << "\"count_a_to_b\":" << row.count_a_to_b << ','
                << "\"count_b_to_a\":" << row.count_b_to_a
                << '}';
        }
        rows_out << ']';
        return rows_out.str();
    };

    auto rate_points_json = [](const std::vector<pfl::FrontendAnalysisRatePointDto>& points) {
        std::ostringstream out {};
        out << '[';
        for (std::size_t index = 0; index < points.size(); ++index) {
            if (index != 0U) {
                out << ',';
            }
            const auto& point = points[index];
            out << '{'
                << "\"relative_time_us\":" << point.relative_time_us << ','
                << "\"data_per_second\":" << point.data_per_second << ','
                << "\"packets_per_second\":" << point.packets_per_second
                << '}';
        }
        out << ']';
        return out.str();
    };

    auto sequence_preview_rows_json = [&analysis]() {
        std::ostringstream rows_out {};
        rows_out << '[';
        for (std::size_t index = 0; index < analysis.sequence_preview_rows.size(); ++index) {
            if (index != 0U) {
                rows_out << ',';
            }
            const auto& row = analysis.sequence_preview_rows[index];
            rows_out << '{'
                << "\"flow_packet_number\":" << row.flow_packet_number << ','
                << "\"direction_text\":" << json_string(row.direction_text) << ','
                << "\"delta_time_text\":" << json_string(row.delta_time_text) << ','
                << "\"timestamp_text\":" << json_string(row.timestamp_text) << ','
                << "\"captured_length\":" << row.captured_length << ','
                << "\"original_length\":" << row.original_length << ','
                << "\"payload_length\":";
            if (row.payload_length.has_value()) {
                rows_out << *row.payload_length;
            } else {
                rows_out << "null";
            }
            rows_out << '}';
        }
        rows_out << ']';
        return rows_out.str();
    };

    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(analysis.has_capture) << ','
        << "\"has_selected_flow\":" << bool_json(analysis.has_selected_flow) << ','
        << "\"analysis_available\":" << bool_json(analysis.analysis_available) << ','
        << "\"has_tcp_control_counts\":" << bool_json(analysis.has_tcp_control_counts) << ','
        << "\"flow_index\":" << analysis.flow_index << ','
        << "\"total_packets\":" << analysis.total_packets << ','
        << "\"total_bytes\":" << analysis.total_bytes << ','
        << "\"captured_bytes\":" << analysis.captured_bytes << ','
        << "\"packets_a_to_b\":" << analysis.packets_a_to_b << ','
        << "\"packets_b_to_a\":" << analysis.packets_b_to_a << ','
        << "\"bytes_a_to_b\":" << analysis.bytes_a_to_b << ','
        << "\"bytes_b_to_a\":" << analysis.bytes_b_to_a << ','
        << "\"tcp_syn_packets\":" << analysis.tcp_syn_packets << ','
        << "\"tcp_fin_packets\":" << analysis.tcp_fin_packets << ','
        << "\"tcp_rst_packets\":" << analysis.tcp_rst_packets << ','
        << "\"endpoint_summary_text\":" << json_string(analysis.endpoint_summary_text) << ','
        << "\"protocol_text\":" << json_string(analysis.protocol_text) << ','
        << "\"protocol_hint_display\":" << json_string(analysis.protocol_hint_display) << ','
        << "\"service_hint_text\":" << json_string(analysis.service_hint_text) << ','
        << "\"protocol_version_text\":" << json_string(analysis.protocol_version_text) << ','
        << "\"protocol_service_text\":" << json_string(analysis.protocol_service_text) << ','
        << "\"protocol_fallback_text\":" << json_string(analysis.protocol_fallback_text) << ','
        << "\"first_packet_time_text\":" << json_string(analysis.first_packet_time_text) << ','
        << "\"last_packet_time_text\":" << json_string(analysis.last_packet_time_text) << ','
        << "\"duration_text\":" << json_string(analysis.duration_text) << ','
        << "\"largest_gap_text\":" << json_string(analysis.largest_gap_text) << ','
        << "\"packets_considered_text\":" << json_string(analysis.packets_considered_text) << ','
        << "\"total_packets_text\":" << json_string(analysis.total_packets_text) << ','
        << "\"total_bytes_text\":" << json_string(analysis.total_bytes_text) << ','
        << "\"captured_bytes_text\":" << json_string(analysis.captured_bytes_text) << ','
        << "\"packets_a_to_b_text\":" << json_string(analysis.packets_a_to_b_text) << ','
        << "\"packets_b_to_a_text\":" << json_string(analysis.packets_b_to_a_text) << ','
        << "\"bytes_a_to_b_text\":" << json_string(analysis.bytes_a_to_b_text) << ','
        << "\"bytes_b_to_a_text\":" << json_string(analysis.bytes_b_to_a_text) << ','
        << "\"packet_ratio_text\":" << json_string(analysis.packet_ratio_text) << ','
        << "\"byte_ratio_text\":" << json_string(analysis.byte_ratio_text) << ','
        << "\"packet_direction_text\":" << json_string(analysis.packet_direction_text) << ','
        << "\"data_direction_text\":" << json_string(analysis.data_direction_text) << ','
        << "\"packets_per_second_text\":" << json_string(analysis.packets_per_second_text) << ','
        << "\"packets_per_second_a_to_b_text\":" << json_string(analysis.packets_per_second_a_to_b_text) << ','
        << "\"packets_per_second_b_to_a_text\":" << json_string(analysis.packets_per_second_b_to_a_text) << ','
        << "\"bytes_per_second_text\":" << json_string(analysis.bytes_per_second_text) << ','
        << "\"bytes_per_second_a_to_b_text\":" << json_string(analysis.bytes_per_second_a_to_b_text) << ','
        << "\"bytes_per_second_b_to_a_text\":" << json_string(analysis.bytes_per_second_b_to_a_text) << ','
        << "\"average_packet_size_text\":" << json_string(analysis.average_packet_size_text) << ','
        << "\"average_packet_size_a_to_b_text\":" << json_string(analysis.average_packet_size_a_to_b_text) << ','
        << "\"average_packet_size_b_to_a_text\":" << json_string(analysis.average_packet_size_b_to_a_text) << ','
        << "\"average_inter_arrival_text\":" << json_string(analysis.average_inter_arrival_text) << ','
        << "\"min_packet_size_text\":" << json_string(analysis.min_packet_size_text) << ','
        << "\"min_packet_size_a_to_b_text\":" << json_string(analysis.min_packet_size_a_to_b_text) << ','
        << "\"min_packet_size_b_to_a_text\":" << json_string(analysis.min_packet_size_b_to_a_text) << ','
        << "\"max_packet_size_text\":" << json_string(analysis.max_packet_size_text) << ','
        << "\"max_captured_packet_size_text\":" << json_string(analysis.max_captured_packet_size_text) << ','
        << "\"max_packet_size_a_to_b_text\":" << json_string(analysis.max_packet_size_a_to_b_text) << ','
        << "\"max_packet_size_b_to_a_text\":" << json_string(analysis.max_packet_size_b_to_a_text) << ','
        << "\"tcp_syn_packets_text\":" << json_string(analysis.tcp_syn_packets_text) << ','
        << "\"tcp_fin_packets_text\":" << json_string(analysis.tcp_fin_packets_text) << ','
        << "\"tcp_rst_packets_text\":" << json_string(analysis.tcp_rst_packets_text) << ','
        << "\"burst_count_text\":" << json_string(analysis.burst_count_text) << ','
        << "\"longest_burst_packet_count_text\":" << json_string(analysis.longest_burst_packet_count_text) << ','
        << "\"largest_burst_bytes_text\":" << json_string(analysis.largest_burst_bytes_text) << ','
        << "\"idle_gap_count_text\":" << json_string(analysis.idle_gap_count_text) << ','
        << "\"largest_idle_gap_text\":" << json_string(analysis.largest_idle_gap_text) << ','
        << "\"rate_graph_available\":" << bool_json(analysis.rate_graph_available) << ','
        << "\"rate_graph_status_text\":" << json_string(analysis.rate_graph_status_text) << ','
        << "\"rate_graph_window_text\":" << json_string(analysis.rate_graph_window_text) << ','
        << "\"rate_graph_points_a_to_b\":" << rate_points_json(analysis.rate_graph_points_a_to_b) << ','
        << "\"rate_graph_points_b_to_a\":" << rate_points_json(analysis.rate_graph_points_b_to_a) << ','
        << "\"unavailable_text\":" << json_string(analysis.unavailable_text) << ','
        << "\"error_text\":" << json_string(analysis.error_text) << ','
        << "\"inter_arrival_histogram_rows\":" << histogram_rows_json(analysis.inter_arrival_histogram_rows) << ','
        << "\"packet_size_histogram_rows\":" << histogram_rows_json(analysis.packet_size_histogram_rows) << ','
        << "\"sequence_preview_rows\":" << sequence_preview_rows_json()
        << '}';
    return out.str();
}

std::string analysis_sequence_export_result_json(const pfl::FrontendAnalysisSequenceExportResultDto& result) {
    std::ostringstream out {};
    out << '{'
        << "\"exported\":" << bool_json(result.exported) << ','
        << "\"output_path\":" << json_string(result.output_path) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string selection_json(const pfl::FrontendSelectionResultDto& result) {
    std::ostringstream out {};
    out << '{'
        << "\"selected\":" << bool_json(result.selected) << ','
        << "\"updated_flow\":";
    if (result.updated_flow.has_value()) {
        out << flow_json(*result.updated_flow);
    } else {
        out << "null";
    }
    out << '}';
    return out.str();
}

std::string stream_item_json(const pfl::FrontendStreamItemDto& item) {
    std::ostringstream out {};
    out << '{'
        << "\"stream_item_index\":" << item.stream_item_index << ','
        << "\"direction_text\":" << json_string(item.direction_text) << ','
        << "\"label\":" << json_string(item.label) << ','
        << "\"byte_count\":" << item.byte_count << ','
        << "\"packet_count\":" << item.packet_count << ','
        << "\"source_packet_indices\":[";

    for (std::size_t packet_index = 0; packet_index < item.source_packet_indices.size(); ++packet_index) {
        if (packet_index != 0U) {
            out << ',';
        }
        out << item.source_packet_indices[packet_index];
    }

    out << "],"
        << "\"source_packets_text\":" << json_string(item.source_packets_text) << ','
        << "\"has_constricted_contribution\":" << bool_json(item.has_constricted_contribution) << ','
        << "\"header_secondary_text\":" << json_string(item.header_secondary_text) << ','
        << "\"badge_text\":" << json_string(item.badge_text) << ','
        << "\"summary_text\":" << json_string(item.summary_text) << ','
        << "\"summary_layers\":[";

    for (std::size_t index = 0; index < item.summary_layers.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << packet_summary_layer_json(item.summary_layers[index]);
    }

    out << "],"
        << "\"stream_item_data\":" << stream_item_data_json(item.stream_item_data) << ','
        << "\"payload_tab_title\":" << json_string(item.payload_tab_title) << ','
        << "\"payload_preview_text\":" << json_string(item.payload_preview_text) << ','
        << "\"payload_preview_unavailable_text\":" << json_string(item.payload_preview_unavailable_text) << ','
        << "\"constricted_contribution_notes\":[";

    for (std::size_t note_index = 0; note_index < item.constricted_contribution_notes.size(); ++note_index) {
        if (note_index != 0U) {
            out << ',';
        }
        out << json_string(item.constricted_contribution_notes[note_index]);
    }

    out << "],"
        << "\"constricted_packet_notes\":[";

    for (std::size_t note_index = 0; note_index < item.constricted_packet_notes.size(); ++note_index) {
        if (note_index != 0U) {
            out << ',';
        }
        out << json_string(item.constricted_packet_notes[note_index]);
    }

    out << "]"
        << '}';
    return out.str();
}

[[nodiscard]] pfl::FrontendOverviewDto unavailable_overview() {
    return pfl::FrontendOverviewDto {};
}

[[nodiscard]] pfl::FrontendFlowPacketCountHistogramDto unavailable_flow_packet_count_histogram() {
    return pfl::FrontendFlowPacketCountHistogramDto {};
}

[[nodiscard]] pfl::FrontendCapturePacketSizeStatisticsDto unavailable_capture_packet_size_statistics() {
    return pfl::FrontendCapturePacketSizeStatisticsDto {};
}

[[nodiscard]] pfl::FrontendProtocolHintStatisticsDto unavailable_protocol_hint_statistics() {
    return pfl::FrontendProtocolHintStatisticsDto {};
}

[[nodiscard]] pfl::FrontendQuicTlsStatisticsDto unavailable_quic_tls_statistics() {
    return pfl::FrontendQuicTlsStatisticsDto {};
}

[[nodiscard]] pfl::FrontendTopEndpointPortStatisticsDto unavailable_top_endpoint_port_statistics() {
    return pfl::FrontendTopEndpointPortStatisticsDto {};
}

[[nodiscard]] pfl::FrontendSelectedFlowPacketsResult unavailable_selected_flow_packets() {
    return pfl::FrontendSelectedFlowPacketsResult {};
}

[[nodiscard]] pfl::FrontendUnrecognizedPacketsResult unavailable_unrecognized_packets() {
    return pfl::FrontendUnrecognizedPacketsResult {};
}

[[nodiscard]] pfl::FrontendSelectedFlowStreamResult unavailable_selected_flow_stream() {
    pfl::FrontendSelectedFlowStreamResult result {};
    result.unavailable_text = std::string {kAdapterUnavailableText};
    result.error_text = std::string {kAdapterUnavailableText};
    return result;
}

[[nodiscard]] pfl::FrontendStreamItemDto unavailable_stream_item(const std::uint64_t stream_item_index = 0U) {
    pfl::FrontendStreamItemDto item {};
    item.stream_item_index = stream_item_index;
    item.payload_tab_title = "Item Data";
    item.stream_item_data.status_text = std::string {kAdapterUnavailableText};
    item.stream_item_data.unavailable_text = std::string {kAdapterUnavailableText};
    item.payload_preview_unavailable_text = std::string {kAdapterUnavailableText};
    return item;
}

[[nodiscard]] pfl::FrontendPacketDetailsDto unavailable_packet_details() {
    pfl::FrontendPacketDetailsDto details {};
    details.details_title = "Packet Details";
    details.selected_byte_view.unavailable_text = std::string {kAdapterUnavailableText};
    details.unavailable_text = std::string {kAdapterUnavailableText};
    details.error_text = std::string {kAdapterUnavailableText};
    return details;
}

[[nodiscard]] pfl::FrontendPacketDetailsDto::PacketByteViewContent unavailable_packet_byte_view_content() {
    pfl::FrontendPacketDetailsDto::PacketByteViewContent content {};
    content.unavailable_text = std::string {kAdapterUnavailableText};
    return content;
}

[[nodiscard]] pfl::FrontendSelectedFlowAnalysisDto unavailable_selected_flow_analysis() {
    pfl::FrontendSelectedFlowAnalysisDto analysis {};
    analysis.unavailable_text = std::string {kAdapterUnavailableText};
    analysis.error_text = std::string {kAdapterUnavailableText};
    return analysis;
}

}  // namespace

struct PflFrontendSessionAdapterHandle {
    FrontendSessionAdapter adapter {};
};

extern "C" {

PflFrontendSessionAdapterHandle* pfl_frontend_session_adapter_new() {
    return new (std::nothrow) PflFrontendSessionAdapterHandle {};
}

void pfl_frontend_session_adapter_free(PflFrontendSessionAdapterHandle* handle) {
    delete handle;
}

char* pfl_frontend_session_adapter_open_capture_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
) {
    if (handle == nullptr) {
        return make_c_string("{\"opened\":false,\"cancelled\":false,\"opened_from_index\":false,\"partial_open\":false,\"partial_open_warning_text\":\"\",\"has_source_capture\":false,\"source_capture_accessible\":false,\"input_path\":\"\",\"active_source_capture_path\":\"\",\"expected_source_capture_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\",\"source_availability\":{\"has_source_capture\":false,\"source_capture_accessible\":false,\"opened_from_index\":false,\"partial_open\":false,\"byte_backed_inspection_available\":false,\"flow_grouping_ignores_vlan_and_mpls_layers\":false,\"flow_grouping_ignores_gtpu_teids\":false,\"active_source_capture_path\":\"\",\"expected_source_capture_path\":\"\"}}");
    }

    const auto path = path_from_utf8(path_utf8);
    return make_c_string(open_result_json(handle->adapter.open_capture(path)));
}

char* pfl_frontend_session_adapter_start_open_capture_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
) {
    if (handle == nullptr) {
        return make_c_string("{\"started\":false,\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const auto path = path_from_utf8(path_utf8);
    return make_c_string(open_start_result_json(handle->adapter.start_open_capture(path)));
}

char* pfl_frontend_session_adapter_poll_open_capture_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string("{\"ready\":false,\"progress\":{\"in_progress\":false,\"cancel_requested\":false,\"opening_as_index\":false,\"packets_processed\":0,\"bytes_processed\":0,\"total_bytes\":0,\"percent\":0.0,\"input_path\":\"\"},\"result\":{\"opened\":false,\"cancelled\":false,\"opened_from_index\":false,\"partial_open\":false,\"partial_open_warning_text\":\"\",\"has_source_capture\":false,\"source_capture_accessible\":false,\"input_path\":\"\",\"active_source_capture_path\":\"\",\"expected_source_capture_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\",\"source_availability\":{\"has_source_capture\":false,\"source_capture_accessible\":false,\"opened_from_index\":false,\"partial_open\":false,\"byte_backed_inspection_available\":false,\"flow_grouping_ignores_vlan_and_mpls_layers\":false,\"flow_grouping_ignores_gtpu_teids\":false,\"active_source_capture_path\":\"\",\"expected_source_capture_path\":\"\"}}}");
    }

    return make_c_string(open_poll_result_json(handle->adapter.poll_open_capture()));
}

char* pfl_frontend_session_adapter_cancel_open_capture_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string("{\"cancelled\":false}");
    }

    return make_c_string(std::string {"{\"cancelled\":"} + bool_json(handle->adapter.cancel_open_capture()) + '}');
}

char* pfl_frontend_session_adapter_attach_source_capture_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
) {
    if (handle == nullptr) {
        return make_c_string("{\"attached\":false,\"error_text\":\"Adapter handle is unavailable.\",\"source_availability\":{\"has_source_capture\":false,\"source_capture_accessible\":false,\"opened_from_index\":false,\"partial_open\":false,\"byte_backed_inspection_available\":false,\"flow_grouping_ignores_vlan_and_mpls_layers\":false,\"flow_grouping_ignores_gtpu_teids\":false,\"active_source_capture_path\":\"\",\"expected_source_capture_path\":\"\"}}");
    }

    const auto path = path_from_utf8(path_utf8);
    return make_c_string(attach_source_capture_result_json(handle->adapter.attach_source_capture(path)));
}

char* pfl_frontend_session_adapter_save_index_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
) {
    if (handle == nullptr) {
        return make_c_string("{\"saved\":false,\"output_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const auto path = path_from_utf8(path_utf8);
    return make_c_string(save_index_result_json(handle->adapter.save_index(path)));
}

char* pfl_frontend_session_adapter_get_settings_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string("{\"http_use_path_as_service_hint\":false,\"use_possible_tls_quic\":false,\"ignore_vlan_and_mpls_layers_when_grouping_flows\":false,\"ignore_gtpu_teids_when_grouping_inner_flows\":false,\"show_wireshark_filter_for_selected_flow\":true,\"validate_selected_packet_checksums\":false}");
    }

    return make_c_string(settings_json(handle->adapter.get_settings()));
}

char* pfl_frontend_session_adapter_get_flow_packet_count_histogram_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string(flow_packet_count_histogram_json(unavailable_flow_packet_count_histogram()));
    }

    return make_c_string(flow_packet_count_histogram_json(handle->adapter.get_flow_packet_count_histogram()));
}

char* pfl_frontend_session_adapter_get_capture_packet_size_statistics_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string(capture_packet_size_statistics_json(unavailable_capture_packet_size_statistics()));
    }

    return make_c_string(capture_packet_size_statistics_json(handle->adapter.get_capture_packet_size_statistics()));
}

char* pfl_frontend_session_adapter_get_protocol_hint_statistics_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string(protocol_hint_statistics_json(unavailable_protocol_hint_statistics()));
    }

    return make_c_string(protocol_hint_statistics_json(handle->adapter.get_protocol_hint_statistics()));
}

char* pfl_frontend_session_adapter_get_quic_tls_statistics_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string(quic_tls_statistics_json(unavailable_quic_tls_statistics()));
    }

    return make_c_string(quic_tls_statistics_json(handle->adapter.get_quic_tls_statistics()));
}

char* pfl_frontend_session_adapter_get_top_endpoint_port_statistics_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::size_t limit
) {
    if (handle == nullptr) {
        return make_c_string(top_endpoint_port_statistics_json(unavailable_top_endpoint_port_statistics()));
    }

    return make_c_string(top_endpoint_port_statistics_json(handle->adapter.get_top_endpoint_port_statistics(limit)));
}

char* pfl_frontend_session_adapter_get_protocol_path_legend_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string("[]");
    }

    return make_c_string(protocol_path_legend_json(handle->adapter.get_protocol_path_legend()));
}

char* pfl_frontend_session_adapter_get_supported_protocol_catalog_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string("{\"rows\":[]}");
    }

    return make_c_string(supported_protocol_catalog_json(handle->adapter.get_supported_protocol_catalog()));
}

char* pfl_frontend_session_adapter_get_protocol_path_statistics_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint8_t mode
) {
    if (handle == nullptr) {
        return make_c_string("[]");
    }

    const auto statistics_mode = mode == 1U
        ? pfl::ProtocolPathStatisticsMode::identity_tree
        : (mode == 2U
            ? pfl::ProtocolPathStatisticsMode::terminal_paths
            : pfl::ProtocolPathStatisticsMode::kind_overview);
    return make_c_string(protocol_path_statistics_json(
        handle->adapter.get_protocol_path_statistics(statistics_mode)
    ));
}

char* pfl_frontend_session_adapter_get_protocol_path_summary_flow_indices_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint8_t mode,
    const std::uint64_t node_id
) {
    if (handle == nullptr) {
        return make_c_string("[]");
    }

    const auto statistics_mode = mode == 1U
        ? pfl::ProtocolPathStatisticsMode::identity_tree
        : (mode == 2U
            ? pfl::ProtocolPathStatisticsMode::terminal_paths
            : pfl::ProtocolPathStatisticsMode::kind_overview);
    return make_c_string(flow_indices_json(
        handle->adapter.get_protocol_path_summary_flow_indices(statistics_mode, node_id)
    ));
}

char* pfl_frontend_session_adapter_get_advanced_flow_filter_protocol_path_row_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint8_t mode,
    const std::uint64_t node_id
) {
    if (handle == nullptr) {
        return make_c_string(structured_protocol_path_row_json({}));
    }

    const auto statistics_mode = mode == 1U
        ? pfl::ProtocolPathStatisticsMode::identity_tree
        : (mode == 2U
            ? pfl::ProtocolPathStatisticsMode::terminal_paths
            : pfl::ProtocolPathStatisticsMode::kind_overview);
    const auto row = handle->adapter.get_advanced_flow_filter_protocol_path_row(statistics_mode, node_id);
    return make_c_string(structured_protocol_path_row_json(row.value_or(pfl::FrontendAdvancedFlowFilterProtocolPathRowDto {})));
}

char* pfl_frontend_session_adapter_query_advanced_flows_text_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* filter_text_utf8,
    const std::size_t* candidate_flow_indices,
    const std::size_t candidate_flow_index_count
) {
    if (handle == nullptr || filter_text_utf8 == nullptr) {
        return make_c_string(
            "{\"status\":\"invalid_filter_text\",\"matching_flow_indices\":[],\"result_count_before_limit\":0,"
            "\"configured_rule_count\":0,\"active_rule_count\":0,\"parse_status\":\"invalid_value\","
            "\"parse_issue\":null,\"compile_status\":\"ok\",\"compile_issue\":null,\"invalid_flow_index\":null,"
            "\"error_text\":\"Invalid advanced filter request.\"}"
        );
    }
    if (candidate_flow_index_count > 0U && candidate_flow_indices == nullptr) {
        return make_c_string(
            "{\"status\":\"invalid_flow_index\",\"matching_flow_indices\":[],\"result_count_before_limit\":0,"
            "\"configured_rule_count\":0,\"active_rule_count\":0,\"parse_status\":\"ok\","
            "\"parse_issue\":null,\"compile_status\":\"ok\",\"compile_issue\":null,\"invalid_flow_index\":null,"
            "\"error_text\":\"Invalid advanced filter request.\"}"
        );
    }

    // nullptr + zero count means no scope; non-null + zero count means an explicitly empty scope.
    std::optional<std::vector<std::size_t>> candidate_indices {};
    if (candidate_flow_indices != nullptr) {
        candidate_indices = std::vector<std::size_t> {};
        candidate_indices->reserve(candidate_flow_index_count);
        for (std::size_t index = 0; index < candidate_flow_index_count; ++index) {
            candidate_indices->push_back(candidate_flow_indices[index]);
        }
    }

    return make_c_string(advanced_flow_query_result_json(
        handle->adapter.query_advanced_flows_text(
            std::string_view {filter_text_utf8},
            candidate_indices,
            std::nullopt,
            std::nullopt
        )
    ));
}

char* pfl_frontend_session_adapter_parse_advanced_flow_filter_structured_document_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* filter_text_utf8
) {
    if (handle == nullptr || filter_text_utf8 == nullptr) {
        pfl::FrontendAdvancedFlowFilterStructuredDocumentResult result {};
        result.status = pfl::FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_advanced_filter;
        result.parse_status = pfl::session_detail::AdvancedFlowFilterTextParseStatus::invalid_value;
        result.error_text = "Invalid advanced filter request.";
        return make_c_string(structured_document_result_json(result));
    }

    const auto result =
        handle->adapter.parse_advanced_flow_filter_structured_document(std::string_view {filter_text_utf8});
    return make_c_string(structured_document_result_json(result));
}

char* pfl_frontend_session_adapter_get_advanced_flow_filter_document_workflow_state_json(
    PflFrontendSessionAdapterHandle* handle
) {
    if (handle == nullptr) {
        return make_c_string(advanced_flow_filter_document_workflow_state_json({}));
    }

    return make_c_string(advanced_flow_filter_document_workflow_state_json(
        handle->adapter.get_advanced_flow_filter_document_workflow_state()
    ));
}

char* pfl_frontend_session_adapter_update_advanced_flow_filter_structured_section_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* filter_text_utf8,
    const char* section_id_utf8,
    const std::uint8_t enabled,
    const char* const* include_ids_utf8,
    const std::size_t include_id_count,
    const char* const* exclude_ids_utf8,
    const std::size_t exclude_id_count
) {
    if (handle == nullptr || filter_text_utf8 == nullptr || section_id_utf8 == nullptr) {
        pfl::FrontendAdvancedFlowFilterStructuredDocumentResult result {};
        result.status = pfl::FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_document_update;
        result.error_text = "Invalid structured advanced filter update request.";
        return make_c_string(structured_document_result_json(result));
    }

    if ((include_id_count > 0U && include_ids_utf8 == nullptr) || (exclude_id_count > 0U && exclude_ids_utf8 == nullptr)) {
        pfl::FrontendAdvancedFlowFilterStructuredDocumentResult result {};
        result.status = pfl::FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_document_update;
        result.error_text = "Invalid structured advanced filter update request.";
        return make_c_string(structured_document_result_json(result));
    }

    std::vector<std::string> include_ids {};
    include_ids.reserve(include_id_count);
    for (std::size_t index = 0; index < include_id_count; ++index) {
        include_ids.push_back(include_ids_utf8[index] != nullptr ? std::string {include_ids_utf8[index]} : std::string {});
    }

    std::vector<std::string> exclude_ids {};
    exclude_ids.reserve(exclude_id_count);
    for (std::size_t index = 0; index < exclude_id_count; ++index) {
        exclude_ids.push_back(exclude_ids_utf8[index] != nullptr ? std::string {exclude_ids_utf8[index]} : std::string {});
    }

    return make_c_string(structured_document_result_json(
        handle->adapter.update_advanced_flow_filter_structured_section(
            std::string_view {filter_text_utf8},
            std::string_view {section_id_utf8},
            enabled != 0U,
            include_ids,
            exclude_ids
        )
    ));
}

char* pfl_frontend_session_adapter_apply_advanced_flow_filter_structured_document_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* filter_text_utf8,
    const std::uint8_t address_family_enabled,
    const char* const* address_family_include_ids_utf8,
    const std::size_t address_family_include_id_count,
    const char* const* address_family_exclude_ids_utf8,
    const std::size_t address_family_exclude_id_count,
    const std::uint8_t flow_protocol_enabled,
    const char* const* flow_protocol_include_ids_utf8,
    const std::size_t flow_protocol_include_id_count,
    const char* const* flow_protocol_exclude_ids_utf8,
    const std::size_t flow_protocol_exclude_id_count,
    const std::uint8_t detected_protocol_enabled,
    const char* const* detected_protocol_include_ids_utf8,
    const std::size_t detected_protocol_include_id_count,
    const char* const* detected_protocol_exclude_ids_utf8,
    const std::size_t detected_protocol_exclude_id_count,
    const std::uint8_t tls_version_enabled,
    const char* const* tls_version_include_ids_utf8,
    const std::size_t tls_version_include_id_count,
    const char* const* tls_version_exclude_ids_utf8,
    const std::size_t tls_version_exclude_id_count,
    const std::uint8_t quic_version_enabled,
    const char* const* quic_version_include_ids_utf8,
    const std::size_t quic_version_include_id_count,
    const char* const* quic_version_exclude_ids_utf8,
    const std::size_t quic_version_exclude_id_count,
    const std::uint8_t directionality_enabled,
    const char* const* directionality_include_ids_utf8,
    const std::size_t directionality_include_id_count,
    const char* const* directionality_exclude_ids_utf8,
    const std::size_t directionality_exclude_id_count,
    const std::uint8_t ports_enabled,
    const char* const* ports_include_scope_ids_utf8,
    const std::uint8_t* ports_include_range_enabled,
    const char* const* ports_include_primary_text_utf8,
    const char* const* ports_include_secondary_text_utf8,
    const std::size_t ports_include_count,
    const char* const* ports_exclude_scope_ids_utf8,
    const std::uint8_t* ports_exclude_range_enabled,
    const char* const* ports_exclude_primary_text_utf8,
    const char* const* ports_exclude_secondary_text_utf8,
    const std::size_t ports_exclude_count,
    const std::uint8_t ip_addresses_enabled,
    const char* const* ip_include_scope_ids_utf8,
    const std::uint8_t* ip_include_subnet_enabled,
    const char* const* ip_include_address_text_utf8,
    const char* const* ip_include_prefix_text_utf8,
    const std::size_t ip_include_count,
    const char* const* ip_exclude_scope_ids_utf8,
    const std::uint8_t* ip_exclude_subnet_enabled,
    const char* const* ip_exclude_address_text_utf8,
    const char* const* ip_exclude_prefix_text_utf8,
    const std::size_t ip_exclude_count,
    const std::uint8_t time_enabled,
    const char* const* time_range_metric_ids_utf8,
    const char* const* time_range_from_text_utf8,
    const char* const* time_range_to_text_utf8,
    const std::size_t time_range_count,
    const char* time_duration_metric_id_utf8,
    const char* time_duration_unit_id_utf8,
    const char* time_duration_min_text_utf8,
    const char* time_duration_max_text_utf8,
    const std::uint8_t traffic_enabled,
    const char* const* packet_distribution_include_ids_utf8,
    const std::size_t packet_distribution_include_id_count,
    const char* const* packet_distribution_exclude_ids_utf8,
    const std::size_t packet_distribution_exclude_id_count,
    const char* const* data_distribution_include_ids_utf8,
    const std::size_t data_distribution_include_id_count,
    const char* const* data_distribution_exclude_ids_utf8,
    const std::size_t data_distribution_exclude_id_count,
    const char* const* traffic_primary_metric_ids_utf8,
    const char* const* traffic_primary_unit_ids_utf8,
    const char* const* traffic_primary_min_text_utf8,
    const char* const* traffic_primary_max_text_utf8,
    const std::size_t traffic_primary_count,
    const char* const* traffic_directional_packets_metric_ids_utf8,
    const char* const* traffic_directional_packets_unit_ids_utf8,
    const char* const* traffic_directional_packets_min_text_utf8,
    const char* const* traffic_directional_packets_max_text_utf8,
    const std::size_t traffic_directional_packets_count,
    const char* const* traffic_directional_original_bytes_metric_ids_utf8,
    const char* const* traffic_directional_original_bytes_unit_ids_utf8,
    const char* const* traffic_directional_original_bytes_min_text_utf8,
    const char* const* traffic_directional_original_bytes_max_text_utf8,
    const std::size_t traffic_directional_original_bytes_count,
    const char* const* traffic_additional_metric_ids_utf8,
    const char* const* traffic_additional_unit_ids_utf8,
    const char* const* traffic_additional_min_text_utf8,
    const char* const* traffic_additional_max_text_utf8,
    const std::size_t traffic_additional_count,
    const std::uint8_t service_enabled,
    const std::uint8_t service_include_recognized,
    const std::uint8_t service_include_unrecognized,
    const char* const* service_include_operator_ids_utf8,
    const std::uint8_t* service_include_case_sensitive,
    const char* const* service_include_text_utf8,
    const std::size_t service_include_text_count,
    const std::uint8_t service_exclude_recognized,
    const std::uint8_t service_exclude_unrecognized,
    const char* const* service_exclude_operator_ids_utf8,
    const std::uint8_t* service_exclude_case_sensitive,
    const char* const* service_exclude_text_utf8,
    const std::size_t service_exclude_text_count,
    const std::uint8_t protocol_path_enabled,
    const char* const* protocol_path_include_selector_mode_ids_utf8,
    const char* const* protocol_path_include_predicate_text_utf8,
    const std::size_t protocol_path_include_count,
    const char* const* protocol_path_exclude_selector_mode_ids_utf8,
    const char* const* protocol_path_exclude_predicate_text_utf8,
    const std::size_t protocol_path_exclude_count,
    const std::uint8_t contains_layer_enabled,
    const char* const* contains_layer_include_layer_stable_ids_utf8,
    const char* const* contains_layer_include_identifier_mode_ids_utf8,
    const char* const* contains_layer_include_exact_value_text_utf8,
    const std::size_t contains_layer_include_count,
    const char* const* contains_layer_exclude_layer_stable_ids_utf8,
    const char* const* contains_layer_exclude_identifier_mode_ids_utf8,
    const char* const* contains_layer_exclude_exact_value_text_utf8,
    const std::size_t contains_layer_exclude_count
) {
    const auto invalid_request = []() {
        pfl::FrontendAdvancedFlowFilterStructuredDocumentResult result {};
        result.status = pfl::FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_document_update;
        result.error_text = "Invalid structured advanced filter update request.";
        return make_c_string(structured_document_result_json(result));
    };

    if (handle == nullptr || filter_text_utf8 == nullptr) {
        return invalid_request();
    }

    const auto string_array_invalid = [](const char* const* values, const std::size_t count) {
        return count > 0U && values == nullptr;
    };
    if (string_array_invalid(address_family_include_ids_utf8, address_family_include_id_count) ||
        string_array_invalid(address_family_exclude_ids_utf8, address_family_exclude_id_count) ||
        string_array_invalid(flow_protocol_include_ids_utf8, flow_protocol_include_id_count) ||
        string_array_invalid(flow_protocol_exclude_ids_utf8, flow_protocol_exclude_id_count) ||
        string_array_invalid(detected_protocol_include_ids_utf8, detected_protocol_include_id_count) ||
        string_array_invalid(detected_protocol_exclude_ids_utf8, detected_protocol_exclude_id_count) ||
        string_array_invalid(tls_version_include_ids_utf8, tls_version_include_id_count) ||
        string_array_invalid(tls_version_exclude_ids_utf8, tls_version_exclude_id_count) ||
        string_array_invalid(quic_version_include_ids_utf8, quic_version_include_id_count) ||
        string_array_invalid(quic_version_exclude_ids_utf8, quic_version_exclude_id_count) ||
        string_array_invalid(directionality_include_ids_utf8, directionality_include_id_count) ||
        string_array_invalid(directionality_exclude_ids_utf8, directionality_exclude_id_count) ||
        string_array_invalid(ports_include_scope_ids_utf8, ports_include_count) ||
        (ports_include_count > 0U && (ports_include_range_enabled == nullptr ||
                                      ports_include_primary_text_utf8 == nullptr ||
                                      ports_include_secondary_text_utf8 == nullptr)) ||
        string_array_invalid(ports_exclude_scope_ids_utf8, ports_exclude_count) ||
        (ports_exclude_count > 0U && (ports_exclude_range_enabled == nullptr ||
                                      ports_exclude_primary_text_utf8 == nullptr ||
                                      ports_exclude_secondary_text_utf8 == nullptr)) ||
        string_array_invalid(ip_include_scope_ids_utf8, ip_include_count) ||
        (ip_include_count > 0U && (ip_include_subnet_enabled == nullptr ||
                                   ip_include_address_text_utf8 == nullptr ||
                                   ip_include_prefix_text_utf8 == nullptr)) ||
        string_array_invalid(ip_exclude_scope_ids_utf8, ip_exclude_count) ||
        (ip_exclude_count > 0U && (ip_exclude_subnet_enabled == nullptr ||
                                   ip_exclude_address_text_utf8 == nullptr ||
                                   ip_exclude_prefix_text_utf8 == nullptr)) ||
        string_array_invalid(time_range_metric_ids_utf8, time_range_count) ||
        (time_range_count > 0U && (time_range_from_text_utf8 == nullptr ||
                                   time_range_to_text_utf8 == nullptr)) ||
        time_duration_metric_id_utf8 == nullptr ||
        time_duration_unit_id_utf8 == nullptr ||
        time_duration_min_text_utf8 == nullptr ||
        time_duration_max_text_utf8 == nullptr ||
        string_array_invalid(packet_distribution_include_ids_utf8, packet_distribution_include_id_count) ||
        string_array_invalid(packet_distribution_exclude_ids_utf8, packet_distribution_exclude_id_count) ||
        string_array_invalid(data_distribution_include_ids_utf8, data_distribution_include_id_count) ||
        string_array_invalid(data_distribution_exclude_ids_utf8, data_distribution_exclude_id_count) ||
        string_array_invalid(traffic_primary_metric_ids_utf8, traffic_primary_count) ||
        (traffic_primary_count > 0U && (traffic_primary_unit_ids_utf8 == nullptr ||
                                        traffic_primary_min_text_utf8 == nullptr ||
                                        traffic_primary_max_text_utf8 == nullptr)) ||
        string_array_invalid(traffic_directional_packets_metric_ids_utf8, traffic_directional_packets_count) ||
        (traffic_directional_packets_count > 0U &&
         (traffic_directional_packets_unit_ids_utf8 == nullptr ||
          traffic_directional_packets_min_text_utf8 == nullptr ||
          traffic_directional_packets_max_text_utf8 == nullptr)) ||
        string_array_invalid(
            traffic_directional_original_bytes_metric_ids_utf8,
            traffic_directional_original_bytes_count) ||
        (traffic_directional_original_bytes_count > 0U &&
         (traffic_directional_original_bytes_unit_ids_utf8 == nullptr ||
          traffic_directional_original_bytes_min_text_utf8 == nullptr ||
          traffic_directional_original_bytes_max_text_utf8 == nullptr)) ||
        string_array_invalid(traffic_additional_metric_ids_utf8, traffic_additional_count) ||
        (traffic_additional_count > 0U && (traffic_additional_unit_ids_utf8 == nullptr ||
                                           traffic_additional_min_text_utf8 == nullptr ||
                                           traffic_additional_max_text_utf8 == nullptr)) ||
        string_array_invalid(service_include_operator_ids_utf8, service_include_text_count) ||
        (service_include_text_count > 0U && (service_include_case_sensitive == nullptr ||
                                             service_include_text_utf8 == nullptr)) ||
        string_array_invalid(service_exclude_operator_ids_utf8, service_exclude_text_count) ||
        (service_exclude_text_count > 0U && (service_exclude_case_sensitive == nullptr ||
                                             service_exclude_text_utf8 == nullptr)) ||
        string_array_invalid(protocol_path_include_selector_mode_ids_utf8, protocol_path_include_count) ||
        string_array_invalid(protocol_path_include_predicate_text_utf8, protocol_path_include_count) ||
        string_array_invalid(protocol_path_exclude_selector_mode_ids_utf8, protocol_path_exclude_count) ||
        string_array_invalid(protocol_path_exclude_predicate_text_utf8, protocol_path_exclude_count) ||
        string_array_invalid(contains_layer_include_layer_stable_ids_utf8, contains_layer_include_count) ||
        (contains_layer_include_count > 0U &&
         (contains_layer_include_identifier_mode_ids_utf8 == nullptr ||
          contains_layer_include_exact_value_text_utf8 == nullptr ||
          string_array_invalid(contains_layer_include_identifier_mode_ids_utf8, contains_layer_include_count) ||
          string_array_invalid(contains_layer_include_exact_value_text_utf8, contains_layer_include_count))) ||
        string_array_invalid(contains_layer_exclude_layer_stable_ids_utf8, contains_layer_exclude_count) ||
        (contains_layer_exclude_count > 0U &&
         (contains_layer_exclude_identifier_mode_ids_utf8 == nullptr ||
          contains_layer_exclude_exact_value_text_utf8 == nullptr ||
          string_array_invalid(contains_layer_exclude_identifier_mode_ids_utf8, contains_layer_exclude_count) ||
          string_array_invalid(contains_layer_exclude_exact_value_text_utf8, contains_layer_exclude_count)))) {
        return invalid_request();
    }

    const auto collect_strings = [](const char* const* values, const std::size_t count) {
        std::vector<std::string> collected {};
        collected.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            collected.push_back(values[index] != nullptr ? std::string {values[index]} : std::string {});
        }
        return collected;
    };

    const auto collect_port_rows = [](
                                       const char* const* scope_ids_utf8,
                                       const std::uint8_t* range_enabled,
                                       const char* const* primary_text_utf8,
                                       const char* const* secondary_text_utf8,
                                       const std::size_t count) {
        std::vector<pfl::FrontendAdvancedFlowFilterPortRowDto> rows {};
        rows.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            rows.push_back(pfl::FrontendAdvancedFlowFilterPortRowDto {
                .scope_id = scope_ids_utf8[index] != nullptr ? std::string {scope_ids_utf8[index]} : std::string {},
                .range_enabled = range_enabled[index] != 0U,
                .primary_text = primary_text_utf8[index] != nullptr ? std::string {primary_text_utf8[index]} : std::string {},
                .secondary_text = secondary_text_utf8[index] != nullptr ? std::string {secondary_text_utf8[index]} : std::string {},
            });
        }
        return rows;
    };

    const auto collect_ip_rows = [](
                                     const char* const* scope_ids_utf8,
                                     const std::uint8_t* subnet_enabled,
                                     const char* const* address_text_utf8,
                                     const char* const* prefix_text_utf8,
                                     const std::size_t count) {
        std::vector<pfl::FrontendAdvancedFlowFilterIpAddressRowDto> rows {};
        rows.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            rows.push_back(pfl::FrontendAdvancedFlowFilterIpAddressRowDto {
                .scope_id = scope_ids_utf8[index] != nullptr ? std::string {scope_ids_utf8[index]} : std::string {},
                .subnet_enabled = subnet_enabled[index] != 0U,
                .address_text = address_text_utf8[index] != nullptr ? std::string {address_text_utf8[index]} : std::string {},
                .prefix_text = prefix_text_utf8[index] != nullptr ? std::string {prefix_text_utf8[index]} : std::string {},
            });
        }
        return rows;
    };

    const auto collect_time_rows = [](
                                      const char* const* metric_ids_utf8,
                                      const char* const* from_text_utf8,
                                      const char* const* to_text_utf8,
                                      const std::size_t count) {
        std::vector<pfl::FrontendAdvancedFlowFilterTimeRowDto> rows {};
        rows.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            rows.push_back(pfl::FrontendAdvancedFlowFilterTimeRowDto {
                .metric_id = metric_ids_utf8[index] != nullptr ? std::string {metric_ids_utf8[index]} : std::string {},
                .from_text = from_text_utf8[index] != nullptr ? std::string {from_text_utf8[index]} : std::string {},
                .to_text = to_text_utf8[index] != nullptr ? std::string {to_text_utf8[index]} : std::string {},
            });
        }
        return rows;
    };

    const auto collect_traffic_rows = [](
                                          const char* const* metric_ids_utf8,
                                          const char* const* unit_ids_utf8,
                                          const char* const* min_text_utf8,
                                          const char* const* max_text_utf8,
                                          const std::size_t count) {
        std::vector<pfl::FrontendAdvancedFlowFilterTrafficRowDto> rows {};
        rows.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            rows.push_back(pfl::FrontendAdvancedFlowFilterTrafficRowDto {
                .metric_id = metric_ids_utf8[index] != nullptr ? std::string {metric_ids_utf8[index]} : std::string {},
                .unit_id = unit_ids_utf8[index] != nullptr ? std::string {unit_ids_utf8[index]} : std::string {},
                .min_text = min_text_utf8[index] != nullptr ? std::string {min_text_utf8[index]} : std::string {},
                .max_text = max_text_utf8[index] != nullptr ? std::string {max_text_utf8[index]} : std::string {},
            });
        }
        return rows;
    };

    const auto collect_service_rows = [](
                                         const char* const* operator_ids_utf8,
                                         const std::uint8_t* case_sensitive,
                                         const char* const* text_utf8,
                                         const std::size_t count) {
        std::vector<pfl::FrontendAdvancedFlowFilterServiceTextRowDto> rows {};
        rows.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            rows.push_back(pfl::FrontendAdvancedFlowFilterServiceTextRowDto {
                .operator_id = operator_ids_utf8[index] != nullptr ? std::string {operator_ids_utf8[index]} : std::string {},
                .case_sensitive = case_sensitive[index] != 0U,
                .text = text_utf8[index] != nullptr ? std::string {text_utf8[index]} : std::string {},
            });
        }
        return rows;
    };

    const auto collect_protocol_path_rows = [](
                                                 const char* const* selector_mode_ids_utf8,
                                                 const char* const* predicate_text_utf8,
                                                 const std::size_t count) {
        std::vector<pfl::FrontendAdvancedFlowFilterProtocolPathRowDto> rows {};
        rows.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            rows.push_back(pfl::FrontendAdvancedFlowFilterProtocolPathRowDto {
                .selector_mode_id = selector_mode_ids_utf8[index] != nullptr
                    ? std::string {selector_mode_ids_utf8[index]}
                    : std::string {},
                .predicate_text = predicate_text_utf8[index] != nullptr
                    ? std::string {predicate_text_utf8[index]}
                    : std::string {},
            });
        }
        return rows;
    };

    const auto collect_contains_layer_rows = [](
                                                   const char* const* layer_stable_ids_utf8,
                                                   const char* const* identifier_mode_ids_utf8,
                                                   const char* const* exact_value_text_utf8,
                                                   const std::size_t count) {
        std::vector<pfl::FrontendAdvancedFlowFilterContainsLayerRowDto> rows {};
        rows.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            rows.push_back(pfl::FrontendAdvancedFlowFilterContainsLayerRowDto {
                .layer_stable_id = layer_stable_ids_utf8[index] != nullptr
                    ? std::string {layer_stable_ids_utf8[index]}
                    : std::string {},
                .identifier_mode_id = identifier_mode_ids_utf8[index] != nullptr
                    ? std::string {identifier_mode_ids_utf8[index]}
                    : std::string {},
                .exact_value_text = exact_value_text_utf8[index] != nullptr
                    ? std::string {exact_value_text_utf8[index]}
                    : std::string {},
            });
        }
        return rows;
    };

    pfl::FrontendAdvancedFlowFilterStructuredDocumentDto draft {};
    draft.address_family.enabled = address_family_enabled != 0U;
    draft.address_family.include = collect_strings(address_family_include_ids_utf8, address_family_include_id_count);
    draft.address_family.exclude = collect_strings(address_family_exclude_ids_utf8, address_family_exclude_id_count);
    draft.flow_protocol.enabled = flow_protocol_enabled != 0U;
    draft.flow_protocol.include = collect_strings(flow_protocol_include_ids_utf8, flow_protocol_include_id_count);
    draft.flow_protocol.exclude = collect_strings(flow_protocol_exclude_ids_utf8, flow_protocol_exclude_id_count);
    draft.detected_protocol.enabled = detected_protocol_enabled != 0U;
    draft.detected_protocol.include = collect_strings(detected_protocol_include_ids_utf8, detected_protocol_include_id_count);
    draft.detected_protocol.exclude = collect_strings(detected_protocol_exclude_ids_utf8, detected_protocol_exclude_id_count);
    draft.tls_version.enabled = tls_version_enabled != 0U;
    draft.tls_version.include = collect_strings(tls_version_include_ids_utf8, tls_version_include_id_count);
    draft.tls_version.exclude = collect_strings(tls_version_exclude_ids_utf8, tls_version_exclude_id_count);
    draft.quic_version.enabled = quic_version_enabled != 0U;
    draft.quic_version.include = collect_strings(quic_version_include_ids_utf8, quic_version_include_id_count);
    draft.quic_version.exclude = collect_strings(quic_version_exclude_ids_utf8, quic_version_exclude_id_count);
    draft.directionality.enabled = directionality_enabled != 0U;
    draft.directionality.include = collect_strings(directionality_include_ids_utf8, directionality_include_id_count);
    draft.directionality.exclude = collect_strings(directionality_exclude_ids_utf8, directionality_exclude_id_count);
    draft.ports.enabled = ports_enabled != 0U;
    draft.ports.include = collect_port_rows(
        ports_include_scope_ids_utf8,
        ports_include_range_enabled,
        ports_include_primary_text_utf8,
        ports_include_secondary_text_utf8,
        ports_include_count
    );
    draft.ports.exclude = collect_port_rows(
        ports_exclude_scope_ids_utf8,
        ports_exclude_range_enabled,
        ports_exclude_primary_text_utf8,
        ports_exclude_secondary_text_utf8,
        ports_exclude_count
    );
    draft.ip_addresses.enabled = ip_addresses_enabled != 0U;
    draft.ip_addresses.include = collect_ip_rows(
        ip_include_scope_ids_utf8,
        ip_include_subnet_enabled,
        ip_include_address_text_utf8,
        ip_include_prefix_text_utf8,
        ip_include_count
    );
    draft.ip_addresses.exclude = collect_ip_rows(
        ip_exclude_scope_ids_utf8,
        ip_exclude_subnet_enabled,
        ip_exclude_address_text_utf8,
        ip_exclude_prefix_text_utf8,
        ip_exclude_count
    );
    draft.time.enabled = time_enabled != 0U;
    draft.time.ranges = collect_time_rows(
        time_range_metric_ids_utf8,
        time_range_from_text_utf8,
        time_range_to_text_utf8,
        time_range_count
    );
    draft.time.duration = pfl::FrontendAdvancedFlowFilterTrafficRowDto {
        .metric_id = std::string {time_duration_metric_id_utf8},
        .unit_id = std::string {time_duration_unit_id_utf8},
        .min_text = std::string {time_duration_min_text_utf8},
        .max_text = std::string {time_duration_max_text_utf8},
    };
    draft.traffic.enabled = traffic_enabled != 0U;
    draft.traffic.packet_distribution.include =
        collect_strings(packet_distribution_include_ids_utf8, packet_distribution_include_id_count);
    draft.traffic.packet_distribution.exclude =
        collect_strings(packet_distribution_exclude_ids_utf8, packet_distribution_exclude_id_count);
    draft.traffic.data_distribution.include =
        collect_strings(data_distribution_include_ids_utf8, data_distribution_include_id_count);
    draft.traffic.data_distribution.exclude =
        collect_strings(data_distribution_exclude_ids_utf8, data_distribution_exclude_id_count);
    draft.traffic.primary = collect_traffic_rows(
        traffic_primary_metric_ids_utf8,
        traffic_primary_unit_ids_utf8,
        traffic_primary_min_text_utf8,
        traffic_primary_max_text_utf8,
        traffic_primary_count
    );
    draft.traffic.directional_packets = collect_traffic_rows(
        traffic_directional_packets_metric_ids_utf8,
        traffic_directional_packets_unit_ids_utf8,
        traffic_directional_packets_min_text_utf8,
        traffic_directional_packets_max_text_utf8,
        traffic_directional_packets_count
    );
    draft.traffic.directional_original_bytes = collect_traffic_rows(
        traffic_directional_original_bytes_metric_ids_utf8,
        traffic_directional_original_bytes_unit_ids_utf8,
        traffic_directional_original_bytes_min_text_utf8,
        traffic_directional_original_bytes_max_text_utf8,
        traffic_directional_original_bytes_count
    );
    draft.traffic.additional = collect_traffic_rows(
        traffic_additional_metric_ids_utf8,
        traffic_additional_unit_ids_utf8,
        traffic_additional_min_text_utf8,
        traffic_additional_max_text_utf8,
        traffic_additional_count
    );
    draft.service.enabled = service_enabled != 0U;
    draft.service.include_recognized = service_include_recognized != 0U;
    draft.service.include_unrecognized = service_include_unrecognized != 0U;
    draft.service.include_text = collect_service_rows(
        service_include_operator_ids_utf8,
        service_include_case_sensitive,
        service_include_text_utf8,
        service_include_text_count
    );
    draft.service.exclude_recognized = service_exclude_recognized != 0U;
    draft.service.exclude_unrecognized = service_exclude_unrecognized != 0U;
    draft.service.exclude_text = collect_service_rows(
        service_exclude_operator_ids_utf8,
        service_exclude_case_sensitive,
        service_exclude_text_utf8,
        service_exclude_text_count
    );
    draft.protocol_path.enabled = protocol_path_enabled != 0U;
    draft.protocol_path.include = collect_protocol_path_rows(
        protocol_path_include_selector_mode_ids_utf8,
        protocol_path_include_predicate_text_utf8,
        protocol_path_include_count
    );
    draft.protocol_path.exclude = collect_protocol_path_rows(
        protocol_path_exclude_selector_mode_ids_utf8,
        protocol_path_exclude_predicate_text_utf8,
        protocol_path_exclude_count
    );
    draft.contains_layer.enabled = contains_layer_enabled != 0U;
    draft.contains_layer.include = collect_contains_layer_rows(
        contains_layer_include_layer_stable_ids_utf8,
        contains_layer_include_identifier_mode_ids_utf8,
        contains_layer_include_exact_value_text_utf8,
        contains_layer_include_count
    );
    draft.contains_layer.exclude = collect_contains_layer_rows(
        contains_layer_exclude_layer_stable_ids_utf8,
        contains_layer_exclude_identifier_mode_ids_utf8,
        contains_layer_exclude_exact_value_text_utf8,
        contains_layer_exclude_count
    );

    return make_c_string(structured_document_result_json(
        handle->adapter.apply_advanced_flow_filter_structured_document(
            std::string_view {filter_text_utf8},
            draft
        )
    ));
}

char* pfl_frontend_session_adapter_apply_advanced_flow_filter_document_text_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* filter_text_utf8
) {
    if (handle == nullptr || filter_text_utf8 == nullptr) {
        return make_c_string(advanced_flow_filter_document_workflow_state_json({}));
    }

    return make_c_string(advanced_flow_filter_document_workflow_state_json(
        handle->adapter.apply_advanced_flow_filter_document_text(std::string_view {filter_text_utf8})
    ));
}

char* pfl_frontend_session_adapter_accept_opened_advanced_flow_filter_document_text_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* filter_text_utf8,
    const char* source_path_utf8
) {
    if (handle == nullptr || filter_text_utf8 == nullptr || source_path_utf8 == nullptr) {
        return make_c_string(advanced_flow_filter_document_workflow_state_json({}));
    }

    return make_c_string(advanced_flow_filter_document_workflow_state_json(
        handle->adapter.accept_opened_advanced_flow_filter_document_text(
            std::string_view {filter_text_utf8},
            path_from_utf8(source_path_utf8)
        )
    ));
}

char* pfl_frontend_session_adapter_accept_saved_advanced_flow_filter_document_text_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* filter_text_utf8,
    const char* source_path_utf8
) {
    if (handle == nullptr || filter_text_utf8 == nullptr || source_path_utf8 == nullptr) {
        return make_c_string(advanced_flow_filter_document_workflow_state_json({}));
    }

    return make_c_string(advanced_flow_filter_document_workflow_state_json(
        handle->adapter.accept_saved_advanced_flow_filter_document_text(
            std::string_view {filter_text_utf8},
            path_from_utf8(source_path_utf8)
        )
    ));
}

char* pfl_frontend_session_adapter_clear_advanced_flow_filter_unsaved_changes_json(
    PflFrontendSessionAdapterHandle* handle
) {
    if (handle == nullptr) {
        return make_c_string(advanced_flow_filter_document_workflow_state_json({}));
    }

    return make_c_string(advanced_flow_filter_document_workflow_state_json(
        handle->adapter.clear_advanced_flow_filter_unsaved_changes()
    ));
}

char* pfl_frontend_session_adapter_clear_advanced_flow_filter_document_json(
    PflFrontendSessionAdapterHandle* handle
) {
    if (handle == nullptr) {
        return make_c_string(advanced_flow_filter_document_workflow_state_json({}));
    }

    return make_c_string(advanced_flow_filter_document_workflow_state_json(
        handle->adapter.clear_advanced_flow_filter_document()
    ));
}

std::size_t pfl_frontend_advanced_flow_filter_max_file_bytes() {
    return pfl::session_detail::kAdvancedFlowFilterMaxFileBytes;
}

char* pfl_frontend_session_adapter_export_protocol_path_tree_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint8_t mode,
    const char* path_utf8
) {
    if (handle == nullptr || path_utf8 == nullptr) {
        return make_c_string("{\"exported\":false,\"output_path\":\"\",\"error_text\":\"Invalid export request.\"}");
    }

    const auto statistics_mode = mode == 1U
        ? pfl::ProtocolPathStatisticsMode::identity_tree
        : (mode == 2U
            ? pfl::ProtocolPathStatisticsMode::terminal_paths
            : pfl::ProtocolPathStatisticsMode::kind_overview);
    const auto path = path_from_utf8(path_utf8);
    return make_c_string(export_protocol_path_tree_result_json(
        handle->adapter.export_protocol_path_tree(statistics_mode, path)
    ));
}

char* pfl_frontend_session_adapter_get_byte_export_formats_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string("[]");
    }

    return make_c_string(byte_export_formats_json(handle->adapter.get_byte_export_formats()));
}

char* pfl_frontend_session_adapter_export_selected_flow_packet_byte_view_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint64_t packet_index,
    const char* stable_id_utf8,
    const char* format_id_utf8,
    const char* path_utf8,
    const std::uint64_t flow_packet_index,
    const std::uint64_t loaded_packet_window_count
) {
    if (handle == nullptr) {
        return make_c_string("{\"exported\":false,\"output_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const std::string stable_id = stable_id_utf8 != nullptr ? std::string {stable_id_utf8} : std::string {};
    const std::string format_id = format_id_utf8 != nullptr ? std::string {format_id_utf8} : std::string {};
    const auto path = path_from_utf8(path_utf8);
    return make_c_string(byte_export_result_json(handle->adapter.export_selected_flow_packet_byte_view(
        packet_index,
        stable_id,
        format_id,
        path,
        flow_packet_index,
        loaded_packet_window_count
    )));
}

char* pfl_frontend_session_adapter_export_unrecognized_packet_byte_view_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint64_t packet_index,
    const char* stable_id_utf8,
    const char* format_id_utf8,
    const char* path_utf8
) {
    if (handle == nullptr) {
        return make_c_string("{\"exported\":false,\"output_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const std::string stable_id = stable_id_utf8 != nullptr ? std::string {stable_id_utf8} : std::string {};
    const std::string format_id = format_id_utf8 != nullptr ? std::string {format_id_utf8} : std::string {};
    const auto path = path_from_utf8(path_utf8);
    return make_c_string(byte_export_result_json(handle->adapter.export_unrecognized_packet_byte_view(
        packet_index,
        stable_id,
        format_id,
        path
    )));
}

char* pfl_frontend_session_adapter_export_selected_flow_stream_item_data_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::size_t max_packets_to_scan,
    const std::size_t limit,
    const std::uint64_t stream_item_index,
    const char* format_id_utf8,
    const char* path_utf8
) {
    if (handle == nullptr) {
        return make_c_string("{\"exported\":false,\"output_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const std::string format_id = format_id_utf8 != nullptr ? std::string {format_id_utf8} : std::string {};
    const auto path = path_from_utf8(path_utf8);
    return make_c_string(byte_export_result_json(handle->adapter.export_selected_flow_stream_item_data(
        max_packets_to_scan,
        limit,
        stream_item_index,
        format_id,
        path
    )));
}

char* pfl_frontend_session_adapter_update_settings_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint8_t http_use_path_as_service_hint,
    const std::uint8_t use_possible_tls_quic,
    const std::uint8_t ignore_vlan_and_mpls_layers_when_grouping_flows,
    const std::uint8_t ignore_gtpu_teids_when_grouping_inner_flows,
    const std::uint8_t show_wireshark_filter_for_selected_flow,
    const std::uint8_t validate_selected_packet_checksums
) {
    if (handle == nullptr) {
        // Keep the existing default-settings fallback here because the C ABI currently
        // returns only the settings payload, not a richer success/error result object.
        return make_c_string("{\"http_use_path_as_service_hint\":false,\"use_possible_tls_quic\":false,\"ignore_vlan_and_mpls_layers_when_grouping_flows\":false,\"ignore_gtpu_teids_when_grouping_inner_flows\":false,\"show_wireshark_filter_for_selected_flow\":true,\"validate_selected_packet_checksums\":false}");
    }

    return make_c_string(settings_json(handle->adapter.update_settings(pfl::FrontendSettingsDto {
        .http_use_path_as_service_hint = http_use_path_as_service_hint != 0U,
        .use_possible_tls_quic = use_possible_tls_quic != 0U,
        .ignore_vlan_and_mpls_layers_when_grouping_flows = ignore_vlan_and_mpls_layers_when_grouping_flows != 0U,
        .ignore_gtpu_teids_when_grouping_inner_flows = ignore_gtpu_teids_when_grouping_inner_flows != 0U,
        .show_wireshark_filter_for_selected_flow = show_wireshark_filter_for_selected_flow != 0U,
        .validate_selected_packet_checksums = validate_selected_packet_checksums != 0U,
    })));
}

char* pfl_frontend_session_adapter_export_current_flow_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
) {
    if (handle == nullptr) {
        return make_c_string("{\"exported\":false,\"output_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const auto path = path_from_utf8(path_utf8);
    return make_c_string(export_current_flow_result_json(handle->adapter.export_current_flow(path)));
}

char* pfl_frontend_session_adapter_export_selected_flows_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8,
    const std::size_t* flow_indices,
    const std::size_t flow_index_count
) {
    if (handle == nullptr) {
        return make_c_string("{\"exported\":false,\"output_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const auto path = path_from_utf8(path_utf8);

    std::vector<std::size_t> indices {};
    if (flow_indices != nullptr && flow_index_count > 0U) {
        indices.assign(flow_indices, flow_indices + flow_index_count);
    }

    return make_c_string(export_selected_flows_result_json(handle->adapter.export_selected_flows(path, indices)));
}

char* pfl_frontend_session_adapter_export_all_flows_info_csv_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
) {
    if (handle == nullptr) {
        return make_c_string("{\"exported\":false,\"output_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const auto path = path_from_utf8(path_utf8);
    return make_c_string(export_all_flows_info_csv_result_json(handle->adapter.export_all_flows_info_csv(path)));
}

char* pfl_frontend_session_adapter_export_smart_flows_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8,
    const std::size_t* flow_indices,
    const std::size_t flow_index_count,
    const std::uint8_t output_mode,
    const std::uint8_t base_mode,
    const std::uint64_t first_n_packets,
    const std::uint64_t first_m_original_bytes,
    const std::uint8_t include_last_packet,
    const std::uint8_t include_every_kth_packet_after_base,
    const std::uint64_t every_kth_packet,
    const std::size_t per_flow_buffer_budget_bytes
) {
    if (handle == nullptr) {
        return make_c_string("{\"exported\":false,\"output_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const auto path = path_from_utf8(path_utf8);

    std::vector<std::size_t> indices {};
    if (flow_indices != nullptr && flow_index_count > 0U) {
        indices.assign(flow_indices, flow_indices + flow_index_count);
    }

    const auto options = pfl::FrontendSmartExportOptions {
        .output_mode = output_mode == 1U
            ? pfl::FrontendSmartExportOutputMode::separate_file_per_flow
            : pfl::FrontendSmartExportOutputMode::single_file,
        .base_mode = base_mode == 1U
            ? pfl::FrontendSmartExportBaseMode::first_n_packets
            : (base_mode == 2U
                ? pfl::FrontendSmartExportBaseMode::first_m_original_bytes
                : pfl::FrontendSmartExportBaseMode::all_packets),
        .first_n_packets = first_n_packets,
        .first_m_original_bytes = first_m_original_bytes,
        .include_last_packet = include_last_packet != 0U,
        .include_every_kth_packet_after_base = include_every_kth_packet_after_base != 0U,
        .every_kth_packet = every_kth_packet,
        .per_flow_buffer_budget_bytes = per_flow_buffer_budget_bytes,
    };

    return make_c_string(smart_export_result_json(handle->adapter.export_smart_flows(path, indices, options)));
}

char* pfl_frontend_session_adapter_export_smart_unrecognized_packets_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8,
    const std::uint8_t base_mode,
    const std::uint64_t first_n_packets,
    const std::uint64_t first_m_original_bytes,
    const std::uint8_t include_last_packet,
    const std::uint8_t include_every_kth_packet_after_base,
    const std::uint64_t every_kth_packet
) {
    if (handle == nullptr) {
        return make_c_string("{\"exported\":false,\"output_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const auto path = path_from_utf8(path_utf8);
    const auto options = pfl::FrontendSmartExportOptions {
        .output_mode = pfl::FrontendSmartExportOutputMode::single_file,
        .base_mode = base_mode == 1U
            ? pfl::FrontendSmartExportBaseMode::first_n_packets
            : (base_mode == 2U
                ? pfl::FrontendSmartExportBaseMode::first_m_original_bytes
                : pfl::FrontendSmartExportBaseMode::all_packets),
        .first_n_packets = first_n_packets,
        .first_m_original_bytes = first_m_original_bytes,
        .include_last_packet = include_last_packet != 0U,
        .include_every_kth_packet_after_base = include_every_kth_packet_after_base != 0U,
        .every_kth_packet = every_kth_packet,
        .per_flow_buffer_budget_bytes = 0U,
    };

    return make_c_string(smart_export_result_json(handle->adapter.export_smart_unrecognized_packets(path, options)));
}

char* pfl_frontend_session_adapter_get_overview_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string(overview_json(unavailable_overview()));
    }

    return make_c_string(overview_json(handle->adapter.get_overview()));
}

char* pfl_frontend_session_adapter_get_flows_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string("[]");
    }

    return make_c_string(flows_json(handle->adapter.get_flows()));
}

char* pfl_frontend_session_adapter_select_flow_json(PflFrontendSessionAdapterHandle* handle, const std::size_t flow_index) {
    if (handle == nullptr) {
        return make_c_string(selection_json(pfl::FrontendSelectionResultDto {}));
    }

    return make_c_string(selection_json(handle->adapter.select_flow(flow_index)));
}

char* pfl_frontend_session_adapter_get_selected_flow_packets_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::size_t offset,
    const std::size_t limit
) {
    if (handle == nullptr) {
        return make_c_string(packet_result_json(unavailable_selected_flow_packets()));
    }

    return make_c_string(packet_result_json(handle->adapter.get_selected_flow_packets(offset, limit)));
}

char* pfl_frontend_session_adapter_get_unrecognized_packets_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::size_t offset,
    const std::size_t limit
) {
    if (handle == nullptr) {
        return make_c_string(unrecognized_packet_result_json(unavailable_unrecognized_packets()));
    }

    return make_c_string(unrecognized_packet_result_json(handle->adapter.get_unrecognized_packets(offset, limit)));
}

char* pfl_frontend_session_adapter_get_selected_flow_stream_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::size_t max_packets_to_scan,
    const std::size_t limit
) {
    if (handle == nullptr) {
        return make_c_string(stream_result_json(unavailable_selected_flow_stream()));
    }

    return make_c_string(stream_result_json(handle->adapter.get_selected_flow_stream(max_packets_to_scan, limit)));
}

char* pfl_frontend_session_adapter_get_selected_flow_stream_item_details_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::size_t max_packets_to_scan,
    const std::size_t limit,
    const std::uint64_t stream_item_index
) {
    if (handle == nullptr) {
        return make_c_string(stream_item_json(unavailable_stream_item(stream_item_index)));
    }

    return make_c_string(
        stream_item_json(handle->adapter.get_selected_flow_stream_item_details(
            max_packets_to_scan,
            limit,
            stream_item_index
        ))
    );
}

char* pfl_frontend_session_adapter_get_selected_flow_packet_details_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint64_t packet_index,
    const std::uint64_t flow_packet_index,
    const std::uint64_t loaded_packet_window_count
) {
    if (handle == nullptr) {
        return make_c_string(packet_details_json(unavailable_packet_details()));
    }

    return make_c_string(packet_details_json(handle->adapter.get_selected_flow_packet_details(
        packet_index,
        flow_packet_index,
        loaded_packet_window_count
    )));
}

char* pfl_frontend_session_adapter_get_selected_flow_packet_byte_view_content_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint64_t packet_index,
    const char* stable_id_utf8,
    const std::uint64_t flow_packet_index,
    const std::uint64_t loaded_packet_window_count
) {
    if (handle == nullptr) {
        return make_c_string(packet_byte_view_content_json(unavailable_packet_byte_view_content()));
    }

    const std::string stable_id = stable_id_utf8 != nullptr ? std::string {stable_id_utf8} : std::string {};
    return make_c_string(packet_byte_view_content_json(handle->adapter.get_selected_flow_packet_byte_view_content(
        packet_index,
        stable_id,
        flow_packet_index,
        loaded_packet_window_count
    )));
}

char* pfl_frontend_session_adapter_get_unrecognized_packet_details_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint64_t packet_index
) {
    if (handle == nullptr) {
        return make_c_string(packet_details_json(unavailable_packet_details()));
    }

    return make_c_string(packet_details_json(handle->adapter.get_unrecognized_packet_details(packet_index)));
}

char* pfl_frontend_session_adapter_get_unrecognized_packet_byte_view_content_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint64_t packet_index,
    const char* stable_id_utf8
) {
    if (handle == nullptr) {
        return make_c_string(packet_byte_view_content_json(unavailable_packet_byte_view_content()));
    }

    const std::string stable_id = stable_id_utf8 != nullptr ? std::string {stable_id_utf8} : std::string {};
    return make_c_string(packet_byte_view_content_json(
        handle->adapter.get_unrecognized_packet_byte_view_content(packet_index, stable_id)
    ));
}

char* pfl_frontend_session_adapter_get_selected_flow_analysis_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string(analysis_json(unavailable_selected_flow_analysis()));
    }

    return make_c_string(analysis_json(handle->adapter.get_selected_flow_analysis()));
}

char* pfl_frontend_session_adapter_export_selected_flow_analysis_sequence_csv_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
) {
    if (handle == nullptr) {
        return make_c_string("{\"exported\":false,\"output_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const auto path = path_from_utf8(path_utf8);
    return make_c_string(analysis_sequence_export_result_json(
        handle->adapter.export_selected_flow_analysis_sequence_csv(path)
    ));
}

void pfl_frontend_string_free(char* value) {
    delete[] value;
}

}
