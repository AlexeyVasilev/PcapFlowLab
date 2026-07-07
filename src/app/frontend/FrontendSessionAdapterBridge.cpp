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
using pfl::FrontendOpenMode;
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

std::string protocol_stats_json(const pfl::ProtocolStats& stats) {
    std::ostringstream out {};
    out << '{'
        << "\"flow_count\":" << stats.flow_count << ','
        << "\"packet_count\":" << stats.packet_count << ','
        << "\"captured_bytes\":" << stats.captured_bytes << ','
        << "\"original_bytes\":" << stats.original_bytes
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

std::string source_availability_json(const pfl::FrontendSourceAvailabilityDto& source) {
    std::ostringstream out {};
    out << '{'
        << "\"has_source_capture\":" << bool_json(source.has_source_capture) << ','
        << "\"source_capture_accessible\":" << bool_json(source.source_capture_accessible) << ','
        << "\"opened_from_index\":" << bool_json(source.opened_from_index) << ','
        << "\"partial_open\":" << bool_json(source.partial_open) << ','
        << "\"byte_backed_inspection_available\":" << bool_json(source.byte_backed_inspection_available) << ','
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

std::string smart_export_result_json(const pfl::FrontendSmartExportResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"exported\":" << bool_json(result.exported) << ','
        << "\"output_path\":" << json_string(result.output_path) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string overview_json(const pfl::FrontendOverviewDto& overview) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(overview.has_capture) << ','
        << "\"unrecognized_packet_count\":" << overview.unrecognized_packet_count << ','
        << "\"summary\":{"
        << "\"packet_count\":" << overview.summary.packet_count << ','
        << "\"flow_count\":" << overview.summary.flow_count << ','
        << "\"captured_bytes\":" << overview.captured_bytes << ','
        << "\"original_bytes\":" << overview.original_bytes << ','
        << "\"total_bytes\":" << overview.summary.total_bytes
        << "},"
        << "\"protocol_summary\":{"
        << "\"tcp\":" << protocol_stats_json(overview.protocol_summary.tcp) << ','
        << "\"udp\":" << protocol_stats_json(overview.protocol_summary.udp) << ','
        << "\"sctp\":" << protocol_stats_json(overview.protocol_summary.sctp) << ','
        << "\"other\":" << protocol_stats_json(overview.protocol_summary.other) << ','
        << "\"ipv4\":" << protocol_stats_json(overview.protocol_summary.ipv4) << ','
        << "\"ipv6\":" << protocol_stats_json(overview.protocol_summary.ipv6)
        << "},"
        << "\"quic_recognition\":{"
        << "\"total_flows\":" << overview.quic_recognition.total_flows << ','
        << "\"with_sni\":" << overview.quic_recognition.with_sni << ','
        << "\"without_sni\":" << overview.quic_recognition.without_sni << ','
        << "\"version_v1\":" << overview.quic_recognition.version_v1 << ','
        << "\"version_draft29\":" << overview.quic_recognition.version_draft29 << ','
        << "\"version_v2\":" << overview.quic_recognition.version_v2 << ','
        << "\"version_unknown\":" << overview.quic_recognition.version_unknown
        << "},"
        << "\"tls_recognition\":{"
        << "\"total_flows\":" << overview.tls_recognition.total_flows << ','
        << "\"with_sni\":" << overview.tls_recognition.with_sni << ','
        << "\"without_sni\":" << overview.tls_recognition.without_sni << ','
        << "\"version_tls12\":" << overview.tls_recognition.version_tls12 << ','
        << "\"version_tls13\":" << overview.tls_recognition.version_tls13 << ','
        << "\"version_unknown\":" << overview.tls_recognition.version_unknown
        << "},"
        << "\"protocol_hints\":[";

    for (std::size_t index = 0; index < overview.protocol_hints.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }

        const auto& row = overview.protocol_hints[index];
        out << '{'
            << "\"group\":" << json_string(row.group) << ','
            << "\"protocol_label\":" << json_string(row.protocol_label) << ','
            << "\"flow_count\":" << row.flow_count << ','
            << "\"packet_count\":" << row.packet_count << ','
            << "\"captured_bytes\":" << row.captured_bytes << ','
            << "\"original_bytes\":" << row.original_bytes
            << '}';
    }

    out << "],"
        << "\"top_endpoints\":[";

    for (std::size_t index = 0; index < overview.top_endpoints.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }

        const auto& row = overview.top_endpoints[index];
        out << '{'
            << "\"endpoint_label\":" << json_string(row.endpoint_label) << ','
            << "\"packet_count\":" << row.packet_count << ','
            << "\"total_bytes\":" << row.total_bytes
            << '}';
    }

    out << "],"
        << "\"top_ports\":[";

    for (std::size_t index = 0; index < overview.top_ports.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }

        const auto& row = overview.top_ports[index];
        out << '{'
            << "\"port\":" << row.port << ','
            << "\"packet_count\":" << row.packet_count << ','
            << "\"total_bytes\":" << row.total_bytes
            << '}';
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
            << "\"protocol_path_text\":" << json_string(flow.protocol_path_text) << ','
            << "\"protocol_path_compact_text\":" << json_string(flow.protocol_path_compact_text) << ','
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
            << "\"wireshark_display_filter\":" << json_string(flow.wireshark_display_filter) << ','
            << "\"protocol_path_badges\":[";

        for (std::size_t badge_index = 0; badge_index < flow.protocol_path_badges.size(); ++badge_index) {
            if (badge_index != 0U) {
                out << ',';
            }
            out << protocol_path_badge_json(flow.protocol_path_badges[badge_index]);
        }

        out << ']'
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
        << "\"protocol_path_text\":" << json_string(flow.protocol_path_text) << ','
        << "\"protocol_path_compact_text\":" << json_string(flow.protocol_path_compact_text) << ','
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
        << "\"wireshark_display_filter\":" << json_string(flow.wireshark_display_filter) << ','
        << "\"protocol_path_badges\":[";

    for (std::size_t badge_index = 0; badge_index < flow.protocol_path_badges.size(); ++badge_index) {
        if (badge_index != 0U) {
            out << ',';
        }
        out << protocol_path_badge_json(flow.protocol_path_badges[badge_index]);
    }

    out << ']'
        << '}';
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
            << "\"payload_length\":" << packet.payload_length << ','
            << "\"is_ip_fragmented\":" << bool_json(packet.is_ip_fragmented) << ','
            << "\"suspected_tcp_retransmission\":" << bool_json(packet.suspected_tcp_retransmission) << ','
            << "\"tcp_flags_text\":" << json_string(packet.tcp_flags_text)
            << '}';
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
        << "\"raw_preview_available\":" << bool_json(details.raw_preview_available) << ','
        << "\"raw_preview_truncated\":" << bool_json(details.raw_preview_truncated) << ','
        << "\"payload_preview_available\":" << bool_json(details.payload_preview_available) << ','
        << "\"payload_preview_truncated\":" << bool_json(details.payload_preview_truncated) << ','
        << "\"payload_preview_no_payload\":" << bool_json(details.payload_preview_no_payload) << ','
        << "\"checksum_validation_enabled\":" << bool_json(details.checksum_validation_enabled) << ','
        << "\"flow_index\":" << details.flow_index << ','
        << "\"packet_index\":" << details.packet_index << ','
        << "\"details_title\":" << json_string(details.details_title) << ','
        << "\"summary_text\":" << json_string(details.summary_text) << ','
        << "\"payload_tab_title\":" << json_string(details.payload_tab_title) << ','
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
        << "\"protocol_details_text\":" << json_string(details.protocol_details_text) << ','
        << "\"raw_preview_text\":" << json_string(details.raw_preview_text) << ','
        << "\"raw_preview_unavailable_text\":" << json_string(details.raw_preview_unavailable_text) << ','
        << "\"payload_preview_text\":" << json_string(details.payload_preview_text) << ','
        << "\"payload_preview_unavailable_text\":" << json_string(details.payload_preview_unavailable_text) << ','
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
                << "\"payload_length\":" << row.payload_length
                << '}';
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
        << "\"payload_tab_title\":" << json_string(item.payload_tab_title) << ','
        << "\"payload_preview_text\":" << json_string(item.payload_preview_text) << ','
        << "\"payload_preview_unavailable_text\":" << json_string(item.payload_preview_unavailable_text) << ','
        << "\"protocol_details_text\":" << json_string(item.protocol_details_text) << ','
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
    item.payload_tab_title = "Payload";
    item.payload_preview_unavailable_text = std::string {kAdapterUnavailableText};
    item.protocol_details_text = std::string {kAdapterUnavailableText};
    return item;
}

[[nodiscard]] pfl::FrontendPacketDetailsDto unavailable_packet_details() {
    pfl::FrontendPacketDetailsDto details {};
    details.details_title = "Packet Details";
    details.payload_tab_title = "Payload";
    details.raw_preview_unavailable_text = std::string {kAdapterUnavailableText};
    details.payload_preview_unavailable_text = std::string {kAdapterUnavailableText};
    details.unavailable_text = std::string {kAdapterUnavailableText};
    details.error_text = std::string {kAdapterUnavailableText};
    return details;
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
    const char* path_utf8,
    const std::uint8_t open_mode
) {
    if (handle == nullptr) {
        return make_c_string("{\"opened\":false,\"cancelled\":false,\"opened_from_index\":false,\"partial_open\":false,\"partial_open_warning_text\":\"\",\"has_source_capture\":false,\"source_capture_accessible\":false,\"input_path\":\"\",\"active_source_capture_path\":\"\",\"expected_source_capture_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\",\"source_availability\":{\"has_source_capture\":false,\"source_capture_accessible\":false,\"opened_from_index\":false,\"partial_open\":false,\"byte_backed_inspection_available\":false,\"active_source_capture_path\":\"\",\"expected_source_capture_path\":\"\"}}");
    }

    const auto mode = open_mode == 1U ? FrontendOpenMode::deep : FrontendOpenMode::fast;
    const auto path = path_from_utf8(path_utf8);
    return make_c_string(open_result_json(handle->adapter.open_capture(path, mode)));
}

char* pfl_frontend_session_adapter_start_open_capture_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8,
    const std::uint8_t open_mode
) {
    if (handle == nullptr) {
        return make_c_string("{\"started\":false,\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const auto mode = open_mode == 1U ? FrontendOpenMode::deep : FrontendOpenMode::fast;
    const auto path = path_from_utf8(path_utf8);
    return make_c_string(open_start_result_json(handle->adapter.start_open_capture(path, mode)));
}

char* pfl_frontend_session_adapter_poll_open_capture_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string("{\"ready\":false,\"progress\":{\"in_progress\":false,\"cancel_requested\":false,\"opening_as_index\":false,\"packets_processed\":0,\"bytes_processed\":0,\"total_bytes\":0,\"percent\":0.0,\"input_path\":\"\"},\"result\":{\"opened\":false,\"cancelled\":false,\"opened_from_index\":false,\"partial_open\":false,\"partial_open_warning_text\":\"\",\"has_source_capture\":false,\"source_capture_accessible\":false,\"input_path\":\"\",\"active_source_capture_path\":\"\",\"expected_source_capture_path\":\"\",\"error_text\":\"Adapter handle is unavailable.\",\"source_availability\":{\"has_source_capture\":false,\"source_capture_accessible\":false,\"opened_from_index\":false,\"partial_open\":false,\"byte_backed_inspection_available\":false,\"active_source_capture_path\":\"\",\"expected_source_capture_path\":\"\"}}}");
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
        return make_c_string("{\"attached\":false,\"error_text\":\"Adapter handle is unavailable.\",\"source_availability\":{\"has_source_capture\":false,\"source_capture_accessible\":false,\"opened_from_index\":false,\"partial_open\":false,\"byte_backed_inspection_available\":false,\"active_source_capture_path\":\"\",\"expected_source_capture_path\":\"\"}}");
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
        return make_c_string("{\"http_use_path_as_service_hint\":false,\"use_possible_tls_quic\":false,\"show_wireshark_filter_for_selected_flow\":true,\"validate_selected_packet_checksums\":false}");
    }

    return make_c_string(settings_json(handle->adapter.get_settings()));
}

char* pfl_frontend_session_adapter_update_settings_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint8_t http_use_path_as_service_hint,
    const std::uint8_t use_possible_tls_quic,
    const std::uint8_t show_wireshark_filter_for_selected_flow,
    const std::uint8_t validate_selected_packet_checksums
) {
    if (handle == nullptr) {
        // Keep the existing default-settings fallback here because the C ABI currently
        // returns only the settings payload, not a richer success/error result object.
        return make_c_string("{\"http_use_path_as_service_hint\":false,\"use_possible_tls_quic\":false,\"show_wireshark_filter_for_selected_flow\":true,\"validate_selected_packet_checksums\":false}");
    }

    return make_c_string(settings_json(handle->adapter.update_settings(pfl::FrontendSettingsDto {
        .http_use_path_as_service_hint = http_use_path_as_service_hint != 0U,
        .use_possible_tls_quic = use_possible_tls_quic != 0U,
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
    const std::uint64_t flow_packet_index
) {
    if (handle == nullptr) {
        return make_c_string(packet_details_json(unavailable_packet_details()));
    }

    return make_c_string(packet_details_json(handle->adapter.get_selected_flow_packet_details(packet_index, flow_packet_index)));
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
