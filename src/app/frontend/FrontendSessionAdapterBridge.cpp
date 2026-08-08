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

std::string protocol_path_stats_json(const pfl::FrontendProtocolPathStatsDto& row) {
    std::ostringstream out {};
    out << '{'
        << "\"node_id\":" << row.node_id << ','
        << "\"parent_node_id\":" << row.parent_node_id << ','
        << "\"depth\":" << row.depth << ','
        << "\"layer_text\":" << json_string(row.layer_text) << ','
        << "\"path_text\":" << json_string(row.path_text) << ','
        << "\"compact_text\":" << json_string(row.compact_text) << ','
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
    const std::filesystem::path path {std::string {path_utf8}};
    return make_c_string(export_protocol_path_tree_result_json(
        handle->adapter.export_protocol_path_tree(statistics_mode, path)
    ));
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
