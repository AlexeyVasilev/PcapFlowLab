#include "app/frontend/FrontendSessionAdapterBridge.h"

#include "app/frontend/FrontendSessionAdapter.h"

#include <cstring>
#include <filesystem>
#include <new>
#include <sstream>
#include <string_view>

namespace {

using pfl::FlowAddressFamily;
using pfl::FrontendOpenMode;
using pfl::FrontendSessionAdapter;

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

std::string open_result_json(const pfl::FrontendOpenResult& result) {
    std::ostringstream out {};
    out << '{'
        << "\"opened\":" << bool_json(result.opened) << ','
        << "\"opened_from_index\":" << bool_json(result.opened_from_index) << ','
        << "\"partial_open\":" << bool_json(result.partial_open) << ','
        << "\"has_source_capture\":" << bool_json(result.has_source_capture) << ','
        << "\"source_capture_accessible\":" << bool_json(result.source_capture_accessible) << ','
        << "\"input_path\":" << json_string(result.input_path) << ','
        << "\"active_source_capture_path\":" << json_string(result.active_source_capture_path) << ','
        << "\"expected_source_capture_path\":" << json_string(result.expected_source_capture_path) << ','
        << "\"error_text\":" << json_string(result.error_text)
        << '}';
    return out.str();
}

std::string overview_json(const pfl::FrontendOverviewDto& overview) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(overview.has_capture) << ','
        << "\"summary\":{"
        << "\"packet_count\":" << overview.summary.packet_count << ','
        << "\"flow_count\":" << overview.summary.flow_count << ','
        << "\"total_bytes\":" << overview.summary.total_bytes
        << "},"
        << "\"protocol_summary\":{"
        << "\"tcp\":" << protocol_stats_json(overview.protocol_summary.tcp) << ','
        << "\"udp\":" << protocol_stats_json(overview.protocol_summary.udp) << ','
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
        << '}'
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
            << "\"service_hint\":" << json_string(flow.service_hint) << ','
            << "\"has_fragmented_packets\":" << bool_json(flow.has_fragmented_packets) << ','
            << "\"fragmented_packet_count\":" << flow.fragmented_packet_count << ','
            << "\"address_a\":" << json_string(flow.address_a) << ','
            << "\"port_a\":" << flow.port_a << ','
            << "\"endpoint_a\":" << json_string(flow.endpoint_a) << ','
            << "\"address_b\":" << json_string(flow.address_b) << ','
            << "\"port_b\":" << flow.port_b << ','
            << "\"endpoint_b\":" << json_string(flow.endpoint_b) << ','
            << "\"packet_count\":" << flow.packet_count << ','
            << "\"total_bytes\":" << flow.total_bytes
            << '}';
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

std::string packet_details_json(const pfl::FrontendPacketDetailsDto& details) {
    std::ostringstream out {};
    out << '{'
        << "\"has_capture\":" << bool_json(details.has_capture) << ','
        << "\"has_selected_flow\":" << bool_json(details.has_selected_flow) << ','
        << "\"packet_found\":" << bool_json(details.packet_found) << ','
        << "\"source_capture_accessible\":" << bool_json(details.source_capture_accessible) << ','
        << "\"details_available\":" << bool_json(details.details_available) << ','
        << "\"payload_preview_available\":" << bool_json(details.payload_preview_available) << ','
        << "\"payload_preview_truncated\":" << bool_json(details.payload_preview_truncated) << ','
        << "\"flow_index\":" << details.flow_index << ','
        << "\"packet_index\":" << details.packet_index << ','
        << "\"timestamp_text\":" << json_string(details.timestamp_text) << ','
        << "\"captured_length\":" << details.captured_length << ','
        << "\"original_length\":" << details.original_length << ','
        << "\"payload_length\":" << details.payload_length << ','
        << "\"is_ip_fragmented\":" << bool_json(details.is_ip_fragmented) << ','
        << "\"tcp_flags_text\":" << json_string(details.tcp_flags_text) << ','
        << "\"link_summary_text\":" << json_string(details.link_summary_text) << ','
        << "\"network_summary_text\":" << json_string(details.network_summary_text) << ','
        << "\"transport_summary_text\":" << json_string(details.transport_summary_text) << ','
        << "\"protocol_details_text\":" << json_string(details.protocol_details_text) << ','
        << "\"payload_preview_text\":" << json_string(details.payload_preview_text) << ','
        << "\"unavailable_text\":" << json_string(details.unavailable_text) << ','
        << "\"error_text\":" << json_string(details.error_text)
        << '}';
    return out.str();
}

std::string selection_json(const bool selected) {
    return std::string {"{\"selected\":"} + bool_json(selected) + '}';
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
        return make_c_string("{\"opened\":false,\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    const auto mode = open_mode == 1U ? FrontendOpenMode::deep : FrontendOpenMode::fast;
    const auto path = path_utf8 == nullptr
        ? std::filesystem::path {}
        : std::filesystem::u8path(path_utf8);
    return make_c_string(open_result_json(handle->adapter.open_capture(path, mode)));
}

char* pfl_frontend_session_adapter_get_overview_json(PflFrontendSessionAdapterHandle* handle) {
    if (handle == nullptr) {
        return make_c_string("{\"has_capture\":false}");
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
        return make_c_string(selection_json(false));
    }

    return make_c_string(selection_json(handle->adapter.select_flow(flow_index)));
}

char* pfl_frontend_session_adapter_get_selected_flow_packets_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::size_t offset,
    const std::size_t limit
) {
    if (handle == nullptr) {
        return make_c_string("{\"has_capture\":false,\"has_selected_flow\":false,\"flow_index\":0,\"offset\":0,\"limit\":0,\"total_count\":0,\"packets\":[]}");
    }

    return make_c_string(packet_result_json(handle->adapter.get_selected_flow_packets(offset, limit)));
}

char* pfl_frontend_session_adapter_get_selected_flow_packet_details_json(
    PflFrontendSessionAdapterHandle* handle,
    const std::uint64_t packet_index
) {
    if (handle == nullptr) {
        return make_c_string("{\"has_capture\":false,\"has_selected_flow\":false,\"packet_found\":false,\"source_capture_accessible\":false,\"details_available\":false,\"payload_preview_available\":false,\"payload_preview_truncated\":false,\"flow_index\":0,\"packet_index\":0,\"timestamp_text\":\"\",\"captured_length\":0,\"original_length\":0,\"payload_length\":0,\"is_ip_fragmented\":false,\"tcp_flags_text\":\"\",\"link_summary_text\":\"\",\"network_summary_text\":\"\",\"transport_summary_text\":\"\",\"protocol_details_text\":\"\",\"payload_preview_text\":\"\",\"unavailable_text\":\"Adapter handle is unavailable.\",\"error_text\":\"Adapter handle is unavailable.\"}");
    }

    return make_c_string(packet_details_json(handle->adapter.get_selected_flow_packet_details(packet_index)));
}

void pfl_frontend_string_free(char* value) {
    delete[] value;
}

}
