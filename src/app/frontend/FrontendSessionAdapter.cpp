#include "app/frontend/FrontendSessionAdapter.h"

#include "app/session/SessionFormatting.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "core/index/CaptureIndex.h"
#include "core/services/CaptureImporter.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketPayloadService.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <map>
#include <span>
#include <sstream>
#include <set>

namespace pfl {

namespace {

constexpr std::size_t kPacketPreviewBytes = 128U;

struct AnalysisSequenceExportRow {
    std::uint64_t flow_packet_index {0};
    std::uint64_t packet_index {0};
    std::string direction_text {};
    std::string timestamp_text {};
    std::uint64_t delta_us {0};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::optional<std::uint32_t> transport_payload_length {};
    std::string tcp_flags_text {};
    std::string protocol_hint_text {};
};

CaptureImportOptions import_options_for_frontend_mode(const FrontendOpenMode mode) {
    return CaptureImportOptions {
        .mode = (mode == FrontendOpenMode::deep) ? ImportMode::deep : ImportMode::fast,
    };
}

std::string path_to_string(const std::filesystem::path& path) {
    return path.empty() ? std::string {} : path.string();
}

std::string format_protocol_hint_display(const std::string& value) {
    if (value == "possible_tls") {
        return "Possible TLS";
    }
    if (value == "possible_quic") {
        return "Possible QUIC";
    }

    std::string formatted = value;
    std::transform(formatted.begin(), formatted.end(), formatted.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return formatted;
}

FrontendProtocolHintStatsDto make_protocol_hint_stats(
    const char* group,
    const char* protocol_label,
    const ProtocolStats& stats
) {
    return FrontendProtocolHintStatsDto {
        .group = group,
        .protocol_label = protocol_label,
        .flow_count = stats.flow_count,
        .packet_count = stats.packet_count,
        .captured_bytes = stats.captured_bytes,
        .original_bytes = stats.original_bytes,
    };
}

std::vector<FrontendProtocolHintStatsDto> build_protocol_hint_stats(const CaptureProtocolSummary& summary) {
    std::vector<FrontendProtocolHintStatsDto> rows {};
    rows.reserve(13U);
    rows.push_back(make_protocol_hint_stats("Confirmed", "HTTP", summary.hint_http));
    rows.push_back(make_protocol_hint_stats("Confirmed", "TLS", summary.hint_tls));
    rows.push_back(make_protocol_hint_stats("Possible", "Possible TLS", summary.hint_possible_tls));
    rows.push_back(make_protocol_hint_stats("Confirmed", "DNS", summary.hint_dns));
    rows.push_back(make_protocol_hint_stats("Confirmed", "QUIC", summary.hint_quic));
    rows.push_back(make_protocol_hint_stats("Possible", "Possible QUIC", summary.hint_possible_quic));
    rows.push_back(make_protocol_hint_stats("Confirmed", "SSH", summary.hint_ssh));
    rows.push_back(make_protocol_hint_stats("Confirmed", "STUN", summary.hint_stun));
    rows.push_back(make_protocol_hint_stats("Confirmed", "BitTorrent", summary.hint_bittorrent));
    rows.push_back(make_protocol_hint_stats("Confirmed", "Mail protocols", summary.hint_mail_protocols));
    rows.push_back(make_protocol_hint_stats("Confirmed", "DHCP", summary.hint_dhcp));
    rows.push_back(make_protocol_hint_stats("Confirmed", "mDNS", summary.hint_mdns));
    rows.push_back(make_protocol_hint_stats("Unknown", "Unknown", summary.hint_unknown));
    return rows;
}

std::vector<FrontendTopEndpointDto> build_top_endpoints(const CaptureTopSummary& summary) {
    std::vector<FrontendTopEndpointDto> rows {};
    rows.reserve(summary.endpoints_by_bytes.size());

    for (const auto& endpoint : summary.endpoints_by_bytes) {
        rows.push_back(FrontendTopEndpointDto {
            .endpoint_label = endpoint.endpoint,
            .packet_count = endpoint.packet_count,
            .total_bytes = endpoint.total_bytes,
        });
    }

    return rows;
}

std::vector<FrontendTopPortDto> build_top_ports(const CaptureTopSummary& summary) {
    std::vector<FrontendTopPortDto> rows {};
    rows.reserve(summary.ports_by_bytes.size());

    for (const auto& port : summary.ports_by_bytes) {
        rows.push_back(FrontendTopPortDto {
            .port = port.port,
            .packet_count = port.packet_count,
            .total_bytes = port.total_bytes,
        });
    }

    return rows;
}

std::string build_wireshark_display_filter(const FlowRow& row) {
    const std::string address_term = row.family == FlowAddressFamily::ipv6 ? "ipv6.addr" : "ip.addr";

    std::string port_term {};
    if (row.protocol_text == "TCP") {
        port_term = "tcp.port";
    } else if (row.protocol_text == "UDP") {
        port_term = "udp.port";
    }

    if (address_term.empty() || port_term.empty() || row.address_a.empty() || row.address_b.empty()) {
        return {};
    }

    const auto selected_port = std::max(row.port_a, row.port_b);
    return address_term + " == " + row.address_a
        + " && " + address_term + " == " + row.address_b
        + " && " + port_term + " == " + std::to_string(selected_port);
}

std::string format_link_summary(const PacketDetails& details) {
    std::ostringstream out {};

    if (details.has_ethernet) {
        out << "Ethernet";
        if (details.has_vlan) {
            out << ", VLAN tags: " << details.vlan_tags.size();
        }
        return out.str();
    }

    if (details.has_linux_cooked) {
        return "Linux cooked capture";
    }

    if (details.has_arp) {
        return "ARP";
    }

    return {};
}

std::string format_network_summary(const PacketDetails& details) {
    std::ostringstream out {};

    if (details.has_ipv4) {
        out << "IPv4 " << session_detail::format_ipv4_address(details.ipv4.src_addr)
            << " -> " << session_detail::format_ipv4_address(details.ipv4.dst_addr);
        return out.str();
    }

    if (details.has_ipv6) {
        out << "IPv6 " << session_detail::format_ipv6_address(details.ipv6.src_addr)
            << " -> " << session_detail::format_ipv6_address(details.ipv6.dst_addr);
        return out.str();
    }

    if (const auto basic_text = session_detail::build_basic_protocol_details_text(details); basic_text.has_value()) {
        return *basic_text;
    }

    return {};
}

std::string format_transport_summary(const PacketDetails& details) {
    std::ostringstream out {};

    if (details.has_tcp) {
        out << "TCP "
            << details.tcp.src_port << " -> " << details.tcp.dst_port
            << " Flags: " << session_detail::format_tcp_flags_text(details.tcp.flags);
        return out.str();
    }

    if (details.has_udp) {
        out << "UDP "
            << details.udp.src_port << " -> " << details.udp.dst_port;
        return out.str();
    }

    if (details.has_icmp) {
        out << "ICMP type " << static_cast<unsigned>(details.icmp.type)
            << ", code " << static_cast<unsigned>(details.icmp.code);
        return out.str();
    }

    if (details.has_icmpv6) {
        out << "ICMPv6 type " << static_cast<unsigned>(details.icmpv6.type)
            << ", code " << static_cast<unsigned>(details.icmpv6.code);
        return out.str();
    }

    return {};
}

std::string packet_details_title() {
    return "Packet Details";
}

std::string packet_payload_tab_title(const PacketDetails& details) {
    if (details.has_tcp) {
        return "TCP Payload";
    }
    if (details.has_udp) {
        return "UDP Payload";
    }
    return "Payload";
}

std::string format_stream_source_packets_text(
    const StreamItemRow& row,
    const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers
) {
    std::vector<std::string> packet_numbers {};
    packet_numbers.reserve(row.packet_indices.size());

    bool used_flow_numbers = true;
    for (const auto packet_index : row.packet_indices) {
        const auto flow_it = flow_packet_numbers.find(packet_index);
        if (flow_it == flow_packet_numbers.end()) {
            used_flow_numbers = false;
            break;
        }
        packet_numbers.push_back("#" + std::to_string(flow_it->second));
    }

    if (!used_flow_numbers) {
        packet_numbers.clear();
        packet_numbers.reserve(row.packet_indices.size());
        for (const auto packet_index : row.packet_indices) {
            packet_numbers.push_back("#" + std::to_string(packet_index));
        }
    }

    if (packet_numbers.empty()) {
        return row.packet_count == 1U
            ? "1 packet"
            : std::to_string(row.packet_count) + " packets";
    }

    std::ostringstream out {};
    out << (packet_numbers.size() == 1U ? "packet " : "packets ");
    for (std::size_t index = 0; index < packet_numbers.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << packet_numbers[index];
    }

    return out.str();
}

std::pair<std::string, bool> build_payload_preview(
    const std::vector<std::uint8_t>& packet_bytes,
    const PacketRef& packet
) {
    if (packet_bytes.empty()) {
        return {};
    }

    PacketPayloadService payload_service {};
    const auto payload_bytes = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
    if (payload_bytes.empty()) {
        return {};
    }

    const auto preview_size = std::min<std::size_t>(kPacketPreviewBytes, payload_bytes.size());
    HexDumpService hex_dump_service {};
    return {
        hex_dump_service.format(std::span<const std::uint8_t>(payload_bytes.data(), preview_size)),
        payload_bytes.size() > preview_size,
    };
}

std::pair<std::string, bool> build_raw_preview(const std::vector<std::uint8_t>& packet_bytes) {
    if (packet_bytes.empty()) {
        return {};
    }

    const auto preview_size = std::min<std::size_t>(kPacketPreviewBytes, packet_bytes.size());
    HexDumpService hex_dump_service {};
    return {
        hex_dump_service.format(std::span<const std::uint8_t>(packet_bytes.data(), preview_size)),
        packet_bytes.size() > preview_size,
    };
}

std::string trim_trailing_zeros(std::string text) {
    const auto decimal_index = text.find('.');
    if (decimal_index == std::string::npos) {
        return text;
    }

    while (!text.empty() && text.back() == '0') {
        text.pop_back();
    }
    if (!text.empty() && text.back() == '.') {
        text.pop_back();
    }

    return text;
}

std::string format_rate_value(double value, const char* suffix);
std::string format_byte_rate_value(double value);
std::string format_size_value(double value);

std::string format_packet_rate_for_duration(const std::uint64_t packet_count, const std::uint64_t duration_us) {
    if (duration_us == 0U) {
        return format_rate_value(0.0, "pkt/s");
    }

    const auto packets_per_second = (static_cast<double>(packet_count) * 1'000'000.0) / static_cast<double>(duration_us);
    return format_rate_value(packets_per_second, "pkt/s");
}

std::string format_data_rate_for_duration(const std::uint64_t byte_count, const std::uint64_t duration_us) {
    if (duration_us == 0U) {
        return format_byte_rate_value(0.0);
    }

    const auto bytes_per_second = (static_cast<double>(byte_count) * 1'000'000.0) / static_cast<double>(duration_us);
    return format_byte_rate_value(bytes_per_second);
}

std::string format_average_packet_size_for_direction(const std::uint64_t byte_count, const std::uint64_t packet_count) {
    const auto average_packet_size = packet_count > 0U
        ? static_cast<double>(byte_count) / static_cast<double>(packet_count)
        : 0.0;
    return format_size_value(average_packet_size);
}

template <typename HistogramRow>
std::vector<FrontendAnalysisHistogramRowDto> build_analysis_histogram_rows(
    const std::vector<HistogramRow>& all_rows,
    const std::vector<HistogramRow>& a_to_b_rows,
    const std::vector<HistogramRow>& b_to_a_rows
) {
    std::vector<FrontendAnalysisHistogramRowDto> rows {};
    std::map<std::string, std::size_t, std::less<>> row_index_by_bucket {};

    auto ensure_row = [&](const std::string& bucket_label) -> FrontendAnalysisHistogramRowDto& {
        const auto existing = row_index_by_bucket.find(bucket_label);
        if (existing != row_index_by_bucket.end()) {
            return rows[existing->second];
        }

        row_index_by_bucket.emplace(bucket_label, rows.size());
        rows.push_back(FrontendAnalysisHistogramRowDto {.bucket_label = bucket_label});
        return rows.back();
    };

    for (const auto& row : all_rows) {
        ensure_row(row.bucket_label).count_all = row.packet_count;
    }
    for (const auto& row : a_to_b_rows) {
        ensure_row(row.bucket_label).count_a_to_b = row.packet_count;
    }
    for (const auto& row : b_to_a_rows) {
        ensure_row(row.bucket_label).count_b_to_a = row.packet_count;
    }

    return rows;
}

std::string group_integer_part(std::string text) {
    const auto decimal_index = text.find('.');
    const auto fraction = decimal_index == std::string::npos ? std::string {} : text.substr(decimal_index);
    std::string integer_part = decimal_index == std::string::npos ? std::move(text) : text.substr(0U, decimal_index);

    const bool negative = !integer_part.empty() && integer_part.front() == '-';
    if (negative) {
        integer_part.erase(integer_part.begin());
    }

    for (std::ptrdiff_t index = static_cast<std::ptrdiff_t>(integer_part.size()) - 3; index > 0; index -= 3) {
        integer_part.insert(static_cast<std::size_t>(index), " ");
    }

    if (negative) {
        integer_part.insert(integer_part.begin(), '-');
    }

    return integer_part + fraction;
}

std::string format_grouped_integer(const std::uint64_t value) {
    return group_integer_part(std::to_string(value));
}

std::string format_grouped_decimal(const double value, const int decimals) {
    std::ostringstream out {};
    out << std::fixed << std::setprecision(decimals) << value;
    return group_integer_part(trim_trailing_zeros(out.str()));
}

std::string format_duration_us(const std::uint64_t duration_us) {
    if (duration_us == 0U) {
        return "0 us";
    }

    std::ostringstream out {};
    if (duration_us < 1000U) {
        out << duration_us << " us";
        return out.str();
    }

    if (duration_us < 1000000U) {
        out << std::fixed << std::setprecision(3) << (static_cast<double>(duration_us) / 1000.0) << " ms";
        return out.str();
    }

    out << std::fixed << std::setprecision(3) << (static_cast<double>(duration_us) / 1000000.0) << " s";
    return out.str();
}

std::string format_rate_value(const double value, const char* suffix) {
    std::ostringstream out {};
    out << std::fixed << std::setprecision(3) << value << ' ' << suffix;
    return out.str();
}

std::string format_human_readable_bytes(const double value, const char* suffix = "") {
    constexpr const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    constexpr std::size_t unit_count = sizeof(units) / sizeof(units[0]);

    double scaled_value = std::max(0.0, value);
    std::size_t unit_index = 0U;
    while (scaled_value >= 1024.0 && unit_index + 1U < unit_count) {
        scaled_value /= 1024.0;
        ++unit_index;
    }

    std::string numeric_text {};
    if (unit_index == 0U) {
        const auto rounded_value = std::round(scaled_value);
        numeric_text = std::fabs(scaled_value - rounded_value) < 0.05
            ? format_grouped_integer(static_cast<std::uint64_t>(std::llround(rounded_value)))
            : format_grouped_decimal(scaled_value, 1);
    } else {
        numeric_text = format_grouped_decimal(scaled_value, 1);
    }

    return numeric_text + ' ' + units[unit_index] + suffix;
}

std::string format_byte_rate_value(const double value) {
    return format_human_readable_bytes(value, "/s");
}

std::string format_size_value(const double value) {
    return format_human_readable_bytes(value);
}

std::string format_size_value(const std::uint32_t value) {
    return format_human_readable_bytes(static_cast<double>(value));
}

std::string format_size_value(const std::uint64_t value) {
    return format_human_readable_bytes(static_cast<double>(value));
}

std::optional<FlowRow> selected_flow_row(const CaptureSession& session, const std::size_t flow_index) {
    const auto rows = session.list_flows();
    const auto it = std::find_if(rows.begin(), rows.end(), [flow_index](const FlowRow& row) {
        return row.index == flow_index;
    });
    if (it == rows.end()) {
        return std::nullopt;
    }

    return *it;
}

std::string build_analysis_endpoint_summary(const FlowRow& row) {
    std::ostringstream out {};
    out << row.address_a << ':' << row.port_a
        << " <-> "
        << row.address_b << ':' << row.port_b;
    return out.str();
}

std::uint64_t packet_timestamp_us(const PacketRef& packet) noexcept {
    return (static_cast<std::uint64_t>(packet.ts_sec) * 1'000'000ULL) + static_cast<std::uint64_t>(packet.ts_usec);
}

std::string normalize_sequence_direction(const std::string& direction_text) {
    if (direction_text == "A\xE2\x86\x92" "B") {
        return "A->B";
    }
    if (direction_text == "B\xE2\x86\x92" "A") {
        return "B->A";
    }

    return direction_text;
}

std::string escape_csv_field(const std::string& field) {
    if (field.find_first_of(",\"\r\n") == std::string::npos) {
        return field;
    }

    std::string escaped {};
    escaped.reserve(field.size() + 2U);
    escaped.push_back('"');
    for (const auto ch : field) {
        if (ch == '"') {
            escaped.push_back('"');
        }
        escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

std::optional<std::vector<AnalysisSequenceExportRow>> build_analysis_sequence_export_rows(
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::string& protocol_hint_text
) {
    const auto packet_rows = session.list_flow_packets(flow_index);
    const auto packets = session.flow_packets(flow_index);
    if (!packets.has_value() || packet_rows.size() != packets->size()) {
        return std::nullopt;
    }

    std::vector<AnalysisSequenceExportRow> rows {};
    rows.reserve(packet_rows.size());

    std::optional<std::uint64_t> previous_timestamp_us {};
    for (std::size_t index = 0; index < packet_rows.size(); ++index) {
        const auto& packet_row = packet_rows[index];
        const auto& packet = packets->at(index);
        if (packet_row.packet_index != packet.packet_index) {
            return std::nullopt;
        }

        const auto timestamp_us = packet_timestamp_us(packet);
        const auto delta_us = previous_timestamp_us.has_value() && timestamp_us >= *previous_timestamp_us
            ? timestamp_us - *previous_timestamp_us
            : 0U;

        rows.push_back(AnalysisSequenceExportRow {
            .flow_packet_index = packet_row.row_number,
            .packet_index = packet.packet_index,
            .direction_text = normalize_sequence_direction(packet_row.direction_text),
            .timestamp_text = packet_row.timestamp_text,
            .delta_us = delta_us,
            .captured_length = packet.captured_length,
            .original_length = packet.original_length,
            .transport_payload_length = session_detail::derive_transport_payload_length_from_headers(session, packet),
            .tcp_flags_text = packet_row.tcp_flags_text,
            .protocol_hint_text = protocol_hint_text,
        });

        previous_timestamp_us = timestamp_us;
    }

    return rows;
}

bool write_analysis_sequence_csv(
    const std::vector<AnalysisSequenceExportRow>& rows,
    const std::filesystem::path& output_path,
    std::string* error_text
) {
    std::ofstream stream {output_path, std::ios::binary | std::ios::trunc};
    if (!stream.is_open()) {
        if (error_text != nullptr) {
            *error_text = "Failed to open output CSV file.";
        }
        return false;
    }

    stream << "flow_packet_index,packet_index,direction,timestamp,delta_us,captured_length,original_length,transport_payload_length,tcp_flags,protocol_hint\n";
    for (const auto& row : rows) {
        stream << row.flow_packet_index << ','
               << row.packet_index << ','
               << escape_csv_field(row.direction_text) << ','
               << escape_csv_field(row.timestamp_text) << ','
               << row.delta_us << ','
               << row.captured_length << ','
               << row.original_length << ','
               << (row.transport_payload_length.has_value() ? std::to_string(*row.transport_payload_length) : std::string {}) << ','
               << escape_csv_field(row.tcp_flags_text) << ','
               << escape_csv_field(row.protocol_hint_text) << '\n';
    }

    if (!stream.good()) {
        if (error_text != nullptr) {
            *error_text = "Failed to write flow sequence CSV.";
        }
        return false;
    }

    return true;
}

}  // namespace

FrontendSourceAvailabilityDto FrontendSessionAdapter::current_source_availability() const {
    return FrontendSourceAvailabilityDto {
        .has_source_capture = session_.has_source_capture(),
        .source_capture_accessible = session_.source_capture_accessible(),
        .opened_from_index = session_.opened_from_index(),
        .partial_open = session_.is_partial_open(),
        .byte_backed_inspection_available = session_.has_source_capture() && session_.source_capture_accessible(),
        .active_source_capture_path = path_to_string(session_.attached_source_capture_path()),
        .expected_source_capture_path = path_to_string(session_.expected_source_capture_path()),
    };
}

FrontendOpenResult FrontendSessionAdapter::open_capture(
    const std::filesystem::path& path,
    const FrontendOpenMode open_mode
) {
    clear_selection();
    session_ = CaptureSession {};

    if (path.empty()) {
        return FrontendOpenResult {
            .opened = false,
            .error_text = "No file selected.",
        };
    }

    const bool opened = looks_like_index_file(path)
        ? session_.load_index(path)
        : session_.open_capture(path, import_options_for_frontend_mode(open_mode));

    const auto source_availability = current_source_availability();

    return FrontendOpenResult {
        .opened = opened,
        .opened_from_index = source_availability.opened_from_index,
        .partial_open = source_availability.partial_open,
        .has_source_capture = source_availability.has_source_capture,
        .source_capture_accessible = source_availability.source_capture_accessible,
        .input_path = path_to_string(path),
        .active_source_capture_path = source_availability.active_source_capture_path,
        .expected_source_capture_path = source_availability.expected_source_capture_path,
        .error_text = opened ? std::string {} : session_.last_open_error_text(),
        .source_availability = source_availability,
    };
}

FrontendOverviewDto FrontendSessionAdapter::get_overview() const {
    const auto protocol_summary = session_.protocol_summary();
    const auto top_summary = session_.has_capture() ? session_.top_summary() : CaptureTopSummary {};
    return FrontendOverviewDto {
        .has_capture = session_.has_capture(),
        .summary = session_.summary(),
        .captured_bytes = protocol_summary.tcp.captured_bytes + protocol_summary.udp.captured_bytes + protocol_summary.other.captured_bytes,
        .original_bytes = protocol_summary.tcp.original_bytes + protocol_summary.udp.original_bytes + protocol_summary.other.original_bytes,
        .protocol_summary = protocol_summary,
        .quic_recognition = session_.quic_recognition_stats(),
        .tls_recognition = session_.tls_recognition_stats(),
        .protocol_hints = build_protocol_hint_stats(protocol_summary),
        .top_endpoints = build_top_endpoints(top_summary),
        .top_ports = build_top_ports(top_summary),
    };
}

std::vector<FrontendFlowDto> FrontendSessionAdapter::get_flows() const {
    const auto rows = session_.list_flows();
    std::vector<FrontendFlowDto> flows {};
    flows.reserve(rows.size());

    for (const auto& row : rows) {
        flows.push_back(to_frontend_flow(row));
    }

    return flows;
}

bool FrontendSessionAdapter::select_flow(const std::size_t flow_index) {
    if (!session_.has_capture()) {
        clear_selection();
        return false;
    }

    if (flow_index >= session_.summary().flow_count) {
        return false;
    }

    selected_flow_index_ = flow_index;
    session_.clear_selected_flow_packet_cache();
    session_.clear_selected_flow_tcp_payload_suppression();
    return true;
}

FrontendSelectedFlowPacketsResult FrontendSessionAdapter::get_selected_flow_packets(
    const std::size_t offset,
    const std::size_t limit
) {
    FrontendSelectedFlowPacketsResult result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = selected_flow_index_.has_value(),
        .flow_index = selected_flow_index_.value_or(0U),
        .offset = offset,
        .limit = limit,
        .total_count = 0U,
    };

    if (!result.has_capture || !result.has_selected_flow) {
        return result;
    }

    const auto flow_index = *selected_flow_index_;
    const auto total_count = session_.flow_packet_count(flow_index);
    result.total_count = total_count;

    if (offset >= total_count || limit == 0U) {
        return result;
    }

    auto rows = session_.list_flow_packets(flow_index, offset, limit);
    if (!rows.empty()) {
        session_detail::apply_original_transport_payload_lengths(session_, rows);

        const auto scanned_packet_count = offset + rows.size();
        const auto retransmission_packet_indices = session_.suspected_tcp_retransmission_packet_indices(flow_index, scanned_packet_count);
        const auto retransmission_set = std::set<std::uint64_t>(retransmission_packet_indices.begin(), retransmission_packet_indices.end());

        for (auto& row : rows) {
            row.suspected_tcp_retransmission = retransmission_set.contains(row.packet_index);
        }
    }

    result.packets.reserve(rows.size());
    for (const auto& row : rows) {
        result.packets.push_back(to_frontend_packet(row));
    }

    return result;
}

FrontendSelectedFlowStreamResult FrontendSessionAdapter::get_selected_flow_stream(
    const std::size_t max_packets_to_scan,
    const std::size_t limit
) const {
    FrontendSelectedFlowStreamResult result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = selected_flow_index_.has_value(),
        .source_capture_accessible = session_.source_capture_accessible(),
        .stream_available = false,
        .stream_partially_loaded = false,
        .packet_window_partial = false,
        .can_load_more = false,
        .flow_index = selected_flow_index_.value_or(0U),
        .packet_window_count = 0U,
        .total_flow_packet_count = 0U,
        .requested_item_limit = limit,
        .loaded_item_count = 0U,
        .total_item_count = 0U,
        .source_availability = current_source_availability(),
    };

    if (!result.has_capture) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (!result.has_selected_flow) {
        result.error_text = "No flow is selected.";
        return result;
    }

    if (!result.source_capture_accessible) {
        result.unavailable_text =
            "Stream reconstruction requires the original source capture to be attached and readable.";
        return result;
    }

    const auto flow_index = *selected_flow_index_;
    const auto total_flow_packet_count = session_.flow_packet_count(flow_index);
    result.total_flow_packet_count = total_flow_packet_count;

    if (limit == 0U || max_packets_to_scan == 0U || total_flow_packet_count == 0U) {
        result.stream_available = true;
        return result;
    }

    result.packet_window_count = std::min(total_flow_packet_count, max_packets_to_scan);
    result.packet_window_partial = result.packet_window_count < total_flow_packet_count;

    session_.prepare_selected_flow_packet_cache(flow_index, result.packet_window_count);
    auto rows = session_.list_flow_stream_items_for_packet_prefix(flow_index, result.packet_window_count, limit + 1U);

    const bool has_more_items = rows.size() > limit;
    if (has_more_items) {
        rows.resize(limit);
    }

    result.stream_available = true;
    result.loaded_item_count = rows.size();
    result.can_load_more = result.packet_window_partial || has_more_items;
    result.stream_partially_loaded = result.can_load_more;
    result.total_item_count = result.can_load_more ? 0U : result.loaded_item_count;

    std::map<std::uint64_t, std::uint64_t> flow_packet_numbers {};
    if (const auto flow_packets = session_.flow_packets(flow_index); flow_packets.has_value()) {
        for (std::size_t index = 0; index < flow_packets->size(); ++index) {
            flow_packet_numbers.emplace((*flow_packets)[index].packet_index, static_cast<std::uint64_t>(index + 1U));
        }
    }

    result.items.reserve(rows.size());
    for (const auto& row : rows) {
        result.items.push_back(to_frontend_stream_item(row, flow_packet_numbers));
    }

    return result;
}

FrontendSelectedFlowAnalysisDto FrontendSessionAdapter::get_selected_flow_analysis() const {
    FrontendSelectedFlowAnalysisDto result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = selected_flow_index_.has_value(),
        .analysis_available = false,
        .has_tcp_control_counts = false,
        .flow_index = selected_flow_index_.value_or(0U),
    };

    if (!result.has_capture) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (!result.has_selected_flow) {
        result.error_text = "No flow is selected.";
        return result;
    }

    const auto flow_index = *selected_flow_index_;
    const auto row = selected_flow_row(session_, flow_index);
    if (!row.has_value()) {
        result.error_text = "The selected flow is unavailable.";
        return result;
    }

    const auto analysis = session_.get_flow_analysis(flow_index);
    if (!analysis.has_value()) {
        result.unavailable_text = "Analysis is unavailable for the selected flow.";
        return result;
    }

    const auto flow_packets = session_.flow_packets(flow_index);
    if (!flow_packets.has_value()) {
        result.unavailable_text = "Analysis is unavailable because the selected flow packets cannot be read.";
        return result;
    }

    std::uint64_t captured_bytes = 0U;
    for (const auto& packet : *flow_packets) {
        captured_bytes += packet.captured_length;
    }

    result.analysis_available = true;
    result.has_tcp_control_counts = analysis->has_tcp_control_counts;
    result.total_packets = analysis->total_packets;
    result.total_bytes = analysis->total_bytes;
    result.captured_bytes = captured_bytes;
    result.packets_a_to_b = analysis->packets_a_to_b;
    result.packets_b_to_a = analysis->packets_b_to_a;
    result.bytes_a_to_b = analysis->bytes_a_to_b;
    result.bytes_b_to_a = analysis->bytes_b_to_a;
    result.tcp_syn_packets = analysis->tcp_syn_packets;
    result.tcp_fin_packets = analysis->tcp_fin_packets;
    result.tcp_rst_packets = analysis->tcp_rst_packets;
    result.endpoint_summary_text = build_analysis_endpoint_summary(*row);
    result.protocol_text = row->protocol_text;
    result.protocol_hint_display = !analysis->protocol_hint.empty()
        ? format_protocol_hint_display(analysis->protocol_hint)
        : format_protocol_hint_display(row->protocol_hint);
    result.service_hint_text = !analysis->service_hint.empty()
        ? analysis->service_hint
        : (!row->service_hint.empty() ? row->service_hint : analysis->protocol_panel_service_text);
    if (!analysis->protocol_panel_version_text.empty()) {
        result.protocol_version_text = analysis->protocol_panel_version_text;
    } else if (analysis->protocol_hint == "tls" || analysis->protocol_hint == "quic") {
        result.protocol_version_text = "unknown";
    }
    if (!analysis->protocol_panel_service_text.empty()) {
        result.protocol_service_text = analysis->protocol_panel_service_text;
    } else if (analysis->protocol_hint == "tls" || analysis->protocol_hint == "quic") {
        result.protocol_service_text = !row->service_hint.empty() ? row->service_hint : "unknown";
    }
    result.protocol_fallback_text = analysis->protocol_panel_fallback_text;
    result.first_packet_time_text = analysis->first_packet_timestamp_text;
    result.last_packet_time_text = analysis->last_packet_timestamp_text;
    result.duration_text = format_duration_us(analysis->duration_us);
    result.largest_gap_text = format_duration_us(analysis->largest_gap_us);
    result.packets_considered_text = format_grouped_integer(analysis->timeline_packet_count_considered);
    result.total_packets_text = format_grouped_integer(analysis->total_packets);
    result.total_bytes_text = format_size_value(analysis->total_bytes);
    result.captured_bytes_text = format_size_value(captured_bytes);
    result.packets_a_to_b_text = format_grouped_integer(analysis->packets_a_to_b);
    result.packets_b_to_a_text = format_grouped_integer(analysis->packets_b_to_a);
    result.bytes_a_to_b_text = format_size_value(analysis->bytes_a_to_b);
    result.bytes_b_to_a_text = format_size_value(analysis->bytes_b_to_a);
    result.packet_ratio_text = analysis->packet_ratio_text;
    result.byte_ratio_text = analysis->byte_ratio_text;
    result.packet_direction_text = analysis->packet_direction_text;
    result.data_direction_text = analysis->data_direction_text;
    result.packets_per_second_text = format_rate_value(analysis->packets_per_second, "pkt/s");
    result.packets_per_second_a_to_b_text = format_packet_rate_for_duration(analysis->packets_a_to_b, analysis->duration_us);
    result.packets_per_second_b_to_a_text = format_packet_rate_for_duration(analysis->packets_b_to_a, analysis->duration_us);
    result.bytes_per_second_text = format_byte_rate_value(analysis->bytes_per_second);
    result.bytes_per_second_a_to_b_text = format_data_rate_for_duration(analysis->bytes_a_to_b, analysis->duration_us);
    result.bytes_per_second_b_to_a_text = format_data_rate_for_duration(analysis->bytes_b_to_a, analysis->duration_us);
    result.average_packet_size_text = format_size_value(analysis->average_packet_size_bytes);
    result.average_packet_size_a_to_b_text =
        format_average_packet_size_for_direction(analysis->bytes_a_to_b, analysis->packets_a_to_b);
    result.average_packet_size_b_to_a_text =
        format_average_packet_size_for_direction(analysis->bytes_b_to_a, analysis->packets_b_to_a);
    result.average_inter_arrival_text =
        format_duration_us(static_cast<std::uint64_t>(std::llround(analysis->average_inter_arrival_us)));
    result.min_packet_size_text = format_size_value(analysis->min_packet_size_bytes);
    if (analysis->packets_a_to_b > 0U) {
        result.min_packet_size_a_to_b_text = format_size_value(analysis->min_packet_size_a_to_b_bytes);
    }
    if (analysis->packets_b_to_a > 0U) {
        result.min_packet_size_b_to_a_text = format_size_value(analysis->min_packet_size_b_to_a_bytes);
    }
    result.max_packet_size_text = format_size_value(analysis->max_packet_size_bytes);
    if (analysis->packets_a_to_b > 0U) {
        result.max_packet_size_a_to_b_text = format_size_value(analysis->max_packet_size_a_to_b_bytes);
    }
    if (analysis->packets_b_to_a > 0U) {
        result.max_packet_size_b_to_a_text = format_size_value(analysis->max_packet_size_b_to_a_bytes);
    }
    result.tcp_syn_packets_text = format_grouped_integer(analysis->tcp_syn_packets);
    result.tcp_fin_packets_text = format_grouped_integer(analysis->tcp_fin_packets);
    result.tcp_rst_packets_text = format_grouped_integer(analysis->tcp_rst_packets);
    result.burst_count_text = format_grouped_integer(analysis->burst_count);
    result.longest_burst_packet_count_text = format_grouped_integer(analysis->longest_burst_packet_count);
    result.largest_burst_bytes_text = format_size_value(analysis->largest_burst_bytes);
    result.idle_gap_count_text = format_grouped_integer(analysis->idle_gap_count);
    result.largest_idle_gap_text = format_duration_us(analysis->largest_idle_gap_us);
    result.inter_arrival_histogram_rows = build_analysis_histogram_rows(
        analysis->inter_arrival_histograms.histogram_all,
        analysis->inter_arrival_histograms.histogram_a_to_b,
        analysis->inter_arrival_histograms.histogram_b_to_a
    );
    result.packet_size_histogram_rows = build_analysis_histogram_rows(
        analysis->packet_size_histograms.histogram_all,
        analysis->packet_size_histograms.histogram_a_to_b,
        analysis->packet_size_histograms.histogram_b_to_a
    );
    result.sequence_preview_rows.reserve(analysis->sequence_preview_rows.size());
    for (const auto& row_preview : analysis->sequence_preview_rows) {
        result.sequence_preview_rows.push_back(FrontendAnalysisSequencePreviewRowDto {
            .flow_packet_number = row_preview.flow_packet_number,
            .direction_text = row_preview.direction_text,
            .delta_time_text = format_duration_us(row_preview.delta_time_us),
            .timestamp_text = row_preview.timestamp_text,
            .captured_length = row_preview.captured_length,
            .original_length = row_preview.original_length,
            .payload_length = row_preview.payload_length,
        });
    }

    return result;
}

FrontendAnalysisSequenceExportResultDto FrontendSessionAdapter::export_selected_flow_analysis_sequence_csv(
    const std::filesystem::path& output_path
) const {
    FrontendAnalysisSequenceExportResultDto result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (!selected_flow_index_.has_value()) {
        result.error_text = "No flow selected for sequence export.";
        return result;
    }

    if (output_path.empty()) {
        result.error_text = "No output file selected.";
        return result;
    }

    const auto flow_index = *selected_flow_index_;
    const auto row = selected_flow_row(session_, flow_index);
    if (!row.has_value()) {
        result.error_text = "The selected flow is unavailable.";
        return result;
    }

    const auto protocol_hint_text = format_protocol_hint_display(row->protocol_hint);
    const auto rows = build_analysis_sequence_export_rows(session_, flow_index, protocol_hint_text);
    if (!rows.has_value()) {
        result.error_text = "Failed to prepare flow sequence export.";
        return result;
    }

    std::string write_error_text {};
    if (!write_analysis_sequence_csv(*rows, output_path, &write_error_text)) {
        result.error_text = write_error_text.empty() ? "Failed to write flow sequence CSV." : write_error_text;
        return result;
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendPacketDetailsDto FrontendSessionAdapter::get_selected_flow_packet_details(const std::uint64_t packet_index) const {
    FrontendPacketDetailsDto result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = selected_flow_index_.has_value(),
        .packet_found = false,
        .source_capture_accessible = session_.source_capture_accessible(),
        .details_available = false,
        .raw_preview_available = false,
        .raw_preview_truncated = false,
        .payload_preview_available = false,
        .payload_preview_truncated = false,
        .payload_preview_no_payload = false,
        .flow_index = selected_flow_index_.value_or(0U),
        .packet_index = packet_index,
        .details_title = packet_details_title(),
        .payload_tab_title = "Payload",
        .source_availability = current_source_availability(),
    };

    if (!result.has_capture) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (!result.has_selected_flow) {
        result.error_text = "No flow is selected.";
        return result;
    }

    const auto flow_packets = session_.flow_packets(*selected_flow_index_);
    if (!flow_packets.has_value()) {
        result.error_text = "The selected flow is unavailable.";
        return result;
    }

    const auto packet_it = std::find_if(flow_packets->begin(), flow_packets->end(), [&](const PacketRef& packet) {
        return packet.packet_index == packet_index;
    });
    if (packet_it == flow_packets->end()) {
        result.error_text = "The selected packet is unavailable in the active flow context.";
        return result;
    }

    const auto& packet = *packet_it;
    result.packet_found = true;
    result.timestamp_text = session_detail::format_packet_timestamp_full(packet);
    result.captured_length = packet.captured_length;
    result.original_length = packet.original_length;
    result.payload_length = packet.payload_length;
    result.is_ip_fragmented = packet.is_ip_fragmented;
    result.tcp_flags_text = session_detail::format_tcp_flags_text(packet.tcp_flags);

    if (!result.source_capture_accessible) {
        result.unavailable_text =
            "Byte-backed packet details are unavailable because the original source capture cannot be read.";
        result.raw_preview_unavailable_text = result.unavailable_text;
        result.payload_preview_unavailable_text = result.unavailable_text;
        return result;
    }

    const auto details = session_.read_packet_details(packet);
    if (!details.has_value()) {
        result.unavailable_text = "Packet details are unavailable for this packet.";
        return result;
    }

    result.details_available = true;
    result.payload_tab_title = packet_payload_tab_title(*details);
    result.link_summary_text = format_link_summary(*details);
    result.network_summary_text = format_network_summary(*details);
    result.transport_summary_text = format_transport_summary(*details);
    result.protocol_details_text = session_.read_packet_protocol_details_text(packet);

    const auto packet_bytes = session_.read_packet_data(packet);
    const auto [raw_preview_text, raw_preview_truncated] = build_raw_preview(packet_bytes);
    result.raw_preview_text = raw_preview_text;
    result.raw_preview_truncated = raw_preview_truncated;
    result.raw_preview_available = !raw_preview_text.empty();
    result.raw_preview_unavailable_text = result.raw_preview_available
        ? std::string {}
        : "Raw packet preview is unavailable for this packet.";

    const auto [payload_preview_text, payload_preview_truncated] = build_payload_preview(packet_bytes, packet);
    result.payload_preview_text = payload_preview_text;
    result.payload_preview_truncated = payload_preview_truncated;
    result.payload_preview_available = !payload_preview_text.empty();
    result.payload_preview_no_payload =
        !result.payload_preview_available && (details->has_tcp || details->has_udp) && packet.payload_length == 0U;
    result.payload_preview_unavailable_text = result.payload_preview_available
        ? std::string {}
        : (result.payload_preview_no_payload
            ? "No transport payload is available for this packet."
            : "Transport payload preview is not available for this packet.");

    if (!result.payload_preview_available) {
        result.unavailable_text = result.payload_preview_unavailable_text;
    }

    return result;
}

bool FrontendSessionAdapter::has_capture() const noexcept {
    return session_.has_capture();
}

std::optional<std::size_t> FrontendSessionAdapter::selected_flow_index() const noexcept {
    return selected_flow_index_;
}

void FrontendSessionAdapter::clear_selection() noexcept {
    selected_flow_index_.reset();
    session_.clear_selected_flow_packet_cache();
    session_.clear_selected_flow_tcp_payload_suppression();
}

FrontendFlowDto FrontendSessionAdapter::to_frontend_flow(const FlowRow& row) {
    return FrontendFlowDto {
        .flow_index = row.index,
        .family = row.family,
        .protocol_text = row.protocol_text,
        .protocol_hint = row.protocol_hint,
        .protocol_hint_display = format_protocol_hint_display(row.protocol_hint),
        .service_hint = row.service_hint,
        .has_fragmented_packets = row.has_fragmented_packets,
        .fragmented_packet_count = row.fragmented_packet_count,
        .address_a = row.address_a,
        .port_a = row.port_a,
        .endpoint_a = row.endpoint_a,
        .address_b = row.address_b,
        .port_b = row.port_b,
        .endpoint_b = row.endpoint_b,
        .packet_count = row.packet_count,
        .total_bytes = row.total_bytes,
        .wireshark_display_filter = build_wireshark_display_filter(row),
    };
}

FrontendPacketDto FrontendSessionAdapter::to_frontend_packet(const PacketRow& row) {
    return FrontendPacketDto {
        .row_number = row.row_number,
        .packet_index = row.packet_index,
        .direction_text = row.direction_text,
        .timestamp_text = row.timestamp_text,
        .captured_length = row.captured_length,
        .original_length = row.original_length,
        .payload_length = row.payload_length,
        .is_ip_fragmented = row.is_ip_fragmented,
        .suspected_tcp_retransmission = row.suspected_tcp_retransmission,
        .tcp_flags_text = row.tcp_flags_text,
    };
}

FrontendStreamItemDto FrontendSessionAdapter::to_frontend_stream_item(
    const StreamItemRow& row,
    const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers
) const {
    return FrontendStreamItemDto {
        .stream_item_index = row.stream_item_index,
        .direction_text = row.direction_text,
        .label = row.label,
        .byte_count = row.byte_count,
        .packet_count = row.packet_count,
        .source_packet_indices = row.packet_indices,
        .source_packets_text = format_stream_source_packets_text(row, flow_packet_numbers),
        .has_constricted_contribution = row.has_constricted_contribution,
        .constricted_contribution_notes = row.constricted_contribution_notes,
        .constricted_packet_notes = row.constricted_packet_notes,
    };
}

}  // namespace pfl
