#include "app/frontend/FrontendSessionAdapter.h"

#include "app/session/ProtocolPathPresentation.h"
#include "app/session/SessionFormatting.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "core/decode/PacketDecodeSupport.h"
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

enum class ChecksumValidationStatus {
    valid,
    invalid,
    unavailable,
    not_checked,
};

struct ChecksumValidationResult {
    ChecksumValidationStatus status {ChecksumValidationStatus::unavailable};
    std::string note {};
};

struct PacketChecksumSections {
    std::vector<std::string> summary_lines {};
    std::vector<std::string> warnings {};
};

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

CaptureImportOptions import_options_for_frontend_mode(const FrontendOpenMode mode, const AnalysisSettings& settings) {
    return CaptureImportOptions {
        .mode = (mode == FrontendOpenMode::deep) ? ImportMode::deep : ImportMode::fast,
        .settings = settings,
    };
}

std::string path_to_string(const std::filesystem::path& path) {
    return path.empty() ? std::string {} : path.string();
}

std::optional<SmartPacketRetentionOptions> build_smart_packet_retention_options(
    const FrontendSmartExportOptions& options,
    std::string& error_text
) {
    SmartPacketRetentionOptions retention {};

    switch (options.base_mode) {
    case FrontendSmartExportBaseMode::all_packets:
        retention.base_mode = SmartFlowExportBaseMode::all_packets;
        break;
    case FrontendSmartExportBaseMode::first_n_packets:
        if (options.first_n_packets == 0U) {
            error_text = "Enter a positive packet count for smart export.";
            return std::nullopt;
        }
        retention.base_mode = SmartFlowExportBaseMode::first_n_packets;
        retention.first_n_packets = options.first_n_packets;
        break;
    case FrontendSmartExportBaseMode::first_m_original_bytes:
        if (options.first_m_original_bytes == 0U) {
            error_text = "Enter a positive original-byte limit for smart export.";
            return std::nullopt;
        }
        retention.base_mode = SmartFlowExportBaseMode::first_m_original_bytes;
        retention.first_m_original_bytes = options.first_m_original_bytes;
        break;
    }

    if (retention.base_mode != SmartFlowExportBaseMode::all_packets) {
        retention.include_last_packet = options.include_last_packet;
        retention.include_every_kth_packet_after_base = options.include_every_kth_packet_after_base;
        if (retention.include_every_kth_packet_after_base) {
            if (options.every_kth_packet == 0U) {
                error_text = "Enter a positive K value for sparse smart export retention.";
                return std::nullopt;
            }
            retention.every_kth_packet = options.every_kth_packet;
        }
    }

    return retention;
}

std::map<std::uint64_t, std::uint64_t> build_bounded_flow_packet_numbers(
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::size_t packet_window_count,
    const std::vector<StreamItemRow>& rows
) {
    std::set<std::uint64_t> needed_packet_indices {};
    for (const auto& row : rows) {
        needed_packet_indices.insert(row.packet_indices.begin(), row.packet_indices.end());
    }

    std::map<std::uint64_t, std::uint64_t> flow_packet_numbers {};
    for (const auto packet_index : needed_packet_indices) {
        if (const auto packet_number = session.selected_flow_cached_packet_number(flow_index, packet_index);
            packet_number.has_value()) {
            flow_packet_numbers.emplace(packet_index, *packet_number);
        }
    }

    if (flow_packet_numbers.size() == needed_packet_indices.size() || packet_window_count == 0U) {
        return flow_packet_numbers;
    }

    const auto bounded_packet_rows = session.list_flow_packets(flow_index, 0U, packet_window_count);
    for (const auto& row : bounded_packet_rows) {
        if (!needed_packet_indices.contains(row.packet_index)) {
            continue;
        }
        flow_packet_numbers.emplace(row.packet_index, row.row_number);
    }

    return flow_packet_numbers;
}

std::string format_partial_open_warning_message(const OpenFailureInfo& failure) {
    std::string message = "Capture opened partially.";

    if (failure.has_file_offset || failure.has_packet_index || !failure.reason.empty()) {
        message += " Import stopped";
        if (failure.has_file_offset) {
            message += " at offset " + std::to_string(failure.file_offset);
        }
        if (failure.has_packet_index) {
            message += failure.has_file_offset
                ? " (packet " + std::to_string(failure.packet_index) + ')'
                : " at packet " + std::to_string(failure.packet_index);
        }
        if (!failure.reason.empty()) {
            message += ": " + failure.reason;
        }
        message += '.';
    }

    message += " Results are incomplete.";
    return message;
}

std::string format_protocol_hint_display(const std::string& value) {
    if (value == "possible_tls") {
        return "Possible TLS";
    }
    if (value == "possible_quic") {
        return "Possible QUIC";
    }
    if (value == "igmp") {
        return "IGMP";
    }
    if (value == "igmpv1") {
        return "IGMPv1";
    }
    if (value == "igmpv2") {
        return "IGMPv2";
    }
    if (value == "igmpv3") {
        return "IGMPv3";
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

std::vector<FrontendProtocolPathStatsDto> build_protocol_path_statistics(const CaptureProtocolPathSummary& summary) {
    std::vector<FrontendProtocolPathStatsDto> rows {};
    rows.reserve(summary.rows.size());

    for (const auto& row : summary.rows) {
        rows.push_back(FrontendProtocolPathStatsDto {
            .depth = row.depth,
            .path_text = row.path_text,
            .compact_text = row.compact_text,
            .badges = row.badges,
            .flow_count = row.flow_count,
            .packet_count = row.packet_count,
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
    } else if (row.protocol_text == "SCTP") {
        port_term = "sctp.port";
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

std::string format_hex16_value(const std::uint16_t value) {
    std::ostringstream out {};
    out << "0x" << std::hex << std::nouppercase << std::setw(4) << std::setfill('0') << value;
    return out.str();
}

std::string format_protocol_value(const std::uint8_t protocol) {
    switch (protocol) {
    case detail::kIpProtocolIcmp:
        return "ICMP";
    case detail::kIpProtocolIgmp:
        return "IGMP";
    case detail::kIpProtocolTcp:
        return "TCP";
    case detail::kIpProtocolUdp:
        return "UDP";
    case detail::kIpProtocolIcmpV6:
        return "ICMPv6";
    default:
        return std::to_string(protocol);
    }
}

void append_summary_section(
    std::vector<std::string>& lines,
    const std::string& title,
    const std::vector<std::string>& section_lines
) {
    if (section_lines.empty()) {
        return;
    }

    if (!lines.empty()) {
        lines.push_back({});
    }

    lines.push_back(title);
    for (const auto& line : section_lines) {
        lines.push_back("  " + line);
    }
}

std::string build_frontend_packet_summary_text(
    const PacketRef& packet,
    const std::optional<PacketDetails>& details,
    const PacketChecksumSections& checksum_sections,
    const bool source_capture_accessible
) {
    std::vector<std::string> lines {};
    const auto packet_number_in_file = packet.packet_index + 1U;

    append_summary_section(lines, "Packet", {
        "Packet number in file: " + std::to_string(packet_number_in_file),
        "Time: " + session_detail::format_packet_timestamp_full(packet),
        "Captured Length: " + std::to_string(packet.captured_length),
        "Original Length: " + std::to_string(packet.original_length),
    });

    std::vector<std::string> warnings {};
    if (packet.is_ip_fragmented) {
        warnings.push_back("Packet is IP-fragmented");
    }
    if (packet.captured_length != packet.original_length) {
        warnings.push_back("Packet is truncated in capture");
        warnings.push_back("Captured Length: " + std::to_string(packet.captured_length));
        warnings.push_back("Original Length: " + std::to_string(packet.original_length));
    }
    if (!source_capture_accessible) {
        warnings.push_back("Byte-backed packet details are unavailable because the original source capture cannot be read.");
    }
    warnings.insert(warnings.end(), checksum_sections.warnings.begin(), checksum_sections.warnings.end());
    append_summary_section(lines, "Warnings", warnings);
    append_summary_section(lines, "Checksums", checksum_sections.summary_lines);

    if (!details.has_value()) {
        std::ostringstream out {};
        for (std::size_t index = 0; index < lines.size(); ++index) {
            if (index != 0U) {
                out << '\n';
            }
            out << lines[index];
        }
        return out.str();
    }

    if (details->has_ethernet) {
        append_summary_section(lines, "Ethernet", {
            "EtherType: " + format_hex16_value(details->ethernet.ether_type),
        });
    }

    append_summary_section(lines, "ARP", session_detail::build_basic_summary_lines(*details));

    if (details->has_ipv4) {
        append_summary_section(lines, "IPv4", {
            "Source: " + session_detail::format_ipv4_address(details->ipv4.src_addr),
            "Destination: " + session_detail::format_ipv4_address(details->ipv4.dst_addr),
            "Protocol: " + format_protocol_value(details->ipv4.protocol),
        });
    }

    if (details->has_ipv6) {
        append_summary_section(lines, "IPv6", {
            "Source: " + session_detail::format_ipv6_address(details->ipv6.src_addr),
            "Destination: " + session_detail::format_ipv6_address(details->ipv6.dst_addr),
            "Next Header: " + format_protocol_value(details->ipv6.next_header),
        });
    }

    if (details->has_tcp) {
        auto tcp_lines = std::vector<std::string> {
            "Source Port: " + std::to_string(details->tcp.src_port),
            "Destination Port: " + std::to_string(details->tcp.dst_port),
            "Flags: " + session_detail::format_tcp_flags_text(details->tcp.flags),
            "Payload Length: " + std::to_string(packet.payload_length),
        };
        append_summary_section(lines, "TCP", tcp_lines);
    }

    if (details->has_udp) {
        auto udp_lines = std::vector<std::string> {
            "Source Port: " + std::to_string(details->udp.src_port),
            "Destination Port: " + std::to_string(details->udp.dst_port),
            "Payload Length: " + std::to_string(packet.payload_length),
        };
        append_summary_section(lines, "UDP", udp_lines);
    }

    if (details->has_icmp) {
        append_summary_section(lines, "ICMP", {
            "Type: " + std::to_string(details->icmp.type),
            "Code: " + std::to_string(details->icmp.code),
        });
    }

    if (details->has_icmpv6) {
        append_summary_section(lines, "ICMPv6", {
            "Type: " + std::to_string(details->icmpv6.type),
            "Code: " + std::to_string(details->icmpv6.code),
        });
    }

    std::ostringstream out {};
    for (std::size_t index = 0; index < lines.size(); ++index) {
        if (index != 0U) {
            out << '\n';
        }
        out << lines[index];
    }
    return out.str();
}

std::string packet_payload_tab_title(const PacketDetails& details) {
    return session_detail::packet_payload_tab_title(details);
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

bool stream_item_uses_packet_fallback(const StreamItemRow& row) {
    return row.payload_hex_text.empty() && row.protocol_text.empty() && row.packet_indices.size() == 1U;
}

std::string stream_item_details_source_text(const StreamItemRow& row) {
    return stream_item_uses_packet_fallback(row)
        ? "Packet fallback"
        : "Stream item";
}

std::string stream_item_frames_hint_text(const StreamItemRow& row) {
    if (row.protocol_text.empty()) {
        return {};
    }

    std::vector<std::string> hints {};
    auto extract_line_value = [&](const std::string& marker) -> std::string {
        const auto marker_index = row.protocol_text.find(marker);
        if (marker_index == std::string::npos) {
            return {};
        }

        const auto line_start = marker_index + marker.size();
        const auto line_end = row.protocol_text.find('\n', line_start);
        auto value = row.protocol_text.substr(
            line_start,
            line_end == std::string::npos ? std::string::npos : (line_end - line_start)
        );
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
            value.erase(value.begin());
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
            value.pop_back();
        }
        return value;
    };

    auto append_normalized_values = [&](const std::string& value) {
        std::stringstream stream {value};
        std::string part {};
        while (std::getline(stream, part, ',')) {
            while (!part.empty() && std::isspace(static_cast<unsigned char>(part.front())) != 0) {
                part.erase(part.begin());
            }
            while (!part.empty() && std::isspace(static_cast<unsigned char>(part.back())) != 0) {
                part.pop_back();
            }
            if (part == "Protected Payload") {
                part = "Protected payload";
            }
            if (part.empty() || part == "Packet Type: Initial" || part == "Initial") {
                continue;
            }
            if (std::find(hints.begin(), hints.end(), part) == hints.end()) {
                hints.push_back(part);
            }
        }
    };

    append_normalized_values(extract_line_value("Frame Presence:"));
    append_normalized_values(extract_line_value("Packet Type:"));
    append_normalized_values(extract_line_value("Additional Packet Types:"));

    if (hints.empty()) {
        return {};
    }

    std::ostringstream out {};
    out << "Frames: ";
    for (std::size_t index = 0; index < hints.size(); ++index) {
        if (index != 0U) {
            out << ", ";
        }
        out << hints[index];
    }
    return out.str();
}

std::string stream_item_header_secondary_text(
    const StreamItemRow& row,
    const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers
) {
    std::ostringstream out {};
    out << row.byte_count << " bytes"
        << " \xE2\x80\xA2 "
        << format_stream_source_packets_text(row, flow_packet_numbers);
    return out.str();
}

std::string stream_item_header_badge_text(const StreamItemRow& row) {
    if (row.has_constricted_contribution) {
        return "Constricted";
    }

    std::string lower_label = row.label;
    std::transform(lower_label.begin(), lower_label.end(), lower_label.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (lower_label.find("partial") != std::string::npos) {
        return "Partial";
    }
    if (stream_item_uses_packet_fallback(row)) {
        return "Packet fallback";
    }
    if (row.packet_count > 1U) {
        return "Reassembled";
    }
    return {};
}

std::string stream_item_payload_tab_title(const StreamItemRow& row) {
    if (row.protocol_text.rfind("Protocol: ARP", 0) == 0) {
        return "ARP Payload";
    }

    if (row.label.rfind("QUIC ", 0) == 0 ||
        row.label == "QUIC Initial: ACK" ||
        row.label == "QUIC Initial: CRYPTO" ||
        row.label == "ACK" ||
        row.label == "CRYPTO" ||
        row.label == "0-RTT" ||
        row.label == "Handshake" ||
        row.label == "Protected payload" ||
        row.protocol_text.rfind("QUIC", 0) == 0) {
        return "UDP Payload";
    }

    if (row.label.rfind("TLS ", 0) == 0 ||
        row.label.rfind("HTTP ", 0) == 0 ||
        row.label == "HTTP Request" ||
        row.label == "HTTP Response" ||
        row.protocol_text.rfind("TLS", 0) == 0 ||
        row.protocol_text.rfind("HTTP", 0) == 0) {
        return "Item Payload";
    }

    return "Payload";
}

std::string stream_payload_unavailable_text() {
    return "Payload is not available for this stream item.";
}

std::string stream_protocol_unavailable_text() {
    return "Protocol details are not available for this stream item.";
}

std::string build_stream_item_summary_text(
    const StreamItemRow& row,
    const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers
) {
    const auto source_packets = format_stream_source_packets_text(row, flow_packet_numbers);
    const auto source_packets_line = source_packets.rfind("packet ", 0) == 0
        ? "Source packet: " + source_packets.substr(7)
        : (source_packets.rfind("packets ", 0) == 0
            ? "Source packets: " + source_packets.substr(8)
            : "Source packets: " + source_packets);

    if (!row.summary_text.empty()) {
        std::vector<std::string> lines {
            row.summary_text,
            {},
            "Stream item: #" + std::to_string(row.stream_item_index),
            "Direction: " + row.direction_text,
            source_packets_line,
        };

        std::ostringstream out {};
        for (std::size_t index = 0; index < lines.size(); ++index) {
            if (index != 0U) {
                out << '\n';
            }
            out << lines[index];
        }
        return out.str();
    }

    std::vector<std::string> lines {
        "Label: " + row.label,
        "Size: " + std::to_string(row.byte_count) + " bytes",
        source_packets_line,
        "Details source: " + stream_item_details_source_text(row),
    };

    if (const auto frames_hint = stream_item_frames_hint_text(row); !frames_hint.empty()) {
        lines.insert(lines.begin() + 2, frames_hint);
    }

    if (!row.constricted_contribution_notes.empty()) {
        lines.push_back({});
        if (row.constricted_contribution_notes.size() == 1U) {
            lines.push_back("Constricted contribution: " + row.constricted_contribution_notes.front());
        } else {
            lines.push_back("Constricted contributions:");
            for (const auto& note : row.constricted_contribution_notes) {
                lines.push_back(note);
            }
        }
    }

    if (!row.constricted_packet_notes.empty()) {
        lines.push_back({});
        for (const auto& note : row.constricted_packet_notes) {
            lines.push_back(note);
        }
    }

    std::ostringstream out {};
    for (std::size_t index = 0; index < lines.size(); ++index) {
        if (index != 0U) {
            out << '\n';
        }
        out << lines[index];
    }
    return out.str();
}

std::string frontend_stream_payload_text(const CaptureSession& session, const StreamItemRow& row) {
    if (!row.payload_hex_text.empty()) {
        return row.payload_hex_text;
    }

    if (row.packet_indices.size() == 1U) {
        if (const auto packet = session.find_packet(row.packet_indices.front()); packet.has_value()) {
            return session.read_packet_payload_hex_dump(*packet);
        }
    }

    return {};
}

std::string frontend_stream_protocol_text(
    const CaptureSession& session,
    const std::size_t flow_index,
    const StreamItemRow& row
) {
    if (!row.protocol_text.empty()) {
        if (row.protocol_text.find("QUIC") != std::string::npos) {
            if (const auto context_text = session.derive_quic_protocol_text_for_packet_context(flow_index, row.packet_indices);
                context_text.has_value() && !context_text->empty()) {
                return *context_text;
            }
        }
        return row.protocol_text;
    }

    if (row.packet_indices.size() == 1U) {
        if (const auto packet = session.find_packet(row.packet_indices.front()); packet.has_value()) {
            auto protocol_text = session.read_packet_protocol_details_text(*packet);
            if (protocol_text.find("QUIC") != std::string::npos) {
                if (const auto context_text = session.derive_quic_protocol_text_for_packet(flow_index, packet->packet_index);
                    context_text.has_value() && !context_text->empty()) {
                    protocol_text = *context_text;
                }
            }
            return protocol_text.empty() ? stream_protocol_unavailable_text() : protocol_text;
        }
    }

    return stream_protocol_unavailable_text();
}

std::string frontend_packet_protocol_text(
    const CaptureSession& session,
    const std::optional<std::size_t> flow_index,
    const PacketRef& packet
) {
    auto protocol_text = session.read_packet_protocol_details_text(packet);
    if (!flow_index.has_value() || protocol_text.find("QUIC") == std::string::npos) {
        return protocol_text;
    }

    if (const auto context_text = session.derive_quic_protocol_text_for_packet(*flow_index, packet.packet_index);
        context_text.has_value() && !context_text->empty()) {
        return *context_text;
    }

    return protocol_text;
}

std::string build_packet_payload_text(
    const std::vector<std::uint8_t>& packet_bytes,
    const PacketRef& packet
) {
    if (packet_bytes.empty()) {
        return {};
    }

    PacketPayloadService payload_service {};
    const auto payload_bytes = payload_service.extract_packet_details_payload(packet_bytes, packet.data_link_type);
    if (payload_bytes.empty()) {
        return {};
    }

    HexDumpService hex_dump_service {};
    return hex_dump_service.format(std::span<const std::uint8_t>(payload_bytes.data(), payload_bytes.size()));
}

std::string build_packet_raw_text(const std::vector<std::uint8_t>& packet_bytes) {
    if (packet_bytes.empty()) {
        return {};
    }

    HexDumpService hex_dump_service {};
    return hex_dump_service.format(std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()));
}

std::string checksum_status_text(const ChecksumValidationStatus status) {
    switch (status) {
    case ChecksumValidationStatus::valid:
        return "valid";
    case ChecksumValidationStatus::invalid:
        return "invalid";
    case ChecksumValidationStatus::unavailable:
        return "unavailable";
    case ChecksumValidationStatus::not_checked:
        return "not checked";
    }

    return "unavailable";
}

void append_be16_bytes(std::vector<std::uint8_t>& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_be32_bytes(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::uint16_t compute_internet_checksum(std::span<const std::uint8_t> bytes) {
    std::uint32_t sum = 0U;
    std::size_t index = 0U;
    while (index + 1U < bytes.size()) {
        sum += static_cast<std::uint32_t>(
            (static_cast<std::uint16_t>(bytes[index]) << 8U) |
            static_cast<std::uint16_t>(bytes[index + 1U])
        );
        index += 2U;
    }

    if (index < bytes.size()) {
        sum += static_cast<std::uint32_t>(static_cast<std::uint16_t>(bytes[index]) << 8U);
    }

    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }

    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

std::vector<std::uint8_t> copy_zeroed_range(
    std::span<const std::uint8_t> bytes,
    const std::size_t offset,
    const std::size_t length,
    const std::size_t zero_offset,
    const std::size_t zero_length
) {
    std::vector<std::uint8_t> copied(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                     bytes.begin() + static_cast<std::ptrdiff_t>(offset + length));
    if (zero_offset >= offset && zero_offset + zero_length <= offset + length) {
        const auto local_offset = zero_offset - offset;
        for (std::size_t index = 0; index < zero_length; ++index) {
            copied[local_offset + index] = 0U;
        }
    }
    return copied;
}

ChecksumValidationResult validate_ipv4_header_checksum(
    std::span<const std::uint8_t> packet_bytes,
    const PacketDetails& details,
    const PacketRef& packet
) {
    const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
    if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv4) {
        return {};
    }

    const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(packet_bytes, network->payload_offset);
    if (!ipv4_bounds.has_value()) {
        return {};
    }

    const auto checksum_offset = network->payload_offset + 10U;
    if (checksum_offset + 2U > packet_bytes.size()) {
        return {};
    }

    const auto stored_checksum = detail::read_be16(packet_bytes, checksum_offset);
    const auto header_bytes = copy_zeroed_range(
        packet_bytes,
        network->payload_offset,
        ipv4_bounds->header_length,
        checksum_offset,
        2U
    );
    const auto computed_checksum = compute_internet_checksum(header_bytes);
    if (computed_checksum == stored_checksum) {
        return ChecksumValidationResult {
            .status = ChecksumValidationStatus::valid,
        };
    }

    if (details.ipv4_bounds_from_captured_bytes) {
        return ChecksumValidationResult {
            .status = ChecksumValidationStatus::unavailable,
            .note = "Possible pre-offload packet; IPv4 checksum may be incomplete or not finalized.",
        };
    }

    return ChecksumValidationResult {
        .status = ChecksumValidationStatus::invalid,
    };
}

ChecksumValidationResult validate_tcp_checksum(
    std::span<const std::uint8_t> packet_bytes,
    const PacketDetails& details,
    const PacketRef& packet
) {
    if (packet.is_ip_fragmented) {
        return ChecksumValidationResult {
            .status = ChecksumValidationStatus::unavailable,
            .note = "TCP checksum not validated for IP-fragmented packet.",
        };
    }

    if (details.has_ipv4) {
        const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
        if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv4) {
            return {};
        }

        const auto ipv4_offset = network->payload_offset;
        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(packet_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return {};
        }

        if (details.ipv4_bounds_from_captured_bytes) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = "Possible pre-offload packet; TCP checksum may be incomplete or not finalized.",
            };
        }

        if (packet.captured_length < packet.original_length || packet_bytes.size() < ipv4_bounds->nominal_packet_end) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = "Packet is truncated in capture; full TCP segment bytes are unavailable.",
            };
        }

        const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
        if (transport_offset + detail::kTcpMinimumHeaderSize > packet_bytes.size()) {
            return {};
        }

        const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
        const auto segment_length = static_cast<std::size_t>(ipv4_bounds->total_length) - ipv4_bounds->header_length;
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            transport_offset + segment_length > packet_bytes.size() ||
            segment_length < tcp_header_length) {
            return {};
        }

        const auto checksum_offset = transport_offset + 16U;
        const auto stored_checksum = detail::read_be16(packet_bytes, checksum_offset);

        std::vector<std::uint8_t> checksum_bytes {};
        checksum_bytes.reserve(12U + segment_length + (segment_length % 2U));
        append_be32_bytes(checksum_bytes, details.ipv4.src_addr);
        append_be32_bytes(checksum_bytes, details.ipv4.dst_addr);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(detail::kIpProtocolTcp);
        append_be16_bytes(checksum_bytes, static_cast<std::uint16_t>(segment_length));
        const auto segment_bytes = copy_zeroed_range(packet_bytes, transport_offset, segment_length, checksum_offset, 2U);
        checksum_bytes.insert(checksum_bytes.end(), segment_bytes.begin(), segment_bytes.end());

        return ChecksumValidationResult {
            .status = compute_internet_checksum(checksum_bytes) == stored_checksum
                ? ChecksumValidationStatus::valid
                : ChecksumValidationStatus::invalid,
        };
    }

    if (details.has_ipv6) {
        const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
        if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv6) {
            return {};
        }

        const auto ipv6_offset = network->payload_offset;
        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        if (!payload.has_value() || payload->has_fragment_header) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = "TCP checksum not validated for fragmented IPv6 packet.",
            };
        }

        const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv6_offset + 4U));
        const auto nominal_packet_end = ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length;
        if (packet.captured_length < packet.original_length || packet_bytes.size() < nominal_packet_end) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = "Packet is truncated in capture; full TCP segment bytes are unavailable.",
            };
        }

        const auto transport_offset = payload->payload_offset;
        if (transport_offset + detail::kTcpMinimumHeaderSize > packet_bytes.size()) {
            return {};
        }

        const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
        const auto segment_length = nominal_packet_end - transport_offset;
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            transport_offset + segment_length > packet_bytes.size() ||
            segment_length < tcp_header_length) {
            return {};
        }

        const auto checksum_offset = transport_offset + 16U;
        const auto stored_checksum = detail::read_be16(packet_bytes, checksum_offset);

        std::vector<std::uint8_t> checksum_bytes {};
        checksum_bytes.reserve(40U + segment_length + (segment_length % 2U));
        checksum_bytes.insert(checksum_bytes.end(), details.ipv6.src_addr.begin(), details.ipv6.src_addr.end());
        checksum_bytes.insert(checksum_bytes.end(), details.ipv6.dst_addr.begin(), details.ipv6.dst_addr.end());
        append_be32_bytes(checksum_bytes, static_cast<std::uint32_t>(segment_length));
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(detail::kIpProtocolTcp);
        const auto segment_bytes = copy_zeroed_range(packet_bytes, transport_offset, segment_length, checksum_offset, 2U);
        checksum_bytes.insert(checksum_bytes.end(), segment_bytes.begin(), segment_bytes.end());

        return ChecksumValidationResult {
            .status = compute_internet_checksum(checksum_bytes) == stored_checksum
                ? ChecksumValidationStatus::valid
                : ChecksumValidationStatus::invalid,
        };
    }

    return {};
}

ChecksumValidationResult validate_udp_checksum(
    std::span<const std::uint8_t> packet_bytes,
    const PacketDetails& details,
    const PacketRef& packet
) {
    if (packet.is_ip_fragmented) {
        return ChecksumValidationResult {
            .status = ChecksumValidationStatus::unavailable,
            .note = "UDP checksum not validated for IP-fragmented packet.",
        };
    }

    if (details.has_ipv4) {
        const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
        if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv4) {
            return {};
        }

        const auto ipv4_offset = network->payload_offset;
        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(packet_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return {};
        }

        if (details.ipv4_bounds_from_captured_bytes) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = "Possible pre-offload packet; UDP checksum may be incomplete or not finalized.",
            };
        }

        const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
        if (transport_offset + detail::kUdpHeaderSize > packet_bytes.size()) {
            return {};
        }

        const auto datagram_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, transport_offset + 4U));
        if (datagram_length < detail::kUdpHeaderSize ||
            transport_offset + datagram_length > ipv4_bounds->nominal_packet_end) {
            return {};
        }

        const auto stored_checksum = detail::read_be16(packet_bytes, transport_offset + 6U);
        if (stored_checksum == 0U) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::not_checked,
                .note = "UDP checksum is not present in this IPv4 packet.",
            };
        }

        if (packet.captured_length < packet.original_length || packet_bytes.size() < transport_offset + datagram_length) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = "Packet is truncated in capture; full UDP datagram bytes are unavailable.",
            };
        }

        std::vector<std::uint8_t> checksum_bytes {};
        checksum_bytes.reserve(12U + datagram_length + (datagram_length % 2U));
        append_be32_bytes(checksum_bytes, details.ipv4.src_addr);
        append_be32_bytes(checksum_bytes, details.ipv4.dst_addr);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(detail::kIpProtocolUdp);
        append_be16_bytes(checksum_bytes, static_cast<std::uint16_t>(datagram_length));
        const auto datagram_bytes =
            copy_zeroed_range(packet_bytes, transport_offset, datagram_length, transport_offset + 6U, 2U);
        checksum_bytes.insert(checksum_bytes.end(), datagram_bytes.begin(), datagram_bytes.end());

        return ChecksumValidationResult {
            .status = compute_internet_checksum(checksum_bytes) == stored_checksum
                ? ChecksumValidationStatus::valid
                : ChecksumValidationStatus::invalid,
        };
    }

    if (details.has_ipv6) {
        const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
        if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv6) {
            return {};
        }

        const auto ipv6_offset = network->payload_offset;
        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        if (!payload.has_value() || payload->has_fragment_header) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = "UDP checksum not validated for fragmented IPv6 packet.",
            };
        }

        const auto transport_offset = payload->payload_offset;
        if (transport_offset + detail::kUdpHeaderSize > packet_bytes.size()) {
            return {};
        }

        const auto datagram_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, transport_offset + 4U));
        const auto nominal_packet_end = ipv6_offset + detail::kIpv6HeaderSize + static_cast<std::size_t>(details.ipv6.payload_length);
        if (datagram_length < detail::kUdpHeaderSize || transport_offset + datagram_length > nominal_packet_end) {
            return {};
        }

        const auto stored_checksum = detail::read_be16(packet_bytes, transport_offset + 6U);
        if (stored_checksum == 0U) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::invalid,
                .note = "UDP checksum is required for IPv6 packets.",
            };
        }

        if (packet.captured_length < packet.original_length || packet_bytes.size() < transport_offset + datagram_length) {
            return ChecksumValidationResult {
                .status = ChecksumValidationStatus::unavailable,
                .note = "Packet is truncated in capture; full UDP datagram bytes are unavailable.",
            };
        }

        std::vector<std::uint8_t> checksum_bytes {};
        checksum_bytes.reserve(40U + datagram_length + (datagram_length % 2U));
        checksum_bytes.insert(checksum_bytes.end(), details.ipv6.src_addr.begin(), details.ipv6.src_addr.end());
        checksum_bytes.insert(checksum_bytes.end(), details.ipv6.dst_addr.begin(), details.ipv6.dst_addr.end());
        append_be32_bytes(checksum_bytes, static_cast<std::uint32_t>(datagram_length));
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(0U);
        checksum_bytes.push_back(detail::kIpProtocolUdp);
        const auto datagram_bytes =
            copy_zeroed_range(packet_bytes, transport_offset, datagram_length, transport_offset + 6U, 2U);
        checksum_bytes.insert(checksum_bytes.end(), datagram_bytes.begin(), datagram_bytes.end());

        return ChecksumValidationResult {
            .status = compute_internet_checksum(checksum_bytes) == stored_checksum
                ? ChecksumValidationStatus::valid
                : ChecksumValidationStatus::invalid,
        };
    }

    return {};
}

void append_checksum_line(
    std::vector<std::string>& lines,
    const std::string& label,
    const ChecksumValidationResult& result
) {
    lines.push_back(label + ": " + checksum_status_text(result.status));
    if (!result.note.empty()) {
        lines.push_back(label + " note: " + result.note);
    }
}

bool should_promote_checksum_note_to_warning(const ChecksumValidationResult& result) noexcept {
    return !result.note.empty()
        && result.status != ChecksumValidationStatus::valid
        && result.status != ChecksumValidationStatus::not_checked;
}

std::string checksum_warning_text(const std::string& label, const ChecksumValidationResult& result) {
    if (result.status == ChecksumValidationStatus::invalid) {
        return result.note.empty()
            ? label + " is invalid."
            : label + " is invalid. " + result.note;
    }

    if (should_promote_checksum_note_to_warning(result)) {
        return result.note;
    }

    return {};
}

PacketChecksumSections build_packet_checksum_sections(
    const PacketDetails& details,
    const PacketRef& packet,
    std::span<const std::uint8_t> packet_bytes
) {
    PacketChecksumSections sections {};

    if (details.has_ipv4) {
        const auto ipv4_result = validate_ipv4_header_checksum(packet_bytes, details, packet);
        append_checksum_line(sections.summary_lines, "IPv4 checksum", ipv4_result);
        const auto warning = checksum_warning_text("IPv4 checksum", ipv4_result);
        if (!warning.empty()) {
            sections.warnings.push_back(warning);
        }
    }

    if (details.has_tcp) {
        const auto tcp_result = validate_tcp_checksum(packet_bytes, details, packet);
        append_checksum_line(sections.summary_lines, "TCP checksum", tcp_result);
        const auto warning = checksum_warning_text("TCP checksum", tcp_result);
        if (!warning.empty()) {
            sections.warnings.push_back(warning);
        }
    }

    if (details.has_udp) {
        const auto udp_result = validate_udp_checksum(packet_bytes, details, packet);
        append_checksum_line(sections.summary_lines, "UDP checksum", udp_result);
        const auto warning = checksum_warning_text("UDP checksum", udp_result);
        if (!warning.empty()) {
            sections.warnings.push_back(warning);
        }
    }

    return sections;
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

std::string format_rate_graph_window_text(const std::uint64_t window_us) {
    if (window_us == 0U) {
        return {};
    }

    if (window_us < 1000000U) {
        const auto window_ms = static_cast<double>(window_us) / 1000.0;
        std::ostringstream out {};
        out << trim_trailing_zeros(std::to_string(window_ms)) << " ms (auto)";
        return out.str();
    }

    const auto window_seconds = static_cast<double>(window_us) / 1000000.0;
    std::ostringstream out {};
    out << trim_trailing_zeros(std::to_string(window_seconds)) << " s (auto)";
    return out.str();
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
    return session.flow_row(flow_index);
}

std::string build_analysis_endpoint_summary(const FlowRow& row) {
    std::ostringstream out {};
    out << row.endpoint_a
        << " <-> "
        << row.endpoint_b;
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

FrontendSessionAdapter::~FrontendSessionAdapter() {
    cancel_and_join_open_worker();
}

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
    cancel_and_join_open_worker();
    clear_selection();
    session_ = CaptureSession {};
    const auto analysis_settings = to_analysis_settings(settings_);

    if (path.empty()) {
        return FrontendOpenResult {
            .opened = false,
            .error_text = "No file selected.",
        };
    }

    const bool opened = looks_like_index_file(path)
        ? session_.load_index(path)
        : session_.open_capture(path, import_options_for_frontend_mode(open_mode, analysis_settings));

    if (opened) {
        session_.set_analysis_settings(analysis_settings);
    }

    const auto source_availability = current_source_availability();

    return FrontendOpenResult {
        .opened = opened,
        .cancelled = false,
        .opened_from_index = source_availability.opened_from_index,
        .partial_open = source_availability.partial_open,
        .partial_open_warning_text = source_availability.partial_open
            ? format_partial_open_warning_message(session_.partial_open_failure())
            : std::string {},
        .has_source_capture = source_availability.has_source_capture,
        .source_capture_accessible = source_availability.source_capture_accessible,
        .input_path = path_to_string(path),
        .active_source_capture_path = source_availability.active_source_capture_path,
        .expected_source_capture_path = source_availability.expected_source_capture_path,
        .error_text = opened ? std::string {} : session_.last_open_error_text(),
        .source_availability = source_availability,
    };
}

FrontendOpenStartResult FrontendSessionAdapter::start_open_capture(
    const std::filesystem::path& path,
    const FrontendOpenMode open_mode
) {
    join_finished_open_worker();

    if (path.empty()) {
        return FrontendOpenStartResult {
            .started = false,
            .error_text = "No file selected.",
        };
    }

    {
        std::lock_guard lock {async_open_.mutex};
        if (async_open_.in_progress) {
            return FrontendOpenStartResult {
                .started = false,
                .error_text = "Another open request is already in progress.",
            };
        }
        async_open_.cancel_requested = false;
        async_open_.result_ready = false;
        async_open_.progress = FrontendOpenProgressDto {
            .in_progress = true,
            .cancel_requested = false,
            .opening_as_index = looks_like_index_file(path),
            .input_path = path_to_string(path),
        };
        async_open_.result = FrontendOpenResult {};
        async_open_.completed_session.reset();
        async_open_.context = std::make_shared<OpenContext>();
        async_open_.in_progress = true;
    }

    clear_selection();
    session_ = CaptureSession {};
    const auto analysis_settings = to_analysis_settings(settings_);
    const auto open_as_index = looks_like_index_file(path);
    const auto context = async_open_.context;

    context->on_progress = [this, path](const OpenProgress& progress) {
        std::lock_guard lock {async_open_.mutex};
        async_open_.progress.in_progress = async_open_.in_progress;
        async_open_.progress.cancel_requested = async_open_.cancel_requested || (async_open_.context != nullptr && async_open_.context->is_cancel_requested());
        async_open_.progress.opening_as_index = looks_like_index_file(path);
        async_open_.progress.packets_processed = progress.packets_processed;
        async_open_.progress.bytes_processed = progress.bytes_processed;
        async_open_.progress.total_bytes = progress.total_bytes;
        async_open_.progress.percent = std::clamp(progress.percent(), 0.0, 1.0);
        async_open_.progress.input_path = path_to_string(path);
    };

    async_open_.worker = std::thread([this, path, open_mode, open_as_index, analysis_settings, context]() {
        CaptureSession worker_session {};
        const bool opened = open_as_index
            ? worker_session.load_index(path, context.get())
            : worker_session.open_capture(path, import_options_for_frontend_mode(open_mode, analysis_settings), context.get());
        if (opened) {
            worker_session.set_analysis_settings(analysis_settings);
        }

        const bool cancelled = context->is_cancel_requested();
        FrontendSourceAvailabilityDto source_availability {};
        if (opened && !cancelled) {
            source_availability = FrontendSourceAvailabilityDto {
                .has_source_capture = worker_session.has_source_capture(),
                .source_capture_accessible = worker_session.source_capture_accessible(),
                .opened_from_index = worker_session.opened_from_index(),
                .partial_open = worker_session.is_partial_open(),
                .byte_backed_inspection_available = worker_session.has_source_capture() && worker_session.source_capture_accessible(),
                .active_source_capture_path = path_to_string(worker_session.attached_source_capture_path()),
                .expected_source_capture_path = path_to_string(worker_session.expected_source_capture_path()),
            };
        }

        std::lock_guard lock {async_open_.mutex};
        async_open_.in_progress = false;
        async_open_.cancel_requested = cancelled;
        async_open_.result_ready = true;
        async_open_.progress.in_progress = false;
        async_open_.progress.cancel_requested = cancelled;
        async_open_.progress.opening_as_index = open_as_index;
        async_open_.progress.packets_processed = context->progress.packets_processed;
        async_open_.progress.bytes_processed = context->progress.bytes_processed;
        async_open_.progress.total_bytes = context->progress.total_bytes;
        async_open_.progress.percent = std::clamp(context->progress.percent(), 0.0, 1.0);
        async_open_.progress.input_path = path_to_string(path);
        async_open_.result = FrontendOpenResult {
            .opened = opened && !cancelled,
            .cancelled = cancelled,
            .opened_from_index = source_availability.opened_from_index,
            .partial_open = source_availability.partial_open,
            .partial_open_warning_text = source_availability.partial_open
                ? format_partial_open_warning_message(worker_session.partial_open_failure())
                : std::string {},
            .has_source_capture = source_availability.has_source_capture,
            .source_capture_accessible = source_availability.source_capture_accessible,
            .input_path = path_to_string(path),
            .active_source_capture_path = source_availability.active_source_capture_path,
            .expected_source_capture_path = source_availability.expected_source_capture_path,
            .error_text = (opened || cancelled) ? std::string {} : worker_session.last_open_error_text(),
            .source_availability = source_availability,
        };
        if (opened && !cancelled) {
            async_open_.completed_session = std::move(worker_session);
        } else {
            async_open_.completed_session.reset();
        }
        async_open_.context.reset();
    });

    return FrontendOpenStartResult {
        .started = true,
        .error_text = {},
    };
}

FrontendOpenPollResultDto FrontendSessionAdapter::poll_open_capture() {
    join_finished_open_worker();

    FrontendOpenPollResultDto result {};
    std::lock_guard lock {async_open_.mutex};
    result.progress = async_open_.progress;
    result.ready = async_open_.result_ready;
    if (!async_open_.result_ready) {
        return result;
    }

    result.result = async_open_.result;
    if (async_open_.completed_session.has_value() && result.result.opened && !result.result.cancelled) {
        session_ = std::move(*async_open_.completed_session);
        async_open_.completed_session.reset();
    }

    async_open_.result_ready = false;
    async_open_.result = FrontendOpenResult {};
    async_open_.progress = FrontendOpenProgressDto {};
    return result;
}

bool FrontendSessionAdapter::cancel_open_capture() {
    std::lock_guard lock {async_open_.mutex};
    if (!async_open_.in_progress || async_open_.context == nullptr) {
        return false;
    }

    async_open_.cancel_requested = true;
    async_open_.progress.cancel_requested = true;
    async_open_.context->request_cancel();
    return true;
}

FrontendAttachSourceCaptureResult FrontendSessionAdapter::attach_source_capture(const std::filesystem::path& path) {
    FrontendAttachSourceCaptureResult result {
        .attached = false,
        .source_availability = current_source_availability(),
    };

    if (!session_.has_capture()) {
        result.error_text = "Source capture attachment is not available for the current session.";
        return result;
    }

    if (path.empty()) {
        result.error_text = "No source capture selected.";
        return result;
    }

    if (!session_.attach_source_capture(path)) {
        result.error_text = "Selected file does not match the expected source capture.";
        result.source_availability = current_source_availability();
        return result;
    }

    result.attached = true;
    result.source_availability = current_source_availability();
    return result;
}

FrontendSaveIndexResult FrontendSessionAdapter::save_index(const std::filesystem::path& output_path) const {
    FrontendSaveIndexResult result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (output_path.empty()) {
        result.error_text = "No output file selected.";
        return result;
    }

    if (session_.is_partial_open()) {
        result.error_text = "Saving an index from a partial capture is not supported yet.";
        return result;
    }

    if (!session_.has_source_capture() || !session_.source_capture_accessible()) {
        result.error_text = "Original source capture is unavailable. Reattach the capture file to save an analysis index.";
        return result;
    }

    if (!session_.save_index(output_path)) {
        result.error_text = "Failed to save analysis index.";
        return result;
    }

    result.saved = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendSettingsDto FrontendSessionAdapter::get_settings() const noexcept {
    return settings_;
}

FrontendSettingsDto FrontendSessionAdapter::update_settings(const FrontendSettingsDto& settings) {
    const bool use_possible_tls_quic_changed = settings_.use_possible_tls_quic != settings.use_possible_tls_quic;
    settings_ = settings;

    if (use_possible_tls_quic_changed && session_.has_capture()) {
        session_.set_analysis_settings(to_analysis_settings(settings_));
    }

    return settings_;
}

FrontendExportCurrentFlowResult FrontendSessionAdapter::export_current_flow(const std::filesystem::path& output_path) const {
    FrontendExportCurrentFlowResult result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (!selected_flow_index_.has_value()) {
        result.error_text = "No flow selected for export.";
        return result;
    }

    if (!session_.has_source_capture() || !session_.source_capture_accessible()) {
        result.error_text = "Original source capture is unavailable. Reattach the capture file to export flows.";
        return result;
    }

    if (output_path.empty()) {
        result.error_text = "No output file selected.";
        return result;
    }

    if (!session_.export_flow_to_pcap(*selected_flow_index_, output_path)) {
        result.error_text = "Failed to export selected flow.";
        return result;
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendExportSelectedFlowsResult FrontendSessionAdapter::export_selected_flows(
    const std::filesystem::path& output_path,
    const std::vector<std::size_t>& flow_indices
) const {
    FrontendExportSelectedFlowsResult result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (flow_indices.empty()) {
        result.error_text = "No selected flows for export.";
        return result;
    }

    if (!session_.has_source_capture() || !session_.source_capture_accessible()) {
        result.error_text = "Original source capture is unavailable. Reattach the capture file to export flows.";
        return result;
    }

    if (output_path.empty()) {
        result.error_text = "No output file selected.";
        return result;
    }

    if (!session_.export_flows_to_pcap(flow_indices, output_path)) {
        result.error_text = "Failed to export selected flows.";
        return result;
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendSmartExportResult FrontendSessionAdapter::export_smart_flows(
    const std::filesystem::path& output_path,
    const std::vector<std::size_t>& flow_indices,
    const FrontendSmartExportOptions& options
) const {
    FrontendSmartExportResult result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (flow_indices.empty()) {
        result.error_text = "No flows selected for smart export.";
        return result;
    }

    if (!session_.has_source_capture() || !session_.source_capture_accessible()) {
        result.error_text = "Original source capture is unavailable. Reattach the capture file to export flows.";
        return result;
    }

    if (output_path.empty()) {
        result.error_text = options.output_mode == FrontendSmartExportOutputMode::separate_file_per_flow
            ? "No destination folder selected for smart export."
            : "No output file selected.";
        return result;
    }

    std::string retention_error_text {};
    const auto retention = build_smart_packet_retention_options(options, retention_error_text);
    if (!retention.has_value()) {
        result.error_text = retention_error_text;
        return result;
    }

    SmartFlowExportRequest request {};
    request.flow_indices = flow_indices;
    request.base_mode = retention->base_mode;
    request.first_n_packets = retention->first_n_packets;
    request.first_m_original_bytes = retention->first_m_original_bytes;
    request.include_last_packet = retention->include_last_packet;
    request.include_every_kth_packet_after_base = retention->include_every_kth_packet_after_base;
    request.every_kth_packet = retention->every_kth_packet;

    if (options.output_mode == FrontendSmartExportOutputMode::separate_file_per_flow) {
        if (options.per_flow_buffer_budget_bytes == 0U) {
            result.error_text = "Select a valid buffer memory budget preset for per-flow smart export.";
            return result;
        }

        std::string error_text {};
        const SmartPerFlowExportOptions per_flow_options {
            .buffer_budget_bytes = options.per_flow_buffer_budget_bytes,
        };

        if (!session_.export_smart_flows_to_folder(request, output_path, per_flow_options, &error_text)) {
            result.error_text = error_text.empty() ? "Failed to smart-export flows." : error_text;
            return result;
        }
    } else {
        if (!session_.export_smart_flows_to_pcap(request, output_path)) {
            result.error_text = "Failed to smart-export flows.";
            return result;
        }
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendSmartExportResult FrontendSessionAdapter::export_smart_unrecognized_packets(
    const std::filesystem::path& output_path,
    const FrontendSmartExportOptions& options
) const {
    FrontendSmartExportResult result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (!session_.has_source_capture() || !session_.source_capture_accessible()) {
        result.error_text = "Original source capture is unavailable. Reattach the capture file to export packets.";
        return result;
    }

    if (session_.unrecognized_packet_count() == 0U) {
        result.error_text = "No unrecognized packets available for smart export.";
        return result;
    }

    if (options.output_mode != FrontendSmartExportOutputMode::single_file) {
        result.error_text = "Unrecognized packets can only be smart-exported to a single output file.";
        return result;
    }

    if (output_path.empty()) {
        result.error_text = "No output file selected.";
        return result;
    }

    std::string retention_error_text {};
    const auto retention = build_smart_packet_retention_options(options, retention_error_text);
    if (!retention.has_value()) {
        result.error_text = retention_error_text;
        return result;
    }

    std::string error_text {};
    if (!session_.export_smart_unrecognized_packets_to_pcap(*retention, output_path, SmartSingleFileExportOptions {}, &error_text)) {
        result.error_text = error_text.empty()
            ? "Failed to smart-export unrecognized packets."
            : error_text;
        return result;
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendOverviewDto FrontendSessionAdapter::get_overview() const {
    const auto protocol_summary = session_.protocol_summary();
    const auto protocol_path_summary = session_.protocol_path_summary();
    const auto top_summary = session_.has_capture() ? session_.top_summary() : CaptureTopSummary {};
    return FrontendOverviewDto {
        .has_capture = session_.has_capture(),
        .summary = session_.summary(),
        .captured_bytes = protocol_summary.tcp.captured_bytes + protocol_summary.udp.captured_bytes +
            protocol_summary.sctp.captured_bytes + protocol_summary.other.captured_bytes,
        .original_bytes = protocol_summary.tcp.original_bytes + protocol_summary.udp.original_bytes +
            protocol_summary.sctp.original_bytes + protocol_summary.other.original_bytes,
        .unrecognized_packet_count = session_.unrecognized_packet_count(),
        .protocol_summary = protocol_summary,
        .quic_recognition = session_.quic_recognition_stats(),
        .tls_recognition = session_.tls_recognition_stats(),
        .protocol_hints = build_protocol_hint_stats(protocol_summary),
        .top_endpoints = build_top_endpoints(top_summary),
        .top_ports = build_top_ports(top_summary),
        .protocol_path_statistics = build_protocol_path_statistics(protocol_path_summary),
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

std::vector<FrontendProtocolPathLegendEntryDto> FrontendSessionAdapter::get_protocol_path_legend() const {
    const auto legend = session_detail::protocol_path_legend_entries();
    std::vector<FrontendProtocolPathLegendEntryDto> rows {};
    rows.reserve(legend.size());

    for (const auto& entry : legend) {
        rows.push_back(FrontendProtocolPathLegendEntryDto {
            .short_label = entry.short_label,
            .full_name = entry.full_name,
            .tooltip = entry.tooltip,
            .color_key = entry.color_key,
            .background_color = entry.background_color,
            .border_color = entry.border_color,
            .text_color = entry.text_color,
        });
    }

    return rows;
}

FrontendSelectionResultDto FrontendSessionAdapter::select_flow(const std::size_t flow_index) {
    FrontendSelectionResultDto result {};

    if (!session_.has_capture()) {
        clear_selection();
        return result;
    }

    if (flow_index >= session_.summary().flow_count) {
        return result;
    }

    selected_flow_index_ = flow_index;
    session_.clear_selected_flow_packet_cache();
    session_.clear_selected_flow_tcp_payload_suppression();
    result.selected = true;

    const auto row = session_.flow_row(flow_index);
    if (!row.has_value()) {
        return result;
    }

    const auto protocol_hint_is_quic = row->protocol_hint == "quic" || row->protocol_hint == "QUIC";
    if (!protocol_hint_is_quic || !row->service_hint.empty()) {
        return result;
    }

    const auto derived_service_hint = session_.derive_quic_service_hint_for_flow(flow_index);
    if (!derived_service_hint.has_value() || derived_service_hint->empty()) {
        return result;
    }

    auto updated_row = *row;
    updated_row.service_hint = *derived_service_hint;
    result.updated_flow = to_frontend_flow(updated_row);
    return result;
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

FrontendUnrecognizedPacketsResult FrontendSessionAdapter::get_unrecognized_packets(
    const std::size_t offset,
    const std::size_t limit
) const {
    FrontendUnrecognizedPacketsResult result {
        .has_capture = session_.has_capture(),
        .offset = offset,
        .limit = limit,
        .total_count = session_.unrecognized_packet_count(),
    };

    if (!result.has_capture || offset >= result.total_count || limit == 0U) {
        return result;
    }

    const auto rows = session_.list_unrecognized_packets(offset, limit);
    result.packets.reserve(rows.size());
    for (const auto& row : rows) {
        result.packets.push_back(to_frontend_unrecognized_packet(row));
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

    const auto flow_packet_numbers = build_bounded_flow_packet_numbers(
        session_,
        flow_index,
        result.packet_window_count,
        rows
    );

    result.items.reserve(rows.size());
    for (const auto& row : rows) {
        auto source_packet_indices = row.packet_indices;
        auto constricted_contribution_notes = row.constricted_contribution_notes;
        auto constricted_packet_notes = row.constricted_packet_notes;

        auto source_packets_text = format_stream_source_packets_text(row, flow_packet_numbers);
        auto header_secondary_text = stream_item_header_secondary_text(row, flow_packet_numbers);
        auto badge_text = stream_item_header_badge_text(row);
        auto summary_text = build_stream_item_summary_text(row, flow_packet_numbers);
        auto payload_tab_title = stream_item_payload_tab_title(row);

        result.items.push_back(FrontendStreamItemDto {
            .stream_item_index = row.stream_item_index,
            .direction_text = row.direction_text,
            .label = row.label,
            .byte_count = row.byte_count,
            .packet_count = row.packet_count,
            .source_packet_indices = std::move(source_packet_indices),
            .source_packets_text = std::move(source_packets_text),
            .has_constricted_contribution = row.has_constricted_contribution,
            .constricted_contribution_notes = std::move(constricted_contribution_notes),
            .constricted_packet_notes = std::move(constricted_packet_notes),
            .header_secondary_text = std::move(header_secondary_text),
            .badge_text = std::move(badge_text),
            .summary_text = std::move(summary_text),
            .payload_tab_title = std::move(payload_tab_title),
            .payload_preview_text = {},
            .payload_preview_unavailable_text = {},
            .protocol_details_text = {},
        });
    }
    return result;
}

FrontendStreamItemDto FrontendSessionAdapter::get_selected_flow_stream_item_details(
    const std::size_t max_packets_to_scan,
    const std::size_t limit,
    const std::uint64_t stream_item_index
) const {
    FrontendStreamItemDto result {
        .stream_item_index = stream_item_index,
        .payload_tab_title = "Payload",
    };

    if (!session_.has_capture() || !selected_flow_index_.has_value()) {
        result.payload_preview_unavailable_text = stream_payload_unavailable_text();
        result.protocol_details_text = stream_protocol_unavailable_text();
        return result;
    }

    if (!session_.source_capture_accessible()) {
        result.payload_preview_unavailable_text = stream_payload_unavailable_text();
        result.protocol_details_text = stream_protocol_unavailable_text();
        return result;
    }

    const auto flow_index = *selected_flow_index_;
    const auto total_flow_packet_count = session_.flow_packet_count(flow_index);
    if (limit == 0U || max_packets_to_scan == 0U || total_flow_packet_count == 0U) {
        result.payload_preview_unavailable_text = stream_payload_unavailable_text();
        result.protocol_details_text = stream_protocol_unavailable_text();
        return result;
    }

    const auto packet_window_count = std::min(total_flow_packet_count, max_packets_to_scan);
    auto rows = session_.list_flow_stream_items_for_packet_prefix(flow_index, packet_window_count, limit + 1U);
    if (rows.size() > limit) {
        rows.resize(limit);
    }

    const auto flow_packet_numbers = build_bounded_flow_packet_numbers(
        session_,
        flow_index,
        packet_window_count,
        rows
    );
    if (const auto it = std::find_if(
            rows.begin(),
            rows.end(),
            [stream_item_index](const StreamItemRow& row) { return row.stream_item_index == stream_item_index; }
        );
        it != rows.end()) {
        result = to_frontend_stream_item(*it, flow_packet_numbers, true);
    } else {
        result.payload_preview_unavailable_text = "The selected stream item is no longer available in the current stream window.";
        result.protocol_details_text = stream_protocol_unavailable_text();
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
    result.rate_graph_available = analysis->rate_graph.available;
    result.rate_graph_status_text = analysis->rate_graph.status_text;
    result.rate_graph_window_text = format_rate_graph_window_text(analysis->rate_graph.window_us);
    result.rate_graph_points_a_to_b.reserve(analysis->rate_graph.points_a_to_b.size());
    for (const auto& point : analysis->rate_graph.points_a_to_b) {
        result.rate_graph_points_a_to_b.push_back(FrontendAnalysisRatePointDto {
            .relative_time_us = point.relative_time_us,
            .data_per_second = point.data_per_second,
            .packets_per_second = point.packets_per_second,
        });
    }
    result.rate_graph_points_b_to_a.reserve(analysis->rate_graph.points_b_to_a.size());
    for (const auto& point : analysis->rate_graph.points_b_to_a) {
        result.rate_graph_points_b_to_a.push_back(FrontendAnalysisRatePointDto {
            .relative_time_us = point.relative_time_us,
            .data_per_second = point.data_per_second,
            .packets_per_second = point.packets_per_second,
        });
    }
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

FrontendPacketDetailsDto FrontendSessionAdapter::get_selected_flow_packet_details(
    const std::uint64_t packet_index,
    const std::uint64_t flow_packet_index
) const {
    FrontendPacketDetailsDto result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = selected_flow_index_.has_value(),
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

    std::optional<PacketRef> packet {};
    if (flow_packet_index != 0U) {
        packet = session_.selected_flow_packet_at(*selected_flow_index_, flow_packet_index);
        if (!packet.has_value() || packet->packet_index != packet_index) {
            result.error_text = "The selected packet is unavailable.";
            return result;
        }
    } else {
        if (!session_.selected_flow_exact_packet_number(*selected_flow_index_, packet_index).has_value()) {
            result.error_text = "The selected packet is unavailable.";
            return result;
        }
        packet = session_.find_packet(packet_index);
        if (!packet.has_value()) {
            result.error_text = "The selected packet is unavailable.";
            return result;
        }
    }

    auto details = build_frontend_packet_details(
        *packet,
        selected_flow_index_,
        flow_packet_index != 0U ? std::optional<std::uint64_t> {flow_packet_index} : std::nullopt
    );
    return details;
}

FrontendPacketDetailsDto FrontendSessionAdapter::get_unrecognized_packet_details(const std::uint64_t packet_index) const {
    FrontendPacketDetailsDto result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = false,
        .packet_index = packet_index,
        .details_title = packet_details_title(),
        .payload_tab_title = "Payload",
        .source_availability = current_source_availability(),
    };

    if (!result.has_capture) {
        result.error_text = "No capture is open.";
        return result;
    }

    const auto packet = session_.find_packet(packet_index);
    if (!packet.has_value()) {
        result.error_text = "The selected packet is unavailable.";
        return result;
    }

    const auto matches_unrecognized = std::any_of(
        session_.state().unrecognized_packets.begin(),
        session_.state().unrecognized_packets.end(),
        [packet_index](const UnrecognizedPacketRecord& record) {
            return record.packet.packet_index == packet_index;
        }
    );
    if (!matches_unrecognized) {
        result.error_text = "The selected packet is unavailable in the unrecognized packet context.";
        return result;
    }

    return build_frontend_packet_details(*packet, std::nullopt, std::nullopt);
}

FrontendPacketDetailsDto FrontendSessionAdapter::build_frontend_packet_details(
    const PacketRef& packet,
    const std::optional<std::size_t> flow_index,
    const std::optional<std::uint64_t> flow_packet_index
) const {
    FrontendPacketDetailsDto result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = flow_index.has_value(),
        .packet_found = true,
        .source_capture_accessible = session_.source_capture_accessible(),
        .details_available = false,
        .raw_preview_available = false,
        .raw_preview_truncated = false,
        .payload_preview_available = false,
        .payload_preview_truncated = false,
        .payload_preview_no_payload = false,
        .checksum_validation_enabled = settings_.validate_selected_packet_checksums,
        .flow_index = flow_index.value_or(0U),
        .packet_index = packet.packet_index,
        .details_title = packet_details_title(),
        .summary_text = {},
        .payload_tab_title = "Payload",
        .timestamp_text = session_detail::format_packet_timestamp_full(packet),
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
        .payload_length = packet.payload_length,
        .is_ip_fragmented = packet.is_ip_fragmented,
        .tcp_flags_text = session_detail::format_tcp_flags_text(packet.tcp_flags),
        .source_availability = current_source_availability(),
    };

    if (!result.source_capture_accessible) {
        result.summary_text = build_frontend_packet_summary_text(packet, std::nullopt, {}, false);
        result.unavailable_text =
            "Byte-backed packet details are unavailable because the original source capture cannot be read.";
        result.raw_preview_unavailable_text = result.unavailable_text;
        result.payload_preview_unavailable_text = result.unavailable_text;
        if (result.checksum_validation_enabled) {
            result.checksum_warning_lines.push_back(
                "Checksum validation requires the original source capture bytes to be attached and readable."
            );
        }
        return result;
    }

    const auto details = session_.read_packet_details(packet);
    const auto packet_bytes = session_.read_packet_data(packet);
    const auto raw_preview_text = build_packet_raw_text(packet_bytes);
    result.raw_preview_text = raw_preview_text;
    result.raw_preview_truncated = false;
    result.raw_preview_available = !raw_preview_text.empty();
    result.raw_preview_unavailable_text = result.raw_preview_available
        ? std::string {}
        : "Raw packet bytes are unavailable for this packet.";

    const auto payload_preview_text = build_packet_payload_text(packet_bytes, packet);
    result.payload_preview_text = payload_preview_text;
    result.payload_preview_truncated = false;
    result.payload_preview_available = !payload_preview_text.empty();

    PacketChecksumSections checksum_sections {};
    result.protocol_details_text = frontend_packet_protocol_text(session_, flow_index, packet);

    if (details.has_value() && result.checksum_validation_enabled) {
        checksum_sections =
            build_packet_checksum_sections(*details, packet, std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()));
        result.checksum_summary_lines = checksum_sections.summary_lines;
        result.checksum_warning_lines = checksum_sections.warnings;
    }

    if (details.has_value()) {
        result.details_available = true;
        result.payload_tab_title = packet_payload_tab_title(*details);
        result.link_summary_text = format_link_summary(*details);
        result.network_summary_text = format_network_summary(*details);
        result.transport_summary_text = format_transport_summary(*details);
        result.summary_layers = session_detail::build_packet_summary_layers(*details, packet, {
            .source_capture_accessible = true,
            .flow_packet_index = flow_packet_index,
            .transport_payload_length = packet.payload_length,
            .original_transport_payload_length = session_detail::derive_transport_payload_length_from_headers(session_, packet),
            .protocol_details_text = result.protocol_details_text,
            .checksum_summary_lines = result.checksum_summary_lines,
            .checksum_warning_lines = result.checksum_warning_lines,
        });
    } else {
        result.unavailable_text = "Only partial packet details are available for this packet.";
    }

    result.summary_text = build_frontend_packet_summary_text(packet, details, checksum_sections, true);
    result.payload_preview_no_payload =
        !result.payload_preview_available && packet.payload_length == 0U && (details.has_value() ? (details->has_tcp || details->has_udp) : true);
    result.payload_preview_unavailable_text = result.payload_preview_available
        ? std::string {}
        : (result.payload_preview_no_payload
            ? "No transport payload is available for this packet."
            : "Transport payload bytes are unavailable for this packet.");

    if (!result.payload_preview_available && result.unavailable_text.empty()) {
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

void FrontendSessionAdapter::join_finished_open_worker() {
    std::thread finished_worker {};
    {
        std::lock_guard lock {async_open_.mutex};
        if (!async_open_.in_progress && async_open_.worker.joinable()) {
            finished_worker = std::move(async_open_.worker);
        }
    }

    if (finished_worker.joinable()) {
        finished_worker.join();
    }
}

void FrontendSessionAdapter::cancel_and_join_open_worker() {
    {
        std::lock_guard lock {async_open_.mutex};
        if (async_open_.context != nullptr) {
            async_open_.cancel_requested = true;
            async_open_.progress.cancel_requested = true;
            async_open_.context->request_cancel();
        }
    }

    if (async_open_.worker.joinable()) {
        async_open_.worker.join();
    }

    std::lock_guard lock {async_open_.mutex};
    async_open_.context.reset();
    async_open_.in_progress = false;
    async_open_.cancel_requested = false;
    async_open_.result_ready = false;
    async_open_.progress = FrontendOpenProgressDto {};
    async_open_.result = FrontendOpenResult {};
    async_open_.completed_session.reset();
}

AnalysisSettings FrontendSessionAdapter::to_analysis_settings(const FrontendSettingsDto& settings) noexcept {
    return AnalysisSettings {
        .http_use_path_as_service_hint = settings.http_use_path_as_service_hint,
        .use_possible_tls_quic = settings.use_possible_tls_quic,
    };
}

FrontendFlowDto FrontendSessionAdapter::to_frontend_flow(const FlowRow& row) {
    return FrontendFlowDto {
        .flow_index = row.index,
        .family = row.family,
        .protocol_text = row.protocol_text,
        .protocol_hint = row.protocol_hint,
        .protocol_hint_display = format_protocol_hint_display(row.protocol_hint),
        .service_hint = row.service_hint,
        .protocol_path_text = row.protocol_path_text,
        .protocol_path_compact_text = row.protocol_path_compact_text,
        .protocol_path_badges = row.protocol_path_badges,
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
    const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers,
    const bool include_details
) const {
    const auto payload_preview_text = include_details ? frontend_stream_payload_text(session_, row) : std::string {};
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
        .header_secondary_text = stream_item_header_secondary_text(row, flow_packet_numbers),
        .badge_text = stream_item_header_badge_text(row),
        .summary_text = build_stream_item_summary_text(row, flow_packet_numbers),
        .payload_tab_title = stream_item_payload_tab_title(row),
        .payload_preview_text = payload_preview_text,
        .payload_preview_unavailable_text = include_details && payload_preview_text.empty()
            ? stream_payload_unavailable_text()
            : std::string {},
        .protocol_details_text = include_details
            ? frontend_stream_protocol_text(session_, selected_flow_index_.value_or(0U), row)
            : std::string {},
    };
}

FrontendUnrecognizedPacketDto FrontendSessionAdapter::to_frontend_unrecognized_packet(const UnrecognizedPacketRow& row) {
    return FrontendUnrecognizedPacketDto {
        .row_number = row.row_number,
        .packet_index = row.packet_index,
        .timestamp_text = row.timestamp_text,
        .captured_length = row.captured_length,
        .original_length = row.original_length,
        .reason_text = row.reason_text,
    };
}

}  // namespace pfl
