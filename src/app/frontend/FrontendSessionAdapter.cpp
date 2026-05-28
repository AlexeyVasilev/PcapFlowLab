#include "app/frontend/FrontendSessionAdapter.h"

#include "app/session/SessionFormatting.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "core/index/CaptureIndex.h"
#include "core/services/CaptureImporter.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketPayloadService.h"

#include <algorithm>
#include <span>
#include <sstream>
#include <set>

namespace pfl {

namespace {

constexpr std::size_t kPacketPreviewBytes = 128U;

CaptureImportOptions import_options_for_frontend_mode(const FrontendOpenMode mode) {
    return CaptureImportOptions {
        .mode = (mode == FrontendOpenMode::deep) ? ImportMode::deep : ImportMode::fast,
    };
}

std::string path_to_string(const std::filesystem::path& path) {
    return path.empty() ? std::string {} : path.string();
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

}  // namespace

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

    return FrontendOpenResult {
        .opened = opened,
        .opened_from_index = session_.opened_from_index(),
        .partial_open = session_.is_partial_open(),
        .has_source_capture = session_.has_source_capture(),
        .source_capture_accessible = session_.source_capture_accessible(),
        .input_path = path_to_string(path),
        .active_source_capture_path = path_to_string(session_.attached_source_capture_path()),
        .expected_source_capture_path = path_to_string(session_.expected_source_capture_path()),
        .error_text = opened ? std::string {} : session_.last_open_error_text(),
    };
}

FrontendOverviewDto FrontendSessionAdapter::get_overview() const {
    return FrontendOverviewDto {
        .has_capture = session_.has_capture(),
        .summary = session_.summary(),
        .protocol_summary = session_.protocol_summary(),
        .quic_recognition = session_.quic_recognition_stats(),
        .tls_recognition = session_.tls_recognition_stats(),
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
        .flow_index = selected_flow_index_.value_or(0U),
        .packet_index = packet_index,
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
    result.payload_preview_unavailable_text = result.payload_preview_available
        ? std::string {}
        : ((details->has_tcp || details->has_udp)
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

}  // namespace pfl
