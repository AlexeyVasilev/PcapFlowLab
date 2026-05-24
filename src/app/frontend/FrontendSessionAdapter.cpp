#include "app/frontend/FrontendSessionAdapter.h"

#include "app/session/SelectedFlowPacketSemantics.h"
#include "core/index/CaptureIndex.h"
#include "core/services/CaptureImporter.h"

#include <algorithm>
#include <set>

namespace pfl {

namespace {

CaptureImportOptions import_options_for_frontend_mode(const FrontendOpenMode mode) {
    return CaptureImportOptions {
        .mode = (mode == FrontendOpenMode::deep) ? ImportMode::deep : ImportMode::fast,
    };
}

std::string path_to_string(const std::filesystem::path& path) {
    return path.empty() ? std::string {} : path.string();
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
