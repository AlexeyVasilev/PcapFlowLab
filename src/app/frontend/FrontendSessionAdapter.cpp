#include "app/frontend/FrontendSessionAdapter.h"

#include "app/frontend/FrontendStatisticsOverview.h"
#include "app/session/ProtocolPathPresentation.h"
#include "app/session/SelectedPacketSummaryPreparation.h"
#include "app/session/SessionFlowHelpers.h"
#include "app/session/SessionFormatting.h"
#include "app/session/SessionTlsPresentation.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SupportedProtocolCatalog.h"
#include "core/decode/PacketDecodeSupport.h"
#include "core/index/CaptureIndex.h"
#include "core/services/CaptureImporter.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketDetailsService.h"
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

std::string path_to_string(const std::filesystem::path& path) {
    return path.empty() ? std::string {} : path.string();
}

FrontendByteExportResult unavailable_byte_export_result(const std::string& error_text) {
    return FrontendByteExportResult {
        .exported = false,
        .output_path = {},
        .error_text = error_text,
    };
}

std::vector<FrontendByteExportFormatDto> frontend_byte_export_formats() {
    std::vector<FrontendByteExportFormatDto> result {};
    for (const auto& descriptor : session_detail::byte_export_format_descriptors()) {
        result.push_back(FrontendByteExportFormatDto {
            .stable_id = descriptor.stable_id,
            .label = descriptor.label,
            .suggested_extension = descriptor.suggested_extension,
            .binary_output = descriptor.binary_output,
        });
    }
    return result;
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

FrontendProtocolStatsDto make_frontend_protocol_stats(const ProtocolStats& stats) {
    return FrontendProtocolStatsDto {
        .flow_count = stats.flow_count,
        .packet_count = stats.packet_count,
        .captured_bytes = stats.captured_bytes,
        .captured_bytes_text = session_detail::format_statistics_compact_size_value(stats.captured_bytes),
        .original_bytes = stats.original_bytes,
        .original_bytes_text = session_detail::format_statistics_compact_size_value(stats.original_bytes),
    };
}

std::vector<FrontendProtocolHintStatsDto> build_protocol_hint_stats(const CaptureProtocolSummary& summary) {
    const auto shared_rows = session_detail::build_protocol_hint_statistics_rows(summary);
    std::vector<FrontendProtocolHintStatsDto> rows {};
    rows.reserve(shared_rows.size());

    for (const auto& row : shared_rows) {
        rows.push_back(FrontendProtocolHintStatsDto {
            .group = row.group,
            .protocol_label = row.protocol_label,
            .flow_count = row.flow_count,
            .flow_count_text = row.flow_count_text,
            .packet_count = row.packet_count,
            .packet_count_text = row.packet_count_text,
            .captured_bytes = row.captured_bytes,
            .captured_bytes_text = row.captured_bytes_text,
            .original_bytes = row.original_bytes,
            .original_bytes_text = row.original_bytes_text,
        });
    }

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

std::string format_size_value(const std::uint64_t value);

double safe_percent(const std::uint64_t numerator, const std::uint64_t denominator) {
    if (denominator == 0U) {
        return 0.0;
    }

    return (static_cast<double>(numerator) * 100.0) / static_cast<double>(denominator);
}

FrontendInputKind frontend_input_kind_for_session(const CaptureSession& session) {
    if (session.opened_from_index()) {
        return FrontendInputKind::pcap_flow_lab_index;
    }

    switch (session.source_info().format) {
    case CaptureSourceFormat::classic_pcap:
        return FrontendInputKind::classic_pcap;
    case CaptureSourceFormat::pcapng:
        return FrontendInputKind::pcapng;
    case CaptureSourceFormat::unknown:
    default:
        return FrontendInputKind::unknown;
    }
}

FrontendInputMetadataDto build_frontend_input_metadata(const CaptureSession& session) {
    FrontendInputMetadataDto metadata {};
    metadata.input_path = path_to_string(session.input_path());
    metadata.input_kind = frontend_input_kind_for_session(session);
    metadata.input_file_size = session.input_file_size();
    metadata.source_capture_accessible = session.source_capture_accessible();

    if (session.opened_from_index() && !session.expected_source_capture_path().empty()) {
        metadata.source_capture_path = path_to_string(session.expected_source_capture_path());
    }

    return metadata;
}

FrontendCapturePacketSizeStatisticsDto build_capture_packet_size_statistics_dto(
    const CapturePacketStatistics& statistics
) {
    FrontendCapturePacketSizeStatisticsDto dto {};
    dto.has_capture = true;
    dto.total_packet_count = statistics.total_packet_count;
    dto.maximum_captured_bucket_packet_count = statistics.captured_size_distribution.maximum_bucket_packet_count;
    dto.maximum_original_bucket_packet_count = statistics.original_size_distribution.maximum_bucket_packet_count;
    dto.maximum_captured_packet_length = statistics.maximum_captured_packet_length;
    dto.maximum_captured_packet_length_text = session_detail::format_statistics_size_value(
        statistics.maximum_captured_packet_length
    );
    dto.maximum_original_packet_length = statistics.maximum_original_packet_length;
    dto.maximum_original_packet_length_text = session_detail::format_statistics_size_value(
        statistics.maximum_original_packet_length
    );
    dto.buckets.reserve(statistics.captured_size_distribution.buckets.size());

    for (std::size_t index = 0U; index < statistics.captured_size_distribution.buckets.size(); ++index) {
        const auto& captured_bucket = statistics.captured_size_distribution.buckets[index];
        const auto& original_bucket = statistics.original_size_distribution.buckets[index];
        dto.buckets.push_back(FrontendCapturePacketSizeStatisticsBucketDto {
            .bucket_id = std::string(captured_bucket.stable_id),
            .label = session_detail::capture_packet_size_bucket_label(captured_bucket),
            .lower_bound_inclusive = captured_bucket.lower_bound_inclusive,
            .upper_bound_inclusive = captured_bucket.upper_bound_inclusive,
            .captured_packet_count = captured_bucket.packet_count,
            .captured_packet_count_text = session_detail::format_statistics_count_value(captured_bucket.packet_count),
            .captured_total_fraction = statistics.total_packet_count > 0U
                ? static_cast<double>(captured_bucket.packet_count) / static_cast<double>(statistics.total_packet_count)
                : 0.0,
            .captured_total_percent_text = session_detail::format_statistics_percent_text(
                safe_percent(captured_bucket.packet_count, statistics.total_packet_count)
            ),
            .captured_normalized_fraction = statistics.captured_size_distribution.maximum_bucket_packet_count > 0U
                ? static_cast<double>(captured_bucket.packet_count)
                    / static_cast<double>(statistics.captured_size_distribution.maximum_bucket_packet_count)
                : 0.0,
            .original_packet_count = original_bucket.packet_count,
            .original_packet_count_text = session_detail::format_statistics_count_value(original_bucket.packet_count),
            .original_total_fraction = statistics.total_packet_count > 0U
                ? static_cast<double>(original_bucket.packet_count) / static_cast<double>(statistics.total_packet_count)
                : 0.0,
            .original_total_percent_text = session_detail::format_statistics_percent_text(
                safe_percent(original_bucket.packet_count, statistics.total_packet_count)
            ),
            .original_normalized_fraction = statistics.original_size_distribution.maximum_bucket_packet_count > 0U
                ? static_cast<double>(original_bucket.packet_count)
                    / static_cast<double>(statistics.original_size_distribution.maximum_bucket_packet_count)
                : 0.0,
        });
    }

    return dto;
}

FrontendFlowPacketCountHistogramDto build_flow_packet_count_histogram_dto(
    const FlowPacketCountHistogram& histogram
) {
    FrontendFlowPacketCountHistogramDto dto {};
    dto.has_capture = true;
    dto.total_flow_count = histogram.total_flow_count;
    dto.total_captured_byte_count = histogram.total_captured_byte_count;
    dto.total_original_byte_count = histogram.total_original_byte_count;
    dto.maximum_bucket_flow_count = histogram.maximum_bucket_flow_count;
    dto.maximum_bucket_captured_byte_count = histogram.maximum_bucket_captured_byte_count;
    dto.maximum_bucket_original_byte_count = histogram.maximum_bucket_original_byte_count;
    dto.excluded_zero_packet_flow_count = histogram.excluded_zero_packet_flow_count;
    dto.excluded_zero_packet_captured_byte_count = histogram.excluded_zero_packet_captured_byte_count;
    dto.excluded_zero_packet_original_byte_count = histogram.excluded_zero_packet_original_byte_count;
    dto.buckets.reserve(histogram.buckets.size());

    for (const auto& bucket : histogram.buckets) {
        dto.buckets.push_back(FrontendFlowPacketCountHistogramBucketDto {
            .bucket_id = bucket.stable_id,
            .label = session_detail::format_statistics_bucket_label(
                bucket.lower_bound_inclusive,
                bucket.upper_bound_inclusive
            ),
            .lower_bound_inclusive = bucket.lower_bound_inclusive,
            .upper_bound_inclusive = bucket.upper_bound_inclusive,
            .flow_count = bucket.flow_count,
            .flow_count_with_total_percent_text = session_detail::format_statistics_count_with_percent_text(
                bucket.flow_count,
                safe_percent(bucket.flow_count, histogram.total_flow_count)
            ),
            .captured_byte_count = bucket.captured_byte_count,
            .captured_byte_count_text = format_size_value(bucket.captured_byte_count),
            .captured_byte_count_with_total_percent_text = session_detail::format_statistics_size_with_percent_text(
                bucket.captured_byte_count,
                safe_percent(bucket.captured_byte_count, histogram.total_captured_byte_count)
            ),
            .original_byte_count = bucket.original_byte_count,
            .original_byte_count_text = format_size_value(bucket.original_byte_count),
            .original_byte_count_with_total_percent_text = session_detail::format_statistics_size_with_percent_text(
                bucket.original_byte_count,
                safe_percent(bucket.original_byte_count, histogram.total_original_byte_count)
            ),
            .total_flow_fraction = histogram.total_flow_count > 0U
                ? static_cast<double>(bucket.flow_count) / static_cast<double>(histogram.total_flow_count)
                : 0.0,
            .total_captured_byte_fraction = histogram.total_captured_byte_count > 0U
                ? static_cast<double>(bucket.captured_byte_count) / static_cast<double>(histogram.total_captured_byte_count)
                : 0.0,
            .total_original_byte_fraction = histogram.total_original_byte_count > 0U
                ? static_cast<double>(bucket.original_byte_count) / static_cast<double>(histogram.total_original_byte_count)
                : 0.0,
            .normalized_flow_fraction = histogram.maximum_bucket_flow_count > 0U
                ? static_cast<double>(bucket.flow_count) / static_cast<double>(histogram.maximum_bucket_flow_count)
                : 0.0,
            .normalized_captured_byte_fraction = histogram.maximum_bucket_captured_byte_count > 0U
                ? static_cast<double>(bucket.captured_byte_count)
                    / static_cast<double>(histogram.maximum_bucket_captured_byte_count)
                : 0.0,
            .normalized_original_byte_fraction = histogram.maximum_bucket_original_byte_count > 0U
                ? static_cast<double>(bucket.original_byte_count)
                    / static_cast<double>(histogram.maximum_bucket_original_byte_count)
                : 0.0,
        });
    }

    return dto;
}

std::vector<FrontendProtocolPathStatsDto> build_protocol_path_statistics(const CaptureProtocolPathSummary& summary) {
    std::vector<FrontendProtocolPathStatsDto> rows {};
    rows.reserve(summary.rows.size());

    for (const auto& row : summary.rows) {
        session_detail::AdvancedFlowFilterProtocolPathPredicate predicate {
            .match_kind = ProtocolPathStatisticsMode::terminal_paths == summary.mode
                ? session_detail::AdvancedFlowFilterProtocolPathMatchKind::exact_path
                : session_detail::AdvancedFlowFilterProtocolPathMatchKind::path_prefix,
        };
        predicate.layers.reserve(row.path.layers().size());
        for (const auto& layer : row.path.layers()) {
            predicate.layers.push_back(session_detail::AdvancedFlowFilterProtocolLayerPredicate {
                .kind = layer.kind,
                .identifier = layer.identifier.kind != ProtocolLayerIdentifierKind::none
                    ? std::optional {layer.identifier}
                    : std::nullopt,
            });
        }
        if (summary.mode == ProtocolPathStatisticsMode::kind_overview) {
            for (auto& layer : predicate.layers) {
                layer.identifier.reset();
            }
        }

        const auto predicate_text =
            format_advanced_flow_filter_protocol_path_predicate_text(predicate).value_or(std::string {});
        rows.push_back(FrontendProtocolPathStatsDto {
            .node_id = row.node_id,
            .parent_node_id = row.parent_node_id,
            .depth = row.depth,
            .layer_text = row.layer_text,
            .path_text = row.path_text,
            .compact_text = row.compact_text,
            .advanced_filter_predicate_text = std::move(predicate_text),
            .badges = row.badges,
            .has_children = row.has_children,
            .is_terminal = row.is_terminal,
            .flow_count = row.flow_count,
            .packet_count = row.packet_count,
            .original_byte_count = row.original_byte_count,
            .flow_percent = row.flow_percent,
            .packet_percent = row.packet_percent,
            .original_byte_percent = row.original_byte_percent,
            .flow_count_text = row.flow_count_text,
            .packet_count_text = row.packet_count_text,
            .original_byte_count_text = row.original_byte_count_text,
        });
    }

    return rows;
}

bool protocol_path_layers_have_identifiers(const std::vector<LayerKey>& layers) noexcept {
    return std::any_of(layers.begin(), layers.end(), [](const LayerKey& layer) {
        return layer.identifier.kind != ProtocolLayerIdentifierKind::none;
    });
}

std::vector<LayerKey> protocol_path_layers_from_predicate(
    const std::vector<session_detail::AdvancedFlowFilterProtocolLayerPredicate>& layers
) {
    std::vector<LayerKey> converted {};
    converted.reserve(layers.size());
    for (const auto& layer : layers) {
        converted.push_back(LayerKey {
            .kind = layer.kind,
            .identifier = layer.identifier.value_or(ProtocolLayerIdentifier {}),
        });
    }
    return converted;
}

ProtocolPathStatisticsMode protocol_path_selector_mode_for_predicate(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    if (predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::exact_path) {
        return ProtocolPathStatisticsMode::terminal_paths;
    }

    return protocol_path_layers_have_identifiers(protocol_path_layers_from_predicate(predicate.layers))
        ? ProtocolPathStatisticsMode::identity_tree
        : ProtocolPathStatisticsMode::kind_overview;
}

bool protocol_path_contains_layer_matches(
    const ProtocolPath& path,
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) {
    if (predicate.layers.size() != 1U) {
        return false;
    }

    const auto& target = predicate.layers.front();
    for (const auto& layer : path.layers()) {
        if (layer.kind != target.kind) {
            continue;
        }
        if (!target.identifier.has_value()) {
            return true;
        }
        if (layer.identifier == target.identifier) {
            return true;
        }
    }
    return false;
}

std::optional<bool> protocol_path_predicate_applicability(
    const CaptureSession& session,
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) {
    if (!session.has_capture()) {
        return std::nullopt;
    }

    if (predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::contains_layer) {
        const auto summary = session.protocol_path_summary(ProtocolPathStatisticsMode::terminal_paths);
        return std::any_of(summary.rows.begin(), summary.rows.end(), [&](const auto& row) {
            return protocol_path_contains_layer_matches(row.path, predicate);
        });
    }

    const auto summary = session.protocol_path_summary(protocol_path_selector_mode_for_predicate(predicate));
    const auto predicate_layers = protocol_path_layers_from_predicate(predicate.layers);
    return std::any_of(summary.rows.begin(), summary.rows.end(), [&](const auto& row) {
        return row.path.layers() == predicate_layers;
    });
}

std::vector<FrontendProtocolPathPresentationDto> build_protocol_path_presentations(const CaptureSession& session) {
    std::vector<FrontendProtocolPathPresentationDto> rows {};
    const auto& registry = session.state().protocol_path_registry;
    rows.reserve(registry.size());

    for (ProtocolPathId protocol_path_id = 1U;
         protocol_path_id <= static_cast<ProtocolPathId>(registry.size());
         ++protocol_path_id) {
        const auto presentation = session_detail::build_protocol_path_presentation(registry, protocol_path_id);
        rows.push_back(FrontendProtocolPathPresentationDto {
            .protocol_path_id = protocol_path_id,
            .path_text = std::move(presentation.full_text),
            .compact_text = std::move(presentation.compact_text),
            .badges = std::move(presentation.badges),
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

    if (details.has_ah && details.ah.has_inner_packet && details.ah.inner_packet) {
        if (details.ah.inner_packet->has_tcp) {
            out << "Inner TCP "
                << details.ah.inner_packet->tcp.src_port << " -> " << details.ah.inner_packet->tcp.dst_port
                << " Flags: " << session_detail::format_tcp_flags_text(details.ah.inner_packet->tcp.flags);
            return out.str();
        }

        if (details.ah.inner_packet->has_udp) {
            out << "Inner UDP "
                << details.ah.inner_packet->udp.src_port << " -> " << details.ah.inner_packet->udp.dst_port;
            return out.str();
        }
    }

    if (details.has_ip_encapsulation) {
        if (details.ip_encapsulation.has_tcp) {
            out << "Inner TCP "
                << details.ip_encapsulation.tcp.src_port << " -> " << details.ip_encapsulation.tcp.dst_port
                << " Flags: " << session_detail::format_tcp_flags_text(details.ip_encapsulation.tcp.flags);
            return out.str();
        }

        if (details.ip_encapsulation.has_udp) {
            out << "Inner UDP "
                << details.ip_encapsulation.udp.src_port << " -> " << details.ip_encapsulation.udp.dst_port;
            return out.str();
        }

        if (details.ip_encapsulation.has_icmp) {
            out << "Inner ICMP type " << static_cast<unsigned>(details.ip_encapsulation.icmp.type)
                << ", code " << static_cast<unsigned>(details.ip_encapsulation.icmp.code);
            return out.str();
        }

        if (details.ip_encapsulation.has_icmpv6) {
            out << "Inner ICMPv6 type " << static_cast<unsigned>(details.ip_encapsulation.icmpv6.type)
                << ", code " << static_cast<unsigned>(details.ip_encapsulation.icmpv6.code);
            return out.str();
        }
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

std::string flow_packet_direction_text(const Direction direction) {
    switch (direction) {
    case Direction::a_to_b:
        return "A -> B";
    case Direction::b_to_a:
        return "B -> A";
    default:
        return {};
    }
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
    case detail::kIpProtocolEsp:
        return "ESP";
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
    const bool source_capture_accessible,
    const session_detail::TransientPacketDerivedMetadata& metadata = {}
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
    if (metadata.is_ip_fragmented.value_or(false)) {
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

    if (details->has_ip_encapsulation && !details->ip_encapsulation.inner_ip_layers.empty()) {
        for (const auto& inner : details->ip_encapsulation.inner_ip_layers) {
            if (inner.has_ipv4) {
                auto section_lines = std::vector<std::string> {};
                if (details->ip_encapsulation.inner_header_truncated) {
                    section_lines.push_back(
                        "Available Header Bytes: " + std::to_string(details->ip_encapsulation.available_inner_bytes) +
                        " / " + std::to_string(details->ip_encapsulation.required_inner_header_bytes)
                    );
                    if (details->ip_encapsulation.available_inner_bytes >= 10U) {
                        section_lines.push_back("Protocol: " + format_protocol_value(inner.ipv4.protocol));
                    }
                    if (details->ip_encapsulation.available_inner_bytes >= 16U) {
                        section_lines.push_back("Source: " + session_detail::format_ipv4_address(inner.ipv4.src_addr));
                    }
                    if (details->ip_encapsulation.available_inner_bytes >= 20U) {
                        section_lines.push_back("Destination: " + session_detail::format_ipv4_address(inner.ipv4.dst_addr));
                    }
                    section_lines.push_back("Warning: Inner IPv4 header is truncated");
                } else {
                    section_lines.push_back("Source: " + session_detail::format_ipv4_address(inner.ipv4.src_addr));
                    section_lines.push_back("Destination: " + session_detail::format_ipv4_address(inner.ipv4.dst_addr));
                    section_lines.push_back("Protocol: " + format_protocol_value(inner.ipv4.protocol));
                }
                append_summary_section(lines, "Inner IPv4", section_lines);
            } else if (inner.has_ipv6) {
                auto section_lines = std::vector<std::string> {};
                if (details->ip_encapsulation.inner_header_truncated) {
                    section_lines.push_back(
                        "Available Header Bytes: " + std::to_string(details->ip_encapsulation.available_inner_bytes) +
                        " / " + std::to_string(details->ip_encapsulation.required_inner_header_bytes)
                    );
                    if (details->ip_encapsulation.available_inner_bytes >= 8U) {
                        section_lines.push_back("Next Header: " + format_protocol_value(inner.ipv6.next_header));
                    }
                    if (details->ip_encapsulation.available_inner_bytes >= 24U) {
                        section_lines.push_back("Source: " + session_detail::format_ipv6_address(inner.ipv6.src_addr));
                    }
                    if (details->ip_encapsulation.available_inner_bytes >= 40U) {
                        section_lines.push_back("Destination: " + session_detail::format_ipv6_address(inner.ipv6.dst_addr));
                    }
                    section_lines.push_back("Warning: Inner IPv6 header is truncated");
                } else {
                    section_lines.push_back("Source: " + session_detail::format_ipv6_address(inner.ipv6.src_addr));
                    section_lines.push_back("Destination: " + session_detail::format_ipv6_address(inner.ipv6.dst_addr));
                    section_lines.push_back("Next Header: " + format_protocol_value(inner.ipv6.next_header));
                }
                append_summary_section(lines, "Inner IPv6", section_lines);
            }
        }
    }

    if (details->has_tcp) {
        auto tcp_lines = std::vector<std::string> {
            "Source Port: " + std::to_string(details->tcp.src_port),
            "Destination Port: " + std::to_string(details->tcp.dst_port),
            "Flags: " + session_detail::format_tcp_flags_text(details->tcp.flags),
        };
        if (metadata.original_transport_payload_length.has_value()) {
            if (metadata.captured_transport_payload_length.has_value() &&
                *metadata.captured_transport_payload_length != *metadata.original_transport_payload_length) {
                tcp_lines.push_back("Real Payload Length: " + std::to_string(*metadata.captured_transport_payload_length));
                tcp_lines.push_back("Original Payload Length: " + std::to_string(*metadata.original_transport_payload_length));
            } else {
                tcp_lines.push_back("Payload Length: " + std::to_string(*metadata.original_transport_payload_length));
            }
        } else if (metadata.captured_transport_payload_length.has_value()) {
            tcp_lines.push_back("Payload Length: " + std::to_string(*metadata.captured_transport_payload_length));
        }
        append_summary_section(lines, "TCP", tcp_lines);
    }

    if (details->has_udp) {
        auto udp_lines = std::vector<std::string> {
            "Source Port: " + std::to_string(details->udp.src_port),
            "Destination Port: " + std::to_string(details->udp.dst_port),
        };
        if (metadata.original_transport_payload_length.has_value()) {
            if (metadata.captured_transport_payload_length.has_value() &&
                *metadata.captured_transport_payload_length != *metadata.original_transport_payload_length) {
                udp_lines.push_back("Real Payload Length: " + std::to_string(*metadata.captured_transport_payload_length));
                udp_lines.push_back("Original Payload Length: " + std::to_string(*metadata.original_transport_payload_length));
            } else {
                udp_lines.push_back("Payload Length: " + std::to_string(*metadata.original_transport_payload_length));
            }
        } else if (metadata.captured_transport_payload_length.has_value()) {
            udp_lines.push_back("Payload Length: " + std::to_string(*metadata.captured_transport_payload_length));
        }
        append_summary_section(lines, "UDP", udp_lines);
    }

    if (details->has_ip_encapsulation && details->ip_encapsulation.has_tcp) {
        append_summary_section(lines, "Inner TCP", {
            "Source Port: " + std::to_string(details->ip_encapsulation.tcp.src_port),
            "Destination Port: " + std::to_string(details->ip_encapsulation.tcp.dst_port),
            "Flags: " + session_detail::format_tcp_flags_text(details->ip_encapsulation.tcp.flags),
        });
    }

    if (details->has_ip_encapsulation && details->ip_encapsulation.has_udp) {
        append_summary_section(lines, "Inner UDP", {
            "Source Port: " + std::to_string(details->ip_encapsulation.udp.src_port),
            "Destination Port: " + std::to_string(details->ip_encapsulation.udp.dst_port),
            "Length: " + std::to_string(details->ip_encapsulation.udp.length),
        });
    }

    if (details->has_ip_encapsulation && details->ip_encapsulation.has_icmp) {
        append_summary_section(lines, "Inner ICMP", {
            "Type: " + std::to_string(details->ip_encapsulation.icmp.type),
            "Code: " + std::to_string(details->ip_encapsulation.icmp.code),
        });
    }

    if (details->has_ip_encapsulation && details->ip_encapsulation.has_icmpv6) {
        append_summary_section(lines, "Inner ICMPv6", {
            "Type: " + std::to_string(details->ip_encapsulation.icmpv6.type),
            "Code: " + std::to_string(details->ip_encapsulation.icmpv6.code),
        });
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

std::string stream_item_details_source_text(const StreamItemRow& row) {
    return session_detail::stream_item_details_source_text(row);
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
    if (row.tls_semantic_kind == TlsStreamItemSemanticKind::partial_record ||
        row.tls_semantic_kind == TlsStreamItemSemanticKind::partial_payload ||
        (row.http_summary.has_value() && row.http_summary->semantic_kind == HttpStreamItemSemanticKind::partial_payload) ||
        row.materialization_stability == StreamMaterializationStability::window_incomplete) {
        return "Partial";
    }
    if (session_detail::stream_item_uses_packet_fallback(row)) {
        return "Packet fallback";
    }
    if (row.packet_count > 1U) {
        return "Reassembled";
    }
    return {};
}

std::string stream_item_payload_tab_title() {
    return "Item Data";
}

FrontendStreamItemDto::StreamItemDataDto build_frontend_stream_item_data(
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::size_t max_packets_to_scan,
    const std::size_t limit,
    const std::uint64_t stream_item_index
) {
    const auto presentation = session.derive_selected_flow_stream_item_data(
        flow_index,
        max_packets_to_scan,
        limit,
        stream_item_index
    );
    const auto formatted_text = session.format_selected_flow_stream_item_data_hex_dump(
        flow_index,
        max_packets_to_scan,
        limit,
        stream_item_index
    );
    const auto item_data_requires_materialization =
        presentation.source_kind != session_detail::StreamItemDataSourceKind::unavailable &&
        presentation.state != session_detail::StreamItemDataState::synthetic;
    const auto status_text = formatted_text.has_value() || !item_data_requires_materialization
        ? session_detail::format_selected_stream_item_data_status_text(presentation)
        : std::string {
            "Item data unavailable • Failed to materialize the selected item bytes."
        };
    const auto available = formatted_text.has_value();

    return FrontendStreamItemDto::StreamItemDataDto {
        .available = available,
        .semantic_kind = session_detail::to_string(
            available || !item_data_requires_materialization
                ? presentation.semantic_kind
                : session_detail::StreamItemDataSemanticKind::other),
        .source_kind = session_detail::to_string(
            available || !item_data_requires_materialization
                ? presentation.source_kind
                : session_detail::StreamItemDataSourceKind::unavailable),
        .state = session_detail::to_string(
            available || !item_data_requires_materialization
                ? presentation.state
                : session_detail::StreamItemDataState::unavailable),
        .assembly_kind = session_detail::to_string(presentation.assembly_kind),
        .available_length = presentation.available_length,
        .declared_length = presentation.declared_length.has_value()
            ? std::optional<std::uint64_t> {static_cast<std::uint64_t>(*presentation.declared_length)}
            : std::optional<std::uint64_t> {},
        .contributing_unit_kind =
            presentation.contributing_unit_kind.has_value()
                ? std::optional<std::string> {session_detail::to_string(*presentation.contributing_unit_kind)}
                : std::optional<std::string> {},
        .contributing_unit_count =
            presentation.contributing_unit_count.has_value()
                ? std::optional<std::uint64_t> {static_cast<std::uint64_t>(*presentation.contributing_unit_count)}
                : std::optional<std::uint64_t> {},
        .logical_offset = presentation.quic_crypto_stream_offset,
        .status_text = status_text,
        .formatted_text = formatted_text.value_or(std::string {}),
        .unavailable_text = available
            ? std::string {}
            : (!presentation.unavailable_reason.empty()
                ? presentation.unavailable_reason
                : "No authoritative item-owned byte sequence is retained for this Stream item."),
    };
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

std::vector<session_detail::PacketSummaryLayer> build_stream_item_summary_layers(
    const StreamItemRow& row,
    const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers
) {
    return session_detail::build_stream_item_summary_layers(
        row,
        format_stream_source_packets_text(row, flow_packet_numbers)
    );
}

std::string format_byte_count_text(const std::size_t count) {
    return std::to_string(count) + (count == 1U ? " byte" : " bytes");
}

std::string packet_byte_view_state_text(const std::string_view state) {
    if (state == "complete") {
        return "Complete";
    }
    if (state == "partial") {
        return "Partial";
    }
    if (state == "truncated") {
        return "Truncated";
    }
    return "Unavailable";
}

std::string packet_byte_view_contributing_unit_text(
    const std::string_view unit_kind,
    const std::uint32_t count
) {
    if (unit_kind == "tcp_segment") {
        return count == 1U ? "TCP segment" : "TCP segments";
    }
    if (unit_kind == "quic_crypto_frame") {
        return count == 1U ? "CRYPTO frame" : "CRYPTO frames";
    }
    return count == 1U ? "unit" : "units";
}

std::string packet_byte_view_status_text(
    const std::string_view state,
    const std::string_view assembly_kind,
    const std::optional<std::uint32_t>& contributing_unit_count,
    const std::optional<std::string>& contributing_unit_kind,
    const std::uint32_t available_length,
    const std::optional<std::uint32_t>& declared_length
) {
    auto status = packet_byte_view_state_text(state);
    if (assembly_kind == "reassembled") {
        status += " \xE2\x80\xA2 Reassembled";
        if (contributing_unit_count.has_value() && contributing_unit_kind.has_value()) {
            status += " from " + std::to_string(*contributing_unit_count) + ' ' +
                packet_byte_view_contributing_unit_text(*contributing_unit_kind, *contributing_unit_count);
        }
    }
    status += " \xE2\x80\xA2 Available: " + format_byte_count_text(available_length);
    if (declared_length.has_value()) {
        status += " \xE2\x80\xA2 Declared: " + format_byte_count_text(*declared_length);
    }
    return status;
}

std::vector<FrontendPacketDetailsDto::PacketByteViewDescriptor> build_frontend_packet_byte_view_descriptors(
    const std::vector<session_detail::SelectedPacketByteViewPresentationDescriptor>& descriptors
) {
    std::vector<FrontendPacketDetailsDto::PacketByteViewDescriptor> items {};
    items.reserve(descriptors.size());
    for (const auto& descriptor : descriptors) {
        items.push_back(FrontendPacketDetailsDto::PacketByteViewDescriptor {
            .stable_id = descriptor.stable_id,
            .label = descriptor.label,
            .parent_stable_id = descriptor.parent_stable_id,
            .depth = descriptor.depth,
            .owner_kind = descriptor.owner_kind,
            .role = descriptor.role,
            .assembly_kind = descriptor.assembly_kind,
            .available_length = descriptor.available_length,
            .declared_length = descriptor.declared_length,
            .state = descriptor.state,
            .supports_payload_only = descriptor.supports_payload_only,
            .payload_available_length = descriptor.payload_available_length,
            .payload_declared_length = descriptor.payload_declared_length,
            .payload_state = descriptor.payload_state,
            .contributing_unit_count = descriptor.contributing_unit_count,
            .contributing_unit_kind = descriptor.contributing_unit_kind,
            .quic_crypto_stream_offset = descriptor.quic_crypto_stream_offset,
        });
    }
    return items;
}

std::optional<session_detail::SelectedPacketByteViewId> select_default_packet_byte_view_id(
    const std::vector<session_detail::SelectedPacketByteViewPresentationDescriptor>& descriptors
) {
    const auto frame_it = std::find_if(
        descriptors.begin(),
        descriptors.end(),
        [](const session_detail::SelectedPacketByteViewPresentationDescriptor& descriptor) {
            return descriptor.stable_id == "frame:0:0";
        }
    );
    if (frame_it != descriptors.end()) {
        return session_detail::parse_selected_packet_byte_view_stable_id(frame_it->stable_id);
    }
    if (!descriptors.empty()) {
        return session_detail::parse_selected_packet_byte_view_stable_id(descriptors.front().stable_id);
    }
    return std::nullopt;
}

std::optional<session_detail::SelectedPacketBytePresentation> derive_frontend_packet_byte_presentation(
    CaptureSession& session,
    const PacketRef& packet,
    const std::vector<std::uint8_t>& packet_bytes,
    const std::optional<PacketDetails>& details,
    const std::optional<std::size_t> flow_index,
    const std::optional<std::uint64_t> flow_packet_index,
    const std::optional<std::size_t> loaded_packet_window_count
) {
    if (packet_bytes.empty()) {
        return std::nullopt;
    }

    if (!details.has_value()) {
        return session_detail::build_captured_packet_fallback_presentation(packet);
    }

    const auto metadata = session_detail::derive_transient_packet_metadata(
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        packet
    );
    const auto internal_flow_packet_index =
        flow_packet_index.has_value()
            ? std::optional<std::uint64_t> {*flow_packet_index - 1U}
            : std::nullopt;
    auto packet_summary_preparation = session_detail::prepare_selected_packet_summary(
        session,
        *details,
        packet,
        flow_index,
        internal_flow_packet_index,
        loaded_packet_window_count,
        metadata.captured_transport_payload_length,
        metadata.original_transport_payload_length
    );
    return session_detail::build_selected_packet_byte_presentation(
        *details,
        packet,
        session_detail::SelectedPacketByteBuildOptions {
            .packet_bytes = std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
            .flow_packet_index = packet_summary_preparation.flow_packet_index,
            .packet_data = packet_summary_preparation.packet_data,
            .tls_initial_parser_context = packet_summary_preparation.tls_initial_parser_context,
            .reconstructed_tls_records = std::move(packet_summary_preparation.reconstructed_tls_records),
            .quic_presentation = std::move(packet_summary_preparation.quic_presentation),
        }
    );
}

std::string packet_lookup_error_text(const SourcePacketLookupStatus status) {
    switch (status) {
    case SourcePacketLookupStatus::found:
    case SourcePacketLookupStatus::out_of_range:
        return {};
    case SourcePacketLookupStatus::source_unavailable:
        return "Byte-backed packet details are unavailable because the original source capture cannot be read.";
    case SourcePacketLookupStatus::locator_unavailable:
        return "The requested packet cannot be located because source packet locators are unavailable for this input.";
    case SourcePacketLookupStatus::unsupported_format:
        return "The requested packet cannot be located because this source capture format is not supported by sparse packet lookup.";
    case SourcePacketLookupStatus::source_read_failed:
        return "The requested packet could not be read from the source capture.";
    }

    return "The requested packet could not be read from the source capture.";
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
    if (session_detail::derive_ip_fragmentation_state_from_packet_details(packet_bytes, packet, details).value_or(false)) {
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
    if (session_detail::derive_ip_fragmentation_state_from_packet_details(packet_bytes, packet, details).value_or(false)) {
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

FlowRow apply_service_hint_override(
    FlowRow row,
    const std::map<std::size_t, std::string>& overrides
) {
    const auto override_it = overrides.find(row.index);
    if (override_it != overrides.end() && row.service_hint.empty()) {
        row.service_hint = override_it->second;
    }
    return row;
}

std::string build_analysis_endpoint_summary(const FlowRow& row) {
    std::ostringstream out {};
    out << row.endpoint_a
        << " <-> "
        << row.endpoint_b;
    return out.str();
}

std::string flow_family_text(const FlowAddressFamily family) {
    return family == FlowAddressFamily::ipv6 ? "IPv6" : "IPv4";
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

        const auto metadata = session_detail::derive_transient_packet_metadata(session, packet);
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
            .transport_payload_length = metadata.original_transport_payload_length,
            .tcp_flags_text = metadata.tcp_flags.has_value()
                ? session_detail::format_tcp_flags_text(*metadata.tcp_flags)
                : packet_row.tcp_flags_text,
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
        .flow_grouping_ignores_vlan_and_mpls_layers = session_.flow_grouping_ignores_vlan_and_mpls_layers(),
        .flow_grouping_ignores_gtpu_teids = session_.flow_grouping_ignores_gtpu_teids(),
        .active_source_capture_path = path_to_string(session_.attached_source_capture_path()),
        .expected_source_capture_path = path_to_string(session_.expected_source_capture_path()),
    };
}

FrontendOpenResult FrontendSessionAdapter::open_capture(const std::filesystem::path& path) {
    cancel_and_join_open_worker();
    clear_selection();
    flow_service_hint_overrides_.clear();
    advanced_flow_filter_document_state_.clear_all();
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
        : session_.open_capture(path, CaptureImportOptions {.settings = analysis_settings});

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

FrontendOpenStartResult FrontendSessionAdapter::start_open_capture(const std::filesystem::path& path) {
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
    flow_service_hint_overrides_.clear();
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

    async_open_.worker = std::thread([this, path, open_as_index, analysis_settings, context]() {
        CaptureSession worker_session {};
        const bool opened = open_as_index
            ? worker_session.load_index(path, context.get())
            : worker_session.open_capture(path, CaptureImportOptions {.settings = analysis_settings}, context.get());
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
                .flow_grouping_ignores_vlan_and_mpls_layers = worker_session.flow_grouping_ignores_vlan_and_mpls_layers(),
                .flow_grouping_ignores_gtpu_teids = worker_session.flow_grouping_ignores_gtpu_teids(),
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
        flow_service_hint_overrides_.clear();
        advanced_flow_filter_document_state_.clear_all();
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

FrontendSourceAvailabilityDto FrontendSessionAdapter::source_availability() const {
    return current_source_availability();
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
    const bool ignore_vlan_layers_changed =
        settings_.ignore_vlan_and_mpls_layers_when_grouping_flows != settings.ignore_vlan_and_mpls_layers_when_grouping_flows;
    const bool ignore_gtpu_teids_changed =
        settings_.ignore_gtpu_teids_when_grouping_inner_flows != settings.ignore_gtpu_teids_when_grouping_inner_flows;
    settings_ = settings;

    if ((use_possible_tls_quic_changed || ignore_vlan_layers_changed || ignore_gtpu_teids_changed) && session_.has_capture()) {
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
    return export_flows_to_pcap(output_path, flow_indices);
}

FrontendExportSelectedFlowsResult FrontendSessionAdapter::export_flows_to_pcap(
    const std::filesystem::path& output_path,
    const std::vector<std::size_t>& flow_indices,
    const SmartSingleFileExportOptions& options
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

    if (!session_.export_flows_to_pcap(flow_indices, output_path, options)) {
        result.error_text = "Failed to export selected flows.";
        return result;
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendExportAllFlowsInfoCsvResult FrontendSessionAdapter::export_all_flows_info_csv(
    const std::filesystem::path& output_path
) const {
    FrontendExportAllFlowsInfoCsvResult result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (session_.summary().flow_count == 0U) {
        result.error_text = "No flows available for CSV export.";
        return result;
    }

    if (output_path.empty()) {
        result.error_text = "No output file selected.";
        return result;
    }

    std::string error_text {};
    if (!session_.export_all_flows_info_csv(output_path, &error_text)) {
        result.error_text = error_text.empty() ? "Failed to export all flows info CSV." : error_text;
        return result;
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendExportAllFlowsInfoCsvResult FrontendSessionAdapter::export_flows_info_csv(
    const std::filesystem::path& output_path,
    const std::vector<std::size_t>& flow_indices
) const {
    FrontendExportAllFlowsInfoCsvResult result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (output_path.empty()) {
        result.error_text = "No output file selected.";
        return result;
    }

    std::string error_text {};
    if (!session_.export_flows_info_csv(flow_indices, output_path, &error_text)) {
        result.error_text = error_text.empty() ? "Failed to export flows info CSV." : error_text;
        return result;
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendExportProtocolPathTreeResult FrontendSessionAdapter::export_protocol_path_tree(
    const ProtocolPathStatisticsMode mode,
    const std::filesystem::path& output_path
) const {
    FrontendExportProtocolPathTreeResult result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (output_path.empty()) {
        result.error_text = "No output file selected.";
        return result;
    }

    std::string error_text {};
    if (!session_.export_protocol_path_tree_text(
            mode,
            output_path,
            session_detail::TextExportOverwritePolicy::overwrite_existing,
            &error_text)) {
        result.error_text = error_text.empty() ? "Failed to export Protocol Path Tree." : error_text;
        return result;
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

std::vector<FrontendByteExportFormatDto> FrontendSessionAdapter::get_byte_export_formats() const {
    return frontend_byte_export_formats();
}

FrontendByteExportResult FrontendSessionAdapter::export_selected_flow_packet_byte_view(
    const std::uint64_t packet_index,
    const std::string& stable_id,
    const std::string& format_id,
    const std::filesystem::path& output_path,
    const std::uint64_t flow_packet_index,
    const std::uint64_t loaded_packet_window_count
) const {
    if (!session_.has_capture()) {
        return unavailable_byte_export_result("No capture is open.");
    }
    if (!selected_flow_index_.has_value()) {
        return unavailable_byte_export_result("No flow is selected.");
    }
    if (output_path.empty()) {
        return unavailable_byte_export_result("No output file selected.");
    }

    const auto parsed_format = session_detail::parse_byte_export_format_id(format_id);
    if (!parsed_format.has_value()) {
        return unavailable_byte_export_result("Unknown byte export format.");
    }

    const auto parsed_view_id = session_detail::parse_selected_packet_byte_view_stable_id(stable_id);
    if (!parsed_view_id.has_value()) {
        return unavailable_byte_export_result("The selected packet byte view is invalid.");
    }

    std::optional<PacketRef> packet {};
    if (flow_packet_index != 0U) {
        packet = session_.selected_flow_packet_at(*selected_flow_index_, flow_packet_index);
        if (!packet.has_value() || packet->packet_index != packet_index) {
            return unavailable_byte_export_result("The selected packet is unavailable.");
        }
    } else {
        if (!session_.selected_flow_exact_packet_number(*selected_flow_index_, packet_index).has_value()) {
            return unavailable_byte_export_result("The selected packet is unavailable.");
        }
        packet = session_.find_packet(packet_index);
        if (!packet.has_value()) {
            return unavailable_byte_export_result("The selected packet is unavailable.");
        }
    }

    static_cast<void>(loaded_packet_window_count);
    std::string error_text {};
    if (!session_.export_selected_packet_byte_view(
            *packet,
            *parsed_view_id,
            *parsed_format,
            output_path,
            &error_text)) {
        return unavailable_byte_export_result(
            error_text.empty() ? "Failed to export the selected packet byte view." : error_text
        );
    }

    return FrontendByteExportResult {
        .exported = true,
        .output_path = path_to_string(output_path),
        .error_text = {},
    };
}

FrontendByteExportResult FrontendSessionAdapter::export_unrecognized_packet_byte_view(
    const std::uint64_t packet_index,
    const std::string& stable_id,
    const std::string& format_id,
    const std::filesystem::path& output_path
) const {
    if (!session_.has_capture()) {
        return unavailable_byte_export_result("No capture is open.");
    }
    if (output_path.empty()) {
        return unavailable_byte_export_result("No output file selected.");
    }

    const auto parsed_format = session_detail::parse_byte_export_format_id(format_id);
    if (!parsed_format.has_value()) {
        return unavailable_byte_export_result("Unknown byte export format.");
    }

    const auto parsed_view_id = session_detail::parse_selected_packet_byte_view_stable_id(stable_id);
    if (!parsed_view_id.has_value()) {
        return unavailable_byte_export_result("The selected packet byte view is invalid.");
    }

    const auto packet = session_.find_packet(packet_index);
    if (!packet.has_value()) {
        return unavailable_byte_export_result("The selected packet is unavailable.");
    }

    const auto matches_unrecognized = std::any_of(
        session_.state().unrecognized_packets.begin(),
        session_.state().unrecognized_packets.end(),
        [packet_index](const UnrecognizedPacketRecord& record) {
            return record.packet.packet_index == packet_index;
        }
    );
    if (!matches_unrecognized) {
        return unavailable_byte_export_result("The selected packet is unavailable in the unrecognized packet context.");
    }

    std::string error_text {};
    if (!session_.export_selected_packet_byte_view(
            *packet,
            *parsed_view_id,
            *parsed_format,
            output_path,
            &error_text)) {
        return unavailable_byte_export_result(
            error_text.empty() ? "Failed to export the selected packet byte view." : error_text
        );
    }

    return FrontendByteExportResult {
        .exported = true,
        .output_path = path_to_string(output_path),
        .error_text = {},
    };
}

FrontendByteExportResult FrontendSessionAdapter::export_selected_flow_stream_item_data(
    const std::size_t max_packets_to_scan,
    const std::size_t limit,
    const std::uint64_t stream_item_index,
    const std::string& format_id,
    const std::filesystem::path& output_path
) const {
    if (!session_.has_capture()) {
        return unavailable_byte_export_result("No capture is open.");
    }
    if (!selected_flow_index_.has_value()) {
        return unavailable_byte_export_result("No flow is selected.");
    }
    if (output_path.empty()) {
        return unavailable_byte_export_result("No output file selected.");
    }

    const auto parsed_format = session_detail::parse_byte_export_format_id(format_id);
    if (!parsed_format.has_value()) {
        return unavailable_byte_export_result("Unknown byte export format.");
    }

    std::string error_text {};
    if (!session_.export_selected_flow_stream_item_data(
            *selected_flow_index_,
            max_packets_to_scan,
            limit,
            stream_item_index,
            *parsed_format,
            output_path,
            &error_text)) {
        return unavailable_byte_export_result(
            error_text.empty() ? "Failed to export the selected stream item data." : error_text
        );
    }

    return FrontendByteExportResult {
        .exported = true,
        .output_path = path_to_string(output_path),
        .error_text = {},
    };
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

        return export_smart_flows_to_folder(output_path, request, SmartPerFlowExportOptions {
            .buffer_budget_bytes = options.per_flow_buffer_budget_bytes,
        });
    }

    return export_smart_flows_to_pcap(output_path, request);
}

FrontendSmartExportResult FrontendSessionAdapter::export_smart_flows_to_pcap(
    const std::filesystem::path& output_path,
    const SmartFlowExportRequest& request,
    const SmartSingleFileExportOptions& options
) const {
    FrontendSmartExportResult result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (request.flow_indices.empty()) {
        result.error_text = "No flows selected for smart export.";
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

    std::string error_text {};
    if (!session_.export_smart_flows_to_pcap(request, output_path, options, &error_text)) {
        result.error_text = error_text.empty() ? "Failed to smart-export flows." : error_text;
        return result;
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendSmartExportResult FrontendSessionAdapter::export_smart_flows_to_folder(
    const std::filesystem::path& output_path,
    const SmartFlowExportRequest& request,
    const SmartPerFlowExportOptions& options
) const {
    FrontendSmartExportResult result {};

    if (!session_.has_capture()) {
        result.error_text = "No capture is open.";
        return result;
    }

    if (request.flow_indices.empty()) {
        result.error_text = "No flows selected for smart export.";
        return result;
    }

    if (!session_.has_source_capture() || !session_.source_capture_accessible()) {
        result.error_text = "Original source capture is unavailable. Reattach the capture file to export flows.";
        return result;
    }

    if (output_path.empty()) {
        result.error_text = "No destination folder selected for smart export.";
        return result;
    }

    if (options.buffer_budget_bytes == 0U) {
        result.error_text = "Select a valid buffer memory budget preset for per-flow smart export.";
        return result;
    }

    std::string error_text {};
    if (!session_.export_smart_flows_to_folder(request, output_path, options, &error_text)) {
        result.error_text = error_text.empty() ? "Failed to smart-export flows." : error_text;
        return result;
    }

    result.exported = true;
    result.output_path = path_to_string(output_path);
    return result;
}

FrontendSmartExportResult FrontendSessionAdapter::export_smart_unrecognized_packets(
    const std::filesystem::path& output_path,
    const FrontendSmartExportOptions& options
) const {
    return export_smart_unrecognized_packets(output_path, options, SmartSingleFileExportOptions {});
}

FrontendSmartExportResult FrontendSessionAdapter::export_smart_unrecognized_packets(
    const std::filesystem::path& output_path,
    const FrontendSmartExportOptions& options,
    const SmartSingleFileExportOptions& export_options
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
    if (!session_.export_smart_unrecognized_packets_to_pcap(*retention, output_path, export_options, &error_text)) {
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
    const auto& packet_statistics = session_.packet_statistics();
    const auto flow_characteristics_statistics = session_.flow_characteristics_statistics();
    const auto packet_direction_distribution_statistics = session_.packet_direction_distribution_statistics();
    const auto original_byte_direction_distribution_statistics =
        session_.original_byte_direction_distribution_statistics();
    const auto unrecognized_packets = session_.unrecognized_packet_statistics();
    const auto protocol_path_presentations = build_protocol_path_presentations(session_);
    const auto input_metadata = build_frontend_input_metadata(session_);
    const auto capture_time = build_frontend_capture_time_statistics(packet_statistics);
    const auto capture_metrics = build_frontend_capture_metrics(packet_statistics);
    const auto flow_characteristics = build_frontend_flow_characteristics(flow_characteristics_statistics);
    const auto packet_direction_distribution = build_frontend_packet_direction_distribution(
        flow_characteristics_statistics,
        packet_direction_distribution_statistics
    );
    const auto original_byte_direction_distribution =
        build_frontend_original_byte_direction_distribution(
            flow_characteristics_statistics,
            original_byte_direction_distribution_statistics
        );
    const auto tcp_flag_statistics = build_frontend_tcp_flag_statistics(
        session_.tcp_flag_statistics(),
        protocol_summary.tcp.packet_count
    );
    const auto captured_bytes = protocol_summary.tcp.captured_bytes + protocol_summary.udp.captured_bytes +
        protocol_summary.sctp.captured_bytes + protocol_summary.other.captured_bytes;
    const auto original_bytes = protocol_summary.tcp.original_bytes + protocol_summary.udp.original_bytes +
        protocol_summary.sctp.original_bytes + protocol_summary.other.original_bytes;
    const auto whole_capture_packet_count = packet_statistics.total_packet_count;
    const auto whole_capture_captured_bytes = packet_statistics.total_captured_bytes;
    const auto whole_capture_original_bytes = packet_statistics.total_original_bytes;
    return FrontendOverviewDto {
        .has_capture = session_.has_capture(),
        .summary = FrontendOverviewSummaryDto {
            .packet_count = session_.summary().packet_count,
            .flow_count = session_.summary().flow_count,
            .captured_bytes = captured_bytes,
            .captured_bytes_text = session_detail::format_statistics_compact_size_value(captured_bytes),
            .original_bytes = original_bytes,
            .original_bytes_text = session_detail::format_statistics_compact_size_value(original_bytes),
            .total_bytes = session_.summary().total_bytes,
        },
        .whole_capture_totals = FrontendWholeCaptureTotalsDto {
            .packet_count = whole_capture_packet_count,
            .captured_bytes = whole_capture_captured_bytes,
            .captured_bytes_text = session_detail::format_statistics_compact_size_value(whole_capture_captured_bytes),
            .original_bytes = whole_capture_original_bytes,
            .original_bytes_text = session_detail::format_statistics_compact_size_value(whole_capture_original_bytes),
        },
        .input_metadata = std::move(input_metadata),
        .capture_time = std::move(capture_time),
        .capture_metrics = std::move(capture_metrics),
        .flow_characteristics = std::move(flow_characteristics),
        .packet_direction_distribution = std::move(packet_direction_distribution),
        .original_byte_direction_distribution = std::move(original_byte_direction_distribution),
        .tcp_flag_statistics = std::move(tcp_flag_statistics),
        .statistics_partial_open_warning_text =
            build_frontend_statistics_partial_open_warning_text(session_.is_partial_open()),
        .captured_bytes = captured_bytes,
        .original_bytes = original_bytes,
        .unrecognized_packet_count = session_.unrecognized_packet_count(),
        .unrecognized_packets = unrecognized_packets.packet_count > 0U
            ? std::optional<FrontendUnrecognizedPacketStatisticsDto> {
                FrontendUnrecognizedPacketStatisticsDto {
                    .packet_count = unrecognized_packets.packet_count,
                    .captured_bytes = unrecognized_packets.captured_bytes,
                    .captured_bytes_text =
                        session_detail::format_statistics_compact_size_value(unrecognized_packets.captured_bytes),
                    .original_bytes = unrecognized_packets.original_bytes,
                    .original_bytes_text =
                        session_detail::format_statistics_compact_size_value(unrecognized_packets.original_bytes),
                }
            }
            : std::nullopt,
        .protocol_summary = FrontendOverviewProtocolSummaryDto {
            .tcp = make_frontend_protocol_stats(protocol_summary.tcp),
            .udp = make_frontend_protocol_stats(protocol_summary.udp),
            .sctp = make_frontend_protocol_stats(protocol_summary.sctp),
            .other = make_frontend_protocol_stats(protocol_summary.other),
            .ipv4 = make_frontend_protocol_stats(protocol_summary.ipv4),
            .ipv6 = make_frontend_protocol_stats(protocol_summary.ipv6),
        },
        .protocol_path_statistics_default_mode = ProtocolPathStatisticsMode::kind_overview,
        .protocol_path_presentations = std::move(protocol_path_presentations),
    };
}

FrontendCapturePacketSizeStatisticsDto FrontendSessionAdapter::get_capture_packet_size_statistics() const {
    if (!session_.has_capture()) {
        return {};
    }

    return build_capture_packet_size_statistics_dto(session_.packet_statistics());
}

FrontendFlowPacketCountHistogramDto FrontendSessionAdapter::get_flow_packet_count_histogram() const {
    if (!session_.has_capture()) {
        return {};
    }

    return build_flow_packet_count_histogram_dto(session_.flow_packet_count_histogram());
}

FrontendProtocolHintStatisticsDto FrontendSessionAdapter::get_protocol_hint_statistics() const {
    if (!session_.has_capture()) {
        return {};
    }

    FrontendProtocolHintStatisticsDto dto {};
    dto.has_capture = true;
    dto.protocol_hints = build_protocol_hint_stats(session_.protocol_summary());
    return dto;
}

FrontendQuicTlsStatisticsDto FrontendSessionAdapter::get_quic_tls_statistics() const {
    if (!session_.has_capture()) {
        return {};
    }

    const auto summary = session_.quic_tls_summary();
    return FrontendQuicTlsStatisticsDto {
        .has_capture = true,
        .quic_recognition = summary.quic,
        .tls_recognition = summary.tls,
    };
}

FrontendTopEndpointPortStatisticsDto FrontendSessionAdapter::get_top_endpoint_port_statistics(const std::size_t limit) const {
    if (!session_.has_capture()) {
        return {};
    }

    const auto summary = session_.top_summary(limit);
    return FrontendTopEndpointPortStatisticsDto {
        .has_capture = true,
        .limit = limit,
        .top_endpoints = build_top_endpoints(summary),
        .top_ports = build_top_ports(summary),
    };
}

std::vector<FrontendFlowDto> FrontendSessionAdapter::get_flows() const {
    const auto rows = session_.list_flows();
    std::vector<FrontendFlowDto> flows {};
    flows.reserve(rows.size());

    for (const auto& row : rows) {
        flows.push_back(to_frontend_flow(apply_service_hint_override(row, flow_service_hint_overrides_)));
    }

    return flows;
}

session_detail::FlowQueryResult FrontendSessionAdapter::query_flows(const session_detail::FlowQuery& query) const {
    return session_.query_flows(query);
}

FrontendAdvancedFlowQueryResult FrontendSessionAdapter::query_advanced_flows(
    const session_detail::AdvancedFlowFilterSpec& filter_spec,
    const std::optional<std::vector<std::size_t>>& candidate_flow_indices,
    const std::optional<session_detail::FlowQuerySortSpec> sort,
    const std::optional<std::size_t> limit
) const {
    const auto query_result = session_.query_advanced_flows(filter_spec, candidate_flow_indices, sort, limit);
    switch (query_result.status) {
    case session_detail::AdvancedFlowQueryStatus::ok:
        return FrontendAdvancedFlowQueryResult {
            .status = FrontendAdvancedFlowQueryStatus::ok,
            .ordered_flow_indices = query_result.ordered_flow_indices,
            .result_count_before_limit = query_result.result_count_before_limit,
        };
    case session_detail::AdvancedFlowQueryStatus::invalid_flow_index:
        return FrontendAdvancedFlowQueryResult {
            .status = FrontendAdvancedFlowQueryStatus::invalid_flow_index,
            .invalid_flow_index = query_result.invalid_flow_index,
        };
    case session_detail::AdvancedFlowQueryStatus::invalid_limit:
        return FrontendAdvancedFlowQueryResult {
            .status = FrontendAdvancedFlowQueryStatus::invalid_limit,
        };
    case session_detail::AdvancedFlowQueryStatus::invalid_advanced_filter:
        return FrontendAdvancedFlowQueryResult {
            .status = FrontendAdvancedFlowQueryStatus::invalid_advanced_filter,
            .compile_status = query_result.compile_status,
            .compile_issue = query_result.compile_issue,
        };
    }

    return FrontendAdvancedFlowQueryResult {};
}

FrontendAdvancedFlowQueryResult FrontendSessionAdapter::query_advanced_flows_text(
    const std::string_view filter_text,
    const std::optional<std::vector<std::size_t>>& candidate_flow_indices,
    const std::optional<session_detail::FlowQuerySortSpec> sort,
    const std::optional<std::size_t> limit
) const {
    const auto parse_result = session_detail::parse_advanced_flow_filter_text(filter_text);
    if (parse_result.status != session_detail::AdvancedFlowFilterTextParseStatus::ok) {
        FrontendAdvancedFlowQueryResult result {};
        result.status = FrontendAdvancedFlowQueryStatus::invalid_filter_text;
        result.parse_status = parse_result.status;
        if (parse_result.issue.has_value()) {
            result.parse_issue = FrontendAdvancedFlowTextParseIssue {
                .status = parse_result.issue->status,
                .line = parse_result.issue->line,
                .column = parse_result.issue->column,
                .key = parse_result.issue->key,
                .token = parse_result.issue->token,
                .message = parse_result.issue->message,
            };
        }
        return result;
    }

    const auto configured_rule_count =
        session_detail::count_configured_advanced_flow_filter_atomic_rules(parse_result.document);
    const auto active_rule_count =
        session_detail::count_active_advanced_flow_filter_atomic_rules(parse_result.document);
    const auto effective_spec = session_detail::make_effective_advanced_flow_filter_spec(parse_result.document);
    auto result = query_advanced_flows(effective_spec, candidate_flow_indices, sort, limit);
    result.configured_rule_count = configured_rule_count;
    result.active_rule_count = active_rule_count;
    return result;
}

std::optional<FlowRow> FrontendSessionAdapter::flow_row(const std::size_t flow_index) const {
    return session_.flow_row(flow_index);
}

std::string FrontendSessionAdapter::protocol_path_compact_text(const ProtocolPathId protocol_path_id) const {
    return session_.protocol_path_compact_text(protocol_path_id);
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

FrontendSupportedProtocolCatalogDto FrontendSessionAdapter::get_supported_protocol_catalog() const {
    FrontendSupportedProtocolCatalogDto catalog {};
    const auto rows = session_detail::supported_protocol_catalog_rows();
    catalog.rows.reserve(rows.size());

    for (const auto& row : rows) {
        catalog.rows.push_back(FrontendSupportedProtocolCatalogRowDto {
            .category_id = std::string {session_detail::supported_protocol_category_stable_id(row.category)},
            .category_label = std::string {session_detail::supported_protocol_category_display_label(row.category)},
            .protocol_id = std::string {row.stable_id},
            .protocol = std::string {row.protocol},
            .recognition_status_id = std::string {session_detail::supported_protocol_status_stable_id(row.recognition)},
            .recognition_status_label = std::string {session_detail::supported_protocol_status_display_label(row.recognition)},
            .service_status_id = std::string {session_detail::supported_protocol_status_stable_id(row.service)},
            .service_status_label = std::string {session_detail::supported_protocol_status_display_label(row.service)},
            .packet_summary_status_id = std::string {session_detail::supported_protocol_status_stable_id(row.packet_summary)},
            .packet_summary_status_label = std::string {session_detail::supported_protocol_status_display_label(row.packet_summary)},
            .stream_status_id = std::string {session_detail::supported_protocol_status_stable_id(row.stream)},
            .stream_status_label = std::string {session_detail::supported_protocol_status_display_label(row.stream)},
            .notes = std::string {row.notes},
        });
    }

    return catalog;
}

std::vector<FrontendProtocolPathStatsDto> FrontendSessionAdapter::get_protocol_path_statistics(
    const ProtocolPathStatisticsMode mode
) const {
    if (!session_.has_capture()) {
        return {};
    }

    return build_protocol_path_statistics(session_.protocol_path_summary(mode));
}

std::optional<bool> FrontendSessionAdapter::advanced_flow_filter_protocol_path_predicate_applicability(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) const {
    return protocol_path_predicate_applicability(session_, predicate);
}

std::optional<FrontendAdvancedFlowFilterProtocolPathRowDto>
FrontendSessionAdapter::get_advanced_flow_filter_protocol_path_row(
    const ProtocolPathStatisticsMode mode,
    const std::uint64_t node_id
) const {
    if (!session_.has_capture()) {
        return std::nullopt;
    }

    const auto summary = session_.protocol_path_summary(mode);
    const auto row_it = std::find_if(summary.rows.begin(), summary.rows.end(), [node_id](const auto& row) {
        return row.node_id == node_id;
    });
    if (row_it == summary.rows.end()) {
        return std::nullopt;
    }

    session_detail::AdvancedFlowFilterProtocolPathPredicate predicate {
        .match_kind = mode == ProtocolPathStatisticsMode::terminal_paths
            ? session_detail::AdvancedFlowFilterProtocolPathMatchKind::exact_path
            : session_detail::AdvancedFlowFilterProtocolPathMatchKind::path_prefix,
    };
    predicate.layers.reserve(row_it->path.layers().size());
    for (const auto& layer : row_it->path.layers()) {
        predicate.layers.push_back(session_detail::AdvancedFlowFilterProtocolLayerPredicate {
            .kind = layer.kind,
            .identifier = (mode != ProtocolPathStatisticsMode::kind_overview &&
                layer.identifier.kind != ProtocolLayerIdentifierKind::none)
                ? std::optional {layer.identifier}
                : std::nullopt,
        });
    }

    FrontendAdvancedFlowFilterStructuredDocumentResult result {};
    FrontendAdvancedFlowFilterProtocolPathRowDto dto {};
    if (!encode_advanced_flow_filter_protocol_path_row(*this, predicate, dto, result)) {
        return std::nullopt;
    }
    return dto;
}

std::vector<std::size_t> FrontendSessionAdapter::get_protocol_path_summary_flow_indices(
    const ProtocolPathStatisticsMode mode,
    const std::uint64_t node_id
) const {
    if (!session_.has_capture()) {
        return {};
    }

    const auto flow_indices = session_.protocol_path_summary_flow_indices(mode, node_id);
    return {flow_indices.begin(), flow_indices.end()};
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

    flow_service_hint_overrides_[flow_index] = *derived_service_hint;
    auto updated_row = apply_service_hint_override(*row, flow_service_hint_overrides_);
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
        session_.prepare_selected_flow_packet_cache(flow_index, offset + rows.size());
        session_detail::populate_transient_packet_row_metadata(session_, flow_index, rows);

        const auto scanned_packet_count = offset + rows.size();
        const auto retransmission_packet_indices = session_.suspected_tcp_retransmission_packet_indices(flow_index, scanned_packet_count);
        const auto retransmission_set = std::set<std::uint64_t>(retransmission_packet_indices.begin(), retransmission_packet_indices.end());

        for (auto& row : rows) {
            row.suspected_tcp_retransmission = retransmission_set.contains(row.packet_index);
        }
    }

    if (offset == 0U && !rows.empty()) {
        const auto flow_row = session_.flow_row(flow_index);
        if (flow_row.has_value()) {
            auto effective_row = apply_service_hint_override(*flow_row, flow_service_hint_overrides_);
            const auto protocol_hint_is_tls =
                effective_row.protocol_hint == "tls" || effective_row.protocol_hint == "TLS";
            if (protocol_hint_is_tls && effective_row.service_hint.empty()) {
                const auto derived_service_hint = session_detail::derive_tls_service_hint_for_loaded_flow_prefix(
                    session_,
                    flow_index,
                    rows.size()
                );
                if (derived_service_hint.has_value() && !derived_service_hint->empty()) {
                    flow_service_hint_overrides_[flow_index] = *derived_service_hint;
                    effective_row = apply_service_hint_override(*flow_row, flow_service_hint_overrides_);
                }
            }

            if (effective_row.service_hint != flow_row->service_hint) {
                result.updated_flow = to_frontend_flow(effective_row);
            }
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
        auto payload_tab_title = stream_item_payload_tab_title();

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
            .stream_item_data = {},
            .payload_tab_title = std::move(payload_tab_title),
            .payload_preview_text = {},
            .payload_preview_unavailable_text = {},
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
        .payload_tab_title = stream_item_payload_tab_title(),
    };

    if (!session_.has_capture() || !selected_flow_index_.has_value()) {
        result.stream_item_data.status_text = "Item data unavailable • No selected flow is active.";
        result.stream_item_data.unavailable_text = "No selected flow is active.";
        result.payload_preview_unavailable_text = result.stream_item_data.status_text;
        return result;
    }

    if (!session_.source_capture_accessible()) {
        result.stream_item_data.status_text =
            "Item data unavailable • The original source capture cannot be read.";
        result.stream_item_data.unavailable_text =
            "The original source capture cannot be read.";
        result.payload_preview_unavailable_text = result.stream_item_data.status_text;
        return result;
    }

    const auto flow_index = *selected_flow_index_;
    const auto total_flow_packet_count = session_.flow_packet_count(flow_index);
    if (limit == 0U || max_packets_to_scan == 0U || total_flow_packet_count == 0U) {
        result.stream_item_data.status_text =
            "Item data unavailable • The selected stream window is empty.";
        result.stream_item_data.unavailable_text =
            "The selected stream window is empty.";
        result.payload_preview_unavailable_text = result.stream_item_data.status_text;
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
        result = to_frontend_stream_item(*it, flow_packet_numbers, true, packet_window_count, limit);
    } else {
        result.stream_item_data = build_frontend_stream_item_data(
            session_,
            flow_index,
            packet_window_count,
            limit,
            stream_item_index
        );
        result.payload_preview_unavailable_text = result.stream_item_data.status_text;
        result.payload_tab_title = stream_item_payload_tab_title();
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
    auto row = selected_flow_row(session_, flow_index);
    if (row.has_value()) {
        row = apply_service_hint_override(*row, flow_service_hint_overrides_);
    }
    if (!row.has_value()) {
        result.error_text = "The selected flow is unavailable.";
        return result;
    }

    const auto analysis = session_.get_flow_analysis(flow_index);
    if (!analysis.has_value()) {
        result.unavailable_text = "Analysis is unavailable for the selected flow.";
        return result;
    }

    result.analysis_available = true;
    result.has_tcp_control_counts = analysis->has_tcp_control_counts;
    result.total_packets = analysis->total_packets;
    result.total_bytes = analysis->total_bytes;
    result.captured_bytes = analysis->captured_bytes;
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
        ? session_detail::format_flow_protocol_hint_display(analysis->protocol_hint)
        : session_detail::format_flow_protocol_hint_display(row->protocol_hint);
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
    result.captured_bytes_text = format_size_value(analysis->captured_bytes);
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
    result.max_captured_packet_size_text = session_detail::format_statistics_size_value(
        analysis->max_captured_packet_size_bytes
    );
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

FrontendFlowInfoDto FrontendSessionAdapter::get_flow_info(const std::size_t flow_index) const {
    FrontendFlowInfoDto result {
        .has_capture = session_.has_capture(),
        .flow_available = false,
        .analysis_available = false,
        .flow_index = flow_index,
    };

    if (!result.has_capture) {
        result.error_text = "No capture is open.";
        return result;
    }

    auto row = session_.flow_row(flow_index);
    if (row.has_value()) {
        row = apply_service_hint_override(*row, flow_service_hint_overrides_);
    }
    if (!row.has_value()) {
        result.error_text = "The requested flow is unavailable.";
        return result;
    }

    result.flow_available = true;

    const auto analysis = session_.get_flow_analysis(flow_index);
    if (!analysis.has_value()) {
        result.unavailable_text = "Analysis is unavailable for the requested flow.";
        return result;
    }

    const auto protocol_path = session_detail::build_protocol_path_presentation(
        session_.state().protocol_path_registry,
        row->protocol_path_id
    );

    result.analysis_available = true;
    result.total_packets = analysis->total_packets;
    result.total_bytes = analysis->total_bytes;
    result.captured_bytes = analysis->captured_bytes;
    result.packets_a_to_b = analysis->packets_a_to_b;
    result.packets_b_to_a = analysis->packets_b_to_a;
    result.bytes_a_to_b = analysis->bytes_a_to_b;
    result.bytes_b_to_a = analysis->bytes_b_to_a;
    result.endpoint_a = row->endpoint_a;
    result.endpoint_b = row->endpoint_b;
    result.endpoint_summary_text = build_analysis_endpoint_summary(*row);
    result.family_text = flow_family_text(row->family);
    result.protocol_text = row->protocol_text;
    result.protocol_hint_display = !analysis->protocol_hint.empty()
        ? session_detail::format_flow_protocol_hint_display(analysis->protocol_hint)
        : session_detail::format_flow_protocol_hint_display(row->protocol_hint);
    result.service_hint_text = !analysis->service_hint.empty()
        ? analysis->service_hint
        : (!row->service_hint.empty() ? row->service_hint : analysis->protocol_panel_service_text);
    result.protocol_path_text = protocol_path.full_text;
    result.first_packet_time_text = analysis->first_packet_timestamp_text;
    result.last_packet_time_text = analysis->last_packet_timestamp_text;
    result.duration_text = format_duration_us(analysis->duration_us);
    result.largest_gap_text = format_duration_us(analysis->largest_gap_us);
    result.total_packets_text = format_grouped_integer(analysis->total_packets);
    result.total_bytes_text = format_size_value(analysis->total_bytes);
    result.captured_bytes_text = format_size_value(analysis->captured_bytes);
    result.max_captured_packet_size_text = session_detail::format_statistics_size_value(
        analysis->max_captured_packet_size_bytes
    );
    result.packets_a_to_b_text = format_grouped_integer(analysis->packets_a_to_b);
    result.packets_b_to_a_text = format_grouped_integer(analysis->packets_b_to_a);
    result.total_direction_packets_text = format_grouped_integer(analysis->total_packets);
    result.bytes_a_to_b_text = format_size_value(analysis->bytes_a_to_b);
    result.bytes_b_to_a_text = format_size_value(analysis->bytes_b_to_a);
    result.total_direction_bytes_text = format_size_value(analysis->total_bytes);
    result.packet_direction_text = analysis->packet_direction_text;
    result.data_direction_text = analysis->data_direction_text;
    result.packet_size_histogram_rows = build_analysis_histogram_rows(
        analysis->packet_size_histograms.histogram_all,
        analysis->packet_size_histograms.histogram_a_to_b,
        analysis->packet_size_histograms.histogram_b_to_a
    );
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

    const auto protocol_hint_text = session_detail::format_flow_protocol_hint_display(row->protocol_hint);
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
    const std::uint64_t flow_packet_index,
    const std::uint64_t loaded_packet_window_count
) {
    FrontendPacketDetailsDto result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = selected_flow_index_.has_value(),
        .packet_index = packet_index,
        .details_title = packet_details_title(),
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
        flow_packet_index != 0U ? std::optional<std::uint64_t> {flow_packet_index} : std::nullopt,
        loaded_packet_window_count != 0U ? std::optional<std::size_t> {static_cast<std::size_t>(loaded_packet_window_count)} : std::nullopt
    );
    return details;
}

FrontendPacketDetailsDto::PacketByteViewContent FrontendSessionAdapter::get_selected_flow_packet_byte_view_content(
    const std::uint64_t packet_index,
    const std::string& stable_id,
    const std::uint64_t flow_packet_index,
    const std::uint64_t loaded_packet_window_count
) {
    if (!session_.has_capture()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "No capture is open.",
        };
    }
    if (!selected_flow_index_.has_value()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "No flow is selected.",
        };
    }

    std::optional<PacketRef> packet {};
    if (flow_packet_index != 0U) {
        packet = session_.selected_flow_packet_at(*selected_flow_index_, flow_packet_index);
        if (!packet.has_value() || packet->packet_index != packet_index) {
            return FrontendPacketDetailsDto::PacketByteViewContent {
                .available = false,
                .unavailable_text = "The selected packet is unavailable.",
            };
        }
    } else {
        if (!session_.selected_flow_exact_packet_number(*selected_flow_index_, packet_index).has_value()) {
            return FrontendPacketDetailsDto::PacketByteViewContent {
                .available = false,
                .unavailable_text = "The selected packet is unavailable.",
            };
        }
        packet = session_.find_packet(packet_index);
        if (!packet.has_value()) {
            return FrontendPacketDetailsDto::PacketByteViewContent {
                .available = false,
                .unavailable_text = "The selected packet is unavailable.",
            };
        }
    }

    return build_frontend_packet_byte_view_content(
        *packet,
        stable_id,
        flow_packet_index != 0U ? std::optional<std::uint64_t> {flow_packet_index} : std::nullopt,
        loaded_packet_window_count != 0U ? std::optional<std::size_t> {static_cast<std::size_t>(loaded_packet_window_count)} : std::nullopt
    );
}

FrontendPacketDetailsDto FrontendSessionAdapter::get_unrecognized_packet_details(const std::uint64_t packet_index) {
    FrontendPacketDetailsDto result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = false,
        .packet_index = packet_index,
        .details_title = packet_details_title(),
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

FrontendPacketDetailsDto::PacketByteViewContent FrontendSessionAdapter::get_unrecognized_packet_byte_view_content(
    const std::uint64_t packet_index,
    const std::string& stable_id
) {
    if (!session_.has_capture()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "No capture is open.",
        };
    }

    const auto packet = session_.find_packet(packet_index);
    if (!packet.has_value()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "The selected packet is unavailable.",
        };
    }

    return build_frontend_packet_byte_view_content(*packet, stable_id);
}

FrontendPacketDetailsDto::PacketByteViewContent FrontendSessionAdapter::build_frontend_captured_packet_byte_view_content(
    const PacketRef& packet,
    const std::optional<std::size_t> flow_index,
    const std::optional<std::uint64_t> flow_packet_index,
    const std::optional<std::size_t> loaded_packet_window_count
) {
    if (!session_.source_capture_accessible()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "Byte-backed packet details are unavailable because the original source capture cannot be read.",
        };
    }

    const auto packet_bytes = session_.read_packet_data(packet);
    const auto details = session_.read_packet_details(packet);
    return build_frontend_captured_packet_byte_view_content_from_materialized_packet(
        packet,
        packet_bytes,
        details,
        flow_index,
        flow_packet_index,
        loaded_packet_window_count
    );
}

FrontendPacketDetailsDto::PacketByteViewContent
FrontendSessionAdapter::build_frontend_captured_packet_byte_view_content_from_materialized_packet(
    const PacketRef& packet,
    const std::vector<std::uint8_t>& packet_bytes,
    const std::optional<PacketDetails>& details,
    const std::optional<std::size_t> flow_index,
    const std::optional<std::uint64_t> flow_packet_index,
    const std::optional<std::size_t> loaded_packet_window_count
) {
    const auto packet_byte_presentation = derive_frontend_packet_byte_presentation(
        session_,
        packet,
        packet_bytes,
        details,
        flow_index,
        flow_packet_index,
        loaded_packet_window_count
    );
    if (!packet_byte_presentation.has_value()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "No byte views are available for this packet.",
        };
    }

    const auto selected_id = session_detail::select_whole_captured_packet_view_id(*packet_byte_presentation);
    if (!selected_id.has_value()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "The requested byte view is unavailable for this packet.",
        };
    }

    HexDumpService hex_dump_service {};
    const auto content = session_detail::format_selected_packet_byte_view_content(
        *packet_byte_presentation,
        *selected_id,
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        hex_dump_service
    );
    if (!content.has_value()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "The requested byte view is unavailable for this packet.",
        };
    }

    return FrontendPacketDetailsDto::PacketByteViewContent {
        .available = true,
        .stable_id = content->stable_id,
        .label = content->label,
        .mode = content->mode == session_detail::SelectedPacketByteRangeMode::payload_only
            ? "payload_only"
            : "whole_unit",
        .assembly_kind = content->assembly_kind,
        .available_length = content->available_length,
        .declared_length = content->declared_length,
        .state = content->state,
        .contributing_unit_count = content->contributing_unit_count,
        .contributing_unit_kind = content->contributing_unit_kind,
        .status_text = packet_byte_view_status_text(
            content->state,
            content->assembly_kind,
            content->contributing_unit_count,
            content->contributing_unit_kind,
            content->available_length,
            content->declared_length
        ),
        .formatted_text = content->formatted_text,
        .unavailable_text = {},
    };
}

FrontendPacketInfoDto FrontendSessionAdapter::get_packet_info_by_flow(
    const std::size_t flow_index,
    const std::uint64_t flow_packet_index,
    const bool include_bytes
) {
    FrontendPacketInfoDto result {
        .has_capture = session_.has_capture(),
        .packet_available = false,
        .recognized_flow = false,
        .source_capture_accessible = session_.source_capture_accessible(),
        .details_available = false,
        .source_availability = current_source_availability(),
    };

    if (!result.has_capture) {
        result.error_text = "No capture is open.";
        return result;
    }

    auto row = session_.flow_row(flow_index);
    if (row.has_value()) {
        row = apply_service_hint_override(*row, flow_service_hint_overrides_);
    }
    if (!row.has_value()) {
        result.error_text = "The requested flow is unavailable.";
        return result;
    }

    const auto packet_context = session_.selected_flow_packet_context_at(flow_index, flow_packet_index);
    if (!packet_context.has_value()) {
        result.error_text = "The requested packet is unavailable in the selected flow.";
        return result;
    }

    const auto packet_bytes = session_.read_packet_data(packet_context->packet);
    const auto decoded_details = session_.read_packet_details(packet_context->packet);
    const auto details = build_frontend_packet_details_from_materialized_packet(
        packet_context->packet,
        packet_bytes,
        decoded_details,
        flow_index,
        packet_context->flow_packet_index,
        std::nullopt,
        false
    );

    result.packet_available = true;
    result.recognized_flow = true;
    result.details_available = details.details_available;
    result.packet_index = packet_context->packet.packet_index;
    result.packet_in_file = packet_context->packet.packet_index + 1U;
    result.flow_index = flow_index;
    result.packet_in_flow = packet_context->flow_packet_index;
    result.endpoint_summary_text = build_analysis_endpoint_summary(*row);
    result.direction_text = flow_packet_direction_text(packet_context->direction);
    result.timestamp_text = details.timestamp_text;
    result.captured_length = details.captured_length;
    result.original_length = details.original_length;
    result.summary_layers = details.summary_layers;
    if (include_bytes) {
        result.captured_packet_bytes = build_frontend_captured_packet_byte_view_content_from_materialized_packet(
            packet_context->packet,
            packet_bytes,
            decoded_details,
            flow_index,
            packet_context->flow_packet_index
        );
    }
    result.unavailable_text = details.unavailable_text;
    result.error_text = details.error_text;
    result.source_capture_accessible = details.source_capture_accessible;
    result.source_availability = details.source_availability;
    return result;
}

FrontendPacketInfoDto FrontendSessionAdapter::get_packet_info_by_file(
    const std::uint64_t packet_index,
    const bool include_bytes
) {
    FrontendPacketInfoDto result {
        .has_capture = session_.has_capture(),
        .packet_available = false,
        .recognized_flow = false,
        .source_capture_accessible = session_.source_capture_accessible(),
        .details_available = false,
        .source_availability = current_source_availability(),
    };

    if (!result.has_capture) {
        result.error_text = "No capture is open.";
        return result;
    }

    const auto packet_lookup = session_.lookup_source_packet(packet_index);
    if (packet_lookup.status != SourcePacketLookupStatus::found ||
        !packet_lookup.packet.has_value() ||
        !packet_lookup.source_packet.has_value()) {
        result.error_text = packet_lookup_error_text(packet_lookup.status);
        return result;
    }

    PacketDetailsService packet_details_service {};
    const auto packet = *packet_lookup.packet;
    const auto& packet_bytes = packet_lookup.source_packet->bytes;
    const auto decoded_details = packet_details_service.decode_best_effort(
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        packet
    );

    auto details = build_frontend_packet_details_from_materialized_packet(
        packet,
        packet_bytes,
        decoded_details,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        false
    );

    const auto unrecognized_packet = std::lower_bound(
        session_.state().unrecognized_packets.begin(),
        session_.state().unrecognized_packets.end(),
        packet_index,
        [](const UnrecognizedPacketRecord& record, const std::uint64_t target_packet_index) {
            return record.packet.packet_index < target_packet_index;
        }
    );

    result.packet_available = true;
    result.recognized_flow = unrecognized_packet == session_.state().unrecognized_packets.end() ||
        unrecognized_packet->packet.packet_index != packet_index;
    result.details_available = details.details_available;
    result.packet_index = packet.packet_index;
    result.packet_in_file = packet.packet_index + 1U;
    result.timestamp_text = details.timestamp_text;
    result.captured_length = details.captured_length;
    result.original_length = details.original_length;
    result.summary_layers = details.summary_layers;
    if (include_bytes) {
        result.captured_packet_bytes = build_frontend_captured_packet_byte_view_content_from_materialized_packet(
            packet,
            packet_bytes,
            decoded_details,
            std::nullopt,
            std::nullopt
        );
    }
    result.unavailable_text = details.unavailable_text;
    result.error_text = details.error_text;
    result.source_capture_accessible = details.source_capture_accessible;
    result.source_availability = details.source_availability;

    return result;
}

FrontendPacketDetailsDto FrontendSessionAdapter::build_frontend_packet_details(
    const PacketRef& packet,
    const std::optional<std::size_t> flow_index,
    const std::optional<std::uint64_t> flow_packet_index,
    const std::optional<std::size_t> loaded_packet_window_count
) {
    FrontendPacketDetailsDto result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = flow_index.has_value(),
        .packet_found = true,
        .source_capture_accessible = session_.source_capture_accessible(),
        .details_available = false,
        .checksum_validation_enabled = settings_.validate_selected_packet_checksums,
        .flow_index = flow_index.value_or(0U),
        .packet_index = packet.packet_index,
        .details_title = packet_details_title(),
        .summary_text = {},
        .timestamp_text = session_detail::format_packet_timestamp_full(packet),
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
        .payload_length = 0U,
        .is_ip_fragmented = false,
        .tcp_flags_text = {},
        .source_availability = current_source_availability(),
    };

    if (!result.source_capture_accessible) {
        result.summary_text = build_frontend_packet_summary_text(packet, std::nullopt, {}, false);
        result.unavailable_text =
            "Byte-backed packet details are unavailable because the original source capture cannot be read.";
        result.selected_byte_view.unavailable_text = result.unavailable_text;
        if (result.checksum_validation_enabled) {
            result.checksum_warning_lines.push_back(
                "Checksum validation requires the original source capture bytes to be attached and readable."
            );
        }
        return result;
    }

    const auto packet_bytes = session_.read_packet_data(packet);
    std::optional<PacketDetails> details {};
    if (!packet_bytes.empty()) {
        PacketDetailsService packet_details_service {};
        details = packet_details_service.decode_best_effort(
            std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
            packet
        );
    }
    return build_frontend_packet_details_from_materialized_packet(
        packet,
        packet_bytes,
        details,
        flow_index,
        flow_packet_index,
        loaded_packet_window_count
    );
}

FrontendPacketDetailsDto FrontendSessionAdapter::build_frontend_packet_details_from_materialized_packet(
    const PacketRef& packet,
    const std::vector<std::uint8_t>& packet_bytes,
    const std::optional<PacketDetails>& details,
    const std::optional<std::size_t> flow_index,
    const std::optional<std::uint64_t> flow_packet_index,
    const std::optional<std::size_t> loaded_packet_window_count,
    const bool include_selected_byte_view
) {
    const auto metadata = session_detail::derive_transient_packet_metadata(
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        packet
    );
    FrontendPacketDetailsDto result {
        .has_capture = session_.has_capture(),
        .has_selected_flow = flow_index.has_value(),
        .packet_found = true,
        .source_capture_accessible = session_.source_capture_accessible(),
        .details_available = false,
        .checksum_validation_enabled = settings_.validate_selected_packet_checksums,
        .flow_index = flow_index.value_or(0U),
        .packet_index = packet.packet_index,
        .details_title = packet_details_title(),
        .summary_text = {},
        .timestamp_text = session_detail::format_packet_timestamp_full(packet),
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
        .payload_length = metadata.original_transport_payload_length
            .value_or(metadata.captured_transport_payload_length.value_or(0U)),
        .is_ip_fragmented = metadata.is_ip_fragmented.value_or(false),
        .tcp_flags_text = metadata.tcp_flags.has_value()
            ? session_detail::format_tcp_flags_text(*metadata.tcp_flags)
            : std::string {},
        .source_availability = current_source_availability(),
    };

    PacketChecksumSections checksum_sections {};
    if (details.has_value() && result.checksum_validation_enabled) {
        checksum_sections =
            build_packet_checksum_sections(*details, packet, std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()));
        result.checksum_summary_lines = checksum_sections.summary_lines;
        result.checksum_warning_lines = checksum_sections.warnings;
    }

    std::optional<session_detail::SelectedPacketSummaryPreparation> packet_summary_preparation {};
    if (details.has_value()) {
        const auto internal_flow_packet_index =
            flow_packet_index.has_value()
                ? std::optional<std::uint64_t> {*flow_packet_index - 1U}
                : std::nullopt;
        packet_summary_preparation = session_detail::prepare_selected_packet_summary(
            session_,
            *details,
            packet,
            flow_index,
            internal_flow_packet_index,
            loaded_packet_window_count,
            metadata.captured_transport_payload_length,
            metadata.original_transport_payload_length,
            result.checksum_summary_lines,
            result.checksum_warning_lines
        );

        result.details_available = true;
        result.link_summary_text = format_link_summary(*details);
        result.network_summary_text = format_network_summary(*details);
        result.transport_summary_text = format_transport_summary(*details);
        result.summary_layers = session_detail::build_packet_summary_layers(
            *details,
            packet,
            packet_summary_preparation->make_options()
        );
    } else {
        result.unavailable_text = "Only partial packet details are available for this packet.";
    }

    if (include_selected_byte_view) {
        if (const auto packet_byte_presentation = derive_frontend_packet_byte_presentation(
                session_,
                packet,
                packet_bytes,
                details,
                flow_index,
                flow_packet_index,
                loaded_packet_window_count);
            packet_byte_presentation.has_value()) {
            const auto prepared_descriptors = session_detail::build_selected_packet_byte_view_descriptors(*packet_byte_presentation);
            result.byte_view_descriptors = build_frontend_packet_byte_view_descriptors(prepared_descriptors);
            if (const auto selected_id = select_default_packet_byte_view_id(prepared_descriptors); selected_id.has_value()) {
                HexDumpService hex_dump_service {};
                if (const auto content = session_detail::format_selected_packet_byte_view_content(
                        *packet_byte_presentation,
                        *selected_id,
                        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
                        hex_dump_service);
                    content.has_value()) {
                    result.selected_byte_view = FrontendPacketDetailsDto::PacketByteViewContent {
                        .available = true,
                        .stable_id = content->stable_id,
                        .label = content->label,
                        .mode = content->mode == session_detail::SelectedPacketByteRangeMode::payload_only
                            ? "payload_only"
                            : "whole_unit",
                        .assembly_kind = content->assembly_kind,
                        .available_length = content->available_length,
                        .declared_length = content->declared_length,
                        .state = content->state,
                        .contributing_unit_count = content->contributing_unit_count,
                        .contributing_unit_kind = content->contributing_unit_kind,
                        .status_text = packet_byte_view_status_text(
                            content->state,
                            content->assembly_kind,
                            content->contributing_unit_count,
                            content->contributing_unit_kind,
                            content->available_length,
                            content->declared_length
                        ),
                        .formatted_text = content->formatted_text,
                        .unavailable_text = {},
                    };
                }
            }
        }
    }

    result.summary_text = build_frontend_packet_summary_text(packet, details, checksum_sections, true, metadata);
    if (include_selected_byte_view && !result.selected_byte_view.available && result.unavailable_text.empty()) {
        result.selected_byte_view.unavailable_text = result.byte_view_descriptors.empty()
            ? "No byte views are available for this packet."
            : "The selected byte view is unavailable for this packet.";
        result.unavailable_text = result.selected_byte_view.unavailable_text;
    }

    return result;
}

FrontendPacketDetailsDto::PacketByteViewContent FrontendSessionAdapter::build_frontend_packet_byte_view_content(
    const PacketRef& packet,
    const std::string& stable_id,
    const std::optional<std::uint64_t> flow_packet_index,
    const std::optional<std::size_t> loaded_packet_window_count
) {
    if (!session_.source_capture_accessible()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "Byte-backed packet details are unavailable because the original source capture cannot be read.",
        };
    }

    const auto packet_bytes = session_.read_packet_data(packet);
    const auto details = session_.read_packet_details(packet);
    const auto packet_byte_presentation = derive_frontend_packet_byte_presentation(
        session_,
        packet,
        packet_bytes,
        details,
        selected_flow_index_,
        flow_packet_index,
        loaded_packet_window_count
    );
    if (!packet_byte_presentation.has_value()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "No byte views are available for this packet.",
        };
    }

    const auto selected_id = session_detail::parse_selected_packet_byte_view_stable_id(stable_id);
    if (!selected_id.has_value()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "The requested byte view is unavailable for this packet.",
        };
    }

    HexDumpService hex_dump_service {};
    const auto content = session_detail::format_selected_packet_byte_view_content(
        *packet_byte_presentation,
        *selected_id,
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        hex_dump_service
    );
    if (!content.has_value()) {
        return FrontendPacketDetailsDto::PacketByteViewContent {
            .available = false,
            .unavailable_text = "The requested byte view is unavailable for this packet.",
        };
    }

    return FrontendPacketDetailsDto::PacketByteViewContent {
        .available = true,
        .stable_id = content->stable_id,
        .label = content->label,
        .mode = content->mode == session_detail::SelectedPacketByteRangeMode::payload_only
            ? "payload_only"
            : "whole_unit",
        .assembly_kind = content->assembly_kind,
        .available_length = content->available_length,
        .declared_length = content->declared_length,
        .state = content->state,
        .contributing_unit_count = content->contributing_unit_count,
        .contributing_unit_kind = content->contributing_unit_kind,
        .status_text = packet_byte_view_status_text(
            content->state,
            content->assembly_kind,
            content->contributing_unit_count,
            content->contributing_unit_kind,
            content->available_length,
            content->declared_length
        ),
        .formatted_text = content->formatted_text,
        .unavailable_text = {},
    };
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
        .ignore_vlan_and_mpls_layers_when_grouping_flows = settings.ignore_vlan_and_mpls_layers_when_grouping_flows,
        .ignore_gtpu_teids_when_grouping_inner_flows = settings.ignore_gtpu_teids_when_grouping_inner_flows,
    };
}

FrontendFlowDto FrontendSessionAdapter::to_frontend_flow(const FlowRow& row) {
    return FrontendFlowDto {
        .flow_index = row.index,
        .family = row.family,
        .protocol_text = row.protocol_text,
        .protocol_hint = row.protocol_hint,
        .protocol_hint_display = session_detail::format_flow_protocol_hint_display(row.protocol_hint),
        .service_hint = row.service_hint,
        .protocol_path_id = row.protocol_path_id,
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
        .payload_length = row.derived_payload_length,
        .is_ip_fragmented = row.derived_is_ip_fragmented,
        .suspected_tcp_retransmission = row.suspected_tcp_retransmission,
        .tcp_flags_text = row.derived_tcp_flags_text,
    };
}

FrontendStreamItemDto FrontendSessionAdapter::to_frontend_stream_item(
    const StreamItemRow& row,
    const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers,
    const bool include_details,
    const std::size_t max_packets_to_scan,
    const std::size_t limit
) const {
    FrontendStreamItemDto::StreamItemDataDto stream_item_data {};
    if (include_details && selected_flow_index_.has_value()) {
        stream_item_data = build_frontend_stream_item_data(
            session_,
            *selected_flow_index_,
            max_packets_to_scan,
            limit,
            row.stream_item_index
        );
    }
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
        .summary_layers = include_details ? build_stream_item_summary_layers(row, flow_packet_numbers) : std::vector<session_detail::PacketSummaryLayer> {},
        .stream_item_data = std::move(stream_item_data),
        .payload_tab_title = stream_item_payload_tab_title(),
        .payload_preview_text = include_details ? stream_item_data.formatted_text : std::string {},
        .payload_preview_unavailable_text =
            include_details && !stream_item_data.available
                ? stream_item_data.status_text
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
