#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <map>
#include <optional>
#include <thread>
#include <vector>

#include "app/frontend/AdvancedFlowFilterStructuredDocument.h"
#include "app/frontend/FrontendDtos.h"
#include "app/session/AdvancedFlowFilter.h"
#include "app/session/CaptureSession.h"
#include "../../../core/open_context.h"

namespace pfl {

class FrontendSessionAdapter {
public:
    FrontendSessionAdapter() = default;
    ~FrontendSessionAdapter();

    [[nodiscard]] FrontendOpenResult open_capture(const std::filesystem::path& path);
    [[nodiscard]] FrontendOpenStartResult start_open_capture(const std::filesystem::path& path);
    [[nodiscard]] FrontendOpenPollResultDto poll_open_capture();
    [[nodiscard]] bool cancel_open_capture();
    [[nodiscard]] FrontendSourceAvailabilityDto source_availability() const;
    [[nodiscard]] FrontendAttachSourceCaptureResult attach_source_capture(const std::filesystem::path& path);
    [[nodiscard]] FrontendSaveIndexResult save_index(const std::filesystem::path& output_path) const;
    [[nodiscard]] FrontendSettingsDto get_settings() const noexcept;
    [[nodiscard]] FrontendSettingsDto update_settings(const FrontendSettingsDto& settings);
    [[nodiscard]] FrontendExportCurrentFlowResult export_current_flow(const std::filesystem::path& output_path) const;
    [[nodiscard]] FrontendExportSelectedFlowsResult export_flows_to_pcap(
        const std::filesystem::path& output_path,
        const std::vector<std::size_t>& flow_indices,
        const SmartSingleFileExportOptions& options = {}
    ) const;
    [[nodiscard]] FrontendExportSelectedFlowsResult export_selected_flows(
        const std::filesystem::path& output_path,
        const std::vector<std::size_t>& flow_indices
    ) const;
    [[nodiscard]] FrontendExportAllFlowsInfoCsvResult export_all_flows_info_csv(
        const std::filesystem::path& output_path
    ) const;
    [[nodiscard]] FrontendExportAllFlowsInfoCsvResult export_flows_info_csv(
        const std::filesystem::path& output_path,
        const std::vector<std::size_t>& flow_indices
    ) const;
    [[nodiscard]] FrontendExportProtocolPathTreeResult export_protocol_path_tree(
        ProtocolPathStatisticsMode mode,
        const std::filesystem::path& output_path
    ) const;
    [[nodiscard]] std::vector<FrontendByteExportFormatDto> get_byte_export_formats() const;
    [[nodiscard]] FrontendByteExportResult export_selected_flow_packet_byte_view(
        std::uint64_t packet_index,
        const std::string& stable_id,
        const std::string& format_id,
        const std::filesystem::path& output_path,
        std::uint64_t flow_packet_index = 0U,
        std::uint64_t loaded_packet_window_count = 0U
    ) const;
    [[nodiscard]] FrontendByteExportResult export_unrecognized_packet_byte_view(
        std::uint64_t packet_index,
        const std::string& stable_id,
        const std::string& format_id,
        const std::filesystem::path& output_path
    ) const;
    [[nodiscard]] FrontendByteExportResult export_selected_flow_stream_item_data(
        std::size_t max_packets_to_scan,
        std::size_t limit,
        std::uint64_t stream_item_index,
        const std::string& format_id,
        const std::filesystem::path& output_path
    ) const;
    [[nodiscard]] FrontendSmartExportResult export_smart_flows(
        const std::filesystem::path& output_path,
        const std::vector<std::size_t>& flow_indices,
        const FrontendSmartExportOptions& options
    ) const;
    [[nodiscard]] FrontendSmartExportResult export_smart_flows_to_pcap(
        const std::filesystem::path& output_path,
        const SmartFlowExportRequest& request,
        const SmartSingleFileExportOptions& options = {}
    ) const;
    [[nodiscard]] FrontendSmartExportResult export_smart_flows_to_folder(
        const std::filesystem::path& output_path,
        const SmartFlowExportRequest& request,
        const SmartPerFlowExportOptions& options = {}
    ) const;
    [[nodiscard]] FrontendSmartExportResult export_smart_unrecognized_packets(
        const std::filesystem::path& output_path,
        const FrontendSmartExportOptions& options
    ) const;
    [[nodiscard]] FrontendSmartExportResult export_smart_unrecognized_packets(
        const std::filesystem::path& output_path,
        const FrontendSmartExportOptions& options,
        const SmartSingleFileExportOptions& export_options
    ) const;
    [[nodiscard]] FrontendOverviewDto get_overview() const;
    [[nodiscard]] FrontendCapturePacketSizeStatisticsDto get_capture_packet_size_statistics() const;
    [[nodiscard]] FrontendFlowPacketCountHistogramDto get_flow_packet_count_histogram() const;
    [[nodiscard]] FrontendProtocolHintStatisticsDto get_protocol_hint_statistics() const;
    [[nodiscard]] FrontendQuicTlsStatisticsDto get_quic_tls_statistics() const;
    [[nodiscard]] FrontendTopEndpointPortStatisticsDto get_top_endpoint_port_statistics(std::size_t limit = 5U) const;
    [[nodiscard]] std::vector<FrontendFlowDto> get_flows() const;
    [[nodiscard]] std::vector<FrontendProtocolPathLegendEntryDto> get_protocol_path_legend() const;
    [[nodiscard]] FrontendSupportedProtocolCatalogDto get_supported_protocol_catalog() const;
    [[nodiscard]] std::vector<FrontendProtocolPathStatsDto> get_protocol_path_statistics(
        ProtocolPathStatisticsMode mode
    ) const;
    [[nodiscard]] std::optional<bool> advanced_flow_filter_protocol_path_predicate_applicability(
        const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
    ) const;
    [[nodiscard]] std::optional<FrontendAdvancedFlowFilterProtocolPathRowDto>
    get_advanced_flow_filter_protocol_path_row(
        ProtocolPathStatisticsMode mode,
        std::uint64_t node_id
    ) const;
    [[nodiscard]] std::vector<std::size_t> get_protocol_path_summary_flow_indices(
        ProtocolPathStatisticsMode mode,
        std::uint64_t node_id
    ) const;
    [[nodiscard]] FrontendSelectionResultDto select_flow(std::size_t flow_index);
    [[nodiscard]] FrontendSelectedFlowPacketsResult get_selected_flow_packets(std::size_t offset, std::size_t limit);
    [[nodiscard]] FrontendUnrecognizedPacketsResult get_unrecognized_packets(std::size_t offset, std::size_t limit) const;
    [[nodiscard]] FrontendSelectedFlowStreamResult get_selected_flow_stream(std::size_t max_packets_to_scan, std::size_t limit) const;
    [[nodiscard]] FrontendStreamItemDto get_selected_flow_stream_item_details(
        std::size_t max_packets_to_scan,
        std::size_t limit,
        std::uint64_t stream_item_index
    ) const;
    [[nodiscard]] FrontendPacketDetailsDto get_selected_flow_packet_details(
        std::uint64_t packet_index,
        std::uint64_t flow_packet_index = 0U,
        std::uint64_t loaded_packet_window_count = 0U
    );
    [[nodiscard]] FrontendPacketDetailsDto::PacketByteViewContent get_selected_flow_packet_byte_view_content(
        std::uint64_t packet_index,
        const std::string& stable_id,
        std::uint64_t flow_packet_index = 0U,
        std::uint64_t loaded_packet_window_count = 0U
    );
    [[nodiscard]] FrontendPacketDetailsDto get_unrecognized_packet_details(std::uint64_t packet_index);
    [[nodiscard]] FrontendPacketDetailsDto::PacketByteViewContent get_unrecognized_packet_byte_view_content(
        std::uint64_t packet_index,
        const std::string& stable_id
    );
    [[nodiscard]] FrontendPacketInfoDto get_packet_info_by_flow(
        std::size_t flow_index,
        std::uint64_t flow_packet_index,
        bool include_bytes
    );
    [[nodiscard]] FrontendPacketInfoDto get_packet_info_by_file(std::uint64_t packet_index, bool include_bytes);
    [[nodiscard]] FrontendSelectedFlowAnalysisDto get_selected_flow_analysis() const;
    [[nodiscard]] FrontendFlowInfoDto get_flow_info(std::size_t flow_index) const;
    [[nodiscard]] FrontendAnalysisSequenceExportResultDto export_selected_flow_analysis_sequence_csv(
        const std::filesystem::path& output_path
    ) const;
    [[nodiscard]] session_detail::FlowQueryResult query_flows(const session_detail::FlowQuery& query) const;
    [[nodiscard]] FrontendAdvancedFlowQueryResult query_advanced_flows(
        const session_detail::AdvancedFlowFilterSpec& filter_spec,
        const std::optional<std::vector<std::size_t>>& candidate_flow_indices,
        std::optional<session_detail::FlowQuerySortSpec> sort,
        std::optional<std::size_t> limit
    ) const;
    [[nodiscard]] FrontendAdvancedFlowQueryResult query_advanced_flows_text(
        std::string_view filter_text,
        const std::optional<std::vector<std::size_t>>& candidate_flow_indices,
        std::optional<session_detail::FlowQuerySortSpec> sort,
        std::optional<std::size_t> limit
    ) const;
    [[nodiscard]] FrontendAdvancedFlowFilterStructuredDocumentResult parse_advanced_flow_filter_structured_document(
        std::string_view filter_text
    ) const;
    [[nodiscard]] FrontendAdvancedFlowFilterStructuredDocumentResult update_advanced_flow_filter_structured_section(
        std::string_view filter_text,
        std::string_view section_id,
        bool enabled,
        const std::vector<std::string>& include_ids,
        const std::vector<std::string>& exclude_ids
    ) const;
    [[nodiscard]] FrontendAdvancedFlowFilterStructuredDocumentResult apply_advanced_flow_filter_structured_document(
        std::string_view filter_text,
        const FrontendAdvancedFlowFilterStructuredDocumentDto& document
    ) const;
    [[nodiscard]] std::optional<FlowRow> flow_row(std::size_t flow_index) const;
    [[nodiscard]] std::string protocol_path_compact_text(ProtocolPathId protocol_path_id) const;

    [[nodiscard]] bool has_capture() const noexcept;
    [[nodiscard]] std::optional<std::size_t> selected_flow_index() const noexcept;
    void clear_selection() noexcept;

private:
    struct AsyncOpenState {
        std::mutex mutex {};
        std::thread worker {};
        std::shared_ptr<OpenContext> context {};
        bool in_progress {false};
        bool cancel_requested {false};
        bool result_ready {false};
        FrontendOpenProgressDto progress {};
        FrontendOpenResult result {};
        std::optional<CaptureSession> completed_session {};
    };

    [[nodiscard]] FrontendSourceAvailabilityDto current_source_availability() const;
    [[nodiscard]] static FrontendFlowDto to_frontend_flow(const FlowRow& row);
    [[nodiscard]] static FrontendPacketDto to_frontend_packet(const PacketRow& row);
    [[nodiscard]] static FrontendUnrecognizedPacketDto to_frontend_unrecognized_packet(const UnrecognizedPacketRow& row);
    [[nodiscard]] FrontendPacketDetailsDto build_frontend_packet_details(
        const PacketRef& packet,
        std::optional<std::size_t> flow_index,
        std::optional<std::uint64_t> flow_packet_index,
        std::optional<std::size_t> loaded_packet_window_count = std::nullopt
    );
    [[nodiscard]] FrontendPacketDetailsDto build_frontend_packet_details_from_materialized_packet(
        const PacketRef& packet,
        const std::vector<std::uint8_t>& packet_bytes,
        const std::optional<PacketDetails>& details,
        std::optional<std::size_t> flow_index,
        std::optional<std::uint64_t> flow_packet_index,
        std::optional<std::size_t> loaded_packet_window_count = std::nullopt,
        bool include_selected_byte_view = true
    );
    [[nodiscard]] FrontendPacketDetailsDto::PacketByteViewContent build_frontend_packet_byte_view_content(
        const PacketRef& packet,
        const std::string& stable_id,
        std::optional<std::uint64_t> flow_packet_index = {},
        std::optional<std::size_t> loaded_packet_window_count = {}
    );
    [[nodiscard]] FrontendPacketDetailsDto::PacketByteViewContent build_frontend_captured_packet_byte_view_content(
        const PacketRef& packet,
        std::optional<std::size_t> flow_index = {},
        std::optional<std::uint64_t> flow_packet_index = {},
        std::optional<std::size_t> loaded_packet_window_count = {}
    );
    [[nodiscard]] FrontendPacketDetailsDto::PacketByteViewContent
    build_frontend_captured_packet_byte_view_content_from_materialized_packet(
        const PacketRef& packet,
        const std::vector<std::uint8_t>& packet_bytes,
        const std::optional<PacketDetails>& details,
        std::optional<std::size_t> flow_index = {},
        std::optional<std::uint64_t> flow_packet_index = {},
        std::optional<std::size_t> loaded_packet_window_count = {}
    );
    [[nodiscard]] static AnalysisSettings to_analysis_settings(const FrontendSettingsDto& settings) noexcept;
    [[nodiscard]] FrontendStreamItemDto to_frontend_stream_item(
        const StreamItemRow& row,
        const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers,
        bool include_details,
        std::size_t max_packets_to_scan = 0U,
        std::size_t limit = 0U
    ) const;
    void join_finished_open_worker();
    void cancel_and_join_open_worker();

    CaptureSession session_ {};
    std::optional<std::size_t> selected_flow_index_ {};
    std::map<std::size_t, std::string> flow_service_hint_overrides_ {};
    FrontendSettingsDto settings_ {};
    AsyncOpenState async_open_ {};
};

}  // namespace pfl
