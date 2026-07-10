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

#include "app/frontend/FrontendDtos.h"
#include "app/session/CaptureSession.h"
#include "../../../core/open_context.h"

namespace pfl {

class FrontendSessionAdapter {
public:
    FrontendSessionAdapter() = default;
    ~FrontendSessionAdapter();

    [[nodiscard]] FrontendOpenResult open_capture(const std::filesystem::path& path, FrontendOpenMode open_mode);
    [[nodiscard]] FrontendOpenStartResult start_open_capture(const std::filesystem::path& path, FrontendOpenMode open_mode);
    [[nodiscard]] FrontendOpenPollResultDto poll_open_capture();
    [[nodiscard]] bool cancel_open_capture();
    [[nodiscard]] FrontendAttachSourceCaptureResult attach_source_capture(const std::filesystem::path& path);
    [[nodiscard]] FrontendSaveIndexResult save_index(const std::filesystem::path& output_path) const;
    [[nodiscard]] FrontendSettingsDto get_settings() const noexcept;
    [[nodiscard]] FrontendSettingsDto update_settings(const FrontendSettingsDto& settings);
    [[nodiscard]] FrontendExportCurrentFlowResult export_current_flow(const std::filesystem::path& output_path) const;
    [[nodiscard]] FrontendExportSelectedFlowsResult export_selected_flows(
        const std::filesystem::path& output_path,
        const std::vector<std::size_t>& flow_indices
    ) const;
    [[nodiscard]] FrontendSmartExportResult export_smart_flows(
        const std::filesystem::path& output_path,
        const std::vector<std::size_t>& flow_indices,
        const FrontendSmartExportOptions& options
    ) const;
    [[nodiscard]] FrontendSmartExportResult export_smart_unrecognized_packets(
        const std::filesystem::path& output_path,
        const FrontendSmartExportOptions& options
    ) const;
    [[nodiscard]] FrontendOverviewDto get_overview() const;
    [[nodiscard]] std::vector<FrontendFlowDto> get_flows() const;
    [[nodiscard]] std::vector<FrontendProtocolPathLegendEntryDto> get_protocol_path_legend() const;
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
        std::uint64_t flow_packet_index = 0U
    ) const;
    [[nodiscard]] FrontendPacketDetailsDto get_unrecognized_packet_details(std::uint64_t packet_index) const;
    [[nodiscard]] FrontendSelectedFlowAnalysisDto get_selected_flow_analysis() const;
    [[nodiscard]] FrontendAnalysisSequenceExportResultDto export_selected_flow_analysis_sequence_csv(
        const std::filesystem::path& output_path
    ) const;

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
        std::optional<std::uint64_t> flow_packet_index
    ) const;
    [[nodiscard]] static AnalysisSettings to_analysis_settings(const FrontendSettingsDto& settings) noexcept;
    [[nodiscard]] FrontendStreamItemDto to_frontend_stream_item(
        const StreamItemRow& row,
        const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers,
        bool include_details
    ) const;
    void join_finished_open_worker();
    void cancel_and_join_open_worker();

    CaptureSession session_ {};
    std::optional<std::size_t> selected_flow_index_ {};
    FrontendSettingsDto settings_ {};
    AsyncOpenState async_open_ {};
};

}  // namespace pfl
