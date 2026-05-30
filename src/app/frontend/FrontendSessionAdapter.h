#pragma once

#include <cstddef>
#include <filesystem>
#include <map>
#include <optional>
#include <vector>

#include "app/frontend/FrontendDtos.h"
#include "app/session/CaptureSession.h"

namespace pfl {

class FrontendSessionAdapter {
public:
    FrontendSessionAdapter() = default;

    [[nodiscard]] FrontendOpenResult open_capture(const std::filesystem::path& path, FrontendOpenMode open_mode);
    [[nodiscard]] FrontendAttachSourceCaptureResult attach_source_capture(const std::filesystem::path& path);
    [[nodiscard]] FrontendSaveIndexResult save_index(const std::filesystem::path& output_path) const;
    [[nodiscard]] FrontendExportCurrentFlowResult export_current_flow(const std::filesystem::path& output_path) const;
    [[nodiscard]] FrontendExportSelectedFlowsResult export_selected_flows(
        const std::filesystem::path& output_path,
        const std::vector<std::size_t>& flow_indices
    ) const;
    [[nodiscard]] FrontendOverviewDto get_overview() const;
    [[nodiscard]] std::vector<FrontendFlowDto> get_flows() const;
    [[nodiscard]] bool select_flow(std::size_t flow_index);
    [[nodiscard]] FrontendSelectedFlowPacketsResult get_selected_flow_packets(std::size_t offset, std::size_t limit);
    [[nodiscard]] FrontendSelectedFlowStreamResult get_selected_flow_stream(std::size_t max_packets_to_scan, std::size_t limit) const;
    [[nodiscard]] FrontendPacketDetailsDto get_selected_flow_packet_details(std::uint64_t packet_index) const;
    [[nodiscard]] FrontendSelectedFlowAnalysisDto get_selected_flow_analysis() const;
    [[nodiscard]] FrontendAnalysisSequenceExportResultDto export_selected_flow_analysis_sequence_csv(
        const std::filesystem::path& output_path
    ) const;

    [[nodiscard]] bool has_capture() const noexcept;
    [[nodiscard]] std::optional<std::size_t> selected_flow_index() const noexcept;
    void clear_selection() noexcept;

private:
    [[nodiscard]] FrontendSourceAvailabilityDto current_source_availability() const;
    [[nodiscard]] static FrontendFlowDto to_frontend_flow(const FlowRow& row);
    [[nodiscard]] static FrontendPacketDto to_frontend_packet(const PacketRow& row);
    [[nodiscard]] FrontendStreamItemDto to_frontend_stream_item(
        const StreamItemRow& row,
        const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers
    ) const;

    CaptureSession session_ {};
    std::optional<std::size_t> selected_flow_index_ {};
};

}  // namespace pfl
