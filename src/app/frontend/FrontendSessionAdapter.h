#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <vector>

#include "app/frontend/FrontendDtos.h"
#include "app/session/CaptureSession.h"

namespace pfl {

class FrontendSessionAdapter {
public:
    FrontendSessionAdapter() = default;

    [[nodiscard]] FrontendOpenResult open_capture(const std::filesystem::path& path, FrontendOpenMode open_mode);
    [[nodiscard]] FrontendOverviewDto get_overview() const;
    [[nodiscard]] std::vector<FrontendFlowDto> get_flows() const;
    [[nodiscard]] bool select_flow(std::size_t flow_index);
    [[nodiscard]] FrontendSelectedFlowPacketsResult get_selected_flow_packets(std::size_t offset, std::size_t limit);

    [[nodiscard]] bool has_capture() const noexcept;
    [[nodiscard]] std::optional<std::size_t> selected_flow_index() const noexcept;
    void clear_selection() noexcept;

private:
    [[nodiscard]] static FrontendFlowDto to_frontend_flow(const FlowRow& row);
    [[nodiscard]] static FrontendPacketDto to_frontend_packet(const PacketRow& row);

    CaptureSession session_ {};
    std::optional<std::size_t> selected_flow_index_ {};
};

}  // namespace pfl
