#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/CaptureState.h"
#include "core/domain/PacketDetails.h"

namespace pfl {

class CaptureSession {
public:
    bool open_capture(const std::filesystem::path& path);
    [[nodiscard]] bool has_capture() const noexcept;
    [[nodiscard]] const CaptureSummary& summary() const noexcept;
    [[nodiscard]] std::vector<std::uint8_t> read_packet_data(const PacketRef& packet) const;
    [[nodiscard]] std::optional<PacketDetails> read_packet_details(const PacketRef& packet) const;
    [[nodiscard]] std::string read_packet_hex_dump(const PacketRef& packet) const;
    [[nodiscard]] std::vector<FlowRowV4> list_ipv4_flows() const;
    [[nodiscard]] std::vector<FlowRowV6> list_ipv6_flows() const;
    [[nodiscard]] std::optional<PacketRef> find_packet(std::uint64_t packet_index) const;
    [[nodiscard]] CaptureState& state() noexcept;
    [[nodiscard]] const CaptureState& state() const noexcept;

private:
    std::filesystem::path capture_path_ {};
    CaptureState state_ {};
};

}  // namespace pfl
