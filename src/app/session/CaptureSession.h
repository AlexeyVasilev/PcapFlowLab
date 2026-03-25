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
    bool open_input(const std::filesystem::path& path);
    bool save_index(const std::filesystem::path& index_path) const;
    bool load_index(const std::filesystem::path& index_path);
    [[nodiscard]] bool has_capture() const noexcept;
    [[nodiscard]] const std::filesystem::path& capture_path() const noexcept;
    [[nodiscard]] const CaptureSummary& summary() const noexcept;
    [[nodiscard]] CaptureProtocolSummary protocol_summary() const noexcept;
    [[nodiscard]] CaptureTopSummary top_summary(std::size_t limit = 5) const;
    [[nodiscard]] std::vector<std::uint8_t> read_packet_data(const PacketRef& packet) const;
    [[nodiscard]] std::optional<PacketDetails> read_packet_details(const PacketRef& packet) const;
    [[nodiscard]] std::string read_packet_hex_dump(const PacketRef& packet) const;
    [[nodiscard]] std::string read_packet_payload_hex_dump(const PacketRef& packet) const;
    [[nodiscard]] std::vector<FlowRow> list_flows() const;
    [[nodiscard]] std::vector<PacketRow> list_flow_packets(std::size_t flow_index) const;
    [[nodiscard]] std::optional<std::vector<PacketRef>> flow_packets(std::size_t flow_index) const;
    bool export_flow_to_pcap(std::size_t flow_index, const std::filesystem::path& output_path) const;
    [[nodiscard]] std::optional<PacketRef> find_packet(std::uint64_t packet_index) const;
    [[nodiscard]] CaptureState& state() noexcept;
    [[nodiscard]] const CaptureState& state() const noexcept;

private:
    std::filesystem::path capture_path_ {};
    CaptureState state_ {};
};

}  // namespace pfl
