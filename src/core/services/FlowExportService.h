#pragma once

#include <cstdint>
#include <filesystem>
#include <span>

#include "core/domain/PacketRef.h"

namespace pfl {

struct PerFlowExportTarget {
    std::uint32_t export_flow_id {0};
    std::filesystem::path output_path {};
};

class FlowExportService {
public:
    bool export_packets_to_pcap(const std::filesystem::path& output_path,
                                std::span<const PacketRef> packets,
                                const std::filesystem::path& source_capture_path) const;
    bool export_marked_packets_to_pcap(const std::filesystem::path& output_path,
                                       std::span<const std::uint8_t> packet_selection,
                                       const std::filesystem::path& source_capture_path) const;
    bool export_owned_packets_to_pcaps(std::span<const PerFlowExportTarget> targets,
                                       std::span<const std::uint32_t> packet_owner,
                                       const std::filesystem::path& source_capture_path) const;
};

}  // namespace pfl
