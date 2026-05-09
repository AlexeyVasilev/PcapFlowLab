#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <string>

#include "core/domain/PacketRef.h"

namespace pfl {

struct PerFlowExportTarget {
    std::uint32_t export_flow_id {0};
    std::filesystem::path output_path {};
};

enum class PerFlowExportPhase {
    writing,
};

struct PerFlowExportProgress {
    PerFlowExportPhase phase {PerFlowExportPhase::writing};
    std::uint64_t packets_processed {0};
    std::uint64_t total_packets_to_scan {0};
    std::uint64_t exported_packets_written {0};
};

using PerFlowExportProgressCallback = std::function<void(const PerFlowExportProgress&)>;

struct PerFlowExportOptions {
    std::size_t buffer_budget_bytes {128U * 1024U * 1024U};
    std::size_t max_open_file_handles {64U};
    PerFlowExportProgressCallback progress_callback {};
    std::function<bool()> cancel_requested {};
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
                                       const std::filesystem::path& source_capture_path,
                                       const PerFlowExportOptions& options = {},
                                       std::string* out_error_text = nullptr) const;
};

}  // namespace pfl
