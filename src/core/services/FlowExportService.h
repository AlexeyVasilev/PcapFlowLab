#pragma once

#include <filesystem>
#include <span>

#include "core/domain/PacketRef.h"

namespace pfl {

class FlowExportService {
public:
    bool export_packets_to_pcap(const std::filesystem::path& output_path,
                                std::span<const PacketRef> packets,
                                const std::filesystem::path& source_capture_path) const;
};

}  // namespace pfl
