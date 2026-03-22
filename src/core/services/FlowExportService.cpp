#include "core/services/FlowExportService.h"

#include <vector>

#include "core/io/CaptureFilePacketReader.h"
#include "core/io/PcapWriter.h"

namespace pfl {

bool FlowExportService::export_packets_to_pcap(const std::filesystem::path& output_path,
                                               std::span<const PacketRef> packets,
                                               const std::filesystem::path& source_capture_path) const {
    CaptureFilePacketReader reader {source_capture_path};
    if (!reader.is_open()) {
        return false;
    }

    PcapWriter writer {};
    if (!writer.open(output_path)) {
        return false;
    }

    std::vector<std::uint8_t> bytes {};
    for (const auto& packet : packets) {
        if (!reader.read_packet_data(packet, bytes)) {
            writer.close();
            return false;
        }

        if (!writer.write_packet(packet, bytes)) {
            writer.close();
            return false;
        }
    }

    writer.close();
    return true;
}

}  // namespace pfl
