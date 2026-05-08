#include "core/services/FlowExportService.h"

#include <algorithm>
#include <vector>

#include "core/index/CaptureIndex.h"
#include "core/io/CaptureFilePacketReader.h"
#include "core/io/LinkType.h"
#include "core/io/PcapNgReader.h"
#include "core/io/PcapReader.h"
#include "core/io/PcapWriter.h"

namespace pfl {

namespace {

template <typename Reader>
bool export_marked_packets_with_reader(
    Reader& reader,
    const std::filesystem::path& output_path,
    std::span<const std::uint8_t> packet_selection
) {
    PcapWriter writer {};
    bool writer_open = false;
    auto remaining_marked_packets = static_cast<std::size_t>(std::count_if(
        packet_selection.begin(),
        packet_selection.end(),
        [](const std::uint8_t marker) { return marker != 0U; }
    ));

    if (remaining_marked_packets == 0U) {
        return false;
    }

    while (const auto raw_packet = reader.read_next()) {
        if (raw_packet->packet_index >= packet_selection.size()) {
            break;
        }

        if (packet_selection[static_cast<std::size_t>(raw_packet->packet_index)] == 0U) {
            continue;
        }

        if (!writer_open) {
            if (!writer.open(output_path, raw_packet->data_link_type)) {
                return false;
            }
            writer_open = true;
        }

        const PacketRef packet_ref {
            .packet_index = raw_packet->packet_index,
            .byte_offset = raw_packet->data_offset,
            .data_link_type = raw_packet->data_link_type,
            .captured_length = raw_packet->captured_length,
            .original_length = raw_packet->original_length,
            .ts_sec = raw_packet->ts_sec,
            .ts_usec = raw_packet->ts_usec,
        };

        if (!writer.write_packet(packet_ref, raw_packet->bytes)) {
            writer.close();
            return false;
        }

        --remaining_marked_packets;
        if (remaining_marked_packets == 0U) {
            writer.close();
            return true;
        }
    }

    if (!writer_open) {
        return false;
    }

    writer.close();
    return remaining_marked_packets == 0U && !reader.has_error();
}

template <typename Reader>
bool export_owned_packets_with_reader(
    Reader& reader,
    std::span<const PerFlowExportTarget> targets,
    std::span<const std::uint32_t> packet_owner
) {
    auto remaining_owned_packets = static_cast<std::size_t>(std::count_if(
        packet_owner.begin(),
        packet_owner.end(),
        [](const std::uint32_t owner) { return owner != 0U; }
    ));
    if (remaining_owned_packets == 0U || targets.empty()) {
        return false;
    }

    std::vector<PcapWriter> writers(targets.size());
    std::vector<bool> writer_open(targets.size(), false);

    while (const auto raw_packet = reader.read_next()) {
        if (raw_packet->packet_index >= packet_owner.size()) {
            break;
        }

        const auto owner = packet_owner[static_cast<std::size_t>(raw_packet->packet_index)];
        if (owner == 0U) {
            continue;
        }

        const auto target_index = static_cast<std::size_t>(owner - 1U);
        if (target_index >= targets.size() || targets[target_index].export_flow_id != owner) {
            for (std::size_t index = 0; index < writers.size(); ++index) {
                if (writer_open[index]) {
                    writers[index].close();
                }
            }
            return false;
        }

        if (!writer_open[target_index]) {
            if (!writers[target_index].open(targets[target_index].output_path, raw_packet->data_link_type)) {
                for (std::size_t index = 0; index < writers.size(); ++index) {
                    if (writer_open[index]) {
                        writers[index].close();
                    }
                }
                return false;
            }
            writer_open[target_index] = true;
        }

        const PacketRef packet_ref {
            .packet_index = raw_packet->packet_index,
            .byte_offset = raw_packet->data_offset,
            .data_link_type = raw_packet->data_link_type,
            .captured_length = raw_packet->captured_length,
            .original_length = raw_packet->original_length,
            .ts_sec = raw_packet->ts_sec,
            .ts_usec = raw_packet->ts_usec,
        };

        if (!writers[target_index].write_packet(packet_ref, raw_packet->bytes)) {
            for (std::size_t index = 0; index < writers.size(); ++index) {
                if (writer_open[index]) {
                    writers[index].close();
                }
            }
            return false;
        }

        --remaining_owned_packets;
        if (remaining_owned_packets == 0U) {
            for (std::size_t index = 0; index < writers.size(); ++index) {
                if (writer_open[index]) {
                    writers[index].close();
                }
            }
            return true;
        }
    }

    for (std::size_t index = 0; index < writers.size(); ++index) {
        if (writer_open[index]) {
            writers[index].close();
        }
    }

    return std::all_of(writer_open.begin(), writer_open.end(), [](const bool opened) { return opened; }) &&
           remaining_owned_packets == 0U &&
           !reader.has_error();
}

}  // namespace

bool FlowExportService::export_packets_to_pcap(const std::filesystem::path& output_path,
                                               std::span<const PacketRef> packets,
                                               const std::filesystem::path& source_capture_path) const {
    CaptureFilePacketReader reader {source_capture_path};
    if (!reader.is_open()) {
        return false;
    }

    PcapWriter writer {};
    const auto link_type = packets.empty() ? kLinkTypeEthernet : packets.front().data_link_type;
    if (!writer.open(output_path, link_type)) {
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

bool FlowExportService::export_marked_packets_to_pcap(
    const std::filesystem::path& output_path,
    std::span<const std::uint8_t> packet_selection,
    const std::filesystem::path& source_capture_path
) const {
    if (packet_selection.empty()) {
        return false;
    }

    switch (detect_capture_source_format(source_capture_path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(source_capture_path)) {
            return false;
        }

        return export_marked_packets_with_reader(reader, output_path, packet_selection);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(source_capture_path)) {
            return false;
        }

        return export_marked_packets_with_reader(reader, output_path, packet_selection);
    }
    default:
        return false;
    }
}

bool FlowExportService::export_owned_packets_to_pcaps(
    std::span<const PerFlowExportTarget> targets,
    std::span<const std::uint32_t> packet_owner,
    const std::filesystem::path& source_capture_path
) const {
    if (targets.empty() || packet_owner.empty()) {
        return false;
    }

    switch (detect_capture_source_format(source_capture_path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(source_capture_path)) {
            return false;
        }

        return export_owned_packets_with_reader(reader, targets, packet_owner);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(source_capture_path)) {
            return false;
        }

        return export_owned_packets_with_reader(reader, targets, packet_owner);
    }
    default:
        return false;
    }
}

}  // namespace pfl
