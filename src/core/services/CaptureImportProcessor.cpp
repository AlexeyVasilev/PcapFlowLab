#include "core/services/CaptureImportProcessor.h"

#include <span>

#include "core/index/CaptureIndex.h"
#include "core/services/PacketIngestor.h"

namespace pfl {

namespace {

constexpr std::uint32_t kEthernetLinkType = 1U;

template <typename Reader>
bool import_packets(Reader& reader, CaptureState& state, const CaptureImportProcessor& processor) {
    while (const auto packet = reader.read_next()) {
        processor.process_packet(*packet, state);
    }

    return !reader.has_error();
}

}  // namespace

CaptureImportProcessor::CaptureImportProcessor(const AnalysisSettings settings)
    : hint_service_(settings) {
}

void CaptureImportProcessor::process_packet(const RawPcapPacket& packet, CaptureState& state) const {
    PacketIngestor ingestor {state};

    const auto decoded = decoder_.decode_ethernet(packet);
    const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());

    if (decoded.ipv4.has_value()) {
        ingestor.ingest(*decoded.ipv4);
        auto& connection = state.ipv4_connections.get_or_create(make_connection_key(decoded.ipv4->flow_key));
        connection.apply_hints(hint_service_.detect(packet_bytes, decoded.ipv4->flow_key));
        return;
    }

    if (decoded.ipv6.has_value()) {
        ingestor.ingest(*decoded.ipv6);
        auto& connection = state.ipv6_connections.get_or_create(make_connection_key(decoded.ipv6->flow_key));
        connection.apply_hints(hint_service_.detect(packet_bytes, decoded.ipv6->flow_key));
    }
}

bool import_capture_from_reader(PcapReader& reader, CaptureState& state, const CaptureImportProcessor& processor) {
    if (reader.data_link_type() != kEthernetLinkType) {
        return false;
    }

    return import_packets(reader, state, processor);
}

bool import_capture_from_reader(PcapNgReader& reader, CaptureState& state, const CaptureImportProcessor& processor) {
    return import_packets(reader, state, processor);
}

bool import_capture_from_path(const std::filesystem::path& path, CaptureState& state, const CaptureImportProcessor& processor) {
    switch (detect_capture_source_format(path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(path)) {
            return false;
        }

        return import_capture_from_reader(reader, state, processor);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(path)) {
            return false;
        }

        return import_capture_from_reader(reader, state, processor);
    }
    default:
        return false;
    }
}

}  // namespace pfl
