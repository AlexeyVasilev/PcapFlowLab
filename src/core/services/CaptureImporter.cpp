#include "core/services/CaptureImporter.h"

#include <array>
#include <fstream>

#include "core/decode/PacketDecoder.h"
#include "core/io/PcapNgReader.h"
#include "core/io/PcapReader.h"
#include "core/services/FlowHintService.h"
#include "core/services/PacketIngestor.h"

namespace pfl {

namespace {

enum class CaptureFormat : std::uint8_t {
    unknown,
    classic_pcap,
    pcapng,
};

constexpr std::uint32_t kEthernetLinkType = 1U;
constexpr std::array<std::uint8_t, 4> kClassicPcapLittleEndianMagicBytes {0xd4U, 0xc3U, 0xb2U, 0xa1U};
constexpr std::array<std::uint8_t, 4> kPcapNgSectionHeaderMagicBytes {0x0aU, 0x0dU, 0x0dU, 0x0aU};

CaptureFormat detect_capture_format(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        return CaptureFormat::unknown;
    }

    std::array<std::uint8_t, 4> header {};
    stream.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (stream.gcount() != static_cast<std::streamsize>(header.size())) {
        return CaptureFormat::unknown;
    }

    if (header == kClassicPcapLittleEndianMagicBytes) {
        return CaptureFormat::classic_pcap;
    }

    if (header == kPcapNgSectionHeaderMagicBytes) {
        return CaptureFormat::pcapng;
    }

    return CaptureFormat::unknown;
}

template <typename Reader>
bool import_packets(Reader& reader, CaptureState& state) {
    PacketDecoder decoder {};
    PacketIngestor ingestor {state};
    FlowHintService hint_service {};

    while (const auto packet = reader.read_next()) {
        const auto decoded = decoder.decode_ethernet(*packet);
        const auto packet_bytes = std::span<const std::uint8_t>(packet->bytes.data(), packet->bytes.size());

        if (decoded.ipv4.has_value()) {
            ingestor.ingest(*decoded.ipv4);
            auto& connection = state.ipv4_connections.get_or_create(make_connection_key(decoded.ipv4->flow_key));
            connection.apply_hints(hint_service.detect(packet_bytes, decoded.ipv4->flow_key));
            continue;
        }

        if (decoded.ipv6.has_value()) {
            ingestor.ingest(*decoded.ipv6);
            auto& connection = state.ipv6_connections.get_or_create(make_connection_key(decoded.ipv6->flow_key));
            connection.apply_hints(hint_service.detect(packet_bytes, decoded.ipv6->flow_key));
        }
    }

    return !reader.has_error();
}

}  // namespace

bool CaptureImporter::import_capture(const std::filesystem::path& path, CaptureState& state) {
    state = {};

    switch (detect_capture_format(path)) {
    case CaptureFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(path)) {
            return false;
        }

        if (reader.data_link_type() != kEthernetLinkType) {
            return false;
        }

        return import_packets(reader, state);
    }
    case CaptureFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(path)) {
            return false;
        }

        return import_packets(reader, state);
    }
    default:
        return false;
    }
}

}  // namespace pfl
