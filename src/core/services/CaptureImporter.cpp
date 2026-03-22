#include "core/services/CaptureImporter.h"

#include "core/decode/PacketDecoder.h"
#include "core/io/PcapReader.h"
#include "core/services/PacketIngestor.h"

namespace pfl {

namespace {

constexpr std::uint32_t kEthernetLinkType = 1;

}  // namespace

bool CaptureImporter::import_pcap(const std::filesystem::path& path, CaptureState& state) {
    state = {};

    PcapReader reader {};
    if (!reader.open(path)) {
        return false;
    }

    if (reader.data_link_type() != kEthernetLinkType) {
        return false;
    }

    PacketDecoder decoder {};
    PacketIngestor ingestor {state};

    while (const auto packet = reader.read_next()) {
        const auto decoded = decoder.decode_ethernet(*packet);
        if (decoded.ipv4.has_value()) {
            ingestor.ingest(*decoded.ipv4);
            continue;
        }

        if (decoded.ipv6.has_value()) {
            ingestor.ingest(*decoded.ipv6);
        }
    }

    return !reader.has_error();
}

}  // namespace pfl
