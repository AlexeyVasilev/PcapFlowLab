#include "core/io/PcapWriter.h"

#include <cstdint>

namespace pfl {

namespace {

constexpr std::uint32_t kClassicPcapLittleEndianMagic = 0xa1b2c3d4U;
constexpr std::uint16_t kPcapVersionMajor = 2;
constexpr std::uint16_t kPcapVersionMinor = 4;
constexpr std::uint32_t kPcapSnapLength = 65535U;
constexpr std::uint32_t kEthernetLinkType = 1U;

struct PcapGlobalHeader {
    std::uint32_t magic_number {kClassicPcapLittleEndianMagic};
    std::uint16_t version_major {kPcapVersionMajor};
    std::uint16_t version_minor {kPcapVersionMinor};
    std::int32_t thiszone {0};
    std::uint32_t sigfigs {0};
    std::uint32_t snaplen {kPcapSnapLength};
    std::uint32_t network {kEthernetLinkType};
};

struct PcapPacketHeader {
    std::uint32_t ts_sec {0};
    std::uint32_t ts_usec {0};
    std::uint32_t included_length {0};
    std::uint32_t original_length {0};
};

}  // namespace

bool PcapWriter::open(const std::filesystem::path& path) {
    close();

    stream_ = std::ofstream(path, std::ios::binary | std::ios::trunc);
    if (!stream_.is_open()) {
        return false;
    }

    const PcapGlobalHeader header {};
    stream_.write(reinterpret_cast<const char*>(&header), static_cast<std::streamsize>(sizeof(header)));
    return stream_.good();
}

bool PcapWriter::write_packet(const PacketRef& packet, std::span<const std::uint8_t> bytes) {
    if (!stream_.is_open()) {
        return false;
    }

    if (bytes.size() != packet.captured_length) {
        return false;
    }

    const PcapPacketHeader header {
        .ts_sec = packet.ts_sec,
        .ts_usec = packet.ts_usec,
        .included_length = packet.captured_length,
        .original_length = packet.original_length,
    };

    stream_.write(reinterpret_cast<const char*>(&header), static_cast<std::streamsize>(sizeof(header)));
    stream_.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream_.good();
}

void PcapWriter::close() {
    if (stream_.is_open()) {
        stream_.close();
    }
}

bool PcapWriter::is_open() const noexcept {
    return stream_.is_open();
}

}  // namespace pfl
