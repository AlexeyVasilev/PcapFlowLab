#include "core/io/CaptureFilePacketReader.h"

namespace pfl {

CaptureFilePacketReader::CaptureFilePacketReader(const std::filesystem::path& path)
    : source_(path)
    , reader_(source_) {}

bool CaptureFilePacketReader::is_open() const noexcept {
    return source_.is_open();
}

std::vector<std::uint8_t> CaptureFilePacketReader::read_packet_data(const PacketRef& packet) const {
    return reader_.read_packet_data(packet);
}

bool CaptureFilePacketReader::read_packet_data(const PacketRef& packet, std::vector<std::uint8_t>& out) const {
    return reader_.read_packet_data(packet, out);
}

}  // namespace pfl
