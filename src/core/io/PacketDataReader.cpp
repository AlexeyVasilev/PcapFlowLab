#include "core/io/PacketDataReader.h"

namespace pfl {

PacketDataReader::PacketDataReader(IByteSource& source) noexcept
    : source_(source) {}

std::vector<std::uint8_t> PacketDataReader::read_packet_data(const PacketRef& packet) const {
    std::vector<std::uint8_t> out {};
    if (!read_packet_data(packet, out)) {
        return {};
    }
    return out;
}

bool PacketDataReader::read_packet_data(const PacketRef& packet, std::vector<std::uint8_t>& out) const {
    out.resize(packet.captured_length);
    return source_.read_at(packet.byte_offset, std::span<std::uint8_t>(out));
}

}  // namespace pfl
