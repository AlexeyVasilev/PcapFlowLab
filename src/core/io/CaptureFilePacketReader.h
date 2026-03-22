#pragma once

#include <filesystem>
#include <vector>

#include "core/domain/PacketRef.h"
#include "core/io/FileByteSource.h"
#include "core/io/PacketDataReader.h"

namespace pfl {

class CaptureFilePacketReader {
public:
    explicit CaptureFilePacketReader(const std::filesystem::path& path);

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] std::vector<std::uint8_t> read_packet_data(const PacketRef& packet) const;
    [[nodiscard]] bool read_packet_data(const PacketRef& packet, std::vector<std::uint8_t>& out) const;

private:
    FileByteSource source_;
    PacketDataReader reader_;
};

}  // namespace pfl
