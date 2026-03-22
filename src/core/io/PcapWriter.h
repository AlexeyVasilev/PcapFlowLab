#pragma once

#include <filesystem>
#include <fstream>
#include <span>

#include "core/domain/PacketRef.h"

namespace pfl {

class PcapWriter {
public:
    bool open(const std::filesystem::path& path);
    bool write_packet(const PacketRef& packet, std::span<const std::uint8_t> bytes);
    void close();

    [[nodiscard]] bool is_open() const noexcept;

private:
    std::ofstream stream_ {};
};

}  // namespace pfl
