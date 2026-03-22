#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <vector>

#include "core/io/PcapReader.h"

namespace pfl {

struct PcapNgTimestampResolution {
    bool power_of_two {false};
    std::uint8_t exponent {6};
};

struct PcapNgInterfaceInfo {
    std::uint16_t linktype {0};
    std::uint32_t snaplen {0};
    PcapNgTimestampResolution timestamp_resolution {};
};

class PcapNgReader {
public:
    bool open(const std::filesystem::path& path);
    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] bool has_error() const noexcept;
    std::optional<RawPcapPacket> read_next();

private:
    bool parse_section_header();
    bool parse_interface_description(std::span<const std::uint8_t> body);

    std::ifstream stream_ {};
    std::vector<PcapNgInterfaceInfo> interfaces_ {};
    std::uint64_t next_packet_index_ {0};
    bool has_error_ {false};
    bool little_endian_ {true};
};

}  // namespace pfl
