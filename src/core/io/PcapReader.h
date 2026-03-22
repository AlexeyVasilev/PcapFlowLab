#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <vector>

namespace pfl {

struct PcapGlobalHeader {
    std::uint32_t magic_number {0};
    std::uint16_t version_major {0};
    std::uint16_t version_minor {0};
    std::int32_t thiszone {0};
    std::uint32_t sigfigs {0};
    std::uint32_t snaplen {0};
    std::uint32_t network {0};
};

struct PcapPacketHeader {
    std::uint32_t ts_sec {0};
    std::uint32_t ts_usec {0};
    std::uint32_t included_length {0};
    std::uint32_t original_length {0};
};

struct RawPcapPacket {
    std::uint64_t packet_index {0};
    std::uint32_t ts_sec {0};
    std::uint32_t ts_usec {0};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::uint64_t data_offset {0};
    std::vector<std::uint8_t> bytes {};
};

class PcapReader {
public:
    bool open(const std::filesystem::path& path);
    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] bool has_error() const noexcept;
    [[nodiscard]] const PcapGlobalHeader& global_header() const noexcept;
    [[nodiscard]] std::uint32_t data_link_type() const noexcept;
    std::optional<RawPcapPacket> read_next();

private:
    std::ifstream stream_ {};
    PcapGlobalHeader global_header_ {};
    std::uint64_t next_packet_index_ {0};
    bool has_error_ {false};
};

}  // namespace pfl
