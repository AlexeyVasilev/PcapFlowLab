#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <vector>

#include "core/io/LinkType.h"
#include "core/open_failure_info.h"

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
    std::uint32_t data_link_type {kLinkTypeEthernet};
    std::vector<std::uint8_t> bytes {};
};

class PcapReader {
public:
    bool open(const std::filesystem::path& path);
    bool open(const std::filesystem::path& path, std::uint64_t next_input_offset, std::uint64_t next_packet_index);
    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] bool has_error() const noexcept;
    [[nodiscard]] const OpenFailureInfo& last_error() const noexcept;
    [[nodiscard]] bool at_eof();
    [[nodiscard]] const PcapGlobalHeader& global_header() const noexcept;
    [[nodiscard]] std::uint32_t data_link_type() const noexcept;
    [[nodiscard]] std::uint64_t next_input_offset() const noexcept;
    std::optional<RawPcapPacket> read_next();
    std::optional<RawPcapPacket> read_next_prefix(std::size_t prefix_bytes);
    // Import-specific hybrid path: small packets are read fully, while staged-eligible
    // packets return only the current prefix and must be materialized/finalized before
    // the next packet can be read.
    std::optional<RawPcapPacket> read_next_import_packet(
        std::size_t prefix_bytes,
        std::size_t min_staged_captured_length_bytes
    );
    // Import-only reusable-buffer path. EOF and read failures both return false;
    // callers distinguish them through has_error().
    bool read_next_import_packet_into(
        RawPcapPacket& packet,
        std::size_t prefix_bytes,
        std::size_t min_staged_captured_length_bytes
    );
    bool materialize_packet_bytes(RawPcapPacket& packet);
    bool finish_prefix_packet(const RawPcapPacket& packet);

private:
    struct PrefixPacketState {
        // `read_next_prefix()` leaves the reader positioned after the prefix bytes
        // of the current packet until the caller either materializes the
        // remaining bytes sequentially or explicitly finalizes/skips them.
        bool active {false};
        std::uint64_t packet_index {0};
        std::uint64_t data_offset {0};
        std::uint64_t next_record_offset {0};
        std::uint32_t captured_length {0};
    };

    void clear_prefix_packet_state() noexcept;
    [[nodiscard]] bool is_current_prefix_packet(const RawPcapPacket& packet) const noexcept;
    void clear_error();
    void set_error(std::uint64_t file_offset, const char* reason, bool include_packet_index = false);
    void set_error(std::uint64_t file_offset, const char* reason, std::uint64_t packet_index);
    void set_error(const char* reason);

    std::ifstream stream_ {};
    PcapGlobalHeader global_header_ {};
    std::uint64_t next_packet_index_ {0};
    std::uint64_t next_input_offset_ {0};
    PrefixPacketState prefix_packet_state_ {};
    bool has_error_ {false};
    OpenFailureInfo last_error_ {};
};

}  // namespace pfl

