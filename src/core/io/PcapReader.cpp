#include "core/io/PcapReader.h"

namespace pfl {

namespace {

constexpr std::uint32_t kClassicPcapLittleEndianMagic = 0xa1b2c3d4U;

}  // namespace

bool PcapReader::open(const std::filesystem::path& path) {
    stream_ = std::ifstream(path, std::ios::binary);
    global_header_ = {};
    next_packet_index_ = 0;
    has_error_ = false;

    if (!stream_.is_open()) {
        return false;
    }

    stream_.read(reinterpret_cast<char*>(&global_header_), sizeof(global_header_));
    if (stream_.gcount() != static_cast<std::streamsize>(sizeof(global_header_))) {
        stream_.close();
        return false;
    }

    if (global_header_.magic_number != kClassicPcapLittleEndianMagic) {
        stream_.close();
        return false;
    }

    if (global_header_.version_major != 2 || global_header_.version_minor != 4) {
        stream_.close();
        return false;
    }

    if (global_header_.snaplen == 0) {
        stream_.close();
        return false;
    }

    return true;
}

bool PcapReader::is_open() const noexcept {
    return stream_.is_open();
}

bool PcapReader::has_error() const noexcept {
    return has_error_;
}

const PcapGlobalHeader& PcapReader::global_header() const noexcept {
    return global_header_;
}

std::uint32_t PcapReader::data_link_type() const noexcept {
    return global_header_.network;
}

std::optional<RawPcapPacket> PcapReader::read_next() {
    if (!stream_.is_open()) {
        return std::nullopt;
    }

    PcapPacketHeader packet_header {};
    stream_.read(reinterpret_cast<char*>(&packet_header), sizeof(packet_header));
    if (stream_.gcount() == 0) {
        return std::nullopt;
    }

    if (stream_.gcount() != static_cast<std::streamsize>(sizeof(packet_header))) {
        has_error_ = true;
        return std::nullopt;
    }

    const auto data_offset = static_cast<std::uint64_t>(stream_.tellg());
    std::vector<std::uint8_t> bytes(packet_header.included_length);
    stream_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (stream_.gcount() != static_cast<std::streamsize>(bytes.size())) {
        has_error_ = true;
        return std::nullopt;
    }

    RawPcapPacket packet {
        .packet_index = next_packet_index_,
        .ts_sec = packet_header.ts_sec,
        .ts_usec = packet_header.ts_usec,
        .captured_length = packet_header.included_length,
        .original_length = packet_header.original_length,
        .data_offset = data_offset,
        .bytes = std::move(bytes),
    };
    ++next_packet_index_;
    return packet;
}

}  // namespace pfl
