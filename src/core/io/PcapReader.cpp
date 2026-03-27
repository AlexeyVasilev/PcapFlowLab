#include "core/io/PcapReader.h"

namespace pfl {

namespace {

constexpr std::uint32_t kClassicPcapLittleEndianMagic = 0xa1b2c3d4U;
constexpr std::uint64_t kPcapGlobalHeaderSize = sizeof(PcapGlobalHeader);

}  // namespace

bool PcapReader::open(const std::filesystem::path& path) {
    return open(path, 0, 0);
}

bool PcapReader::open(const std::filesystem::path& path, std::uint64_t next_input_offset, std::uint64_t next_packet_index) {
    stream_ = std::ifstream(path, std::ios::binary);
    global_header_ = {};
    next_packet_index_ = 0;
    next_input_offset_ = 0;
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

    next_input_offset_ = kPcapGlobalHeaderSize;
    next_packet_index_ = next_packet_index;

    if (next_input_offset != 0) {
        if (next_input_offset < kPcapGlobalHeaderSize) {
            stream_.close();
            return false;
        }

        stream_.seekg(static_cast<std::streamoff>(next_input_offset), std::ios::beg);
        if (!stream_) {
            stream_.close();
            return false;
        }
        next_input_offset_ = next_input_offset;
    }

    return true;
}

bool PcapReader::is_open() const noexcept {
    return stream_.is_open();
}

bool PcapReader::has_error() const noexcept {
    return has_error_;
}

bool PcapReader::at_eof() {
    if (!stream_.is_open()) {
        return true;
    }

    const auto next = stream_.peek();
    if (next == std::char_traits<char>::eof()) {
        stream_.clear();
        return true;
    }

    return false;
}

const PcapGlobalHeader& PcapReader::global_header() const noexcept {
    return global_header_;
}

std::uint32_t PcapReader::data_link_type() const noexcept {
    return global_header_.network;
}

std::uint64_t PcapReader::next_input_offset() const noexcept {
    return next_input_offset_;
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

    next_input_offset_ = static_cast<std::uint64_t>(stream_.tellg());

    RawPcapPacket packet {
        .packet_index = next_packet_index_,
        .ts_sec = packet_header.ts_sec,
        .ts_usec = packet_header.ts_usec,
        .captured_length = packet_header.included_length,
        .original_length = packet_header.original_length,
        .data_offset = data_offset,
        .data_link_type = global_header_.network,
        .bytes = std::move(bytes),
    };
    ++next_packet_index_;
    return packet;
}

}  // namespace pfl
