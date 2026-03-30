#include "core/io/PcapReader.h"

namespace pfl {

namespace {

constexpr std::uint32_t kClassicPcapLittleEndianMagic = 0xa1b2c3d4U;
constexpr std::uint64_t kPcapGlobalHeaderSize = sizeof(PcapGlobalHeader);

}  // namespace

void PcapReader::clear_error() {
    has_error_ = false;
    last_error_ = {};
}

void PcapReader::set_error(std::uint64_t file_offset, const char* reason, const bool include_packet_index) {
    has_error_ = true;
    last_error_ = {};
    last_error_.has_file_offset = true;
    last_error_.file_offset = file_offset;
    last_error_.reason = reason;
    if (include_packet_index) {
        last_error_.has_packet_index = true;
        last_error_.packet_index = next_packet_index_;
    }
}

void PcapReader::set_error(const char* reason) {
    has_error_ = true;
    last_error_ = {};
    last_error_.reason = reason;
}

bool PcapReader::open(const std::filesystem::path& path) {
    return open(path, 0, 0);
}

bool PcapReader::open(const std::filesystem::path& path, std::uint64_t next_input_offset, std::uint64_t next_packet_index) {
    stream_ = std::ifstream(path, std::ios::binary);
    global_header_ = {};
    next_packet_index_ = 0;
    next_input_offset_ = 0;
    clear_error();

    if (!stream_.is_open()) {
        set_error("file access failed");
        return false;
    }

    stream_.read(reinterpret_cast<char*>(&global_header_), sizeof(global_header_));
    if (stream_.gcount() != static_cast<std::streamsize>(sizeof(global_header_))) {
        set_error(0, "unexpected EOF while reading PCAP global header");
        stream_.close();
        return false;
    }

    if (global_header_.magic_number != kClassicPcapLittleEndianMagic) {
        set_error(0, "unsupported PCAP magic number");
        stream_.close();
        return false;
    }

    if (global_header_.version_major != 2 || global_header_.version_minor != 4) {
        set_error(0, "unsupported PCAP version");
        stream_.close();
        return false;
    }

    if (global_header_.snaplen == 0) {
        set_error(0, "invalid PCAP snaplen");
        stream_.close();
        return false;
    }

    next_input_offset_ = kPcapGlobalHeaderSize;
    next_packet_index_ = next_packet_index;

    if (next_input_offset != 0) {
        if (next_input_offset < kPcapGlobalHeaderSize) {
            set_error(next_input_offset, "invalid resume offset");
            stream_.close();
            return false;
        }

        stream_.seekg(static_cast<std::streamoff>(next_input_offset), std::ios::beg);
        if (!stream_) {
            set_error(next_input_offset, "seek failed");
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

const OpenFailureInfo& PcapReader::last_error() const noexcept {
    return last_error_;
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

    const auto packet_header_offset = next_input_offset_;
    PcapPacketHeader packet_header {};
    stream_.read(reinterpret_cast<char*>(&packet_header), sizeof(packet_header));
    if (stream_.gcount() == 0) {
        return std::nullopt;
    }

    if (stream_.gcount() != static_cast<std::streamsize>(sizeof(packet_header))) {
        set_error(packet_header_offset, "unexpected EOF while reading packet header", true);
        return std::nullopt;
    }

    const auto data_offset = static_cast<std::uint64_t>(stream_.tellg());
    std::vector<std::uint8_t> bytes(packet_header.included_length);
    stream_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (stream_.gcount() != static_cast<std::streamsize>(bytes.size())) {
        set_error(data_offset, "unexpected EOF while reading packet data", true);
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

