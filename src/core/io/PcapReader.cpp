#include "core/io/PcapReader.h"

#include <algorithm>

#include "core/io/ErfRecord.h"

namespace pfl {

namespace {

constexpr std::uint32_t kClassicPcapLittleEndianMagic = 0xa1b2c3d4U;
constexpr std::uint64_t kPcapGlobalHeaderSize = sizeof(PcapGlobalHeader);

[[nodiscard]] std::size_t bounded_erf_prefix_read_size(
    const std::size_t requested_network_prefix_bytes,
    const std::uint32_t captured_record_length
) noexcept {
    const auto captured_bytes = static_cast<std::size_t>(captured_record_length);
    if (requested_network_prefix_bytes >= captured_bytes) {
        return captured_bytes;
    }

    const auto remaining_bytes = captured_bytes - requested_network_prefix_bytes;
    return requested_network_prefix_bytes + std::min(remaining_bytes, erf::kMaxSupportedEnvelopeBytes);
}

[[nodiscard]] std::size_t physical_prefix_read_size(
    const std::uint32_t link_type,
    const std::size_t requested_prefix_bytes,
    const std::uint32_t captured_record_length
) noexcept {
    if (link_type == kLinkTypeErf) {
        return bounded_erf_prefix_read_size(requested_prefix_bytes, captured_record_length);
    }

    return std::min<std::size_t>(requested_prefix_bytes, captured_record_length);
}

void normalize_erf_type_eth_packet(RawPcapPacket& packet) {
    if (packet.data_link_type != kLinkTypeErf) {
        return;
    }

    const auto view = erf::parse_type_eth_view(
        std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size()),
        packet.captured_length
    );
    if (view.status != erf::TypeEthParseStatus::ok) {
        return;
    }

    const auto network_offset = view.network_offset;
    if (network_offset > packet.bytes.size()) {
        return;
    }

    packet.bytes.erase(
        packet.bytes.begin(),
        packet.bytes.begin() + static_cast<std::ptrdiff_t>(network_offset)
    );
    packet.data_offset += static_cast<std::uint64_t>(network_offset);
    packet.data_link_type = kLinkTypeEthernet;
    packet.captured_length = view.captured_network_length;
    packet.original_length = view.original_network_length;
}

}  // namespace

void PcapReader::clear_prefix_packet_state() noexcept {
    prefix_packet_state_ = {};
}

bool PcapReader::is_current_prefix_packet(const RawPcapPacket& packet) const noexcept {
    return prefix_packet_state_.active &&
        prefix_packet_state_.packet_index == packet.packet_index &&
        prefix_packet_state_.data_offset == packet.data_offset &&
        prefix_packet_state_.captured_length == packet.captured_length;
}

bool PcapReader::trim_erf_prefix_overread(RawPcapPacket& packet, const std::size_t requested_network_prefix_bytes) {
    if (global_header_.network != kLinkTypeErf ||
        packet.data_link_type != kLinkTypeEthernet ||
        requested_network_prefix_bytes >= packet.captured_length ||
        packet.bytes.size() <= requested_network_prefix_bytes) {
        return true;
    }

    const auto overread_bytes = packet.bytes.size() - requested_network_prefix_bytes;
    stream_.seekg(-static_cast<std::streamoff>(overread_bytes), std::ios::cur);
    if (!stream_) {
        set_error(next_input_offset_, "seek failed", packet.packet_index);
        return false;
    }

    next_input_offset_ -= static_cast<std::uint64_t>(overread_bytes);
    packet.bytes.resize(requested_network_prefix_bytes);
    return true;
}

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

void PcapReader::set_error(const std::uint64_t file_offset, const char* reason, const std::uint64_t packet_index) {
    has_error_ = true;
    last_error_ = {};
    last_error_.has_file_offset = true;
    last_error_.file_offset = file_offset;
    last_error_.reason = reason;
    last_error_.has_packet_index = true;
    last_error_.packet_index = packet_index;
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
    clear_prefix_packet_state();
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

    if (prefix_packet_state_.active) {
        set_error(next_input_offset_, "current prefix packet must be finalized before reading next packet",
                  prefix_packet_state_.packet_index);
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
        .record_file_offset = packet_header_offset,
        .data_offset = data_offset,
        .data_link_type = global_header_.network,
        .bytes = std::move(bytes),
    };
    normalize_erf_type_eth_packet(packet);
    ++next_packet_index_;
    return packet;
}

std::optional<RawPcapPacket> PcapReader::read_next_prefix(const std::size_t prefix_bytes) {
    if (!stream_.is_open()) {
        return std::nullopt;
    }

    if (prefix_packet_state_.active) {
        set_error(next_input_offset_, "current prefix packet must be finalized before reading next packet",
                  prefix_packet_state_.packet_index);
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

    const auto data_offset = packet_header_offset + sizeof(packet_header);
    const auto available_prefix_bytes =
        physical_prefix_read_size(global_header_.network, prefix_bytes, packet_header.included_length);
    std::vector<std::uint8_t> bytes(available_prefix_bytes);
    if (!bytes.empty()) {
        stream_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (stream_.gcount() != static_cast<std::streamsize>(bytes.size())) {
            set_error(data_offset, "unexpected EOF while reading packet data", next_packet_index_);
            return std::nullopt;
        }
    }

    const auto next_record_offset = data_offset + packet_header.included_length;
    next_input_offset_ = data_offset + static_cast<std::uint64_t>(available_prefix_bytes);

    RawPcapPacket packet {
        .packet_index = next_packet_index_,
        .ts_sec = packet_header.ts_sec,
        .ts_usec = packet_header.ts_usec,
        .captured_length = packet_header.included_length,
        .original_length = packet_header.original_length,
        .record_file_offset = packet_header_offset,
        .data_offset = data_offset,
        .data_link_type = global_header_.network,
        .bytes = std::move(bytes),
    };
    normalize_erf_type_eth_packet(packet);
    if (!trim_erf_prefix_overread(packet, prefix_bytes)) {
        return std::nullopt;
    }

    if (next_input_offset_ < next_record_offset) {
        prefix_packet_state_ = PrefixPacketState {
            .active = true,
            .packet_index = next_packet_index_,
            .data_offset = packet.data_offset,
            .next_record_offset = next_record_offset,
            .captured_length = packet.captured_length,
        };
    } else {
        clear_prefix_packet_state();
        next_input_offset_ = next_record_offset;
    }

    ++next_packet_index_;
    return packet;
}

std::optional<RawPcapPacket> PcapReader::read_next_import_packet(
    const std::size_t prefix_bytes,
    const std::size_t min_staged_captured_length_bytes
) {
    if (!stream_.is_open()) {
        return std::nullopt;
    }

    if (prefix_packet_state_.active) {
        set_error(next_input_offset_, "current prefix packet must be finalized before reading next packet",
                  prefix_packet_state_.packet_index);
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

    const auto data_offset = packet_header_offset + sizeof(packet_header);
    if (packet_header.included_length < min_staged_captured_length_bytes) {
        std::vector<std::uint8_t> bytes(packet_header.included_length);
        if (!bytes.empty()) {
            stream_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            if (stream_.gcount() != static_cast<std::streamsize>(bytes.size())) {
                set_error(data_offset, "unexpected EOF while reading packet data", next_packet_index_);
                return std::nullopt;
            }
        }

        next_input_offset_ = data_offset + packet_header.included_length;
        clear_prefix_packet_state();

        RawPcapPacket packet {
            .packet_index = next_packet_index_,
            .ts_sec = packet_header.ts_sec,
            .ts_usec = packet_header.ts_usec,
            .captured_length = packet_header.included_length,
            .original_length = packet_header.original_length,
            .record_file_offset = packet_header_offset,
            .data_offset = data_offset,
            .data_link_type = global_header_.network,
            .bytes = std::move(bytes),
        };
        normalize_erf_type_eth_packet(packet);
        ++next_packet_index_;
        return packet;
    }

    const auto available_prefix_bytes =
        physical_prefix_read_size(global_header_.network, prefix_bytes, packet_header.included_length);
    std::vector<std::uint8_t> bytes(available_prefix_bytes);
    if (!bytes.empty()) {
        stream_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (stream_.gcount() != static_cast<std::streamsize>(bytes.size())) {
            set_error(data_offset, "unexpected EOF while reading packet data", next_packet_index_);
            return std::nullopt;
        }
    }

    const auto next_record_offset = data_offset + packet_header.included_length;
    next_input_offset_ = data_offset + static_cast<std::uint64_t>(available_prefix_bytes);

    RawPcapPacket packet {
        .packet_index = next_packet_index_,
        .ts_sec = packet_header.ts_sec,
        .ts_usec = packet_header.ts_usec,
        .captured_length = packet_header.included_length,
        .original_length = packet_header.original_length,
        .record_file_offset = packet_header_offset,
        .data_offset = data_offset,
        .data_link_type = global_header_.network,
        .bytes = std::move(bytes),
    };
    normalize_erf_type_eth_packet(packet);
    if (!trim_erf_prefix_overread(packet, prefix_bytes)) {
        return std::nullopt;
    }

    if (next_input_offset_ < next_record_offset) {
        prefix_packet_state_ = PrefixPacketState {
            .active = true,
            .packet_index = next_packet_index_,
            .data_offset = packet.data_offset,
            .next_record_offset = next_record_offset,
            .captured_length = packet.captured_length,
        };
    } else {
        clear_prefix_packet_state();
        next_input_offset_ = next_record_offset;
    }

    ++next_packet_index_;
    return packet;
}

bool PcapReader::read_next_import_packet_into(
    RawPcapPacket& packet,
    const std::size_t prefix_bytes,
    const std::size_t min_staged_captured_length_bytes
) {
    if (!stream_.is_open()) {
        return false;
    }

    if (prefix_packet_state_.active) {
        set_error(next_input_offset_, "current prefix packet must be finalized before reading next packet",
                  prefix_packet_state_.packet_index);
        return false;
    }

    const auto packet_header_offset = next_input_offset_;
    PcapPacketHeader packet_header {};
    stream_.read(reinterpret_cast<char*>(&packet_header), sizeof(packet_header));
    if (stream_.gcount() == 0) {
        return false;
    }

    if (stream_.gcount() != static_cast<std::streamsize>(sizeof(packet_header))) {
        set_error(packet_header_offset, "unexpected EOF while reading packet header", true);
        return false;
    }

    const auto data_offset = packet_header_offset + sizeof(packet_header);
    if (packet_header.included_length < min_staged_captured_length_bytes) {
        packet.bytes.resize(packet_header.included_length);
        if (!packet.bytes.empty()) {
            stream_.read(
                reinterpret_cast<char*>(packet.bytes.data()),
                static_cast<std::streamsize>(packet.bytes.size())
            );
            if (stream_.gcount() != static_cast<std::streamsize>(packet.bytes.size())) {
                set_error(data_offset, "unexpected EOF while reading packet data", next_packet_index_);
                return false;
            }
        }

        next_input_offset_ = data_offset + packet_header.included_length;
        clear_prefix_packet_state();

        packet.packet_index = next_packet_index_;
        packet.ts_sec = packet_header.ts_sec;
        packet.ts_usec = packet_header.ts_usec;
        packet.captured_length = packet_header.included_length;
        packet.original_length = packet_header.original_length;
        packet.record_file_offset = packet_header_offset;
        packet.data_offset = data_offset;
        packet.data_link_type = global_header_.network;
        normalize_erf_type_eth_packet(packet);

        ++next_packet_index_;
        return true;
    }

    const auto available_prefix_bytes =
        physical_prefix_read_size(global_header_.network, prefix_bytes, packet_header.included_length);
    packet.bytes.resize(available_prefix_bytes);
    if (!packet.bytes.empty()) {
        stream_.read(
            reinterpret_cast<char*>(packet.bytes.data()),
            static_cast<std::streamsize>(packet.bytes.size())
        );
        if (stream_.gcount() != static_cast<std::streamsize>(packet.bytes.size())) {
            set_error(data_offset, "unexpected EOF while reading packet data", next_packet_index_);
            return false;
        }
    }

    const auto next_record_offset = data_offset + packet_header.included_length;
    next_input_offset_ = data_offset + static_cast<std::uint64_t>(available_prefix_bytes);

    packet.packet_index = next_packet_index_;
    packet.ts_sec = packet_header.ts_sec;
    packet.ts_usec = packet_header.ts_usec;
    packet.captured_length = packet_header.included_length;
    packet.original_length = packet_header.original_length;
    packet.record_file_offset = packet_header_offset;
    packet.data_offset = data_offset;
    packet.data_link_type = global_header_.network;
    normalize_erf_type_eth_packet(packet);
    if (!trim_erf_prefix_overread(packet, prefix_bytes)) {
        return false;
    }

    if (next_input_offset_ < next_record_offset) {
        prefix_packet_state_ = PrefixPacketState {
            .active = true,
            .packet_index = next_packet_index_,
            .data_offset = packet.data_offset,
            .next_record_offset = next_record_offset,
            .captured_length = packet.captured_length,
        };
    } else {
        clear_prefix_packet_state();
        next_input_offset_ = next_record_offset;
    }

    ++next_packet_index_;
    return true;
}

bool PcapReader::materialize_packet_bytes(RawPcapPacket& packet) {
    if (!stream_.is_open()) {
        return false;
    }

    if (packet.bytes.size() >= packet.captured_length) {
        return true;
    }

    if (is_current_prefix_packet(packet)) {
        const auto bytes_already_read = packet.bytes.size();
        packet.bytes.resize(packet.captured_length);
        stream_.read(reinterpret_cast<char*>(packet.bytes.data() + static_cast<std::ptrdiff_t>(bytes_already_read)),
                     static_cast<std::streamsize>(packet.bytes.size() - bytes_already_read));
        if (stream_.gcount() != static_cast<std::streamsize>(packet.bytes.size() - bytes_already_read)) {
            set_error(packet.data_offset + static_cast<std::uint64_t>(bytes_already_read),
                      "unexpected EOF while reading packet data",
                      packet.packet_index);
            return false;
        }

        next_input_offset_ = prefix_packet_state_.next_record_offset;
        clear_prefix_packet_state();
        return true;
    }

    const auto resume_offset = next_input_offset_;
    stream_.clear();
    stream_.seekg(static_cast<std::streamoff>(packet.data_offset), std::ios::beg);
    if (!stream_) {
        set_error(packet.data_offset, "seek failed", packet.packet_index);
        return false;
    }

    std::vector<std::uint8_t> bytes(packet.captured_length);
    if (!bytes.empty()) {
        stream_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (stream_.gcount() != static_cast<std::streamsize>(bytes.size())) {
            set_error(packet.data_offset, "unexpected EOF while reading packet data", packet.packet_index);
            return false;
        }
    }

    stream_.clear();
    stream_.seekg(static_cast<std::streamoff>(resume_offset), std::ios::beg);
    if (!stream_) {
        set_error(resume_offset, "seek failed", packet.packet_index);
        return false;
    }

    packet.bytes = std::move(bytes);
    return true;
}

bool PcapReader::finish_prefix_packet(const RawPcapPacket& packet) {
    if (!stream_.is_open()) {
        return false;
    }

    if (!prefix_packet_state_.active) {
        return true;
    }

    if (!is_current_prefix_packet(packet)) {
        set_error(next_input_offset_, "current prefix packet mismatch during finalization",
                  prefix_packet_state_.packet_index);
        return false;
    }

    if (next_input_offset_ < prefix_packet_state_.next_record_offset) {
        const auto unread_bytes = prefix_packet_state_.next_record_offset - next_input_offset_;
        stream_.seekg(static_cast<std::streamoff>(unread_bytes), std::ios::cur);
        if (!stream_) {
            set_error(next_input_offset_, "seek failed", packet.packet_index);
            return false;
        }
    }

    next_input_offset_ = prefix_packet_state_.next_record_offset;
    clear_prefix_packet_state();
    return true;
}

}  // namespace pfl

