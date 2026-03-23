#include "core/io/PcapNgReader.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>

namespace pfl {

namespace {

constexpr std::array<std::uint8_t, 4> kSectionHeaderBlockBytes {0x0aU, 0x0dU, 0x0dU, 0x0aU};
constexpr std::array<std::uint8_t, 4> kLittleEndianByteOrderMagicBytes {0x4dU, 0x3cU, 0x2bU, 0x1aU};
constexpr std::array<std::uint8_t, 4> kBigEndianByteOrderMagicBytes {0x1aU, 0x2bU, 0x3cU, 0x4dU};
constexpr std::uint32_t kInterfaceDescriptionBlockType = 0x00000001U;
constexpr std::uint32_t kEnhancedPacketBlockType = 0x00000006U;
constexpr std::uint16_t kEthernetLinkType = 1U;
constexpr std::uint16_t kEndOfOptionsCode = 0U;
constexpr std::uint16_t kIfTsResolOptionCode = 9U;

bool read_exact(std::ifstream& stream, std::span<std::uint8_t> bytes) {
    if (bytes.empty()) {
        return true;
    }

    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream.gcount() == static_cast<std::streamsize>(bytes.size());
}

std::uint16_t read_u16(std::span<const std::uint8_t> bytes, std::size_t offset, bool little_endian) noexcept {
    if (little_endian) {
        return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) |
                                          (static_cast<std::uint16_t>(bytes[offset + 1]) << 8U));
    }

    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes, std::size_t offset, bool little_endian) noexcept {
    if (little_endian) {
        return static_cast<std::uint32_t>(bytes[offset]) |
               (static_cast<std::uint32_t>(bytes[offset + 1]) << 8U) |
               (static_cast<std::uint32_t>(bytes[offset + 2]) << 16U) |
               (static_cast<std::uint32_t>(bytes[offset + 3]) << 24U);
    }

    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
}

std::size_t padded_length(std::size_t length) noexcept {
    return (length + 3U) & ~std::size_t {3};
}

std::pair<std::uint32_t, std::uint32_t> normalize_timestamp(
    std::uint64_t raw_timestamp,
    const PcapNgTimestampResolution& resolution
) {
    long double divisor = 1.0L;
    if (resolution.power_of_two) {
        divisor = std::ldexp(1.0L, static_cast<int>(resolution.exponent));
    } else {
        for (std::uint8_t index = 0; index < resolution.exponent; ++index) {
            divisor *= 10.0L;
        }
    }

    const auto total_seconds = static_cast<long double>(raw_timestamp) / divisor;
    auto seconds = static_cast<std::uint64_t>(total_seconds);
    auto usec = static_cast<std::uint64_t>((total_seconds - static_cast<long double>(seconds)) * 1'000'000.0L + 0.5L);
    if (usec >= 1'000'000U) {
        ++seconds;
        usec -= 1'000'000U;
    }

    if (seconds > std::numeric_limits<std::uint32_t>::max()) {
        seconds = std::numeric_limits<std::uint32_t>::max();
        usec = 999'999U;
    }

    return {
        static_cast<std::uint32_t>(seconds),
        static_cast<std::uint32_t>(usec),
    };
}

}  // namespace

bool PcapNgReader::open(const std::filesystem::path& path) {
    return open(path, 0, 0);
}

bool PcapNgReader::open(const std::filesystem::path& path, std::uint64_t next_input_offset, std::uint64_t next_packet_index) {
    stream_ = std::ifstream(path, std::ios::binary);
    interfaces_.clear();
    next_packet_index_ = next_packet_index;
    next_input_offset_ = 0;
    has_error_ = false;
    little_endian_ = true;

    if (!stream_.is_open()) {
        return false;
    }

    if (!parse_section_header()) {
        return false;
    }

    if (next_input_offset != 0 && next_input_offset != next_input_offset_) {
        if (!seek_to_offset(next_input_offset)) {
            stream_.close();
            return false;
        }
    }

    return true;
}

bool PcapNgReader::is_open() const noexcept {
    return stream_.is_open();
}

bool PcapNgReader::has_error() const noexcept {
    return has_error_;
}

bool PcapNgReader::at_eof() {
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

std::uint64_t PcapNgReader::next_input_offset() const noexcept {
    return next_input_offset_;
}

std::optional<RawPcapPacket> PcapNgReader::read_next() {
    while (stream_.is_open()) {
        const auto block_start_position = stream_.tellg();
        if (block_start_position < 0) {
            return std::nullopt;
        }
        const auto block_start = static_cast<std::uint64_t>(block_start_position);

        std::array<std::uint8_t, 8> header {};
        stream_.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
        if (stream_.gcount() == 0) {
            next_input_offset_ = block_start;
            return std::nullopt;
        }

        if (stream_.gcount() != static_cast<std::streamsize>(header.size())) {
            has_error_ = true;
            return std::nullopt;
        }

        if (std::equal(kSectionHeaderBlockBytes.begin(), kSectionHeaderBlockBytes.end(), header.begin())) {
            stream_.clear();
            stream_.seekg(static_cast<std::streamoff>(block_start), std::ios::beg);
            if (!stream_ || !parse_section_header()) {
                has_error_ = true;
                return std::nullopt;
            }
            continue;
        }

        const auto block_type = read_u32(header, 0, little_endian_);
        const auto block_total_length = read_u32(header, 4, little_endian_);
        if (block_total_length < 12U || (block_total_length % 4U) != 0U) {
            has_error_ = true;
            return std::nullopt;
        }

        std::vector<std::uint8_t> remaining(block_total_length - header.size());
        if (!read_exact(stream_, std::span<std::uint8_t>(remaining))) {
            has_error_ = true;
            return std::nullopt;
        }

        next_input_offset_ = block_start + block_total_length;

        const auto trailing_length = read_u32(remaining, remaining.size() - 4U, little_endian_);
        if (trailing_length != block_total_length) {
            has_error_ = true;
            return std::nullopt;
        }

        const auto body = std::span<const std::uint8_t>(remaining.data(), remaining.size() - 4U);
        if (block_type == kInterfaceDescriptionBlockType) {
            if (!parse_interface_description(body)) {
                has_error_ = true;
                return std::nullopt;
            }
            continue;
        }

        if (block_type != kEnhancedPacketBlockType) {
            continue;
        }

        if (body.size() < 20U) {
            has_error_ = true;
            return std::nullopt;
        }

        const auto interface_id = read_u32(body, 0, little_endian_);
        if (interface_id >= interfaces_.size()) {
            continue;
        }

        const auto captured_length = read_u32(body, 12, little_endian_);
        const auto original_length = read_u32(body, 16, little_endian_);
        const auto padded_capture_length = padded_length(static_cast<std::size_t>(captured_length));
        if (body.size() < 20U + padded_capture_length) {
            has_error_ = true;
            return std::nullopt;
        }

        const auto& interface_info = interfaces_[interface_id];
        if (interface_info.linktype != kEthernetLinkType) {
            continue;
        }

        const auto timestamp = (static_cast<std::uint64_t>(read_u32(body, 4, little_endian_)) << 32U) |
                               static_cast<std::uint64_t>(read_u32(body, 8, little_endian_));
        const auto [ts_sec, ts_usec] = normalize_timestamp(timestamp, interface_info.timestamp_resolution);

        std::vector<std::uint8_t> bytes(captured_length);
        std::copy_n(body.begin() + 20, static_cast<std::ptrdiff_t>(captured_length), bytes.begin());

        RawPcapPacket packet {
            .packet_index = next_packet_index_,
            .ts_sec = ts_sec,
            .ts_usec = ts_usec,
            .captured_length = captured_length,
            .original_length = original_length,
            .data_offset = block_start + 28U,
            .bytes = std::move(bytes),
        };
        ++next_packet_index_;
        return packet;
    }

    return std::nullopt;
}

bool PcapNgReader::parse_section_header() {
    const auto block_start = static_cast<std::uint64_t>(stream_.tellg());

    std::array<std::uint8_t, 12> header {};
    stream_.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (stream_.gcount() != static_cast<std::streamsize>(header.size())) {
        return false;
    }

    if (!std::equal(kSectionHeaderBlockBytes.begin(), kSectionHeaderBlockBytes.end(), header.begin())) {
        return false;
    }

    const auto byte_order_magic = std::span<const std::uint8_t>(header.data() + 8, 4);
    if (std::equal(byte_order_magic.begin(), byte_order_magic.end(), kLittleEndianByteOrderMagicBytes.begin())) {
        little_endian_ = true;
    } else if (std::equal(byte_order_magic.begin(), byte_order_magic.end(), kBigEndianByteOrderMagicBytes.begin())) {
        little_endian_ = false;
    } else {
        return false;
    }

    const auto block_total_length = read_u32(header, 4, little_endian_);
    if (block_total_length < 28U || (block_total_length % 4U) != 0U) {
        has_error_ = true;
        return false;
    }

    std::vector<std::uint8_t> remaining(block_total_length - header.size());
    if (!read_exact(stream_, std::span<std::uint8_t>(remaining))) {
        has_error_ = true;
        return false;
    }

    const auto trailing_length = read_u32(remaining, remaining.size() - 4U, little_endian_);
    if (trailing_length != block_total_length) {
        has_error_ = true;
        return false;
    }

    const auto body = std::span<const std::uint8_t>(remaining.data(), remaining.size() - 4U);
    if (body.size() < 12U) {
        has_error_ = true;
        return false;
    }

    const auto version_major = read_u16(body, 0, little_endian_);
    if (version_major != 1U) {
        has_error_ = true;
        return false;
    }

    interfaces_.clear();
    next_input_offset_ = block_start + block_total_length;
    return true;
}

bool PcapNgReader::parse_interface_description(std::span<const std::uint8_t> body) {
    if (body.size() < 8U) {
        return false;
    }

    PcapNgInterfaceInfo interface_info {
        .linktype = read_u16(body, 0, little_endian_),
        .snaplen = read_u32(body, 4, little_endian_),
    };

    auto options = body.subspan(8);
    while (options.size() >= 4U) {
        const auto option_code = read_u16(options, 0, little_endian_);
        const auto option_length = read_u16(options, 2, little_endian_);
        options = options.subspan(4);

        const auto padded_option_length = padded_length(option_length);
        if (options.size() < padded_option_length) {
            return false;
        }

        if (option_code == kEndOfOptionsCode) {
            if (option_length != 0U) {
                return false;
            }
            break;
        }

        const auto option_value = options.first(option_length);
        if (option_code == kIfTsResolOptionCode && option_length == 1U) {
            interface_info.timestamp_resolution.power_of_two = (option_value[0] & 0x80U) != 0U;
            interface_info.timestamp_resolution.exponent = static_cast<std::uint8_t>(option_value[0] & 0x7FU);
        }

        options = options.subspan(padded_option_length);
    }

    interfaces_.push_back(interface_info);
    return true;
}

bool PcapNgReader::seek_to_offset(std::uint64_t target_offset) {
    while (stream_.is_open()) {
        const auto block_start_position = stream_.tellg();
        if (block_start_position < 0) {
            return false;
        }

        const auto block_start = static_cast<std::uint64_t>(block_start_position);
        if (block_start == target_offset) {
            next_input_offset_ = target_offset;
            return true;
        }

        if (block_start > target_offset) {
            return false;
        }

        std::array<std::uint8_t, 8> header {};
        stream_.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
        if (stream_.gcount() == 0) {
            next_input_offset_ = block_start;
            return target_offset == block_start;
        }

        if (stream_.gcount() != static_cast<std::streamsize>(header.size())) {
            has_error_ = true;
            return false;
        }

        if (std::equal(kSectionHeaderBlockBytes.begin(), kSectionHeaderBlockBytes.end(), header.begin())) {
            stream_.clear();
            stream_.seekg(static_cast<std::streamoff>(block_start), std::ios::beg);
            if (!stream_ || !parse_section_header()) {
                has_error_ = true;
                return false;
            }
            if (next_input_offset_ == target_offset) {
                return true;
            }
            if (next_input_offset_ > target_offset) {
                return false;
            }
            continue;
        }

        const auto block_type = read_u32(header, 0, little_endian_);
        const auto block_total_length = read_u32(header, 4, little_endian_);
        if (block_total_length < 12U || (block_total_length % 4U) != 0U) {
            has_error_ = true;
            return false;
        }

        const auto block_end = block_start + block_total_length;
        if (block_end > target_offset && block_start < target_offset) {
            return false;
        }

        const auto remaining_size = static_cast<std::size_t>(block_total_length - header.size());
        if (block_type == kInterfaceDescriptionBlockType) {
            std::vector<std::uint8_t> remaining(remaining_size);
            if (!read_exact(stream_, std::span<std::uint8_t>(remaining))) {
                has_error_ = true;
                return false;
            }

            const auto trailing_length = read_u32(remaining, remaining.size() - 4U, little_endian_);
            if (trailing_length != block_total_length) {
                has_error_ = true;
                return false;
            }

            const auto body = std::span<const std::uint8_t>(remaining.data(), remaining.size() - 4U);
            if (!parse_interface_description(body)) {
                has_error_ = true;
                return false;
            }
        } else {
            stream_.seekg(static_cast<std::streamoff>(remaining_size), std::ios::cur);
            if (!stream_) {
                has_error_ = true;
                return false;
            }
        }

        next_input_offset_ = block_end;
        if (next_input_offset_ == target_offset) {
            return true;
        }
    }

    return false;
}

}  // namespace pfl
