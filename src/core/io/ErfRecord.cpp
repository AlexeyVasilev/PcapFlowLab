#include "core/io/ErfRecord.h"

namespace pfl::erf {

namespace {

[[nodiscard]] std::uint16_t read_be16(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1U]));
}

[[nodiscard]] TypeEthView parse_status(const TypeEthParseStatus status) noexcept {
    return TypeEthView {.status = status};
}

[[nodiscard]] TypeEthParseStatus missing_bytes_status(
    const std::size_t available_bytes,
    const std::uint32_t captured_record_length,
    const std::size_t required_bytes
) noexcept {
    return captured_record_length >= required_bytes && available_bytes < required_bytes
        ? TypeEthParseStatus::need_more_prefix_bytes
        : TypeEthParseStatus::truncated_record;
}

}  // namespace

TypeEthView parse_type_eth_view(
    const std::span<const std::uint8_t> record_prefix,
    const std::uint32_t captured_record_length
) noexcept {
    if (captured_record_length < kGenericHeaderSize) {
        return parse_status(TypeEthParseStatus::truncated_record);
    }
    if (record_prefix.size() < kGenericHeaderSize) {
        return parse_status(missing_bytes_status(record_prefix.size(), captured_record_length, kGenericHeaderSize));
    }

    const auto type = record_prefix[8U];
    const auto flags = record_prefix[9U];
    if ((type & kTypeMask) != kTypeEth) {
        return parse_status(TypeEthParseStatus::unsupported_type);
    }

    const auto rlen = read_be16(record_prefix, 10U);
    const auto wlen = read_be16(record_prefix, 14U);
    if (rlen != captured_record_length || wlen == 0U) {
        return parse_status(TypeEthParseStatus::invalid_length);
    }

    auto offset = kGenericHeaderSize;
    auto has_more_extensions = (type & kExtensionPresentBit) != 0U;
    for (std::size_t extension_count = 0U; has_more_extensions; ++extension_count) {
        if (extension_count >= kMaxExtensionHeaders) {
            return parse_status(TypeEthParseStatus::too_many_extension_headers);
        }

        const auto extension_end = offset + kExtensionHeaderSize;
        if (captured_record_length < extension_end) {
            return parse_status(TypeEthParseStatus::truncated_record);
        }
        if (record_prefix.size() < extension_end) {
            return parse_status(missing_bytes_status(record_prefix.size(), captured_record_length, extension_end));
        }

        has_more_extensions = (record_prefix[offset] & kExtensionPresentBit) != 0U;
        offset = extension_end;
    }

    const auto type_eth_metadata_offset = offset;
    const auto network_offset = offset + kTypeEthMetadataSize;
    if (captured_record_length < network_offset) {
        return parse_status(TypeEthParseStatus::truncated_record);
    }
    if (record_prefix.size() < network_offset) {
        return parse_status(missing_bytes_status(record_prefix.size(), captured_record_length, network_offset));
    }

    const auto captured_network_length = captured_record_length - static_cast<std::uint32_t>(network_offset);
    if (captured_network_length > wlen) {
        return parse_status(TypeEthParseStatus::invalid_length);
    }

    return TypeEthView {
        .status = TypeEthParseStatus::ok,
        .flags = flags,
        .record_length = rlen,
        .wire_length = wlen,
        .type_eth_metadata_offset = type_eth_metadata_offset,
        .type_eth_metadata_byte0 = record_prefix[type_eth_metadata_offset],
        .type_eth_metadata_byte1 = record_prefix[type_eth_metadata_offset + 1U],
        .network_offset = network_offset,
        .captured_network_length = captured_network_length,
        .original_network_length = wlen,
    };
}

}  // namespace pfl::erf
