#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace pfl::erf {

inline constexpr std::size_t kGenericHeaderSize = 16U;
inline constexpr std::size_t kExtensionHeaderSize = 8U;
inline constexpr std::size_t kTypeEthMetadataSize = 2U;
inline constexpr std::size_t kMaxExtensionHeaders = 8U;
inline constexpr std::size_t kMaxSupportedEnvelopeBytes =
    kGenericHeaderSize + (kMaxExtensionHeaders * kExtensionHeaderSize) + kTypeEthMetadataSize;
inline constexpr std::uint8_t kExtensionPresentBit = 0x80U;
inline constexpr std::uint8_t kTypeMask = 0x7fU;
inline constexpr std::uint8_t kTypeEth = 0x02U;

enum class TypeEthParseStatus : std::uint8_t {
    ok,
    need_more_prefix_bytes,
    truncated_record,
    unsupported_type,
    too_many_extension_headers,
    invalid_length,
};

struct TypeEthView {
    TypeEthParseStatus status {TypeEthParseStatus::truncated_record};
    std::uint8_t flags {0U};
    std::uint16_t record_length {0U};
    std::uint16_t wire_length {0U};
    std::size_t type_eth_metadata_offset {0U};
    // TYPE_ETH metadata byte values are capture metadata, not an Ethernet start displacement.
    std::uint8_t type_eth_metadata_byte0 {0U};
    std::uint8_t type_eth_metadata_byte1 {0U};
    std::size_t network_offset {0U};
    std::uint32_t captured_network_length {0U};
    std::uint32_t original_network_length {0U};
};

[[nodiscard]] TypeEthView parse_type_eth_view(
    std::span<const std::uint8_t> record_prefix,
    std::uint32_t captured_record_length
) noexcept;

}  // namespace pfl::erf
