#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pfl {

enum class StunMessageClass : std::uint8_t {
    request = 0,
    indication,
    success_response,
    error_response,
};

enum class StunAttributeSemanticKind : std::uint8_t {
    unknown = 0,
    mapped_address,
    username,
    message_integrity,
    error_code,
    realm,
    nonce,
    message_integrity_sha256,
    xor_mapped_address,
    priority,
    use_candidate,
    software,
    fingerprint,
    ice_controlled,
    ice_controlling,
};

enum class StunAttributeStatus : std::uint8_t {
    complete = 0,
    malformed,
};

enum class StunAddressFamily : std::uint8_t {
    unknown = 0,
    ipv4,
    ipv6,
};

struct StunAddress {
    StunAddressFamily family {StunAddressFamily::unknown};
    std::array<std::uint8_t, 16> address {};
    std::uint16_t port {0U};
};

struct StunAttribute {
    std::uint16_t type {0U};
    std::uint16_t declared_length {0U};
    std::uint16_t available_value_length {0U};
    bool comprehension_required {false};
    StunAttributeSemanticKind semantic_kind {StunAttributeSemanticKind::unknown};
    StunAttributeStatus status {StunAttributeStatus::complete};
    std::vector<std::uint8_t> value {};
    std::optional<StunAddress> address {};
    std::optional<std::uint32_t> uint32_value {};
    std::optional<std::uint64_t> uint64_value {};
    std::optional<std::string> text_value {};
    std::optional<std::uint16_t> error_code {};
    std::optional<std::string> error_reason {};
};

struct StunMessage {
    std::uint16_t message_type {0U};
    std::uint16_t method {0U};
    StunMessageClass message_class {StunMessageClass::request};
    std::uint16_t message_length {0U};
    std::uint32_t magic_cookie {0U};
    std::array<std::uint8_t, 12> transaction_id {};
    std::vector<StunAttribute> attributes {};
    bool has_malformed_attribute {false};
};

}  // namespace pfl
