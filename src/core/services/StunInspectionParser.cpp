#include "core/services/StunInspectionParser.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>

namespace pfl {

namespace {

std::uint16_t read_be16(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t read_be32(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

std::uint64_t read_be64(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return (static_cast<std::uint64_t>(read_be32(bytes, offset)) << 32U) |
           static_cast<std::uint64_t>(read_be32(bytes, offset + 4U));
}

std::uint16_t decode_stun_method(const std::uint16_t message_type) noexcept {
    return static_cast<std::uint16_t>(
        (message_type & 0x000FU) |
        ((message_type & 0x00E0U) >> 1U) |
        ((message_type & 0x3E00U) >> 2U)
    );
}

StunMessageClass decode_stun_class(const std::uint16_t message_type) noexcept {
    const auto class_bits = static_cast<std::uint8_t>(
        ((message_type & 0x0010U) >> 4U) |
        ((message_type & 0x0100U) >> 7U)
    );
    switch (class_bits) {
    case 1U:
        return StunMessageClass::indication;
    case 2U:
        return StunMessageClass::success_response;
    case 3U:
        return StunMessageClass::error_response;
    case 0U:
    default:
        return StunMessageClass::request;
    }
}

StunAttributeSemanticKind semantic_kind_for_type(const std::uint16_t type) noexcept {
    switch (type) {
    case 0x0001U:
        return StunAttributeSemanticKind::mapped_address;
    case 0x0006U:
        return StunAttributeSemanticKind::username;
    case 0x0008U:
        return StunAttributeSemanticKind::message_integrity;
    case 0x0009U:
        return StunAttributeSemanticKind::error_code;
    case 0x0014U:
        return StunAttributeSemanticKind::realm;
    case 0x0015U:
        return StunAttributeSemanticKind::nonce;
    case 0x001CU:
        return StunAttributeSemanticKind::message_integrity_sha256;
    case 0x0020U:
        return StunAttributeSemanticKind::xor_mapped_address;
    case 0x0024U:
        return StunAttributeSemanticKind::priority;
    case 0x0025U:
        return StunAttributeSemanticKind::use_candidate;
    case 0x8022U:
        return StunAttributeSemanticKind::software;
    case 0x8028U:
        return StunAttributeSemanticKind::fingerprint;
    case 0x8029U:
        return StunAttributeSemanticKind::ice_controlled;
    case 0x802AU:
        return StunAttributeSemanticKind::ice_controlling;
    default:
        return StunAttributeSemanticKind::unknown;
    }
}

std::string decode_text_value(const std::span<const std::uint8_t> value) {
    std::string text {};
    text.reserve(value.size());
    for (const auto byte : value) {
        text.push_back(std::isprint(static_cast<unsigned char>(byte)) != 0
            ? static_cast<char>(byte)
            : '.');
    }
    return text;
}

std::optional<StunAddress> decode_address(
    const StunAttributeSemanticKind semantic_kind,
    const std::span<const std::uint8_t> value,
    const std::array<std::uint8_t, 12>& transaction_id
) noexcept {
    if (value.size() < 4U) {
        return std::nullopt;
    }

    const auto family = value[1];
    const auto xor_encoded = semantic_kind == StunAttributeSemanticKind::xor_mapped_address;
    auto port = read_be16(value, 2U);
    if (xor_encoded) {
        port = static_cast<std::uint16_t>(port ^ static_cast<std::uint16_t>(StunInspectionParser::kMagicCookie >> 16U));
    }

    StunAddress address {};
    address.port = port;

    if (family == 0x01U && value.size() >= 8U) {
        address.family = StunAddressFamily::ipv4;
        for (std::size_t index = 0; index < 4U; ++index) {
            auto byte = value[4U + index];
            if (xor_encoded) {
                byte = static_cast<std::uint8_t>(byte ^ ((StunInspectionParser::kMagicCookie >> ((3U - index) * 8U)) & 0xFFU));
            }
            address.address[index] = byte;
        }
        return address;
    }

    if (family == 0x02U && value.size() >= 20U) {
        address.family = StunAddressFamily::ipv6;
        for (std::size_t index = 0; index < 16U; ++index) {
            auto byte = value[4U + index];
            if (xor_encoded) {
                byte = index < 4U
                    ? static_cast<std::uint8_t>(byte ^ ((StunInspectionParser::kMagicCookie >> ((3U - index) * 8U)) & 0xFFU))
                    : static_cast<std::uint8_t>(byte ^ transaction_id[index - 4U]);
            }
            address.address[index] = byte;
        }
        return address;
    }

    return std::nullopt;
}

void enrich_attribute(StunAttribute& attribute, const std::array<std::uint8_t, 12>& transaction_id) {
    const auto value = std::span<const std::uint8_t>(attribute.value.data(), attribute.value.size());
    switch (attribute.semantic_kind) {
    case StunAttributeSemanticKind::mapped_address:
    case StunAttributeSemanticKind::xor_mapped_address:
        attribute.address = decode_address(attribute.semantic_kind, value, transaction_id);
        break;
    case StunAttributeSemanticKind::username:
    case StunAttributeSemanticKind::realm:
    case StunAttributeSemanticKind::nonce:
    case StunAttributeSemanticKind::software:
        attribute.text_value = decode_text_value(value);
        break;
    case StunAttributeSemanticKind::priority:
    case StunAttributeSemanticKind::fingerprint:
        if (value.size() >= 4U) {
            attribute.uint32_value = read_be32(value, 0U);
        }
        break;
    case StunAttributeSemanticKind::ice_controlled:
    case StunAttributeSemanticKind::ice_controlling:
        if (value.size() >= 8U) {
            attribute.uint64_value = read_be64(value, 0U);
        }
        break;
    case StunAttributeSemanticKind::error_code:
        if (value.size() >= 4U) {
            attribute.error_code = static_cast<std::uint16_t>((static_cast<std::uint16_t>(value[2]) * 100U) + value[3]);
            attribute.error_reason = decode_text_value(value.subspan(4U));
        }
        break;
    default:
        break;
    }
}

}  // namespace

std::optional<StunEnvelope> inspect_stun_envelope(const std::span<const std::uint8_t> stun_bytes) noexcept {
    if (stun_bytes.size() < StunInspectionParser::kHeaderSize) {
        return std::nullopt;
    }

    if ((stun_bytes[0] & 0xC0U) != 0U) {
        return std::nullopt;
    }

    const auto message_length = read_be16(stun_bytes, 2U);
    if ((message_length % 4U) != 0U) {
        return std::nullopt;
    }

    if (stun_bytes.size() != (StunInspectionParser::kHeaderSize + static_cast<std::size_t>(message_length))) {
        return std::nullopt;
    }

    const auto magic_cookie = read_be32(stun_bytes, 4U);
    if (magic_cookie != StunInspectionParser::kMagicCookie) {
        return std::nullopt;
    }

    StunEnvelope envelope {
        .message_type = read_be16(stun_bytes, 0U),
        .message_length = message_length,
        .magic_cookie = magic_cookie,
    };
    std::copy_n(stun_bytes.begin() + 8, envelope.transaction_id.size(), envelope.transaction_id.begin());
    return envelope;
}

bool stun_message_matches_current_support_contract(const std::span<const std::uint8_t> stun_bytes) noexcept {
    return inspect_stun_envelope(stun_bytes).has_value();
}

std::optional<StunMessage> StunInspectionParser::inspect(const std::span<const std::uint8_t> stun_bytes) const {
    const auto envelope = inspect_stun_envelope(stun_bytes);
    if (!envelope.has_value()) {
        return std::nullopt;
    }

    StunMessage message {
        .message_type = envelope->message_type,
        .method = decode_stun_method(envelope->message_type),
        .message_class = decode_stun_class(envelope->message_type),
        .message_length = envelope->message_length,
        .magic_cookie = envelope->magic_cookie,
        .transaction_id = envelope->transaction_id,
    };

    const auto message_end = kHeaderSize + static_cast<std::size_t>(message.message_length);
    auto cursor = kHeaderSize;
    while (cursor < message_end) {
        if (message_end - cursor < 4U) {
            message.has_malformed_attribute = true;
            break;
        }

        const auto type = read_be16(stun_bytes, cursor);
        const auto declared_length = read_be16(stun_bytes, cursor + 2U);
        const auto value_offset = cursor + 4U;
        const auto available_length = value_offset <= message_end
            ? std::min<std::size_t>(declared_length, message_end - value_offset)
            : 0U;

        StunAttribute attribute {
            .type = type,
            .declared_length = declared_length,
            .available_value_length = static_cast<std::uint16_t>(available_length),
            .comprehension_required = type < 0x8000U,
            .semantic_kind = semantic_kind_for_type(type),
            .status = value_offset + static_cast<std::size_t>(declared_length) <= message_end
                ? StunAttributeStatus::complete
                : StunAttributeStatus::malformed,
        };
        attribute.value.assign(
            stun_bytes.begin() + static_cast<std::ptrdiff_t>(value_offset),
            stun_bytes.begin() + static_cast<std::ptrdiff_t>(value_offset + available_length)
        );
        enrich_attribute(attribute, message.transaction_id);
        if (attribute.status == StunAttributeStatus::malformed) {
            message.has_malformed_attribute = true;
        }
        message.attributes.push_back(std::move(attribute));

        if (message.attributes.back().status == StunAttributeStatus::malformed) {
            break;
        }

        const auto padded_length = (static_cast<std::size_t>(declared_length) + 3U) & ~std::size_t {3U};
        cursor = value_offset + padded_length;
    }

    return message;
}

std::optional<StunMessage> inspect_supported_stun_message(const std::span<const std::uint8_t> stun_bytes) {
    StunInspectionParser parser {};
    return parser.inspect(stun_bytes);
}

}  // namespace pfl
