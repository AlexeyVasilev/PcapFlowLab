#include "app/session/StunSummaryPresentation.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace pfl::session_detail {

namespace {

constexpr std::size_t kMaxAttributeTitlePreviewTextLength = 48U;

PacketSummaryField make_summary_field(std::string label, std::string value) {
    return PacketSummaryField {
        .label = std::move(label),
        .value = std::move(value),
    };
}

std::string format_hex(const std::uint64_t value, const int width) {
    std::ostringstream builder {};
    builder << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(width) << value;
    return builder.str();
}

std::string format_hex_bytes(const std::span<const std::uint8_t> bytes) {
    std::ostringstream builder {};
    builder << std::hex << std::nouppercase << std::setfill('0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0U) {
            builder << ' ';
        }
        builder << std::setw(2) << static_cast<unsigned>(bytes[index]);
    }
    return builder.str();
}

std::string format_transaction_id(const std::array<std::uint8_t, 12>& value) {
    std::ostringstream builder {};
    builder << "0x" << std::hex << std::nouppercase << std::setfill('0');
    for (const auto byte : value) {
        builder << std::setw(2) << static_cast<unsigned>(byte);
    }
    return builder.str();
}

std::string format_method(const std::uint16_t method) {
    if (method == 0x001U) {
        return "Binding (0x001)";
    }
    return "Unknown (" + format_hex(method, 3) + ")";
}

std::string format_class(const StunMessageClass message_class) {
    switch (message_class) {
    case StunMessageClass::request:
        return "Request";
    case StunMessageClass::indication:
        return "Indication";
    case StunMessageClass::success_response:
        return "Success Response";
    case StunMessageClass::error_response:
        return "Error Response";
    default:
        return "Unknown";
    }
}

std::string attribute_name(const StunAttributeSemanticKind kind) {
    switch (kind) {
    case StunAttributeSemanticKind::mapped_address:
        return "MAPPED-ADDRESS";
    case StunAttributeSemanticKind::username:
        return "USERNAME";
    case StunAttributeSemanticKind::message_integrity:
        return "MESSAGE-INTEGRITY";
    case StunAttributeSemanticKind::error_code:
        return "ERROR-CODE";
    case StunAttributeSemanticKind::realm:
        return "REALM";
    case StunAttributeSemanticKind::nonce:
        return "NONCE";
    case StunAttributeSemanticKind::message_integrity_sha256:
        return "MESSAGE-INTEGRITY-SHA256";
    case StunAttributeSemanticKind::xor_mapped_address:
        return "XOR-MAPPED-ADDRESS";
    case StunAttributeSemanticKind::priority:
        return "PRIORITY";
    case StunAttributeSemanticKind::use_candidate:
        return "USE-CANDIDATE";
    case StunAttributeSemanticKind::software:
        return "SOFTWARE";
    case StunAttributeSemanticKind::fingerprint:
        return "FINGERPRINT";
    case StunAttributeSemanticKind::ice_controlled:
        return "ICE-CONTROLLED";
    case StunAttributeSemanticKind::ice_controlling:
        return "ICE-CONTROLLING";
    default:
        return "Unknown " + format_hex(static_cast<std::uint64_t>(0U), 4);
    }
}

std::string format_ipv4_address(const std::array<std::uint8_t, 16>& address) {
    return std::to_string(address[0]) + '.' +
        std::to_string(address[1]) + '.' +
        std::to_string(address[2]) + '.' +
        std::to_string(address[3]);
}

std::string format_ipv6_compressed(const std::array<std::uint8_t, 16>& address) {
    std::array<std::uint16_t, 8> groups {};
    for (std::size_t index = 0; index < groups.size(); ++index) {
        groups[index] = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(address[index * 2U]) << 8U) |
            static_cast<std::uint16_t>(address[(index * 2U) + 1U])
        );
    }

    std::size_t best_start = groups.size();
    std::size_t best_length = 0U;
    for (std::size_t index = 0; index < groups.size();) {
        if (groups[index] != 0U) {
            ++index;
            continue;
        }
        const auto start = index;
        while (index < groups.size() && groups[index] == 0U) {
            ++index;
        }
        const auto length = index - start;
        if (length >= 2U && length > best_length) {
            best_start = start;
            best_length = length;
        }
    }

    std::ostringstream builder {};
    builder << std::hex << std::nouppercase;
    for (std::size_t index = 0; index < groups.size();) {
        if (index == best_start) {
            builder << "::";
            index += best_length;
            if (index >= groups.size()) {
                break;
            }
            continue;
        }
        if (index != 0U && !(best_length > 0U && index == best_start + best_length)) {
            builder << ':';
        }
        builder << groups[index];
        ++index;
    }
    return builder.str();
}

std::string format_address_family(const StunAddressFamily family) {
    switch (family) {
    case StunAddressFamily::ipv4:
        return "IPv4";
    case StunAddressFamily::ipv6:
        return "IPv6";
    default:
        return "Unknown";
    }
}

std::string format_address(const StunAddress& address) {
    switch (address.family) {
    case StunAddressFamily::ipv4:
        return format_ipv4_address(address.address);
    case StunAddressFamily::ipv6:
        return format_ipv6_compressed(address.address);
    default:
        return "Unknown";
    }
}

std::optional<std::string> text_attribute_title_preview(const StunAttribute& attribute) {
    if (attribute.status != StunAttributeStatus::complete || !attribute.text_value.has_value() ||
        attribute.text_value->empty() || attribute.text_value->size() > kMaxAttributeTitlePreviewTextLength) {
        return std::nullopt;
    }
    return *attribute.text_value;
}

std::optional<std::string> address_attribute_title_preview(const StunAttribute& attribute) {
    if (attribute.status != StunAttributeStatus::complete || !attribute.address.has_value()) {
        return std::nullopt;
    }

    switch (attribute.address->family) {
    case StunAddressFamily::ipv4:
        return format_address(*attribute.address) + ":" + std::to_string(attribute.address->port);
    case StunAddressFamily::ipv6:
        return "[" + format_address(*attribute.address) + "]:" + std::to_string(attribute.address->port);
    default:
        return std::nullopt;
    }
}

std::optional<std::string> error_code_attribute_title_preview(const StunAttribute& attribute) {
    if (attribute.status != StunAttributeStatus::complete || !attribute.error_code.has_value()) {
        return std::nullopt;
    }

    auto preview = std::to_string(*attribute.error_code);
    if (attribute.error_reason.has_value() && !attribute.error_reason->empty() &&
        attribute.error_reason->size() <= kMaxAttributeTitlePreviewTextLength) {
        preview += ' ';
        preview += *attribute.error_reason;
    }
    return preview;
}

std::optional<std::string> attribute_title_preview(const StunAttribute& attribute) {
    switch (attribute.semantic_kind) {
    case StunAttributeSemanticKind::username:
    case StunAttributeSemanticKind::realm:
    case StunAttributeSemanticKind::nonce:
        return text_attribute_title_preview(attribute);
    case StunAttributeSemanticKind::mapped_address:
    case StunAttributeSemanticKind::xor_mapped_address:
        return address_attribute_title_preview(attribute);
    case StunAttributeSemanticKind::error_code:
        return error_code_attribute_title_preview(attribute);
    default:
        return std::nullopt;
    }
}

std::string format_attribute_title(const StunAttribute& attribute) {
    std::string title;
    if (attribute.semantic_kind == StunAttributeSemanticKind::unknown) {
        title = "Attribute: Unknown " + format_hex(attribute.type, 4);
    } else {
        title = "Attribute: " + attribute_name(attribute.semantic_kind);
    }

    if (const auto preview = attribute_title_preview(attribute); preview.has_value()) {
        title += " (";
        title += *preview;
        title += ")";
    }
    return title;
}

PacketSummaryLayer build_attribute_layer(const StunAttribute& attribute) {
    std::vector<PacketSummaryField> fields {
        make_summary_field("Type", format_hex(attribute.type, 4)),
        make_summary_field("Length", std::to_string(attribute.declared_length)),
    };

    switch (attribute.semantic_kind) {
    case StunAttributeSemanticKind::mapped_address:
    case StunAttributeSemanticKind::xor_mapped_address:
        if (attribute.address.has_value()) {
            fields.push_back(make_summary_field("Family", format_address_family(attribute.address->family)));
            fields.push_back(make_summary_field("Address", format_address(*attribute.address)));
            fields.push_back(make_summary_field("Port", std::to_string(attribute.address->port)));
        }
        break;
    case StunAttributeSemanticKind::username:
    case StunAttributeSemanticKind::realm:
    case StunAttributeSemanticKind::nonce:
    case StunAttributeSemanticKind::software:
        if (attribute.text_value.has_value()) {
            fields.push_back(make_summary_field("Value", *attribute.text_value));
        }
        break;
    case StunAttributeSemanticKind::priority:
        if (attribute.uint32_value.has_value()) {
            fields.push_back(make_summary_field("Priority", std::to_string(*attribute.uint32_value)));
        }
        break;
    case StunAttributeSemanticKind::ice_controlled:
    case StunAttributeSemanticKind::ice_controlling:
        if (attribute.uint64_value.has_value()) {
            fields.push_back(make_summary_field("Tie Breaker", format_hex(*attribute.uint64_value, 16)));
        }
        break;
    case StunAttributeSemanticKind::use_candidate:
        fields.push_back(make_summary_field("Value", "flag present"));
        break;
    case StunAttributeSemanticKind::message_integrity:
    case StunAttributeSemanticKind::message_integrity_sha256:
        fields.push_back(make_summary_field("Validation", "Not performed"));
        break;
    case StunAttributeSemanticKind::fingerprint:
        if (attribute.uint32_value.has_value()) {
            fields.push_back(make_summary_field("Value", format_hex(*attribute.uint32_value, 8)));
        }
        break;
    case StunAttributeSemanticKind::error_code:
        if (attribute.error_code.has_value()) {
            fields.push_back(make_summary_field("Code", std::to_string(*attribute.error_code)));
        }
        if (attribute.error_reason.has_value()) {
            fields.push_back(make_summary_field("Reason", *attribute.error_reason));
        }
        break;
    case StunAttributeSemanticKind::unknown:
    default:
        fields.push_back(make_summary_field(
            "Comprehension",
            attribute.comprehension_required ? "required" : "optional"
        ));
        if (!attribute.value.empty()) {
            fields.push_back(make_summary_field("Value", format_hex_bytes(attribute.value)));
        }
        break;
    }

    if (attribute.status == StunAttributeStatus::malformed) {
        fields.push_back(make_summary_field("Status", "malformed"));
        fields.push_back(make_summary_field("Warning", "Attribute extends beyond STUN message"));
    }

    return PacketSummaryLayer {
        .id = "stun.attribute",
        .title = format_attribute_title(attribute),
        .fields = std::move(fields),
        .warning = attribute.status == StunAttributeStatus::malformed,
    };
}

}  // namespace

std::optional<PacketSummaryLayer> build_stun_summary_layer(const StunMessage& message) {
    std::vector<PacketSummaryField> fields {
        make_summary_field("Message Type", format_hex(message.message_type, 4)),
        make_summary_field("Method", format_method(message.method)),
        make_summary_field("Class", format_class(message.message_class)),
        make_summary_field("Message Length", std::to_string(message.message_length)),
        make_summary_field("Magic Cookie", format_hex(message.magic_cookie, 8)),
        make_summary_field("Transaction ID", format_transaction_id(message.transaction_id)),
    };

    std::vector<PacketSummaryLayer> children {};
    children.reserve(message.attributes.size());
    for (const auto& attribute : message.attributes) {
        children.push_back(build_attribute_layer(attribute));
    }

    return PacketSummaryLayer {
        .id = "stun",
        .title = "STUN",
        .fields = std::move(fields),
        .children = std::move(children),
        .warning = message.has_malformed_attribute,
    };
}

}  // namespace pfl::session_detail
