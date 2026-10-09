#include "app/session/DhcpSummaryPresentation.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace pfl::session_detail {

namespace {

PacketSummaryField make_summary_field(std::string label, std::string value) {
    return PacketSummaryField {
        .label = std::move(label),
        .value = std::move(value),
    };
}

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

std::string format_hex(const std::uint64_t value, const int width) {
    std::ostringstream builder {};
    builder << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(width) << value;
    return builder.str();
}

std::string format_hex_bytes(const std::span<const std::uint8_t> bytes) {
    std::ostringstream builder {};
    builder << std::hex << std::nouppercase << std::setfill('0');
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
        if (index != 0U) {
            builder << ' ';
        }
        builder << std::setw(2) << static_cast<unsigned>(bytes[index]);
    }
    return builder.str();
}

std::string format_ipv4(const std::uint32_t address) {
    return std::to_string((address >> 24U) & 0xFFU) + '.' +
        std::to_string((address >> 16U) & 0xFFU) + '.' +
        std::to_string((address >> 8U) & 0xFFU) + '.' +
        std::to_string(address & 0xFFU);
}

std::string safe_printable_text(const std::span<const std::uint8_t> bytes) {
    std::string text {};
    text.reserve(bytes.size());
    for (const auto byte : bytes) {
        text.push_back(std::isprint(static_cast<unsigned char>(byte)) != 0
            ? static_cast<char>(byte)
            : '.');
    }
    return text;
}

template <std::size_t Size>
std::optional<std::string> bootp_text_field(const std::array<std::uint8_t, Size>& bytes) {
    const auto nul_it = std::find(bytes.begin(), bytes.end(), std::uint8_t {0U});
    const auto length = static_cast<std::size_t>(nul_it - bytes.begin());
    if (length == 0U) {
        return std::nullopt;
    }
    return safe_printable_text(std::span<const std::uint8_t>(bytes.data(), length));
}

std::string format_operation(const std::uint8_t value) {
    switch (value) {
    case 1U:
        return "BOOTREQUEST (1)";
    case 2U:
        return "BOOTREPLY (2)";
    default:
        return "Unknown (" + std::to_string(static_cast<unsigned>(value)) + ")";
    }
}

std::string format_hardware_type(const std::uint8_t value) {
    if (value == 1U) {
        return "Ethernet (1)";
    }
    return "Unknown (" + std::to_string(static_cast<unsigned>(value)) + ")";
}

std::string format_mac_address(const std::span<const std::uint8_t> bytes) {
    std::ostringstream builder {};
    builder << std::hex << std::nouppercase << std::setfill('0');
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
        if (index != 0U) {
            builder << ':';
        }
        builder << std::setw(2) << static_cast<unsigned>(bytes[index]);
    }
    return builder.str();
}

std::string format_client_hardware_address(const DhcpMessage& message) {
    const auto available_length = std::min<std::size_t>(message.hlen, message.chaddr.size());
    const auto bytes = std::span<const std::uint8_t>(message.chaddr.data(), available_length);
    if (message.htype == 1U && message.hlen == 6U) {
        return format_mac_address(bytes);
    }
    if (bytes.empty()) {
        return "";
    }
    return format_hex_bytes(bytes);
}

const char* known_message_type_name(const std::uint8_t value) noexcept {
    switch (value) {
    case 1U:
        return "Discover";
    case 2U:
        return "Offer";
    case 3U:
        return "Request";
    case 4U:
        return "Decline";
    case 5U:
        return "ACK";
    case 6U:
        return "NAK";
    case 7U:
        return "Release";
    case 8U:
        return "Inform";
    default:
        return nullptr;
    }
}

std::string format_message_type(const std::uint8_t value) {
    if (const auto* name = known_message_type_name(value); name != nullptr) {
        return std::string {name} + " (" + std::to_string(static_cast<unsigned>(value)) + ')';
    }
    return "Unknown (" + std::to_string(static_cast<unsigned>(value)) + ")";
}

const char* known_option_name(const std::uint8_t code) noexcept {
    switch (code) {
    case 1U:
        return "Subnet Mask";
    case 3U:
        return "Router";
    case 6U:
        return "Domain Name Server";
    case 12U:
        return "Host Name";
    case 15U:
        return "Domain Name";
    case 28U:
        return "Broadcast Address";
    case 50U:
        return "Requested IP Address";
    case 51U:
        return "IP Address Lease Time";
    case 52U:
        return "Option Overload";
    case 53U:
        return "DHCP Message Type";
    case 54U:
        return "Server Identifier";
    case 55U:
        return "Parameter Request List";
    case 56U:
        return "Message";
    case 57U:
        return "Maximum DHCP Message Size";
    case 58U:
        return "Renewal Time Value";
    case 59U:
        return "Rebinding Time Value";
    case 60U:
        return "Vendor Class Identifier";
    case 61U:
        return "Client Identifier";
    case 66U:
        return "TFTP Server Name";
    case 67U:
        return "Bootfile Name";
    default:
        return nullptr;
    }
}

std::string option_name(const DhcpOption& option) {
    if (option.semantic_kind == DhcpOptionSemanticKind::end) {
        return "End";
    }

    if (const auto* name = known_option_name(option.code); name != nullptr) {
        return name;
    }

    return "Unknown " + std::to_string(static_cast<unsigned>(option.code));
}

std::string format_requested_option(const std::uint8_t code) {
    auto text = std::to_string(static_cast<unsigned>(code));
    if (const auto* name = known_option_name(code); name != nullptr) {
        text += " (";
        text += name;
        text += ')';
    }
    return text;
}

std::optional<std::uint32_t> option_ipv4(const DhcpOption& option) noexcept {
    if (option.value.size() != 4U) {
        return std::nullopt;
    }
    return read_be32(std::span<const std::uint8_t>(option.value.data(), option.value.size()), 0U);
}

std::optional<std::uint32_t> option_u32(const DhcpOption& option) noexcept {
    if (option.value.size() != 4U) {
        return std::nullopt;
    }
    return read_be32(std::span<const std::uint8_t>(option.value.data(), option.value.size()), 0U);
}

std::optional<std::uint16_t> option_u16(const DhcpOption& option) noexcept {
    if (option.value.size() != 2U) {
        return std::nullopt;
    }
    return read_be16(std::span<const std::uint8_t>(option.value.data(), option.value.size()), 0U);
}

std::optional<std::string> option_title_preview(const DhcpOption& option) {
    if (option.status != DhcpOptionStatus::complete) {
        return std::nullopt;
    }

    switch (option.semantic_kind) {
    case DhcpOptionSemanticKind::message_type:
        if (option.value.size() == 1U) {
            if (const auto* name = known_message_type_name(option.value.front()); name != nullptr) {
                return std::string {name};
            }
        }
        return std::nullopt;
    case DhcpOptionSemanticKind::subnet_mask:
    case DhcpOptionSemanticKind::broadcast_address:
    case DhcpOptionSemanticKind::requested_ip_address:
    case DhcpOptionSemanticKind::server_identifier:
        if (const auto address = option_ipv4(option); address.has_value()) {
            return format_ipv4(*address);
        }
        return std::nullopt;
    default:
        return std::nullopt;
    }
}

std::string option_title(const DhcpOption& option) {
    auto title = "Option: " + option_name(option);
    if (const auto preview = option_title_preview(option); preview.has_value()) {
        title += " (";
        title += *preview;
        title += ')';
    }
    return title;
}

std::vector<PacketSummaryField> base_option_fields(const DhcpOption& option) {
    std::vector<PacketSummaryField> fields {};
    fields.push_back(make_summary_field("Code", std::to_string(static_cast<unsigned>(option.code))));
    if (option.declared_length.has_value()) {
        fields.push_back(make_summary_field("Length", std::to_string(static_cast<unsigned>(*option.declared_length))));
    }
    return fields;
}

void append_raw_value_if_present(std::vector<PacketSummaryField>& fields, const DhcpOption& option) {
    if (!option.value.empty()) {
        fields.push_back(make_summary_field("Value", format_hex_bytes(option.value)));
    }
}

void append_ipv4_list(std::vector<PacketSummaryField>& fields, const DhcpOption& option, const std::string& label) {
    if (option.value.empty() || (option.value.size() % 4U) != 0U) {
        append_raw_value_if_present(fields, option);
        return;
    }

    std::vector<std::string> addresses {};
    for (std::size_t offset = 0U; offset < option.value.size(); offset += 4U) {
        addresses.push_back(format_ipv4(read_be32(std::span<const std::uint8_t>(option.value.data(), option.value.size()), offset)));
    }
    for (const auto& address : addresses) {
        fields.push_back(make_summary_field(label, address));
    }
}

std::string format_option_overload_value(const DhcpOption& option) {
    if (option.value.size() != 1U) {
        return format_hex_bytes(option.value);
    }
    switch (option.value.front()) {
    case 1U:
        return "file (1)";
    case 2U:
        return "sname / Server Name (2)";
    case 3U:
        return "file and sname / Server Name (3)";
    default:
        return "Unknown (" + std::to_string(static_cast<unsigned>(option.value.front())) + ")";
    }
}

PacketSummaryLayer build_option_layer(const DhcpOption& option) {
    std::vector<PacketSummaryField> fields = base_option_fields(option);

    if (option.semantic_kind == DhcpOptionSemanticKind::end) {
        return PacketSummaryLayer {
            .id = "dhcp.option.end",
            .title = "Option: End",
            .fields = std::move(fields),
        };
    }

    switch (option.semantic_kind) {
    case DhcpOptionSemanticKind::message_type:
        if (option.value.size() == 1U) {
            fields.push_back(make_summary_field("Value", format_message_type(option.value.front())));
        } else {
            append_raw_value_if_present(fields, option);
        }
        break;
    case DhcpOptionSemanticKind::subnet_mask:
    case DhcpOptionSemanticKind::broadcast_address:
    case DhcpOptionSemanticKind::requested_ip_address:
    case DhcpOptionSemanticKind::server_identifier:
        if (const auto address = option_ipv4(option); address.has_value()) {
            fields.push_back(make_summary_field("Address", format_ipv4(*address)));
        } else {
            append_raw_value_if_present(fields, option);
        }
        break;
    case DhcpOptionSemanticKind::router:
    case DhcpOptionSemanticKind::domain_name_server:
        append_ipv4_list(fields, option, "Address");
        break;
    case DhcpOptionSemanticKind::host_name:
    case DhcpOptionSemanticKind::domain_name:
    case DhcpOptionSemanticKind::message:
    case DhcpOptionSemanticKind::vendor_class_identifier:
    case DhcpOptionSemanticKind::tftp_server_name:
    case DhcpOptionSemanticKind::bootfile_name:
        fields.push_back(make_summary_field("Value", safe_printable_text(option.value)));
        break;
    case DhcpOptionSemanticKind::lease_time:
    case DhcpOptionSemanticKind::renewal_time:
    case DhcpOptionSemanticKind::rebinding_time:
        if (const auto value = option_u32(option); value.has_value()) {
            fields.push_back(make_summary_field("Value", std::to_string(*value) + " seconds"));
        } else {
            append_raw_value_if_present(fields, option);
        }
        break;
    case DhcpOptionSemanticKind::option_overload:
        fields.push_back(make_summary_field("Value", format_option_overload_value(option)));
        break;
    case DhcpOptionSemanticKind::parameter_request_list:
        for (const auto code : option.value) {
            fields.push_back(make_summary_field("Requested Option", format_requested_option(code)));
        }
        break;
    case DhcpOptionSemanticKind::maximum_message_size:
        if (const auto value = option_u16(option); value.has_value()) {
            fields.push_back(make_summary_field("Value", std::to_string(*value) + " bytes"));
        } else {
            append_raw_value_if_present(fields, option);
        }
        break;
    case DhcpOptionSemanticKind::client_identifier:
        if (option.value.size() >= 1U) {
            fields.push_back(make_summary_field("Hardware Type", format_hardware_type(option.value.front())));
            const auto identifier = std::span<const std::uint8_t>(
                option.value.data() + 1,
                option.value.size() - 1U
            );
            if (option.value.front() == 1U && identifier.size() == 6U) {
                fields.push_back(make_summary_field("Client Hardware Address", format_mac_address(identifier)));
            } else if (!identifier.empty()) {
                fields.push_back(make_summary_field("Identifier", format_hex_bytes(identifier)));
            }
        }
        break;
    case DhcpOptionSemanticKind::unknown:
    default:
        append_raw_value_if_present(fields, option);
        break;
    }

    if (option.status == DhcpOptionStatus::malformed) {
        if (option.declared_length.has_value()) {
            fields.push_back(make_summary_field("Declared Length", std::to_string(static_cast<unsigned>(*option.declared_length))));
        }
        fields.push_back(make_summary_field("Available Value Length", std::to_string(static_cast<unsigned>(option.available_value_length))));
        fields.push_back(make_summary_field("Status", "malformed"));
        fields.push_back(make_summary_field("Warning", "Option value extends beyond DHCP option area"));
    }

    return PacketSummaryLayer {
        .id = "dhcp.option",
        .title = option_title(option),
        .fields = std::move(fields),
        .warning = option.status == DhcpOptionStatus::malformed,
    };
}

PacketSummaryLayer build_options_layer(std::string title, const std::vector<DhcpOption>& options) {
    std::vector<PacketSummaryLayer> children {};
    children.reserve(options.size());
    for (const auto& option : options) {
        children.push_back(build_option_layer(option));
    }

    return PacketSummaryLayer {
        .id = "dhcp.options",
        .title = std::move(title),
        .children = std::move(children),
    };
}

}  // namespace

std::optional<PacketSummaryLayer> build_dhcp_summary_layer(const DhcpMessage& message) {
    std::vector<PacketSummaryField> fields {
        make_summary_field("Operation", format_operation(message.op)),
        make_summary_field("Hardware Type", format_hardware_type(message.htype)),
        make_summary_field("Hardware Address Length", std::to_string(static_cast<unsigned>(message.hlen))),
        make_summary_field("Hops", std::to_string(static_cast<unsigned>(message.hops))),
        make_summary_field("Transaction ID", format_hex(message.xid, 8)),
        make_summary_field("Seconds Elapsed", std::to_string(message.secs)),
        make_summary_field("Flags", format_hex(message.flags, 4) + (message.flags & 0x8000U ? " (Broadcast)" : "")),
        make_summary_field("Broadcast", (message.flags & 0x8000U) ? "Yes" : "No"),
        make_summary_field("Client IP Address", format_ipv4(message.ciaddr)),
        make_summary_field("Your IP Address", format_ipv4(message.yiaddr)),
        make_summary_field("Next Server IP Address", format_ipv4(message.siaddr)),
        make_summary_field("Relay Agent IP Address", format_ipv4(message.giaddr)),
        make_summary_field("Client Hardware Address", format_client_hardware_address(message)),
        make_summary_field("DHCP Magic Cookie", format_hex(message.magic_cookie, 8)),
    };

    if (!message.sname_overloaded) {
        if (const auto text = bootp_text_field(message.sname); text.has_value()) {
            fields.push_back(make_summary_field("Server Host Name", *text));
        }
    }
    if (!message.file_overloaded) {
        if (const auto text = bootp_text_field(message.file); text.has_value()) {
            fields.push_back(make_summary_field("Boot File Name", *text));
        }
    }

    std::vector<PacketSummaryLayer> children {};
    children.push_back(build_options_layer("Options", message.main_options));
    if (message.file_overloaded) {
        children.push_back(build_options_layer("Overloaded File Options", message.file_options));
    }
    if (message.sname_overloaded) {
        children.push_back(build_options_layer("Overloaded Server Name Options", message.sname_options));
    }

    return PacketSummaryLayer {
        .id = "dhcp",
        .title = "Dynamic Host Configuration Protocol (DHCPv4)",
        .fields = std::move(fields),
        .children = std::move(children),
        .warning = message.has_malformed_option,
    };
}

}  // namespace pfl::session_detail
