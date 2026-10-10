#include "core/services/DhcpInspectionParser.h"

#include <algorithm>
#include <utility>

namespace pfl {

namespace {

constexpr std::uint16_t kDhcpServerPort = 67U;
constexpr std::uint16_t kDhcpClientPort = 68U;
constexpr std::size_t kChaddrOffset = 28U;
constexpr std::size_t kSnameOffset = 44U;
constexpr std::size_t kFileOffset = 108U;
constexpr std::size_t kChaddrSize = 16U;
constexpr std::size_t kSnameSize = 64U;
constexpr std::size_t kFileSize = 128U;

constexpr std::uint8_t kOptionPad = 0U;
constexpr std::uint8_t kOptionEnd = 255U;
constexpr std::uint8_t kOptionOverload = 52U;

bool has_port_pair(
    const std::uint16_t left,
    const std::uint16_t right,
    const std::uint16_t port_a,
    const std::uint16_t port_b
) noexcept {
    return (left == port_a && right == port_b) || (left == port_b && right == port_a);
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

DhcpOptionSemanticKind semantic_kind_for_code(const std::uint8_t code) noexcept {
    switch (code) {
    case 1U:
        return DhcpOptionSemanticKind::subnet_mask;
    case 3U:
        return DhcpOptionSemanticKind::router;
    case 6U:
        return DhcpOptionSemanticKind::domain_name_server;
    case 12U:
        return DhcpOptionSemanticKind::host_name;
    case 15U:
        return DhcpOptionSemanticKind::domain_name;
    case 28U:
        return DhcpOptionSemanticKind::broadcast_address;
    case 50U:
        return DhcpOptionSemanticKind::requested_ip_address;
    case 51U:
        return DhcpOptionSemanticKind::lease_time;
    case 52U:
        return DhcpOptionSemanticKind::option_overload;
    case 53U:
        return DhcpOptionSemanticKind::message_type;
    case 54U:
        return DhcpOptionSemanticKind::server_identifier;
    case 55U:
        return DhcpOptionSemanticKind::parameter_request_list;
    case 56U:
        return DhcpOptionSemanticKind::message;
    case 57U:
        return DhcpOptionSemanticKind::maximum_message_size;
    case 58U:
        return DhcpOptionSemanticKind::renewal_time;
    case 59U:
        return DhcpOptionSemanticKind::rebinding_time;
    case 60U:
        return DhcpOptionSemanticKind::vendor_class_identifier;
    case 61U:
        return DhcpOptionSemanticKind::client_identifier;
    case 66U:
        return DhcpOptionSemanticKind::tftp_server_name;
    case 67U:
        return DhcpOptionSemanticKind::bootfile_name;
    case kOptionEnd:
        return DhcpOptionSemanticKind::end;
    default:
        return DhcpOptionSemanticKind::unknown;
    }
}

std::vector<DhcpOption> parse_option_area(
    const std::span<const std::uint8_t> bytes,
    const DhcpOptionArea area,
    bool& has_malformed_option
) {
    std::vector<DhcpOption> options {};
    std::size_t cursor = 0U;
    while (cursor < bytes.size()) {
        const auto code = bytes[cursor];
        ++cursor;

        if (code == kOptionPad) {
            continue;
        }

        if (code == kOptionEnd) {
            options.push_back(DhcpOption {
                .area = area,
                .code = code,
                .semantic_kind = DhcpOptionSemanticKind::end,
            });
            break;
        }

        if (cursor >= bytes.size()) {
            options.push_back(DhcpOption {
                .area = area,
                .code = code,
                .declared_length = std::nullopt,
                .available_value_length = 0U,
                .semantic_kind = semantic_kind_for_code(code),
                .status = DhcpOptionStatus::malformed,
            });
            has_malformed_option = true;
            break;
        }

        const auto declared_length = bytes[cursor];
        ++cursor;
        const auto available_length = std::min<std::size_t>(declared_length, bytes.size() - cursor);

        DhcpOption option {
            .area = area,
            .code = code,
            .declared_length = declared_length,
            .available_value_length = static_cast<std::uint8_t>(available_length),
            .semantic_kind = semantic_kind_for_code(code),
            .status = available_length == declared_length ? DhcpOptionStatus::complete : DhcpOptionStatus::malformed,
        };
        option.value.assign(
            bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
            bytes.begin() + static_cast<std::ptrdiff_t>(cursor + available_length)
        );
        options.push_back(std::move(option));

        if (available_length != declared_length) {
            has_malformed_option = true;
            break;
        }

        cursor += declared_length;
    }

    return options;
}

std::optional<std::uint8_t> first_valid_option_overload_value(const std::vector<DhcpOption>& options) noexcept {
    for (const auto& option : options) {
        if (option.code != kOptionOverload ||
            option.status != DhcpOptionStatus::complete ||
            option.value.size() != 1U) {
            continue;
        }

        const auto value = option.value.front();
        if (value >= 1U && value <= 3U) {
            return value;
        }
    }

    return std::nullopt;
}

}  // namespace

bool dhcp_message_matches_current_support_contract(
    const std::span<const std::uint8_t> dhcp_bytes,
    const DhcpRecognitionContext context
) noexcept {
    if (!has_port_pair(context.src_port, context.dst_port, kDhcpClientPort, kDhcpServerPort)) {
        return false;
    }
    if (dhcp_bytes.size() < DhcpInspectionParser::kMinPayloadSize) {
        return false;
    }
    return read_be32(dhcp_bytes, DhcpInspectionParser::kMagicCookieOffset) == DhcpInspectionParser::kMagicCookie;
}

std::optional<DhcpMessage> DhcpInspectionParser::inspect(const std::span<const std::uint8_t> dhcp_bytes) const {
    if (dhcp_bytes.size() < kMinPayloadSize) {
        return std::nullopt;
    }

    DhcpMessage message {
        .op = dhcp_bytes[0],
        .htype = dhcp_bytes[1],
        .hlen = dhcp_bytes[2],
        .hops = dhcp_bytes[3],
        .xid = read_be32(dhcp_bytes, 4U),
        .secs = read_be16(dhcp_bytes, 8U),
        .flags = read_be16(dhcp_bytes, 10U),
        .ciaddr = read_be32(dhcp_bytes, 12U),
        .yiaddr = read_be32(dhcp_bytes, 16U),
        .siaddr = read_be32(dhcp_bytes, 20U),
        .giaddr = read_be32(dhcp_bytes, 24U),
        .magic_cookie = read_be32(dhcp_bytes, kMagicCookieOffset),
    };

    std::copy_n(dhcp_bytes.begin() + static_cast<std::ptrdiff_t>(kChaddrOffset), kChaddrSize, message.chaddr.begin());
    std::copy_n(dhcp_bytes.begin() + static_cast<std::ptrdiff_t>(kSnameOffset), kSnameSize, message.sname.begin());
    std::copy_n(dhcp_bytes.begin() + static_cast<std::ptrdiff_t>(kFileOffset), kFileSize, message.file.begin());

    const auto main_options_bytes = dhcp_bytes.subspan(kOptionsOffset);
    message.main_options = parse_option_area(main_options_bytes, DhcpOptionArea::main, message.has_malformed_option);

    const auto overload = first_valid_option_overload_value(message.main_options);
    if (overload.has_value()) {
        message.file_overloaded = (*overload & 0x01U) != 0U;
        message.sname_overloaded = (*overload & 0x02U) != 0U;
    }

    if (message.file_overloaded) {
        message.file_options = parse_option_area(
            std::span<const std::uint8_t>(message.file.data(), message.file.size()),
            DhcpOptionArea::file,
            message.has_malformed_option
        );
    }
    if (message.sname_overloaded) {
        message.sname_options = parse_option_area(
            std::span<const std::uint8_t>(message.sname.data(), message.sname.size()),
            DhcpOptionArea::sname,
            message.has_malformed_option
        );
    }

    return message;
}

std::optional<DhcpMessage> inspect_supported_dhcp_message(
    const std::span<const std::uint8_t> dhcp_bytes,
    const DhcpRecognitionContext context
) {
    if (!dhcp_message_matches_current_support_contract(dhcp_bytes, context)) {
        return std::nullopt;
    }

    DhcpInspectionParser parser {};
    return parser.inspect(dhcp_bytes);
}

}  // namespace pfl
