#include "core/services/IcmpInspectionParser.h"

#include "core/decode/PacketDecodeSupport.h"

namespace pfl {

namespace {

constexpr std::size_t kIcmpCommonHeaderSize = 4U;
constexpr std::size_t kIcmpTypeSpecificHeaderSize = 8U;

IcmpMessageKind classify_icmp_message_kind(const std::optional<std::uint8_t> type) noexcept {
    if (!type.has_value()) {
        return IcmpMessageKind::unknown;
    }

    switch (*type) {
    case 0U:
        return IcmpMessageKind::echo_reply;
    case 3U:
        return IcmpMessageKind::destination_unreachable;
    case 5U:
        return IcmpMessageKind::redirect;
    case 8U:
        return IcmpMessageKind::echo_request;
    case 11U:
        return IcmpMessageKind::time_exceeded;
    case 12U:
        return IcmpMessageKind::parameter_problem;
    default:
        return IcmpMessageKind::unknown;
    }
}

void populate_common_header(
    IcmpMessage& message,
    const std::span<const std::uint8_t> bytes
) {
    if (bytes.size() >= 1U) {
        message.type = bytes[0U];
    }
    if (bytes.size() >= 2U) {
        message.code = bytes[1U];
    }
    if (bytes.size() >= kIcmpCommonHeaderSize) {
        message.checksum = detail::read_be16(bytes, 2U);
    }
}

void mark_type_specific_status(
    IcmpMessage& message,
    const std::size_t visible_size,
    const std::size_t nominal_size
) {
    if (nominal_size < kIcmpTypeSpecificHeaderSize) {
        message.status = IcmpInspectionStatus::malformed;
        return;
    }
    if (visible_size < kIcmpTypeSpecificHeaderSize) {
        message.status = IcmpInspectionStatus::truncated;
    }
}

std::optional<IcmpQuotedDataInfo> make_quoted_data_info(
    const std::size_t visible_size
) {
    if (visible_size < kIcmpTypeSpecificHeaderSize) {
        return std::nullopt;
    }

    return IcmpQuotedDataInfo {
        .offset = static_cast<std::uint32_t>(kIcmpTypeSpecificHeaderSize),
        .length = static_cast<std::uint32_t>(visible_size - kIcmpTypeSpecificHeaderSize),
    };
}

}  // namespace

IcmpMessage IcmpInspectionParser::inspect(
    const std::span<const std::uint8_t> icmp_bytes,
    const std::optional<std::size_t> declared_length
) const {
    IcmpMessage message {};
    populate_common_header(message, icmp_bytes);

    const auto nominal_size = declared_length.value_or(icmp_bytes.size());
    if (nominal_size < kIcmpCommonHeaderSize) {
        message.status = IcmpInspectionStatus::malformed;
        message.kind = classify_icmp_message_kind(message.type);
        return message;
    }
    if (icmp_bytes.size() < kIcmpCommonHeaderSize) {
        message.status = declared_length.has_value()
            ? IcmpInspectionStatus::truncated
            : IcmpInspectionStatus::not_enough_header;
        message.kind = classify_icmp_message_kind(message.type);
        return message;
    }

    message.status = IcmpInspectionStatus::complete;
    message.kind = classify_icmp_message_kind(message.type);

    switch (message.kind) {
    case IcmpMessageKind::echo_request:
    case IcmpMessageKind::echo_reply: {
        IcmpEchoMessage echo {};
        if (icmp_bytes.size() >= 6U) {
            echo.identifier = detail::read_be16(icmp_bytes, 4U);
        }
        if (icmp_bytes.size() >= 8U) {
            echo.sequence_number = detail::read_be16(icmp_bytes, 6U);
            echo.payload_length = static_cast<std::uint32_t>(icmp_bytes.size() - kIcmpTypeSpecificHeaderSize);
        }
        message.echo = echo;
        mark_type_specific_status(message, icmp_bytes.size(), nominal_size);
        break;
    }
    case IcmpMessageKind::destination_unreachable: {
        IcmpDestinationUnreachableMessage destination_unreachable {};
        if (message.code == std::optional<std::uint8_t> {4U} && icmp_bytes.size() >= 8U) {
            destination_unreachable.next_hop_mtu = detail::read_be16(icmp_bytes, 6U);
        }
        destination_unreachable.quoted_data = make_quoted_data_info(icmp_bytes.size());
        message.destination_unreachable = destination_unreachable;
        mark_type_specific_status(message, icmp_bytes.size(), nominal_size);
        break;
    }
    case IcmpMessageKind::time_exceeded: {
        IcmpTimeExceededMessage time_exceeded {};
        time_exceeded.quoted_data = make_quoted_data_info(icmp_bytes.size());
        message.time_exceeded = time_exceeded;
        mark_type_specific_status(message, icmp_bytes.size(), nominal_size);
        break;
    }
    case IcmpMessageKind::redirect: {
        IcmpRedirectMessage redirect {};
        if (icmp_bytes.size() >= 8U) {
            redirect.gateway_address = detail::read_be32(icmp_bytes, 4U);
        }
        redirect.quoted_data = make_quoted_data_info(icmp_bytes.size());
        message.redirect = redirect;
        mark_type_specific_status(message, icmp_bytes.size(), nominal_size);
        break;
    }
    case IcmpMessageKind::parameter_problem: {
        IcmpParameterProblemMessage parameter_problem {};
        if (icmp_bytes.size() >= 5U) {
            parameter_problem.pointer = icmp_bytes[4U];
        }
        parameter_problem.quoted_data = make_quoted_data_info(icmp_bytes.size());
        message.parameter_problem = parameter_problem;
        mark_type_specific_status(message, icmp_bytes.size(), nominal_size);
        break;
    }
    case IcmpMessageKind::unknown:
    default:
        break;
    }

    return message;
}

bool icmp_common_header_complete(const IcmpMessage& message) noexcept {
    return message.type.has_value() && message.code.has_value() && message.checksum.has_value();
}

}  // namespace pfl
