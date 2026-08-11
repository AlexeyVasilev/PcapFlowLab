#include "app/session/IcmpSummaryPresentation.h"

#include <iomanip>
#include <sstream>
#include <string_view>
#include <utility>

namespace pfl::session_detail {

namespace {

PacketSummaryField make_summary_field(std::string label, std::string value) {
    return PacketSummaryField {
        .label = std::move(label),
        .value = std::move(value),
    };
}

std::string format_hex16_value(const std::uint16_t value) {
    std::ostringstream builder {};
    builder << "0x"
            << std::uppercase
            << std::hex
            << std::setw(4)
            << std::setfill('0')
            << static_cast<unsigned>(value);
    return builder.str();
}

std::string format_type_text(const IcmpMessageKind kind, const std::uint8_t type) {
    switch (kind) {
    case IcmpMessageKind::echo_request:
        return "Echo Request (" + std::to_string(type) + ")";
    case IcmpMessageKind::echo_reply:
        return "Echo Reply (" + std::to_string(type) + ")";
    case IcmpMessageKind::destination_unreachable:
        return "Destination Unreachable (" + std::to_string(type) + ")";
    case IcmpMessageKind::time_exceeded:
        return "Time Exceeded (" + std::to_string(type) + ")";
    case IcmpMessageKind::redirect:
        return "Redirect (" + std::to_string(type) + ")";
    case IcmpMessageKind::parameter_problem:
        return "Parameter Problem (" + std::to_string(type) + ")";
    case IcmpMessageKind::unknown:
    default:
        return "Unknown (" + std::to_string(type) + ")";
    }
}

std::string format_code_text(const IcmpMessage& message) {
    if (!message.code.has_value()) {
        return {};
    }

    const auto code = *message.code;
    switch (message.kind) {
    case IcmpMessageKind::destination_unreachable:
        switch (code) {
        case 0U:
            return "Network Unreachable (0)";
        case 1U:
            return "Host Unreachable (1)";
        case 3U:
            return "Port Unreachable (3)";
        case 4U:
            return "Fragmentation Needed (4)";
        default:
            break;
        }
        break;
    case IcmpMessageKind::time_exceeded:
        switch (code) {
        case 0U:
            return "TTL Exceeded in Transit (0)";
        case 1U:
            return "Fragment Reassembly Time Exceeded (1)";
        default:
            break;
        }
        break;
    case IcmpMessageKind::redirect:
        switch (code) {
        case 0U:
            return "Redirect Datagram for the Network (0)";
        case 1U:
            return "Redirect Datagram for the Host (1)";
        default:
            break;
        }
        break;
    case IcmpMessageKind::parameter_problem:
        switch (code) {
        case 0U:
            return "Pointer Indicates Error (0)";
        default:
            break;
        }
        break;
    default:
        break;
    }

    return std::to_string(code);
}

std::string format_title(const IcmpMessage& message) {
    constexpr std::string_view prefix = "Internet Control Message Protocol";
    switch (message.kind) {
    case IcmpMessageKind::echo_request:
        return std::string(prefix) + ", Echo Request";
    case IcmpMessageKind::echo_reply:
        return std::string(prefix) + ", Echo Reply";
    case IcmpMessageKind::destination_unreachable:
        return std::string(prefix) + ", Destination Unreachable";
    case IcmpMessageKind::time_exceeded:
        return std::string(prefix) + ", Time Exceeded";
    case IcmpMessageKind::redirect:
        return std::string(prefix) + ", Redirect";
    case IcmpMessageKind::parameter_problem:
        return std::string(prefix) + ", Parameter Problem";
    case IcmpMessageKind::unknown:
    default:
        return std::string(prefix);
    }
}

std::string warning_text(const IcmpInspectionStatus status) {
    switch (status) {
    case IcmpInspectionStatus::truncated:
        return "ICMP message truncated";
    case IcmpInspectionStatus::malformed:
        return "ICMP message malformed";
    case IcmpInspectionStatus::not_enough_header:
        return "ICMP common header is incomplete";
    case IcmpInspectionStatus::complete:
    default:
        return {};
    }
}

void append_quoted_data_length(
    std::vector<PacketSummaryField>& fields,
    const std::optional<IcmpQuotedDataInfo>& quoted_data
) {
    if (!quoted_data.has_value()) {
        return;
    }
    fields.push_back(make_summary_field("Quoted Data Length", std::to_string(quoted_data->length)));
}

}  // namespace

std::optional<PacketSummaryLayer> build_icmp_summary_layer(const PacketDetails& details) {
    if (!details.has_icmp && !details.icmp_message.has_value()) {
        return std::nullopt;
    }

    if (!details.icmp_message.has_value()) {
        std::vector<PacketSummaryField> legacy_fields {
            make_summary_field("Type", std::to_string(details.icmp.type)),
            make_summary_field("Code", std::to_string(details.icmp.code)),
        };
        if (details.has_ipv4) {
            legacy_fields.push_back(make_summary_field("Source", format_ipv4_address(details.ipv4.src_addr)));
            legacy_fields.push_back(make_summary_field("Destination", format_ipv4_address(details.ipv4.dst_addr)));
        }

        return PacketSummaryLayer {
            .id = "icmp",
            .title = "Internet Control Message Protocol",
            .fields = std::move(legacy_fields),
        };
    }

    const auto& message = *details.icmp_message;
    std::vector<PacketSummaryField> fields {};
    if (message.type.has_value()) {
        fields.push_back(make_summary_field("Type", format_type_text(message.kind, *message.type)));
    }
    if (message.code.has_value()) {
        fields.push_back(make_summary_field("Code", format_code_text(message)));
    }
    if (message.checksum.has_value()) {
        fields.push_back(make_summary_field("Checksum", format_hex16_value(*message.checksum)));
    }

    if (message.echo.has_value()) {
        if (message.echo->identifier.has_value()) {
            fields.push_back(make_summary_field("Identifier", std::to_string(*message.echo->identifier)));
        }
        if (message.echo->sequence_number.has_value()) {
            fields.push_back(make_summary_field("Sequence Number", std::to_string(*message.echo->sequence_number)));
        }
        if (message.echo->payload_length.has_value()) {
            fields.push_back(make_summary_field("Payload Length", std::to_string(*message.echo->payload_length)));
        }
    }

    if (message.destination_unreachable.has_value()) {
        if (message.destination_unreachable->next_hop_mtu.has_value()) {
            fields.push_back(make_summary_field("Next-Hop MTU", std::to_string(*message.destination_unreachable->next_hop_mtu)));
        }
        append_quoted_data_length(fields, message.destination_unreachable->quoted_data);
    }

    if (message.time_exceeded.has_value()) {
        append_quoted_data_length(fields, message.time_exceeded->quoted_data);
    }

    if (message.redirect.has_value()) {
        if (message.redirect->gateway_address.has_value()) {
            fields.push_back(make_summary_field("Gateway Address", format_ipv4_address(*message.redirect->gateway_address)));
        }
        append_quoted_data_length(fields, message.redirect->quoted_data);
    }

    if (message.parameter_problem.has_value()) {
        if (message.parameter_problem->pointer.has_value()) {
            fields.push_back(make_summary_field("Pointer", std::to_string(*message.parameter_problem->pointer)));
        }
        append_quoted_data_length(fields, message.parameter_problem->quoted_data);
    }

    if (details.has_ipv4) {
        fields.push_back(make_summary_field("Source", format_ipv4_address(details.ipv4.src_addr)));
        fields.push_back(make_summary_field("Destination", format_ipv4_address(details.ipv4.dst_addr)));
    }

    const auto warning = warning_text(message.status);
    if (!warning.empty()) {
        fields.push_back(make_summary_field({}, warning));
    }

    return PacketSummaryLayer {
        .id = "icmp",
        .title = format_title(message),
        .fields = std::move(fields),
        .warning = !warning.empty(),
        .marker_text = !warning.empty() ? std::string {"Warning"} : std::string {},
    };
}

}  // namespace pfl::session_detail
