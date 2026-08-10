#include "app/session/DnsSummaryPresentation.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <type_traits>
#include <utility>

namespace pfl::session_detail {

namespace {

PacketSummaryField make_summary_field(std::string label, std::string value) {
    return PacketSummaryField {
        .label = std::move(label),
        .value = std::move(value),
    };
}

void append_field_if_not_empty(
    std::vector<PacketSummaryField>& fields,
    std::string label,
    const std::optional<std::string>& value
) {
    if (value.has_value() && !value->empty()) {
        fields.push_back(make_summary_field(std::move(label), *value));
    }
}

void append_field_if_not_empty(
    std::vector<PacketSummaryField>& fields,
    std::string label,
    const std::string& value
) {
    if (!value.empty()) {
        fields.push_back(make_summary_field(std::move(label), value));
    }
}

std::string format_yes_no(const bool value) {
    return value ? "Yes" : "No";
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

std::string format_dns_opcode(const std::uint8_t opcode) {
    switch (opcode) {
    case 0U:
        return "Standard query (0)";
    case 1U:
        return "Inverse query (1)";
    case 2U:
        return "Server status request (2)";
    default:
        return "Unknown (" + std::to_string(opcode) + ")";
    }
}

std::string format_dns_response_code(const std::uint8_t code) {
    switch (code) {
    case 0U:
        return "No error (0)";
    case 1U:
        return "Format error (1)";
    case 2U:
        return "Server failure (2)";
    case 3U:
        return "NXDOMAIN (3)";
    case 4U:
        return "Not implemented (4)";
    case 5U:
        return "Refused (5)";
    default:
        return "Unknown (" + std::to_string(code) + ")";
    }
}

std::string format_dns_type(const std::uint16_t type) {
    switch (type) {
    case 1U:
        return "A (1)";
    case 2U:
        return "NS (2)";
    case 5U:
        return "CNAME (5)";
    case 12U:
        return "PTR (12)";
    case 15U:
        return "MX (15)";
    case 16U:
        return "TXT (16)";
    case 28U:
        return "AAAA (28)";
    case 33U:
        return "SRV (33)";
    case 64U:
        return "SVCB (64)";
    case 65U:
        return "HTTPS (65)";
    default:
        return "Unknown (" + std::to_string(type) + ")";
    }
}

std::string format_dns_class(const std::uint16_t raw_class) {
    switch (raw_class) {
    case 1U:
        return "IN (1)";
    case 3U:
        return "CH (3)";
    case 4U:
        return "HS (4)";
    case 255U:
        return "ANY (255)";
    default:
        return "Unknown (" + std::to_string(raw_class) + ")";
    }
}

std::string format_txt_chunk(std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        return "<empty>";
    }

    const bool printable = std::all_of(bytes.begin(), bytes.end(), [](const std::uint8_t byte) {
        return byte >= 0x20U && byte <= 0x7eU;
    });
    if (printable) {
        return std::string(bytes.begin(), bytes.end());
    }

    std::ostringstream builder {};
    builder << "hex: ";
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
        if (index > 0U) {
            builder << ' ';
        }
        builder << std::uppercase
                << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<unsigned>(bytes[index]);
    }
    return builder.str();
}

std::optional<std::string> first_question_name(const DnsMessage& message) {
    if (message.questions.empty()) {
        return std::nullopt;
    }
    if (message.questions[0].name.empty() || message.questions[0].name == ".") {
        return std::nullopt;
    }
    return message.questions[0].name;
}

std::optional<std::string> first_question_type(const DnsMessage& message) {
    if (message.questions.empty()) {
        return std::nullopt;
    }
    return format_dns_type(message.questions[0].type);
}

std::string dns_layer_id(const DnsSummaryPresentationKind kind) {
    return kind == DnsSummaryPresentationKind::mdns ? "mdns" : "dns";
}

std::string dns_layer_prefix_title(const DnsSummaryPresentationKind kind) {
    return kind == DnsSummaryPresentationKind::mdns
        ? "Multicast Domain Name System"
        : "Domain Name System";
}

std::string dns_message_type_text(const DnsMessage& message) {
    return message.is_response ? "Response" : "Query";
}

std::optional<std::string> dns_warning_text(const DnsInspectionStatus status) {
    switch (status) {
    case DnsInspectionStatus::truncated:
        return std::string {"DNS message truncated"};
    case DnsInspectionStatus::malformed:
        return std::string {"DNS message malformed"};
    case DnsInspectionStatus::not_enough_header:
        return std::string {"DNS header is incomplete"};
    case DnsInspectionStatus::complete:
    default:
        return std::nullopt;
    }
}

PacketSummaryLayer build_dns_question_layer(
    const DnsQuestion& question,
    const DnsSummaryPresentationKind presentation_kind
) {
    std::vector<PacketSummaryField> fields {
        make_summary_field("Type", format_dns_type(question.type)),
        make_summary_field(
            "Class",
            format_dns_class(
                presentation_kind == DnsSummaryPresentationKind::mdns
                    ? static_cast<std::uint16_t>(question.raw_class & 0x7FFFU)
                    : question.raw_class
            )
        ),
    };
    if (presentation_kind == DnsSummaryPresentationKind::mdns) {
        fields.push_back(make_summary_field(
            "Unicast Response Requested",
            format_yes_no((question.raw_class & 0x8000U) != 0U)
        ));
    }

    return PacketSummaryLayer {
        .id = "dns_question",
        .title = question.name.empty() ? std::string {"."} : question.name,
        .fields = std::move(fields),
        .expanded_by_default = false,
    };
}

void append_rdata_fields(
    std::vector<PacketSummaryField>& fields,
    const DnsResourceRecord& record
) {
    switch (record.rdata.kind) {
    case DnsRdataKind::a:
        if (record.rdata.parse_status == DnsRdataParseStatus::parsed && record.rdata.address_size == 4U) {
            fields.push_back(make_summary_field("Address", format_ipv4_address({
                record.rdata.address_bytes[0],
                record.rdata.address_bytes[1],
                record.rdata.address_bytes[2],
                record.rdata.address_bytes[3],
            })));
        }
        break;
    case DnsRdataKind::aaaa:
        if (record.rdata.parse_status == DnsRdataParseStatus::parsed && record.rdata.address_size == 16U) {
            fields.push_back(make_summary_field("Address", format_ipv6_address(record.rdata.address_bytes)));
        }
        break;
    case DnsRdataKind::cname:
        append_field_if_not_empty(fields, "Canonical Name", record.rdata.name);
        break;
    case DnsRdataKind::ptr:
        append_field_if_not_empty(fields, "PTR Target", record.rdata.name);
        break;
    case DnsRdataKind::ns:
        append_field_if_not_empty(fields, "Name Server", record.rdata.name);
        break;
    case DnsRdataKind::srv:
        fields.push_back(make_summary_field("Priority", std::to_string(record.rdata.srv_priority)));
        fields.push_back(make_summary_field("Weight", std::to_string(record.rdata.srv_weight)));
        fields.push_back(make_summary_field("Port", std::to_string(record.rdata.srv_port)));
        append_field_if_not_empty(fields, "Target", record.rdata.srv_target);
        break;
    case DnsRdataKind::txt:
        for (std::size_t index = 0U; index < record.rdata.txt_chunks.size(); ++index) {
            const auto& chunk = record.rdata.txt_chunks[index];
            fields.push_back(make_summary_field(
                "TXT[" + std::to_string(index) + "]",
                format_txt_chunk(std::span<const std::uint8_t>(chunk.bytes.data(), chunk.bytes.size()))
            ));
        }
        break;
    case DnsRdataKind::mx:
        fields.push_back(make_summary_field("Preference", std::to_string(record.rdata.mx_preference)));
        append_field_if_not_empty(fields, "Exchange", record.rdata.mx_exchange);
        break;
    case DnsRdataKind::opaque:
    case DnsRdataKind::none:
    default:
        break;
    }
}

PacketSummaryLayer build_dns_resource_record_layer(
    const DnsResourceRecord& record,
    const DnsSummaryPresentationKind presentation_kind
) {
    std::vector<PacketSummaryField> fields {
        make_summary_field("Type", format_dns_type(record.type)),
        make_summary_field(
            "Class",
            format_dns_class(
                presentation_kind == DnsSummaryPresentationKind::mdns
                    ? static_cast<std::uint16_t>(record.raw_class & 0x7FFFU)
                    : record.raw_class
            )
        ),
        make_summary_field("TTL", std::to_string(record.ttl)),
        make_summary_field("RDATA Length", std::to_string(record.rdlength)),
    };

    if (presentation_kind == DnsSummaryPresentationKind::mdns) {
        fields.push_back(make_summary_field(
            "Cache Flush",
            format_yes_no((record.raw_class & 0x8000U) != 0U)
        ));
    }

    append_rdata_fields(fields, record);

    if (record.rdata.parse_status == DnsRdataParseStatus::truncated) {
        fields.push_back(make_summary_field("RDATA Status", "Truncated"));
    } else if (record.rdata.parse_status == DnsRdataParseStatus::malformed) {
        fields.push_back(make_summary_field("RDATA Status", "Malformed"));
    } else if (record.rdata.parse_status == DnsRdataParseStatus::not_supported) {
        fields.push_back(make_summary_field("RDATA Status", "Opaque / not parsed"));
    }

    return PacketSummaryLayer {
        .id = "dns_rr",
        .title = record.name.empty() ? std::string {"."} : record.name,
        .fields = std::move(fields),
        .expanded_by_default = false,
    };
}

template <typename T>
std::optional<PacketSummaryLayer> build_dns_section_layer(
    const std::string& id,
    const std::string& title,
    const std::vector<T>& items,
    const DnsSummaryPresentationKind presentation_kind
) {
    if (items.empty()) {
        return std::nullopt;
    }

    std::vector<PacketSummaryLayer> children {};
    children.reserve(items.size());
    for (const auto& item : items) {
        if constexpr (std::is_same_v<T, DnsQuestion>) {
            children.push_back(build_dns_question_layer(item, presentation_kind));
        } else {
            children.push_back(build_dns_resource_record_layer(item, presentation_kind));
        }
    }

    return PacketSummaryLayer {
        .id = id,
        .title = title,
        .children = std::move(children),
        .expanded_by_default = true,
    };
}

std::optional<PacketSummaryLayer> build_legacy_dns_summary_layer(
    const PacketDetails& details,
    const DnsSummaryPresentationKind presentation_kind
) {
    if (!details.has_dns) {
        return std::nullopt;
    }

    std::vector<PacketSummaryField> fields {
        make_summary_field("Transaction ID", format_hex16_value(details.dns.transaction_id)),
        make_summary_field("QName", details.dns.query_name),
        make_summary_field("QType", format_dns_type(details.dns.query_type)),
    };
    if (details.dns.is_response && details.dns.response_code.has_value()) {
        fields.push_back(make_summary_field("Response Code", format_dns_response_code(*details.dns.response_code)));
    }

    return PacketSummaryLayer {
        .id = dns_layer_id(presentation_kind),
        .title = dns_layer_prefix_title(presentation_kind) + ", " + (details.dns.is_response ? "Response" : "Query"),
        .fields = std::move(fields),
    };
}

}  // namespace

std::optional<PacketSummaryLayer> build_dns_summary_layer(
    const PacketDetails& details,
    const DnsSummaryPresentationKind presentation_kind
) {
    if (!details.dns_message.has_value() ||
        details.dns_message->status == DnsInspectionStatus::not_enough_header) {
        if (!details.has_dns) {
            return std::nullopt;
        }
        return build_legacy_dns_summary_layer(details, presentation_kind);
    }

    const auto& message = *details.dns_message;
    std::vector<PacketSummaryField> fields {
        make_summary_field("Message Type", dns_message_type_text(message)),
        make_summary_field("Transaction ID", format_hex16_value(message.transaction_id)),
        make_summary_field("Flags", format_hex16_value(message.raw_flags)),
        make_summary_field("Opcode", format_dns_opcode(message.opcode)),
        make_summary_field("Authoritative Answer", format_yes_no(message.authoritative_answer)),
        make_summary_field("Truncated", format_yes_no(message.truncated)),
        make_summary_field("Recursion Desired", format_yes_no(message.recursion_desired)),
        make_summary_field("Recursion Available", format_yes_no(message.recursion_available)),
        make_summary_field("Response Code", format_dns_response_code(message.response_code)),
        make_summary_field("Questions", std::to_string(message.declared_question_count)),
        make_summary_field("Answers", std::to_string(message.declared_answer_count)),
        make_summary_field("Authority RRs", std::to_string(message.declared_authority_count)),
        make_summary_field("Additional RRs", std::to_string(message.declared_additional_count)),
    };

    append_field_if_not_empty(fields, "QName", first_question_name(message));
    append_field_if_not_empty(fields, "QType", first_question_type(message));
    append_field_if_not_empty(fields, "Warning", dns_warning_text(message.status));

    std::vector<PacketSummaryLayer> children {};
    if (const auto questions = build_dns_section_layer(
            "dns_questions",
            "Questions",
            message.questions,
            presentation_kind
        );
        questions.has_value()) {
        children.push_back(*questions);
    }
    if (const auto answers = build_dns_section_layer(
            "dns_answers",
            "Answers",
            message.answers,
            presentation_kind
        );
        answers.has_value()) {
        children.push_back(*answers);
    }
    if (const auto authorities = build_dns_section_layer(
            "dns_authorities",
            "Authorities",
            message.authorities,
            presentation_kind
        );
        authorities.has_value()) {
        children.push_back(*authorities);
    }
    if (const auto additionals = build_dns_section_layer(
            "dns_additionals",
            "Additionals",
            message.additionals,
            presentation_kind
        );
        additionals.has_value()) {
        children.push_back(*additionals);
    }

    return PacketSummaryLayer {
        .id = dns_layer_id(presentation_kind),
        .title = dns_layer_prefix_title(presentation_kind) + ", " + dns_message_type_text(message),
        .fields = std::move(fields),
        .children = std::move(children),
        .expanded_by_default = true,
        .warning = message.status != DnsInspectionStatus::complete,
        .marker_text = message.status != DnsInspectionStatus::complete ? "Warning" : std::string {},
    };
}

}  // namespace pfl::session_detail
