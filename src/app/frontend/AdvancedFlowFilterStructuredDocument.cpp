#include "app/frontend/FrontendSessionAdapter.h"

#include <algorithm>
#include <array>
#include <sstream>

namespace pfl {

namespace {

template <typename Enum>
struct EnumDescriptor {
    Enum value {};
    const char* stable_id {""};
    const char* label {""};
};

constexpr std::array<EnumDescriptor<FlowAddressFamily>, 2> kAddressFamilyDescriptors {{
    {FlowAddressFamily::ipv4, "ipv4", "IPv4"},
    {FlowAddressFamily::ipv6, "ipv6", "IPv6"},
}};

constexpr std::array<EnumDescriptor<ProtocolId>, 9> kFlowProtocolDescriptors {{
    {ProtocolId::unknown, "unknown", "Unknown"},
    {ProtocolId::icmp, "icmp", "ICMP"},
    {ProtocolId::igmp, "igmp", "IGMP"},
    {ProtocolId::tcp, "tcp", "TCP"},
    {ProtocolId::udp, "udp", "UDP"},
    {ProtocolId::esp, "esp", "ESP"},
    {ProtocolId::icmpv6, "icmpv6", "ICMPv6"},
    {ProtocolId::sctp, "sctp", "SCTP"},
    {ProtocolId::arp, "arp", "ARP"},
}};

constexpr std::array<EnumDescriptor<FlowProtocolHint>, 17> kDetectedProtocolDescriptors {{
    {FlowProtocolHint::unknown, "unknown", "Unknown"},
    {FlowProtocolHint::tls, "tls", "TLS"},
    {FlowProtocolHint::http, "http", "HTTP"},
    {FlowProtocolHint::dns, "dns", "DNS"},
    {FlowProtocolHint::quic, "quic", "QUIC"},
    {FlowProtocolHint::ssh, "ssh", "SSH"},
    {FlowProtocolHint::stun, "stun", "STUN"},
    {FlowProtocolHint::bittorrent, "bittorrent", "BitTorrent"},
    {FlowProtocolHint::dhcp, "dhcp", "DHCP"},
    {FlowProtocolHint::mdns, "mdns", "mDNS"},
    {FlowProtocolHint::smtp, "smtp", "SMTP"},
    {FlowProtocolHint::pop3, "pop3", "POP3"},
    {FlowProtocolHint::imap, "imap", "IMAP"},
    {FlowProtocolHint::igmp, "igmp", "IGMP"},
    {FlowProtocolHint::igmpv1, "igmpv1", "IGMPv1"},
    {FlowProtocolHint::igmpv2, "igmpv2", "IGMPv2"},
    {FlowProtocolHint::igmpv3, "igmpv3", "IGMPv3"},
}};

constexpr std::array<EnumDescriptor<TlsVersionHint>, 3> kTlsVersionDescriptors {{
    {TlsVersionHint::unknown, "unknown", "Unknown"},
    {TlsVersionHint::tls12, "tls1_2", "TLS 1.2"},
    {TlsVersionHint::tls13, "tls1_3", "TLS 1.3"},
}};

constexpr std::array<EnumDescriptor<QuicVersionHint>, 4> kQuicVersionDescriptors {{
    {QuicVersionHint::unknown, "unknown", "Unknown"},
    {QuicVersionHint::v1, "v1", "QUIC v1"},
    {QuicVersionHint::draft29, "draft29", "QUIC draft-29"},
    {QuicVersionHint::v2, "v2", "QUIC v2"},
}};

constexpr std::array<EnumDescriptor<session_detail::AdvancedFlowFilterDirectionality>, 2>
    kDirectionalityDescriptors {{
        {session_detail::AdvancedFlowFilterDirectionality::unidirectional, "unidirectional", "One direction"},
        {session_detail::AdvancedFlowFilterDirectionality::bidirectional, "bidirectional", "Both directions"},
    }};

template <typename Enum, std::size_t Size>
const EnumDescriptor<Enum>* descriptor_for_value(
    const std::array<EnumDescriptor<Enum>, Size>& descriptors,
    const Enum value
) {
    const auto it = std::find_if(
        descriptors.begin(),
        descriptors.end(),
        [value](const auto& descriptor) { return descriptor.value == value; }
    );
    return it == descriptors.end() ? nullptr : &(*it);
}

template <typename Enum, std::size_t Size>
const EnumDescriptor<Enum>* descriptor_for_id(
    const std::array<EnumDescriptor<Enum>, Size>& descriptors,
    const std::string_view stable_id
) {
    const auto it = std::find_if(
        descriptors.begin(),
        descriptors.end(),
        [stable_id](const auto& descriptor) { return stable_id == descriptor.stable_id; }
    );
    return it == descriptors.end() ? nullptr : &(*it);
}

FrontendAdvancedFlowFilterStructuredOptionCatalogDto build_option_catalog() {
    FrontendAdvancedFlowFilterStructuredOptionCatalogDto catalog {};

    const auto append_catalog = []<typename Enum, std::size_t Size>(
                                    const std::array<EnumDescriptor<Enum>, Size>& descriptors,
                                    std::vector<FrontendAdvancedFlowFilterFiniteOptionDto>& out) {
        out.reserve(descriptors.size());
        for (const auto& descriptor : descriptors) {
            out.push_back(FrontendAdvancedFlowFilterFiniteOptionDto {
                .stable_id = descriptor.stable_id,
                .label = descriptor.label,
            });
        }
    };

    append_catalog(kAddressFamilyDescriptors, catalog.address_family);
    append_catalog(kFlowProtocolDescriptors, catalog.flow_protocol);
    append_catalog(kDetectedProtocolDescriptors, catalog.detected_protocol);
    append_catalog(kTlsVersionDescriptors, catalog.tls_version);
    append_catalog(kQuicVersionDescriptors, catalog.quic_version);
    append_catalog(kDirectionalityDescriptors, catalog.directionality);
    return catalog;
}

std::string parse_error_text(const std::optional<FrontendAdvancedFlowTextParseIssue>& issue) {
    if (!issue.has_value()) {
        return "Advanced filter text is invalid.";
    }

    std::ostringstream out {};
    out << "Line " << issue->line;
    if (issue->column.has_value()) {
        out << ':' << *issue->column;
    }
    if (!issue->message.empty()) {
        out << ": " << issue->message;
    } else {
        out << ": Advanced filter text is invalid.";
    }
    return out.str();
}

std::string compile_error_text(
    const session_detail::AdvancedFlowFilterCompileStatus status,
    const std::optional<session_detail::AdvancedFlowFilterCompileIssue>& issue
) {
    if (issue.has_value() && !issue->category.empty()) {
        return "Advanced filter is invalid: " + issue->category + '.';
    }

    switch (status) {
    case session_detail::AdvancedFlowFilterCompileStatus::invalid_numeric_range:
        return "Advanced filter is invalid: numeric range.";
    case session_detail::AdvancedFlowFilterCompileStatus::invalid_protocol_path_predicate:
        return "Advanced filter is invalid: protocol path predicate.";
    case session_detail::AdvancedFlowFilterCompileStatus::invalid_address_predicate:
        return "Advanced filter is invalid: address predicate.";
    case session_detail::AdvancedFlowFilterCompileStatus::invalid_service_predicate:
        return "Advanced filter is invalid: service predicate.";
    case session_detail::AdvancedFlowFilterCompileStatus::invalid_directionality_predicate:
        return "Advanced filter is invalid: directionality predicate.";
    case session_detail::AdvancedFlowFilterCompileStatus::invalid_address_family_predicate:
        return "Advanced filter is invalid: address family predicate.";
    case session_detail::AdvancedFlowFilterCompileStatus::ok:
        return {};
    }

    return "Advanced filter is invalid.";
}

std::string structured_status_error_text(const FrontendAdvancedFlowFilterStructuredDocumentResult& result) {
    if (!result.error_text.empty()) {
        return result.error_text;
    }
    switch (result.status) {
    case FrontendAdvancedFlowFilterStructuredDocumentStatus::ok:
        return {};
    case FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_document_update:
        if (result.update_issue.has_value() && !result.update_issue->message.empty()) {
            return result.update_issue->message;
        }
        return "Advanced filter document update is invalid.";
    case FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document:
        return "Advanced filter document cannot be represented by the Tauri structured editor.";
    case FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_advanced_filter:
        if (result.parse_status != session_detail::AdvancedFlowFilterTextParseStatus::ok) {
            return parse_error_text(result.parse_issue);
        }
        return compile_error_text(result.compile_status, result.compile_issue);
    case FrontendAdvancedFlowFilterStructuredDocumentStatus::query_failure:
        return "Advanced filter validation failed.";
    }
    return "Advanced filter validation failed.";
}

template <typename Enum, std::size_t Size>
bool encode_finite_values(
    const std::array<EnumDescriptor<Enum>, Size>& descriptors,
    const std::vector<Enum>& values,
    const std::string_view section_id,
    const std::string_view group,
    std::vector<std::string>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    out.clear();
    out.reserve(values.size());
    for (const auto value : values) {
        const auto* descriptor = descriptor_for_value(descriptors, value);
        if (descriptor == nullptr) {
            result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
            result.update_issue = FrontendAdvancedFlowFilterStructuredUpdateIssue {
                .section_id = std::string(section_id),
                .group = std::string(group),
                .value_id = {},
                .message = "The current Advanced Filter document contains a finite value that the Tauri structured editor cannot represent.",
            };
            result.error_text = structured_status_error_text(result);
            return false;
        }
        if (std::find(out.begin(), out.end(), descriptor->stable_id) != out.end()) {
            result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
            result.update_issue = FrontendAdvancedFlowFilterStructuredUpdateIssue {
                .section_id = std::string(section_id),
                .group = std::string(group),
                .value_id = descriptor->stable_id,
                .message = "Repeated finite-section predicates cannot be represented by the Tauri structured editor.",
            };
            result.error_text = structured_status_error_text(result);
            return false;
        }
        out.push_back(descriptor->stable_id);
    }
    return true;
}

template <typename Enum, std::size_t Size>
bool decode_finite_values(
    const std::array<EnumDescriptor<Enum>, Size>& descriptors,
    const std::string_view section_id,
    const std::string_view group,
    const std::vector<std::string>& stable_ids,
    std::vector<Enum>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    out.clear();
    out.reserve(stable_ids.size());
    std::vector<std::string> seen {};
    seen.reserve(stable_ids.size());
    for (const auto& stable_id : stable_ids) {
        const auto* descriptor = descriptor_for_id(descriptors, stable_id);
        if (descriptor == nullptr) {
            result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_document_update;
            result.update_issue = FrontendAdvancedFlowFilterStructuredUpdateIssue {
                .section_id = std::string(section_id),
                .group = std::string(group),
                .value_id = stable_id,
                .message = "The structured Advanced Filter update contains an unknown finite stable ID.",
            };
            result.error_text = structured_status_error_text(result);
            return false;
        }
        if (std::find(seen.begin(), seen.end(), stable_id) != seen.end()) {
            result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_document_update;
            result.update_issue = FrontendAdvancedFlowFilterStructuredUpdateIssue {
                .section_id = std::string(section_id),
                .group = std::string(group),
                .value_id = stable_id,
                .message = "The structured Advanced Filter update repeats a finite stable ID.",
            };
            result.error_text = structured_status_error_text(result);
            return false;
        }
        seen.push_back(stable_id);
        out.push_back(descriptor->value);
    }
    return true;
}

bool has_unsupported_configured_sections(const session_detail::AdvancedFlowFilterDocument& document) {
    const auto& spec = document.configured_spec;
    const auto& aggregate = spec.aggregate;
    return !spec.ports.include.empty() ||
        !spec.ports.exclude.empty() ||
        !spec.addresses.ipv4_include.empty() ||
        !spec.addresses.ipv4_exclude.empty() ||
        !spec.addresses.ipv6_include.empty() ||
        !spec.addresses.ipv6_exclude.empty() ||
        aggregate.packet_count.has_value() ||
        aggregate.original_bytes.has_value() ||
        aggregate.captured_bytes.has_value() ||
        aggregate.duration_us.has_value() ||
        aggregate.fragmented_packet_count.has_value() ||
        aggregate.truncated_packet_count.has_value() ||
        aggregate.tcp_syn_count.has_value() ||
        aggregate.tcp_fin_count.has_value() ||
        aggregate.tcp_rst_count.has_value() ||
        aggregate.max_original_packet_length.has_value() ||
        aggregate.max_captured_packet_length.has_value() ||
        !spec.service.include.empty() ||
        !spec.service.exclude.empty() ||
        !spec.protocol_path.include.empty() ||
        !spec.protocol_path.exclude.empty();
}

std::optional<FrontendAdvancedFlowFilterStructuredDocumentDto> build_structured_document(
    const session_detail::AdvancedFlowFilterDocument& document,
    const std::string& canonical_text,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    FrontendAdvancedFlowFilterStructuredDocumentDto structured {};
    structured.canonical_text = canonical_text;
    structured.address_family.enabled = document.section_states.address_family;
    structured.flow_protocol.enabled = document.section_states.flow_protocol;
    structured.detected_protocol.enabled = document.section_states.detected_protocol;
    structured.tls_version.enabled = document.section_states.tls_version;
    structured.quic_version.enabled = document.section_states.quic_version;
    structured.directionality.enabled = document.section_states.directionality;
    structured.has_unsupported_configured_sections = has_unsupported_configured_sections(document);

    if (!encode_finite_values(
            kAddressFamilyDescriptors,
            document.configured_spec.address_family.include,
            "address_family",
            "include",
            structured.address_family.include,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kAddressFamilyDescriptors,
            document.configured_spec.address_family.exclude,
            "address_family",
            "exclude",
            structured.address_family.exclude,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kFlowProtocolDescriptors,
            document.configured_spec.flow_protocol.include,
            "flow_protocol",
            "include",
            structured.flow_protocol.include,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kFlowProtocolDescriptors,
            document.configured_spec.flow_protocol.exclude,
            "flow_protocol",
            "exclude",
            structured.flow_protocol.exclude,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kDetectedProtocolDescriptors,
            document.configured_spec.detected_protocol.include,
            "detected_protocol",
            "include",
            structured.detected_protocol.include,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kDetectedProtocolDescriptors,
            document.configured_spec.detected_protocol.exclude,
            "detected_protocol",
            "exclude",
            structured.detected_protocol.exclude,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kTlsVersionDescriptors,
            document.configured_spec.tls_version.include,
            "tls_version",
            "include",
            structured.tls_version.include,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kTlsVersionDescriptors,
            document.configured_spec.tls_version.exclude,
            "tls_version",
            "exclude",
            structured.tls_version.exclude,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kQuicVersionDescriptors,
            document.configured_spec.quic_version.include,
            "quic_version",
            "include",
            structured.quic_version.include,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kQuicVersionDescriptors,
            document.configured_spec.quic_version.exclude,
            "quic_version",
            "exclude",
            structured.quic_version.exclude,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kDirectionalityDescriptors,
            document.configured_spec.directionality.include,
            "directionality",
            "include",
            structured.directionality.include,
            result)) {
        return std::nullopt;
    }
    if (!encode_finite_values(
            kDirectionalityDescriptors,
            document.configured_spec.directionality.exclude,
            "directionality",
            "exclude",
            structured.directionality.exclude,
            result)) {
        return std::nullopt;
    }

    return structured;
}

FrontendAdvancedFlowFilterStructuredDocumentResult parse_document_text(
    const std::string_view filter_text
) {
    FrontendAdvancedFlowFilterStructuredDocumentResult result {};
    result.option_catalog = build_option_catalog();

    const auto parse_result = session_detail::parse_advanced_flow_filter_text(filter_text);
    result.parse_status = parse_result.status;
    if (parse_result.issue.has_value()) {
        result.parse_issue = FrontendAdvancedFlowTextParseIssue {
            .status = parse_result.issue->status,
            .line = parse_result.issue->line,
            .column = parse_result.issue->column,
            .key = parse_result.issue->key,
            .token = parse_result.issue->token,
            .message = parse_result.issue->message,
        };
    }
    if (parse_result.status != session_detail::AdvancedFlowFilterTextParseStatus::ok) {
        result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_advanced_filter;
        result.error_text = structured_status_error_text(result);
        return result;
    }

    result.configured_rule_count =
        session_detail::count_configured_advanced_flow_filter_atomic_rules(parse_result.document);
    result.active_rule_count =
        session_detail::count_active_advanced_flow_filter_atomic_rules(parse_result.document);

    const auto format_result = session_detail::format_advanced_flow_filter_text(parse_result.document);
    if (format_result.status != session_detail::AdvancedFlowFilterTextFormatStatus::ok) {
        result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
        result.error_text = format_result.issue.has_value()
            ? format_result.issue->message
            : structured_status_error_text(result);
        return result;
    }

    result.document = build_structured_document(parse_result.document, format_result.text, result);
    if (!result.document.has_value()) {
        if (result.error_text.empty()) {
            result.error_text = structured_status_error_text(result);
        }
        return result;
    }

    result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::ok;
    return result;
}

}  // namespace

FrontendAdvancedFlowFilterStructuredDocumentResult
FrontendSessionAdapter::parse_advanced_flow_filter_structured_document(const std::string_view filter_text) const {
    return parse_document_text(filter_text);
}

FrontendAdvancedFlowFilterStructuredDocumentResult
FrontendSessionAdapter::update_advanced_flow_filter_structured_section(
    const std::string_view filter_text,
    const std::string_view section_id,
    const bool enabled,
    const std::vector<std::string>& include_ids,
    const std::vector<std::string>& exclude_ids
) const {
    auto parsed = parse_document_text(filter_text);
    if (parsed.status != FrontendAdvancedFlowFilterStructuredDocumentStatus::ok) {
        return parsed;
    }

    const auto parse_result = session_detail::parse_advanced_flow_filter_text(filter_text);
    if (parse_result.status != session_detail::AdvancedFlowFilterTextParseStatus::ok) {
        return parsed;
    }

    auto document = parse_result.document;
    auto& spec = document.configured_spec;

    if (section_id == "address_family") {
        document.section_states.address_family = enabled;
        if (!decode_finite_values(
                kAddressFamilyDescriptors,
                section_id,
                "include",
                include_ids,
                spec.address_family.include,
                parsed) ||
            !decode_finite_values(
                kAddressFamilyDescriptors,
                section_id,
                "exclude",
                exclude_ids,
                spec.address_family.exclude,
                parsed)) {
            return parsed;
        }
    } else if (section_id == "flow_protocol") {
        document.section_states.flow_protocol = enabled;
        if (!decode_finite_values(
                kFlowProtocolDescriptors,
                section_id,
                "include",
                include_ids,
                spec.flow_protocol.include,
                parsed) ||
            !decode_finite_values(
                kFlowProtocolDescriptors,
                section_id,
                "exclude",
                exclude_ids,
                spec.flow_protocol.exclude,
                parsed)) {
            return parsed;
        }
    } else if (section_id == "detected_protocol") {
        document.section_states.detected_protocol = enabled;
        if (!decode_finite_values(
                kDetectedProtocolDescriptors,
                section_id,
                "include",
                include_ids,
                spec.detected_protocol.include,
                parsed) ||
            !decode_finite_values(
                kDetectedProtocolDescriptors,
                section_id,
                "exclude",
                exclude_ids,
                spec.detected_protocol.exclude,
                parsed)) {
            return parsed;
        }
    } else if (section_id == "tls_version") {
        document.section_states.tls_version = enabled;
        if (!decode_finite_values(
                kTlsVersionDescriptors,
                section_id,
                "include",
                include_ids,
                spec.tls_version.include,
                parsed) ||
            !decode_finite_values(
                kTlsVersionDescriptors,
                section_id,
                "exclude",
                exclude_ids,
                spec.tls_version.exclude,
                parsed)) {
            return parsed;
        }
    } else if (section_id == "quic_version") {
        document.section_states.quic_version = enabled;
        if (!decode_finite_values(
                kQuicVersionDescriptors,
                section_id,
                "include",
                include_ids,
                spec.quic_version.include,
                parsed) ||
            !decode_finite_values(
                kQuicVersionDescriptors,
                section_id,
                "exclude",
                exclude_ids,
                spec.quic_version.exclude,
                parsed)) {
            return parsed;
        }
    } else if (section_id == "directionality") {
        document.section_states.directionality = enabled;
        if (!decode_finite_values(
                kDirectionalityDescriptors,
                section_id,
                "include",
                include_ids,
                spec.directionality.include,
                parsed) ||
            !decode_finite_values(
                kDirectionalityDescriptors,
                section_id,
                "exclude",
                exclude_ids,
                spec.directionality.exclude,
                parsed)) {
            return parsed;
        }
    } else {
        parsed.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_document_update;
        parsed.update_issue = FrontendAdvancedFlowFilterStructuredUpdateIssue {
            .section_id = std::string(section_id),
            .group = {},
            .value_id = {},
            .message = "The structured Advanced Filter update references an unknown finite section.",
        };
        parsed.error_text = structured_status_error_text(parsed);
        return parsed;
    }

    const auto format_result = session_detail::format_advanced_flow_filter_text(document);
    if (format_result.status != session_detail::AdvancedFlowFilterTextFormatStatus::ok) {
        parsed.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
        parsed.error_text = format_result.issue.has_value()
            ? format_result.issue->message
            : structured_status_error_text(parsed);
        return parsed;
    }

    return parse_document_text(format_result.text);
}

}  // namespace pfl
