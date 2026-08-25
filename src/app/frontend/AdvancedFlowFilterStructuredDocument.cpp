#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/SessionFormatting.h"

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

constexpr std::array<EnumDescriptor<session_detail::AdvancedFlowFilterPortScope>, 3> kPortScopeDescriptors {{
    {session_detail::AdvancedFlowFilterPortScope::either_endpoint, "either", "Either endpoint"},
    {session_detail::AdvancedFlowFilterPortScope::endpoint_a, "a", "Endpoint A"},
    {session_detail::AdvancedFlowFilterPortScope::endpoint_b, "b", "Endpoint B"},
}};

constexpr std::array<EnumDescriptor<session_detail::AdvancedFlowFilterEndpointScope>, 3>
    kEndpointScopeDescriptors {{
        {session_detail::AdvancedFlowFilterEndpointScope::either_endpoint, "either", "Either endpoint"},
        {session_detail::AdvancedFlowFilterEndpointScope::endpoint_a, "a", "Endpoint A"},
        {session_detail::AdvancedFlowFilterEndpointScope::endpoint_b, "b", "Endpoint B"},
    }};

std::string structured_status_error_text(const FrontendAdvancedFlowFilterStructuredDocumentResult& result);

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

FrontendAdvancedFlowFilterStructuredUpdateIssue make_update_issue(
    const std::string_view section_id,
    const std::string_view group,
    const std::string_view value_id,
    const std::optional<std::size_t> row_index,
    const std::string_view field_id,
    const std::string_view message
) {
    return FrontendAdvancedFlowFilterStructuredUpdateIssue {
        .section_id = std::string(section_id),
        .group = std::string(group),
        .value_id = std::string(value_id),
        .row_index = row_index,
        .field_id = std::string(field_id),
        .message = std::string(message),
    };
}

void set_invalid_update_issue(
    FrontendAdvancedFlowFilterStructuredDocumentResult& result,
    const std::string_view section_id,
    const std::string_view group,
    const std::string_view value_id,
    const std::optional<std::size_t> row_index,
    const std::string_view field_id,
    const std::string_view message
) {
    result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::invalid_document_update;
    result.update_issue = make_update_issue(section_id, group, value_id, row_index, field_id, message);
    result.error_text = structured_status_error_text(result);
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
    append_catalog(kPortScopeDescriptors, catalog.endpoint_scope);
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

bool encode_port_rows(
    const std::vector<session_detail::AdvancedFlowFilterPortPredicate>& predicates,
    const std::string_view section_id,
    const std::string_view group,
    std::vector<FrontendAdvancedFlowFilterPortRowDto>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    out.clear();
    out.reserve(predicates.size());
    for (const auto& predicate : predicates) {
        const auto* scope_descriptor = descriptor_for_value(kPortScopeDescriptors, predicate.scope);
        if (scope_descriptor == nullptr) {
            result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
            result.update_issue = make_update_issue(
                section_id,
                group,
                {},
                std::nullopt,
                "scope_id",
                "The current Advanced Filter document contains a port scope that the Tauri structured editor cannot represent."
            );
            result.error_text = structured_status_error_text(result);
            return false;
        }
        out.push_back(FrontendAdvancedFlowFilterPortRowDto {
            .scope_id = scope_descriptor->stable_id,
            .range_enabled = predicate.range.first != predicate.range.last,
            .primary_text = std::to_string(predicate.range.first),
            .secondary_text = predicate.range.first != predicate.range.last
                ? std::to_string(predicate.range.last)
                : std::string {},
        });
    }
    return true;
}

FrontendAdvancedFlowFilterIpAddressRowDto ipv4_row_from_predicate(
    const session_detail::AdvancedFlowFilterIpv4AddressPredicate& predicate,
    const EnumDescriptor<session_detail::AdvancedFlowFilterEndpointScope>* scope_descriptor
) {
    return FrontendAdvancedFlowFilterIpAddressRowDto {
        .scope_id = scope_descriptor->stable_id,
        .subnet_enabled = predicate.match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
        .address_text = session_detail::format_ipv4_address(predicate.value),
        .prefix_text = predicate.match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr
            ? std::to_string(predicate.prefix_length)
            : std::string {},
    };
}

FrontendAdvancedFlowFilterIpAddressRowDto ipv6_row_from_predicate(
    const session_detail::AdvancedFlowFilterIpv6AddressPredicate& predicate,
    const EnumDescriptor<session_detail::AdvancedFlowFilterEndpointScope>* scope_descriptor
) {
    return FrontendAdvancedFlowFilterIpAddressRowDto {
        .scope_id = scope_descriptor->stable_id,
        .subnet_enabled = predicate.match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
        .address_text = session_detail::format_ipv6_address(predicate.value),
        .prefix_text = predicate.match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr
            ? std::to_string(predicate.prefix_length)
            : std::string {},
    };
}

bool encode_ip_rows(
    const std::vector<session_detail::AdvancedFlowFilterIpv4AddressPredicate>& ipv4_predicates,
    const std::vector<session_detail::AdvancedFlowFilterIpv6AddressPredicate>& ipv6_predicates,
    const std::string_view section_id,
    const std::string_view group,
    std::vector<FrontendAdvancedFlowFilterIpAddressRowDto>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    out.clear();
    out.reserve(ipv4_predicates.size() + ipv6_predicates.size());

    for (const auto& predicate : ipv4_predicates) {
        const auto* scope_descriptor = descriptor_for_value(kEndpointScopeDescriptors, predicate.scope);
        if (scope_descriptor == nullptr) {
            result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
            result.update_issue = make_update_issue(
                section_id,
                group,
                {},
                std::nullopt,
                "scope_id",
                "The current Advanced Filter document contains an IP scope that the Tauri structured editor cannot represent."
            );
            result.error_text = structured_status_error_text(result);
            return false;
        }
        out.push_back(ipv4_row_from_predicate(predicate, scope_descriptor));
    }

    for (const auto& predicate : ipv6_predicates) {
        const auto* scope_descriptor = descriptor_for_value(kEndpointScopeDescriptors, predicate.scope);
        if (scope_descriptor == nullptr) {
            result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
            result.update_issue = make_update_issue(
                section_id,
                group,
                {},
                std::nullopt,
                "scope_id",
                "The current Advanced Filter document contains an IP scope that the Tauri structured editor cannot represent."
            );
            result.error_text = structured_status_error_text(result);
            return false;
        }
        out.push_back(ipv6_row_from_predicate(predicate, scope_descriptor));
    }

    return true;
}

bool has_unsupported_configured_sections(const session_detail::AdvancedFlowFilterDocument& document) {
    const auto& spec = document.configured_spec;
    const auto& aggregate = spec.aggregate;
    return aggregate.packet_count.has_value() ||
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
    structured.ports.enabled = document.section_states.ports;
    structured.ip_addresses.enabled = document.section_states.ip_addresses;
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
    if (!encode_port_rows(
            document.configured_spec.ports.include,
            "ports",
            "include",
            structured.ports.include,
            result)) {
        return std::nullopt;
    }
    if (!encode_port_rows(
            document.configured_spec.ports.exclude,
            "ports",
            "exclude",
            structured.ports.exclude,
            result)) {
        return std::nullopt;
    }
    if (!encode_ip_rows(
            document.configured_spec.addresses.ipv4_include,
            document.configured_spec.addresses.ipv6_include,
            "ip_addresses",
            "include",
            structured.ip_addresses.include,
            result)) {
        return std::nullopt;
    }
    if (!encode_ip_rows(
            document.configured_spec.addresses.ipv4_exclude,
            document.configured_spec.addresses.ipv6_exclude,
            "ip_addresses",
            "exclude",
            structured.ip_addresses.exclude,
            result)) {
        return std::nullopt;
    }

    return structured;
}

std::string_view endpoint_scope_key_suffix(const session_detail::AdvancedFlowFilterEndpointScope scope) {
    const auto* descriptor = descriptor_for_value(kEndpointScopeDescriptors, scope);
    return descriptor != nullptr ? std::string_view {descriptor->stable_id} : std::string_view {};
}

bool decode_port_scope_id(
    const std::string& scope_id,
    const std::string_view section_id,
    const std::string_view group,
    const std::size_t row_index,
    session_detail::AdvancedFlowFilterPortScope& out_scope,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    const auto* descriptor = descriptor_for_id(kPortScopeDescriptors, scope_id);
    if (descriptor == nullptr) {
        set_invalid_update_issue(
            result,
            section_id,
            group,
            scope_id,
            row_index,
            "scope_id",
            "Port rules must target Either endpoint, Endpoint A, or Endpoint B."
        );
        return false;
    }
    out_scope = descriptor->value;
    return true;
}

bool decode_endpoint_scope_id(
    const std::string& scope_id,
    const std::string_view section_id,
    const std::string_view group,
    const std::size_t row_index,
    session_detail::AdvancedFlowFilterEndpointScope& out_scope,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    const auto* descriptor = descriptor_for_id(kEndpointScopeDescriptors, scope_id);
    if (descriptor == nullptr) {
        set_invalid_update_issue(
            result,
            section_id,
            group,
            scope_id,
            row_index,
            "scope_id",
            "IP rules must target Either endpoint, Endpoint A, or Endpoint B."
        );
        return false;
    }
    out_scope = descriptor->value;
    return true;
}

bool parse_port_text(
    const std::string& text,
    const std::string_view section_id,
    const std::string_view group,
    const std::size_t row_index,
    const std::string_view field_id,
    std::uint16_t& value,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    const auto parsed = session_detail::parse_advanced_flow_filter_unsigned_integer_text(text);
    if (!parsed.ok || parsed.overflow || parsed.value > 65535U) {
        set_invalid_update_issue(
            result,
            section_id,
            group,
            {},
            row_index,
            field_id,
            "Port must be an integer between 0 and 65535."
        );
        return false;
    }
    value = static_cast<std::uint16_t>(parsed.value);
    return true;
}

bool decode_port_rows(
    const std::vector<FrontendAdvancedFlowFilterPortRowDto>& rows,
    const std::string_view group,
    std::vector<session_detail::AdvancedFlowFilterPortPredicate>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    out.clear();
    out.reserve(rows.size());
    constexpr std::string_view section_id {"ports"};

    for (std::size_t row_index = 0; row_index < rows.size(); ++row_index) {
        const auto& row = rows[row_index];
        session_detail::AdvancedFlowFilterPortScope scope {};
        if (!decode_port_scope_id(row.scope_id, section_id, group, row_index, scope, result)) {
            return false;
        }

        if (!row.range_enabled) {
            if (row.primary_text.empty()) {
                continue;
            }
            std::uint16_t port_value {0};
            if (!parse_port_text(
                    row.primary_text,
                    section_id,
                    group,
                    row_index,
                    "primary_text",
                    port_value,
                    result)) {
                return false;
            }
            out.push_back(session_detail::AdvancedFlowFilterPortPredicate {
                .scope = scope,
                .range = {.first = port_value, .last = port_value},
            });
            continue;
        }

        if (row.primary_text.empty() && row.secondary_text.empty()) {
            continue;
        }
        if (row.primary_text.empty() || row.secondary_text.empty()) {
            set_invalid_update_issue(
                result,
                section_id,
                group,
                {},
                row_index,
                row.primary_text.empty() ? "primary_text" : "secondary_text",
                "Range rules require both From and To values."
            );
            return false;
        }

        std::uint16_t first_value {0};
        std::uint16_t last_value {0};
        if (!parse_port_text(
                row.primary_text,
                section_id,
                group,
                row_index,
                "primary_text",
                first_value,
                result) ||
            !parse_port_text(
                row.secondary_text,
                section_id,
                group,
                row_index,
                "secondary_text",
                last_value,
                result)) {
            return false;
        }
        if (first_value > last_value) {
            set_invalid_update_issue(
                result,
                section_id,
                group,
                {},
                row_index,
                "secondary_text",
                "From must be less than or equal to To."
            );
            return false;
        }

        out.push_back(session_detail::AdvancedFlowFilterPortPredicate {
            .scope = scope,
            .range = {.first = first_value, .last = last_value},
        });
    }

    return true;
}

bool decode_ip_rows(
    const std::vector<FrontendAdvancedFlowFilterIpAddressRowDto>& rows,
    const std::string_view group,
    std::vector<session_detail::AdvancedFlowFilterIpv4AddressPredicate>& ipv4_out,
    std::vector<session_detail::AdvancedFlowFilterIpv6AddressPredicate>& ipv6_out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    ipv4_out.clear();
    ipv6_out.clear();
    ipv4_out.reserve(rows.size());
    ipv6_out.reserve(rows.size());
    constexpr std::string_view section_id {"ip_addresses"};

    for (std::size_t row_index = 0; row_index < rows.size(); ++row_index) {
        const auto& row = rows[row_index];
        session_detail::AdvancedFlowFilterEndpointScope scope {};
        if (!decode_endpoint_scope_id(row.scope_id, section_id, group, row_index, scope, result)) {
            return false;
        }

        std::string predicate_value {};
        if (!row.subnet_enabled) {
            if (row.address_text.empty()) {
                continue;
            }
            if (row.address_text.find('/') != std::string::npos) {
                set_invalid_update_issue(
                    result,
                    section_id,
                    group,
                    {},
                    row_index,
                    "address_text",
                    "Address must be a valid IPv4 or IPv6 value."
                );
                return false;
            }
            predicate_value = row.address_text;
        } else {
            if (row.address_text.empty() && row.prefix_text.empty()) {
                continue;
            }
            if (row.address_text.empty() || row.prefix_text.empty()) {
                set_invalid_update_issue(
                    result,
                    section_id,
                    group,
                    {},
                    row_index,
                    row.address_text.empty() ? "address_text" : "prefix_text",
                    "Subnet rules require both Address and Prefix."
                );
                return false;
            }
            predicate_value = row.address_text + "/" + row.prefix_text;
        }

        std::ostringstream text {};
        text << "format_version = 2\n"
             << "ip." << endpoint_scope_key_suffix(scope) << '.' << group << " = " << predicate_value << '\n';
        const auto parsed = session_detail::parse_advanced_flow_filter_text(text.str());
        if (parsed.status != session_detail::AdvancedFlowFilterTextParseStatus::ok) {
            const auto field_id = parsed.status == session_detail::AdvancedFlowFilterTextParseStatus::invalid_ip_address
                ? "address_text"
                : (row.subnet_enabled ? "prefix_text" : "address_text");
            set_invalid_update_issue(
                result,
                section_id,
                group,
                {},
                row_index,
                field_id,
                parsed.issue.has_value() && !parsed.issue->message.empty()
                    ? parsed.issue->message
                    : "Address rule is invalid."
            );
            return false;
        }

        if (!parsed.document.configured_spec.addresses.ipv4_include.empty()) {
            ipv4_out.push_back(parsed.document.configured_spec.addresses.ipv4_include.front());
            continue;
        }
        if (!parsed.document.configured_spec.addresses.ipv4_exclude.empty()) {
            ipv4_out.push_back(parsed.document.configured_spec.addresses.ipv4_exclude.front());
            continue;
        }
        if (!parsed.document.configured_spec.addresses.ipv6_include.empty()) {
            ipv6_out.push_back(parsed.document.configured_spec.addresses.ipv6_include.front());
            continue;
        }
        if (!parsed.document.configured_spec.addresses.ipv6_exclude.empty()) {
            ipv6_out.push_back(parsed.document.configured_spec.addresses.ipv6_exclude.front());
            continue;
        }

        set_invalid_update_issue(
            result,
            section_id,
            group,
            {},
            row_index,
            "address_text",
            "Address rule is invalid."
        );
        return false;
    }

    return true;
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
    auto draft = *parsed.document;

    if (section_id == "address_family") {
        draft.address_family.enabled = enabled;
        draft.address_family.include = include_ids;
        draft.address_family.exclude = exclude_ids;
    } else if (section_id == "flow_protocol") {
        draft.flow_protocol.enabled = enabled;
        draft.flow_protocol.include = include_ids;
        draft.flow_protocol.exclude = exclude_ids;
    } else if (section_id == "detected_protocol") {
        draft.detected_protocol.enabled = enabled;
        draft.detected_protocol.include = include_ids;
        draft.detected_protocol.exclude = exclude_ids;
    } else if (section_id == "tls_version") {
        draft.tls_version.enabled = enabled;
        draft.tls_version.include = include_ids;
        draft.tls_version.exclude = exclude_ids;
    } else if (section_id == "quic_version") {
        draft.quic_version.enabled = enabled;
        draft.quic_version.include = include_ids;
        draft.quic_version.exclude = exclude_ids;
    } else if (section_id == "directionality") {
        draft.directionality.enabled = enabled;
        draft.directionality.include = include_ids;
        draft.directionality.exclude = exclude_ids;
    } else {
        set_invalid_update_issue(
            parsed,
            section_id,
            {},
            {},
            std::nullopt,
            {},
            "The structured Advanced Filter update references an unknown finite section."
        );
        return parsed;
    }

    return apply_advanced_flow_filter_structured_document(filter_text, draft);
}

FrontendAdvancedFlowFilterStructuredDocumentResult
FrontendSessionAdapter::apply_advanced_flow_filter_structured_document(
    const std::string_view filter_text,
    const FrontendAdvancedFlowFilterStructuredDocumentDto& draft
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

    document.section_states.address_family = draft.address_family.enabled;
    if (!decode_finite_values(
            kAddressFamilyDescriptors,
            "address_family",
            "include",
            draft.address_family.include,
            spec.address_family.include,
            parsed) ||
        !decode_finite_values(
            kAddressFamilyDescriptors,
            "address_family",
            "exclude",
            draft.address_family.exclude,
            spec.address_family.exclude,
            parsed)) {
        return parsed;
    }

    document.section_states.flow_protocol = draft.flow_protocol.enabled;
    if (!decode_finite_values(
            kFlowProtocolDescriptors,
            "flow_protocol",
            "include",
            draft.flow_protocol.include,
            spec.flow_protocol.include,
            parsed) ||
        !decode_finite_values(
            kFlowProtocolDescriptors,
            "flow_protocol",
            "exclude",
            draft.flow_protocol.exclude,
            spec.flow_protocol.exclude,
            parsed)) {
        return parsed;
    }

    document.section_states.detected_protocol = draft.detected_protocol.enabled;
    if (!decode_finite_values(
            kDetectedProtocolDescriptors,
            "detected_protocol",
            "include",
            draft.detected_protocol.include,
            spec.detected_protocol.include,
            parsed) ||
        !decode_finite_values(
            kDetectedProtocolDescriptors,
            "detected_protocol",
            "exclude",
            draft.detected_protocol.exclude,
            spec.detected_protocol.exclude,
            parsed)) {
        return parsed;
    }

    document.section_states.tls_version = draft.tls_version.enabled;
    if (!decode_finite_values(
            kTlsVersionDescriptors,
            "tls_version",
            "include",
            draft.tls_version.include,
            spec.tls_version.include,
            parsed) ||
        !decode_finite_values(
            kTlsVersionDescriptors,
            "tls_version",
            "exclude",
            draft.tls_version.exclude,
            spec.tls_version.exclude,
            parsed)) {
        return parsed;
    }

    document.section_states.quic_version = draft.quic_version.enabled;
    if (!decode_finite_values(
            kQuicVersionDescriptors,
            "quic_version",
            "include",
            draft.quic_version.include,
            spec.quic_version.include,
            parsed) ||
        !decode_finite_values(
            kQuicVersionDescriptors,
            "quic_version",
            "exclude",
            draft.quic_version.exclude,
            spec.quic_version.exclude,
            parsed)) {
        return parsed;
    }

    document.section_states.directionality = draft.directionality.enabled;
    if (!decode_finite_values(
            kDirectionalityDescriptors,
            "directionality",
            "include",
            draft.directionality.include,
            spec.directionality.include,
            parsed) ||
        !decode_finite_values(
            kDirectionalityDescriptors,
            "directionality",
            "exclude",
            draft.directionality.exclude,
            spec.directionality.exclude,
            parsed)) {
        return parsed;
    }

    document.section_states.ports = draft.ports.enabled;
    if (draft.ports.enabled) {
        std::vector<session_detail::AdvancedFlowFilterPortPredicate> port_include {};
        std::vector<session_detail::AdvancedFlowFilterPortPredicate> port_exclude {};
        if (!decode_port_rows(draft.ports.include, "include", port_include, parsed) ||
            !decode_port_rows(draft.ports.exclude, "exclude", port_exclude, parsed)) {
            return parsed;
        }
        spec.ports.include = std::move(port_include);
        spec.ports.exclude = std::move(port_exclude);
    }

    document.section_states.ip_addresses = draft.ip_addresses.enabled;
    if (draft.ip_addresses.enabled) {
        std::vector<session_detail::AdvancedFlowFilterIpv4AddressPredicate> ipv4_include {};
        std::vector<session_detail::AdvancedFlowFilterIpv6AddressPredicate> ipv6_include {};
        std::vector<session_detail::AdvancedFlowFilterIpv4AddressPredicate> ipv4_exclude {};
        std::vector<session_detail::AdvancedFlowFilterIpv6AddressPredicate> ipv6_exclude {};
        if (!decode_ip_rows(draft.ip_addresses.include, "include", ipv4_include, ipv6_include, parsed) ||
            !decode_ip_rows(draft.ip_addresses.exclude, "exclude", ipv4_exclude, ipv6_exclude, parsed)) {
            return parsed;
        }
        spec.addresses.ipv4_include = std::move(ipv4_include);
        spec.addresses.ipv6_include = std::move(ipv6_include);
        spec.addresses.ipv4_exclude = std::move(ipv4_exclude);
        spec.addresses.ipv6_exclude = std::move(ipv6_exclude);
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
