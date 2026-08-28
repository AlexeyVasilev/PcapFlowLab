#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/ProtocolPathPresentation.h"
#include "app/session/SessionFormatting.h"

#include <algorithm>
#include <array>
#include <limits>
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

constexpr std::array<EnumDescriptor<ProtocolPathStatisticsMode>, 3> kProtocolPathSelectorModeDescriptors {{
    {ProtocolPathStatisticsMode::kind_overview, "kind", "Kind overview"},
    {ProtocolPathStatisticsMode::identity_tree, "identity", "Identity tree"},
    {ProtocolPathStatisticsMode::terminal_paths, "terminal", "Terminal paths"},
}};

enum class StructuredContainsLayerIdentifierMode : std::uint8_t {
    any = 0,
    exact,
};

constexpr std::array<EnumDescriptor<StructuredContainsLayerIdentifierMode>, 2>
    kContainsLayerIdentifierModeDescriptors {{
        {StructuredContainsLayerIdentifierMode::any, "any", "Any"},
        {StructuredContainsLayerIdentifierMode::exact, "exact", "Exact"},
    }};

enum class StructuredTrafficValueKind : std::uint8_t {
    count_u64 = 0,
    byte_u64,
    duration_us_u64,
    byte_u32,
};

struct StructuredTrafficMetricDescriptor {
    const char* stable_id {""};
    const char* key_root {""};
    StructuredTrafficValueKind kind {StructuredTrafficValueKind::count_u64};
    bool additional {false};
    const char* default_unit_id {""};
};

struct StructuredTimeRangeDescriptor {
    const char* stable_id {""};
    const char* key_root {""};
};

struct StructuredTrafficUnitDescriptor {
    const char* stable_id {""};
    std::uint64_t multiplier {1U};
};

constexpr std::array<StructuredTimeRangeDescriptor, 3> kTimeRangeDescriptors {{
    {"start", "start"},
    {"end", "end"},
    {"overlap", "overlap"},
}};

constexpr StructuredTrafficMetricDescriptor kTimeDurationMetricDescriptor {
    "duration", "duration", StructuredTrafficValueKind::duration_us_u64, false, "s"
};

constexpr std::array<StructuredTrafficMetricDescriptor, 10> kTrafficMetricDescriptors {{
    {"packets", "packet_count", StructuredTrafficValueKind::count_u64, false, "count"},
    {"original_bytes", "original_bytes", StructuredTrafficValueKind::byte_u64, false, "KiB"},
    {"captured_bytes", "captured_bytes", StructuredTrafficValueKind::byte_u64, false, "KiB"},
    {"max_original_packet_size", "max_original_packet_length", StructuredTrafficValueKind::byte_u32, true, "B"},
    {"max_captured_packet_size", "max_captured_packet_length", StructuredTrafficValueKind::byte_u32, true, "B"},
    {"fragmented_packet_count", "fragmented_packet_count", StructuredTrafficValueKind::count_u64, true, "count"},
    {"truncated_packet_count", "truncated_packet_count", StructuredTrafficValueKind::count_u64, true, "count"},
    {"tcp_syn_count", "tcp_syn_count", StructuredTrafficValueKind::count_u64, true, "count"},
    {"tcp_fin_count", "tcp_fin_count", StructuredTrafficValueKind::count_u64, true, "count"},
    {"tcp_rst_count", "tcp_rst_count", StructuredTrafficValueKind::count_u64, true, "count"},
}};

constexpr std::array<StructuredTrafficUnitDescriptor, 1> kTrafficCountUnits {{
    {"count", 1U},
}};

constexpr std::array<StructuredTrafficUnitDescriptor, 5> kTrafficByteUnits {{
    {"TiB", 1024ULL * 1024ULL * 1024ULL * 1024ULL},
    {"GiB", 1024ULL * 1024ULL * 1024ULL},
    {"MiB", 1024ULL * 1024ULL},
    {"KiB", 1024ULL},
    {"B", 1ULL},
}};

constexpr std::array<StructuredTrafficUnitDescriptor, 5> kTrafficDurationUnits {{
    {"h", 60ULL * 60ULL * 1000ULL * 1000ULL},
    {"min", 60ULL * 1000ULL * 1000ULL},
    {"s", 1000ULL * 1000ULL},
    {"ms", 1000ULL},
    {"us", 1ULL},
}};

constexpr std::array<EnumDescriptor<session_detail::AdvancedFlowFilterServicePredicateKind>, 3>
    kServiceOperatorDescriptors {{
        {session_detail::AdvancedFlowFilterServicePredicateKind::equals, "equals", "Equals"},
        {session_detail::AdvancedFlowFilterServicePredicateKind::starts_with, "starts_with", "Starts with"},
        {session_detail::AdvancedFlowFilterServicePredicateKind::contains, "contains", "Contains"},
    }};

std::string structured_status_error_text(const FrontendAdvancedFlowFilterStructuredDocumentResult& result);

std::string_view trim_ascii_copy(const std::string_view value) noexcept {
    std::size_t begin = 0U;
    while (begin < value.size() && static_cast<unsigned char>(value[begin]) <= 0x20U) {
        ++begin;
    }

    std::size_t end = value.size();
    while (end > begin && static_cast<unsigned char>(value[end - 1U]) <= 0x20U) {
        --end;
    }

    return value.substr(begin, end - begin);
}

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

const StructuredTrafficMetricDescriptor* traffic_metric_descriptor_for_id(const std::string_view stable_id) {
    const auto it = std::find_if(
        kTrafficMetricDescriptors.begin(),
        kTrafficMetricDescriptors.end(),
        [stable_id](const auto& descriptor) { return stable_id == descriptor.stable_id; }
    );
    return it == kTrafficMetricDescriptors.end() ? nullptr : &(*it);
}

const StructuredTimeRangeDescriptor* time_range_descriptor_for_id(const std::string_view stable_id) {
    const auto it = std::find_if(
        kTimeRangeDescriptors.begin(),
        kTimeRangeDescriptors.end(),
        [stable_id](const auto& descriptor) { return stable_id == descriptor.stable_id; }
    );
    return it == kTimeRangeDescriptors.end() ? nullptr : &(*it);
}

template <std::size_t Size>
const StructuredTrafficUnitDescriptor* traffic_unit_descriptor_for_id(
    const std::array<StructuredTrafficUnitDescriptor, Size>& descriptors,
    const std::string_view stable_id
) {
    const auto it = std::find_if(
        descriptors.begin(),
        descriptors.end(),
        [stable_id](const auto& descriptor) { return stable_id == descriptor.stable_id; }
    );
    return it == descriptors.end() ? nullptr : &(*it);
}

const StructuredTrafficUnitDescriptor* traffic_unit_descriptor_for_kind(
    const StructuredTrafficValueKind kind,
    const std::string_view stable_id
) {
    switch (kind) {
    case StructuredTrafficValueKind::count_u64:
        return traffic_unit_descriptor_for_id(kTrafficCountUnits, stable_id);
    case StructuredTrafficValueKind::byte_u64:
    case StructuredTrafficValueKind::byte_u32:
        return traffic_unit_descriptor_for_id(kTrafficByteUnits, stable_id);
    case StructuredTrafficValueKind::duration_us_u64:
        return traffic_unit_descriptor_for_id(kTrafficDurationUnits, stable_id);
    }
    return nullptr;
}

const EnumDescriptor<session_detail::AdvancedFlowFilterServicePredicateKind>* service_operator_descriptor_for_id(
    const std::string_view stable_id
) {
    return descriptor_for_id(kServiceOperatorDescriptors, stable_id);
}

const EnumDescriptor<session_detail::AdvancedFlowFilterServicePredicateKind>* service_operator_descriptor_for_kind(
    const session_detail::AdvancedFlowFilterServicePredicateKind kind
) {
    return descriptor_for_value(kServiceOperatorDescriptors, kind);
}

std::string_view contains_layer_kind_stable_id(const ProtocolLayerKind kind) noexcept {
    switch (kind) {
    case ProtocolLayerKind::vlan:
        return "vlan";
    case ProtocolLayerKind::mpls:
        return "mpls";
    case ProtocolLayerKind::pbb:
        return "pbb";
    case ProtocolLayerKind::vxlan:
        return "vxlan";
    case ProtocolLayerKind::geneve:
        return "geneve";
    case ProtocolLayerKind::gtpu:
        return "gtpu";
    case ProtocolLayerKind::gre:
        return "gre";
    case ProtocolLayerKind::ah:
        return "ah";
    case ProtocolLayerKind::esp:
        return "esp";
    default:
        return {};
    }
}

std::optional<ProtocolLayerKind> contains_layer_kind_from_stable_id(const std::string_view stable_id) {
    for (const auto& descriptor : session_detail::protocol_path_contains_layer_descriptors()) {
        if (stable_id == contains_layer_kind_stable_id(descriptor.kind)) {
            return descriptor.kind;
        }
    }
    return std::nullopt;
}

std::string_view input_format_stable_id(const session_detail::ProtocolPathIdentifierInputFormat format) noexcept {
    switch (format) {
    case session_detail::ProtocolPathIdentifierInputFormat::decimal:
        return "decimal";
    case session_detail::ProtocolPathIdentifierInputFormat::hexadecimal:
        return "hexadecimal";
    }
    return {};
}

ProtocolPath protocol_path_from_predicate_layers(
    const std::vector<session_detail::AdvancedFlowFilterProtocolLayerPredicate>& layers
) {
    std::vector<LayerKey> converted {};
    converted.reserve(layers.size());
    for (const auto& layer : layers) {
        converted.push_back(LayerKey {
            .kind = layer.kind,
            .identifier = layer.identifier.value_or(ProtocolLayerIdentifier {}),
        });
    }
    return ProtocolPath {std::move(converted)};
}

std::string protocol_path_predicate_text(const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate) {
    const auto path = protocol_path_from_predicate_layers(predicate.layers);
    return session_detail::build_protocol_path_presentation(&path).full_text;
}

std::string protocol_path_compact_text(const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate) {
    return session_detail::format_protocol_path_compact_display_text(protocol_path_from_predicate_layers(predicate.layers));
}

std::string contains_layer_exact_placeholder_text(const session_detail::ProtocolPathContainsLayerDescriptor& descriptor) {
    switch (descriptor.preferred_input_format) {
    case session_detail::ProtocolPathIdentifierInputFormat::decimal:
        return descriptor.max_value > 9999U ? "200" : "413";
    case session_detail::ProtocolPathIdentifierInputFormat::hexadecimal:
        return descriptor.max_value <= 0xFFFFFFU ? "0x123456" : "0x12345678";
    }
    return {};
}

std::string contains_layer_compact_text(
    const session_detail::ProtocolPathContainsLayerDescriptor& descriptor,
    const StructuredContainsLayerIdentifierMode mode,
    const std::string_view exact_value_text
) {
    if (mode == StructuredContainsLayerIdentifierMode::any) {
        return std::string(descriptor.layer_label) + " / Any";
    }

    const auto trimmed = trim_ascii_copy(exact_value_text);
    if (trimmed.empty()) {
        return std::string(descriptor.layer_label) + " / " + descriptor.identifier_label;
    }

    std::ostringstream out {};
    out << descriptor.layer_label << " / " << descriptor.identifier_label << ' ' << trimmed;
    return out.str();
}

bool protocol_path_predicate_is_ui_managed(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    return predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::exact_path ||
        predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::path_prefix;
}

bool contains_layer_predicate_is_ui_managed(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    return predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::contains_layer;
}

const EnumDescriptor<ProtocolPathStatisticsMode>* protocol_path_selector_mode_descriptor_for_predicate(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) {
    if (predicate.match_kind == session_detail::AdvancedFlowFilterProtocolPathMatchKind::exact_path) {
        return descriptor_for_value(kProtocolPathSelectorModeDescriptors, ProtocolPathStatisticsMode::terminal_paths);
    }

    const bool has_identifier = std::any_of(
        predicate.layers.begin(),
        predicate.layers.end(),
        [](const auto& layer) { return layer.identifier.has_value(); }
    );
    return descriptor_for_value(
        kProtocolPathSelectorModeDescriptors,
        has_identifier ? ProtocolPathStatisticsMode::identity_tree : ProtocolPathStatisticsMode::kind_overview
    );
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
    append_catalog(kProtocolPathSelectorModeDescriptors, catalog.protocol_path_selector_mode);
    append_catalog(kContainsLayerIdentifierModeDescriptors, catalog.contains_layer_identifier_mode);
    for (const auto& descriptor : session_detail::protocol_path_contains_layer_descriptors()) {
        catalog.contains_layer_kind.push_back(FrontendAdvancedFlowFilterContainsLayerOptionDto {
            .stable_id = std::string(contains_layer_kind_stable_id(descriptor.kind)),
            .label = descriptor.layer_label,
            .object_name_suffix = descriptor.object_name_suffix,
            .identifier_label = descriptor.identifier_label,
            .preferred_input_format_id = std::string(input_format_stable_id(descriptor.preferred_input_format)),
            .exact_value_placeholder = contains_layer_exact_placeholder_text(descriptor),
        });
    }
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
                .row_index = std::nullopt,
                .field_id = {},
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
                .row_index = std::nullopt,
                .field_id = {},
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
                .row_index = std::nullopt,
                .field_id = {},
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
                .row_index = std::nullopt,
                .field_id = {},
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

template <std::size_t Size>
const StructuredTrafficUnitDescriptor* choose_exact_traffic_unit(
    const std::array<StructuredTrafficUnitDescriptor, Size>& descriptors,
    const std::optional<std::uint64_t> min_value,
    const std::optional<std::uint64_t> max_value,
    const std::string_view default_unit_id
) {
    for (const auto& descriptor : descriptors) {
        const bool min_exact = !min_value.has_value() || (*min_value % descriptor.multiplier == 0U);
        const bool max_exact = !max_value.has_value() || (*max_value % descriptor.multiplier == 0U);
        if (min_exact && max_exact) {
            return &descriptor;
        }
    }

    return traffic_unit_descriptor_for_id(descriptors, default_unit_id);
}

const StructuredTrafficUnitDescriptor* choose_traffic_unit(
    const StructuredTrafficMetricDescriptor& descriptor,
    const std::optional<std::uint64_t> min_value,
    const std::optional<std::uint64_t> max_value
) {
    if (!min_value.has_value() && !max_value.has_value()) {
        switch (descriptor.kind) {
        case StructuredTrafficValueKind::count_u64:
            return traffic_unit_descriptor_for_id(kTrafficCountUnits, descriptor.default_unit_id);
        case StructuredTrafficValueKind::byte_u64:
        case StructuredTrafficValueKind::byte_u32:
            return traffic_unit_descriptor_for_id(kTrafficByteUnits, descriptor.default_unit_id);
        case StructuredTrafficValueKind::duration_us_u64:
            return traffic_unit_descriptor_for_id(kTrafficDurationUnits, descriptor.default_unit_id);
        }
        return nullptr;
    }

    switch (descriptor.kind) {
    case StructuredTrafficValueKind::count_u64:
        return traffic_unit_descriptor_for_id(kTrafficCountUnits, descriptor.default_unit_id);
    case StructuredTrafficValueKind::byte_u64:
    case StructuredTrafficValueKind::byte_u32:
        return choose_exact_traffic_unit(kTrafficByteUnits, min_value, max_value, descriptor.default_unit_id);
    case StructuredTrafficValueKind::duration_us_u64:
        return choose_exact_traffic_unit(kTrafficDurationUnits, min_value, max_value, descriptor.default_unit_id);
    }
    return nullptr;
}

template <typename T>
void append_encoded_traffic_row(
    const StructuredTrafficMetricDescriptor& descriptor,
    const std::optional<session_detail::AdvancedFlowFilterInclusiveRange<T>>& range,
    std::vector<FrontendAdvancedFlowFilterTrafficRowDto>& out
) {
    if (!range.has_value()) {
        out.push_back(FrontendAdvancedFlowFilterTrafficRowDto {
            .metric_id = descriptor.stable_id,
            .unit_id = descriptor.default_unit_id,
            .min_text = {},
            .max_text = {},
        });
        return;
    }

    const std::optional<std::uint64_t> min_value = range->min.has_value()
        ? std::optional<std::uint64_t> {static_cast<std::uint64_t>(*range->min)}
        : std::nullopt;
    const std::optional<std::uint64_t> max_value = range->max.has_value()
        ? std::optional<std::uint64_t> {static_cast<std::uint64_t>(*range->max)}
        : std::nullopt;
    const auto* unit_descriptor = choose_traffic_unit(descriptor, min_value, max_value);
    if (unit_descriptor == nullptr) {
        return;
    }

    out.push_back(FrontendAdvancedFlowFilterTrafficRowDto {
        .metric_id = descriptor.stable_id,
        .unit_id = unit_descriptor->stable_id,
        .min_text = min_value.has_value()
            ? std::to_string(*min_value / unit_descriptor->multiplier)
            : std::string {},
        .max_text = max_value.has_value()
            ? std::to_string(*max_value / unit_descriptor->multiplier)
            : std::string {},
    });
}

bool append_encoded_time_range_row(
    const StructuredTimeRangeDescriptor& descriptor,
    const std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t>>& range,
    std::vector<FrontendAdvancedFlowFilterTimeRowDto>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    FrontendAdvancedFlowFilterTimeRowDto row {
        .metric_id = descriptor.stable_id,
        .from_text = {},
        .to_text = {},
    };

    if (range.has_value()) {
        if (range->min.has_value()) {
            const auto formatted =
                session_detail::format_advanced_flow_filter_utc_timestamp_text(*range->min);
            if (!formatted.has_value()) {
                result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
                result.error_text = "The current Advanced Filter document contains a Time range that the structured editor cannot represent.";
                return false;
            }
            row.from_text = *formatted;
        }
        if (range->max.has_value()) {
            const auto formatted =
                session_detail::format_advanced_flow_filter_utc_timestamp_text(*range->max);
            if (!formatted.has_value()) {
                result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
                result.error_text = "The current Advanced Filter document contains a Time range that the structured editor cannot represent.";
                return false;
            }
            row.to_text = *formatted;
        }
    }

    out.push_back(std::move(row));
    return true;
}

bool encode_time_section(
    const session_detail::AdvancedFlowFilterTimeCriteria& time,
    FrontendAdvancedFlowFilterTimeSectionDto& section,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    section.ranges.clear();

    if (!append_encoded_time_range_row(kTimeRangeDescriptors[0], time.start_us, section.ranges, result) ||
        !append_encoded_time_range_row(kTimeRangeDescriptors[1], time.end_us, section.ranges, result) ||
        !append_encoded_time_range_row(kTimeRangeDescriptors[2], time.overlap_us, section.ranges, result)) {
        return false;
    }

    std::vector<FrontendAdvancedFlowFilterTrafficRowDto> duration_rows {};
    append_encoded_traffic_row(kTimeDurationMetricDescriptor, time.duration_us, duration_rows);
    section.duration = duration_rows.empty()
        ? FrontendAdvancedFlowFilterTrafficRowDto {
              .metric_id = kTimeDurationMetricDescriptor.stable_id,
              .unit_id = kTimeDurationMetricDescriptor.default_unit_id,
              .min_text = {},
              .max_text = {},
          }
        : duration_rows.front();
    return true;
}

void encode_traffic_section(
    const session_detail::AdvancedFlowFilterAggregateCriteria& aggregate,
    FrontendAdvancedFlowFilterTrafficSectionDto& traffic
) {
    traffic.primary.clear();
    traffic.additional.clear();

    const auto append_metric = [&](const StructuredTrafficMetricDescriptor& descriptor, const auto& range) {
        auto& target = descriptor.additional ? traffic.additional : traffic.primary;
        append_encoded_traffic_row(descriptor, range, target);
    };

    append_metric(kTrafficMetricDescriptors[0], aggregate.packet_count);
    append_metric(kTrafficMetricDescriptors[1], aggregate.original_bytes);
    append_metric(kTrafficMetricDescriptors[2], aggregate.captured_bytes);
    append_metric(kTrafficMetricDescriptors[3], aggregate.max_original_packet_length);
    append_metric(kTrafficMetricDescriptors[4], aggregate.max_captured_packet_length);
    append_metric(kTrafficMetricDescriptors[5], aggregate.fragmented_packet_count);
    append_metric(kTrafficMetricDescriptors[6], aggregate.truncated_packet_count);
    append_metric(kTrafficMetricDescriptors[7], aggregate.tcp_syn_count);
    append_metric(kTrafficMetricDescriptors[8], aggregate.tcp_fin_count);
    append_metric(kTrafficMetricDescriptors[9], aggregate.tcp_rst_count);
}

bool encode_service_text_rows(
    const std::vector<session_detail::AdvancedFlowFilterServicePredicate>& predicates,
    std::vector<FrontendAdvancedFlowFilterServiceTextRowDto>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    out.clear();
    for (const auto& predicate : predicates) {
        const auto* operator_descriptor = service_operator_descriptor_for_kind(predicate.kind);
        if (operator_descriptor == nullptr) {
            continue;
        }
        out.push_back(FrontendAdvancedFlowFilterServiceTextRowDto {
            .operator_id = operator_descriptor->stable_id,
            .case_sensitive = predicate.case_sensitivity == session_detail::AdvancedFlowFilterStringCaseSensitivity::case_sensitive,
            .text = predicate.value,
        });
    }

    const auto has_unrepresentable = std::any_of(
        predicates.begin(),
        predicates.end(),
        [](const auto& predicate) {
            return predicate.kind != session_detail::AdvancedFlowFilterServicePredicateKind::known &&
                predicate.kind != session_detail::AdvancedFlowFilterServicePredicateKind::unknown &&
                service_operator_descriptor_for_kind(predicate.kind) == nullptr;
        }
    );
    if (has_unrepresentable) {
        result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
        result.error_text = "The current Advanced Filter document contains a service predicate that the Tauri structured editor cannot represent.";
        return false;
    }

    return true;
}

bool encode_service_section(
    const session_detail::AdvancedFlowFilterServiceCriteria& service,
    FrontendAdvancedFlowFilterServiceSectionDto& section,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    section.include_recognized = false;
    section.include_unrecognized = false;
    section.exclude_recognized = false;
    section.exclude_unrecognized = false;

    std::vector<session_detail::AdvancedFlowFilterServicePredicate> include_text_predicates {};
    std::vector<session_detail::AdvancedFlowFilterServicePredicate> exclude_text_predicates {};

    for (const auto& predicate : service.include) {
        if (predicate.kind == session_detail::AdvancedFlowFilterServicePredicateKind::known) {
            section.include_recognized = true;
        } else if (predicate.kind == session_detail::AdvancedFlowFilterServicePredicateKind::unknown) {
            section.include_unrecognized = true;
        } else {
            include_text_predicates.push_back(predicate);
        }
    }

    for (const auto& predicate : service.exclude) {
        if (predicate.kind == session_detail::AdvancedFlowFilterServicePredicateKind::known) {
            section.exclude_recognized = true;
        } else if (predicate.kind == session_detail::AdvancedFlowFilterServicePredicateKind::unknown) {
            section.exclude_unrecognized = true;
        } else {
            exclude_text_predicates.push_back(predicate);
        }
    }

    return encode_service_text_rows(include_text_predicates, section.include_text, result) &&
        encode_service_text_rows(exclude_text_predicates, section.exclude_text, result);
}

std::optional<session_detail::AdvancedFlowFilterProtocolPathPredicate> parse_protocol_path_predicate_text(
    const std::string_view key,
    const std::string_view predicate_text
) {
    std::ostringstream text {};
    text << "format_version = 3\n" << key << " = " << predicate_text << '\n';
    const auto parsed = session_detail::parse_advanced_flow_filter_text(text.str());
    if (parsed.status != session_detail::AdvancedFlowFilterTextParseStatus::ok) {
        return std::nullopt;
    }

    const auto& include = parsed.document.configured_spec.protocol_path.include;
    if (!include.empty()) {
        return include.front();
    }
    const auto& exclude = parsed.document.configured_spec.protocol_path.exclude;
    if (!exclude.empty()) {
        return exclude.front();
    }
    return std::nullopt;
}

std::optional<bool> contains_layer_predicate_applicability(
    const FrontendSessionAdapter& adapter,
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) {
    return adapter.advanced_flow_filter_protocol_path_predicate_applicability(predicate);
}

bool encode_protocol_path_rows(
    const FrontendSessionAdapter& adapter,
    const std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate>& predicates,
    const std::string_view group,
    std::vector<FrontendAdvancedFlowFilterProtocolPathRowDto>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    static_cast<void>(group);
    out.clear();
    for (const auto& predicate : predicates) {
        if (!protocol_path_predicate_is_ui_managed(predicate)) {
            continue;
        }

        const auto* selector_mode = protocol_path_selector_mode_descriptor_for_predicate(predicate);
        if (selector_mode == nullptr) {
            result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
            result.error_text = "The current Advanced Filter document contains a Protocol Path predicate that the Tauri structured editor cannot represent.";
            return false;
        }

        FrontendAdvancedFlowFilterProtocolPathRowDto row {};
        if (!encode_advanced_flow_filter_protocol_path_row(adapter, predicate, row, result)) {
            return false;
        }
        out.push_back(std::move(row));
    }
    return true;
}

bool encode_contains_layer_rows(
    const FrontendSessionAdapter& adapter,
    const std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate>& predicates,
    const std::string_view group,
    std::vector<FrontendAdvancedFlowFilterContainsLayerRowDto>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    static_cast<void>(group);
    out.clear();
    for (const auto& predicate : predicates) {
        if (!contains_layer_predicate_is_ui_managed(predicate) || predicate.layers.size() != 1U) {
            continue;
        }

        const auto& layer = predicate.layers.front();
        const auto* descriptor = session_detail::protocol_path_contains_layer_descriptor(layer.kind);
        if (descriptor == nullptr) {
            result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
            result.error_text = "The current Advanced Filter document contains a Contains Layer rule that the Tauri structured editor cannot represent.";
            return false;
        }

        const auto identifier_mode = layer.identifier.has_value()
            ? StructuredContainsLayerIdentifierMode::exact
            : StructuredContainsLayerIdentifierMode::any;
        const auto applicability = contains_layer_predicate_applicability(adapter, predicate);
        out.push_back(FrontendAdvancedFlowFilterContainsLayerRowDto {
            .layer_stable_id = std::string(contains_layer_kind_stable_id(descriptor->kind)),
            .identifier_mode_id = descriptor_for_value(kContainsLayerIdentifierModeDescriptors, identifier_mode)->stable_id,
            .exact_value_text = layer.identifier.has_value()
                ? session_detail::format_protocol_path_identifier_editor_text(layer.identifier->kind, layer.identifier->value)
                : std::string {},
            .compact_text = contains_layer_compact_text(
                *descriptor,
                identifier_mode,
                layer.identifier.has_value()
                    ? session_detail::format_protocol_path_identifier_editor_text(
                          layer.identifier->kind,
                          layer.identifier->value)
                    : std::string_view {}
            ),
            .applicability_known = applicability.has_value(),
            .applicable = applicability.value_or(false),
            .status_text = !applicability.has_value()
                ? "No current capture."
                : (applicability.value() ? std::string {} : "Not present in current capture"),
        });
    }
    return true;
}

bool has_unsupported_configured_sections(const session_detail::AdvancedFlowFilterDocument& document) {
    static_cast<void>(document);
    return false;
}

std::optional<FrontendAdvancedFlowFilterStructuredDocumentDto> build_structured_document(
    const FrontendSessionAdapter& adapter,
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
    structured.time.enabled = document.section_states.time;
    structured.traffic.enabled = document.section_states.traffic;
    structured.service.enabled = document.section_states.service;
    structured.protocol_path.enabled = document.section_states.protocol_path;
    structured.contains_layer.enabled = document.section_states.contains_layer;
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

    if (!encode_time_section(document.configured_spec.time, structured.time, result)) {
        return std::nullopt;
    }
    encode_traffic_section(document.configured_spec.aggregate, structured.traffic);
    if (!encode_service_section(document.configured_spec.service, structured.service, result)) {
        return std::nullopt;
    }
    if (!encode_protocol_path_rows(
            adapter,
            document.configured_spec.protocol_path.include,
            "include",
            structured.protocol_path.include,
            result) ||
        !encode_protocol_path_rows(
            adapter,
            document.configured_spec.protocol_path.exclude,
            "exclude",
            structured.protocol_path.exclude,
            result) ||
        !encode_contains_layer_rows(
            adapter,
            document.configured_spec.protocol_path.include,
            "include",
            structured.contains_layer.include,
            result) ||
        !encode_contains_layer_rows(
            adapter,
            document.configured_spec.protocol_path.exclude,
            "exclude",
            structured.contains_layer.exclude,
            result)) {
        return std::nullopt;
    }

    return structured;
}

bool parse_traffic_bound_text(
    const StructuredTrafficMetricDescriptor& descriptor,
    const std::string_view text,
    const std::string_view section_id,
    const std::size_t row_index,
    const std::string_view field_id,
    const std::string_view unit_id,
    std::uint64_t& out_value,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    const auto parsed = session_detail::parse_advanced_flow_filter_unsigned_integer_text(text);
    if (!parsed.ok || parsed.overflow) {
        set_invalid_update_issue(
            result,
            section_id,
            "traffic",
            descriptor.stable_id,
            row_index,
            field_id,
            "Traffic bounds must be non-negative integers."
        );
        return false;
    }

    const auto* unit_descriptor = traffic_unit_descriptor_for_kind(descriptor.kind, unit_id);
    if (unit_descriptor == nullptr) {
        set_invalid_update_issue(
            result,
            section_id,
            "traffic",
            descriptor.stable_id,
            row_index,
            "unit_id",
            "Traffic row contains an unknown unit."
        );
        return false;
    }

    if (parsed.value > 0U && parsed.value > (std::numeric_limits<std::uint64_t>::max() / unit_descriptor->multiplier)) {
        set_invalid_update_issue(
            result,
            section_id,
            "traffic",
            descriptor.stable_id,
            row_index,
            field_id,
            "Traffic bound is too large."
        );
        return false;
    }

    out_value = parsed.value * unit_descriptor->multiplier;
    return true;
}

template <typename T>
bool decode_traffic_row_into_range(
    const FrontendAdvancedFlowFilterTrafficRowDto& row,
    const StructuredTrafficMetricDescriptor& descriptor,
    const std::size_t row_index,
    std::optional<session_detail::AdvancedFlowFilterInclusiveRange<T>>& target,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    if (row.min_text.empty() && row.max_text.empty()) {
        target.reset();
        return true;
    }

    session_detail::AdvancedFlowFilterInclusiveRange<T> range {};
    std::uint64_t min_value_u64 {0U};
    std::uint64_t max_value_u64 {0U};

    if (!row.min_text.empty() &&
        !parse_traffic_bound_text(
            descriptor,
            row.min_text,
            "traffic",
            row_index,
            "min_text",
            row.unit_id,
            min_value_u64,
            result)) {
        return false;
    }
    if (!row.max_text.empty() &&
        !parse_traffic_bound_text(
            descriptor,
            row.max_text,
            "traffic",
            row_index,
            "max_text",
            row.unit_id,
            max_value_u64,
            result)) {
        return false;
    }

    if (!row.min_text.empty() && !row.max_text.empty() && min_value_u64 > max_value_u64) {
        set_invalid_update_issue(
            result,
            "traffic",
            "traffic",
            descriptor.stable_id,
            row_index,
            "max_text",
            "Traffic Min must be less than or equal to Max."
        );
        return false;
    }

    if constexpr (sizeof(T) < sizeof(std::uint64_t)) {
        if ((!row.min_text.empty() && min_value_u64 > static_cast<std::uint64_t>(std::numeric_limits<T>::max())) ||
            (!row.max_text.empty() && max_value_u64 > static_cast<std::uint64_t>(std::numeric_limits<T>::max()))) {
            set_invalid_update_issue(
                result,
                "traffic",
                "traffic",
                descriptor.stable_id,
                row_index,
                !row.max_text.empty() ? "max_text" : "min_text",
                "Traffic bound exceeds the supported range for this metric."
            );
            return false;
        }
    }

    if (!row.min_text.empty()) {
        range.min = static_cast<T>(min_value_u64);
    }
    if (!row.max_text.empty()) {
        range.max = static_cast<T>(max_value_u64);
    }
    target = range;
    return true;
}

bool decode_time_section(
    const FrontendAdvancedFlowFilterTimeSectionDto& section,
    session_detail::AdvancedFlowFilterTimeCriteria& time,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    time = session_detail::AdvancedFlowFilterTimeCriteria {};

    for (std::size_t row_index = 0; row_index < section.ranges.size(); ++row_index) {
        const auto& row = section.ranges[row_index];
        const auto* descriptor = time_range_descriptor_for_id(row.metric_id);
        if (descriptor == nullptr) {
            set_invalid_update_issue(
                result,
                "time",
                "ranges",
                row.metric_id,
                row_index,
                "metric_id",
                "Time row contains an unknown metric."
            );
            return false;
        }

        std::optional<session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t>>* target = nullptr;
        if (row.metric_id == "start") {
            target = &time.start_us;
        } else if (row.metric_id == "end") {
            target = &time.end_us;
        } else if (row.metric_id == "overlap") {
            target = &time.overlap_us;
        }
        if (target == nullptr) {
            set_invalid_update_issue(
                result,
                "time",
                "ranges",
                row.metric_id,
                row_index,
                "metric_id",
                "Time row contains an unsupported metric."
            );
            return false;
        }

        if (row.from_text.empty() && row.to_text.empty()) {
            target->reset();
            continue;
        }

        session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t> range {};
        auto parse_bound = [&](const std::string& text,
                               const char* field_id,
                               std::optional<std::uint64_t>& out_value) -> bool {
            if (text.empty()) {
                return true;
            }

            const auto parsed = session_detail::parse_advanced_flow_filter_utc_timestamp_text(text);
            if (!parsed.ok) {
                set_invalid_update_issue(
                    result,
                    "time",
                    descriptor->stable_id,
                    row.metric_id,
                    row_index,
                    field_id,
                    parsed.overflow
                        ? "UTC timestamp is too large."
                        : "Expected a UTC timestamp in the form YYYY-MM-DDTHH:MM:SS(.ffffff)Z."
                );
                return false;
            }

            out_value = parsed.value_us;
            return true;
        };

        if (!parse_bound(row.from_text, "from_text", range.min) ||
            !parse_bound(row.to_text, "to_text", range.max)) {
            return false;
        }
        *target = range;
    }

    if (section.duration.metric_id != kTimeDurationMetricDescriptor.stable_id) {
        set_invalid_update_issue(
            result,
            "time",
            "duration",
            section.duration.metric_id,
            0U,
            "metric_id",
            "Time duration row contains an unknown metric."
        );
        return false;
    }

    if (section.duration.min_text.empty() && section.duration.max_text.empty()) {
        time.duration_us.reset();
        return true;
    }

    if (!decode_traffic_row_into_range(
            section.duration,
            kTimeDurationMetricDescriptor,
            0U,
            time.duration_us,
            result)) {
        return false;
    }

    return true;
}

bool decode_traffic_section(
    const FrontendAdvancedFlowFilterTrafficSectionDto& traffic,
    session_detail::AdvancedFlowFilterAggregateCriteria& aggregate,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    aggregate = session_detail::AdvancedFlowFilterAggregateCriteria {};

    auto decode_row = [&](const FrontendAdvancedFlowFilterTrafficRowDto& row, const std::size_t row_index) -> bool {
        const auto* descriptor = traffic_metric_descriptor_for_id(row.metric_id);
        if (descriptor == nullptr) {
            set_invalid_update_issue(
                result,
                "traffic",
                "traffic",
                row.metric_id,
                row_index,
                "metric_id",
                "Traffic row contains an unknown metric."
            );
            return false;
        }

        switch (descriptor->kind) {
        case StructuredTrafficValueKind::count_u64:
            if (row.metric_id == "packets") {
                return decode_traffic_row_into_range(row, *descriptor, row_index, aggregate.packet_count, result);
            }
            if (row.metric_id == "fragmented_packet_count") {
                return decode_traffic_row_into_range(row, *descriptor, row_index, aggregate.fragmented_packet_count, result);
            }
            if (row.metric_id == "truncated_packet_count") {
                return decode_traffic_row_into_range(row, *descriptor, row_index, aggregate.truncated_packet_count, result);
            }
            if (row.metric_id == "tcp_syn_count") {
                return decode_traffic_row_into_range(row, *descriptor, row_index, aggregate.tcp_syn_count, result);
            }
            if (row.metric_id == "tcp_fin_count") {
                return decode_traffic_row_into_range(row, *descriptor, row_index, aggregate.tcp_fin_count, result);
            }
            if (row.metric_id == "tcp_rst_count") {
                return decode_traffic_row_into_range(row, *descriptor, row_index, aggregate.tcp_rst_count, result);
            }
            break;
        case StructuredTrafficValueKind::byte_u64:
            if (row.metric_id == "original_bytes") {
                return decode_traffic_row_into_range(row, *descriptor, row_index, aggregate.original_bytes, result);
            }
            if (row.metric_id == "captured_bytes") {
                return decode_traffic_row_into_range(row, *descriptor, row_index, aggregate.captured_bytes, result);
            }
            break;
        case StructuredTrafficValueKind::byte_u32:
            if (row.metric_id == "max_original_packet_size") {
                return decode_traffic_row_into_range(row, *descriptor, row_index, aggregate.max_original_packet_length, result);
            }
            if (row.metric_id == "max_captured_packet_size") {
                return decode_traffic_row_into_range(row, *descriptor, row_index, aggregate.max_captured_packet_length, result);
            }
            break;
        case StructuredTrafficValueKind::duration_us_u64:
            break;
        }

        set_invalid_update_issue(
            result,
            "traffic",
            "traffic",
            row.metric_id,
            row_index,
            "metric_id",
            "Traffic row contains an unsupported metric."
        );
        return false;
    };

    std::size_t row_index = 0U;
    for (const auto& row : traffic.primary) {
        if (!decode_row(row, row_index++)) {
            return false;
        }
    }
    for (const auto& row : traffic.additional) {
        if (!decode_row(row, row_index++)) {
            return false;
        }
    }

    return true;
}

bool decode_service_text_rows(
    const std::vector<FrontendAdvancedFlowFilterServiceTextRowDto>& rows,
    const std::string_view group,
    std::vector<session_detail::AdvancedFlowFilterServicePredicate>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    for (std::size_t row_index = 0; row_index < rows.size(); ++row_index) {
        const auto& row = rows[row_index];
        if (row.text.empty()) {
            continue;
        }

        const auto* operator_descriptor = service_operator_descriptor_for_id(row.operator_id);
        if (operator_descriptor == nullptr) {
            set_invalid_update_issue(
                result,
                "service",
                group,
                row.operator_id,
                row_index,
                "operator_id",
                "Service row contains an unknown operator."
            );
            return false;
        }

        out.push_back(session_detail::AdvancedFlowFilterServicePredicate {
            .kind = operator_descriptor->value,
            .value = row.text,
            .case_sensitivity = row.case_sensitive
                ? session_detail::AdvancedFlowFilterStringCaseSensitivity::case_sensitive
                : session_detail::AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
        });
    }

    return true;
}

bool decode_service_section(
    const FrontendAdvancedFlowFilterServiceSectionDto& service,
    session_detail::AdvancedFlowFilterServiceCriteria& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    out = session_detail::AdvancedFlowFilterServiceCriteria {};

    if (service.include_recognized) {
        out.include.push_back(session_detail::AdvancedFlowFilterServicePredicate {
            .kind = session_detail::AdvancedFlowFilterServicePredicateKind::known,
        });
    }
    if (service.include_unrecognized) {
        out.include.push_back(session_detail::AdvancedFlowFilterServicePredicate {
            .kind = session_detail::AdvancedFlowFilterServicePredicateKind::unknown,
        });
    }
    if (!decode_service_text_rows(service.include_text, "include", out.include, result)) {
        return false;
    }

    if (service.exclude_recognized) {
        out.exclude.push_back(session_detail::AdvancedFlowFilterServicePredicate {
            .kind = session_detail::AdvancedFlowFilterServicePredicateKind::known,
        });
    }
    if (service.exclude_unrecognized) {
        out.exclude.push_back(session_detail::AdvancedFlowFilterServicePredicate {
            .kind = session_detail::AdvancedFlowFilterServicePredicateKind::unknown,
        });
    }
    if (!decode_service_text_rows(service.exclude_text, "exclude", out.exclude, result)) {
        return false;
    }

    return true;
}

bool decode_protocol_path_rows(
    const std::vector<FrontendAdvancedFlowFilterProtocolPathRowDto>& rows,
    const std::string_view group,
    std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    out.clear();
    out.reserve(rows.size());

    for (std::size_t row_index = 0; row_index < rows.size(); ++row_index) {
        const auto& row = rows[row_index];
        if (row.predicate_text.empty()) {
            set_invalid_update_issue(
                result,
                "protocol_path",
                group,
                {},
                row_index,
                "predicate_text",
                "Protocol Path rows require a selected path."
            );
            return false;
        }

        const auto* mode_descriptor = descriptor_for_id(kProtocolPathSelectorModeDescriptors, row.selector_mode_id);
        if (mode_descriptor == nullptr) {
            set_invalid_update_issue(
                result,
                "protocol_path",
                group,
                row.selector_mode_id,
                row_index,
                "selector_mode_id",
                "Protocol Path row contains an unknown selector mode."
            );
            return false;
        }

        const auto key = mode_descriptor->value == ProtocolPathStatisticsMode::terminal_paths
            ? std::string("protocol_path.exact.") + std::string(group)
            : std::string("protocol_path.prefix.") + std::string(group);
        auto predicate = parse_protocol_path_predicate_text(key, row.predicate_text);
        if (!predicate.has_value()) {
            set_invalid_update_issue(
                result,
                "protocol_path",
                group,
                {},
                row_index,
                "predicate_text",
                "Protocol Path row is invalid."
            );
            return false;
        }

        if (mode_descriptor->value == ProtocolPathStatisticsMode::kind_overview) {
            for (auto& layer : predicate->layers) {
                layer.identifier.reset();
            }
        }

        out.push_back(*predicate);
    }

    return true;
}

bool decode_contains_layer_rows(
    const std::vector<FrontendAdvancedFlowFilterContainsLayerRowDto>& rows,
    const std::string_view group,
    std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate>& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    out.clear();
    out.reserve(rows.size());

    for (std::size_t row_index = 0; row_index < rows.size(); ++row_index) {
        const auto& row = rows[row_index];
        const auto kind = contains_layer_kind_from_stable_id(row.layer_stable_id);
        if (!kind.has_value()) {
            set_invalid_update_issue(
                result,
                "contains_layer",
                group,
                row.layer_stable_id,
                row_index,
                "layer",
                "Contains Layer row contains an unknown layer kind."
            );
            return false;
        }

        const auto* descriptor = session_detail::protocol_path_contains_layer_descriptor(*kind);
        if (descriptor == nullptr) {
            set_invalid_update_issue(
                result,
                "contains_layer",
                group,
                row.layer_stable_id,
                row_index,
                "layer",
                "Contains Layer row contains an unsupported layer kind."
            );
            return false;
        }

        const auto* mode_descriptor = descriptor_for_id(kContainsLayerIdentifierModeDescriptors, row.identifier_mode_id);
        if (mode_descriptor == nullptr) {
            set_invalid_update_issue(
                result,
                "contains_layer",
                group,
                row.identifier_mode_id,
                row_index,
                "mode",
                "Contains Layer row contains an unknown identifier mode."
            );
            return false;
        }

        session_detail::AdvancedFlowFilterProtocolLayerPredicate layer {
            .kind = *kind,
        };

        if (mode_descriptor->value == StructuredContainsLayerIdentifierMode::exact) {
            const auto trimmed = trim_ascii_copy(row.exact_value_text);
            if (trimmed.empty()) {
                set_invalid_update_issue(
                    result,
                    "contains_layer",
                    group,
                    row.layer_stable_id,
                    row_index,
                    "value",
                    std::string(descriptor->layer_label) + ' ' + descriptor->identifier_label + " value is required."
                );
                return false;
            }

            const auto parsed = session_detail::parse_advanced_flow_filter_unsigned_integer_text(trimmed);
            if (!parsed.ok || parsed.overflow) {
                set_invalid_update_issue(
                    result,
                    "contains_layer",
                    group,
                    row.layer_stable_id,
                    row_index,
                    "value",
                    "Contains Layer exact identifiers must be valid non-negative integers."
                );
                return false;
            }
            if (parsed.value > descriptor->max_value) {
                set_invalid_update_issue(
                    result,
                    "contains_layer",
                    group,
                    row.layer_stable_id,
                    row_index,
                    "value",
                    std::string(descriptor->layer_label) + ' ' + descriptor->identifier_label + " is out of range."
                );
                return false;
            }

            layer.identifier = ProtocolLayerIdentifier {
                .kind = descriptor->identifier_kind,
                .value = parsed.value,
            };
        }

        out.push_back(session_detail::AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = session_detail::AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {std::move(layer)},
        });
    }

    return true;
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
        text << "format_version = 3\n"
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
    const FrontendSessionAdapter& adapter,
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

    result.document = build_structured_document(adapter, parse_result.document, format_result.text, result);
    if (!result.document.has_value()) {
        if (result.error_text.empty()) {
            result.error_text = structured_status_error_text(result);
        }
        return result;
    }

    result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::ok;
    return result;
}

std::string advanced_flow_filter_display_name(
    const session_detail::AdvancedFlowFilterDocumentState& state
) {
    const auto* source_path = state.source_path();
    if (source_path == nullptr) {
        return "Custom filter";
    }

    std::string display_name {};
    if (source_path->has_stem()) {
        display_name = source_path->stem().string();
    }
    if (display_name.empty()) {
        display_name = source_path->filename().string();
    }
    if (display_name.empty()) {
        display_name = source_path->string();
    }
    if (state.has_unsaved_changes()) {
        display_name += " *";
    }
    return display_name;
}

FrontendAdvancedFlowFilterDocumentWorkflowStateDto build_document_workflow_state(
    const session_detail::AdvancedFlowFilterDocumentState& state
) {
    FrontendAdvancedFlowFilterDocumentWorkflowStateDto dto {};
    dto.is_file_backed = state.is_file_backed();
    dto.has_unsaved_changes = state.has_unsaved_changes();
    dto.has_unsaved_configuration = state.has_unsaved_configuration();
    dto.can_clear_unsaved_changes = state.can_clear_unsaved_changes();
    dto.clear_available = !session_detail::is_default_advanced_flow_filter_document(
        state.current_user_visible_document()
    );
    dto.configured_rule_count = state.configured_rule_count();
    dto.active_rule_count = state.active_rule_count();
    dto.display_name = advanced_flow_filter_display_name(state);
    if (const auto* source_path = state.source_path(); source_path != nullptr) {
        dto.source_path = source_path->string();
    }

    const auto format_result =
        session_detail::format_advanced_flow_filter_text(state.current_user_visible_document());
    if (format_result.status == session_detail::AdvancedFlowFilterTextFormatStatus::ok) {
        dto.canonical_text = format_result.text;
    }
    return dto;
}

std::optional<session_detail::AdvancedFlowFilterDocument> parse_valid_document_text(
    const std::string_view filter_text
) {
    const auto parse_result = session_detail::parse_advanced_flow_filter_text(filter_text);
    if (parse_result.status != session_detail::AdvancedFlowFilterTextParseStatus::ok) {
        return std::nullopt;
    }
    return parse_result.document;
}

}  // namespace

FrontendAdvancedFlowFilterStructuredDocumentResult
FrontendSessionAdapter::parse_advanced_flow_filter_structured_document(const std::string_view filter_text) const {
    return parse_document_text(*this, filter_text);
}

FrontendAdvancedFlowFilterStructuredDocumentResult
FrontendSessionAdapter::update_advanced_flow_filter_structured_section(
    const std::string_view filter_text,
    const std::string_view section_id,
    const bool enabled,
    const std::vector<std::string>& include_ids,
    const std::vector<std::string>& exclude_ids
) const {
    auto parsed = parse_document_text(*this, filter_text);
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
    auto parsed = parse_document_text(*this, filter_text);
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

    document.section_states.time = draft.time.enabled;
    if (draft.time.enabled) {
        session_detail::AdvancedFlowFilterTimeCriteria time {};
        if (!decode_time_section(draft.time, time, parsed)) {
            return parsed;
        }
        spec.time = std::move(time);
    }

    document.section_states.traffic = draft.traffic.enabled;
    if (draft.traffic.enabled) {
        session_detail::AdvancedFlowFilterAggregateCriteria aggregate {};
        if (!decode_traffic_section(draft.traffic, aggregate, parsed)) {
            return parsed;
        }
        spec.aggregate = std::move(aggregate);
    }

    document.section_states.service = draft.service.enabled;
    if (draft.service.enabled) {
        session_detail::AdvancedFlowFilterServiceCriteria service {};
        if (!decode_service_section(draft.service, service, parsed)) {
            return parsed;
        }
        spec.service = std::move(service);
    }

    document.section_states.protocol_path = draft.protocol_path.enabled;
    document.section_states.contains_layer = draft.contains_layer.enabled;
    {
        std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> preserved_include {};
        std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> preserved_exclude {};
        std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> existing_protocol_include {};
        std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> existing_protocol_exclude {};
        std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> existing_contains_include {};
        std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> existing_contains_exclude {};

        const auto split_predicates = [](
                                          const auto& source,
                                          auto& preserved,
                                          auto& protocol_rows,
                                          auto& contains_rows) {
            for (const auto& predicate : source) {
                if (protocol_path_predicate_is_ui_managed(predicate)) {
                    protocol_rows.push_back(predicate);
                } else if (contains_layer_predicate_is_ui_managed(predicate)) {
                    contains_rows.push_back(predicate);
                } else {
                    preserved.push_back(predicate);
                }
            }
        };

        split_predicates(spec.protocol_path.include, preserved_include, existing_protocol_include, existing_contains_include);
        split_predicates(spec.protocol_path.exclude, preserved_exclude, existing_protocol_exclude, existing_contains_exclude);

        std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> updated_protocol_include = std::move(preserved_include);
        std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> updated_protocol_exclude = std::move(preserved_exclude);

        if (draft.protocol_path.enabled) {
            std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> decoded_include {};
            std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> decoded_exclude {};
            if (!decode_protocol_path_rows(draft.protocol_path.include, "include", decoded_include, parsed) ||
                !decode_protocol_path_rows(draft.protocol_path.exclude, "exclude", decoded_exclude, parsed)) {
                return parsed;
            }
            updated_protocol_include.insert(
                updated_protocol_include.end(),
                decoded_include.begin(),
                decoded_include.end()
            );
            updated_protocol_exclude.insert(
                updated_protocol_exclude.end(),
                decoded_exclude.begin(),
                decoded_exclude.end()
            );
        } else {
            updated_protocol_include.insert(
                updated_protocol_include.end(),
                existing_protocol_include.begin(),
                existing_protocol_include.end()
            );
            updated_protocol_exclude.insert(
                updated_protocol_exclude.end(),
                existing_protocol_exclude.begin(),
                existing_protocol_exclude.end()
            );
        }

        if (draft.contains_layer.enabled) {
            std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> decoded_include {};
            std::vector<session_detail::AdvancedFlowFilterProtocolPathPredicate> decoded_exclude {};
            if (!decode_contains_layer_rows(draft.contains_layer.include, "include", decoded_include, parsed) ||
                !decode_contains_layer_rows(draft.contains_layer.exclude, "exclude", decoded_exclude, parsed)) {
                return parsed;
            }
            updated_protocol_include.insert(
                updated_protocol_include.end(),
                decoded_include.begin(),
                decoded_include.end()
            );
            updated_protocol_exclude.insert(
                updated_protocol_exclude.end(),
                decoded_exclude.begin(),
                decoded_exclude.end()
            );
        } else {
            updated_protocol_include.insert(
                updated_protocol_include.end(),
                existing_contains_include.begin(),
                existing_contains_include.end()
            );
            updated_protocol_exclude.insert(
                updated_protocol_exclude.end(),
                existing_contains_exclude.begin(),
                existing_contains_exclude.end()
            );
        }

        spec.protocol_path.include = std::move(updated_protocol_include);
        spec.protocol_path.exclude = std::move(updated_protocol_exclude);
    }

    const auto format_result = session_detail::format_advanced_flow_filter_text(document);
    if (format_result.status != session_detail::AdvancedFlowFilterTextFormatStatus::ok) {
        parsed.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
        parsed.error_text = format_result.issue.has_value()
            ? format_result.issue->message
            : structured_status_error_text(parsed);
        return parsed;
    }

    return parse_document_text(*this, format_result.text);
}

FrontendAdvancedFlowFilterDocumentWorkflowStateDto
FrontendSessionAdapter::get_advanced_flow_filter_document_workflow_state() const {
    return build_document_workflow_state(advanced_flow_filter_document_state_);
}

FrontendAdvancedFlowFilterDocumentWorkflowStateDto
FrontendSessionAdapter::apply_advanced_flow_filter_document_text(const std::string_view filter_text) {
    const auto document = parse_valid_document_text(filter_text);
    if (!document.has_value()) {
        return build_document_workflow_state(advanced_flow_filter_document_state_);
    }

    advanced_flow_filter_document_state_.begin_edit();
    if (auto* draft_document = advanced_flow_filter_document_state_.draft_document(); draft_document != nullptr) {
        *draft_document = *document;
        const bool applied = advanced_flow_filter_document_state_.apply_draft();
        static_cast<void>(applied);
    }
    return build_document_workflow_state(advanced_flow_filter_document_state_);
}

FrontendAdvancedFlowFilterDocumentWorkflowStateDto
FrontendSessionAdapter::accept_opened_advanced_flow_filter_document_text(
    const std::string_view filter_text,
    const std::filesystem::path& source_path
) {
    const auto document = parse_valid_document_text(filter_text);
    if (!document.has_value()) {
        return build_document_workflow_state(advanced_flow_filter_document_state_);
    }

    advanced_flow_filter_document_state_.accept_opened_document(*document, source_path);
    return build_document_workflow_state(advanced_flow_filter_document_state_);
}

FrontendAdvancedFlowFilterDocumentWorkflowStateDto
FrontendSessionAdapter::accept_saved_advanced_flow_filter_document_text(
    const std::string_view filter_text,
    const std::filesystem::path& source_path
) {
    const auto document = parse_valid_document_text(filter_text);
    if (!document.has_value()) {
        return build_document_workflow_state(advanced_flow_filter_document_state_);
    }

    advanced_flow_filter_document_state_.accept_saved_document(*document, source_path);
    return build_document_workflow_state(advanced_flow_filter_document_state_);
}

FrontendAdvancedFlowFilterDocumentWorkflowStateDto
FrontendSessionAdapter::clear_advanced_flow_filter_unsaved_changes() {
    const bool reverted = advanced_flow_filter_document_state_.revert_to_saved_baseline();
    static_cast<void>(reverted);
    return build_document_workflow_state(advanced_flow_filter_document_state_);
}

FrontendAdvancedFlowFilterDocumentWorkflowStateDto
FrontendSessionAdapter::clear_advanced_flow_filter_document() {
    advanced_flow_filter_document_state_.clear_all();
    return build_document_workflow_state(advanced_flow_filter_document_state_);
}

std::optional<std::string> format_advanced_flow_filter_protocol_path_predicate_text(
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate
) {
    session_detail::AdvancedFlowFilterDocument document {};
    document.configured_spec.protocol_path.include = {predicate};

    const auto format_result = session_detail::format_advanced_flow_filter_text(document);
    if (format_result.status != session_detail::AdvancedFlowFilterTextFormatStatus::ok) {
        return std::nullopt;
    }

    const auto newline = format_result.text.find('\n');
    if (newline == std::string::npos || newline + 1U >= format_result.text.size()) {
        return std::nullopt;
    }

    auto assignment = std::string_view {format_result.text}.substr(newline + 1U);
    if (!assignment.empty() && assignment.back() == '\n') {
        assignment.remove_suffix(1U);
    }

    const auto equals = assignment.find(" = ");
    if (equals == std::string_view::npos || equals + 3U > assignment.size()) {
        return std::nullopt;
    }

    return std::string {assignment.substr(equals + 3U)};
}

bool encode_advanced_flow_filter_protocol_path_row(
    const FrontendSessionAdapter& adapter,
    const session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate,
    FrontendAdvancedFlowFilterProtocolPathRowDto& out,
    FrontendAdvancedFlowFilterStructuredDocumentResult& result
) {
    const auto* selector_mode = protocol_path_selector_mode_descriptor_for_predicate(predicate);
    if (selector_mode == nullptr) {
        result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
        result.error_text = "The current Advanced Filter document contains a Protocol Path predicate that the Tauri structured editor cannot represent.";
        return false;
    }

    const auto predicate_text = format_advanced_flow_filter_protocol_path_predicate_text(predicate);
    if (!predicate_text.has_value()) {
        result.status = FrontendAdvancedFlowFilterStructuredDocumentStatus::unrepresentable_document;
        result.error_text = "The current Advanced Filter document contains a Protocol Path predicate that the Tauri structured editor cannot represent.";
        return false;
    }

    const auto applicability = adapter.advanced_flow_filter_protocol_path_predicate_applicability(predicate);
    out = FrontendAdvancedFlowFilterProtocolPathRowDto {
        .selector_mode_id = selector_mode->stable_id,
        .predicate_text = *predicate_text,
        .compact_text = protocol_path_compact_text(predicate),
        .full_text = protocol_path_predicate_text(predicate),
        .applicability_known = applicability.has_value(),
        .applicable = applicability.value_or(false),
        .status_text = !applicability.has_value()
            ? "No current capture."
            : (applicability.value() ? std::string {} : "Not present in current capture"),
    };
    return true;
}

}  // namespace pfl
