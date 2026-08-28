#include "app/session/AdvancedFlowFilter.h"

#include <algorithm>
#include <array>
#include <string_view>

#include "core/domain/Connection.h"

namespace pfl::session_detail {

namespace {

char ascii_lower(const char value) noexcept {
    if (value >= 'A' && value <= 'Z') {
        return static_cast<char>(value - 'A' + 'a');
    }
    return value;
}

bool equals_ascii_case_insensitive(const std::string_view left, const std::string_view right) noexcept {
    if (left.size() != right.size()) {
        return false;
    }

    for (std::size_t index = 0; index < left.size(); ++index) {
        if (ascii_lower(left[index]) != ascii_lower(right[index])) {
            return false;
        }
    }

    return true;
}

bool starts_with_ascii_case_insensitive(const std::string_view value, const std::string_view prefix) noexcept {
    if (prefix.size() > value.size()) {
        return false;
    }

    for (std::size_t index = 0; index < prefix.size(); ++index) {
        if (ascii_lower(value[index]) != ascii_lower(prefix[index])) {
            return false;
        }
    }

    return true;
}

bool contains_ascii_case_insensitive(const std::string_view haystack, const std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (needle.size() > haystack.size()) {
        return false;
    }

    for (std::size_t offset = 0; offset + needle.size() <= haystack.size(); ++offset) {
        bool matches = true;
        for (std::size_t index = 0; index < needle.size(); ++index) {
            if (ascii_lower(haystack[offset + index]) != ascii_lower(needle[index])) {
                matches = false;
                break;
            }
        }
        if (matches) {
            return true;
        }
    }

    return false;
}

std::optional<ProtocolLayerIdentifierKind> expected_identifier_kind(const ProtocolLayerKind kind) noexcept {
    switch (kind) {
    case ProtocolLayerKind::vlan:
        return ProtocolLayerIdentifierKind::vlan_vid;
    case ProtocolLayerKind::mpls:
        return ProtocolLayerIdentifierKind::mpls_label;
    case ProtocolLayerKind::pbb:
        return ProtocolLayerIdentifierKind::pbb_isid;
    case ProtocolLayerKind::vxlan:
        return ProtocolLayerIdentifierKind::vxlan_vni;
    case ProtocolLayerKind::geneve:
        return ProtocolLayerIdentifierKind::geneve_vni;
    case ProtocolLayerKind::gtpu:
        return ProtocolLayerIdentifierKind::gtpu_teid;
    case ProtocolLayerKind::gre:
        return ProtocolLayerIdentifierKind::gre_key;
    case ProtocolLayerKind::ah:
        return ProtocolLayerIdentifierKind::ah_spi;
    case ProtocolLayerKind::esp:
        return ProtocolLayerIdentifierKind::esp_spi;
    default:
        return std::nullopt;
    }
}

bool is_valid_protocol_layer_predicate_shape(const AdvancedFlowFilterProtocolLayerPredicate& predicate) noexcept {
    if (predicate.kind == ProtocolLayerKind::unknown) {
        return false;
    }
    if (!predicate.identifier.has_value()) {
        return true;
    }

    if (predicate.identifier->kind == ProtocolLayerIdentifierKind::none) {
        return false;
    }

    const auto expected_kind = expected_identifier_kind(predicate.kind);
    return expected_kind.has_value() && *expected_kind == predicate.identifier->kind;
}

bool matches_layer_predicate(const LayerKey& key, const AdvancedFlowFilterProtocolLayerPredicate& predicate) noexcept {
    if (key.kind != predicate.kind) {
        return false;
    }
    if (!predicate.identifier.has_value()) {
        return true;
    }
    return key.identifier == *predicate.identifier;
}

bool matches_protocol_path_predicate(
    const ProtocolPath& path,
    const AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    switch (predicate.match_kind) {
    case AdvancedFlowFilterProtocolPathMatchKind::exact_path:
        if (path.size() != predicate.layers.size()) {
            return false;
        }
        for (std::size_t index = 0; index < predicate.layers.size(); ++index) {
            if (!matches_layer_predicate(path[index], predicate.layers[index])) {
                return false;
            }
        }
        return true;
    case AdvancedFlowFilterProtocolPathMatchKind::path_prefix:
        if (path.size() < predicate.layers.size()) {
            return false;
        }
        for (std::size_t index = 0; index < predicate.layers.size(); ++index) {
            if (!matches_layer_predicate(path[index], predicate.layers[index])) {
                return false;
            }
        }
        return true;
    case AdvancedFlowFilterProtocolPathMatchKind::contains_layer:
        if (predicate.layers.empty()) {
            return false;
        }
        for (const auto& layer : path.layers()) {
            if (matches_layer_predicate(layer, predicate.layers.front())) {
                return true;
            }
        }
        return false;
    default:
        return false;
    }
}

bool is_valid_protocol_path_predicate_shape(const AdvancedFlowFilterProtocolPathPredicate& predicate) noexcept {
    if (predicate.match_kind == AdvancedFlowFilterProtocolPathMatchKind::contains_layer) {
        return predicate.layers.size() == 1U &&
            is_valid_protocol_layer_predicate_shape(predicate.layers.front());
    }

    if (predicate.layers.empty()) {
        return false;
    }

    for (const auto& layer : predicate.layers) {
        if (!is_valid_protocol_layer_predicate_shape(layer)) {
            return false;
        }
    }
    return true;
}

template <typename T>
bool is_valid_range(const AdvancedFlowFilterInclusiveRange<T>& range) noexcept {
    return !range.min.has_value() || !range.max.has_value() || *range.min <= *range.max;
}

template <typename T>
bool matches_range(
    const std::optional<AdvancedFlowFilterInclusiveRange<T>>& range,
    const T value
) noexcept {
    if (!range.has_value()) {
        return true;
    }
    if (range->min.has_value() && value < *range->min) {
        return false;
    }
    if (range->max.has_value() && value > *range->max) {
        return false;
    }
    return true;
}

bool is_valid_address_family_value(const FlowAddressFamily family) noexcept {
    switch (family) {
    case FlowAddressFamily::ipv4:
    case FlowAddressFamily::ipv6:
        return true;
    default:
        return false;
    }
}

std::uint32_t ipv4_prefix_mask(const std::uint8_t prefix_length) noexcept {
    if (prefix_length == 0U) {
        return 0U;
    }
    if (prefix_length >= 32U) {
        return 0xFFFFFFFFU;
    }
    return 0xFFFFFFFFU << (32U - prefix_length);
}

std::array<std::uint8_t, 16> normalize_ipv6_network(
    std::array<std::uint8_t, 16> value,
    const std::uint8_t prefix_length
) noexcept {
    const auto full_bytes = static_cast<std::size_t>(prefix_length / 8U);
    const auto partial_bits = static_cast<std::uint8_t>(prefix_length % 8U);

    if (full_bytes < value.size()) {
        if (partial_bits == 0U) {
            for (std::size_t index = full_bytes; index < value.size(); ++index) {
                value[index] = 0U;
            }
        } else {
            value[full_bytes] &= static_cast<std::uint8_t>(0xFFU << (8U - partial_bits));
            for (std::size_t index = full_bytes + 1U; index < value.size(); ++index) {
                value[index] = 0U;
            }
        }
    }

    return value;
}

bool is_valid_ipv4_address_predicate_shape(const AdvancedFlowFilterIpv4AddressPredicate& predicate) noexcept {
    switch (predicate.match_kind) {
    case AdvancedFlowFilterAddressMatchKind::exact:
        return predicate.prefix_length == 32U;
    case AdvancedFlowFilterAddressMatchKind::cidr:
        return predicate.prefix_length <= 32U;
    default:
        return false;
    }
}

bool is_valid_ipv6_address_predicate_shape(const AdvancedFlowFilterIpv6AddressPredicate& predicate) noexcept {
    switch (predicate.match_kind) {
    case AdvancedFlowFilterAddressMatchKind::exact:
        return predicate.prefix_length == 128U;
    case AdvancedFlowFilterAddressMatchKind::cidr:
        return predicate.prefix_length <= 128U;
    default:
        return false;
    }
}

CompiledAdvancedFlowFilterIpv4CidrPredicate compile_ipv4_address_predicate(
    const AdvancedFlowFilterIpv4AddressPredicate& predicate
) noexcept {
    const auto prefix_length =
        predicate.match_kind == AdvancedFlowFilterAddressMatchKind::exact ? static_cast<std::uint8_t>(32U) : predicate.prefix_length;
    const auto mask = ipv4_prefix_mask(prefix_length);
    return CompiledAdvancedFlowFilterIpv4CidrPredicate {
        .scope = predicate.scope,
        .network = predicate.value & mask,
        .mask = mask,
        .prefix_length = prefix_length,
    };
}

CompiledAdvancedFlowFilterIpv6CidrPredicate compile_ipv6_address_predicate(
    const AdvancedFlowFilterIpv6AddressPredicate& predicate
) noexcept {
    const auto prefix_length =
        predicate.match_kind == AdvancedFlowFilterAddressMatchKind::exact ? static_cast<std::uint8_t>(128U) : predicate.prefix_length;
    return CompiledAdvancedFlowFilterIpv6CidrPredicate {
        .scope = predicate.scope,
        .network = normalize_ipv6_network(predicate.value, prefix_length),
        .prefix_length = prefix_length,
    };
}

ProtocolPathId connection_protocol_path_id(const ListedConnectionRef& connection) noexcept {
    return connection.family == FlowAddressFamily::ipv4
        ? connection.ipv4->key.protocol_path_id
        : connection.ipv6->key.protocol_path_id;
}

const ConnectionAggregateStats& aggregate_stats(const ListedConnectionRef& connection) noexcept {
    return connection.family == FlowAddressFamily::ipv4
        ? connection.ipv4->aggregate_stats
        : connection.ipv6->aggregate_stats;
}

std::uint64_t fragmented_packet_count_value(const ListedConnectionRef& connection) noexcept {
    return connection.family == FlowAddressFamily::ipv4
        ? connection.ipv4->fragmented_packet_count
        : connection.ipv6->fragmented_packet_count;
}

std::string_view service_hint_value(const ListedConnectionRef& connection) noexcept {
    return connection.family == FlowAddressFamily::ipv4
        ? std::string_view(connection.ipv4->service_hint)
        : std::string_view(connection.ipv6->service_hint);
}

FlowProtocolHint stored_protocol_hint(const ListedConnectionRef& connection) noexcept {
    return connection.family == FlowAddressFamily::ipv4
        ? connection.ipv4->protocol_hint
        : connection.ipv6->protocol_hint;
}

TlsVersionHint tls_version_hint_value(const ListedConnectionRef& connection) noexcept {
    return connection.family == FlowAddressFamily::ipv4
        ? connection.ipv4->tls_version
        : connection.ipv6->tls_version;
}

QuicVersionHint quic_version_hint_value(const ListedConnectionRef& connection) noexcept {
    return connection.family == FlowAddressFamily::ipv4
        ? connection.ipv4->quic_version
        : connection.ipv6->quic_version;
}

std::pair<std::uint16_t, std::uint16_t> oriented_ports(const ConnectionV4& connection) noexcept {
    if (connection.has_flow_a) {
        return {connection.flow_a.key.src_port, connection.flow_a.key.dst_port};
    }
    if (connection.has_flow_b) {
        return {connection.flow_b.key.dst_port, connection.flow_b.key.src_port};
    }
    return {connection.key.first.port, connection.key.second.port};
}

std::pair<std::uint16_t, std::uint16_t> oriented_ports(const ConnectionV6& connection) noexcept {
    if (connection.has_flow_a) {
        return {connection.flow_a.key.src_port, connection.flow_a.key.dst_port};
    }
    if (connection.has_flow_b) {
        return {connection.flow_b.key.dst_port, connection.flow_b.key.src_port};
    }
    return {connection.key.first.port, connection.key.second.port};
}

std::pair<std::uint16_t, std::uint16_t> oriented_ports(const ListedConnectionRef& connection) noexcept {
    return connection.family == FlowAddressFamily::ipv4
        ? oriented_ports(*connection.ipv4)
        : oriented_ports(*connection.ipv6);
}

std::pair<std::uint32_t, std::uint32_t> oriented_ipv4_addrs(const ConnectionV4& connection) noexcept {
    if (const auto endpoint_a = first_observed_endpoint_a(connection),
        endpoint_b = first_observed_endpoint_b(connection);
        endpoint_a.has_value() && endpoint_b.has_value()) {
        return {endpoint_a->addr, endpoint_b->addr};
    }
    if (connection.has_flow_a) {
        return {connection.flow_a.key.src_addr, connection.flow_a.key.dst_addr};
    }
    return {connection.key.first.addr, connection.key.second.addr};
}

std::pair<std::array<std::uint8_t, 16>, std::array<std::uint8_t, 16>> oriented_ipv6_addrs(const ConnectionV6& connection) noexcept {
    if (const auto endpoint_a = first_observed_endpoint_a(connection),
        endpoint_b = first_observed_endpoint_b(connection);
        endpoint_a.has_value() && endpoint_b.has_value()) {
        return {endpoint_a->addr, endpoint_b->addr};
    }
    if (connection.has_flow_a) {
        return {connection.flow_a.key.src_addr, connection.flow_a.key.dst_addr};
    }
    return {connection.key.first.addr, connection.key.second.addr};
}

std::pair<std::uint64_t, std::uint64_t> directional_packet_counts(const ListedConnectionRef& connection) noexcept {
    if (connection.family == FlowAddressFamily::ipv4) {
        return {
            connection.ipv4->has_flow_a ? connection.ipv4->flow_a.packet_count : 0U,
            connection.ipv4->has_flow_b ? connection.ipv4->flow_b.packet_count : 0U,
        };
    }

    return {
        connection.ipv6->has_flow_a ? connection.ipv6->flow_a.packet_count : 0U,
        connection.ipv6->has_flow_b ? connection.ipv6->flow_b.packet_count : 0U,
    };
}

bool matches_directionality_value(
    const AdvancedFlowFilterDirectionality value,
    const ListedConnectionRef& connection
) noexcept {
    const auto [a_to_b_packets, b_to_a_packets] = directional_packet_counts(connection);
    switch (value) {
    case AdvancedFlowFilterDirectionality::unidirectional:
        return a_to_b_packets > 0U && b_to_a_packets == 0U;
    case AdvancedFlowFilterDirectionality::bidirectional:
        return a_to_b_packets > 0U && b_to_a_packets > 0U;
    default:
        return false;
    }
}

bool is_valid_directionality_value(const AdvancedFlowFilterDirectionality value) noexcept {
    switch (value) {
    case AdvancedFlowFilterDirectionality::unidirectional:
    case AdvancedFlowFilterDirectionality::bidirectional:
        return true;
    default:
        return false;
    }
}

bool matches_service_text_predicate(
    const std::string_view service_hint,
    const CompiledAdvancedFlowFilterServicePredicate& predicate
) noexcept {
    const auto case_insensitive =
        predicate.case_sensitivity == AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive;

    switch (predicate.kind) {
    case AdvancedFlowFilterServicePredicateKind::equals:
        return case_insensitive
            ? equals_ascii_case_insensitive(service_hint, predicate.value)
            : service_hint == predicate.value;
    case AdvancedFlowFilterServicePredicateKind::starts_with:
        return case_insensitive
            ? starts_with_ascii_case_insensitive(service_hint, predicate.value)
            : service_hint.starts_with(predicate.value);
    case AdvancedFlowFilterServicePredicateKind::contains:
        return case_insensitive
            ? contains_ascii_case_insensitive(service_hint, predicate.value)
            : service_hint.find(predicate.value) != std::string_view::npos;
    default:
        return false;
    }
}

bool matches_protocol_membership(
    const CompiledAdvancedFlowFilterProtocolCriteria& criteria,
    const ProtocolId protocol
) noexcept {
    const auto index = static_cast<std::size_t>(protocol);
    const bool include_match = !criteria.has_include_predicates || criteria.include_membership[index];
    const bool exclude_match = criteria.has_exclude_predicates && criteria.exclude_membership[index];
    return include_match && !exclude_match;
}

bool matches_address_family_criteria(
    const CompiledAdvancedFlowFilterAddressFamilyCriteria& criteria,
    const FlowAddressFamily family
) noexcept {
    const auto index = static_cast<std::size_t>(family);
    const bool include_match = !criteria.has_include_predicates || criteria.include_membership[index];
    const bool exclude_match = criteria.has_exclude_predicates && criteria.exclude_membership[index];
    return include_match && !exclude_match;
}

bool matches_detected_protocol_membership(
    const CompiledAdvancedFlowFilterDetectedProtocolCriteria& criteria,
    const FlowProtocolHint protocol_hint
) noexcept {
    const auto index = static_cast<std::size_t>(protocol_hint);
    const bool include_match = !criteria.has_include_predicates || criteria.include_membership[index];
    const bool exclude_match = criteria.has_exclude_predicates && criteria.exclude_membership[index];
    return include_match && !exclude_match;
}

bool matches_tls_version_membership(
    const CompiledAdvancedFlowFilterTlsVersionCriteria& criteria,
    const TlsVersionHint version
) noexcept {
    const auto index = static_cast<std::size_t>(version);
    const bool include_match = !criteria.has_include_predicates || criteria.include_membership[index];
    const bool exclude_match = criteria.has_exclude_predicates && criteria.exclude_membership[index];
    return include_match && !exclude_match;
}

bool matches_quic_version_membership(
    const CompiledAdvancedFlowFilterQuicVersionCriteria& criteria,
    const QuicVersionHint version
) noexcept {
    const auto index = static_cast<std::size_t>(version);
    const bool include_match = !criteria.has_include_predicates || criteria.include_membership[index];
    const bool exclude_match = criteria.has_exclude_predicates && criteria.exclude_membership[index];
    return include_match && !exclude_match;
}

bool matches_port_criteria(
    const CompiledAdvancedFlowFilterPortCriteria& criteria,
    const std::uint16_t endpoint_a_port,
    const std::uint16_t endpoint_b_port
) noexcept {
    const bool include_match =
        (!criteria.include_either.active && !criteria.include_a.active && !criteria.include_b.active) ||
        (criteria.include_either.contains(endpoint_a_port) || criteria.include_either.contains(endpoint_b_port)) ||
        criteria.include_a.contains(endpoint_a_port) ||
        criteria.include_b.contains(endpoint_b_port);

    if (!include_match) {
        return false;
    }

    const bool exclude_match =
        (criteria.exclude_either.contains(endpoint_a_port) || criteria.exclude_either.contains(endpoint_b_port)) ||
        criteria.exclude_a.contains(endpoint_a_port) ||
        criteria.exclude_b.contains(endpoint_b_port);

    return !exclude_match;
}

bool matches_aggregate_criteria(
    const CompiledAdvancedFlowFilterAggregateCriteria& criteria,
    const ListedConnectionRef& connection
) noexcept {
    const auto& stats = aggregate_stats(connection);

    return matches_range(criteria.ranges.packet_count, packet_count(connection)) &&
        matches_range(criteria.ranges.original_bytes, total_bytes(connection)) &&
        matches_range(criteria.ranges.captured_bytes, stats.captured_bytes) &&
        matches_range(criteria.ranges.fragmented_packet_count, fragmented_packet_count_value(connection)) &&
        matches_range(criteria.ranges.truncated_packet_count, stats.truncated_packet_count) &&
        matches_range(criteria.ranges.tcp_syn_count, stats.tcp_syn_count) &&
        matches_range(criteria.ranges.tcp_fin_count, stats.tcp_fin_count) &&
        matches_range(criteria.ranges.tcp_rst_count, stats.tcp_rst_count) &&
        matches_range(criteria.ranges.max_original_packet_length, stats.max_original_packet_length) &&
        matches_range(criteria.ranges.max_captured_packet_length, stats.max_captured_packet_length);
}

bool matches_time_overlap_range(
    const std::optional<AdvancedFlowFilterInclusiveRange<std::uint64_t>>& overlap_range,
    const std::uint64_t flow_start_us,
    const std::uint64_t flow_end_us
) noexcept {
    if (!overlap_range.has_value()) {
        return true;
    }
    if (overlap_range->max.has_value() && flow_start_us > *overlap_range->max) {
        return false;
    }
    if (overlap_range->min.has_value() && flow_end_us < *overlap_range->min) {
        return false;
    }
    return true;
}

bool matches_time_criteria(
    const CompiledAdvancedFlowFilterTimeCriteria& criteria,
    const ListedConnectionRef& connection
) noexcept {
    const auto& stats = aggregate_stats(connection);
    const auto duration_us = stats.last_timestamp_us >= stats.first_timestamp_us
        ? (stats.last_timestamp_us - stats.first_timestamp_us)
        : 0U;

    return matches_range(criteria.ranges.start_us, stats.first_timestamp_us) &&
        matches_range(criteria.ranges.end_us, stats.last_timestamp_us) &&
        matches_time_overlap_range(criteria.ranges.overlap_us, stats.first_timestamp_us, stats.last_timestamp_us) &&
        matches_range(criteria.ranges.duration_us, duration_us);
}

bool matches_directionality_criteria(
    const CompiledAdvancedFlowFilterDirectionalityCriteria& criteria,
    const ListedConnectionRef& connection
) noexcept {
    bool include_match = !criteria.has_include_predicates;
    if (!include_match) {
        for (std::size_t index = 0; index < criteria.include_membership.size(); ++index) {
            if (!criteria.include_membership[index]) {
                continue;
            }
            if (matches_directionality_value(static_cast<AdvancedFlowFilterDirectionality>(index), connection)) {
                include_match = true;
                break;
            }
        }
    }

    if (!include_match) {
        return false;
    }

    if (criteria.has_exclude_predicates) {
        for (std::size_t index = 0; index < criteria.exclude_membership.size(); ++index) {
            if (!criteria.exclude_membership[index]) {
                continue;
            }
            if (matches_directionality_value(static_cast<AdvancedFlowFilterDirectionality>(index), connection)) {
                return false;
            }
        }
    }

    return true;
}

bool matches_tls_version_criteria(
    const CompiledAdvancedFlowFilterTlsVersionCriteria& criteria,
    const ListedConnectionRef& connection
) noexcept {
    if (!criteria.has_include_predicates && !criteria.has_exclude_predicates) {
        return true;
    }

    if (stored_protocol_hint(connection) != FlowProtocolHint::tls) {
        return !criteria.has_include_predicates;
    }

    return matches_tls_version_membership(criteria, tls_version_hint_value(connection));
}

bool matches_quic_version_criteria(
    const CompiledAdvancedFlowFilterQuicVersionCriteria& criteria,
    const ListedConnectionRef& connection
) noexcept {
    if (!criteria.has_include_predicates && !criteria.has_exclude_predicates) {
        return true;
    }

    if (stored_protocol_hint(connection) != FlowProtocolHint::quic) {
        return !criteria.has_include_predicates;
    }

    return matches_quic_version_membership(criteria, quic_version_hint_value(connection));
}

bool matches_ipv4_cidr_address(
    const std::uint32_t address,
    const CompiledAdvancedFlowFilterIpv4CidrPredicate& predicate
) noexcept {
    return (address & predicate.mask) == predicate.network;
}

bool matches_ipv6_cidr_address(
    const std::array<std::uint8_t, 16>& address,
    const CompiledAdvancedFlowFilterIpv6CidrPredicate& predicate
) noexcept {
    const auto full_bytes = static_cast<std::size_t>(predicate.prefix_length / 8U);
    const auto partial_bits = static_cast<std::uint8_t>(predicate.prefix_length % 8U);

    for (std::size_t index = 0; index < full_bytes; ++index) {
        if (address[index] != predicate.network[index]) {
            return false;
        }
    }

    if (partial_bits == 0U) {
        return true;
    }

    const auto mask = static_cast<std::uint8_t>(0xFFU << (8U - partial_bits));
    return (address[full_bytes] & mask) == predicate.network[full_bytes];
}

bool matches_ipv4_cidr_predicate(
    const std::uint32_t endpoint_a_addr,
    const std::uint32_t endpoint_b_addr,
    const CompiledAdvancedFlowFilterIpv4CidrPredicate& predicate
) noexcept {
    switch (predicate.scope) {
    case AdvancedFlowFilterEndpointScope::either_endpoint:
        return matches_ipv4_cidr_address(endpoint_a_addr, predicate) ||
            matches_ipv4_cidr_address(endpoint_b_addr, predicate);
    case AdvancedFlowFilterEndpointScope::endpoint_a:
        return matches_ipv4_cidr_address(endpoint_a_addr, predicate);
    case AdvancedFlowFilterEndpointScope::endpoint_b:
        return matches_ipv4_cidr_address(endpoint_b_addr, predicate);
    default:
        return false;
    }
}

bool matches_ipv6_cidr_predicate(
    const std::array<std::uint8_t, 16>& endpoint_a_addr,
    const std::array<std::uint8_t, 16>& endpoint_b_addr,
    const CompiledAdvancedFlowFilterIpv6CidrPredicate& predicate
) noexcept {
    switch (predicate.scope) {
    case AdvancedFlowFilterEndpointScope::either_endpoint:
        return matches_ipv6_cidr_address(endpoint_a_addr, predicate) ||
            matches_ipv6_cidr_address(endpoint_b_addr, predicate);
    case AdvancedFlowFilterEndpointScope::endpoint_a:
        return matches_ipv6_cidr_address(endpoint_a_addr, predicate);
    case AdvancedFlowFilterEndpointScope::endpoint_b:
        return matches_ipv6_cidr_address(endpoint_b_addr, predicate);
    default:
        return false;
    }
}

bool matches_address_criteria(
    const CompiledAdvancedFlowFilterAddressCriteria& criteria,
    const ListedConnectionRef& connection
) noexcept {
    if (!criteria.has_include_predicates() && !criteria.has_exclude_predicates()) {
        return true;
    }

    if (connection.family == FlowAddressFamily::ipv4) {
        const auto [endpoint_a_addr, endpoint_b_addr] = oriented_ipv4_addrs(*connection.ipv4);

        bool include_match = !criteria.has_include_predicates();
        if (!include_match) {
            for (const auto& predicate : criteria.ipv4_include) {
                if (matches_ipv4_cidr_predicate(endpoint_a_addr, endpoint_b_addr, predicate)) {
                    include_match = true;
                    break;
                }
            }
        }

        if (!include_match) {
            return false;
        }

        for (const auto& predicate : criteria.ipv4_exclude) {
            if (matches_ipv4_cidr_predicate(endpoint_a_addr, endpoint_b_addr, predicate)) {
                return false;
            }
        }

        return true;
    }

    const auto [endpoint_a_addr, endpoint_b_addr] = oriented_ipv6_addrs(*connection.ipv6);

    bool include_match = !criteria.has_include_predicates();
    if (!include_match) {
        for (const auto& predicate : criteria.ipv6_include) {
            if (matches_ipv6_cidr_predicate(endpoint_a_addr, endpoint_b_addr, predicate)) {
                include_match = true;
                break;
            }
        }
    }

    if (!include_match) {
        return false;
    }

    for (const auto& predicate : criteria.ipv6_exclude) {
        if (matches_ipv6_cidr_predicate(endpoint_a_addr, endpoint_b_addr, predicate)) {
            return false;
        }
    }

    return true;
}

bool matches_service_criteria(
    const CompiledAdvancedFlowFilterServiceCriteria& criteria,
    const std::string_view service_hint
) noexcept {
    const bool known = !service_hint.empty();

    bool include_match = !criteria.has_include_predicates();
    if (!include_match) {
        const bool recognition_include_configured = criteria.include_known || criteria.include_unknown;
        const bool text_include_configured = !criteria.include_text.empty();

        const bool recognition_include_match = !recognition_include_configured ||
            ((criteria.include_known && known) || (criteria.include_unknown && !known));

        bool text_include_match = !text_include_configured;
        if (!text_include_match) {
            for (const auto& predicate : criteria.include_text) {
                if (matches_service_text_predicate(service_hint, predicate)) {
                    text_include_match = true;
                    break;
                }
            }
        }

        include_match = recognition_include_match && text_include_match;
    }

    if (!include_match) {
        return false;
    }

    if ((criteria.exclude_known && known) || (criteria.exclude_unknown && !known)) {
        return false;
    }

    for (const auto& predicate : criteria.exclude_text) {
        if (matches_service_text_predicate(service_hint, predicate)) {
            return false;
        }
    }

    return true;
}

std::vector<std::uint64_t>& ensure_port_bitmap_storage(AdvancedFlowFilterPortBitmap& bitmap) {
    if (bitmap.words.empty()) {
        bitmap.words.resize(kAdvancedFlowFilterPortBitmapWordCount, 0U);
    } else if (bitmap.words.size() != kAdvancedFlowFilterPortBitmapWordCount) {
        bitmap.words.resize(kAdvancedFlowFilterPortBitmapWordCount, 0U);
    }
    return bitmap.words;
}

AdvancedFlowFilterCompileResult make_compile_error(
    const AdvancedFlowFilterCompileStatus status,
    std::string category,
    const std::optional<std::size_t> predicate_index = std::nullopt
) {
    AdvancedFlowFilterCompileResult result {};
    result.status = status;
    result.issue = AdvancedFlowFilterCompileIssue {
        .status = status,
        .category = std::move(category),
        .predicate_index = predicate_index,
    };
    return result;
}

template <typename T>
std::optional<AdvancedFlowFilterCompileResult> validate_range_field(
    const std::optional<AdvancedFlowFilterInclusiveRange<T>>& range,
    const std::string_view category
) {
    if (range.has_value() && !is_valid_range(*range)) {
        return make_compile_error(
            AdvancedFlowFilterCompileStatus::invalid_numeric_range,
            std::string(category)
        );
    }
    return std::nullopt;
}

AdvancedFlowFilterCompileResult compile_protocol_path_criteria(
    const AdvancedFlowFilterProtocolPathCriteria& spec,
    const ProtocolPathRegistry& registry,
    CompiledAdvancedFlowFilterProtocolPathCriteria& compiled
) {
    const auto is_protocol_path_predicate = [](const AdvancedFlowFilterProtocolPathPredicate& predicate) noexcept {
        return predicate.match_kind == AdvancedFlowFilterProtocolPathMatchKind::exact_path ||
            predicate.match_kind == AdvancedFlowFilterProtocolPathMatchKind::path_prefix;
    };
    const auto is_contains_layer_predicate = [](const AdvancedFlowFilterProtocolPathPredicate& predicate) noexcept {
        return predicate.match_kind == AdvancedFlowFilterProtocolPathMatchKind::contains_layer;
    };

    compiled.protocol_path_group.has_include_predicates = std::any_of(
        spec.include.begin(),
        spec.include.end(),
        is_protocol_path_predicate
    );
    compiled.protocol_path_group.has_exclude_predicates = std::any_of(
        spec.exclude.begin(),
        spec.exclude.end(),
        is_protocol_path_predicate
    );
    compiled.contains_layer_group.has_include_predicates = std::any_of(
        spec.include.begin(),
        spec.include.end(),
        is_contains_layer_predicate
    );
    compiled.contains_layer_group.has_exclude_predicates = std::any_of(
        spec.exclude.begin(),
        spec.exclude.end(),
        is_contains_layer_predicate
    );

    for (std::size_t index = 0; index < spec.include.size(); ++index) {
        if (!is_valid_protocol_path_predicate_shape(spec.include[index])) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_protocol_path_predicate,
                "protocol_path.include",
                index
            );
        }
    }

    for (std::size_t index = 0; index < spec.exclude.size(); ++index) {
        if (!is_valid_protocol_path_predicate_shape(spec.exclude[index])) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_protocol_path_predicate,
                "protocol_path.exclude",
                index
            );
        }
    }

    const auto initialize_group_membership = [&](CompiledAdvancedFlowFilterProtocolPathPredicateGroup& group) {
        if (!group.has_include_predicates && !group.has_exclude_predicates) {
            return;
        }
        group.include_membership.assign(registry.size() + 1U, 0U);
        group.exclude_membership.assign(registry.size() + 1U, 0U);
    };
    initialize_group_membership(compiled.protocol_path_group);
    initialize_group_membership(compiled.contains_layer_group);

    if ((!compiled.protocol_path_group.has_include_predicates &&
         !compiled.protocol_path_group.has_exclude_predicates) &&
        (!compiled.contains_layer_group.has_include_predicates &&
         !compiled.contains_layer_group.has_exclude_predicates)) {
        return {};
    }

    const auto& paths = registry.paths();
    for (std::size_t index = 0; index < paths.size(); ++index) {
        const auto id = static_cast<ProtocolPathId>(index + 1U);
        const auto populate_membership =
            [&](const auto& predicates,
                const auto predicate_selector,
                CompiledAdvancedFlowFilterProtocolPathPredicateGroup& group,
                const bool include_membership) {
                auto& membership = include_membership ? group.include_membership : group.exclude_membership;
                if (membership.empty()) {
                    return;
                }

                for (const auto& predicate : predicates) {
                    if (!predicate_selector(predicate)) {
                        continue;
                    }
                    if (matches_protocol_path_predicate(paths[index], predicate)) {
                        membership[id] = 1U;
                        break;
                    }
                }
            };

        populate_membership(spec.include, is_protocol_path_predicate, compiled.protocol_path_group, true);
        populate_membership(spec.exclude, is_protocol_path_predicate, compiled.protocol_path_group, false);
        populate_membership(spec.include, is_contains_layer_predicate, compiled.contains_layer_group, true);
        populate_membership(spec.exclude, is_contains_layer_predicate, compiled.contains_layer_group, false);
    }

    return {};
}

AdvancedFlowFilterCompileResult compile_address_family_membership(
    const AdvancedFlowFilterAddressFamilyCriteria& spec,
    CompiledAdvancedFlowFilterAddressFamilyCriteria& compiled
) {
    compiled.has_include_predicates = !spec.include.empty();
    compiled.has_exclude_predicates = !spec.exclude.empty();

    for (std::size_t index = 0; index < spec.include.size(); ++index) {
        const auto family = spec.include[index];
        if (!is_valid_address_family_value(family)) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_address_family_predicate,
                "address_family",
                index
            );
        }
        compiled.include_membership[static_cast<std::size_t>(family)] = true;
    }

    for (std::size_t index = 0; index < spec.exclude.size(); ++index) {
        const auto family = spec.exclude[index];
        if (!is_valid_address_family_value(family)) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_address_family_predicate,
                "address_family",
                index
            );
        }
        compiled.exclude_membership[static_cast<std::size_t>(family)] = true;
    }

    return {};
}

void compile_protocol_membership(
    const AdvancedFlowFilterProtocolCriteria& spec,
    CompiledAdvancedFlowFilterProtocolCriteria& compiled
) {
    compiled.has_include_predicates = !spec.include.empty();
    compiled.has_exclude_predicates = !spec.exclude.empty();

    for (const auto protocol : spec.include) {
        compiled.include_membership[static_cast<std::size_t>(protocol)] = true;
    }

    for (const auto protocol : spec.exclude) {
        compiled.exclude_membership[static_cast<std::size_t>(protocol)] = true;
    }
}

void compile_detected_protocol_membership(
    const AdvancedFlowFilterDetectedProtocolCriteria& spec,
    const AnalysisSettings& settings,
    CompiledAdvancedFlowFilterDetectedProtocolCriteria& compiled
) {
    compiled.has_include_predicates = !spec.include.empty();
    compiled.has_exclude_predicates = !spec.exclude.empty();
    compiled.use_possible_tls_quic = settings.use_possible_tls_quic;

    for (const auto hint : spec.include) {
        compiled.include_membership[static_cast<std::size_t>(hint)] = true;
    }

    for (const auto hint : spec.exclude) {
        compiled.exclude_membership[static_cast<std::size_t>(hint)] = true;
    }
}

void compile_tls_version_membership(
    const AdvancedFlowFilterTlsVersionCriteria& spec,
    CompiledAdvancedFlowFilterTlsVersionCriteria& compiled
) {
    compiled.has_include_predicates = !spec.include.empty();
    compiled.has_exclude_predicates = !spec.exclude.empty();

    for (const auto version : spec.include) {
        compiled.include_membership[static_cast<std::size_t>(version)] = true;
    }

    for (const auto version : spec.exclude) {
        compiled.exclude_membership[static_cast<std::size_t>(version)] = true;
    }
}

void compile_quic_version_membership(
    const AdvancedFlowFilterQuicVersionCriteria& spec,
    CompiledAdvancedFlowFilterQuicVersionCriteria& compiled
) {
    compiled.has_include_predicates = !spec.include.empty();
    compiled.has_exclude_predicates = !spec.exclude.empty();

    for (const auto version : spec.include) {
        compiled.include_membership[static_cast<std::size_t>(version)] = true;
    }

    for (const auto version : spec.exclude) {
        compiled.exclude_membership[static_cast<std::size_t>(version)] = true;
    }
}

AdvancedFlowFilterCompileResult compile_port_criteria(
    const AdvancedFlowFilterPortCriteria& spec,
    CompiledAdvancedFlowFilterPortCriteria& compiled
) {
    for (std::size_t index = 0; index < spec.include.size(); ++index) {
        const auto& predicate = spec.include[index];
        if (predicate.range.first > predicate.range.last) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_numeric_range,
                "ports.include",
                index
            );
        }

        switch (predicate.scope) {
        case AdvancedFlowFilterPortScope::either_endpoint:
            compiled.include_either.set_range(predicate.range.first, predicate.range.last);
            break;
        case AdvancedFlowFilterPortScope::endpoint_a:
            compiled.include_a.set_range(predicate.range.first, predicate.range.last);
            break;
        case AdvancedFlowFilterPortScope::endpoint_b:
            compiled.include_b.set_range(predicate.range.first, predicate.range.last);
            break;
        }
    }

    for (std::size_t index = 0; index < spec.exclude.size(); ++index) {
        const auto& predicate = spec.exclude[index];
        if (predicate.range.first > predicate.range.last) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_numeric_range,
                "ports.exclude",
                index
            );
        }

        switch (predicate.scope) {
        case AdvancedFlowFilterPortScope::either_endpoint:
            compiled.exclude_either.set_range(predicate.range.first, predicate.range.last);
            break;
        case AdvancedFlowFilterPortScope::endpoint_a:
            compiled.exclude_a.set_range(predicate.range.first, predicate.range.last);
            break;
        case AdvancedFlowFilterPortScope::endpoint_b:
            compiled.exclude_b.set_range(predicate.range.first, predicate.range.last);
            break;
        }
    }

    return {};
}

AdvancedFlowFilterCompileResult compile_aggregate_criteria(
    const AdvancedFlowFilterAggregateCriteria& spec,
    CompiledAdvancedFlowFilterAggregateCriteria& compiled
) {
    if (const auto error = validate_range_field(spec.packet_count, "aggregate.packet_count")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.original_bytes, "aggregate.original_bytes")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.captured_bytes, "aggregate.captured_bytes")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.fragmented_packet_count, "aggregate.fragmented_packet_count")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.truncated_packet_count, "aggregate.truncated_packet_count")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.tcp_syn_count, "aggregate.tcp_syn_count")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.tcp_fin_count, "aggregate.tcp_fin_count")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.tcp_rst_count, "aggregate.tcp_rst_count")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.max_original_packet_length, "aggregate.max_original_packet_length")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.max_captured_packet_length, "aggregate.max_captured_packet_length")) {
        return *error;
    }

    compiled.ranges = spec;
    return {};
}

AdvancedFlowFilterCompileResult compile_time_criteria(
    const AdvancedFlowFilterTimeCriteria& spec,
    CompiledAdvancedFlowFilterTimeCriteria& compiled
) {
    if (const auto error = validate_range_field(spec.start_us, "time.start_us")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.end_us, "time.end_us")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.overlap_us, "time.overlap_us")) {
        return *error;
    }
    if (const auto error = validate_range_field(spec.duration_us, "time.duration_us")) {
        return *error;
    }

    compiled.ranges = spec;
    return {};
}

AdvancedFlowFilterCompileResult compile_directionality_criteria(
    const AdvancedFlowFilterDirectionalityCriteria& spec,
    CompiledAdvancedFlowFilterDirectionalityCriteria& compiled
) {
    compiled.has_include_predicates = !spec.include.empty();
    compiled.has_exclude_predicates = !spec.exclude.empty();

    for (std::size_t index = 0; index < spec.include.size(); ++index) {
        const auto value = spec.include[index];
        if (!is_valid_directionality_value(value)) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_directionality_predicate,
                "directionality",
                index
            );
        }
        compiled.include_membership[static_cast<std::size_t>(value)] = true;
    }

    for (std::size_t index = 0; index < spec.exclude.size(); ++index) {
        const auto value = spec.exclude[index];
        if (!is_valid_directionality_value(value)) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_directionality_predicate,
                "directionality",
                index
            );
        }
        compiled.exclude_membership[static_cast<std::size_t>(value)] = true;
    }

    return {};
}

AdvancedFlowFilterCompileResult compile_address_criteria(
    const AdvancedFlowFilterAddressCriteria& spec,
    CompiledAdvancedFlowFilterAddressCriteria& compiled
) {
    for (std::size_t index = 0; index < spec.ipv4_include.size(); ++index) {
        if (!is_valid_ipv4_address_predicate_shape(spec.ipv4_include[index])) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_address_predicate,
                "addresses.ipv4_include",
                index
            );
        }
        compiled.ipv4_include.push_back(compile_ipv4_address_predicate(spec.ipv4_include[index]));
    }

    for (std::size_t index = 0; index < spec.ipv4_exclude.size(); ++index) {
        if (!is_valid_ipv4_address_predicate_shape(spec.ipv4_exclude[index])) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_address_predicate,
                "addresses.ipv4_exclude",
                index
            );
        }
        compiled.ipv4_exclude.push_back(compile_ipv4_address_predicate(spec.ipv4_exclude[index]));
    }

    for (std::size_t index = 0; index < spec.ipv6_include.size(); ++index) {
        if (!is_valid_ipv6_address_predicate_shape(spec.ipv6_include[index])) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_address_predicate,
                "addresses.ipv6_include",
                index
            );
        }
        compiled.ipv6_include.push_back(compile_ipv6_address_predicate(spec.ipv6_include[index]));
    }

    for (std::size_t index = 0; index < spec.ipv6_exclude.size(); ++index) {
        if (!is_valid_ipv6_address_predicate_shape(spec.ipv6_exclude[index])) {
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_address_predicate,
                "addresses.ipv6_exclude",
                index
            );
        }
        compiled.ipv6_exclude.push_back(compile_ipv6_address_predicate(spec.ipv6_exclude[index]));
    }

    return {};
}

AdvancedFlowFilterCompileResult compile_service_criteria(
    const AdvancedFlowFilterServiceCriteria& spec,
    CompiledAdvancedFlowFilterServiceCriteria& compiled
) {
    const auto append_predicate = [&](const AdvancedFlowFilterServicePredicate& predicate,
                                      const bool include,
                                      const std::size_t index) -> std::optional<AdvancedFlowFilterCompileResult> {
        switch (predicate.kind) {
        case AdvancedFlowFilterServicePredicateKind::known:
            if (!predicate.value.empty()) {
                return make_compile_error(
                    AdvancedFlowFilterCompileStatus::invalid_service_predicate,
                    include ? "service.include" : "service.exclude",
                    index
                );
            }
            if (include) {
                compiled.include_known = true;
            } else {
                compiled.exclude_known = true;
            }
            return std::nullopt;
        case AdvancedFlowFilterServicePredicateKind::unknown:
            if (!predicate.value.empty()) {
                return make_compile_error(
                    AdvancedFlowFilterCompileStatus::invalid_service_predicate,
                    include ? "service.include" : "service.exclude",
                    index
                );
            }
            if (include) {
                compiled.include_unknown = true;
            } else {
                compiled.exclude_unknown = true;
            }
            return std::nullopt;
        case AdvancedFlowFilterServicePredicateKind::equals:
        case AdvancedFlowFilterServicePredicateKind::starts_with:
        case AdvancedFlowFilterServicePredicateKind::contains:
            if (predicate.value.empty()) {
                return make_compile_error(
                    AdvancedFlowFilterCompileStatus::invalid_service_predicate,
                    include ? "service.include" : "service.exclude",
                    index
                );
            }
            if (include) {
                compiled.include_text.push_back(CompiledAdvancedFlowFilterServicePredicate {
                    .kind = predicate.kind,
                    .value = predicate.value,
                    .case_sensitivity = predicate.case_sensitivity,
                });
            } else {
                compiled.exclude_text.push_back(CompiledAdvancedFlowFilterServicePredicate {
                    .kind = predicate.kind,
                    .value = predicate.value,
                    .case_sensitivity = predicate.case_sensitivity,
                });
            }
            return std::nullopt;
        default:
            return make_compile_error(
                AdvancedFlowFilterCompileStatus::invalid_service_predicate,
                include ? "service.include" : "service.exclude",
                index
            );
        }
    };

    for (std::size_t index = 0; index < spec.include.size(); ++index) {
        if (const auto error = append_predicate(spec.include[index], true, index)) {
            return *error;
        }
    }

    for (std::size_t index = 0; index < spec.exclude.size(); ++index) {
        if (const auto error = append_predicate(spec.exclude[index], false, index)) {
            return *error;
        }
    }

    return {};
}

bool matches_protocol_path_predicate_group(
    const CompiledAdvancedFlowFilterProtocolPathPredicateGroup& group,
    const ProtocolPathId protocol_path_id
) noexcept {
    const bool include_match = !group.has_include_predicates ||
        (static_cast<std::size_t>(protocol_path_id) < group.include_membership.size() &&
         group.include_membership[protocol_path_id] != 0U);
    if (!include_match) {
        return false;
    }

    const bool exclude_match = group.has_exclude_predicates &&
        static_cast<std::size_t>(protocol_path_id) < group.exclude_membership.size() &&
        group.exclude_membership[protocol_path_id] != 0U;
    return !exclude_match;
}

bool matches_protocol_path_criteria(
    const CompiledAdvancedFlowFilterProtocolPathCriteria& criteria,
    const ProtocolPathId protocol_path_id
) noexcept {
    return matches_protocol_path_predicate_group(criteria.protocol_path_group, protocol_path_id) &&
        matches_protocol_path_predicate_group(criteria.contains_layer_group, protocol_path_id);
}

bool is_contains_layer_protocol_path_predicate(
    const AdvancedFlowFilterProtocolPathPredicate& predicate
) noexcept {
    return predicate.match_kind == AdvancedFlowFilterProtocolPathMatchKind::contains_layer;
}

void append_effective_protocol_path_predicates(
    std::vector<AdvancedFlowFilterProtocolPathPredicate>& destination,
    const std::vector<AdvancedFlowFilterProtocolPathPredicate>& source,
    const bool include_protocol_path_predicates,
    const bool include_contains_layer_predicates
) {
    for (const auto& predicate : source) {
        const bool is_contains_layer = is_contains_layer_protocol_path_predicate(predicate);
        if ((!is_contains_layer && include_protocol_path_predicates) ||
            (is_contains_layer && include_contains_layer_predicates)) {
            destination.push_back(predicate);
        }
    }
}

template <typename T>
std::size_t count_range_atomic_rules(
    const std::optional<AdvancedFlowFilterInclusiveRange<T>>& range
) noexcept {
    if (!range.has_value()) {
        return 0U;
    }

    std::size_t count = 0U;
    if (range->min.has_value()) {
        ++count;
    }
    if (range->max.has_value()) {
        ++count;
    }
    return count;
}

std::size_t count_aggregate_atomic_rules(const AdvancedFlowFilterAggregateCriteria& aggregate) noexcept {
    return count_range_atomic_rules(aggregate.packet_count) +
        count_range_atomic_rules(aggregate.original_bytes) +
        count_range_atomic_rules(aggregate.captured_bytes) +
        count_range_atomic_rules(aggregate.fragmented_packet_count) +
        count_range_atomic_rules(aggregate.truncated_packet_count) +
        count_range_atomic_rules(aggregate.tcp_syn_count) +
        count_range_atomic_rules(aggregate.tcp_fin_count) +
        count_range_atomic_rules(aggregate.tcp_rst_count) +
        count_range_atomic_rules(aggregate.max_original_packet_length) +
        count_range_atomic_rules(aggregate.max_captured_packet_length);
}

std::size_t count_time_atomic_rules(const AdvancedFlowFilterTimeCriteria& time) noexcept {
    return count_range_atomic_rules(time.start_us) +
        count_range_atomic_rules(time.end_us) +
        count_range_atomic_rules(time.overlap_us) +
        count_range_atomic_rules(time.duration_us);
}

}  // namespace

void AdvancedFlowFilterPortBitmap::set_range(const std::uint16_t first, const std::uint16_t last) {
    auto& storage = ensure_port_bitmap_storage(*this);
    for (std::uint32_t port = first; port <= last; ++port) {
        storage[port / 64U] |= (1ULL << (port % 64U));
    }
    active = true;
}

bool AdvancedFlowFilterPortBitmap::contains(const std::uint16_t port) const noexcept {
    if (!active || words.size() != kAdvancedFlowFilterPortBitmapWordCount) {
        return false;
    }
    return (words[port / 64U] & (1ULL << (port % 64U))) != 0U;
}

bool CompiledAdvancedFlowFilterServiceCriteria::has_include_predicates() const noexcept {
    return include_known || include_unknown || !include_text.empty();
}

bool CompiledAdvancedFlowFilterAddressCriteria::has_include_predicates() const noexcept {
    return !ipv4_include.empty() || !ipv6_include.empty();
}

bool CompiledAdvancedFlowFilterAddressCriteria::has_exclude_predicates() const noexcept {
    return !ipv4_exclude.empty() || !ipv6_exclude.empty();
}

AdvancedFlowFilterCompileResult compile_advanced_flow_filter(
    const AdvancedFlowFilterSpec& spec,
    const ProtocolPathRegistry& protocol_path_registry,
    const AnalysisSettings& settings
) {
    AdvancedFlowFilterCompileResult result {};

    if (const auto error =
            compile_protocol_path_criteria(spec.protocol_path, protocol_path_registry, result.filter.protocol_path);
        error.status != AdvancedFlowFilterCompileStatus::ok) {
        return error;
    }

    if (const auto error = compile_address_family_membership(spec.address_family, result.filter.address_family);
        error.status != AdvancedFlowFilterCompileStatus::ok) {
        return error;
    }
    compile_protocol_membership(spec.flow_protocol, result.filter.flow_protocol);
    compile_detected_protocol_membership(spec.detected_protocol, settings, result.filter.detected_protocol);
    compile_tls_version_membership(spec.tls_version, result.filter.tls_version);
    compile_quic_version_membership(spec.quic_version, result.filter.quic_version);

    if (const auto error = compile_port_criteria(spec.ports, result.filter.ports);
        error.status != AdvancedFlowFilterCompileStatus::ok) {
        return error;
    }

    if (const auto error = compile_directionality_criteria(spec.directionality, result.filter.directionality);
        error.status != AdvancedFlowFilterCompileStatus::ok) {
        return error;
    }

    if (const auto error = compile_address_criteria(spec.addresses, result.filter.addresses);
        error.status != AdvancedFlowFilterCompileStatus::ok) {
        return error;
    }

    if (const auto error = compile_time_criteria(spec.time, result.filter.time);
        error.status != AdvancedFlowFilterCompileStatus::ok) {
        return error;
    }

    if (const auto error = compile_aggregate_criteria(spec.aggregate, result.filter.aggregate);
        error.status != AdvancedFlowFilterCompileStatus::ok) {
        return error;
    }

    if (const auto error = compile_service_criteria(spec.service, result.filter.service);
        error.status != AdvancedFlowFilterCompileStatus::ok) {
        return error;
    }

    return result;
}

AdvancedFlowFilterResult evaluate_advanced_flow_filter(
    std::span<const ListedConnectionRef> connections,
    const CompiledAdvancedFlowFilter& filter,
    const std::optional<std::span<const std::size_t>> candidate_flow_indices
) {
    AdvancedFlowFilterResult result {};

    if (candidate_flow_indices.has_value()) {
        for (const auto index : *candidate_flow_indices) {
            if (index >= connections.size()) {
                result.status = AdvancedFlowFilterEvaluationStatus::invalid_candidate_index;
                result.invalid_candidate_index = index;
                result.matching_flow_indices.clear();
                return result;
            }
        }

        if (candidate_flow_indices->empty()) {
            return result;
        }

        std::vector<std::size_t> candidate_indices(candidate_flow_indices->begin(), candidate_flow_indices->end());
        std::sort(candidate_indices.begin(), candidate_indices.end());
        candidate_indices.erase(std::unique(candidate_indices.begin(), candidate_indices.end()), candidate_indices.end());
        result.matching_flow_indices.reserve(candidate_indices.size());

        for (const auto index : candidate_indices) {
            const auto& connection = connections[index];

            if (!matches_address_family_criteria(filter.address_family, connection.family)) {
                continue;
            }

            if (!matches_protocol_path_criteria(filter.protocol_path, connection_protocol_path_id(connection))) {
                continue;
            }

            if (!matches_protocol_membership(filter.flow_protocol, protocol_id(connection))) {
                continue;
            }

            AnalysisSettings hint_settings {};
            hint_settings.use_possible_tls_quic = filter.detected_protocol.use_possible_tls_quic;
            if (!matches_detected_protocol_membership(
                    filter.detected_protocol,
                    effective_protocol_hint(connection, hint_settings))) {
                continue;
            }

            if (!matches_tls_version_criteria(filter.tls_version, connection)) {
                continue;
            }

            if (!matches_quic_version_criteria(filter.quic_version, connection)) {
                continue;
            }

            const auto [endpoint_a_port, endpoint_b_port] = oriented_ports(connection);
            if (!matches_port_criteria(filter.ports, endpoint_a_port, endpoint_b_port)) {
                continue;
            }

            if (!matches_aggregate_criteria(filter.aggregate, connection)) {
                continue;
            }

            if (!matches_directionality_criteria(filter.directionality, connection)) {
                continue;
            }

            if (!matches_address_criteria(filter.addresses, connection)) {
                continue;
            }

            if (!matches_time_criteria(filter.time, connection)) {
                continue;
            }

            if (!matches_service_criteria(filter.service, service_hint_value(connection))) {
                continue;
            }

            result.matching_flow_indices.push_back(index);
        }

        return result;
    }

    result.matching_flow_indices.reserve(connections.size());

    for (std::size_t index = 0; index < connections.size(); ++index) {
        const auto& connection = connections[index];

        if (!matches_address_family_criteria(filter.address_family, connection.family)) {
            continue;
        }

        if (!matches_protocol_path_criteria(filter.protocol_path, connection_protocol_path_id(connection))) {
            continue;
        }

        if (!matches_protocol_membership(filter.flow_protocol, protocol_id(connection))) {
            continue;
        }

        AnalysisSettings hint_settings {};
        hint_settings.use_possible_tls_quic = filter.detected_protocol.use_possible_tls_quic;
        if (!matches_detected_protocol_membership(
                filter.detected_protocol,
                effective_protocol_hint(connection, hint_settings))) {
            continue;
        }

        if (!matches_tls_version_criteria(filter.tls_version, connection)) {
            continue;
        }

        if (!matches_quic_version_criteria(filter.quic_version, connection)) {
            continue;
        }

        const auto [endpoint_a_port, endpoint_b_port] = oriented_ports(connection);
        if (!matches_port_criteria(filter.ports, endpoint_a_port, endpoint_b_port)) {
            continue;
        }

        if (!matches_aggregate_criteria(filter.aggregate, connection)) {
            continue;
        }

        if (!matches_directionality_criteria(filter.directionality, connection)) {
            continue;
        }

        if (!matches_address_criteria(filter.addresses, connection)) {
            continue;
        }

        if (!matches_time_criteria(filter.time, connection)) {
            continue;
        }

        if (!matches_service_criteria(filter.service, service_hint_value(connection))) {
            continue;
        }

        result.matching_flow_indices.push_back(index);
    }

    return result;
}

AdvancedFlowFilterSpec make_effective_advanced_flow_filter_spec(
    const AdvancedFlowFilterDocument& document
) {
    AdvancedFlowFilterSpec effective = document.configured_spec;
    const auto& section_states = document.section_states;

    if (!section_states.address_family) {
        effective.address_family = {};
    }
    if (!section_states.flow_protocol) {
        effective.flow_protocol = {};
    }
    if (!section_states.detected_protocol) {
        effective.detected_protocol = {};
    }
    if (!section_states.tls_version) {
        effective.tls_version = {};
    }
    if (!section_states.quic_version) {
        effective.quic_version = {};
    }
    if (!section_states.directionality) {
        effective.directionality = {};
    }
    if (!section_states.ports) {
        effective.ports = {};
    }
    if (!section_states.ip_addresses) {
        effective.addresses = {};
    }
    if (!section_states.time) {
        effective.time = {};
    }
    if (!section_states.traffic) {
        effective.aggregate = {};
    }
    if (!section_states.service) {
        effective.service = {};
    }

    effective.protocol_path = {};
    append_effective_protocol_path_predicates(
        effective.protocol_path.include,
        document.configured_spec.protocol_path.include,
        section_states.protocol_path,
        section_states.contains_layer
    );
    append_effective_protocol_path_predicates(
        effective.protocol_path.exclude,
        document.configured_spec.protocol_path.exclude,
        section_states.protocol_path,
        section_states.contains_layer
    );

    return effective;
}

std::size_t count_advanced_flow_filter_atomic_rules(const AdvancedFlowFilterSpec& spec) noexcept {
    return spec.protocol_path.include.size() +
        spec.protocol_path.exclude.size() +
        spec.address_family.include.size() +
        spec.address_family.exclude.size() +
        spec.flow_protocol.include.size() +
        spec.flow_protocol.exclude.size() +
        spec.detected_protocol.include.size() +
        spec.detected_protocol.exclude.size() +
        spec.tls_version.include.size() +
        spec.tls_version.exclude.size() +
        spec.quic_version.include.size() +
        spec.quic_version.exclude.size() +
        spec.ports.include.size() +
        spec.ports.exclude.size() +
        spec.directionality.include.size() +
        spec.directionality.exclude.size() +
        spec.addresses.ipv4_include.size() +
        spec.addresses.ipv4_exclude.size() +
        spec.addresses.ipv6_include.size() +
        spec.addresses.ipv6_exclude.size() +
        count_time_atomic_rules(spec.time) +
        count_aggregate_atomic_rules(spec.aggregate) +
        spec.service.include.size() +
        spec.service.exclude.size();
}

std::size_t count_configured_advanced_flow_filter_atomic_rules(
    const AdvancedFlowFilterDocument& document
) noexcept {
    return count_advanced_flow_filter_atomic_rules(document.configured_spec);
}

std::size_t count_active_advanced_flow_filter_atomic_rules(
    const AdvancedFlowFilterDocument& document
) {
    return count_advanced_flow_filter_atomic_rules(make_effective_advanced_flow_filter_spec(document));
}

bool is_default_advanced_flow_filter_document(const AdvancedFlowFilterDocument& document) noexcept {
    return count_configured_advanced_flow_filter_atomic_rules(document) == 0U &&
        document.section_states == AdvancedFlowFilterDocumentSectionStates {};
}

}  // namespace pfl::session_detail
