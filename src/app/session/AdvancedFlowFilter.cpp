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

bool matches_detected_protocol_membership(
    const CompiledAdvancedFlowFilterDetectedProtocolCriteria& criteria,
    const FlowProtocolHint protocol_hint
) noexcept {
    const auto index = static_cast<std::size_t>(protocol_hint);
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
    const auto duration_us = stats.last_timestamp_us >= stats.first_timestamp_us
        ? (stats.last_timestamp_us - stats.first_timestamp_us)
        : 0U;

    return matches_range(criteria.ranges.packet_count, packet_count(connection)) &&
        matches_range(criteria.ranges.original_bytes, total_bytes(connection)) &&
        matches_range(criteria.ranges.captured_bytes, stats.captured_bytes) &&
        matches_range(criteria.ranges.duration_us, duration_us) &&
        matches_range(criteria.ranges.fragmented_packet_count, fragmented_packet_count_value(connection)) &&
        matches_range(criteria.ranges.truncated_packet_count, stats.truncated_packet_count) &&
        matches_range(criteria.ranges.tcp_syn_count, stats.tcp_syn_count) &&
        matches_range(criteria.ranges.tcp_fin_count, stats.tcp_fin_count) &&
        matches_range(criteria.ranges.tcp_rst_count, stats.tcp_rst_count) &&
        matches_range(criteria.ranges.max_original_packet_length, stats.max_original_packet_length) &&
        matches_range(criteria.ranges.max_captured_packet_length, stats.max_captured_packet_length);
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

bool matches_service_criteria(
    const CompiledAdvancedFlowFilterServiceCriteria& criteria,
    const std::string_view service_hint
) noexcept {
    const bool known = !service_hint.empty();

    bool include_match = !criteria.has_include_predicates();
    if (!include_match) {
        include_match = (criteria.include_known && known) || (criteria.include_unknown && !known);
        if (!include_match) {
            for (const auto& predicate : criteria.include_text) {
                if (matches_service_text_predicate(service_hint, predicate)) {
                    include_match = true;
                    break;
                }
            }
        }
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
    compiled.has_include_predicates = !spec.include.empty();
    compiled.has_exclude_predicates = !spec.exclude.empty();

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

    if (!compiled.has_include_predicates && !compiled.has_exclude_predicates) {
        return {};
    }

    compiled.include_membership.assign(registry.size() + 1U, 0U);
    compiled.exclude_membership.assign(registry.size() + 1U, 0U);

    const auto& paths = registry.paths();
    for (std::size_t index = 0; index < paths.size(); ++index) {
        const auto id = static_cast<ProtocolPathId>(index + 1U);
        for (const auto& predicate : spec.include) {
            if (matches_protocol_path_predicate(paths[index], predicate)) {
                compiled.include_membership[id] = 1U;
                break;
            }
        }

        for (const auto& predicate : spec.exclude) {
            if (matches_protocol_path_predicate(paths[index], predicate)) {
                compiled.exclude_membership[id] = 1U;
                break;
            }
        }
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
    if (const auto error = validate_range_field(spec.duration_us, "aggregate.duration_us")) {
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

void compile_directionality_criteria(
    const AdvancedFlowFilterDirectionalityCriteria& spec,
    CompiledAdvancedFlowFilterDirectionalityCriteria& compiled
) {
    compiled.has_include_predicates = !spec.include.empty();
    compiled.has_exclude_predicates = !spec.exclude.empty();

    for (const auto value : spec.include) {
        compiled.include_membership[static_cast<std::size_t>(value)] = true;
    }

    for (const auto value : spec.exclude) {
        compiled.exclude_membership[static_cast<std::size_t>(value)] = true;
    }
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

bool matches_protocol_path_criteria(
    const CompiledAdvancedFlowFilterProtocolPathCriteria& criteria,
    const ProtocolPathId protocol_path_id
) noexcept {
    const bool include_match = !criteria.has_include_predicates ||
        (static_cast<std::size_t>(protocol_path_id) < criteria.include_membership.size() &&
         criteria.include_membership[protocol_path_id] != 0U);

    if (!include_match) {
        return false;
    }

    const bool exclude_match = criteria.has_exclude_predicates &&
        static_cast<std::size_t>(protocol_path_id) < criteria.exclude_membership.size() &&
        criteria.exclude_membership[protocol_path_id] != 0U;
    return !exclude_match;
}

}  // namespace

void AdvancedFlowFilterPortBitmap::set_range(const std::uint16_t first, const std::uint16_t last) noexcept {
    active = true;
    for (std::uint32_t port = first; port <= last; ++port) {
        words[port / 64U] |= (1ULL << (port % 64U));
    }
}

bool AdvancedFlowFilterPortBitmap::contains(const std::uint16_t port) const noexcept {
    if (!active) {
        return false;
    }
    return (words[port / 64U] & (1ULL << (port % 64U))) != 0U;
}

bool CompiledAdvancedFlowFilterServiceCriteria::has_include_predicates() const noexcept {
    return include_known || include_unknown || !include_text.empty();
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

    compile_protocol_membership(spec.flow_protocol, result.filter.flow_protocol);
    compile_detected_protocol_membership(spec.detected_protocol, settings, result.filter.detected_protocol);

    if (const auto error = compile_port_criteria(spec.ports, result.filter.ports);
        error.status != AdvancedFlowFilterCompileStatus::ok) {
        return error;
    }

    if (const auto error = compile_aggregate_criteria(spec.aggregate, result.filter.aggregate);
        error.status != AdvancedFlowFilterCompileStatus::ok) {
        return error;
    }

    compile_directionality_criteria(spec.directionality, result.filter.directionality);

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

    std::vector<std::uint8_t> candidate_membership {};
    if (candidate_flow_indices.has_value()) {
        candidate_membership.assign(connections.size(), 0U);
        for (const auto index : *candidate_flow_indices) {
            if (index >= connections.size()) {
                result.status = AdvancedFlowFilterEvaluationStatus::invalid_candidate_index;
                result.invalid_candidate_index = index;
                result.matching_flow_indices.clear();
                return result;
            }
            candidate_membership[index] = 1U;
        }
    }

    result.matching_flow_indices.reserve(candidate_flow_indices.has_value() ? candidate_flow_indices->size() : connections.size());

    for (std::size_t index = 0; index < connections.size(); ++index) {
        if (candidate_flow_indices.has_value() && candidate_membership[index] == 0U) {
            continue;
        }

        const auto& connection = connections[index];

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

        if (!matches_service_criteria(filter.service, service_hint_value(connection))) {
            continue;
        }

        result.matching_flow_indices.push_back(index);
    }

    return result;
}

}  // namespace pfl::session_detail
