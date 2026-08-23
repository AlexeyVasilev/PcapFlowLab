#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "app/session/SessionFlowHelpers.h"
#include "core/domain/FlowHints.h"
#include "core/domain/ProtocolId.h"
#include "core/domain/ProtocolPath.h"
#include "core/services/AnalysisSettings.h"

namespace pfl::session_detail {

template <typename T>
struct AdvancedFlowFilterInclusiveRange {
    std::optional<T> min {};
    std::optional<T> max {};

    bool operator==(const AdvancedFlowFilterInclusiveRange&) const = default;
};

enum class AdvancedFlowFilterProtocolPathMatchKind : std::uint8_t {
    exact_path = 0,
    path_prefix,
    contains_layer,
};

struct AdvancedFlowFilterProtocolLayerPredicate {
    ProtocolLayerKind kind {ProtocolLayerKind::unknown};
    std::optional<ProtocolLayerIdentifier> identifier {};

    bool operator==(const AdvancedFlowFilterProtocolLayerPredicate&) const = default;
};

struct AdvancedFlowFilterProtocolPathPredicate {
    AdvancedFlowFilterProtocolPathMatchKind match_kind {AdvancedFlowFilterProtocolPathMatchKind::exact_path};
    std::vector<AdvancedFlowFilterProtocolLayerPredicate> layers {};

    bool operator==(const AdvancedFlowFilterProtocolPathPredicate&) const = default;
};

struct AdvancedFlowFilterProtocolPathCriteria {
    std::vector<AdvancedFlowFilterProtocolPathPredicate> include {};
    std::vector<AdvancedFlowFilterProtocolPathPredicate> exclude {};

    bool operator==(const AdvancedFlowFilterProtocolPathCriteria&) const = default;
};

struct AdvancedFlowFilterAddressFamilyCriteria {
    std::vector<FlowAddressFamily> include {};
    std::vector<FlowAddressFamily> exclude {};

    bool operator==(const AdvancedFlowFilterAddressFamilyCriteria&) const = default;
};

struct AdvancedFlowFilterProtocolCriteria {
    std::vector<ProtocolId> include {};
    std::vector<ProtocolId> exclude {};

    bool operator==(const AdvancedFlowFilterProtocolCriteria&) const = default;
};

struct AdvancedFlowFilterDetectedProtocolCriteria {
    std::vector<FlowProtocolHint> include {};
    std::vector<FlowProtocolHint> exclude {};

    bool operator==(const AdvancedFlowFilterDetectedProtocolCriteria&) const = default;
};

enum class AdvancedFlowFilterEndpointScope : std::uint8_t {
    either_endpoint = 0,
    endpoint_a,
    endpoint_b,
};

enum class AdvancedFlowFilterAddressMatchKind : std::uint8_t {
    exact = 0,
    cidr,
};

struct AdvancedFlowFilterIpv4AddressPredicate {
    AdvancedFlowFilterAddressMatchKind match_kind {AdvancedFlowFilterAddressMatchKind::exact};
    AdvancedFlowFilterEndpointScope scope {AdvancedFlowFilterEndpointScope::either_endpoint};
    std::uint32_t value {0};
    std::uint8_t prefix_length {32};

    bool operator==(const AdvancedFlowFilterIpv4AddressPredicate&) const = default;
};

struct AdvancedFlowFilterIpv6AddressPredicate {
    AdvancedFlowFilterAddressMatchKind match_kind {AdvancedFlowFilterAddressMatchKind::exact};
    AdvancedFlowFilterEndpointScope scope {AdvancedFlowFilterEndpointScope::either_endpoint};
    std::array<std::uint8_t, 16> value {};
    std::uint8_t prefix_length {128};

    bool operator==(const AdvancedFlowFilterIpv6AddressPredicate&) const = default;
};

struct AdvancedFlowFilterAddressCriteria {
    std::vector<AdvancedFlowFilterIpv4AddressPredicate> ipv4_include {};
    std::vector<AdvancedFlowFilterIpv4AddressPredicate> ipv4_exclude {};
    std::vector<AdvancedFlowFilterIpv6AddressPredicate> ipv6_include {};
    std::vector<AdvancedFlowFilterIpv6AddressPredicate> ipv6_exclude {};

    bool operator==(const AdvancedFlowFilterAddressCriteria&) const = default;
};

struct AdvancedFlowFilterTlsVersionCriteria {
    std::vector<TlsVersionHint> include {};
    std::vector<TlsVersionHint> exclude {};

    bool operator==(const AdvancedFlowFilterTlsVersionCriteria&) const = default;
};

struct AdvancedFlowFilterQuicVersionCriteria {
    std::vector<QuicVersionHint> include {};
    std::vector<QuicVersionHint> exclude {};

    bool operator==(const AdvancedFlowFilterQuicVersionCriteria&) const = default;
};

enum class AdvancedFlowFilterPortScope : std::uint8_t {
    either_endpoint = 0,
    endpoint_a,
    endpoint_b,
};

struct AdvancedFlowFilterPortRange {
    std::uint16_t first {0};
    std::uint16_t last {0};

    bool operator==(const AdvancedFlowFilterPortRange&) const = default;
};

struct AdvancedFlowFilterPortPredicate {
    AdvancedFlowFilterPortScope scope {AdvancedFlowFilterPortScope::either_endpoint};
    AdvancedFlowFilterPortRange range {};

    bool operator==(const AdvancedFlowFilterPortPredicate&) const = default;
};

struct AdvancedFlowFilterPortCriteria {
    std::vector<AdvancedFlowFilterPortPredicate> include {};
    std::vector<AdvancedFlowFilterPortPredicate> exclude {};

    bool operator==(const AdvancedFlowFilterPortCriteria&) const = default;
};

struct AdvancedFlowFilterAggregateCriteria {
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint64_t>> packet_count {};
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint64_t>> original_bytes {};
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint64_t>> captured_bytes {};
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint64_t>> duration_us {};
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint64_t>> fragmented_packet_count {};
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint64_t>> truncated_packet_count {};
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint64_t>> tcp_syn_count {};
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint64_t>> tcp_fin_count {};
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint64_t>> tcp_rst_count {};
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint32_t>> max_original_packet_length {};
    std::optional<AdvancedFlowFilterInclusiveRange<std::uint32_t>> max_captured_packet_length {};

    bool operator==(const AdvancedFlowFilterAggregateCriteria&) const = default;
};

enum class AdvancedFlowFilterDirectionality : std::uint8_t {
    unidirectional = 0,
    bidirectional,
};

struct AdvancedFlowFilterDirectionalityCriteria {
    std::vector<AdvancedFlowFilterDirectionality> include {};
    std::vector<AdvancedFlowFilterDirectionality> exclude {};

    bool operator==(const AdvancedFlowFilterDirectionalityCriteria&) const = default;
};

enum class AdvancedFlowFilterStringCaseSensitivity : std::uint8_t {
    ascii_case_insensitive = 0,
    case_sensitive,
};

enum class AdvancedFlowFilterServicePredicateKind : std::uint8_t {
    known = 0,
    unknown,
    equals,
    starts_with,
    contains,
};

struct AdvancedFlowFilterServicePredicate {
    AdvancedFlowFilterServicePredicateKind kind {AdvancedFlowFilterServicePredicateKind::known};
    std::string value {};
    AdvancedFlowFilterStringCaseSensitivity case_sensitivity {
        AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive
    };

    bool operator==(const AdvancedFlowFilterServicePredicate&) const = default;
};

struct AdvancedFlowFilterServiceCriteria {
    std::vector<AdvancedFlowFilterServicePredicate> include {};
    std::vector<AdvancedFlowFilterServicePredicate> exclude {};

    bool operator==(const AdvancedFlowFilterServiceCriteria&) const = default;
};

struct AdvancedFlowFilterSpec {
    AdvancedFlowFilterProtocolPathCriteria protocol_path {};
    AdvancedFlowFilterAddressFamilyCriteria address_family {};
    AdvancedFlowFilterProtocolCriteria flow_protocol {};
    AdvancedFlowFilterDetectedProtocolCriteria detected_protocol {};
    AdvancedFlowFilterTlsVersionCriteria tls_version {};
    AdvancedFlowFilterQuicVersionCriteria quic_version {};
    AdvancedFlowFilterPortCriteria ports {};
    AdvancedFlowFilterAggregateCriteria aggregate {};
    AdvancedFlowFilterDirectionalityCriteria directionality {};
    AdvancedFlowFilterAddressCriteria addresses {};
    AdvancedFlowFilterServiceCriteria service {};

    bool operator==(const AdvancedFlowFilterSpec&) const = default;
};

struct AdvancedFlowFilterDocumentSectionStates {
    bool address_family {true};
    bool flow_protocol {true};
    bool detected_protocol {true};
    bool tls_version {true};
    bool quic_version {true};
    bool directionality {true};
    bool ports {true};
    bool ip_addresses {true};
    bool traffic {true};
    bool service {true};
    bool protocol_path {true};
    bool contains_layer {true};

    bool operator==(const AdvancedFlowFilterDocumentSectionStates&) const = default;
};

struct AdvancedFlowFilterDocument {
    AdvancedFlowFilterSpec configured_spec {};
    AdvancedFlowFilterDocumentSectionStates section_states {};

    bool operator==(const AdvancedFlowFilterDocument&) const = default;
};

enum class AdvancedFlowFilterCompileStatus : std::uint8_t {
    ok = 0,
    invalid_numeric_range,
    invalid_protocol_path_predicate,
    invalid_address_predicate,
    invalid_service_predicate,
    invalid_directionality_predicate,
};

struct AdvancedFlowFilterCompileIssue {
    AdvancedFlowFilterCompileStatus status {AdvancedFlowFilterCompileStatus::ok};
    std::string category {};
    std::optional<std::size_t> predicate_index {};
};

struct AdvancedFlowFilterPortBitmap {
    std::array<std::uint64_t, 1024> words {};
    bool active {false};

    void set_range(std::uint16_t first, std::uint16_t last) noexcept;
    [[nodiscard]] bool contains(std::uint16_t port) const noexcept;
};

struct CompiledAdvancedFlowFilterProtocolPathPredicateGroup {
    std::vector<std::uint8_t> include_membership {};
    std::vector<std::uint8_t> exclude_membership {};
    bool has_include_predicates {false};
    bool has_exclude_predicates {false};
};

struct CompiledAdvancedFlowFilterProtocolPathCriteria {
    CompiledAdvancedFlowFilterProtocolPathPredicateGroup protocol_path_group {};
    CompiledAdvancedFlowFilterProtocolPathPredicateGroup contains_layer_group {};
};

struct CompiledAdvancedFlowFilterAddressFamilyCriteria {
    std::array<bool, 2> include_membership {};
    std::array<bool, 2> exclude_membership {};
    bool has_include_predicates {false};
    bool has_exclude_predicates {false};
};

struct CompiledAdvancedFlowFilterProtocolCriteria {
    std::array<bool, 256> include_membership {};
    std::array<bool, 256> exclude_membership {};
    bool has_include_predicates {false};
    bool has_exclude_predicates {false};
};

struct CompiledAdvancedFlowFilterDetectedProtocolCriteria {
    std::array<bool, 256> include_membership {};
    std::array<bool, 256> exclude_membership {};
    bool has_include_predicates {false};
    bool has_exclude_predicates {false};
    bool use_possible_tls_quic {false};
};

struct CompiledAdvancedFlowFilterTlsVersionCriteria {
    std::array<bool, 256> include_membership {};
    std::array<bool, 256> exclude_membership {};
    bool has_include_predicates {false};
    bool has_exclude_predicates {false};
};

struct CompiledAdvancedFlowFilterQuicVersionCriteria {
    std::array<bool, 256> include_membership {};
    std::array<bool, 256> exclude_membership {};
    bool has_include_predicates {false};
    bool has_exclude_predicates {false};
};

struct CompiledAdvancedFlowFilterPortCriteria {
    AdvancedFlowFilterPortBitmap include_either {};
    AdvancedFlowFilterPortBitmap include_a {};
    AdvancedFlowFilterPortBitmap include_b {};
    AdvancedFlowFilterPortBitmap exclude_either {};
    AdvancedFlowFilterPortBitmap exclude_a {};
    AdvancedFlowFilterPortBitmap exclude_b {};
};

struct CompiledAdvancedFlowFilterAggregateCriteria {
    AdvancedFlowFilterAggregateCriteria ranges {};
};

struct CompiledAdvancedFlowFilterDirectionalityCriteria {
    std::array<bool, 2> include_membership {};
    std::array<bool, 2> exclude_membership {};
    bool has_include_predicates {false};
    bool has_exclude_predicates {false};
};

struct CompiledAdvancedFlowFilterIpv4CidrPredicate {
    AdvancedFlowFilterEndpointScope scope {AdvancedFlowFilterEndpointScope::either_endpoint};
    std::uint32_t network {0};
    std::uint32_t mask {0};
    std::uint8_t prefix_length {0};
};

struct CompiledAdvancedFlowFilterIpv6CidrPredicate {
    AdvancedFlowFilterEndpointScope scope {AdvancedFlowFilterEndpointScope::either_endpoint};
    std::array<std::uint8_t, 16> network {};
    std::uint8_t prefix_length {0};
};

struct CompiledAdvancedFlowFilterAddressCriteria {
    std::vector<CompiledAdvancedFlowFilterIpv4CidrPredicate> ipv4_include {};
    std::vector<CompiledAdvancedFlowFilterIpv4CidrPredicate> ipv4_exclude {};
    std::vector<CompiledAdvancedFlowFilterIpv6CidrPredicate> ipv6_include {};
    std::vector<CompiledAdvancedFlowFilterIpv6CidrPredicate> ipv6_exclude {};

    [[nodiscard]] bool has_include_predicates() const noexcept;
    [[nodiscard]] bool has_exclude_predicates() const noexcept;
};

struct CompiledAdvancedFlowFilterServicePredicate {
    AdvancedFlowFilterServicePredicateKind kind {AdvancedFlowFilterServicePredicateKind::known};
    std::string value {};
    AdvancedFlowFilterStringCaseSensitivity case_sensitivity {
        AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive
    };
};

struct CompiledAdvancedFlowFilterServiceCriteria {
    bool include_known {false};
    bool include_unknown {false};
    bool exclude_known {false};
    bool exclude_unknown {false};
    std::vector<CompiledAdvancedFlowFilterServicePredicate> include_text {};
    std::vector<CompiledAdvancedFlowFilterServicePredicate> exclude_text {};

    [[nodiscard]] bool has_include_predicates() const noexcept;
};

struct CompiledAdvancedFlowFilter {
    CompiledAdvancedFlowFilterProtocolPathCriteria protocol_path {};
    CompiledAdvancedFlowFilterAddressFamilyCriteria address_family {};
    CompiledAdvancedFlowFilterProtocolCriteria flow_protocol {};
    CompiledAdvancedFlowFilterDetectedProtocolCriteria detected_protocol {};
    CompiledAdvancedFlowFilterTlsVersionCriteria tls_version {};
    CompiledAdvancedFlowFilterQuicVersionCriteria quic_version {};
    CompiledAdvancedFlowFilterPortCriteria ports {};
    CompiledAdvancedFlowFilterAggregateCriteria aggregate {};
    CompiledAdvancedFlowFilterDirectionalityCriteria directionality {};
    CompiledAdvancedFlowFilterAddressCriteria addresses {};
    CompiledAdvancedFlowFilterServiceCriteria service {};
};

struct AdvancedFlowFilterCompileResult {
    AdvancedFlowFilterCompileStatus status {AdvancedFlowFilterCompileStatus::ok};
    CompiledAdvancedFlowFilter filter {};
    std::optional<AdvancedFlowFilterCompileIssue> issue {};
};

enum class AdvancedFlowFilterEvaluationStatus : std::uint8_t {
    ok = 0,
    invalid_candidate_index,
};

struct AdvancedFlowFilterResult {
    AdvancedFlowFilterEvaluationStatus status {AdvancedFlowFilterEvaluationStatus::ok};
    std::vector<std::size_t> matching_flow_indices {};
    std::optional<std::size_t> invalid_candidate_index {};
};

enum class AdvancedFlowQueryStatus : std::uint8_t {
    ok = 0,
    invalid_flow_index,
    invalid_limit,
    invalid_advanced_filter,
};

struct AdvancedFlowQueryResult {
    AdvancedFlowQueryStatus status {AdvancedFlowQueryStatus::ok};
    std::vector<std::size_t> ordered_flow_indices {};
    std::size_t result_count_before_limit {0U};
    std::optional<std::size_t> invalid_flow_index {};
    AdvancedFlowFilterCompileStatus compile_status {AdvancedFlowFilterCompileStatus::ok};
    std::optional<AdvancedFlowFilterCompileIssue> compile_issue {};
};

[[nodiscard]] AdvancedFlowFilterCompileResult compile_advanced_flow_filter(
    const AdvancedFlowFilterSpec& spec,
    const ProtocolPathRegistry& protocol_path_registry,
    const AnalysisSettings& settings
);

[[nodiscard]] AdvancedFlowFilterResult evaluate_advanced_flow_filter(
    std::span<const ListedConnectionRef> connections,
    const CompiledAdvancedFlowFilter& filter,
    std::optional<std::span<const std::size_t>> candidate_flow_indices = std::nullopt
);

[[nodiscard]] AdvancedFlowFilterSpec make_effective_advanced_flow_filter_spec(
    const AdvancedFlowFilterDocument& document
);

[[nodiscard]] std::size_t count_advanced_flow_filter_atomic_rules(
    const AdvancedFlowFilterSpec& spec
) noexcept;

[[nodiscard]] std::size_t count_configured_advanced_flow_filter_atomic_rules(
    const AdvancedFlowFilterDocument& document
) noexcept;

[[nodiscard]] std::size_t count_active_advanced_flow_filter_atomic_rules(
    const AdvancedFlowFilterDocument& document
);

[[nodiscard]] bool is_default_advanced_flow_filter_document(
    const AdvancedFlowFilterDocument& document
) noexcept;

}  // namespace pfl::session_detail
