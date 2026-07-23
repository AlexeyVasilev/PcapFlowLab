#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "core/dissection/DissectionTypes.h"
#include "core/domain/CaptureState.h"
#include "core/domain/Connection.h"
#include "core/domain/ConnectionKey.h"
#include "core/domain/Flow.h"
#include "core/domain/FlowHints.h"
#include "core/domain/FlowKey.h"
#include "core/domain/PacketRef.h"
#include "core/domain/ProtocolPath.h"
#include "core/domain/ProtocolId.h"

namespace pfl {

struct ImportValidationOptions {
    std::optional<std::uint64_t> max_packets {};
    std::optional<std::uint64_t> packet_index {};
    bool include_hints {true};
    std::size_t max_reported_mismatches {32U};
};

struct ImportValidationHintState {
    std::uint8_t unresolved_payload_attempt_count {0U};
    bool unresolved_payload_attempt_budget_exhausted {false};

    [[nodiscard]] friend constexpr bool operator==(const ImportValidationHintState&, const ImportValidationHintState&) = default;
};

struct ImportValidationFlowSnapshotV4 {
    FlowKeyV4 key {};
    ProtocolPath protocol_path {};
    std::vector<PacketRef> packets {};
    std::uint64_t packet_count {0U};
    std::uint64_t total_bytes {0U};

    [[nodiscard]] friend bool operator==(const ImportValidationFlowSnapshotV4&, const ImportValidationFlowSnapshotV4&) = default;
};

struct ImportValidationFlowSnapshotV6 {
    FlowKeyV6 key {};
    ProtocolPath protocol_path {};
    std::vector<PacketRef> packets {};
    std::uint64_t packet_count {0U};
    std::uint64_t total_bytes {0U};

    [[nodiscard]] friend bool operator==(const ImportValidationFlowSnapshotV6&, const ImportValidationFlowSnapshotV6&) = default;
};

struct ImportValidationConnectionSnapshotV4 {
    ConnectionKeyV4 key {};
    ProtocolPath protocol_path {};
    std::optional<ImportValidationFlowSnapshotV4> flow_a {};
    std::optional<ImportValidationFlowSnapshotV4> flow_b {};
    std::uint64_t packet_count {0U};
    std::uint64_t total_bytes {0U};
    bool has_fragmented_packets {false};
    std::uint64_t fragmented_packet_count {0U};
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    QuicVersionHint quic_version {QuicVersionHint::unknown};
    TlsVersionHint tls_version {TlsVersionHint::unknown};
    ImportValidationHintState hint_search_state {};

    [[nodiscard]] friend bool operator==(const ImportValidationConnectionSnapshotV4&, const ImportValidationConnectionSnapshotV4&) = default;
};

struct ImportValidationConnectionSnapshotV6 {
    ConnectionKeyV6 key {};
    ProtocolPath protocol_path {};
    std::optional<ImportValidationFlowSnapshotV6> flow_a {};
    std::optional<ImportValidationFlowSnapshotV6> flow_b {};
    std::uint64_t packet_count {0U};
    std::uint64_t total_bytes {0U};
    bool has_fragmented_packets {false};
    std::uint64_t fragmented_packet_count {0U};
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    QuicVersionHint quic_version {QuicVersionHint::unknown};
    TlsVersionHint tls_version {TlsVersionHint::unknown};
    ImportValidationHintState hint_search_state {};

    [[nodiscard]] friend bool operator==(const ImportValidationConnectionSnapshotV6&, const ImportValidationConnectionSnapshotV6&) = default;
};

struct ImportValidationUnrecognizedSnapshot {
    PacketRef packet {};
    std::string reason_text {};

    [[nodiscard]] friend bool operator==(const ImportValidationUnrecognizedSnapshot&, const ImportValidationUnrecognizedSnapshot&) = default;
};

struct ImportValidationCanonicalState {
    CaptureSummary summary {};
    std::vector<ProtocolPath> protocol_registry_paths {};
    std::vector<ImportValidationFlowSnapshotV4> ipv4_flows {};
    std::vector<ImportValidationFlowSnapshotV6> ipv6_flows {};
    std::vector<ImportValidationConnectionSnapshotV4> ipv4_connections {};
    std::vector<ImportValidationConnectionSnapshotV6> ipv6_connections {};
    std::vector<ImportValidationUnrecognizedSnapshot> unrecognized_packets {};
};

enum class ImportValidationMismatchCategory : std::uint8_t {
    summary = 0,
    registry,
    connection,
    flow,
    packet_ref,
    unrecognized,
    hint,
};

struct ImportValidationMismatch {
    ImportValidationMismatchCategory category {ImportValidationMismatchCategory::summary};
    std::string entity {};
    std::string field {};
    std::string legacy_value {};
    std::string unified_value {};
};

enum class ImportValidationPacketClassification : std::uint8_t {
    recognized_flow = 0,
    recognized_non_flow,
    unrecognized,
};

struct ImportValidationPacketObservation {
    std::uint64_t packet_index {0U};
    std::uint64_t file_offset {0U};
    std::uint32_t captured_length {0U};
    std::uint32_t original_length {0U};
    std::uint32_t link_type {0U};

    ImportValidationPacketClassification classification {ImportValidationPacketClassification::unrecognized};
    dissection::DissectionAddressFamily family {dissection::DissectionAddressFamily::unknown};
    ProtocolId protocol {ProtocolId::unknown};

    bool has_addresses {false};
    std::uint32_t src_addr_v4 {0U};
    std::uint32_t dst_addr_v4 {0U};
    std::array<std::uint8_t, 16> src_addr_v6 {};
    std::array<std::uint8_t, 16> dst_addr_v6 {};

    bool has_ports {false};
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};

    bool has_transport_payload_length {false};
    std::uint32_t captured_transport_payload_length {0U};

    bool has_tcp_flags {false};
    std::uint8_t tcp_flags {0U};
    bool fragmented {false};

    ProtocolPath physical_path {};
    dissection::ParseStatus final_status {dissection::ParseStatus::opaque};
    dissection::StopReason stop_reason {dissection::StopReason::none};
    std::optional<std::string> unrecognized_reason {};

    [[nodiscard]] friend bool operator==(const ImportValidationPacketObservation&, const ImportValidationPacketObservation&) = default;
};

enum class ImportValidationPacketMismatchCategory : std::uint8_t {
    classification = 0,
    address_family,
    addresses,
    ports,
    protocol,
    payload_length,
    tcp_flags,
    fragmentation,
    physical_path,
    parse_status,
    stop_reason,
    unrecognized_reason,
};

struct ImportValidationPacketMismatch {
    std::uint64_t packet_index {0U};
    std::uint64_t file_offset {0U};
    std::uint32_t captured_length {0U};
    std::uint32_t original_length {0U};
    ImportValidationPacketMismatchCategory category {ImportValidationPacketMismatchCategory::classification};
    std::string legacy_value {};
    std::string unified_value {};
    ProtocolPath legacy_path {};
    ProtocolPath unified_path {};
    ImportValidationPacketObservation legacy_observation {};
    ImportValidationPacketObservation unified_observation {};
};

struct ImportValidationPacketMismatchGroup {
    ImportValidationPacketMismatchCategory category {ImportValidationPacketMismatchCategory::classification};
    ProtocolId legacy_protocol {ProtocolId::unknown};
    ProtocolId unified_protocol {ProtocolId::unknown};
    ProtocolPath legacy_path {};
    ProtocolPath unified_path {};
    std::optional<std::int64_t> numeric_delta {};
    std::size_t occurrence_count {0U};
    std::vector<std::uint64_t> packet_indices {};
    ImportValidationPacketMismatch representative {};
};

struct ImportValidationFirstDivergence {
    std::optional<std::uint64_t> any_packet_index {};
    std::optional<std::uint64_t> classification_packet_index {};
    std::optional<std::uint64_t> physical_path_packet_index {};
    std::optional<std::uint64_t> payload_length_packet_index {};
};

struct ImportValidationPacketCompareResult {
    std::size_t mismatch_count {0U};
    std::vector<ImportValidationPacketMismatch> mismatches {};
    std::vector<ImportValidationPacketMismatchGroup> groups {};
    ImportValidationFirstDivergence first_divergence {};
};

struct ImportValidationRegistryComparison {
    std::size_t shared_structural_path_count {0U};
    std::size_t id_drift_count {0U};
    std::vector<ProtocolPath> only_in_legacy {};
    std::vector<ProtocolPath> only_in_unified {};
};

struct ImportValidationMetrics {
    std::uint64_t file_size {0U};
    std::uint64_t packet_count {0U};
    std::uint64_t captured_bytes {0U};
    std::uint64_t flow_count {0U};
    std::uint64_t connection_count {0U};
    std::uint64_t unrecognized_count {0U};
    std::uint64_t registry_size {0U};
    double elapsed_seconds {0.0};
    double packets_per_second {0.0};
    double mib_per_second {0.0};
    std::optional<std::uint64_t> peak_memory_bytes {};
};

struct ImportValidationRunResult {
    bool success {false};
    std::string error_text {};
    ImportValidationMetrics metrics {};
    ImportValidationCanonicalState canonical_state {};
    std::vector<ImportValidationPacketObservation> packet_observations {};
};

struct ImportValidationCompareResult {
    bool success {false};
    std::string error_text {};
    bool parity {false};
    std::size_t mismatch_count {0U};
    std::vector<ImportValidationMismatch> mismatches {};
    ImportValidationMetrics legacy_metrics {};
    ImportValidationMetrics unified_metrics {};
    ImportValidationRegistryComparison registry_comparison {};
};

struct ImportValidationDiagnoseResult {
    bool success {false};
    std::string error_text {};
    ImportValidationMetrics legacy_metrics {};
    ImportValidationMetrics unified_metrics {};
    ImportValidationCompareResult session_compare {};
    ImportValidationPacketCompareResult packet_compare {};
    std::optional<ImportValidationPacketObservation> legacy_packet {};
    std::optional<ImportValidationPacketObservation> unified_packet {};
};

[[nodiscard]] std::string format_import_validation_mismatch_category(
    ImportValidationMismatchCategory category
);

[[nodiscard]] std::string format_import_validation_packet_classification(
    ImportValidationPacketClassification classification
);

[[nodiscard]] std::string format_import_validation_packet_mismatch_category(
    ImportValidationPacketMismatchCategory category
);

[[nodiscard]] ImportValidationCanonicalState canonicalize_capture_state(
    const CaptureState& state,
    bool include_hints
);

[[nodiscard]] ImportValidationRegistryComparison compare_structural_protocol_path_registries(
    const std::vector<ProtocolPath>& legacy,
    const std::vector<ProtocolPath>& unified
);

[[nodiscard]] ImportValidationPacketCompareResult compare_packet_observations(
    const std::vector<ImportValidationPacketObservation>& legacy,
    const std::vector<ImportValidationPacketObservation>& unified,
    const ImportValidationOptions& options = {}
);

[[nodiscard]] ImportValidationCompareResult compare_canonical_states(
    const ImportValidationCanonicalState& legacy,
    const ImportValidationCanonicalState& unified,
    const ImportValidationOptions& options = {}
);

[[nodiscard]] ImportValidationRunResult run_legacy_import_validation(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options = {}
);

[[nodiscard]] ImportValidationRunResult run_unified_import_validation(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options = {}
);

[[nodiscard]] ImportValidationCompareResult compare_import_validation(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options = {}
);

[[nodiscard]] ImportValidationDiagnoseResult diagnose_import_validation(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options = {}
);

}  // namespace pfl
