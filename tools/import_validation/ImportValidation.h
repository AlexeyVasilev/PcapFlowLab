#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "core/domain/CaptureState.h"
#include "core/domain/Connection.h"
#include "core/domain/ConnectionKey.h"
#include "core/domain/Flow.h"
#include "core/domain/FlowHints.h"
#include "core/domain/FlowKey.h"
#include "core/domain/PacketRef.h"
#include "core/domain/ProtocolPath.h"

namespace pfl {

struct ImportValidationOptions {
    std::optional<std::uint64_t> max_packets {};
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
};

struct ImportValidationCompareResult {
    bool success {false};
    std::string error_text {};
    bool parity {false};
    std::size_t mismatch_count {0U};
    std::vector<ImportValidationMismatch> mismatches {};
    ImportValidationMetrics legacy_metrics {};
    ImportValidationMetrics unified_metrics {};
};

[[nodiscard]] std::string format_import_validation_mismatch_category(
    ImportValidationMismatchCategory category
);

[[nodiscard]] ImportValidationCanonicalState canonicalize_capture_state(
    const CaptureState& state,
    bool include_hints
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

}  // namespace pfl
