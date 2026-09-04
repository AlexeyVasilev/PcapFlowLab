#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "core/domain/CapturePacketSizeStatistics.h"
#include "core/domain/ConnectionKey.h"
#include "core/domain/FlowHints.h"

namespace pfl {

using CaptureStatisticsEndpointIdentity = std::variant<EndpointKeyV4, EndpointKeyV6>;
using CaptureStatisticsConnectionKey = std::variant<ConnectionKeyV4, ConnectionKeyV6>;

enum class CaptureStatisticsScope : std::uint8_t {
    complete = 0,
    partial = 1,
    reserved_unknown = 2,
};

enum class CaptureStatisticsAddressFamily : std::uint8_t {
    ipv4 = 0,
    ipv6 = 1,
};

struct CaptureStatisticsProtocolCounters {
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};

    [[nodiscard]] friend bool operator==(
        const CaptureStatisticsProtocolCounters&,
        const CaptureStatisticsProtocolCounters&
    ) = default;
};

enum class CaptureStatisticsTransportProtocolCategory : std::uint8_t {
    tcp = 0,
    udp = 1,
    sctp = 2,
    other = 3,
};

struct CaptureStatisticsTransportProtocolRow {
    CaptureStatisticsTransportProtocolCategory category {CaptureStatisticsTransportProtocolCategory::tcp};
    CaptureStatisticsProtocolCounters counters {};

    [[nodiscard]] friend bool operator==(
        const CaptureStatisticsTransportProtocolRow&,
        const CaptureStatisticsTransportProtocolRow&
    ) = default;
};

enum class CaptureStatisticsIpFamilyCategory : std::uint8_t {
    ipv4 = 0,
    ipv6 = 1,
};

struct CaptureStatisticsIpFamilyRow {
    CaptureStatisticsIpFamilyCategory category {CaptureStatisticsIpFamilyCategory::ipv4};
    CaptureStatisticsProtocolCounters counters {};

    [[nodiscard]] friend bool operator==(const CaptureStatisticsIpFamilyRow&, const CaptureStatisticsIpFamilyRow&) = default;
};

enum class CaptureStatisticsDetectedProtocolCategory : std::uint8_t {
    http = 0,
    tls = 1,
    dns = 2,
    quic = 3,
    ssh = 4,
    stun = 5,
    bittorrent = 6,
    dhcp = 7,
    mdns = 8,
    smtp = 9,
    pop3 = 10,
    imap = 11,
    mail_protocols = 12,
    possible_tls_candidate = 13,
    possible_quic_candidate = 14,
    unknown_without_possible = 15,
};

struct CaptureStatisticsDetectedProtocolRow {
    CaptureStatisticsDetectedProtocolCategory category {CaptureStatisticsDetectedProtocolCategory::http};
    CaptureStatisticsProtocolCounters counters {};

    [[nodiscard]] friend bool operator==(
        const CaptureStatisticsDetectedProtocolRow&,
        const CaptureStatisticsDetectedProtocolRow&
    ) = default;
};

struct CaptureStatisticsFlowPacketCountBucket {
    std::string stable_id {};
    std::uint64_t lower_bound_inclusive {0};
    std::optional<std::uint64_t> upper_bound_inclusive {};
    std::uint64_t flow_count {0};
    std::uint64_t captured_byte_count {0};
    std::uint64_t original_byte_count {0};

    [[nodiscard]] friend bool operator==(
        const CaptureStatisticsFlowPacketCountBucket&,
        const CaptureStatisticsFlowPacketCountBucket&
    ) = default;
};

struct CaptureStatisticsFlowPacketCountHistogram {
    std::uint64_t total_flow_count {0};
    std::uint64_t total_captured_byte_count {0};
    std::uint64_t total_original_byte_count {0};
    std::uint64_t maximum_bucket_flow_count {0};
    std::uint64_t maximum_bucket_captured_byte_count {0};
    std::uint64_t maximum_bucket_original_byte_count {0};
    std::uint64_t excluded_zero_packet_flow_count {0};
    std::uint64_t excluded_zero_packet_captured_byte_count {0};
    std::uint64_t excluded_zero_packet_original_byte_count {0};
    std::vector<CaptureStatisticsFlowPacketCountBucket> buckets {};

    [[nodiscard]] friend bool operator==(
        const CaptureStatisticsFlowPacketCountHistogram&,
        const CaptureStatisticsFlowPacketCountHistogram&
    ) = default;
};

struct CaptureStatisticsDirectionDistribution {
    std::uint64_t mostly_a_to_b_flow_count {0};
    std::uint64_t balanced_flow_count {0};
    std::uint64_t mostly_b_to_a_flow_count {0};

    [[nodiscard]] friend bool operator==(
        const CaptureStatisticsDirectionDistribution&,
        const CaptureStatisticsDirectionDistribution&
    ) = default;
};

struct CaptureStatisticsTcpFlags {
    std::uint64_t syn_packet_count {0};
    std::uint64_t fin_packet_count {0};
    std::uint64_t rst_packet_count {0};

    [[nodiscard]] friend bool operator==(const CaptureStatisticsTcpFlags&, const CaptureStatisticsTcpFlags&) = default;
};

struct CaptureStatisticsQuicRecognition {
    std::uint64_t flow_count {0};
    std::uint64_t with_sni_count {0};
    std::uint64_t without_sni_count {0};
    std::uint64_t v1_count {0};
    std::uint64_t draft29_count {0};
    std::uint64_t v2_count {0};
    std::uint64_t version_unavailable_count {0};

    [[nodiscard]] friend bool operator==(
        const CaptureStatisticsQuicRecognition&,
        const CaptureStatisticsQuicRecognition&
    ) = default;
};

struct CaptureStatisticsTlsRecognition {
    std::uint64_t flow_count {0};
    std::uint64_t with_sni_count {0};
    std::uint64_t without_sni_count {0};
    std::uint64_t tls12_count {0};
    std::uint64_t tls13_count {0};
    std::uint64_t version_unavailable_count {0};

    [[nodiscard]] friend bool operator==(const CaptureStatisticsTlsRecognition&, const CaptureStatisticsTlsRecognition&) = default;
};

struct CaptureStatisticsTopEndpointRow {
    CaptureStatisticsEndpointIdentity endpoint {};
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};

    [[nodiscard]] friend bool operator==(
        const CaptureStatisticsTopEndpointRow&,
        const CaptureStatisticsTopEndpointRow&
    ) = default;
};

struct CaptureStatisticsTopPortRow {
    std::uint16_t port {0};
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};

    [[nodiscard]] friend bool operator==(const CaptureStatisticsTopPortRow&, const CaptureStatisticsTopPortRow&) = default;
};

struct CaptureStatisticsTopFlowRow {
    std::uint32_t canonical_flow_ordinal {0};
    CaptureStatisticsAddressFamily family {CaptureStatisticsAddressFamily::ipv4};
    CaptureStatisticsConnectionKey connection_key {ConnectionKeyV4 {}};
    CaptureStatisticsEndpointIdentity endpoint_a {};
    CaptureStatisticsEndpointIdentity endpoint_b {};
    ProtocolId flow_protocol {ProtocolId::unknown};
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    ProtocolPathId protocol_path_id {kInvalidProtocolPathId};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};

    [[nodiscard]] friend bool operator==(const CaptureStatisticsTopFlowRow&, const CaptureStatisticsTopFlowRow&) = default;
};

inline constexpr std::size_t kCaptureStatisticsSnapshotTopEndpointCapacity = 20U;
inline constexpr std::size_t kCaptureStatisticsSnapshotTopPortCapacity = 20U;
inline constexpr std::size_t kCaptureStatisticsSnapshotTopFlowCapacity = 10U;
inline constexpr std::size_t kCaptureStatisticsFlowPacketCountHistogramBucketCount = 12U;

[[nodiscard]] std::vector<CaptureStatisticsTransportProtocolRow>
make_default_capture_statistics_transport_protocol_rows();
[[nodiscard]] std::vector<CaptureStatisticsIpFamilyRow> make_default_capture_statistics_ip_family_rows();
[[nodiscard]] std::vector<CaptureStatisticsDetectedProtocolRow>
make_default_capture_statistics_detected_protocol_rows();
[[nodiscard]] CaptureStatisticsFlowPacketCountHistogram make_default_capture_statistics_flow_packet_count_histogram();

struct CaptureStatisticsSnapshot {
    CaptureStatisticsScope scope {CaptureStatisticsScope::complete};
    std::uint64_t total_packet_count {0};
    std::uint64_t total_flow_count {0};
    std::uint64_t total_captured_bytes {0};
    std::uint64_t total_original_bytes {0};
    CapturePacketTimestampRange timestamp_range {};
    std::uint64_t truncated_packet_count {0};
    std::uint32_t maximum_captured_packet_length {0};
    std::uint32_t maximum_original_packet_length {0};
    CapturePacketSizeDistribution captured_packet_size_distribution {};
    CapturePacketSizeDistribution original_packet_size_distribution {
        .maximum_bucket_packet_count = 0U,
        .buckets = make_original_packet_size_statistics_buckets(),
    };
    std::uint64_t unrecognized_packet_count {0};
    std::uint64_t unrecognized_captured_bytes {0};
    std::uint64_t unrecognized_original_bytes {0};
    std::uint64_t only_a_to_b_flow_count {0};
    std::uint64_t service_recognized_flow_count {0};
    CaptureStatisticsDirectionDistribution packet_direction_distribution {};
    CaptureStatisticsDirectionDistribution original_byte_direction_distribution {};
    CaptureStatisticsTcpFlags tcp_flags {};
    CaptureStatisticsFlowPacketCountHistogram flow_packet_count_histogram {
        make_default_capture_statistics_flow_packet_count_histogram()
    };
    std::vector<CaptureStatisticsTransportProtocolRow> transport_protocols {
        make_default_capture_statistics_transport_protocol_rows()
    };
    std::vector<CaptureStatisticsIpFamilyRow> ip_families {
        make_default_capture_statistics_ip_family_rows()
    };
    std::vector<CaptureStatisticsDetectedProtocolRow> detected_protocols {
        make_default_capture_statistics_detected_protocol_rows()
    };
    CaptureStatisticsQuicRecognition quic_recognition {};
    CaptureStatisticsTlsRecognition tls_recognition {};
    std::vector<CaptureStatisticsTopEndpointRow> top_endpoints {};
    std::vector<CaptureStatisticsTopPortRow> top_ports {};
    std::vector<CaptureStatisticsTopFlowRow> top_flows {};

    [[nodiscard]] friend bool operator==(const CaptureStatisticsSnapshot&, const CaptureStatisticsSnapshot&) = default;
};

enum class CaptureStatisticsSnapshotValidationErrorCode : std::uint8_t {
    nonzero_timestamps_without_range = 0,
    invalid_scope,
    invalid_timestamp_range,
    invalid_captured_packet_size_distribution,
    invalid_original_packet_size_distribution,
    invalid_flow_packet_count_histogram_layout,
    captured_packet_histogram_sum_mismatch,
    original_packet_histogram_sum_mismatch,
    unrecognized_packet_count_exceeds_total,
    unrecognized_captured_bytes_exceed_total,
    unrecognized_original_bytes_exceed_total,
    truncated_packet_count_exceeds_total,
    only_a_to_b_flow_count_exceeds_total,
    service_recognized_flow_count_exceeds_total,
    packet_direction_distribution_sum_mismatch,
    original_byte_direction_distribution_sum_mismatch,
    flow_packet_histogram_sum_mismatch,
    top_endpoint_count_exceeds_limit,
    top_port_count_exceeds_limit,
    top_flow_count_exceeds_limit,
    invalid_transport_protocol_rows,
    invalid_ip_family_rows,
    invalid_detected_protocol_rows,
    invalid_top_endpoint_identity,
    invalid_top_flow_key_family,
    invalid_top_flow_endpoint_family,
    invalid_top_flow_protocol_mismatch,
    invalid_top_flow_protocol_path_mismatch,
    top_flow_ordinal_out_of_range,
    duplicate_top_flow_ordinal,
    flow_count_exceeds_top_flow_ordinal_range,
    invalid_quic_sni_sum,
    invalid_quic_version_sum,
    invalid_tls_sni_sum,
    invalid_tls_version_sum,
};

struct CaptureStatisticsSnapshotValidationError {
    CaptureStatisticsSnapshotValidationErrorCode code {
        CaptureStatisticsSnapshotValidationErrorCode::nonzero_timestamps_without_range
    };
    std::string_view field {};
    std::optional<std::size_t> row_index {};
    std::optional<std::uint64_t> expected {};
    std::optional<std::uint64_t> actual {};

    [[nodiscard]] friend bool operator==(
        const CaptureStatisticsSnapshotValidationError&,
        const CaptureStatisticsSnapshotValidationError&
    ) = default;
};

struct CaptureStatisticsSnapshotValidationResult {
    bool ok {true};
    std::optional<CaptureStatisticsSnapshotValidationError> error {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return ok;
    }

    [[nodiscard]] friend bool operator==(
        const CaptureStatisticsSnapshotValidationResult&,
        const CaptureStatisticsSnapshotValidationResult&
    ) = default;
};

[[nodiscard]] CaptureStatisticsSnapshotValidationResult validate_capture_statistics_snapshot(
    const CaptureStatisticsSnapshot& snapshot
) noexcept;

}  // namespace pfl
