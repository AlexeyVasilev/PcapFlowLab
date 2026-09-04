#include "core/domain/CaptureStatisticsSnapshot.h"

#include <algorithm>
#include <array>
#include <limits>
#include <vector>

namespace pfl {

namespace {

struct FlowPacketCountBucketDefinition {
    const char* stable_id;
    std::uint64_t lower_bound_inclusive;
    std::optional<std::uint64_t> upper_bound_inclusive;
};

constexpr std::array<CaptureStatisticsTransportProtocolCategory, 4> kTransportProtocolCategories {{
    CaptureStatisticsTransportProtocolCategory::tcp,
    CaptureStatisticsTransportProtocolCategory::udp,
    CaptureStatisticsTransportProtocolCategory::sctp,
    CaptureStatisticsTransportProtocolCategory::other,
}};

constexpr std::array<CaptureStatisticsIpFamilyCategory, 2> kIpFamilyCategories {{
    CaptureStatisticsIpFamilyCategory::ipv4,
    CaptureStatisticsIpFamilyCategory::ipv6,
}};

constexpr std::array<CaptureStatisticsDetectedProtocolCategory, 16> kDetectedProtocolCategories {{
    CaptureStatisticsDetectedProtocolCategory::http,
    CaptureStatisticsDetectedProtocolCategory::tls,
    CaptureStatisticsDetectedProtocolCategory::dns,
    CaptureStatisticsDetectedProtocolCategory::quic,
    CaptureStatisticsDetectedProtocolCategory::ssh,
    CaptureStatisticsDetectedProtocolCategory::stun,
    CaptureStatisticsDetectedProtocolCategory::bittorrent,
    CaptureStatisticsDetectedProtocolCategory::dhcp,
    CaptureStatisticsDetectedProtocolCategory::mdns,
    CaptureStatisticsDetectedProtocolCategory::smtp,
    CaptureStatisticsDetectedProtocolCategory::pop3,
    CaptureStatisticsDetectedProtocolCategory::imap,
    CaptureStatisticsDetectedProtocolCategory::mail_protocols,
    CaptureStatisticsDetectedProtocolCategory::possible_tls_candidate,
    CaptureStatisticsDetectedProtocolCategory::possible_quic_candidate,
    CaptureStatisticsDetectedProtocolCategory::unknown_without_possible,
}};

constexpr std::uint64_t kMaximumRepresentableFlowOrdinalCount =
    static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)()) + 1U;

constexpr std::array<FlowPacketCountBucketDefinition, kCaptureStatisticsFlowPacketCountHistogramBucketCount>
    kFlowPacketCountBucketDefinitions {{
    {"packets_1", 1U, 1U},
    {"packets_2", 2U, 2U},
    {"packets_3_5", 3U, 5U},
    {"packets_6_10", 6U, 10U},
    {"packets_11_25", 11U, 25U},
    {"packets_26_50", 26U, 50U},
    {"packets_51_100", 51U, 100U},
    {"packets_101_250", 101U, 250U},
    {"packets_251_500", 251U, 500U},
    {"packets_501_1000", 501U, 1000U},
    {"packets_1001_5000", 1001U, 5000U},
    {"packets_5001_plus", 5001U, std::nullopt},
}};

template <typename T>
bool checked_add(const T value, T& total) noexcept {
    if (value > std::numeric_limits<T>::max() - total) {
        return false;
    }
    total += value;
    return true;
}

CaptureStatisticsSnapshotValidationResult make_validation_error(
    const CaptureStatisticsSnapshotValidationErrorCode code,
    const std::string_view field,
    const std::optional<std::size_t> row_index = std::nullopt,
    const std::optional<std::uint64_t> expected = std::nullopt,
    const std::optional<std::uint64_t> actual = std::nullopt
) noexcept {
    return CaptureStatisticsSnapshotValidationResult {
        .ok = false,
        .error = CaptureStatisticsSnapshotValidationError {
            .code = code,
            .field = field,
            .row_index = row_index,
            .expected = expected,
            .actual = actual,
        },
    };
}

template <typename Bucket, std::size_t Size>
CaptureStatisticsSnapshotValidationResult validate_packet_size_distribution(
    const std::array<Bucket, Size>& buckets,
    const std::array<CapturePacketSizeStatisticsBucket, Size>& expected_buckets,
    const std::uint64_t expected_total_packet_count,
    const std::uint64_t expected_maximum_bucket_packet_count,
    const CaptureStatisticsSnapshotValidationErrorCode layout_error,
    const CaptureStatisticsSnapshotValidationErrorCode sum_error,
    const std::string_view field_prefix
) noexcept {
    std::uint64_t total_packet_count {0};
    std::uint64_t maximum_bucket_packet_count {0};

    for (std::size_t index = 0U; index < buckets.size(); ++index) {
        const auto& bucket = buckets[index];
        const auto& expected_bucket = expected_buckets[index];
        if (bucket.stable_id != expected_bucket.stable_id ||
            bucket.lower_bound_inclusive != expected_bucket.lower_bound_inclusive ||
            bucket.upper_bound_inclusive != expected_bucket.upper_bound_inclusive) {
            return make_validation_error(layout_error, field_prefix, index);
        }

        if (!checked_add(bucket.packet_count, total_packet_count)) {
            return make_validation_error(sum_error, field_prefix, index);
        }
        maximum_bucket_packet_count = std::max(maximum_bucket_packet_count, bucket.packet_count);
    }

    if (total_packet_count != expected_total_packet_count) {
        return make_validation_error(sum_error, field_prefix, std::nullopt, expected_total_packet_count, total_packet_count);
    }

    if (maximum_bucket_packet_count != expected_maximum_bucket_packet_count) {
        return make_validation_error(layout_error, field_prefix, std::nullopt, expected_maximum_bucket_packet_count, maximum_bucket_packet_count);
    }

    return {};
}

CaptureStatisticsSnapshotValidationResult validate_flow_packet_count_histogram(
    const CaptureStatisticsSnapshot& snapshot
) noexcept {
    const auto& histogram = snapshot.flow_packet_count_histogram;
    if (histogram.buckets.size() != kFlowPacketCountBucketDefinitions.size()) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_flow_packet_count_histogram_layout,
            "flow_packet_count_histogram.buckets",
            std::nullopt,
            kFlowPacketCountBucketDefinitions.size(),
            histogram.buckets.size()
        );
    }

    std::uint64_t total_flow_count {0};
    std::uint64_t total_captured_byte_count {0};
    std::uint64_t total_original_byte_count {0};
    std::uint64_t maximum_bucket_flow_count {0};
    std::uint64_t maximum_bucket_captured_byte_count {0};
    std::uint64_t maximum_bucket_original_byte_count {0};

    for (std::size_t index = 0U; index < histogram.buckets.size(); ++index) {
        const auto& bucket = histogram.buckets[index];
        const auto& definition = kFlowPacketCountBucketDefinitions[index];
        if (bucket.stable_id != definition.stable_id ||
            bucket.lower_bound_inclusive != definition.lower_bound_inclusive ||
            bucket.upper_bound_inclusive != definition.upper_bound_inclusive) {
            return make_validation_error(
                CaptureStatisticsSnapshotValidationErrorCode::invalid_flow_packet_count_histogram_layout,
                "flow_packet_count_histogram.buckets",
                index
            );
        }

        if (!checked_add(bucket.flow_count, total_flow_count) ||
            !checked_add(bucket.captured_byte_count, total_captured_byte_count) ||
            !checked_add(bucket.original_byte_count, total_original_byte_count)) {
            return make_validation_error(
                CaptureStatisticsSnapshotValidationErrorCode::flow_packet_histogram_sum_mismatch,
                "flow_packet_count_histogram.buckets",
                index
            );
        }

        maximum_bucket_flow_count = std::max(maximum_bucket_flow_count, bucket.flow_count);
        maximum_bucket_captured_byte_count = std::max(maximum_bucket_captured_byte_count, bucket.captured_byte_count);
        maximum_bucket_original_byte_count = std::max(maximum_bucket_original_byte_count, bucket.original_byte_count);
    }

    if (total_flow_count != histogram.total_flow_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::flow_packet_histogram_sum_mismatch,
            "flow_packet_count_histogram.total_flow_count",
            std::nullopt,
            histogram.total_flow_count,
            total_flow_count
        );
    }

    if (total_captured_byte_count != histogram.total_captured_byte_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::flow_packet_histogram_sum_mismatch,
            "flow_packet_count_histogram.total_captured_byte_count",
            std::nullopt,
            histogram.total_captured_byte_count,
            total_captured_byte_count
        );
    }

    if (total_original_byte_count != histogram.total_original_byte_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::flow_packet_histogram_sum_mismatch,
            "flow_packet_count_histogram.total_original_byte_count",
            std::nullopt,
            histogram.total_original_byte_count,
            total_original_byte_count
        );
    }

    if (maximum_bucket_flow_count != histogram.maximum_bucket_flow_count ||
        maximum_bucket_captured_byte_count != histogram.maximum_bucket_captured_byte_count ||
        maximum_bucket_original_byte_count != histogram.maximum_bucket_original_byte_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_flow_packet_count_histogram_layout,
            "flow_packet_count_histogram.maximums"
        );
    }

    std::uint64_t total_histogram_flow_count {histogram.total_flow_count};
    if (!checked_add(histogram.excluded_zero_packet_flow_count, total_histogram_flow_count) ||
        total_histogram_flow_count != snapshot.total_flow_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::flow_packet_histogram_sum_mismatch,
            "flow_packet_count_histogram.total_flow_count_with_excluded_zero_packet_flows",
            std::nullopt,
            snapshot.total_flow_count,
            total_histogram_flow_count
        );
    }

    return {};
}

template <typename Row, typename Category, std::size_t Size>
CaptureStatisticsSnapshotValidationResult validate_protocol_rows(
    const std::vector<Row>& rows,
    const std::array<Category, Size>& expected_categories,
    const CaptureStatisticsSnapshotValidationErrorCode error_code,
    const std::string_view field
) noexcept {
    if (rows.size() != expected_categories.size()) {
        return make_validation_error(error_code, field, std::nullopt, expected_categories.size(), rows.size());
    }

    for (std::size_t index = 0U; index < rows.size(); ++index) {
        if (rows[index].category != expected_categories[index]) {
            return make_validation_error(error_code, field, index);
        }
    }

    return {};
}

bool endpoint_identity_matches_family(
    const CaptureStatisticsEndpointIdentity& endpoint,
    const CaptureStatisticsAddressFamily family
) noexcept {
    if (family == CaptureStatisticsAddressFamily::ipv4) {
        return std::holds_alternative<EndpointKeyV4>(endpoint);
    }
    return std::holds_alternative<EndpointKeyV6>(endpoint);
}

bool connection_key_matches_family(
    const CaptureStatisticsConnectionKey& connection_key,
    const CaptureStatisticsAddressFamily family
) noexcept {
    if (family == CaptureStatisticsAddressFamily::ipv4) {
        return std::holds_alternative<ConnectionKeyV4>(connection_key);
    }
    return std::holds_alternative<ConnectionKeyV6>(connection_key);
}

ProtocolId connection_key_protocol(const CaptureStatisticsConnectionKey& connection_key) noexcept {
    if (const auto* key_v4 = std::get_if<ConnectionKeyV4>(&connection_key)) {
        return key_v4->protocol;
    }
    return std::get<ConnectionKeyV6>(connection_key).protocol;
}

ProtocolPathId connection_key_protocol_path_id(const CaptureStatisticsConnectionKey& connection_key) noexcept {
    if (const auto* key_v4 = std::get_if<ConnectionKeyV4>(&connection_key)) {
        return key_v4->protocol_path_id;
    }
    return std::get<ConnectionKeyV6>(connection_key).protocol_path_id;
}

bool capture_statistics_scope_is_valid(const CaptureStatisticsScope scope) noexcept {
    return scope == CaptureStatisticsScope::complete ||
           scope == CaptureStatisticsScope::partial;
}

}  // namespace

std::vector<CaptureStatisticsTransportProtocolRow> make_default_capture_statistics_transport_protocol_rows() {
    std::vector<CaptureStatisticsTransportProtocolRow> rows {};
    rows.reserve(kTransportProtocolCategories.size());
    for (const auto category : kTransportProtocolCategories) {
        rows.push_back(CaptureStatisticsTransportProtocolRow {.category = category});
    }
    return rows;
}

std::vector<CaptureStatisticsIpFamilyRow> make_default_capture_statistics_ip_family_rows() {
    std::vector<CaptureStatisticsIpFamilyRow> rows {};
    rows.reserve(kIpFamilyCategories.size());
    for (const auto category : kIpFamilyCategories) {
        rows.push_back(CaptureStatisticsIpFamilyRow {.category = category});
    }
    return rows;
}

std::vector<CaptureStatisticsDetectedProtocolRow> make_default_capture_statistics_detected_protocol_rows() {
    std::vector<CaptureStatisticsDetectedProtocolRow> rows {};
    rows.reserve(kDetectedProtocolCategories.size());
    for (const auto category : kDetectedProtocolCategories) {
        rows.push_back(CaptureStatisticsDetectedProtocolRow {.category = category});
    }
    return rows;
}

CaptureStatisticsFlowPacketCountHistogram make_default_capture_statistics_flow_packet_count_histogram() {
    CaptureStatisticsFlowPacketCountHistogram histogram {};
    histogram.buckets.reserve(kFlowPacketCountBucketDefinitions.size());
    for (const auto& definition : kFlowPacketCountBucketDefinitions) {
        histogram.buckets.push_back(CaptureStatisticsFlowPacketCountBucket {
            .stable_id = definition.stable_id,
            .lower_bound_inclusive = definition.lower_bound_inclusive,
            .upper_bound_inclusive = definition.upper_bound_inclusive,
        });
    }
    return histogram;
}

CaptureStatisticsSnapshotValidationResult validate_capture_statistics_snapshot(
    const CaptureStatisticsSnapshot& snapshot
) noexcept {
    if (!capture_statistics_scope_is_valid(snapshot.scope)) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_scope,
            "scope"
        );
    }

    if (snapshot.total_flow_count > kMaximumRepresentableFlowOrdinalCount) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::flow_count_exceeds_top_flow_ordinal_range,
            "total_flow_count",
            std::nullopt,
            kMaximumRepresentableFlowOrdinalCount,
            snapshot.total_flow_count
        );
    }

    if (!snapshot.timestamp_range.available &&
        (snapshot.timestamp_range.earliest_timestamp_us != 0U || snapshot.timestamp_range.latest_timestamp_us != 0U)) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::nonzero_timestamps_without_range,
            "timestamp_range"
        );
    }

    if (snapshot.timestamp_range.available &&
        snapshot.timestamp_range.earliest_timestamp_us > snapshot.timestamp_range.latest_timestamp_us) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_timestamp_range,
            "timestamp_range"
        );
    }

    const auto captured_distribution_validation = validate_packet_size_distribution(
        snapshot.captured_packet_size_distribution.buckets,
        make_captured_packet_size_statistics_buckets(),
        snapshot.total_packet_count,
        snapshot.captured_packet_size_distribution.maximum_bucket_packet_count,
        CaptureStatisticsSnapshotValidationErrorCode::invalid_captured_packet_size_distribution,
        CaptureStatisticsSnapshotValidationErrorCode::captured_packet_histogram_sum_mismatch,
        "captured_packet_size_distribution"
    );
    if (!captured_distribution_validation.ok) {
        return captured_distribution_validation;
    }

    const auto original_distribution_validation = validate_packet_size_distribution(
        snapshot.original_packet_size_distribution.buckets,
        make_original_packet_size_statistics_buckets(),
        snapshot.total_packet_count,
        snapshot.original_packet_size_distribution.maximum_bucket_packet_count,
        CaptureStatisticsSnapshotValidationErrorCode::invalid_original_packet_size_distribution,
        CaptureStatisticsSnapshotValidationErrorCode::original_packet_histogram_sum_mismatch,
        "original_packet_size_distribution"
    );
    if (!original_distribution_validation.ok) {
        return original_distribution_validation;
    }

    if (snapshot.unrecognized_packet_count > snapshot.total_packet_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::unrecognized_packet_count_exceeds_total,
            "unrecognized_packet_count",
            std::nullopt,
            snapshot.total_packet_count,
            snapshot.unrecognized_packet_count
        );
    }
    if (snapshot.unrecognized_captured_bytes > snapshot.total_captured_bytes) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::unrecognized_captured_bytes_exceed_total,
            "unrecognized_captured_bytes",
            std::nullopt,
            snapshot.total_captured_bytes,
            snapshot.unrecognized_captured_bytes
        );
    }
    if (snapshot.unrecognized_original_bytes > snapshot.total_original_bytes) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::unrecognized_original_bytes_exceed_total,
            "unrecognized_original_bytes",
            std::nullopt,
            snapshot.total_original_bytes,
            snapshot.unrecognized_original_bytes
        );
    }
    if (snapshot.truncated_packet_count > snapshot.total_packet_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::truncated_packet_count_exceeds_total,
            "truncated_packet_count",
            std::nullopt,
            snapshot.total_packet_count,
            snapshot.truncated_packet_count
        );
    }
    if (snapshot.only_a_to_b_flow_count > snapshot.total_flow_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::only_a_to_b_flow_count_exceeds_total,
            "only_a_to_b_flow_count",
            std::nullopt,
            snapshot.total_flow_count,
            snapshot.only_a_to_b_flow_count
        );
    }
    if (snapshot.service_recognized_flow_count > snapshot.total_flow_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::service_recognized_flow_count_exceeds_total,
            "service_recognized_flow_count",
            std::nullopt,
            snapshot.total_flow_count,
            snapshot.service_recognized_flow_count
        );
    }

    std::uint64_t packet_direction_sum {0};
    if (!checked_add(snapshot.packet_direction_distribution.mostly_a_to_b_flow_count, packet_direction_sum) ||
        !checked_add(snapshot.packet_direction_distribution.balanced_flow_count, packet_direction_sum) ||
        !checked_add(snapshot.packet_direction_distribution.mostly_b_to_a_flow_count, packet_direction_sum)) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::packet_direction_distribution_sum_mismatch,
            "packet_direction_distribution"
        );
    }
    if (packet_direction_sum != snapshot.total_flow_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::packet_direction_distribution_sum_mismatch,
            "packet_direction_distribution",
            std::nullopt,
            snapshot.total_flow_count,
            packet_direction_sum
        );
    }

    std::uint64_t original_byte_direction_sum {0};
    if (!checked_add(snapshot.original_byte_direction_distribution.mostly_a_to_b_flow_count, original_byte_direction_sum) ||
        !checked_add(snapshot.original_byte_direction_distribution.balanced_flow_count, original_byte_direction_sum) ||
        !checked_add(snapshot.original_byte_direction_distribution.mostly_b_to_a_flow_count, original_byte_direction_sum)) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::original_byte_direction_distribution_sum_mismatch,
            "original_byte_direction_distribution"
        );
    }
    if (original_byte_direction_sum != snapshot.total_flow_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::original_byte_direction_distribution_sum_mismatch,
            "original_byte_direction_distribution",
            std::nullopt,
            snapshot.total_flow_count,
            original_byte_direction_sum
        );
    }

    const auto flow_histogram_validation = validate_flow_packet_count_histogram(snapshot);
    if (!flow_histogram_validation.ok) {
        return flow_histogram_validation;
    }

    if (snapshot.top_endpoints.size() > kCaptureStatisticsSnapshotTopEndpointCapacity) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::top_endpoint_count_exceeds_limit,
            "top_endpoints",
            std::nullopt,
            kCaptureStatisticsSnapshotTopEndpointCapacity,
            snapshot.top_endpoints.size()
        );
    }
    if (snapshot.top_ports.size() > kCaptureStatisticsSnapshotTopPortCapacity) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::top_port_count_exceeds_limit,
            "top_ports",
            std::nullopt,
            kCaptureStatisticsSnapshotTopPortCapacity,
            snapshot.top_ports.size()
        );
    }
    if (snapshot.top_flows.size() > kCaptureStatisticsSnapshotTopFlowCapacity) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::top_flow_count_exceeds_limit,
            "top_flows",
            std::nullopt,
            kCaptureStatisticsSnapshotTopFlowCapacity,
            snapshot.top_flows.size()
        );
    }

    const auto transport_protocol_validation = validate_protocol_rows(
        snapshot.transport_protocols,
        kTransportProtocolCategories,
        CaptureStatisticsSnapshotValidationErrorCode::invalid_transport_protocol_rows,
        "transport_protocols"
    );
    if (!transport_protocol_validation.ok) {
        return transport_protocol_validation;
    }

    const auto ip_family_validation = validate_protocol_rows(
        snapshot.ip_families,
        kIpFamilyCategories,
        CaptureStatisticsSnapshotValidationErrorCode::invalid_ip_family_rows,
        "ip_families"
    );
    if (!ip_family_validation.ok) {
        return ip_family_validation;
    }

    const auto detected_protocol_validation = validate_protocol_rows(
        snapshot.detected_protocols,
        kDetectedProtocolCategories,
        CaptureStatisticsSnapshotValidationErrorCode::invalid_detected_protocol_rows,
        "detected_protocols"
    );
    if (!detected_protocol_validation.ok) {
        return detected_protocol_validation;
    }

    for (std::size_t index = 0U; index < snapshot.top_endpoints.size(); ++index) {
        if (!std::holds_alternative<EndpointKeyV4>(snapshot.top_endpoints[index].endpoint) &&
            !std::holds_alternative<EndpointKeyV6>(snapshot.top_endpoints[index].endpoint)) {
            return make_validation_error(
                CaptureStatisticsSnapshotValidationErrorCode::invalid_top_endpoint_identity,
                "top_endpoints",
                index
            );
        }
    }

    for (std::size_t index = 0U; index < snapshot.top_flows.size(); ++index) {
        const auto& row = snapshot.top_flows[index];
        if (row.canonical_flow_ordinal >= snapshot.total_flow_count) {
            return make_validation_error(
                CaptureStatisticsSnapshotValidationErrorCode::top_flow_ordinal_out_of_range,
                "top_flows.canonical_flow_ordinal",
                index,
                snapshot.total_flow_count,
                row.canonical_flow_ordinal
            );
        }
        for (std::size_t prior_index = 0U; prior_index < index; ++prior_index) {
            if (snapshot.top_flows[prior_index].canonical_flow_ordinal == row.canonical_flow_ordinal) {
                return make_validation_error(
                    CaptureStatisticsSnapshotValidationErrorCode::duplicate_top_flow_ordinal,
                    "top_flows.canonical_flow_ordinal",
                    index
                );
            }
        }
        if (!connection_key_matches_family(row.connection_key, row.family)) {
            return make_validation_error(
                CaptureStatisticsSnapshotValidationErrorCode::invalid_top_flow_key_family,
                "top_flows.connection_key",
                index
            );
        }
        if (!endpoint_identity_matches_family(row.endpoint_a, row.family) ||
            !endpoint_identity_matches_family(row.endpoint_b, row.family)) {
            return make_validation_error(
                CaptureStatisticsSnapshotValidationErrorCode::invalid_top_flow_endpoint_family,
                "top_flows.endpoints",
                index
            );
        }
        if (connection_key_protocol(row.connection_key) != row.flow_protocol) {
            return make_validation_error(
                CaptureStatisticsSnapshotValidationErrorCode::invalid_top_flow_protocol_mismatch,
                "top_flows.flow_protocol",
                index
            );
        }
        if (connection_key_protocol_path_id(row.connection_key) != row.protocol_path_id) {
            return make_validation_error(
                CaptureStatisticsSnapshotValidationErrorCode::invalid_top_flow_protocol_path_mismatch,
                "top_flows.protocol_path_id",
                index
            );
        }
    }

    std::uint64_t quic_sni_sum {0};
    if (!checked_add(snapshot.quic_recognition.with_sni_count, quic_sni_sum) ||
        !checked_add(snapshot.quic_recognition.without_sni_count, quic_sni_sum)) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_quic_sni_sum,
            "quic_recognition"
        );
    }
    if (quic_sni_sum != snapshot.quic_recognition.flow_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_quic_sni_sum,
            "quic_recognition",
            std::nullopt,
            snapshot.quic_recognition.flow_count,
            quic_sni_sum
        );
    }

    std::uint64_t quic_version_sum {0};
    if (!checked_add(snapshot.quic_recognition.v1_count, quic_version_sum) ||
        !checked_add(snapshot.quic_recognition.draft29_count, quic_version_sum) ||
        !checked_add(snapshot.quic_recognition.v2_count, quic_version_sum) ||
        !checked_add(snapshot.quic_recognition.version_unavailable_count, quic_version_sum)) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_quic_version_sum,
            "quic_recognition"
        );
    }
    if (quic_version_sum != snapshot.quic_recognition.flow_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_quic_version_sum,
            "quic_recognition",
            std::nullopt,
            snapshot.quic_recognition.flow_count,
            quic_version_sum
        );
    }

    std::uint64_t tls_sni_sum {0};
    if (!checked_add(snapshot.tls_recognition.with_sni_count, tls_sni_sum) ||
        !checked_add(snapshot.tls_recognition.without_sni_count, tls_sni_sum)) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_tls_sni_sum,
            "tls_recognition"
        );
    }
    if (tls_sni_sum != snapshot.tls_recognition.flow_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_tls_sni_sum,
            "tls_recognition",
            std::nullopt,
            snapshot.tls_recognition.flow_count,
            tls_sni_sum
        );
    }

    std::uint64_t tls_version_sum {0};
    if (!checked_add(snapshot.tls_recognition.tls12_count, tls_version_sum) ||
        !checked_add(snapshot.tls_recognition.tls13_count, tls_version_sum) ||
        !checked_add(snapshot.tls_recognition.version_unavailable_count, tls_version_sum)) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_tls_version_sum,
            "tls_recognition"
        );
    }
    if (tls_version_sum != snapshot.tls_recognition.flow_count) {
        return make_validation_error(
            CaptureStatisticsSnapshotValidationErrorCode::invalid_tls_version_sum,
            "tls_recognition",
            std::nullopt,
            snapshot.tls_recognition.flow_count,
            tls_version_sum
        );
    }

    return {};
}

}  // namespace pfl
