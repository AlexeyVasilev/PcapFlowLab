#include "app/session/SessionFlowHelpers.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <variant>

#include "app/session/ProtocolPathPresentation.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/DirectionDistribution.h"
#include "core/domain/FlowHints.h"

namespace pfl::session_detail {

namespace {

bool has_port_443(const ListedConnectionRef& connection) noexcept;
bool has_port_443(std::uint16_t first_port, std::uint16_t second_port) noexcept;
bool is_listable_connection(const ListedConnectionRef& connection) noexcept;
std::size_t flow_packet_count_histogram_bucket_index(std::uint64_t packet_count_value) noexcept;

struct FlowPacketCountHistogramBucketDefinition {
    const char* stable_id;
    std::uint64_t lower_bound_inclusive;
    std::optional<std::uint64_t> upper_bound_inclusive;
};

const std::array<FlowPacketCountHistogramBucketDefinition, 12> kFlowPacketCountHistogramBucketDefinitions {{
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

FlowProtocolHint protocol_hint(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->protocol_hint : connection.ipv6->protocol_hint;
}

const ConnectionAggregateStats& aggregate_stats(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4)
        ? connection.ipv4->aggregate_stats
        : connection.ipv6->aggregate_stats;
}

const std::string& service_hint(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->service_hint : connection.ipv6->service_hint;
}

std::uint64_t directional_packet_count(const ListedConnectionRef& connection, const Direction direction) noexcept {
    if (connection.family == FlowAddressFamily::ipv4) {
        return direction == Direction::a_to_b
            ? connection.ipv4->flow_a.packet_count
            : connection.ipv4->flow_b.packet_count;
    }

    return direction == Direction::a_to_b
        ? connection.ipv6->flow_a.packet_count
        : connection.ipv6->flow_b.packet_count;
}

std::uint64_t directional_original_byte_count(const ListedConnectionRef& connection, const Direction direction) noexcept {
    if (connection.family == FlowAddressFamily::ipv4) {
        return direction == Direction::a_to_b
            ? connection.ipv4->flow_a.total_bytes
            : connection.ipv4->flow_b.total_bytes;
    }

    return direction == Direction::a_to_b
        ? connection.ipv6->flow_a.total_bytes
        : connection.ipv6->flow_b.total_bytes;
}

void add_distribution_flow(
    FlowDirectionDistributionStatistics& distribution,
    const DirectionDistribution classification
) noexcept {
    switch (classification) {
    case DirectionDistribution::mostly_a_to_b:
        ++distribution.mostly_a_to_b_flow_count;
        break;
    case DirectionDistribution::balanced:
        ++distribution.balanced_flow_count;
        break;
    case DirectionDistribution::mostly_b_to_a:
        ++distribution.mostly_b_to_a_flow_count;
        break;
    }
}

void append_flow_packet_histogram_bucket_definitions(FlowPacketCountHistogram& histogram) {
    histogram.buckets.reserve(kFlowPacketCountHistogramBucketDefinitions.size());
    for (const auto& definition : kFlowPacketCountHistogramBucketDefinitions) {
        histogram.buckets.push_back(FlowPacketCountHistogramBucket {
            .stable_id = definition.stable_id,
            .lower_bound_inclusive = definition.lower_bound_inclusive,
            .upper_bound_inclusive = definition.upper_bound_inclusive,
            .flow_count = 0U,
            .captured_byte_count = 0U,
            .original_byte_count = 0U,
        });
    }
}

void observe_protocol_hint(
    CaptureGeneralProtocolStatistics& statistics,
    const ListedConnectionRef& connection
) noexcept {
    switch (protocol_hint(connection)) {
    case FlowProtocolHint::http:
        add_protocol_stats(statistics.hint_http, connection);
        break;
    case FlowProtocolHint::tls:
        add_protocol_stats(statistics.hint_tls, connection);
        break;
    case FlowProtocolHint::dns:
        add_protocol_stats(statistics.hint_dns, connection);
        break;
    case FlowProtocolHint::quic:
        add_protocol_stats(statistics.hint_quic, connection);
        break;
    case FlowProtocolHint::ssh:
        add_protocol_stats(statistics.hint_ssh, connection);
        break;
    case FlowProtocolHint::stun:
        add_protocol_stats(statistics.hint_stun, connection);
        break;
    case FlowProtocolHint::bittorrent:
        add_protocol_stats(statistics.hint_bittorrent, connection);
        break;
    case FlowProtocolHint::dhcp:
        add_protocol_stats(statistics.hint_dhcp, connection);
        break;
    case FlowProtocolHint::mdns:
        add_protocol_stats(statistics.hint_mdns, connection);
        break;
    case FlowProtocolHint::smtp:
        add_protocol_stats(statistics.hint_smtp, connection);
        add_protocol_stats(statistics.hint_mail_protocols, connection);
        break;
    case FlowProtocolHint::pop3:
        add_protocol_stats(statistics.hint_pop3, connection);
        add_protocol_stats(statistics.hint_mail_protocols, connection);
        break;
    case FlowProtocolHint::imap:
        add_protocol_stats(statistics.hint_imap, connection);
        add_protocol_stats(statistics.hint_mail_protocols, connection);
        break;
    case FlowProtocolHint::possible_tls:
        add_protocol_stats(statistics.hint_possible_tls_candidate, connection);
        break;
    case FlowProtocolHint::possible_quic:
        add_protocol_stats(statistics.hint_possible_quic_candidate, connection);
        break;
    case FlowProtocolHint::igmp:
    case FlowProtocolHint::igmpv1:
    case FlowProtocolHint::igmpv2:
    case FlowProtocolHint::igmpv3:
    case FlowProtocolHint::unknown:
    default:
        if (has_port_443(connection)) {
            switch (protocol_id(connection)) {
            case ProtocolId::tcp:
                add_protocol_stats(statistics.hint_possible_tls_candidate, connection);
                return;
            case ProtocolId::udp:
                add_protocol_stats(statistics.hint_possible_quic_candidate, connection);
                return;
            default:
                break;
            }
        }

        add_protocol_stats(statistics.hint_unknown_without_possible, connection);
        break;
    }
}

void observe_histogram(
    FlowPacketCountHistogram& histogram,
    const ListedConnectionRef& connection
) noexcept {
    const auto packets_for_flow = packet_count(connection);
    const auto captured_bytes_for_flow = captured_bytes(connection);
    const auto original_bytes_for_flow = total_bytes(connection);

    if (packets_for_flow == 0U) {
        ++histogram.excluded_zero_packet_flow_count;
        histogram.excluded_zero_packet_captured_byte_count += captured_bytes_for_flow;
        histogram.excluded_zero_packet_original_byte_count += original_bytes_for_flow;
        return;
    }

    const auto bucket_index = flow_packet_count_histogram_bucket_index(packets_for_flow);
    auto& bucket = histogram.buckets[bucket_index];
    ++bucket.flow_count;
    bucket.captured_byte_count += captured_bytes_for_flow;
    bucket.original_byte_count += original_bytes_for_flow;
    ++histogram.total_flow_count;
    histogram.total_captured_byte_count += captured_bytes_for_flow;
    histogram.total_original_byte_count += original_bytes_for_flow;
}

void finalize_histogram(FlowPacketCountHistogram& histogram) noexcept {
    for (const auto& bucket : histogram.buckets) {
        histogram.maximum_bucket_flow_count = std::max(histogram.maximum_bucket_flow_count, bucket.flow_count);
        histogram.maximum_bucket_captured_byte_count = std::max(
            histogram.maximum_bucket_captured_byte_count,
            bucket.captured_byte_count
        );
        histogram.maximum_bucket_original_byte_count = std::max(
            histogram.maximum_bucket_original_byte_count,
            bucket.original_byte_count
        );
    }
}

constexpr std::size_t kTopFlowSummaryCapacity = 10U;

struct EndpointAccumulator {
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t total_bytes {0};
};

struct PortAccumulator {
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t total_bytes {0};
};

struct EndpointKeyV4Hash {
    [[nodiscard]] std::size_t operator()(const EndpointKeyV4& key) const noexcept {
        auto seed = std::hash<std::uint32_t> {}(key.addr);
        seed ^= std::hash<std::uint16_t> {}(key.port) + 0x9e3779b9U + (seed << 6U) + (seed >> 2U);
        return seed;
    }
};

struct EndpointKeyV6Hash {
    [[nodiscard]] std::size_t operator()(const EndpointKeyV6& key) const noexcept {
        auto seed = std::hash<std::uint16_t> {}(key.port);
        for (const auto octet : key.addr) {
            seed ^= std::hash<std::uint8_t> {}(octet) + 0x9e3779b9U + (seed << 6U) + (seed >> 2U);
        }
        return seed;
    }
};

struct AggregatedEndpointCandidate {
    FlowEndpointIdentity key {EndpointKeyV4 {}};
    EndpointAccumulator accumulator {};
};

struct AggregatedPortCandidate {
    std::uint16_t port {0};
    PortAccumulator accumulator {};
};

template <typename Candidate, typename Better>
void retain_top_candidate(
    std::vector<Candidate>& heap,
    Candidate candidate,
    const std::size_t limit,
    Better better
) {
    if (limit == 0U) {
        return;
    }

    if (heap.size() < limit) {
        heap.push_back(std::move(candidate));
        std::push_heap(heap.begin(), heap.end(), better);
        return;
    }

    if (!better(candidate, heap.front())) {
        return;
    }

    std::pop_heap(heap.begin(), heap.end(), better);
    heap.back() = std::move(candidate);
    std::push_heap(heap.begin(), heap.end(), better);
}

template <typename Candidate, typename Better>
std::vector<Candidate> finalize_top_candidates(std::vector<Candidate> heap, Better better) {
    std::sort(heap.begin(), heap.end(), better);
    return heap;
}

bool endpoint_identity_less(const FlowEndpointIdentity& left, const FlowEndpointIdentity& right) noexcept {
    if (left.index() != right.index()) {
        return left.index() < right.index();
    }

    if (std::holds_alternative<EndpointKeyV4>(left)) {
        return std::get<EndpointKeyV4>(left) < std::get<EndpointKeyV4>(right);
    }

    return std::get<EndpointKeyV6>(left) < std::get<EndpointKeyV6>(right);
}

std::string format_endpoint_identity(const FlowEndpointIdentity& endpoint) {
    return std::visit([](const auto& value) {
        return format_endpoint(value);
    }, endpoint);
}

bool endpoint_candidate_better(
    const AggregatedEndpointCandidate& left,
    const AggregatedEndpointCandidate& right
) noexcept {
    if (left.accumulator.total_bytes != right.accumulator.total_bytes) {
        return left.accumulator.total_bytes > right.accumulator.total_bytes;
    }
    if (left.accumulator.packet_count != right.accumulator.packet_count) {
        return left.accumulator.packet_count > right.accumulator.packet_count;
    }
    return endpoint_identity_less(left.key, right.key);
}

bool port_candidate_better(const AggregatedPortCandidate& left, const AggregatedPortCandidate& right) noexcept {
    if (left.accumulator.total_bytes != right.accumulator.total_bytes) {
        return left.accumulator.total_bytes > right.accumulator.total_bytes;
    }
    if (left.accumulator.packet_count != right.accumulator.packet_count) {
        return left.accumulator.packet_count > right.accumulator.packet_count;
    }
    return left.port < right.port;
}

bool top_flow_row_better(const TopFlowRow& left, const TopFlowRow& right) noexcept {
    if (left.total_bytes != right.total_bytes) {
        return left.total_bytes > right.total_bytes;
    }
    if (left.packet_count != right.packet_count) {
        return left.packet_count > right.packet_count;
    }
    return left.flow_index < right.flow_index;
}

void observe_endpoint_accumulator(
    EndpointAccumulator& accumulator,
    const std::uint64_t packet_count_value,
    const std::uint64_t captured_bytes_value,
    const std::uint64_t total_bytes_value
) noexcept {
    ++accumulator.flow_count;
    accumulator.packet_count += packet_count_value;
    accumulator.captured_bytes += captured_bytes_value;
    accumulator.total_bytes += total_bytes_value;
}

void observe_port_accumulator(
    PortAccumulator& accumulator,
    const std::uint64_t packet_count_value,
    const std::uint64_t captured_bytes_value,
    const std::uint64_t total_bytes_value
) noexcept {
    ++accumulator.flow_count;
    accumulator.packet_count += packet_count_value;
    accumulator.captured_bytes += captured_bytes_value;
    accumulator.total_bytes += total_bytes_value;
}

CaptureStatisticsProtocolCounters make_protocol_counters(const ProtocolStats& stats) {
    return CaptureStatisticsProtocolCounters {
        .flow_count = stats.flow_count,
        .packet_count = stats.packet_count,
        .captured_bytes = stats.captured_bytes,
        .original_bytes = stats.original_bytes,
    };
}

CaptureStatisticsDirectionDistribution make_direction_distribution(
    const FlowDirectionDistributionStatistics& distribution
) {
    return CaptureStatisticsDirectionDistribution {
        .mostly_a_to_b_flow_count = distribution.mostly_a_to_b_flow_count,
        .balanced_flow_count = distribution.balanced_flow_count,
        .mostly_b_to_a_flow_count = distribution.mostly_b_to_a_flow_count,
    };
}

CaptureStatisticsTcpFlags make_tcp_flags(const CaptureTcpFlagStatistics& flags) {
    return CaptureStatisticsTcpFlags {
        .syn_packet_count = flags.syn_packet_count,
        .fin_packet_count = flags.fin_packet_count,
        .rst_packet_count = flags.rst_packet_count,
    };
}

CaptureStatisticsAddressFamily make_capture_statistics_address_family(const FlowAddressFamily family) {
    return family == FlowAddressFamily::ipv4
        ? CaptureStatisticsAddressFamily::ipv4
        : CaptureStatisticsAddressFamily::ipv6;
}

std::optional<TopFlowRow> make_top_flow_row(
    const std::size_t flow_index,
    const ListedConnectionRef& connection
) {
    if (!is_listable_connection(connection)) {
        return std::nullopt;
    }

    if (connection.family == FlowAddressFamily::ipv4) {
        const auto endpoint_a = first_observed_endpoint_a(*connection.ipv4);
        const auto endpoint_b = first_observed_endpoint_b(*connection.ipv4);
        if (!endpoint_a.has_value() || !endpoint_b.has_value()) {
            return std::nullopt;
        }

        return TopFlowRow {
            .flow_index = flow_index,
            .family = FlowAddressFamily::ipv4,
            .key = connection.ipv4->key,
            .endpoint_a_key = *endpoint_a,
            .endpoint_b_key = *endpoint_b,
            .protocol = connection.ipv4->key.protocol,
            .protocol_path_id = connection.ipv4->key.protocol_path_id,
            .protocol_hint = connection.ipv4->protocol_hint,
            .service_hint = connection.ipv4->service_hint,
            .packet_count = connection.ipv4->packet_count,
            .captured_bytes = connection.ipv4->aggregate_stats.captured_bytes,
            .total_bytes = connection.ipv4->total_bytes,
        };
    }

    const auto endpoint_a = first_observed_endpoint_a(*connection.ipv6);
    const auto endpoint_b = first_observed_endpoint_b(*connection.ipv6);
    if (!endpoint_a.has_value() || !endpoint_b.has_value()) {
        return std::nullopt;
    }

    return TopFlowRow {
        .flow_index = flow_index,
        .family = FlowAddressFamily::ipv6,
        .key = connection.ipv6->key,
        .endpoint_a_key = *endpoint_a,
        .endpoint_b_key = *endpoint_b,
        .protocol = connection.ipv6->key.protocol,
        .protocol_path_id = connection.ipv6->key.protocol_path_id,
        .protocol_hint = connection.ipv6->protocol_hint,
        .service_hint = connection.ipv6->service_hint,
        .packet_count = connection.ipv6->packet_count,
        .captured_bytes = connection.ipv6->aggregate_stats.captured_bytes,
        .total_bytes = connection.ipv6->total_bytes,
    };
}

CaptureTopSummary build_top_summary_from_aggregates(
    const std::unordered_map<EndpointKeyV4, EndpointAccumulator, EndpointKeyV4Hash>& endpoint_rows_v4,
    const std::unordered_map<EndpointKeyV6, EndpointAccumulator, EndpointKeyV6Hash>& endpoint_rows_v6,
    const std::vector<PortAccumulator>& port_rows,
    const std::vector<std::uint16_t>& touched_ports,
    std::vector<TopFlowRow> top_flow_heap,
    const std::size_t limit
) {
    std::vector<AggregatedEndpointCandidate> endpoint_heap {};
    endpoint_heap.reserve(std::min(limit, endpoint_rows_v4.size() + endpoint_rows_v6.size()));
    for (const auto& [endpoint, accumulator] : endpoint_rows_v4) {
        retain_top_candidate(
            endpoint_heap,
            AggregatedEndpointCandidate {
                .key = endpoint,
                .accumulator = accumulator,
            },
            limit,
            endpoint_candidate_better
        );
    }
    for (const auto& [endpoint, accumulator] : endpoint_rows_v6) {
        retain_top_candidate(
            endpoint_heap,
            AggregatedEndpointCandidate {
                .key = endpoint,
                .accumulator = accumulator,
            },
            limit,
            endpoint_candidate_better
        );
    }

    std::vector<AggregatedPortCandidate> port_heap {};
    port_heap.reserve(std::min(limit, touched_ports.size()));
    for (const auto port : touched_ports) {
        retain_top_candidate(
            port_heap,
            AggregatedPortCandidate {
                .port = port,
                .accumulator = port_rows[port],
            },
            limit,
            port_candidate_better
        );
    }

    CaptureTopSummary summary {};
    const auto top_endpoints = finalize_top_candidates(std::move(endpoint_heap), endpoint_candidate_better);
    summary.endpoints_by_bytes.reserve(top_endpoints.size());
    for (const auto& candidate : top_endpoints) {
        summary.endpoints_by_bytes.push_back(TopEndpointRow {
            .identity = candidate.key,
            .endpoint = format_endpoint_identity(candidate.key),
            .flow_count = candidate.accumulator.flow_count,
            .packet_count = candidate.accumulator.packet_count,
            .captured_bytes = candidate.accumulator.captured_bytes,
            .total_bytes = candidate.accumulator.total_bytes,
        });
    }

    const auto top_ports = finalize_top_candidates(std::move(port_heap), port_candidate_better);
    summary.ports_by_bytes.reserve(top_ports.size());
    for (const auto& candidate : top_ports) {
        summary.ports_by_bytes.push_back(TopPortRow {
            .port = candidate.port,
            .flow_count = candidate.accumulator.flow_count,
            .packet_count = candidate.accumulator.packet_count,
            .captured_bytes = candidate.accumulator.captured_bytes,
            .total_bytes = candidate.accumulator.total_bytes,
        });
    }

    summary.flows_by_original_bytes = finalize_top_candidates(std::move(top_flow_heap), top_flow_row_better);
    return summary;
}

bool has_port_443(const ListedConnectionRef& connection) noexcept {
    if (connection.family == FlowAddressFamily::ipv4) {
        return has_port_443(connection.ipv4->key.first.port, connection.ipv4->key.second.port);
    }

    return has_port_443(connection.ipv6->key.first.port, connection.ipv6->key.second.port);
}

bool has_port_443(const std::uint16_t first_port, const std::uint16_t second_port) noexcept {
    return first_port == 443U || second_port == 443U;
}

bool listed_connection_less(const ListedConnectionRef& left, const ListedConnectionRef& right) noexcept {
    if (total_bytes(left) != total_bytes(right)) {
        return total_bytes(left) > total_bytes(right);
    }

    if (packet_count(left) != packet_count(right)) {
        return packet_count(left) > packet_count(right);
    }

    if (left.family != right.family) {
        return left.family < right.family;
    }

    if (left.family == FlowAddressFamily::ipv4) {
        return left.ipv4->key < right.ipv4->key;
    }

    return left.ipv6->key < right.ipv6->key;
}

bool is_listable_connection(const ListedConnectionRef& connection) noexcept {
    return connection.family == FlowAddressFamily::ipv4
        ? connection.ipv4 != nullptr && connection.ipv4->has_flow_a
        : connection.ipv6 != nullptr && connection.ipv6->has_flow_a;
}

ProtocolPathId protocol_path_id(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4)
        ? connection.ipv4->key.protocol_path_id
        : connection.ipv6->key.protocol_path_id;
}

template <typename Flow>
std::span<const PacketRef> packet_refs_for_direction(const Flow& flow) noexcept {
    return std::span<const PacketRef>(flow.packets.data(), flow.packets.size());
}

template <typename Flow>
bool directional_flow_is_structurally_valid(const Flow& flow) noexcept {
    return flow.packet_count > 0U &&
        static_cast<std::uint64_t>(flow.packets.size()) == flow.packet_count;
}

template <typename Flow>
bool packet_refs_strictly_increasing(const Flow& flow) noexcept {
    if (flow.packets.empty()) {
        return true;
    }

    std::uint64_t previous_index = flow.packets.front().packet_index;
    for (std::size_t index = 1U; index < flow.packets.size(); ++index) {
        const auto current_index = flow.packets[index].packet_index;
        if (current_index <= previous_index) {
            return false;
        }
        previous_index = current_index;
    }

    return true;
}

bool checked_add_u64(
    const std::uint64_t left,
    const std::uint64_t right,
    std::uint64_t& result
) noexcept {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        return false;
    }
    result = left + right;
    return true;
}

bool checked_multiply_u64(
    const std::uint64_t left,
    const std::uint64_t right,
    std::uint64_t& result
) noexcept {
    if (left != 0U && right > std::numeric_limits<std::uint64_t>::max() / left) {
        return false;
    }
    result = left * right;
    return true;
}

struct ProtocolPathStatisticsAccumulatorNode {
    std::size_t depth {0};
    LayerKey layer {};
    ProtocolPath path {};
    std::size_t parent_index {std::numeric_limits<std::size_t>::max()};
    std::vector<std::size_t> child_indices {};
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t original_byte_count {0};
    bool is_terminal {false};
    double flow_percent {0.0};
    double packet_percent {0.0};
    double original_byte_percent {0.0};
    std::string layer_text {};
    std::string path_text {};
    std::string compact_text {};
    std::string flow_count_text {};
    std::string packet_count_text {};
    std::string original_byte_count_text {};
    std::vector<ProtocolPathBadgeRow> badges {};
    std::vector<FlowIndex> flow_indices {};
};

struct ProtocolPathTerminalAggregateAccumulatorRow {
    ProtocolPathDisplayAggregateRow aggregate {};
    std::vector<FlowIndex> flow_indices {};
};

struct ProtocolPathDisplayStatisticsBuildResult {
    ProtocolPathDisplayStatistics statistics {};
    std::uint64_t total_flow_count {0};
    std::uint64_t total_packet_count {0};
    std::uint64_t total_original_byte_count {0};
    std::unordered_map<ProtocolPathId, std::vector<FlowIndex>> membership_by_path_id {};
};

struct PrefixStepKey {
    std::size_t parent_index {std::numeric_limits<std::size_t>::max()};
    LayerKey layer {};

    [[nodiscard]] friend bool operator==(const PrefixStepKey&, const PrefixStepKey&) = default;
};

struct PrefixStepKeyHash {
    [[nodiscard]] std::size_t operator()(const PrefixStepKey& key) const noexcept {
        auto seed = std::hash<std::size_t> {}(key.parent_index);
        seed = detail::hash_combine(seed, LayerKeyHash {}(key.layer));
        return seed;
    }
};

char ascii_lower(const char value) noexcept {
    if (value >= 'A' && value <= 'Z') {
        return static_cast<char>(value - 'A' + 'a');
    }
    return value;
}

int compare_case_insensitive_text(const std::string_view left, const std::string_view right) {
    const auto shared_length = std::min(left.size(), right.size());
    for (std::size_t index = 0; index < shared_length; ++index) {
        const auto folded_left = ascii_lower(left[index]);
        const auto folded_right = ascii_lower(right[index]);
        if (folded_left < folded_right) {
            return -1;
        }
        if (folded_left > folded_right) {
            return 1;
        }
    }
    if (left.size() < right.size()) {
        return -1;
    }
    if (left.size() > right.size()) {
        return 1;
    }
    if (left < right) {
        return -1;
    }
    if (left > right) {
        return 1;
    }
    return 0;
}

bool contains_case_insensitive_text(const std::string_view haystack, const std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    if (haystack.size() < needle.size()) {
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

std::string flow_family_text(const FlowAddressFamily family) {
    return family == FlowAddressFamily::ipv6 ? "IPv6" : "IPv4";
}

std::string upper_ascii(const std::string_view value) {
    std::string formatted {value};
    std::transform(formatted.begin(), formatted.end(), formatted.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return formatted;
}

int compare_endpoint_fields(
    const FlowAddressFamily left_family,
    const std::string_view left_address,
    const std::uint16_t left_port,
    const FlowAddressFamily right_family,
    const std::string_view right_address,
    const std::uint16_t right_port
) {
    if (left_family != right_family) {
        return left_family < right_family ? -1 : 1;
    }

    if (const auto address_compare = compare_case_insensitive_text(left_address, right_address); address_compare != 0) {
        return address_compare;
    }

    if (left_port < right_port) {
        return -1;
    }
    if (left_port > right_port) {
        return 1;
    }
    return 0;
}

int compare_flow_rows_for_sort(const FlowRow& left, const FlowRow& right, const FlowQuerySortKey key) {
    switch (key) {
    case FlowQuerySortKey::canonical_index:
        break;
    case FlowQuerySortKey::protocol:
        return compare_case_insensitive_text(left.protocol_text, right.protocol_text);
    case FlowQuerySortKey::service:
        return compare_case_insensitive_text(left.service_hint, right.service_hint);
    case FlowQuerySortKey::endpoint_a:
        return compare_endpoint_fields(
            left.family,
            left.address_a,
            left.port_a,
            right.family,
            right.address_a,
            right.port_a
        );
    case FlowQuerySortKey::endpoint_b:
        return compare_endpoint_fields(
            left.family,
            left.address_b,
            left.port_b,
            right.family,
            right.address_b,
            right.port_b
        );
    case FlowQuerySortKey::packets:
        if (left.packet_count < right.packet_count) {
            return -1;
        }
        if (left.packet_count > right.packet_count) {
            return 1;
        }
        return 0;
    case FlowQuerySortKey::bytes:
        if (left.total_bytes < right.total_bytes) {
            return -1;
        }
        if (left.total_bytes > right.total_bytes) {
            return 1;
        }
        return 0;
    }

    if (left.index < right.index) {
        return -1;
    }
    if (left.index > right.index) {
        return 1;
    }
    return 0;
}

struct FlowQueryCandidate {
    std::size_t index {0};
    FlowRow row {};
};

std::string group_integer_part(std::string text) {
    const auto sign_offset = !text.empty() && text.front() == '-' ? std::size_t {1} : std::size_t {0};
    const auto decimal_pos = text.find('.');
    const auto integer_end = decimal_pos == std::string::npos ? text.size() : decimal_pos;

    for (std::ptrdiff_t index = static_cast<std::ptrdiff_t>(integer_end) - 3;
         index > static_cast<std::ptrdiff_t>(sign_offset);
         index -= 3) {
        text.insert(static_cast<std::size_t>(index), 1U, ' ');
    }

    return text;
}

std::string trim_trailing_zeros(std::string text) {
    const auto decimal_pos = text.find('.');
    if (decimal_pos == std::string::npos) {
        return text;
    }

    while (!text.empty() && text.back() == '0') {
        text.pop_back();
    }

    if (!text.empty() && text.back() == '.') {
        text.pop_back();
    }

    return text;
}

std::string format_grouped_integer(const std::uint64_t value) {
    return group_integer_part(std::to_string(value));
}

std::string format_percent_text(const double percent) {
    if (!(percent > 0.0)) {
        return "0%";
    }

    if (percent < 0.01) {
        return "<0.01%";
    }

    std::ostringstream out {};
    if (percent < 1.0) {
        out << std::fixed << std::setprecision(2) << percent;
    } else {
        out << std::fixed << std::setprecision(1) << percent;
    }

    return trim_trailing_zeros(out.str()) + '%';
}

std::string format_count_with_percent_text(const std::uint64_t count, const double percent) {
    return format_grouped_integer(count) + " (" + format_percent_text(percent) + ')';
}

std::string format_byte_value(const std::uint64_t value) {
    static constexpr std::array<const char*, 5> units {"B", "KB", "MB", "GB", "TB"};

    double scaled = static_cast<double>(value);
    std::size_t unit_index = 0;
    while (scaled >= 1024.0 && unit_index + 1U < units.size()) {
        scaled /= 1024.0;
        ++unit_index;
    }

    if (unit_index == 0U) {
        return format_grouped_integer(value) + ' ' + units[unit_index];
    }

    std::ostringstream out {};
    out << std::fixed << std::setprecision(1) << scaled;
    return group_integer_part(trim_trailing_zeros(out.str())) + ' ' + units[unit_index];
}

std::string format_byte_count_with_percent_text(const std::uint64_t count, const double percent) {
    return format_byte_value(count) + " (" + format_percent_text(percent) + ')';
}

double safe_percent(const std::uint64_t part, const std::uint64_t total) noexcept {
    if (part == 0U || total == 0U) {
        return 0.0;
    }

    return (static_cast<double>(part) * 100.0) / static_cast<double>(total);
}

LayerKey kind_only_layer_key(const LayerKey& layer) noexcept {
    return LayerKey {
        .kind = layer.kind,
        .identifier = {},
    };
}

void append_protocol_path_statistics_rows(
    const std::vector<ProtocolPathStatisticsAccumulatorNode>& nodes,
    CaptureProtocolPathSummary& summary,
    const std::vector<std::size_t>& node_indices
) {
    auto sorted_indices = node_indices;
    std::sort(sorted_indices.begin(), sorted_indices.end(), [&](const std::size_t left, const std::size_t right) {
        const auto& left_node = nodes[left];
        const auto& right_node = nodes[right];
        if (left_node.packet_count != right_node.packet_count) {
            return left_node.packet_count > right_node.packet_count;
        }
        if (left_node.flow_count != right_node.flow_count) {
            return left_node.flow_count > right_node.flow_count;
        }
        return left_node.path_text < right_node.path_text;
    });

    for (const auto node_index : sorted_indices) {
        const auto& node = nodes[node_index];
        const auto node_id = static_cast<std::uint64_t>(node_index + 1U);
        if (!summary.node_membership_ranges.empty()) {
            const auto membership_offset = summary.flow_index_pool.size();
            summary.flow_index_pool.insert(
                summary.flow_index_pool.end(),
                node.flow_indices.begin(),
                node.flow_indices.end()
            );
            summary.node_membership_ranges[static_cast<std::size_t>(node_id)] = ProtocolPathStatisticsNodeMembershipRange {
                .offset = membership_offset,
                .count = node.flow_indices.size(),
            };
        }

        summary.rows.push_back(ProtocolPathStatisticsRow {
            .node_id = static_cast<std::uint64_t>(node_index + 1U),
            .parent_node_id = node.parent_index == std::numeric_limits<std::size_t>::max()
                ? kInvalidProtocolPathStatisticsNodeId
                : static_cast<std::uint64_t>(node.parent_index + 1U),
            .depth = node.depth,
            .layer = node.layer,
            .path = node.path,
            .layer_text = node.layer_text,
            .path_text = node.path_text,
            .compact_text = node.compact_text,
            .badges = node.badges,
            .has_children = !node.child_indices.empty(),
            .is_terminal = node.is_terminal,
            .flow_count = node.flow_count,
            .packet_count = node.packet_count,
            .original_byte_count = node.original_byte_count,
            .flow_percent = node.flow_percent,
            .packet_percent = node.packet_percent,
            .original_byte_percent = node.original_byte_percent,
            .flow_count_text = node.flow_count_text,
            .packet_count_text = node.packet_count_text,
            .original_byte_count_text = node.original_byte_count_text,
        });
        append_protocol_path_statistics_rows(nodes, summary, node.child_indices);
    }
}

CaptureProtocolPathSummary build_protocol_path_summary_from_display_statistics_impl(
    const ProtocolPathRegistry& registry,
    const ProtocolPathDisplayStatistics& statistics,
    const std::uint64_t total_flow_count,
    const std::uint64_t total_packet_count,
    const std::uint64_t total_original_byte_count,
    const ProtocolPathStatisticsMode mode,
    const std::unordered_map<ProtocolPathId, std::vector<FlowIndex>>* const membership_by_path_id
) {
    CaptureProtocolPathSummary summary {
        .mode = mode,
        .total_flow_count = total_flow_count,
        .total_packet_count = total_packet_count,
        .total_original_byte_count = total_original_byte_count,
    };

    std::unordered_map<PrefixStepKey, std::size_t, PrefixStepKeyHash> node_index_by_prefix_step {};
    std::unordered_map<ProtocolPathId, std::size_t> terminal_node_index_by_path_id {};
    std::vector<ProtocolPathStatisticsAccumulatorNode> nodes {};

    for (const auto& aggregate_row : statistics.terminal_path_aggregates) {
        const auto* path = registry.find(aggregate_row.protocol_path_id);
        if (path == nullptr || path->empty()) {
            continue;
        }

        const auto* flow_indices = membership_by_path_id != nullptr
            ? [&]() -> const std::vector<FlowIndex>* {
                const auto found = membership_by_path_id->find(aggregate_row.protocol_path_id);
                return found != membership_by_path_id->end() ? &found->second : nullptr;
            }()
            : nullptr;

        if (mode == ProtocolPathStatisticsMode::terminal_paths) {
            auto [it, inserted] = terminal_node_index_by_path_id.emplace(
                aggregate_row.protocol_path_id,
                nodes.size()
            );
            if (inserted) {
                nodes.push_back(ProtocolPathStatisticsAccumulatorNode {
                    .depth = 0U,
                    .layer = path->layers().back(),
                    .path = *path,
                    .is_terminal = true,
                });
            }

            auto& node = nodes[it->second];
            node.flow_count += aggregate_row.flow_count;
            node.packet_count += aggregate_row.packet_count;
            node.original_byte_count += aggregate_row.original_byte_count;
            if (flow_indices != nullptr) {
                node.flow_indices.insert(
                    node.flow_indices.end(),
                    flow_indices->begin(),
                    flow_indices->end()
                );
            }
            continue;
        }

        std::size_t parent_index = std::numeric_limits<std::size_t>::max();
        for (std::size_t depth = 0; depth < path->size(); ++depth) {
            const auto layer = mode == ProtocolPathStatisticsMode::kind_overview
                ? kind_only_layer_key((*path)[depth])
                : (*path)[depth];
            const PrefixStepKey key {
                .parent_index = parent_index,
                .layer = layer,
            };

            auto [it, inserted] = node_index_by_prefix_step.emplace(key, nodes.size());
            if (inserted) {
                ProtocolPath prefix_path {};
                if (parent_index == std::numeric_limits<std::size_t>::max()) {
                    prefix_path = ProtocolPath {{layer}};
                } else {
                    auto prefix_layers = nodes[parent_index].path.layers();
                    prefix_layers.push_back(layer);
                    prefix_path = ProtocolPath {std::move(prefix_layers)};
                }

                nodes.push_back(ProtocolPathStatisticsAccumulatorNode {
                    .depth = depth,
                    .layer = layer,
                    .path = std::move(prefix_path),
                    .parent_index = parent_index,
                    .is_terminal = depth + 1U >= path->size(),
                });
                if (parent_index != std::numeric_limits<std::size_t>::max()) {
                    nodes[parent_index].child_indices.push_back(it->second);
                }
            }

            auto& node = nodes[it->second];
            node.flow_count += aggregate_row.flow_count;
            node.packet_count += aggregate_row.packet_count;
            node.original_byte_count += aggregate_row.original_byte_count;
            if (flow_indices != nullptr) {
                node.flow_indices.insert(
                    node.flow_indices.end(),
                    flow_indices->begin(),
                    flow_indices->end()
                );
            }
            parent_index = it->second;
        }
    }

    std::vector<std::size_t> root_indices {};
    root_indices.reserve(nodes.size());
    for (std::size_t index = 0; index < nodes.size(); ++index) {
        auto presentation = build_protocol_path_presentation(&nodes[index].path);
        nodes[index].path_text = presentation.full_text;
        nodes[index].compact_text = presentation.compact_text;
        nodes[index].badges = std::move(presentation.badges);
        nodes[index].layer_text = mode == ProtocolPathStatisticsMode::terminal_paths
            ? nodes[index].path_text
            : format_protocol_path_layer_display_text(nodes[index].layer);
        nodes[index].flow_percent = safe_percent(nodes[index].flow_count, summary.total_flow_count);
        nodes[index].packet_percent = safe_percent(nodes[index].packet_count, summary.total_packet_count);
        nodes[index].original_byte_percent = safe_percent(
            nodes[index].original_byte_count,
            summary.total_original_byte_count
        );
        nodes[index].flow_count_text =
            format_count_with_percent_text(nodes[index].flow_count, nodes[index].flow_percent);
        nodes[index].packet_count_text =
            format_count_with_percent_text(nodes[index].packet_count, nodes[index].packet_percent);
        nodes[index].original_byte_count_text = format_byte_count_with_percent_text(
            nodes[index].original_byte_count,
            nodes[index].original_byte_percent
        );
        if (nodes[index].parent_index == std::numeric_limits<std::size_t>::max()) {
            root_indices.push_back(index);
        }
    }

    summary.rows.reserve(nodes.size());
    if (membership_by_path_id != nullptr) {
        summary.flow_index_pool.reserve(summary.total_flow_count);
        summary.node_membership_ranges.resize(nodes.size() + 1U);
    }
    append_protocol_path_statistics_rows(nodes, summary, root_indices);
    return summary;
}

ProtocolPathDisplayStatisticsBuildResult build_protocol_path_display_statistics_impl(
    const CaptureState& state,
    const std::vector<ListedConnectionRef>& connections
) {
    ProtocolPathDisplayStatisticsBuildResult result {
        .total_packet_count = state.summary.packet_count,
    };
    std::unordered_map<ProtocolPathId, std::size_t> aggregate_index_by_path_id {};
    std::vector<ProtocolPathTerminalAggregateAccumulatorRow> aggregate_rows {};

    for (std::size_t connection_index = 0; connection_index < connections.size(); ++connection_index) {
        const auto& connection = connections[connection_index];
        const auto path_id = protocol_path_id(connection);
        if (path_id == kInvalidProtocolPathId) {
            continue;
        }

        const auto* path = state.protocol_path_registry.find(path_id);
        if (path == nullptr || path->empty()) {
            continue;
        }

        ++result.total_flow_count;
        const auto packets_for_flow = packet_count(connection);
        const auto original_bytes_for_flow = total_bytes(connection);
        result.total_original_byte_count += original_bytes_for_flow;

        auto [it, inserted] = aggregate_index_by_path_id.emplace(path_id, aggregate_rows.size());
        if (inserted) {
            aggregate_rows.push_back(ProtocolPathTerminalAggregateAccumulatorRow {
                .aggregate = ProtocolPathDisplayAggregateRow {
                    .protocol_path_id = path_id,
                },
            });
        }

        auto& aggregate_row = aggregate_rows[it->second];
        aggregate_row.aggregate.flow_count += 1U;
        aggregate_row.aggregate.packet_count += packets_for_flow;
        aggregate_row.aggregate.original_byte_count += original_bytes_for_flow;
        aggregate_row.flow_indices.push_back(static_cast<FlowIndex>(connection_index));
    }

    result.statistics.terminal_path_aggregates.reserve(aggregate_rows.size());
    result.membership_by_path_id.reserve(aggregate_rows.size());
    for (auto& aggregate_row : aggregate_rows) {
        result.membership_by_path_id.emplace(
            aggregate_row.aggregate.protocol_path_id,
            aggregate_row.flow_indices
        );
        result.statistics.terminal_path_aggregates.push_back(aggregate_row.aggregate);
    }

    return result;
}

std::size_t flow_packet_count_histogram_bucket_index(const std::uint64_t packet_count_value) noexcept {
    for (std::size_t index = 0U; index < kFlowPacketCountHistogramBucketDefinitions.size(); ++index) {
        const auto& bucket = kFlowPacketCountHistogramBucketDefinitions[index];
        if (packet_count_value < bucket.lower_bound_inclusive) {
            continue;
        }
        if (!bucket.upper_bound_inclusive.has_value() || packet_count_value <= *bucket.upper_bound_inclusive) {
            return index;
        }
    }

    return kFlowPacketCountHistogramBucketDefinitions.size() - 1U;
}

}  // namespace

std::string format_flow_protocol_text(const ProtocolId protocol) {
    switch (protocol) {
    case ProtocolId::arp:
        return "ARP";
    case ProtocolId::icmp:
        return "ICMP";
    case ProtocolId::igmp:
        return "IGMP";
    case ProtocolId::tcp:
        return "TCP";
    case ProtocolId::udp:
        return "UDP";
    case ProtocolId::esp:
        return "ESP";
    case ProtocolId::sctp:
        return "SCTP";
    case ProtocolId::icmpv6:
        return "ICMPv6";
    default:
        return "unknown";
    }
}

std::string format_statistics_bucket_label(
    const std::uint64_t lower_bound_inclusive,
    const std::optional<std::uint64_t> upper_bound_inclusive
) {
    if (!upper_bound_inclusive.has_value()) {
        return std::to_string(lower_bound_inclusive) + '+';
    }
    if (lower_bound_inclusive == *upper_bound_inclusive) {
        return std::to_string(lower_bound_inclusive);
    }
    return std::to_string(lower_bound_inclusive) + '-' + std::to_string(*upper_bound_inclusive);
}

std::string capture_packet_size_bucket_label(const CapturePacketSizeStatisticsBucket& bucket) {
    return format_statistics_bucket_label(
        static_cast<std::uint64_t>(bucket.lower_bound_inclusive),
        bucket.upper_bound_inclusive.has_value()
            ? std::optional<std::uint64_t> {static_cast<std::uint64_t>(*bucket.upper_bound_inclusive)}
            : std::nullopt
    );
}

std::string format_statistics_count_value(const std::uint64_t value) {
    return format_grouped_integer(value);
}

std::string format_statistics_compact_size_value(const std::uint64_t value) {
    return format_byte_value(value);
}

std::string format_statistics_percent_text(const double percent) {
    if (!(percent > 0.0)) {
        return "0%";
    }

    if (percent < 0.01) {
        return "<0.01%";
    }

    if (percent < 1.0) {
        std::ostringstream out {};
        out << std::fixed << std::setprecision(2) << percent;
        return trim_trailing_zeros(out.str()) + '%';
    }

    return std::to_string(static_cast<std::uint64_t>(std::llround(percent))) + '%';
}

std::string format_statistics_count_with_percent_text(const std::uint64_t count, const double percent) {
    return format_statistics_count_value(count) + " (" + format_statistics_percent_text(percent) + ')';
}

std::string format_statistics_size_with_percent_text(const std::uint64_t size, const double percent) {
    return format_statistics_compact_size_value(size) + " (" + format_statistics_percent_text(percent) + ')';
}

std::string format_statistics_size_value(const std::uint64_t value) {
    const auto compact = format_statistics_compact_size_value(value);
    if (value == 0U || value < 1024U) {
        return compact;
    }

    return compact + " (" + format_grouped_integer(value) + " B)";
}

std::vector<ProtocolHintStatisticsRow> build_protocol_hint_statistics_rows(const CaptureProtocolSummary& summary) {
    std::vector<ProtocolHintStatisticsRow> rows {};
    rows.reserve(13U);

    auto append_row = [&](const char* group, const char* protocol_label, const ProtocolStats& stats) {
        rows.push_back(ProtocolHintStatisticsRow {
            .group = group,
            .protocol_label = protocol_label,
            .flow_count = stats.flow_count,
            .packet_count = stats.packet_count,
            .captured_bytes = stats.captured_bytes,
            .original_bytes = stats.original_bytes,
        });
    };

    append_row("Confirmed", "HTTP", summary.hint_http);
    append_row("Confirmed", "TLS", summary.hint_tls);
    append_row("Possible", "Possible TLS", summary.hint_possible_tls);
    append_row("Confirmed", "DNS", summary.hint_dns);
    append_row("Confirmed", "QUIC", summary.hint_quic);
    append_row("Possible", "Possible QUIC", summary.hint_possible_quic);
    append_row("Confirmed", "SSH", summary.hint_ssh);
    append_row("Confirmed", "STUN", summary.hint_stun);
    append_row("Confirmed", "BitTorrent", summary.hint_bittorrent);
    append_row("Confirmed", "Mail protocols", summary.hint_mail_protocols);
    append_row("Confirmed", "DHCP", summary.hint_dhcp);
    append_row("Confirmed", "mDNS", summary.hint_mdns);
    append_row("Unknown", "Unknown", summary.hint_unknown);

    std::uint64_t total_flow_count {0};
    std::uint64_t total_packet_count {0};
    std::uint64_t total_captured_bytes {0};
    std::uint64_t total_original_bytes {0};
    for (const auto& row : rows) {
        total_flow_count += row.flow_count;
        total_packet_count += row.packet_count;
        total_captured_bytes += row.captured_bytes;
        total_original_bytes += row.original_bytes;
    }

    for (auto& row : rows) {
        row.flow_count_text = format_statistics_count_with_percent_text(
            row.flow_count,
            safe_percent(row.flow_count, total_flow_count)
        );
        row.packet_count_text = format_statistics_count_with_percent_text(
            row.packet_count,
            safe_percent(row.packet_count, total_packet_count)
        );
        row.captured_bytes_text = format_statistics_size_with_percent_text(
            row.captured_bytes,
            safe_percent(row.captured_bytes, total_captured_bytes)
        );
        row.original_bytes_text = format_statistics_size_with_percent_text(
            row.original_bytes,
            safe_percent(row.original_bytes, total_original_bytes)
        );
    }

    return rows;
}

namespace {

std::string format_flow_endpoint_identity(const FlowEndpointIdentity& endpoint) {
    return std::visit([](const auto& value) {
        return format_endpoint(value);
    }, endpoint);
}

ProtocolStats project_protocol_stats(const CaptureStatisticsProtocolCounters& counters) noexcept {
    return ProtocolStats {
        .flow_count = counters.flow_count,
        .packet_count = counters.packet_count,
        .captured_bytes = counters.captured_bytes,
        .original_bytes = counters.original_bytes,
    };
}

void project_transport_protocol_row(
    CaptureGeneralProtocolStatistics& protocol,
    const CaptureStatisticsTransportProtocolRow& row
) noexcept {
    switch (row.category) {
    case CaptureStatisticsTransportProtocolCategory::tcp:
        protocol.tcp = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsTransportProtocolCategory::udp:
        protocol.udp = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsTransportProtocolCategory::sctp:
        protocol.sctp = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsTransportProtocolCategory::other:
        protocol.other = project_protocol_stats(row.counters);
        break;
    }
}

void project_ip_family_row(
    CaptureGeneralProtocolStatistics& protocol,
    const CaptureStatisticsIpFamilyRow& row
) noexcept {
    switch (row.category) {
    case CaptureStatisticsIpFamilyCategory::ipv4:
        protocol.ipv4 = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsIpFamilyCategory::ipv6:
        protocol.ipv6 = project_protocol_stats(row.counters);
        break;
    }
}

void project_detected_protocol_row(
    CaptureGeneralProtocolStatistics& protocol,
    const CaptureStatisticsDetectedProtocolRow& row
) noexcept {
    switch (row.category) {
    case CaptureStatisticsDetectedProtocolCategory::http:
        protocol.hint_http = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::tls:
        protocol.hint_tls = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::dns:
        protocol.hint_dns = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::quic:
        protocol.hint_quic = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::ssh:
        protocol.hint_ssh = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::stun:
        protocol.hint_stun = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::bittorrent:
        protocol.hint_bittorrent = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::dhcp:
        protocol.hint_dhcp = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::mdns:
        protocol.hint_mdns = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::smtp:
        protocol.hint_smtp = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::pop3:
        protocol.hint_pop3 = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::imap:
        protocol.hint_imap = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::mail_protocols:
        protocol.hint_mail_protocols = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::possible_tls_candidate:
        protocol.hint_possible_tls_candidate = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::possible_quic_candidate:
        protocol.hint_possible_quic_candidate = project_protocol_stats(row.counters);
        break;
    case CaptureStatisticsDetectedProtocolCategory::unknown_without_possible:
        protocol.hint_unknown_without_possible = project_protocol_stats(row.counters);
        break;
    }
}

}  // namespace

CaptureTopSummary project_top_summary_from_snapshot(const CaptureStatisticsSnapshot& snapshot) {
    CaptureTopSummary summary {};
    summary.endpoints_by_bytes.reserve(snapshot.top_endpoints.size());
    for (const auto& row : snapshot.top_endpoints) {
        summary.endpoints_by_bytes.push_back(TopEndpointRow {
            .identity = row.endpoint,
            .endpoint = format_flow_endpoint_identity(row.endpoint),
            .flow_count = row.flow_count,
            .packet_count = row.packet_count,
            .captured_bytes = row.captured_bytes,
            .total_bytes = row.original_bytes,
        });
    }

    summary.ports_by_bytes.reserve(snapshot.top_ports.size());
    for (const auto& row : snapshot.top_ports) {
        summary.ports_by_bytes.push_back(TopPortRow {
            .port = row.port,
            .flow_count = row.flow_count,
            .packet_count = row.packet_count,
            .captured_bytes = row.captured_bytes,
            .total_bytes = row.original_bytes,
        });
    }

    summary.flows_by_original_bytes.reserve(snapshot.top_flows.size());
    for (const auto& row : snapshot.top_flows) {
        summary.flows_by_original_bytes.push_back(TopFlowRow {
            .flow_index = row.canonical_flow_ordinal,
            .family = row.family == CaptureStatisticsAddressFamily::ipv4
                ? FlowAddressFamily::ipv4
                : FlowAddressFamily::ipv6,
            .key = row.connection_key,
            .endpoint_a_key = row.endpoint_a,
            .endpoint_b_key = row.endpoint_b,
            .protocol = row.flow_protocol,
            .protocol_path_id = row.protocol_path_id,
            .protocol_hint = row.protocol_hint,
            .service_hint = row.service_hint,
            .packet_count = row.packet_count,
            .captured_bytes = row.captured_bytes,
            .total_bytes = row.original_bytes,
        });
    }
    return summary;
}

FlowPacketCountHistogram project_flow_packet_count_histogram(
    const CaptureStatisticsFlowPacketCountHistogram& source
) {
    FlowPacketCountHistogram histogram {
        .total_flow_count = source.total_flow_count,
        .total_captured_byte_count = source.total_captured_byte_count,
        .total_original_byte_count = source.total_original_byte_count,
        .maximum_bucket_flow_count = source.maximum_bucket_flow_count,
        .maximum_bucket_captured_byte_count = source.maximum_bucket_captured_byte_count,
        .maximum_bucket_original_byte_count = source.maximum_bucket_original_byte_count,
        .excluded_zero_packet_flow_count = source.excluded_zero_packet_flow_count,
        .excluded_zero_packet_captured_byte_count = source.excluded_zero_packet_captured_byte_count,
        .excluded_zero_packet_original_byte_count = source.excluded_zero_packet_original_byte_count,
    };
    histogram.buckets.reserve(source.buckets.size());
    for (const auto& bucket : source.buckets) {
        histogram.buckets.push_back(FlowPacketCountHistogramBucket {
            .stable_id = bucket.stable_id,
            .lower_bound_inclusive = bucket.lower_bound_inclusive,
            .upper_bound_inclusive = bucket.upper_bound_inclusive,
            .flow_count = bucket.flow_count,
            .captured_byte_count = bucket.captured_byte_count,
            .original_byte_count = bucket.original_byte_count,
        });
    }
    return histogram;
}

CaptureGeneralStatistics project_general_statistics_from_snapshot(
    const CaptureStatisticsSnapshot& snapshot
) {
    CaptureGeneralStatistics statistics {};
    for (const auto& row : snapshot.transport_protocols) {
        project_transport_protocol_row(statistics.protocol, row);
    }
    for (const auto& row : snapshot.ip_families) {
        project_ip_family_row(statistics.protocol, row);
    }
    for (const auto& row : snapshot.detected_protocols) {
        project_detected_protocol_row(statistics.protocol, row);
    }

    statistics.flow_packet_count_histogram =
        project_flow_packet_count_histogram(snapshot.flow_packet_count_histogram);
    statistics.quic_tls_summary = CaptureQuicTlsSummary {
        .quic = QuicRecognitionStats {
            .total_flows = snapshot.quic_recognition.flow_count,
            .with_sni = snapshot.quic_recognition.with_sni_count,
            .without_sni = snapshot.quic_recognition.without_sni_count,
            .version_v1 = snapshot.quic_recognition.v1_count,
            .version_draft29 = snapshot.quic_recognition.draft29_count,
            .version_v2 = snapshot.quic_recognition.v2_count,
            .version_unknown = snapshot.quic_recognition.version_unavailable_count,
        },
        .tls = TlsRecognitionStats {
            .total_flows = snapshot.tls_recognition.flow_count,
            .with_sni = snapshot.tls_recognition.with_sni_count,
            .without_sni = snapshot.tls_recognition.without_sni_count,
            .version_tls12 = snapshot.tls_recognition.tls12_count,
            .version_tls13 = snapshot.tls_recognition.tls13_count,
            .version_unknown = snapshot.tls_recognition.version_unavailable_count,
        },
    };
    statistics.top_summary = project_top_summary_from_snapshot(snapshot);
    statistics.flow_characteristics = CaptureFlowCharacteristicsStatistics {
        .total_flow_count = snapshot.total_flow_count,
        .only_a_to_b_flow_count = snapshot.only_a_to_b_flow_count,
        .service_recognized_flow_count = snapshot.service_recognized_flow_count,
    };
    statistics.packet_direction_distribution = FlowDirectionDistributionStatistics {
        .mostly_a_to_b_flow_count = snapshot.packet_direction_distribution.mostly_a_to_b_flow_count,
        .balanced_flow_count = snapshot.packet_direction_distribution.balanced_flow_count,
        .mostly_b_to_a_flow_count = snapshot.packet_direction_distribution.mostly_b_to_a_flow_count,
    };
    statistics.original_byte_direction_distribution = FlowDirectionDistributionStatistics {
        .mostly_a_to_b_flow_count = snapshot.original_byte_direction_distribution.mostly_a_to_b_flow_count,
        .balanced_flow_count = snapshot.original_byte_direction_distribution.balanced_flow_count,
        .mostly_b_to_a_flow_count = snapshot.original_byte_direction_distribution.mostly_b_to_a_flow_count,
    };
    statistics.tcp_flags = CaptureTcpFlagStatistics {
        .syn_packet_count = snapshot.tcp_flags.syn_packet_count,
        .fin_packet_count = snapshot.tcp_flags.fin_packet_count,
        .rst_packet_count = snapshot.tcp_flags.rst_packet_count,
    };
    return statistics;
}

CapturePacketStatistics project_packet_statistics_from_snapshot(
    const CaptureStatisticsSnapshot& snapshot
) noexcept {
    return CapturePacketStatistics {
        .total_packet_count = snapshot.total_packet_count,
        .total_captured_bytes = snapshot.total_captured_bytes,
        .total_original_bytes = snapshot.total_original_bytes,
        .timestamp_range = snapshot.timestamp_range,
        .truncated_packet_count = snapshot.truncated_packet_count,
        .maximum_captured_packet_length = snapshot.maximum_captured_packet_length,
        .maximum_original_packet_length = snapshot.maximum_original_packet_length,
        .captured_size_distribution = snapshot.captured_packet_size_distribution,
        .original_size_distribution = snapshot.original_packet_size_distribution,
        .unrecognized_packet_count = snapshot.unrecognized_packet_count,
        .unrecognized_captured_bytes = snapshot.unrecognized_captured_bytes,
        .unrecognized_original_bytes = snapshot.unrecognized_original_bytes,
    };
}

std::uint64_t packet_count(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->packet_count : connection.ipv6->packet_count;
}

std::uint64_t captured_bytes(const ListedConnectionRef& connection) noexcept {
    return aggregate_stats(connection).captured_bytes;
}

std::uint64_t total_bytes(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->total_bytes : connection.ipv6->total_bytes;
}

ProtocolId protocol_id(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->key.protocol : connection.ipv6->key.protocol;
}

ProtocolId protocol_id(const CanonicalFlowMetadata& flow) noexcept {
    return flow.protocol;
}

FlowProtocolHint effective_protocol_hint(const ListedConnectionRef& connection, const AnalysisSettings& settings) noexcept {
    if (connection.family == FlowAddressFamily::ipv4) {
        return effective_protocol_hint(
            connection.ipv4->protocol_hint,
            connection.ipv4->key.protocol,
            connection.ipv4->key.first.port,
            connection.ipv4->key.second.port,
            settings
        );
    }

    return effective_protocol_hint(
        connection.ipv6->protocol_hint,
        connection.ipv6->key.protocol,
        connection.ipv6->key.first.port,
        connection.ipv6->key.second.port,
        settings
    );
}

FlowProtocolHint effective_protocol_hint(const CanonicalFlowMetadata& flow, const AnalysisSettings& settings) noexcept {
    return effective_protocol_hint(
        flow.protocol_hint,
        flow.protocol,
        std::visit([](const auto& endpoint) { return endpoint.port; }, flow.endpoint_a),
        std::visit([](const auto& endpoint) { return endpoint.port; }, flow.endpoint_b),
        settings
    );
}

FlowProtocolHint effective_protocol_hint(
    const FlowProtocolHint confirmed_hint,
    const ProtocolId protocol,
    const std::uint16_t first_port,
    const std::uint16_t second_port,
    const AnalysisSettings& settings
) noexcept {
    if (confirmed_hint != FlowProtocolHint::unknown) {
        return confirmed_hint;
    }

    if (!settings.use_possible_tls_quic || !has_port_443(first_port, second_port)) {
        return FlowProtocolHint::unknown;
    }

    switch (protocol) {
    case ProtocolId::tcp:
        return FlowProtocolHint::possible_tls;
    case ProtocolId::udp:
        return FlowProtocolHint::possible_quic;
    default:
        return FlowProtocolHint::unknown;
    }
}

std::vector<ListedConnectionRef> list_connections(const CaptureState& state) {
    std::vector<ListedConnectionRef> connections {};

    const auto ipv4_connections = state.ipv4_connections.list();
    const auto ipv6_connections = state.ipv6_connections.list();
    connections.reserve(ipv4_connections.size() + ipv6_connections.size());

    for (const auto* connection : ipv4_connections) {
        if (connection == nullptr || !connection->has_flow_a) {
            continue;
        }
        connections.push_back(ListedConnectionRef {
            .family = FlowAddressFamily::ipv4,
            .ipv4 = connection,
        });
    }

    for (const auto* connection : ipv6_connections) {
        if (connection == nullptr || !connection->has_flow_a) {
            continue;
        }
        connections.push_back(ListedConnectionRef {
            .family = FlowAddressFamily::ipv6,
            .ipv6 = connection,
        });
    }

    std::sort(connections.begin(), connections.end(), listed_connection_less);
    return connections;
}

std::optional<CanonicalFlowMetadata> make_canonical_flow_metadata(
    const std::size_t canonical_index,
    const ListedConnectionRef& connection
) {
    if (!is_listable_connection(connection)) {
        return std::nullopt;
    }

    if (connection.family == FlowAddressFamily::ipv4) {
        const auto endpoint_a = first_observed_endpoint_a(*connection.ipv4);
        const auto endpoint_b = first_observed_endpoint_b(*connection.ipv4);
        if (!endpoint_a.has_value() || !endpoint_b.has_value()) {
            return std::nullopt;
        }
        return CanonicalFlowMetadata {
            .canonical_index = canonical_index,
            .family = FlowAddressFamily::ipv4,
            .key = connection.ipv4->key,
            .endpoint_a = *endpoint_a,
            .endpoint_b = *endpoint_b,
            .protocol_path_id = connection.ipv4->key.protocol_path_id,
            .protocol = connection.ipv4->key.protocol,
            .protocol_hint = connection.ipv4->protocol_hint,
            .service_hint = connection.ipv4->service_hint,
            .quic_version = connection.ipv4->quic_version,
            .tls_version = connection.ipv4->tls_version,
            .has_fragmented_packets = connection.ipv4->has_fragmented_packets,
            .fragmented_packet_count = connection.ipv4->fragmented_packet_count,
            .aggregate_stats = connection.ipv4->aggregate_stats,
            .packet_count = connection.ipv4->packet_count,
            .total_bytes = connection.ipv4->total_bytes,
            .has_flow_a = connection.ipv4->has_flow_a,
            .has_flow_b = connection.ipv4->has_flow_b,
            .packets_a_to_b = connection.ipv4->has_flow_a ? connection.ipv4->flow_a.packet_count : 0U,
            .packets_b_to_a = connection.ipv4->has_flow_b ? connection.ipv4->flow_b.packet_count : 0U,
            .original_bytes_a_to_b = connection.ipv4->has_flow_a ? connection.ipv4->flow_a.total_bytes : 0U,
            .original_bytes_b_to_a = connection.ipv4->has_flow_b ? connection.ipv4->flow_b.total_bytes : 0U,
        };
    }

    const auto endpoint_a = first_observed_endpoint_a(*connection.ipv6);
    const auto endpoint_b = first_observed_endpoint_b(*connection.ipv6);
    if (!endpoint_a.has_value() || !endpoint_b.has_value()) {
        return std::nullopt;
    }
    return CanonicalFlowMetadata {
        .canonical_index = canonical_index,
        .family = FlowAddressFamily::ipv6,
        .key = connection.ipv6->key,
        .endpoint_a = *endpoint_a,
        .endpoint_b = *endpoint_b,
        .protocol_path_id = connection.ipv6->key.protocol_path_id,
        .protocol = connection.ipv6->key.protocol,
        .protocol_hint = connection.ipv6->protocol_hint,
        .service_hint = connection.ipv6->service_hint,
        .quic_version = connection.ipv6->quic_version,
        .tls_version = connection.ipv6->tls_version,
        .has_fragmented_packets = connection.ipv6->has_fragmented_packets,
        .fragmented_packet_count = connection.ipv6->fragmented_packet_count,
        .aggregate_stats = connection.ipv6->aggregate_stats,
        .packet_count = connection.ipv6->packet_count,
        .total_bytes = connection.ipv6->total_bytes,
        .has_flow_a = connection.ipv6->has_flow_a,
        .has_flow_b = connection.ipv6->has_flow_b,
        .packets_a_to_b = connection.ipv6->has_flow_a ? connection.ipv6->flow_a.packet_count : 0U,
        .packets_b_to_a = connection.ipv6->has_flow_b ? connection.ipv6->flow_b.packet_count : 0U,
        .original_bytes_a_to_b = connection.ipv6->has_flow_a ? connection.ipv6->flow_a.total_bytes : 0U,
        .original_bytes_b_to_a = connection.ipv6->has_flow_b ? connection.ipv6->flow_b.total_bytes : 0U,
    };
}

std::optional<CanonicalFlowMetadata> make_canonical_flow_metadata(
    const CaptureIndexV16ConnectionMetadataV4& row
) {
    if (!row.has_flow_a || row.flow_a.packet_count == 0U) {
        return std::nullopt;
    }

    const EndpointKeyV4 endpoint_a {
        .addr = row.flow_a.key.src_addr,
        .port = row.flow_a.key.src_port,
    };
    const EndpointKeyV4 endpoint_b {
        .addr = row.flow_a.key.dst_addr,
        .port = row.flow_a.key.dst_port,
    };

    return CanonicalFlowMetadata {
        .canonical_index = row.canonical_connection_ordinal,
        .family = FlowAddressFamily::ipv4,
        .key = row.key,
        .endpoint_a = endpoint_a,
        .endpoint_b = endpoint_b,
        .protocol_path_id = row.key.protocol_path_id,
        .protocol = row.key.protocol,
        .protocol_hint = row.protocol_hint,
        .service_hint = row.service_hint,
        .quic_version = row.quic_version,
        .tls_version = row.tls_version,
        .has_fragmented_packets = row.has_fragmented_packets,
        .fragmented_packet_count = row.fragmented_packet_count,
        .aggregate_stats = row.aggregate_stats,
        .packet_count = row.flow_a.packet_count + (row.has_flow_b ? row.flow_b.packet_count : 0U),
        .total_bytes = row.flow_a.original_byte_count + (row.has_flow_b ? row.flow_b.original_byte_count : 0U),
        .has_flow_a = row.has_flow_a,
        .has_flow_b = row.has_flow_b,
        .packets_a_to_b = row.flow_a.packet_count,
        .packets_b_to_a = row.has_flow_b ? row.flow_b.packet_count : 0U,
        .original_bytes_a_to_b = row.flow_a.original_byte_count,
        .original_bytes_b_to_a = row.has_flow_b ? row.flow_b.original_byte_count : 0U,
    };
}

std::optional<CanonicalFlowMetadata> make_canonical_flow_metadata(
    const CaptureIndexV16ConnectionMetadataV6& row
) {
    if (!row.has_flow_a || row.flow_a.packet_count == 0U) {
        return std::nullopt;
    }

    const EndpointKeyV6 endpoint_a {
        .addr = row.flow_a.key.src_addr,
        .port = row.flow_a.key.src_port,
    };
    const EndpointKeyV6 endpoint_b {
        .addr = row.flow_a.key.dst_addr,
        .port = row.flow_a.key.dst_port,
    };

    return CanonicalFlowMetadata {
        .canonical_index = row.canonical_connection_ordinal,
        .family = FlowAddressFamily::ipv6,
        .key = row.key,
        .endpoint_a = endpoint_a,
        .endpoint_b = endpoint_b,
        .protocol_path_id = row.key.protocol_path_id,
        .protocol = row.key.protocol,
        .protocol_hint = row.protocol_hint,
        .service_hint = row.service_hint,
        .quic_version = row.quic_version,
        .tls_version = row.tls_version,
        .has_fragmented_packets = row.has_fragmented_packets,
        .fragmented_packet_count = row.fragmented_packet_count,
        .aggregate_stats = row.aggregate_stats,
        .packet_count = row.flow_a.packet_count + (row.has_flow_b ? row.flow_b.packet_count : 0U),
        .total_bytes = row.flow_a.original_byte_count + (row.has_flow_b ? row.flow_b.original_byte_count : 0U),
        .has_flow_a = row.has_flow_a,
        .has_flow_b = row.has_flow_b,
        .packets_a_to_b = row.flow_a.packet_count,
        .packets_b_to_a = row.has_flow_b ? row.flow_b.packet_count : 0U,
        .original_bytes_a_to_b = row.flow_a.original_byte_count,
        .original_bytes_b_to_a = row.has_flow_b ? row.flow_b.original_byte_count : 0U,
    };
}

void add_protocol_stats(ProtocolStats& stats, const ListedConnectionRef& connection) noexcept {
    ++stats.flow_count;
    stats.packet_count += packet_count(connection);
    stats.captured_bytes += captured_bytes(connection);
    stats.original_bytes += total_bytes(connection);
}

void add_protocol_stats(ProtocolStats& stats, const CanonicalFlowMetadata& flow) noexcept {
    ++stats.flow_count;
    stats.packet_count += flow.packet_count;
    stats.captured_bytes += flow.aggregate_stats.captured_bytes;
    stats.original_bytes += flow.total_bytes;
}

namespace {

void accumulate_protocol_stats(ProtocolStats& destination, const ProtocolStats& source) noexcept {
    destination.flow_count += source.flow_count;
    destination.packet_count += source.packet_count;
    destination.captured_bytes += source.captured_bytes;
    destination.original_bytes += source.original_bytes;
}

}  // namespace

CaptureProtocolSummary project_protocol_summary(
    const CaptureGeneralStatistics& statistics,
    const bool use_possible_tls_quic
) noexcept {
    CaptureProtocolSummary summary {
        .tcp = statistics.protocol.tcp,
        .udp = statistics.protocol.udp,
        .sctp = statistics.protocol.sctp,
        .other = statistics.protocol.other,
        .ipv4 = statistics.protocol.ipv4,
        .ipv6 = statistics.protocol.ipv6,
        .hint_http = statistics.protocol.hint_http,
        .hint_tls = statistics.protocol.hint_tls,
        .hint_dns = statistics.protocol.hint_dns,
        .hint_quic = statistics.protocol.hint_quic,
        .hint_ssh = statistics.protocol.hint_ssh,
        .hint_stun = statistics.protocol.hint_stun,
        .hint_bittorrent = statistics.protocol.hint_bittorrent,
        .hint_dhcp = statistics.protocol.hint_dhcp,
        .hint_mdns = statistics.protocol.hint_mdns,
        .hint_smtp = statistics.protocol.hint_smtp,
        .hint_pop3 = statistics.protocol.hint_pop3,
        .hint_imap = statistics.protocol.hint_imap,
        .hint_mail_protocols = statistics.protocol.hint_mail_protocols,
        .hint_unknown = statistics.protocol.hint_unknown_without_possible,
    };

    if (use_possible_tls_quic) {
        summary.hint_possible_tls = statistics.protocol.hint_possible_tls_candidate;
        summary.hint_possible_quic = statistics.protocol.hint_possible_quic_candidate;
    } else {
        accumulate_protocol_stats(summary.hint_unknown, statistics.protocol.hint_possible_tls_candidate);
        accumulate_protocol_stats(summary.hint_unknown, statistics.protocol.hint_possible_quic_candidate);
    }

    return summary;
}

CaptureTopSummary slice_top_summary(const CaptureTopSummary& summary, const std::size_t limit) {
    CaptureTopSummary projected {};
    projected.endpoints_by_bytes.assign(
        summary.endpoints_by_bytes.begin(),
        summary.endpoints_by_bytes.begin() +
            static_cast<std::ptrdiff_t>(std::min(limit, summary.endpoints_by_bytes.size()))
    );
    projected.ports_by_bytes.assign(
        summary.ports_by_bytes.begin(),
        summary.ports_by_bytes.begin() +
            static_cast<std::ptrdiff_t>(std::min(limit, summary.ports_by_bytes.size()))
    );
    projected.flows_by_original_bytes = summary.flows_by_original_bytes;
    return projected;
}

std::vector<PacketRef> collect_packets(const ConnectionV4& connection) {
    std::vector<PacketRef> packets {};
    packets.reserve(connection.flow_a.packets.size() + connection.flow_b.packets.size());
    packets.insert(packets.end(), connection.flow_a.packets.begin(), connection.flow_a.packets.end());
    packets.insert(packets.end(), connection.flow_b.packets.begin(), connection.flow_b.packets.end());
    std::sort(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index < right.packet_index;
    });
    return packets;
}

std::vector<PacketRef> collect_packets(const ConnectionV6& connection) {
    std::vector<PacketRef> packets {};
    packets.reserve(connection.flow_a.packets.size() + connection.flow_b.packets.size());
    packets.insert(packets.end(), connection.flow_a.packets.begin(), connection.flow_a.packets.end());
    packets.insert(packets.end(), connection.flow_b.packets.begin(), connection.flow_b.packets.end());
    std::sort(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index < right.packet_index;
    });
    return packets;
}

std::optional<FlowRow> make_flow_row(
    const std::size_t index,
    const ListedConnectionRef& connection,
    const AnalysisSettings& settings
) {
    if (!is_listable_connection(connection)) {
        return std::nullopt;
    }

    const auto hint = effective_protocol_hint(connection, settings);
    const auto hint_text = hint == FlowProtocolHint::unknown ? std::string {} : std::string(flow_protocol_hint_text(hint));

    if (connection.family == FlowAddressFamily::ipv4) {
        const auto& key = connection.ipv4->key;
        const auto endpoint_a = first_observed_endpoint_a(*connection.ipv4);
        const auto endpoint_b = first_observed_endpoint_b(*connection.ipv4);
        if (!endpoint_a.has_value() || !endpoint_b.has_value()) {
            return std::nullopt;
        }
        return FlowRow {
            .index = index,
            .family = FlowAddressFamily::ipv4,
            .key = key,
            .protocol_path_id = key.protocol_path_id,
            .protocol_text = format_flow_protocol_text(key.protocol),
            .protocol_hint = hint_text,
            .service_hint = connection.ipv4->service_hint,
            .has_fragmented_packets = connection.ipv4->has_fragmented_packets,
            .fragmented_packet_count = connection.ipv4->fragmented_packet_count,
            .address_a = format_ipv4_address(endpoint_a->addr),
            .port_a = endpoint_a->port,
            .endpoint_a = format_endpoint(*endpoint_a),
            .address_b = format_ipv4_address(endpoint_b->addr),
            .port_b = endpoint_b->port,
            .endpoint_b = format_endpoint(*endpoint_b),
            .packet_count = connection.ipv4->packet_count,
            .total_bytes = connection.ipv4->total_bytes,
        };
    }

    const auto& key = connection.ipv6->key;
    const auto endpoint_a = first_observed_endpoint_a(*connection.ipv6);
    const auto endpoint_b = first_observed_endpoint_b(*connection.ipv6);
    if (!endpoint_a.has_value() || !endpoint_b.has_value()) {
        return std::nullopt;
    }
    return FlowRow {
        .index = index,
        .family = FlowAddressFamily::ipv6,
        .key = key,
        .protocol_path_id = key.protocol_path_id,
        .protocol_text = format_flow_protocol_text(key.protocol),
        .protocol_hint = hint_text,
        .service_hint = connection.ipv6->service_hint,
        .has_fragmented_packets = connection.ipv6->has_fragmented_packets,
        .fragmented_packet_count = connection.ipv6->fragmented_packet_count,
        .address_a = format_ipv6_address(endpoint_a->addr),
        .port_a = endpoint_a->port,
        .endpoint_a = format_endpoint(*endpoint_a),
        .address_b = format_ipv6_address(endpoint_b->addr),
        .port_b = endpoint_b->port,
        .endpoint_b = format_endpoint(*endpoint_b),
        .packet_count = connection.ipv6->packet_count,
        .total_bytes = connection.ipv6->total_bytes,
    };
}

std::optional<FlowRow> make_flow_row(
    const CanonicalFlowMetadata& flow,
    const AnalysisSettings& settings
) {
    const auto hint = effective_protocol_hint(flow, settings);
    const auto hint_text = hint == FlowProtocolHint::unknown ? std::string {} : std::string(flow_protocol_hint_text(hint));

    if (flow.family == FlowAddressFamily::ipv4) {
        const auto& endpoint_a = std::get<EndpointKeyV4>(flow.endpoint_a);
        const auto& endpoint_b = std::get<EndpointKeyV4>(flow.endpoint_b);
        return FlowRow {
            .index = flow.canonical_index,
            .family = FlowAddressFamily::ipv4,
            .key = flow.key,
            .protocol_path_id = flow.protocol_path_id,
            .protocol_text = format_flow_protocol_text(flow.protocol),
            .protocol_hint = hint_text,
            .service_hint = flow.service_hint,
            .has_fragmented_packets = flow.has_fragmented_packets,
            .fragmented_packet_count = flow.fragmented_packet_count,
            .address_a = format_ipv4_address(endpoint_a.addr),
            .port_a = endpoint_a.port,
            .endpoint_a = format_endpoint(endpoint_a),
            .address_b = format_ipv4_address(endpoint_b.addr),
            .port_b = endpoint_b.port,
            .endpoint_b = format_endpoint(endpoint_b),
            .packet_count = flow.packet_count,
            .total_bytes = flow.total_bytes,
        };
    }

    const auto& endpoint_a = std::get<EndpointKeyV6>(flow.endpoint_a);
    const auto& endpoint_b = std::get<EndpointKeyV6>(flow.endpoint_b);
    return FlowRow {
        .index = flow.canonical_index,
        .family = FlowAddressFamily::ipv6,
        .key = flow.key,
        .protocol_path_id = flow.protocol_path_id,
        .protocol_text = format_flow_protocol_text(flow.protocol),
        .protocol_hint = hint_text,
        .service_hint = flow.service_hint,
        .has_fragmented_packets = flow.has_fragmented_packets,
        .fragmented_packet_count = flow.fragmented_packet_count,
        .address_a = format_ipv6_address(endpoint_a.addr),
        .port_a = endpoint_a.port,
        .endpoint_a = format_endpoint(endpoint_a),
        .address_b = format_ipv6_address(endpoint_b.addr),
        .port_b = endpoint_b.port,
        .endpoint_b = format_endpoint(endpoint_b),
        .packet_count = flow.packet_count,
        .total_bytes = flow.total_bytes,
    };
}

std::string format_flow_protocol_hint_display(const std::string_view value) {
    if (value == "possible_tls") {
        return "Possible TLS";
    }
    if (value == "possible_quic") {
        return "Possible QUIC";
    }
    if (value == "igmp") {
        return "IGMP";
    }
    if (value == "igmpv1") {
        return "IGMPv1";
    }
    if (value == "igmpv2") {
        return "IGMPv2";
    }
    if (value == "igmpv3") {
        return "IGMPv3";
    }
    if (value == "mdns") {
        return "mDNS";
    }

    return upper_ascii(value);
}

bool flow_row_matches_text_filter(const FlowRow& row, const std::string_view filter) noexcept {
    if (filter.empty()) {
        return true;
    }

    return contains_case_insensitive_text(flow_family_text(row.family), filter)
        || contains_case_insensitive_text(row.protocol_text, filter)
        || contains_case_insensitive_text(row.protocol_hint, filter)
        || contains_case_insensitive_text(row.service_hint, filter)
        || contains_case_insensitive_text(row.address_a, filter)
        || contains_case_insensitive_text(row.address_b, filter)
        || contains_case_insensitive_text(row.endpoint_a, filter)
        || contains_case_insensitive_text(row.endpoint_b, filter)
        || contains_case_insensitive_text(std::to_string(row.port_a), filter)
        || contains_case_insensitive_text(std::to_string(row.port_b), filter);
}

FlowQueryResult query_flow_indices(
    const std::span<const ListedConnectionRef> connections,
    const AnalysisSettings& settings,
    const FlowQuery& query
) {
    FlowQueryResult result {};

    if (query.limit.has_value() && *query.limit == 0U) {
        result.status = FlowQueryStatus::invalid_limit;
        return result;
    }

    std::vector<std::size_t> candidate_indices {};
    if (query.selected_flow_indices.has_value()) {
        candidate_indices = *query.selected_flow_indices;
        for (const auto flow_index : candidate_indices) {
            if (flow_index >= connections.size()) {
                result.status = FlowQueryStatus::invalid_flow_index;
                result.invalid_flow_index = flow_index;
                return result;
            }
        }

        std::sort(candidate_indices.begin(), candidate_indices.end());
        candidate_indices.erase(std::unique(candidate_indices.begin(), candidate_indices.end()), candidate_indices.end());
    } else {
        candidate_indices.resize(connections.size());
        for (std::size_t index = 0; index < connections.size(); ++index) {
            candidate_indices[index] = index;
        }
    }

    if (query.text_filter.empty() && !query.sort.has_value()) {
        result.result_count_before_limit = candidate_indices.size();
        if (query.limit.has_value() && candidate_indices.size() > *query.limit) {
            candidate_indices.resize(*query.limit);
        }
        result.ordered_flow_indices = std::move(candidate_indices);
        return result;
    }

    std::vector<FlowQueryCandidate> candidates {};
    candidates.reserve(candidate_indices.size());
    for (const auto flow_index : candidate_indices) {
        const auto row = make_flow_row(flow_index, connections[flow_index], settings);
        if (!row.has_value()) {
            result.status = FlowQueryStatus::invalid_flow_index;
            result.invalid_flow_index = flow_index;
            return result;
        }
        candidates.push_back(FlowQueryCandidate {
            .index = flow_index,
            .row = *row,
        });
    }

    if (!query.text_filter.empty()) {
        std::erase_if(candidates, [&](const FlowQueryCandidate& candidate) {
            return !flow_row_matches_text_filter(candidate.row, query.text_filter);
        });
    }

    if (query.sort.has_value()) {
        const auto sort_spec = *query.sort;
        std::stable_sort(candidates.begin(), candidates.end(), [&](const FlowQueryCandidate& left, const FlowQueryCandidate& right) {
            const auto comparison = compare_flow_rows_for_sort(left.row, right.row, sort_spec.key);
            if (comparison == 0) {
                return left.index < right.index;
            }

            return sort_spec.direction == FlowQuerySortDirection::ascending
                ? comparison < 0
                : comparison > 0;
        });
    }

    result.result_count_before_limit = candidates.size();
    if (query.limit.has_value() && candidates.size() > *query.limit) {
        candidates.resize(*query.limit);
    }

    result.ordered_flow_indices.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        result.ordered_flow_indices.push_back(candidate.index);
    }
    return result;
}

FlowQueryResult query_flow_indices(
    const std::span<const CanonicalFlowMetadata> flows,
    const AnalysisSettings& settings,
    const FlowQuery& query
) {
    FlowQueryResult result {};

    if (query.limit.has_value() && *query.limit == 0U) {
        result.status = FlowQueryStatus::invalid_limit;
        return result;
    }

    std::vector<std::size_t> candidate_indices {};
    if (query.selected_flow_indices.has_value()) {
        candidate_indices = *query.selected_flow_indices;
        for (const auto flow_index : candidate_indices) {
            if (flow_index >= flows.size()) {
                result.status = FlowQueryStatus::invalid_flow_index;
                result.invalid_flow_index = flow_index;
                return result;
            }
        }

        std::sort(candidate_indices.begin(), candidate_indices.end());
        candidate_indices.erase(std::unique(candidate_indices.begin(), candidate_indices.end()), candidate_indices.end());
    } else {
        candidate_indices.resize(flows.size());
        for (std::size_t index = 0; index < flows.size(); ++index) {
            candidate_indices[index] = index;
        }
    }

    if (query.text_filter.empty() && !query.sort.has_value()) {
        result.result_count_before_limit = candidate_indices.size();
        if (query.limit.has_value() && candidate_indices.size() > *query.limit) {
            candidate_indices.resize(*query.limit);
        }
        result.ordered_flow_indices = std::move(candidate_indices);
        return result;
    }

    std::vector<FlowQueryCandidate> candidates {};
    candidates.reserve(candidate_indices.size());
    for (const auto flow_index : candidate_indices) {
        const auto row = make_flow_row(flows[flow_index], settings);
        if (!row.has_value()) {
            result.status = FlowQueryStatus::invalid_flow_index;
            result.invalid_flow_index = flow_index;
            return result;
        }
        candidates.push_back(FlowQueryCandidate {
            .index = flow_index,
            .row = *row,
        });
    }

    if (!query.text_filter.empty()) {
        std::erase_if(candidates, [&](const FlowQueryCandidate& candidate) {
            return !flow_row_matches_text_filter(candidate.row, query.text_filter);
        });
    }

    if (query.sort.has_value()) {
        const auto sort_spec = *query.sort;
        std::stable_sort(candidates.begin(), candidates.end(), [&](const FlowQueryCandidate& left, const FlowQueryCandidate& right) {
            const auto comparison = compare_flow_rows_for_sort(left.row, right.row, sort_spec.key);
            if (comparison == 0) {
                return left.index < right.index;
            }

            return sort_spec.direction == FlowQuerySortDirection::ascending
                ? comparison < 0
                : comparison > 0;
        });
    }

    result.result_count_before_limit = candidates.size();
    if (query.limit.has_value() && candidates.size() > *query.limit) {
        candidates.resize(*query.limit);
    }

    result.ordered_flow_indices.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        result.ordered_flow_indices.push_back(candidate.index);
    }
    return result;
}

FlowPacketCountHistogram build_flow_packet_count_histogram(const std::vector<ListedConnectionRef>& connections) {
    return build_capture_general_statistics(
        std::span<const ListedConnectionRef>(connections.data(), connections.size()),
        0U
    ).flow_packet_count_histogram;
}

CaptureStatisticsSnapshot make_capture_statistics_snapshot(
    const CapturePacketStatistics& packet_statistics,
    const CaptureGeneralStatistics& general_statistics,
    const CaptureStatisticsScope scope
) {
    CaptureStatisticsSnapshot snapshot {};
    snapshot.scope = scope;
    snapshot.total_packet_count = packet_statistics.total_packet_count;
    snapshot.total_flow_count = general_statistics.flow_characteristics.total_flow_count;
    snapshot.total_captured_bytes = packet_statistics.total_captured_bytes;
    snapshot.total_original_bytes = packet_statistics.total_original_bytes;
    snapshot.timestamp_range = packet_statistics.timestamp_range;
    snapshot.truncated_packet_count = packet_statistics.truncated_packet_count;
    snapshot.maximum_captured_packet_length = packet_statistics.maximum_captured_packet_length;
    snapshot.maximum_original_packet_length = packet_statistics.maximum_original_packet_length;
    snapshot.captured_packet_size_distribution = packet_statistics.captured_size_distribution;
    snapshot.original_packet_size_distribution = packet_statistics.original_size_distribution;
    snapshot.unrecognized_packet_count = packet_statistics.unrecognized_packet_count;
    snapshot.unrecognized_captured_bytes = packet_statistics.unrecognized_captured_bytes;
    snapshot.unrecognized_original_bytes = packet_statistics.unrecognized_original_bytes;
    snapshot.only_a_to_b_flow_count = general_statistics.flow_characteristics.only_a_to_b_flow_count;
    snapshot.service_recognized_flow_count = general_statistics.flow_characteristics.service_recognized_flow_count;
    snapshot.packet_direction_distribution = make_direction_distribution(
        general_statistics.packet_direction_distribution
    );
    snapshot.original_byte_direction_distribution = make_direction_distribution(
        general_statistics.original_byte_direction_distribution
    );
    snapshot.tcp_flags = make_tcp_flags(general_statistics.tcp_flags);
    snapshot.flow_packet_count_histogram = make_default_capture_statistics_flow_packet_count_histogram();
    snapshot.flow_packet_count_histogram.total_flow_count =
        general_statistics.flow_packet_count_histogram.total_flow_count;
    snapshot.flow_packet_count_histogram.total_captured_byte_count =
        general_statistics.flow_packet_count_histogram.total_captured_byte_count;
    snapshot.flow_packet_count_histogram.total_original_byte_count =
        general_statistics.flow_packet_count_histogram.total_original_byte_count;
    snapshot.flow_packet_count_histogram.maximum_bucket_flow_count =
        general_statistics.flow_packet_count_histogram.maximum_bucket_flow_count;
    snapshot.flow_packet_count_histogram.maximum_bucket_captured_byte_count =
        general_statistics.flow_packet_count_histogram.maximum_bucket_captured_byte_count;
    snapshot.flow_packet_count_histogram.maximum_bucket_original_byte_count =
        general_statistics.flow_packet_count_histogram.maximum_bucket_original_byte_count;
    snapshot.flow_packet_count_histogram.excluded_zero_packet_flow_count =
        general_statistics.flow_packet_count_histogram.excluded_zero_packet_flow_count;
    snapshot.flow_packet_count_histogram.excluded_zero_packet_captured_byte_count =
        general_statistics.flow_packet_count_histogram.excluded_zero_packet_captured_byte_count;
    snapshot.flow_packet_count_histogram.excluded_zero_packet_original_byte_count =
        general_statistics.flow_packet_count_histogram.excluded_zero_packet_original_byte_count;
    for (std::size_t index = 0U;
         index < general_statistics.flow_packet_count_histogram.buckets.size() &&
         index < snapshot.flow_packet_count_histogram.buckets.size();
         ++index) {
        snapshot.flow_packet_count_histogram.buckets[index].flow_count =
            general_statistics.flow_packet_count_histogram.buckets[index].flow_count;
        snapshot.flow_packet_count_histogram.buckets[index].captured_byte_count =
            general_statistics.flow_packet_count_histogram.buckets[index].captured_byte_count;
        snapshot.flow_packet_count_histogram.buckets[index].original_byte_count =
            general_statistics.flow_packet_count_histogram.buckets[index].original_byte_count;
    }

    snapshot.transport_protocols = {
        CaptureStatisticsTransportProtocolRow {
            .category = CaptureStatisticsTransportProtocolCategory::tcp,
            .counters = make_protocol_counters(general_statistics.protocol.tcp),
        },
        CaptureStatisticsTransportProtocolRow {
            .category = CaptureStatisticsTransportProtocolCategory::udp,
            .counters = make_protocol_counters(general_statistics.protocol.udp),
        },
        CaptureStatisticsTransportProtocolRow {
            .category = CaptureStatisticsTransportProtocolCategory::sctp,
            .counters = make_protocol_counters(general_statistics.protocol.sctp),
        },
        CaptureStatisticsTransportProtocolRow {
            .category = CaptureStatisticsTransportProtocolCategory::other,
            .counters = make_protocol_counters(general_statistics.protocol.other),
        },
    };

    snapshot.ip_families = {
        CaptureStatisticsIpFamilyRow {
            .category = CaptureStatisticsIpFamilyCategory::ipv4,
            .counters = make_protocol_counters(general_statistics.protocol.ipv4),
        },
        CaptureStatisticsIpFamilyRow {
            .category = CaptureStatisticsIpFamilyCategory::ipv6,
            .counters = make_protocol_counters(general_statistics.protocol.ipv6),
        },
    };

    snapshot.detected_protocols = {
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::http,
            .counters = make_protocol_counters(general_statistics.protocol.hint_http),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::tls,
            .counters = make_protocol_counters(general_statistics.protocol.hint_tls),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::dns,
            .counters = make_protocol_counters(general_statistics.protocol.hint_dns),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::quic,
            .counters = make_protocol_counters(general_statistics.protocol.hint_quic),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::ssh,
            .counters = make_protocol_counters(general_statistics.protocol.hint_ssh),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::stun,
            .counters = make_protocol_counters(general_statistics.protocol.hint_stun),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::bittorrent,
            .counters = make_protocol_counters(general_statistics.protocol.hint_bittorrent),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::dhcp,
            .counters = make_protocol_counters(general_statistics.protocol.hint_dhcp),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::mdns,
            .counters = make_protocol_counters(general_statistics.protocol.hint_mdns),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::smtp,
            .counters = make_protocol_counters(general_statistics.protocol.hint_smtp),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::pop3,
            .counters = make_protocol_counters(general_statistics.protocol.hint_pop3),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::imap,
            .counters = make_protocol_counters(general_statistics.protocol.hint_imap),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::mail_protocols,
            .counters = make_protocol_counters(general_statistics.protocol.hint_mail_protocols),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::possible_tls_candidate,
            .counters = make_protocol_counters(general_statistics.protocol.hint_possible_tls_candidate),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::possible_quic_candidate,
            .counters = make_protocol_counters(general_statistics.protocol.hint_possible_quic_candidate),
        },
        CaptureStatisticsDetectedProtocolRow {
            .category = CaptureStatisticsDetectedProtocolCategory::unknown_without_possible,
            .counters = make_protocol_counters(general_statistics.protocol.hint_unknown_without_possible),
        },
    };

    snapshot.quic_recognition = CaptureStatisticsQuicRecognition {
        .flow_count = general_statistics.quic_tls_summary.quic.total_flows,
        .with_sni_count = general_statistics.quic_tls_summary.quic.with_sni,
        .without_sni_count = general_statistics.quic_tls_summary.quic.without_sni,
        .v1_count = general_statistics.quic_tls_summary.quic.version_v1,
        .draft29_count = general_statistics.quic_tls_summary.quic.version_draft29,
        .v2_count = general_statistics.quic_tls_summary.quic.version_v2,
        .version_unavailable_count = general_statistics.quic_tls_summary.quic.version_unknown,
    };
    snapshot.tls_recognition = CaptureStatisticsTlsRecognition {
        .flow_count = general_statistics.quic_tls_summary.tls.total_flows,
        .with_sni_count = general_statistics.quic_tls_summary.tls.with_sni,
        .without_sni_count = general_statistics.quic_tls_summary.tls.without_sni,
        .tls12_count = general_statistics.quic_tls_summary.tls.version_tls12,
        .tls13_count = general_statistics.quic_tls_summary.tls.version_tls13,
        .version_unavailable_count = general_statistics.quic_tls_summary.tls.version_unknown,
    };

    snapshot.top_endpoints.reserve(general_statistics.top_summary.endpoints_by_bytes.size());
    for (const auto& row : general_statistics.top_summary.endpoints_by_bytes) {
        snapshot.top_endpoints.push_back(CaptureStatisticsTopEndpointRow {
            .endpoint = row.identity,
            .flow_count = row.flow_count,
            .packet_count = row.packet_count,
            .captured_bytes = row.captured_bytes,
            .original_bytes = row.total_bytes,
        });
    }

    snapshot.top_ports.reserve(general_statistics.top_summary.ports_by_bytes.size());
    for (const auto& row : general_statistics.top_summary.ports_by_bytes) {
        snapshot.top_ports.push_back(CaptureStatisticsTopPortRow {
            .port = row.port,
            .flow_count = row.flow_count,
            .packet_count = row.packet_count,
            .captured_bytes = row.captured_bytes,
            .original_bytes = row.total_bytes,
        });
    }

    snapshot.top_flows.reserve(general_statistics.top_summary.flows_by_original_bytes.size());
    for (const auto& row : general_statistics.top_summary.flows_by_original_bytes) {
        snapshot.top_flows.push_back(CaptureStatisticsTopFlowRow {
            .canonical_flow_ordinal = static_cast<std::uint32_t>(row.flow_index),
            .family = make_capture_statistics_address_family(row.family),
            .connection_key = row.key,
            .endpoint_a = row.endpoint_a_key,
            .endpoint_b = row.endpoint_b_key,
            .flow_protocol = row.protocol,
            .protocol_hint = row.protocol_hint,
            .service_hint = row.service_hint,
            .protocol_path_id = row.protocol_path_id,
            .packet_count = row.packet_count,
            .captured_bytes = row.captured_bytes,
            .original_bytes = row.total_bytes,
        });
    }

    return snapshot;
}

CaptureGeneralStatistics build_capture_general_statistics(
    const std::span<const ListedConnectionRef> connections,
    const std::size_t top_summary_capacity
) {
    CaptureGeneralStatistics statistics {};
    append_flow_packet_histogram_bucket_definitions(statistics.flow_packet_count_histogram);
    std::unordered_map<EndpointKeyV4, EndpointAccumulator, EndpointKeyV4Hash> top_endpoint_rows_v4 {};
    std::unordered_map<EndpointKeyV6, EndpointAccumulator, EndpointKeyV6Hash> top_endpoint_rows_v6 {};
    std::vector<PortAccumulator> top_port_rows {};
    std::vector<std::uint16_t> touched_ports {};
    std::vector<TopFlowRow> top_flow_heap {};

    if (top_summary_capacity > 0U) {
        top_port_rows.resize(static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()) + 1U);
        touched_ports.reserve(std::min(connections.size() * 2U, top_summary_capacity * 4U));
        top_flow_heap.reserve(kTopFlowSummaryCapacity);
    }

    for (std::size_t connection_index = 0U; connection_index < connections.size(); ++connection_index) {
        const auto& connection = connections[connection_index];
        if (connection.family == FlowAddressFamily::ipv4) {
            add_protocol_stats(statistics.protocol.ipv4, connection);
        } else {
            add_protocol_stats(statistics.protocol.ipv6, connection);
        }

        switch (protocol_id(connection)) {
        case ProtocolId::tcp:
            add_protocol_stats(statistics.protocol.tcp, connection);
            break;
        case ProtocolId::udp:
            add_protocol_stats(statistics.protocol.udp, connection);
            break;
        case ProtocolId::sctp:
            add_protocol_stats(statistics.protocol.sctp, connection);
            break;
        default:
            add_protocol_stats(statistics.protocol.other, connection);
            break;
        }

        observe_protocol_hint(statistics.protocol, connection);
        observe_histogram(statistics.flow_packet_count_histogram, connection);

        ++statistics.flow_characteristics.total_flow_count;
        if (directional_packet_count(connection, Direction::a_to_b) > 0U &&
            directional_packet_count(connection, Direction::b_to_a) == 0U) {
            ++statistics.flow_characteristics.only_a_to_b_flow_count;
        }
        if (!service_hint(connection).empty()) {
            ++statistics.flow_characteristics.service_recognized_flow_count;
        }

        add_distribution_flow(
            statistics.packet_direction_distribution,
            classify_direction_distribution(
                directional_packet_count(connection, Direction::a_to_b),
                directional_packet_count(connection, Direction::b_to_a)
            )
        );
        add_distribution_flow(
            statistics.original_byte_direction_distribution,
            classify_direction_distribution(
                directional_original_byte_count(connection, Direction::a_to_b),
                directional_original_byte_count(connection, Direction::b_to_a)
            )
        );

        statistics.tcp_flags.syn_packet_count += aggregate_stats(connection).tcp_syn_count;
        statistics.tcp_flags.fin_packet_count += aggregate_stats(connection).tcp_fin_count;
        statistics.tcp_flags.rst_packet_count += aggregate_stats(connection).tcp_rst_count;

        switch (protocol_hint(connection)) {
        case FlowProtocolHint::quic:
            ++statistics.quic_tls_summary.quic.total_flows;
            if (service_hint(connection).empty()) {
                ++statistics.quic_tls_summary.quic.without_sni;
            } else {
                ++statistics.quic_tls_summary.quic.with_sni;
            }

            switch (connection.family == FlowAddressFamily::ipv4
                    ? connection.ipv4->quic_version
                    : connection.ipv6->quic_version) {
            case QuicVersionHint::v1:
                ++statistics.quic_tls_summary.quic.version_v1;
                break;
            case QuicVersionHint::draft29:
                ++statistics.quic_tls_summary.quic.version_draft29;
                break;
            case QuicVersionHint::v2:
                ++statistics.quic_tls_summary.quic.version_v2;
                break;
            case QuicVersionHint::unknown:
            default:
                ++statistics.quic_tls_summary.quic.version_unknown;
                break;
            }
            break;
        case FlowProtocolHint::tls:
            ++statistics.quic_tls_summary.tls.total_flows;
            if (service_hint(connection).empty()) {
                ++statistics.quic_tls_summary.tls.without_sni;
            } else {
                ++statistics.quic_tls_summary.tls.with_sni;
            }

            switch (connection.family == FlowAddressFamily::ipv4
                    ? connection.ipv4->tls_version
                    : connection.ipv6->tls_version) {
            case TlsVersionHint::tls12:
                ++statistics.quic_tls_summary.tls.version_tls12;
                break;
            case TlsVersionHint::tls13:
                ++statistics.quic_tls_summary.tls.version_tls13;
                break;
            case TlsVersionHint::unknown:
            default:
                ++statistics.quic_tls_summary.tls.version_unknown;
                break;
            }
            break;
        default:
            break;
        }

        if (top_summary_capacity > 0U) {
            const auto packets_for_flow = packet_count(connection);
            const auto captured_bytes_for_flow = captured_bytes(connection);
            const auto original_bytes_for_flow = total_bytes(connection);

            if (connection.family == FlowAddressFamily::ipv4) {
                const auto endpoint_a = first_observed_endpoint_a(*connection.ipv4);
                const auto endpoint_b = first_observed_endpoint_b(*connection.ipv4);
                if (endpoint_a.has_value()) {
                    observe_endpoint_accumulator(
                        top_endpoint_rows_v4[*endpoint_a],
                        packets_for_flow,
                        captured_bytes_for_flow,
                        original_bytes_for_flow
                    );
                }
                if (endpoint_b.has_value() && (!endpoint_a.has_value() || *endpoint_b != *endpoint_a)) {
                    observe_endpoint_accumulator(
                        top_endpoint_rows_v4[*endpoint_b],
                        packets_for_flow,
                        captured_bytes_for_flow,
                        original_bytes_for_flow
                    );
                }
            } else {
                const auto endpoint_a = first_observed_endpoint_a(*connection.ipv6);
                const auto endpoint_b = first_observed_endpoint_b(*connection.ipv6);
                if (endpoint_a.has_value()) {
                    observe_endpoint_accumulator(
                        top_endpoint_rows_v6[*endpoint_a],
                        packets_for_flow,
                        captured_bytes_for_flow,
                        original_bytes_for_flow
                    );
                }
                if (endpoint_b.has_value() && (!endpoint_a.has_value() || *endpoint_b != *endpoint_a)) {
                    observe_endpoint_accumulator(
                        top_endpoint_rows_v6[*endpoint_b],
                        packets_for_flow,
                        captured_bytes_for_flow,
                        original_bytes_for_flow
                    );
                }
            }

            const auto first_port = connection.family == FlowAddressFamily::ipv4
                ? connection.ipv4->key.first.port
                : connection.ipv6->key.first.port;
            const auto second_port = connection.family == FlowAddressFamily::ipv4
                ? connection.ipv4->key.second.port
                : connection.ipv6->key.second.port;

            if (first_port != 0U) {
                if (top_port_rows[first_port].flow_count == 0U) {
                    touched_ports.push_back(first_port);
                }
                observe_port_accumulator(
                    top_port_rows[first_port],
                    packets_for_flow,
                    captured_bytes_for_flow,
                    original_bytes_for_flow
                );
            }
            if (second_port != 0U && second_port != first_port) {
                if (top_port_rows[second_port].flow_count == 0U) {
                    touched_ports.push_back(second_port);
                }
                observe_port_accumulator(
                    top_port_rows[second_port],
                    packets_for_flow,
                    captured_bytes_for_flow,
                    original_bytes_for_flow
                );
            }

            if (const auto top_flow_row = make_top_flow_row(connection_index, connection); top_flow_row.has_value()) {
                retain_top_candidate(
                    top_flow_heap,
                    *top_flow_row,
                    kTopFlowSummaryCapacity,
                    top_flow_row_better
                );
            }
        }
    }

    finalize_histogram(statistics.flow_packet_count_histogram);
    if (top_summary_capacity > 0U) {
        statistics.top_summary = build_top_summary_from_aggregates(
            top_endpoint_rows_v4,
            top_endpoint_rows_v6,
            top_port_rows,
            touched_ports,
            std::move(top_flow_heap),
            top_summary_capacity
        );
    }

#ifndef NDEBUG
    const auto packet_distribution_sum =
        statistics.packet_direction_distribution.mostly_a_to_b_flow_count +
        statistics.packet_direction_distribution.balanced_flow_count +
        statistics.packet_direction_distribution.mostly_b_to_a_flow_count;
    assert(packet_distribution_sum == statistics.flow_characteristics.total_flow_count);

    const auto original_byte_distribution_sum =
        statistics.original_byte_direction_distribution.mostly_a_to_b_flow_count +
        statistics.original_byte_direction_distribution.balanced_flow_count +
        statistics.original_byte_direction_distribution.mostly_b_to_a_flow_count;
    assert(original_byte_distribution_sum == statistics.flow_characteristics.total_flow_count);

    const auto quic_sni_sum =
        statistics.quic_tls_summary.quic.with_sni + statistics.quic_tls_summary.quic.without_sni;
    const auto quic_version_sum =
        statistics.quic_tls_summary.quic.version_v1 +
        statistics.quic_tls_summary.quic.version_draft29 +
        statistics.quic_tls_summary.quic.version_v2 +
        statistics.quic_tls_summary.quic.version_unknown;
    assert(quic_sni_sum == statistics.quic_tls_summary.quic.total_flows);
    assert(quic_version_sum == statistics.quic_tls_summary.quic.total_flows);

    const auto tls_sni_sum =
        statistics.quic_tls_summary.tls.with_sni + statistics.quic_tls_summary.tls.without_sni;
    const auto tls_version_sum =
        statistics.quic_tls_summary.tls.version_tls12 +
        statistics.quic_tls_summary.tls.version_tls13 +
        statistics.quic_tls_summary.tls.version_unknown;
    assert(tls_sni_sum == statistics.quic_tls_summary.tls.total_flows);
    assert(tls_version_sum == statistics.quic_tls_summary.tls.total_flows);
#endif

    return statistics;
}

ProtocolPathDisplayStatistics build_protocol_path_display_statistics(
    const CaptureState& state,
    const std::vector<ListedConnectionRef>& connections
) {
    return build_protocol_path_display_statistics_impl(state, connections).statistics;
}

CaptureIndexV16WritePlanBuildResult build_capture_index_v16_write_plan(
    const CaptureState& state,
    const CaptureIndexV16PacketRefDetailLayoutOptions& options
) {
    struct UnrecognizedReasonLocation {
        std::uint32_t section_occurrence_index {0};
        std::uint64_t payload_offset {0};
        std::uint64_t byte_length {0};
    };

    CaptureIndexV16WritePlanBuildResult result {};
    const auto connections = list_connections(state);
    if (connections.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)())) {
        result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
        result.error_detail = "canonical connection ordinals exceed the supported v16 u32 range";
        return result;
    }

    result.plan.metadata.ipv4_connections.reserve(state.ipv4_connections.size());
    result.plan.metadata.ipv6_connections.reserve(state.ipv6_connections.size());
    result.plan.metadata.packetref_directory.reserve(connections.size() * 2U);
    result.plan.packetref_detail_sections.reserve(connections.size());
    result.plan.unrecognized_directory_sections.reserve(1U);
    result.plan.unrecognized_reason_sections.reserve(1U);
    result.plan.packet_locator_sections.reserve(1U);
    result.plan.packet_locator_entries = std::span<const CapturePacketLocatorEntry>(
        state.packet_locator.data(),
        state.packet_locator.size()
    );

    std::unordered_map<ProtocolPathId, std::size_t> membership_row_indices {};
    membership_row_indices.reserve(connections.size());
    std::vector<UnrecognizedReasonLocation> unrecognized_reason_locations {};
    unrecognized_reason_locations.reserve(state.unrecognized_packets.size());

    auto ensure_detail_section =
        [&](const bool require_empty_section) -> CaptureIndexV16PacketRefDetailSectionWritePlan& {
            if (result.plan.packetref_detail_sections.empty() ||
                (require_empty_section &&
                 !result.plan.packetref_detail_sections.back().extents.empty())) {
                result.plan.packetref_detail_sections.push_back(CaptureIndexV16PacketRefDetailSectionWritePlan {
                    .section_occurrence_index = static_cast<std::uint32_t>(result.plan.packetref_detail_sections.size()),
                });
            }

            return result.plan.packetref_detail_sections.back();
        };

    auto ensure_unrecognized_directory_section =
        [&](const bool require_empty_section) -> CaptureIndexV16UnrecognizedDirectorySectionWritePlan& {
            if (result.plan.unrecognized_directory_sections.empty() ||
                (require_empty_section &&
                 !result.plan.unrecognized_directory_sections.back().rows.empty())) {
                std::uint64_t logical_row_start {0};
                if (!result.plan.unrecognized_directory_sections.empty()) {
                    const auto& prior = result.plan.unrecognized_directory_sections.back();
                    logical_row_start = prior.logical_row_start +
                        static_cast<std::uint64_t>(prior.rows.size());
                }

                result.plan.unrecognized_directory_sections.push_back(
                    CaptureIndexV16UnrecognizedDirectorySectionWritePlan {
                        .section_occurrence_index = static_cast<std::uint32_t>(
                            result.plan.unrecognized_directory_sections.size()),
                        .payload_size = 8U,
                        .logical_row_start = logical_row_start,
                    });
            }

            return result.plan.unrecognized_directory_sections.back();
        };

    auto ensure_unrecognized_reason_section =
        [&](const bool require_empty_section) -> CaptureIndexV16UnrecognizedReasonSectionWritePlan& {
            if (result.plan.unrecognized_reason_sections.empty() ||
                (require_empty_section &&
                 !result.plan.unrecognized_reason_sections.back().extents.empty())) {
                result.plan.unrecognized_reason_sections.push_back(CaptureIndexV16UnrecognizedReasonSectionWritePlan {
                    .section_occurrence_index = static_cast<std::uint32_t>(
                        result.plan.unrecognized_reason_sections.size()),
                });
            }

            return result.plan.unrecognized_reason_sections.back();
        };

    auto ensure_packet_locator_section =
        [&](const bool require_empty_section) -> CaptureIndexV16PacketLocatorSectionWritePlan& {
            if (result.plan.packet_locator_sections.empty() ||
                (require_empty_section &&
                 result.plan.packet_locator_sections.back().entry_count > 0U)) {
                std::uint64_t logical_entry_start {0};
                if (!result.plan.packet_locator_sections.empty()) {
                    const auto& prior = result.plan.packet_locator_sections.back();
                    logical_entry_start = prior.logical_entry_start + prior.entry_count;
                }

                result.plan.packet_locator_sections.push_back(CaptureIndexV16PacketLocatorSectionWritePlan {
                    .section_occurrence_index = static_cast<std::uint32_t>(
                        result.plan.packet_locator_sections.size()),
                    .payload_size = 8U,
                    .logical_entry_start = logical_entry_start,
                });
            }

            return result.plan.packet_locator_sections.back();
        };

    auto append_directory_extent =
        [&](const std::uint32_t canonical_connection_ordinal,
            const Direction direction,
            const auto& flow) -> bool {
            if (!directional_flow_is_structurally_valid(flow)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::invalid_directional_packet_count;
                result.error_detail = "directional flow packet_count must match non-empty PacketRef storage";
                return false;
            }

            if (!packet_refs_strictly_increasing(flow)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::invalid_directional_packet_order;
                result.error_detail = "directional PacketRef sequence must be strictly increasing by packet_index";
                return false;
            }

            std::uint64_t encoded_byte_length {0};
            if (!checked_multiply_u64(flow.packet_count, kCaptureIndexV16PacketRefEncodedStrideBytes, encoded_byte_length)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
                result.error_detail = "PacketRef extent encoded length overflowed";
                return false;
            }

            auto& detail_section = ensure_detail_section(false);
            std::uint64_t combined_payload_size {0};
            if (!checked_add_u64(detail_section.payload_size, encoded_byte_length, combined_payload_size)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
                result.error_detail = "PacketRef detail section payload size overflowed";
                return false;
            }

            if (detail_section.payload_size > 0U &&
                encoded_byte_length > 0U &&
                combined_payload_size > options.target_section_payload_bytes) {
                result.plan.packetref_detail_sections.push_back(CaptureIndexV16PacketRefDetailSectionWritePlan {
                    .section_occurrence_index = static_cast<std::uint32_t>(result.plan.packetref_detail_sections.size()),
                });
            }

            auto& target_section = ensure_detail_section(false);
            const auto payload_offset = target_section.payload_size;
            std::uint64_t next_payload_size {0};
            if (!checked_add_u64(payload_offset, encoded_byte_length, next_payload_size)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
                result.error_detail = "PacketRef detail section payload size overflowed";
                return false;
            }

            target_section.extents.push_back(CaptureIndexV16PacketRefExtentWritePlan {
                .canonical_connection_ordinal = canonical_connection_ordinal,
                .direction = direction,
                .packet_count = flow.packet_count,
                .detail_section_occurrence_index = target_section.section_occurrence_index,
                .payload_offset = payload_offset,
                .encoded_byte_length = encoded_byte_length,
                .packet_refs = packet_refs_for_direction(flow),
            });
            target_section.payload_size = next_payload_size;

            result.plan.metadata.packetref_directory.push_back(CaptureIndexV16PacketRefDirectoryEntry {
                .canonical_connection_ordinal = canonical_connection_ordinal,
                .direction = direction,
                .packet_count = flow.packet_count,
                .detail_section_occurrence_index = target_section.section_occurrence_index,
                .payload_offset = payload_offset,
                .encoded_byte_length = encoded_byte_length,
            });

            std::uint64_t total_packetref_count {0};
            if (!checked_add_u64(result.plan.total_packetref_count, flow.packet_count, total_packetref_count)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
                result.error_detail = "total PacketRef count overflowed";
                return false;
            }
            result.plan.total_packetref_count = total_packetref_count;

            return true;
        };

    {
        std::optional<std::uint64_t> prior_packet_index {};
        for (std::size_t index = 0U; index < state.unrecognized_packets.size(); ++index) {
            const auto& record = state.unrecognized_packets[index];
            if (prior_packet_index.has_value() &&
                record.packet.packet_index <= *prior_packet_index) {
                result.status = CaptureIndexV16WritePlanBuildStatus::invalid_unrecognized_packet_order;
                result.error_detail =
                    "unrecognized packet sequence must be strictly increasing by packet_index";
                return result;
            }
            prior_packet_index = record.packet.packet_index;

            const auto reason_length = static_cast<std::uint64_t>(record.reason_text.size());
            auto& reason_section = ensure_unrecognized_reason_section(false);
            std::uint64_t combined_reason_payload_size {0};
            if (!checked_add_u64(reason_section.payload_size, reason_length, combined_reason_payload_size)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
                result.error_detail = "unrecognized reason payload size overflowed";
                return result;
            }

            if (reason_section.payload_size > 0U &&
                reason_length > 0U &&
                combined_reason_payload_size > options.target_unrecognized_reason_blob_section_payload_bytes) {
                result.plan.unrecognized_reason_sections.push_back(CaptureIndexV16UnrecognizedReasonSectionWritePlan {
                    .section_occurrence_index = static_cast<std::uint32_t>(
                        result.plan.unrecognized_reason_sections.size()),
                });
            }

            auto& target_reason_section = ensure_unrecognized_reason_section(false);
            const auto reason_payload_offset = target_reason_section.payload_size;
            std::uint64_t next_reason_payload_size {0};
            if (!checked_add_u64(reason_payload_offset, reason_length, next_reason_payload_size)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
                result.error_detail = "unrecognized reason payload size overflowed";
                return result;
            }

            target_reason_section.extents.push_back(CaptureIndexV16UnrecognizedReasonExtentWritePlan {
                .source_row_index = static_cast<std::uint64_t>(index),
                .payload_offset = reason_payload_offset,
                .reason_text = record.reason_text,
            });
            target_reason_section.payload_size = next_reason_payload_size;
            unrecognized_reason_locations.push_back(UnrecognizedReasonLocation {
                .section_occurrence_index = target_reason_section.section_occurrence_index,
                .payload_offset = reason_payload_offset,
                .byte_length = reason_length,
            });
        }
    }

    {
        std::optional<std::uint64_t> prior_packet_index {};
        std::optional<std::uint64_t> prior_file_offset {};
        for (std::size_t index = 0U; index < state.packet_locator.size(); ++index) {
            const auto& entry = state.packet_locator[index];
            if ((prior_packet_index.has_value() && entry.packet_index <= *prior_packet_index) ||
                (prior_file_offset.has_value() && entry.file_offset <= *prior_file_offset)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::invalid_packet_locator_order;
                result.error_detail =
                    "packet locator entries must be strictly increasing by packet_index and file_offset";
                return result;
            }
            prior_packet_index = entry.packet_index;
            prior_file_offset = entry.file_offset;

            auto& locator_section = ensure_packet_locator_section(false);
            std::uint64_t prospective_payload_size {0};
            if (!checked_add_u64(
                    locator_section.payload_size,
                    kCaptureIndexV16PacketLocatorEncodedStrideBytes,
                    prospective_payload_size)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
                result.error_detail = "packet locator section payload size overflowed";
                return result;
            }

            if (locator_section.entry_count > 0U &&
                prospective_payload_size > options.target_packet_locator_section_payload_bytes) {
                result.plan.packet_locator_sections.push_back(CaptureIndexV16PacketLocatorSectionWritePlan {
                    .section_occurrence_index = static_cast<std::uint32_t>(
                        result.plan.packet_locator_sections.size()),
                    .payload_size = 8U,
                    .logical_entry_start = locator_section.logical_entry_start + locator_section.entry_count,
                });
            }

            auto& target_locator_section = ensure_packet_locator_section(false);
            std::uint64_t next_payload_size {0};
            if (!checked_add_u64(
                    target_locator_section.payload_size,
                    kCaptureIndexV16PacketLocatorEncodedStrideBytes,
                    next_payload_size)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
                result.error_detail = "packet locator section payload size overflowed";
                return result;
            }
            target_locator_section.payload_size = next_payload_size;
            ++target_locator_section.entry_count;
        }
    }

    for (std::size_t index = 0U; index < connections.size(); ++index) {
        const auto& connection = connections[index];
        const auto canonical_connection_ordinal = static_cast<std::uint32_t>(index);
        const auto path_id = protocol_path_id(connection);
        if (path_id == kInvalidProtocolPathId || state.protocol_path_registry.find(path_id) == nullptr) {
            result.status = CaptureIndexV16WritePlanBuildStatus::invalid_protocol_path_id;
            result.error_detail = "canonical connection metadata referenced an invalid Protocol Path";
            return result;
        }

        const auto [membership_it, inserted] = membership_row_indices.try_emplace(
            path_id,
            result.plan.metadata.protocol_path_membership.size()
        );
        if (inserted) {
            result.plan.metadata.protocol_path_membership.push_back(CaptureIndexV16ProtocolPathMembershipRow {
                .protocol_path_id = path_id,
            });
        }
        result.plan.metadata.protocol_path_membership[membership_it->second]
            .canonical_connection_ordinals.push_back(canonical_connection_ordinal);

        if (connection.family == FlowAddressFamily::ipv4) {
            if (!has_valid_first_observed_orientation(*connection.ipv4)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::invalid_first_observed_orientation;
                result.error_detail = "IPv4 connection violated first-observed A/B orientation";
                return result;
            }

            CaptureIndexV16ConnectionMetadataV4 row {
                .canonical_connection_ordinal = canonical_connection_ordinal,
                .key = connection.ipv4->key,
                .protocol_hint = connection.ipv4->protocol_hint,
                .service_hint = connection.ipv4->service_hint,
                .quic_version = connection.ipv4->quic_version,
                .tls_version = connection.ipv4->tls_version,
                .has_fragmented_packets = connection.ipv4->has_fragmented_packets,
                .fragmented_packet_count = connection.ipv4->fragmented_packet_count,
                .aggregate_stats = connection.ipv4->aggregate_stats,
                .has_flow_a = connection.ipv4->has_flow_a,
                .has_flow_b = connection.ipv4->has_flow_b,
            };

            if (row.has_flow_a) {
                row.flow_a = CaptureIndexV16DirectionalFlowMetadataV4 {
                    .key = connection.ipv4->flow_a.key,
                    .packet_count = connection.ipv4->flow_a.packet_count,
                    .original_byte_count = connection.ipv4->flow_a.total_bytes,
                };
                if (!append_directory_extent(canonical_connection_ordinal, Direction::a_to_b, connection.ipv4->flow_a)) {
                    return result;
                }
            }

            if (row.has_flow_b) {
                row.flow_b = CaptureIndexV16DirectionalFlowMetadataV4 {
                    .key = connection.ipv4->flow_b.key,
                    .packet_count = connection.ipv4->flow_b.packet_count,
                    .original_byte_count = connection.ipv4->flow_b.total_bytes,
                };
                if (!append_directory_extent(canonical_connection_ordinal, Direction::b_to_a, connection.ipv4->flow_b)) {
                    return result;
                }
            }

            result.plan.metadata.ipv4_connections.push_back(std::move(row));
            continue;
        }

        if (!has_valid_first_observed_orientation(*connection.ipv6)) {
            result.status = CaptureIndexV16WritePlanBuildStatus::invalid_first_observed_orientation;
            result.error_detail = "IPv6 connection violated first-observed A/B orientation";
            return result;
        }

        CaptureIndexV16ConnectionMetadataV6 row {
            .canonical_connection_ordinal = canonical_connection_ordinal,
            .key = connection.ipv6->key,
            .protocol_hint = connection.ipv6->protocol_hint,
            .service_hint = connection.ipv6->service_hint,
            .quic_version = connection.ipv6->quic_version,
            .tls_version = connection.ipv6->tls_version,
            .has_fragmented_packets = connection.ipv6->has_fragmented_packets,
            .fragmented_packet_count = connection.ipv6->fragmented_packet_count,
            .aggregate_stats = connection.ipv6->aggregate_stats,
            .has_flow_a = connection.ipv6->has_flow_a,
            .has_flow_b = connection.ipv6->has_flow_b,
        };

        if (row.has_flow_a) {
            row.flow_a = CaptureIndexV16DirectionalFlowMetadataV6 {
                .key = connection.ipv6->flow_a.key,
                .packet_count = connection.ipv6->flow_a.packet_count,
                .original_byte_count = connection.ipv6->flow_a.total_bytes,
            };
            if (!append_directory_extent(canonical_connection_ordinal, Direction::a_to_b, connection.ipv6->flow_a)) {
                return result;
            }
        }

        if (row.has_flow_b) {
            row.flow_b = CaptureIndexV16DirectionalFlowMetadataV6 {
                .key = connection.ipv6->flow_b.key,
                .packet_count = connection.ipv6->flow_b.packet_count,
                .original_byte_count = connection.ipv6->flow_b.total_bytes,
            };
            if (!append_directory_extent(canonical_connection_ordinal, Direction::b_to_a, connection.ipv6->flow_b)) {
                return result;
            }
        }

        result.plan.metadata.ipv6_connections.push_back(std::move(row));
    }

    ensure_detail_section(false);
    ensure_unrecognized_directory_section(false);
    ensure_unrecognized_reason_section(false);
    ensure_packet_locator_section(false);

    {
        for (std::size_t index = 0U; index < state.unrecognized_packets.size(); ++index) {
            auto& directory_section = ensure_unrecognized_directory_section(false);
            std::uint64_t prospective_row_payload_size {0};
            if (!checked_add_u64(
                    directory_section.payload_size,
                    kCaptureIndexV16UnrecognizedDirectoryEncodedStrideBytes,
                    prospective_row_payload_size)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
                result.error_detail = "unrecognized directory payload size overflowed";
                return result;
            }
            if (!directory_section.rows.empty() &&
                prospective_row_payload_size > options.target_unrecognized_directory_section_payload_bytes) {
                result.plan.unrecognized_directory_sections.push_back(
                    CaptureIndexV16UnrecognizedDirectorySectionWritePlan {
                        .section_occurrence_index = static_cast<std::uint32_t>(
                            result.plan.unrecognized_directory_sections.size()),
                        .payload_size = 8U,
                        .logical_row_start = directory_section.logical_row_start +
                            static_cast<std::uint64_t>(directory_section.rows.size()),
                    });
            }

            auto& target_directory_section = ensure_unrecognized_directory_section(false);
            std::uint64_t next_row_payload_size {0};
            if (!checked_add_u64(
                    target_directory_section.payload_size,
                    kCaptureIndexV16UnrecognizedDirectoryEncodedStrideBytes,
                    next_row_payload_size)) {
                result.status = CaptureIndexV16WritePlanBuildStatus::numeric_overflow;
                result.error_detail = "unrecognized directory payload size overflowed";
                return result;
            }
            const auto& record = state.unrecognized_packets[index];
            const auto& reason_location = unrecognized_reason_locations[index];
            target_directory_section.rows.push_back(CaptureIndexV16UnrecognizedDirectoryEntry {
                .row_number = static_cast<std::uint64_t>(index) + 1U,
                .packet_index = record.packet.packet_index,
                .ts_sec = record.packet.ts_sec,
                .ts_usec = record.packet.ts_usec,
                .captured_length = record.packet.captured_length,
                .original_length = record.packet.original_length,
                .reason_section_occurrence_index = reason_location.section_occurrence_index,
                .reason_payload_offset = reason_location.payload_offset,
                .reason_byte_length = reason_location.byte_length,
            });
            target_directory_section.payload_size = next_row_payload_size;
        }
    }

    result.plan.metadata.packetref_detail_sections.reserve(result.plan.packetref_detail_sections.size());
    for (const auto& section : result.plan.packetref_detail_sections) {
        result.plan.metadata.packetref_detail_sections.push_back(CaptureIndexV16PacketRefDetailSectionInfo {
            .section_occurrence_index = section.section_occurrence_index,
            .payload_file_offset = 0U,
            .payload_size = section.payload_size,
        });
    }

    result.plan.metadata.unrecognized_directory_sections.reserve(result.plan.unrecognized_directory_sections.size());
    for (const auto& section : result.plan.unrecognized_directory_sections) {
        result.plan.metadata.unrecognized_directory_sections.push_back(
            CaptureIndexV16UnrecognizedDirectorySectionInfo {
                .section_occurrence_index = section.section_occurrence_index,
                .payload_file_offset = 0U,
                .payload_size = section.payload_size,
                .logical_row_start = section.logical_row_start,
                .row_count = static_cast<std::uint64_t>(section.rows.size()),
            });
    }

    result.plan.metadata.unrecognized_reason_sections.reserve(result.plan.unrecognized_reason_sections.size());
    for (const auto& section : result.plan.unrecognized_reason_sections) {
        result.plan.metadata.unrecognized_reason_sections.push_back(CaptureIndexV16UnrecognizedReasonSectionInfo {
            .section_occurrence_index = section.section_occurrence_index,
            .payload_file_offset = 0U,
            .payload_size = section.payload_size,
        });
    }

    result.plan.metadata.packet_locator_sections.reserve(result.plan.packet_locator_sections.size());
    for (const auto& section : result.plan.packet_locator_sections) {
        CaptureIndexV16PacketLocatorSectionInfo info {
            .section_occurrence_index = section.section_occurrence_index,
            .payload_file_offset = 0U,
            .payload_size = section.payload_size,
            .logical_entry_start = section.logical_entry_start,
            .entry_count = section.entry_count,
        };
        if (section.entry_count > 0U) {
            const auto first_index = static_cast<std::size_t>(section.logical_entry_start);
            const auto last_index = static_cast<std::size_t>(section.logical_entry_start + section.entry_count - 1U);
            info.first_packet_index = state.packet_locator[first_index].packet_index;
            info.last_packet_index = state.packet_locator[last_index].packet_index;
            info.first_file_offset = state.packet_locator[first_index].file_offset;
            info.last_file_offset = state.packet_locator[last_index].file_offset;
        }
        result.plan.metadata.packet_locator_sections.push_back(info);
    }

    return result;
}

CaptureProtocolPathSummary build_protocol_path_summary_from_display_statistics(
    const ProtocolPathRegistry& registry,
    const ProtocolPathDisplayStatistics& statistics,
    const std::uint64_t total_flow_count,
    const std::uint64_t total_packet_count,
    const std::uint64_t total_original_byte_count,
    const ProtocolPathStatisticsMode mode
) {
    return build_protocol_path_summary_from_display_statistics_impl(
        registry,
        statistics,
        total_flow_count,
        total_packet_count,
        total_original_byte_count,
        mode,
        nullptr
    );
}

CaptureProtocolPathSummary build_protocol_path_summary(
    const CaptureState& state,
    const std::vector<ListedConnectionRef>& connections,
    const ProtocolPathStatisticsMode mode
) {
    const auto display_statistics = build_protocol_path_display_statistics_impl(state, connections);
    return build_protocol_path_summary_from_display_statistics_impl(
        state.protocol_path_registry,
        display_statistics.statistics,
        display_statistics.total_flow_count,
        display_statistics.total_packet_count,
        display_statistics.total_original_byte_count,
        mode,
        &display_statistics.membership_by_path_id
    );
}

}  // namespace pfl::session_detail
