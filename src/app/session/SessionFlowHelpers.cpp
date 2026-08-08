#include "app/session/SessionFlowHelpers.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_map>

#include "app/session/ProtocolPathPresentation.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/FlowHints.h"

namespace pfl::session_detail {

namespace {

template <typename Flow>
std::uint64_t sum_captured_bytes(const Flow& flow) noexcept {
    std::uint64_t total {0};
    for (const auto& packet : flow.packets) {
        total += packet.captured_length;
    }

    return total;
}

FlowProtocolHint protocol_hint(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->protocol_hint : connection.ipv6->protocol_hint;
}

bool has_port_443(const ListedConnectionRef& connection) noexcept {
    if (connection.family == FlowAddressFamily::ipv4) {
        return connection.ipv4->key.first.port == 443U || connection.ipv4->key.second.port == 443U;
    }

    return connection.ipv6->key.first.port == 443U || connection.ipv6->key.second.port == 443U;
}

std::string protocol_text(const ProtocolId protocol) {
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

char ascii_lower(const char value) noexcept {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
}

std::string ascii_fold(std::string_view text) {
    std::string folded {};
    folded.reserve(text.size());
    for (const auto ch : text) {
        folded.push_back(ascii_lower(ch));
    }
    return folded;
}

int compare_case_insensitive_text(const std::string_view left, const std::string_view right) {
    const auto folded_left = ascii_fold(left);
    const auto folded_right = ascii_fold(right);
    if (folded_left < folded_right) {
        return -1;
    }
    if (folded_left > folded_right) {
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

std::uint64_t packet_count(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->packet_count : connection.ipv6->packet_count;
}

std::uint64_t captured_bytes(const ListedConnectionRef& connection) noexcept {
    if (connection.family == FlowAddressFamily::ipv4) {
        return sum_captured_bytes(connection.ipv4->flow_a) + sum_captured_bytes(connection.ipv4->flow_b);
    }

    return sum_captured_bytes(connection.ipv6->flow_a) + sum_captured_bytes(connection.ipv6->flow_b);
}

std::uint64_t total_bytes(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->total_bytes : connection.ipv6->total_bytes;
}

ProtocolId protocol_id(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->key.protocol : connection.ipv6->key.protocol;
}

FlowProtocolHint effective_protocol_hint(const ListedConnectionRef& connection, const AnalysisSettings& settings) noexcept {
    const auto confirmed_hint = protocol_hint(connection);
    if (confirmed_hint != FlowProtocolHint::unknown) {
        return confirmed_hint;
    }

    if (!settings.use_possible_tls_quic || !has_port_443(connection)) {
        return FlowProtocolHint::unknown;
    }

    switch (protocol_id(connection)) {
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

void add_protocol_stats(ProtocolStats& stats, const ListedConnectionRef& connection) noexcept {
    ++stats.flow_count;
    stats.packet_count += packet_count(connection);
    stats.captured_bytes += captured_bytes(connection);
    stats.original_bytes += total_bytes(connection);
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
            .protocol_text = protocol_text(key.protocol),
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
        .protocol_text = protocol_text(key.protocol),
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
    FlowPacketCountHistogram histogram {};
    histogram.buckets.reserve(kFlowPacketCountHistogramBucketDefinitions.size());
    for (const auto& definition : kFlowPacketCountHistogramBucketDefinitions) {
        histogram.buckets.push_back(FlowPacketCountHistogramBucket {
            .stable_id = definition.stable_id,
            .lower_bound_inclusive = definition.lower_bound_inclusive,
            .upper_bound_inclusive = definition.upper_bound_inclusive,
            .flow_count = 0U,
            .original_byte_count = 0U,
        });
    }

    for (const auto& connection : connections) {
        const auto packets_for_flow = packet_count(connection);
        const auto original_bytes_for_flow = total_bytes(connection);
        if (packets_for_flow == 0U) {
            ++histogram.excluded_zero_packet_flow_count;
            histogram.excluded_zero_packet_original_byte_count += original_bytes_for_flow;
            continue;
        }

        const auto bucket_index = flow_packet_count_histogram_bucket_index(packets_for_flow);
        ++histogram.buckets[bucket_index].flow_count;
        histogram.buckets[bucket_index].original_byte_count += original_bytes_for_flow;
        ++histogram.total_flow_count;
        histogram.total_original_byte_count += original_bytes_for_flow;
    }

    for (const auto& bucket : histogram.buckets) {
        histogram.maximum_bucket_flow_count = std::max(histogram.maximum_bucket_flow_count, bucket.flow_count);
        histogram.maximum_bucket_original_byte_count = std::max(
            histogram.maximum_bucket_original_byte_count,
            bucket.original_byte_count
        );
    }

    return histogram;
}

CaptureProtocolPathSummary build_protocol_path_summary(
    const CaptureState& state,
    const std::vector<ListedConnectionRef>& connections,
    const ProtocolPathStatisticsMode mode
) {
    CaptureProtocolPathSummary summary {
        .mode = mode,
        // Keep packet shares anchored to the full capture packet count so
        // protocol-path rows remain comparable even when some packets are
        // unrecognized and intentionally excluded from the path tree.
        .total_packet_count = state.summary.packet_count,
    };
    std::unordered_map<PrefixStepKey, std::size_t, PrefixStepKeyHash> node_index_by_prefix_step {};
    std::unordered_map<ProtocolPathId, std::size_t> terminal_node_index_by_path_id {};
    std::vector<ProtocolPathStatisticsAccumulatorNode> nodes {};

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

        ++summary.total_flow_count;
        const auto packets_for_flow = packet_count(connection);
        const auto original_bytes_for_flow = total_bytes(connection);
        summary.total_original_byte_count += original_bytes_for_flow;
        const auto flow_index = static_cast<FlowIndex>(connection_index);

        if (mode == ProtocolPathStatisticsMode::terminal_paths) {
            auto [it, inserted] = terminal_node_index_by_path_id.emplace(path_id, nodes.size());
            if (inserted) {
                nodes.push_back(ProtocolPathStatisticsAccumulatorNode {
                    .depth = 0U,
                    .layer = path->layers().back(),
                    .path = *path,
                    .is_terminal = true,
                });
            }

            auto& node = nodes[it->second];
            node.flow_count += 1U;
            node.packet_count += packets_for_flow;
            node.original_byte_count += original_bytes_for_flow;
            node.flow_indices.push_back(flow_index);
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
            node.flow_count += 1U;
            node.packet_count += packets_for_flow;
            node.original_byte_count += original_bytes_for_flow;
            node.flow_indices.push_back(flow_index);
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
        nodes[index].flow_count_text = format_count_with_percent_text(nodes[index].flow_count, nodes[index].flow_percent);
        nodes[index].packet_count_text = format_count_with_percent_text(nodes[index].packet_count, nodes[index].packet_percent);
        nodes[index].original_byte_count_text = format_byte_count_with_percent_text(
            nodes[index].original_byte_count,
            nodes[index].original_byte_percent
        );
        if (nodes[index].parent_index == std::numeric_limits<std::size_t>::max()) {
            root_indices.push_back(index);
        }
    }

    summary.rows.reserve(nodes.size());
    summary.flow_index_pool.reserve(connections.size() * 2U);
    summary.node_membership_ranges.resize(nodes.size() + 1U);
    append_protocol_path_statistics_rows(nodes, summary, root_indices);
    return summary;
}

}  // namespace pfl::session_detail
