#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <variant>
#include <vector>

#include "core/domain/ConnectionKey.h"
#include "core/domain/ProtocolPath.h"

namespace pfl {

using FlowIndex = std::uint32_t;

enum class FlowAddressFamily : std::uint8_t {
    ipv4,
    ipv6
};

using FlowConnectionKey = std::variant<ConnectionKeyV4, ConnectionKeyV6>;

struct ProtocolPathBadgeRow {
    std::string short_label {};
    std::string full_name {};
    std::string tooltip {};
    std::string color_key {};
    std::string background_color {};
    std::string border_color {};
    std::string text_color {};
};

struct FlowRow {
    std::size_t index {0};
    FlowAddressFamily family {FlowAddressFamily::ipv4};
    FlowConnectionKey key {ConnectionKeyV4 {}};
    ProtocolPathId protocol_path_id {kInvalidProtocolPathId};
    std::string protocol_text {};
    std::string protocol_hint {};
    std::string service_hint {};
    bool has_fragmented_packets {false};
    std::uint64_t fragmented_packet_count {0};
    std::string address_a {};
    std::uint16_t port_a {0};
    std::string endpoint_a {};
    std::string address_b {};
    std::uint16_t port_b {0};
    std::string endpoint_b {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

struct PacketRow {
    std::uint64_t row_number {0};
    std::uint64_t packet_index {0};
    std::string direction_text {};
    std::string timestamp_text {};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::uint32_t payload_length {0};
    bool is_ip_fragmented {false};
    bool suspected_tcp_retransmission {false};
    std::string tcp_flags_text {};
};

struct UnrecognizedPacketRow {
    std::uint64_t row_number {0};
    std::uint64_t packet_index {0};
    std::string timestamp_text {};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::string reason_text {};
};

struct StreamItemRow {
    std::uint64_t stream_item_index {0};
    std::string direction_text {};
    std::string label {};
    std::uint32_t byte_count {0};
    std::uint32_t packet_count {0};
    std::vector<std::uint64_t> packet_indices {};
    bool has_constricted_contribution {false};
    std::vector<std::string> constricted_contribution_notes {};
    std::vector<std::string> constricted_packet_notes {};
    std::string summary_text {};
    std::string payload_hex_text {};
    std::string protocol_text {};
};

struct ProtocolStats {
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};
};

struct CaptureProtocolSummary {
    ProtocolStats tcp {};
    ProtocolStats udp {};
    ProtocolStats sctp {};
    ProtocolStats other {};
    ProtocolStats ipv4 {};
    ProtocolStats ipv6 {};
    ProtocolStats hint_http {};
    ProtocolStats hint_tls {};
    ProtocolStats hint_dns {};
    ProtocolStats hint_quic {};
    ProtocolStats hint_ssh {};
    ProtocolStats hint_stun {};
    ProtocolStats hint_bittorrent {};
    ProtocolStats hint_dhcp {};
    ProtocolStats hint_mdns {};
    ProtocolStats hint_smtp {};
    ProtocolStats hint_pop3 {};
    ProtocolStats hint_imap {};
    ProtocolStats hint_mail_protocols {};
    ProtocolStats hint_possible_tls {};
    ProtocolStats hint_possible_quic {};
    ProtocolStats hint_unknown {};
};

struct TopEndpointRow {
    std::string endpoint {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

struct TopPortRow {
    std::uint16_t port {0};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

struct QuicRecognitionStats {
    std::uint64_t total_flows {0};
    std::uint64_t with_sni {0};
    std::uint64_t without_sni {0};

    std::uint64_t version_v1 {0};
    std::uint64_t version_draft29 {0};
    std::uint64_t version_v2 {0};
    std::uint64_t version_unknown {0};
};

struct TlsRecognitionStats {
    std::uint64_t total_flows {0};
    std::uint64_t with_sni {0};
    std::uint64_t without_sni {0};

    std::uint64_t version_tls12 {0};
    std::uint64_t version_tls13 {0};
    std::uint64_t version_unknown {0};
};

enum class ProtocolPathStatisticsMode : std::uint8_t {
    kind_overview = 0,
    identity_tree = 1,
    terminal_paths = 2,
};

inline constexpr std::uint64_t kInvalidProtocolPathStatisticsNodeId = 0U;

struct CaptureTopSummary {
    std::vector<TopEndpointRow> endpoints_by_bytes {};
    std::vector<TopPortRow> ports_by_bytes {};
};

struct ProtocolPathStatisticsRow {
    std::uint64_t node_id {kInvalidProtocolPathStatisticsNodeId};
    std::uint64_t parent_node_id {kInvalidProtocolPathStatisticsNodeId};
    std::size_t depth {0};
    LayerKey layer {};
    ProtocolPath path {};
    std::string layer_text {};
    std::string path_text {};
    std::string compact_text {};
    std::vector<ProtocolPathBadgeRow> badges {};
    bool has_children {false};
    bool is_terminal {false};
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t original_byte_count {0};
    double flow_percent {0.0};
    double packet_percent {0.0};
    double original_byte_percent {0.0};
    std::string flow_count_text {};
    std::string packet_count_text {};
    std::string original_byte_count_text {};
};

struct ProtocolPathStatisticsNodeMembershipRange {
    std::size_t offset {0};
    std::size_t count {0};
};

struct CaptureProtocolPathSummary {
    ProtocolPathStatisticsMode mode {ProtocolPathStatisticsMode::kind_overview};
    std::uint64_t total_flow_count {0};
    std::uint64_t total_packet_count {0};
    std::uint64_t total_original_byte_count {0};
    std::vector<ProtocolPathStatisticsRow> rows {};
    std::vector<FlowIndex> flow_index_pool {};
    std::vector<ProtocolPathStatisticsNodeMembershipRange> node_membership_ranges {};
};

}  // namespace pfl
