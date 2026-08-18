#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "core/domain/DnsInspection.h"
#include "core/domain/Direction.h"
#include "app/session/SessionQuicPresentation.h"
#include "core/domain/ConnectionKey.h"
#include "core/domain/ProtocolPath.h"
#include "core/services/TlsInspectionModel.h"

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
    std::optional<std::uint32_t> derived_payload_length {};
    std::optional<bool> derived_is_ip_fragmented {};
    std::optional<std::string> derived_tcp_flags_text {};
};

struct UnrecognizedPacketRow {
    std::uint64_t row_number {0};
    std::uint64_t packet_index {0};
    std::string timestamp_text {};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::string reason_text {};
};

enum class TlsStreamItemSemanticKind : std::uint8_t {
    none = 0,
    change_cipher_spec,
    plaintext_handshake,
    encrypted_handshake,
    application_data,
    alert,
    encrypted_alert,
    generic_record,
    partial_record,
    partial_payload,
    gap,
};

enum class StreamMaterializationStability : std::uint8_t {
    stable = 0,
    window_incomplete,
    pagination_lookahead,
};

enum class StreamItemSemanticFamily : std::uint8_t {
    generic = 0,
    http,
    dns,
    tls,
    quic,
    arp,
    synthetic,
    other,
};

enum class GenericStreamItemSemanticKind : std::uint8_t {
    none = 0,
    tcp_payload,
    udp_payload,
    payload,
    gap,
};

enum class HttpStreamItemSemanticKind : std::uint8_t {
    none = 0,
    request,
    response,
    partial_payload,
    gap,
};

enum class DnsStreamItemSemanticKind : std::uint8_t {
    none = 0,
    dns_query,
    dns_response,
    mdns_query,
    mdns_response,
};

struct GenericStreamItemSummaryDetails {
    GenericStreamItemSemanticKind semantic_kind {GenericStreamItemSemanticKind::none};
    std::string diagnostic {};
};

struct HttpStreamItemSummaryDetails {
    HttpStreamItemSemanticKind semantic_kind {HttpStreamItemSemanticKind::none};
    std::string method {};
    std::string target {};
    std::string version {};
    std::optional<std::uint16_t> status_code {};
    std::string reason_phrase {};
    std::string diagnostic {};
};

struct HttpStreamItemByteOwner {
    Direction direction {Direction::a_to_b};
    std::uint32_t reconstructed_offset {0U};
    std::uint32_t length {0U};
};

struct DnsStreamItemSummaryDetails {
    DnsStreamItemSemanticKind semantic_kind {DnsStreamItemSemanticKind::none};
    DnsMessage message {};
    std::string primary_name {};
    std::optional<std::uint16_t> primary_type {};
    std::optional<std::uint16_t> compact_answer_count {};
};

struct ArpStreamItemSummaryDetails {
    std::string title {};
    std::string detail {};
    std::string sender_hardware_address {};
    std::string sender_protocol_address {};
    std::string target_hardware_address {};
    std::string target_protocol_address {};
    bool fixed_header_truncated {false};
    bool address_section_truncated {false};
};

struct StreamItemRow {
    std::uint64_t stream_item_index {0};
    std::string direction_text {};
    std::string label {};
    std::uint32_t byte_count {0};
    std::uint32_t packet_count {0};
    std::vector<std::uint64_t> packet_indices {};
    StreamMaterializationStability materialization_stability {StreamMaterializationStability::stable};
    StreamItemSemanticFamily semantic_family {StreamItemSemanticFamily::generic};
    bool has_constricted_contribution {false};
    std::vector<std::string> constricted_contribution_notes {};
    std::vector<std::string> constricted_packet_notes {};
    std::string summary_text {};
    std::vector<std::uint8_t> summary_payload_bytes {};
    std::optional<GenericStreamItemSummaryDetails> generic_summary {};
    std::optional<HttpStreamItemSummaryDetails> http_summary {};
    std::optional<HttpStreamItemByteOwner> http_byte_owner {};
    std::optional<DnsStreamItemSummaryDetails> dns_summary {};
    std::optional<ArpStreamItemSummaryDetails> arp_summary {};
    TlsStreamItemSemanticKind tls_semantic_kind {TlsStreamItemSemanticKind::none};
    std::vector<TlsRecordModel> tls_summary_records {};
    TlsInspectionParserContext tls_initial_parser_context {};
    TlsInspectionParserContext tls_final_parser_context {};
    std::optional<session_detail::QuicStreamItemPresentation> quic_stream_presentation {};
};

struct ProtocolStats {
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};
};

struct UnrecognizedPacketStatistics {
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

struct CaptureQuicTlsSummary {
    QuicRecognitionStats quic {};
    TlsRecognitionStats tls {};
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

struct FlowPacketCountHistogramBucket {
    std::string stable_id {};
    std::uint64_t lower_bound_inclusive {0};
    std::optional<std::uint64_t> upper_bound_inclusive {};
    std::uint64_t flow_count {0};
    std::uint64_t original_byte_count {0};
};

struct FlowPacketCountHistogram {
    std::uint64_t total_flow_count {0};
    std::uint64_t total_original_byte_count {0};
    std::uint64_t maximum_bucket_flow_count {0};
    std::uint64_t maximum_bucket_original_byte_count {0};
    std::uint64_t excluded_zero_packet_flow_count {0};
    std::uint64_t excluded_zero_packet_original_byte_count {0};
    std::vector<FlowPacketCountHistogramBucket> buckets {};
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
