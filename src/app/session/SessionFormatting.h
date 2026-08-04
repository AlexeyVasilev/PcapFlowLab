#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "app/session/FlowRows.h"
#include "app/session/SessionQuicPresentation.h"
#include "app/session/SessionTlsPresentation.h"
#include "core/domain/ConnectionKey.h"
#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"
#include "core/services/TlsInspectionModel.h"

namespace pfl::session_detail {

struct ArpPresentation {
    std::string title {};
    std::string detail {};
};

struct PacketSummaryField {
    std::string label {};
    std::string value {};
};

enum class PacketDataRole : std::uint8_t {
    none = 0,
    transport_payload,
};

enum class PacketDataTransportKind : std::uint8_t {
    unknown = 0,
    tcp,
    udp,
};

enum class TransportPayloadDisposition : std::uint8_t {
    none = 0,
    unclaimed_data,
    claimed_by_supported_protocol,
    known_opaque_or_encrypted,
    unavailable_or_truncated,
};

enum class PacketDataPlacement : std::uint8_t {
    none = 0,
    after_tcp,
    after_udp,
    after_inner_tcp,
    after_inner_udp,
};

struct PacketDataPresentation {
    PacketDataRole role {PacketDataRole::none};
    PacketDataTransportKind transport {PacketDataTransportKind::unknown};
    TransportPayloadDisposition disposition {TransportPayloadDisposition::none};
    PacketDataPlacement placement {PacketDataPlacement::none};
    std::uint32_t declared_length {0U};
    std::uint32_t captured_length {0U};
    bool declared_length_reliable {false};
    bool truncation_reliable {false};
};

struct PacketSummaryLayer {
    std::string id {};
    std::string title {};
    std::vector<PacketSummaryField> fields {};
    std::vector<PacketSummaryLayer> children {};
    bool expanded_by_default {true};
    bool warning {false};
    std::string marker_text {};
};

struct PacketSummaryOptions {
    bool source_capture_accessible {true};
    // Internal flow-packet index is zero-based; human-readable formatting adds +1.
    std::optional<std::uint64_t> flow_packet_index {};
    std::optional<std::uint32_t> transport_payload_length {};
    std::optional<std::uint32_t> original_transport_payload_length {};
    std::span<const std::uint8_t> transport_payload_bytes {};
    std::vector<std::string> checksum_summary_lines {};
    std::vector<std::string> checksum_warning_lines {};
    std::span<const std::uint8_t> packet_data_preview_bytes {};
    TlsInspectionParserContext tls_initial_parser_context {};
    std::vector<TlsSelectedPacketRecordContext> reconstructed_tls_records {};
    std::vector<PacketSummaryLayer> tls_summary_layers {};
    std::optional<QuicPresentationResult> quic_presentation {};
    std::optional<PacketDataPresentation> packet_data {};
};

std::string format_packet_timestamp(const PacketRef& packet);
std::string format_packet_timestamp_full(const PacketRef& packet);
std::string format_tcp_flags_text(std::uint8_t flags);
std::string format_ipv4_address(std::uint32_t address);
std::string format_ipv4_address(const std::array<std::uint8_t, 4>& address);
std::string format_ipv6_address(const std::array<std::uint8_t, 16>& address);
std::string format_endpoint(const EndpointKeyV4& endpoint);
std::string format_endpoint(const EndpointKeyV6& endpoint);
std::string format_arp_hardware_address(std::span<const std::uint8_t> address);
std::string format_arp_protocol_address(std::uint16_t protocol_type, std::span<const std::uint8_t> address);
std::string format_arp_hardware_type(std::uint16_t hardware_type);
std::string format_arp_protocol_type(std::uint16_t protocol_type);
std::string format_arp_opcode(std::uint16_t opcode);
std::optional<ArpPresentation> describe_arp_packet(const PacketDetails& details);
std::vector<std::string> build_basic_summary_lines(const PacketDetails& details);
std::vector<PacketSummaryLayer> build_tls_summary_layers(std::span<const std::uint8_t> transport_payload_bytes);
std::vector<PacketSummaryLayer> build_tls_summary_layers(
    std::span<const std::uint8_t> transport_payload_bytes,
    TlsInspectionParserContext initial_parser_context,
    bool force_encrypted_handshake_records = false,
    bool force_encrypted_alert_records = false
);
PacketSummaryLayer build_tls_reassembled_metadata_layer(const TlsSelectedPacketRecordContext& context);
std::string stream_item_details_source_text(const StreamItemRow& row);
std::vector<PacketSummaryLayer> build_stream_item_summary_layers(
    const StreamItemRow& row,
    std::string_view source_packets_text
);
std::vector<PacketSummaryLayer> build_packet_summary_layers(
    const PacketDetails& details,
    const PacketRef& packet,
    const PacketSummaryOptions& options = {}
);
std::string packet_payload_tab_title(const PacketDetails& details);
std::optional<std::string> build_basic_protocol_details_text(const PacketDetails& details);

}  // namespace pfl::session_detail
