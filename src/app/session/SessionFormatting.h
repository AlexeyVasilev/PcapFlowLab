#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/domain/ConnectionKey.h"
#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"

namespace pfl::session_detail {

struct ArpPresentation {
    std::string title {};
    std::string detail {};
};

struct PacketSummaryField {
    std::string label {};
    std::string value {};
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
    std::optional<std::uint64_t> flow_packet_index {};
    std::optional<std::uint32_t> transport_payload_length {};
    std::optional<std::uint32_t> original_transport_payload_length {};
    std::string protocol_details_text {};
    std::vector<std::string> checksum_summary_lines {};
    std::vector<std::string> checksum_warning_lines {};
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
std::vector<PacketSummaryLayer> build_packet_summary_layers(
    const PacketDetails& details,
    const PacketRef& packet,
    const PacketSummaryOptions& options = {}
);
std::string packet_payload_tab_title(const PacketDetails& details);
std::optional<std::string> build_basic_protocol_details_text(const PacketDetails& details);

}  // namespace pfl::session_detail
