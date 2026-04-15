#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>

#include "core/domain/ConnectionKey.h"
#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"

namespace pfl::session_detail {

std::string format_packet_timestamp(const PacketRef& packet);
std::string format_tcp_flags_text(std::uint8_t flags);
std::string format_ipv4_address(std::uint32_t address);
std::string format_ipv4_address(const std::array<std::uint8_t, 4>& address);
std::string format_ipv6_address(const std::array<std::uint8_t, 16>& address);
std::string format_endpoint(const EndpointKeyV4& endpoint);
std::string format_endpoint(const EndpointKeyV6& endpoint);
std::optional<std::string> build_basic_protocol_details_text(const PacketDetails& details);

}  // namespace pfl::session_detail
