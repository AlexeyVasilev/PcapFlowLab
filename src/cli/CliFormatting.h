#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "core/domain/ConnectionKey.h"

namespace pfl {

[[nodiscard]] std::string format_protocol(ProtocolId protocol);
[[nodiscard]] std::string format_ipv4_address(std::uint32_t address);
[[nodiscard]] std::string format_ipv6_address(const std::array<std::uint8_t, 16>& address);
[[nodiscard]] std::string format_endpoint(const EndpointKeyV4& endpoint);
[[nodiscard]] std::string format_endpoint(const EndpointKeyV6& endpoint);
[[nodiscard]] std::string format_tcp_flags(std::uint8_t flags);

}  // namespace pfl
