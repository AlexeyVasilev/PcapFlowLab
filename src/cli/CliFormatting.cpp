#include "cli/CliFormatting.h"

#include <iomanip>
#include <sstream>
#include <vector>

namespace pfl {

std::string format_protocol(ProtocolId protocol) {
    switch (protocol) {
    case ProtocolId::arp:
        return "ARP";
    case ProtocolId::icmp:
        return "ICMP";
    case ProtocolId::tcp:
        return "TCP";
    case ProtocolId::udp:
        return "UDP";
    case ProtocolId::icmpv6:
        return "ICMPv6";
    default:
        return "unknown";
    }
}

std::string format_ipv4_address(std::uint32_t address) {
    std::ostringstream output {};
    output << ((address >> 24U) & 0xFFU) << '.'
           << ((address >> 16U) & 0xFFU) << '.'
           << ((address >> 8U) & 0xFFU) << '.'
           << (address & 0xFFU);
    return output.str();
}

std::string format_ipv6_address(const std::array<std::uint8_t, 16>& address) {
    std::ostringstream output {};
    output << std::hex << std::setfill('0');

    for (std::size_t index = 0; index < 8; ++index) {
        if (index > 0) {
            output << ':';
        }

        const auto word = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(address[index * 2U]) << 8U) |
            static_cast<std::uint16_t>(address[index * 2U + 1U])
        );
        output << std::setw(4) << word;
    }

    return output.str();
}

std::string format_endpoint(const EndpointKeyV4& endpoint) {
    std::ostringstream output {};
    output << format_ipv4_address(endpoint.addr) << ':' << endpoint.port;
    return output.str();
}

std::string format_endpoint(const EndpointKeyV6& endpoint) {
    std::ostringstream output {};
    output << '[' << format_ipv6_address(endpoint.addr) << "]:" << endpoint.port;
    return output.str();
}

std::string format_tcp_flags(std::uint8_t flags) {
    struct FlagName {
        std::uint8_t mask;
        const char* name;
    };

    constexpr FlagName names[] {
        {0x80U, "CWR"},
        {0x40U, "ECE"},
        {0x20U, "URG"},
        {0x10U, "ACK"},
        {0x08U, "PSH"},
        {0x04U, "RST"},
        {0x02U, "SYN"},
        {0x01U, "FIN"},
    };

    std::vector<std::string> parts {};
    for (const auto& flag : names) {
        if ((flags & flag.mask) != 0U) {
            parts.emplace_back(flag.name);
        }
    }

    if (parts.empty()) {
        return "none";
    }

    std::ostringstream output {};
    for (std::size_t index = 0; index < parts.size(); ++index) {
        if (index > 0) {
            output << '|';
        }
        output << parts[index];
    }

    return output.str();
}

}  // namespace pfl
