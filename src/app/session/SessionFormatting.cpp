#include "app/session/SessionFormatting.h"

#include <iomanip>
#include <sstream>

namespace pfl::session_detail {

std::string format_packet_timestamp(const PacketRef& packet) {
    const auto seconds_of_day = packet.ts_sec % 86400U;
    const auto hours = seconds_of_day / 3600U;
    const auto minutes = (seconds_of_day % 3600U) / 60U;
    const auto seconds = seconds_of_day % 60U;

    std::ostringstream timestamp {};
    timestamp << std::setfill('0')
              << std::setw(2) << hours << ':'
              << std::setw(2) << minutes << ':'
              << std::setw(2) << seconds << '.'
              << std::setw(6) << packet.ts_usec;
    return timestamp.str();
}

std::string format_tcp_flags_text(const std::uint8_t flags) {
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

    std::ostringstream builder {};
    bool first = true;
    for (const auto& flag : names) {
        if ((flags & flag.mask) == 0U) {
            continue;
        }

        if (!first) {
            builder << '|';
        }

        builder << flag.name;
        first = false;
    }

    return first ? std::string {} : builder.str();
}

std::string format_ipv4_address(const std::uint32_t address) {
    std::ostringstream builder {};
    builder << ((address >> 24U) & 0xFFU) << '.'
            << ((address >> 16U) & 0xFFU) << '.'
            << ((address >> 8U) & 0xFFU) << '.'
            << (address & 0xFFU);
    return builder.str();
}

std::string format_ipv4_address(const std::array<std::uint8_t, 4>& address) {
    std::ostringstream builder {};
    builder << static_cast<unsigned>(address[0]) << '.'
            << static_cast<unsigned>(address[1]) << '.'
            << static_cast<unsigned>(address[2]) << '.'
            << static_cast<unsigned>(address[3]);
    return builder.str();
}

std::string format_ipv6_address(const std::array<std::uint8_t, 16>& address) {
    std::ostringstream builder {};
    builder << std::hex << std::setfill('0');

    for (std::size_t index = 0; index < 8; ++index) {
        if (index > 0) {
            builder << ':';
        }

        const auto word = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(address[index * 2U]) << 8U) |
            static_cast<std::uint16_t>(address[index * 2U + 1U])
        );
        builder << std::setw(4) << word;
    }

    return builder.str();
}

std::string format_endpoint(const EndpointKeyV4& endpoint) {
    std::ostringstream builder {};
    builder << format_ipv4_address(endpoint.addr) << ':' << endpoint.port;
    return builder.str();
}

std::string format_endpoint(const EndpointKeyV6& endpoint) {
    std::ostringstream builder {};
    builder << '[' << format_ipv6_address(endpoint.addr) << "]:" << endpoint.port;
    return builder.str();
}

std::optional<std::string> build_basic_protocol_details_text(const PacketDetails& details) {
    std::ostringstream builder {};

    if (details.has_arp) {
        builder << "ARP\n"
                << "Opcode: " << details.arp.opcode << '\n'
                << "Sender IPv4: " << format_ipv4_address(details.arp.sender_ipv4) << '\n'
                << "Target IPv4: " << format_ipv4_address(details.arp.target_ipv4);
        return builder.str();
    }

    if (details.has_icmp) {
        builder << "ICMP\n"
                << "Type: " << static_cast<unsigned>(details.icmp.type) << '\n'
                << "Code: " << static_cast<unsigned>(details.icmp.code);
        if (details.has_ipv4) {
            builder << '\n'
                    << "Source: " << format_ipv4_address(details.ipv4.src_addr) << '\n'
                    << "Destination: " << format_ipv4_address(details.ipv4.dst_addr);
        }
        return builder.str();
    }

    if (details.has_icmpv6) {
        builder << "ICMPv6\n"
                << "Type: " << static_cast<unsigned>(details.icmpv6.type) << '\n'
                << "Code: " << static_cast<unsigned>(details.icmpv6.code);
        if (details.has_ipv6) {
            builder << '\n'
                    << "Source: " << format_ipv6_address(details.ipv6.src_addr) << '\n'
                    << "Destination: " << format_ipv6_address(details.ipv6.dst_addr);
        }
        return builder.str();
    }

    return std::nullopt;
}

}  // namespace pfl::session_detail
