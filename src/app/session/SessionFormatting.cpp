#include "app/session/SessionFormatting.h"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace pfl::session_detail {

namespace {

constexpr std::uint16_t kArpHardwareTypeEthernet = 1U;
constexpr std::uint16_t kArpProtocolTypeIpv4 = 0x0800U;
constexpr std::uint16_t kArpOpcodeRequest = 1U;
constexpr std::uint16_t kArpOpcodeReply = 2U;

bool has_complete_arp_sender_ipv4(const PacketDetails& details) {
    return details.has_arp &&
           details.arp.protocol_type == kArpProtocolTypeIpv4 &&
           details.arp.protocol_size == 4U &&
           details.arp.sender_protocol_address.size() == 4U;
}

bool has_complete_arp_target_ipv4(const PacketDetails& details) {
    return details.has_arp &&
           details.arp.protocol_type == kArpProtocolTypeIpv4 &&
           details.arp.protocol_size == 4U &&
           details.arp.target_protocol_address.size() == 4U;
}

bool is_zero_ipv4(const std::array<std::uint8_t, 4>& address) noexcept {
    return std::all_of(address.begin(), address.end(), [](const auto byte) {
        return byte == 0U;
    });
}

std::string format_hex16_value(const std::uint16_t value) {
    std::ostringstream builder {};
    builder << "0x" << std::hex << std::nouppercase << std::setw(4) << std::setfill('0') << value;
    return builder.str();
}

std::string format_hex_byte_sequence(std::span<const std::uint8_t> bytes, const char separator = ':') {
    std::ostringstream builder {};
    builder << std::hex << std::nouppercase << std::setfill('0');

    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0U) {
            builder << separator;
        }
        builder << std::setw(2) << static_cast<unsigned>(bytes[index]);
    }

    return builder.str();
}

std::string format_arp_address_field(
    const std::string& label,
    std::span<const std::uint8_t> address,
    const std::size_t expected_size,
    const std::string& formatted_value
) {
    std::ostringstream builder {};
    builder << label << ": ";
    if (address.empty()) {
        builder << "unavailable";
    } else {
        builder << formatted_value;
        if (address.size() < expected_size) {
            builder << " (truncated)";
        }
    }
    return builder.str();
}

}  // namespace

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

std::string format_packet_timestamp_full(const PacketRef& packet) {
    const auto time = static_cast<std::time_t>(packet.ts_sec);

    std::tm utc {};
#ifdef _WIN32
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif

    std::ostringstream timestamp {};
    timestamp << std::setfill('0')
              << std::setw(4) << (utc.tm_year + 1900) << '-'
              << std::setw(2) << (utc.tm_mon + 1) << '-'
              << std::setw(2) << utc.tm_mday << ' '
              << std::setw(2) << utc.tm_hour << ':'
              << std::setw(2) << utc.tm_min << ':'
              << std::setw(2) << utc.tm_sec << '.'
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

std::string format_arp_hardware_address(std::span<const std::uint8_t> address) {
    return format_hex_byte_sequence(address);
}

std::string format_arp_protocol_address(const std::uint16_t protocol_type, std::span<const std::uint8_t> address) {
    if (protocol_type == kArpProtocolTypeIpv4 && address.size() == 4U) {
        return format_ipv4_address({address[0], address[1], address[2], address[3]});
    }

    return format_hex_byte_sequence(address);
}

std::string format_arp_hardware_type(const std::uint16_t hardware_type) {
    if (hardware_type == kArpHardwareTypeEthernet) {
        return "Ethernet (1)";
    }

    return "Unknown (" + std::to_string(hardware_type) + ")";
}

std::string format_arp_protocol_type(const std::uint16_t protocol_type) {
    if (protocol_type == kArpProtocolTypeIpv4) {
        return "IPv4 (" + format_hex16_value(protocol_type) + ")";
    }

    return format_hex16_value(protocol_type);
}

std::string format_arp_opcode(const std::uint16_t opcode) {
    switch (opcode) {
    case kArpOpcodeRequest:
        return "request (1)";
    case kArpOpcodeReply:
        return "reply (2)";
    default:
        return "opcode " + std::to_string(opcode);
    }
}

std::optional<ArpPresentation> describe_arp_packet(const PacketDetails& details) {
    if (!details.has_arp) {
        return std::nullopt;
    }

    if (details.arp.fixed_header_truncated) {
        return ArpPresentation {
            .title = "ARP",
            .detail = "Truncated ARP header",
        };
    }

    const auto sender_protocol = format_arp_protocol_address(
        details.arp.protocol_type,
        std::span<const std::uint8_t>(details.arp.sender_protocol_address.data(), details.arp.sender_protocol_address.size())
    );
    const auto target_protocol = format_arp_protocol_address(
        details.arp.protocol_type,
        std::span<const std::uint8_t>(details.arp.target_protocol_address.data(), details.arp.target_protocol_address.size())
    );
    const auto sender_hardware = format_arp_hardware_address(
        std::span<const std::uint8_t>(details.arp.sender_hardware_address.data(), details.arp.sender_hardware_address.size())
    );

    const bool sender_ipv4_available = has_complete_arp_sender_ipv4(details);
    const bool target_ipv4_available = has_complete_arp_target_ipv4(details);

    if (details.arp.opcode == kArpOpcodeRequest && sender_ipv4_available && target_ipv4_available) {
        if (is_zero_ipv4(details.arp.sender_ipv4)) {
            return ArpPresentation {
                .title = "ARP Probe",
                .detail = "ARP probe for " + target_protocol,
            };
        }

        if (details.arp.sender_ipv4 == details.arp.target_ipv4) {
            return ArpPresentation {
                .title = "Gratuitous ARP",
                .detail = "Gratuitous ARP for " + sender_protocol,
            };
        }

        return ArpPresentation {
            .title = "ARP Request",
            .detail = "Who has " + target_protocol + "? Tell " + sender_protocol,
        };
    }

    if (details.arp.opcode == kArpOpcodeReply && sender_ipv4_available) {
        if (target_ipv4_available && details.arp.sender_ipv4 == details.arp.target_ipv4) {
            return ArpPresentation {
                .title = "Gratuitous ARP",
                .detail = "Gratuitous ARP for " + sender_protocol,
            };
        }

        return ArpPresentation {
            .title = "ARP Reply",
            .detail = sender_protocol + " is at " + (sender_hardware.empty() ? std::string {"unknown"} : sender_hardware),
        };
    }

    if (details.arp.opcode == kArpOpcodeRequest) {
        return ArpPresentation {
            .title = "ARP Request",
            .detail = "ARP request",
        };
    }

    if (details.arp.opcode == kArpOpcodeReply) {
        return ArpPresentation {
            .title = "ARP Reply",
            .detail = "ARP reply",
        };
    }

    return ArpPresentation {
        .title = "ARP",
        .detail = "ARP opcode " + std::to_string(details.arp.opcode),
    };
}

std::vector<std::string> build_basic_summary_lines(const PacketDetails& details) {
    if (!details.has_arp) {
        return {};
    }

    std::vector<std::string> lines {};
    if (const auto presentation = describe_arp_packet(details); presentation.has_value()) {
        lines.push_back("Message: " + presentation->title);
        if (!presentation->detail.empty()) {
            lines.push_back(presentation->detail);
        }
    }

    lines.push_back(format_arp_address_field(
        "Sender MAC Address",
        std::span<const std::uint8_t>(details.arp.sender_hardware_address.data(), details.arp.sender_hardware_address.size()),
        details.arp.hardware_size,
        format_arp_hardware_address(std::span<const std::uint8_t>(
            details.arp.sender_hardware_address.data(),
            details.arp.sender_hardware_address.size()))
    ));
    lines.push_back(format_arp_address_field(
        "Sender Protocol Address",
        std::span<const std::uint8_t>(details.arp.sender_protocol_address.data(), details.arp.sender_protocol_address.size()),
        details.arp.protocol_size,
        format_arp_protocol_address(
            details.arp.protocol_type,
            std::span<const std::uint8_t>(details.arp.sender_protocol_address.data(), details.arp.sender_protocol_address.size()))
    ));
    lines.push_back(format_arp_address_field(
        "Target MAC Address",
        std::span<const std::uint8_t>(details.arp.target_hardware_address.data(), details.arp.target_hardware_address.size()),
        details.arp.hardware_size,
        format_arp_hardware_address(std::span<const std::uint8_t>(
            details.arp.target_hardware_address.data(),
            details.arp.target_hardware_address.size()))
    ));
    lines.push_back(format_arp_address_field(
        "Target Protocol Address",
        std::span<const std::uint8_t>(details.arp.target_protocol_address.data(), details.arp.target_protocol_address.size()),
        details.arp.protocol_size,
        format_arp_protocol_address(
            details.arp.protocol_type,
            std::span<const std::uint8_t>(details.arp.target_protocol_address.data(), details.arp.target_protocol_address.size()))
    ));

    if (details.arp.fixed_header_truncated) {
        lines.push_back("ARP fixed header is truncated.");
    } else if (details.arp.address_section_truncated) {
        lines.push_back("ARP address section is truncated.");
    }

    return lines;
}

std::string packet_payload_tab_title(const PacketDetails& details) {
    if (details.has_tcp) {
        return "TCP Payload";
    }
    if (details.has_udp) {
        return "UDP Payload";
    }
    if (details.has_arp) {
        return "ARP Payload";
    }
    return "Payload";
}

std::optional<std::string> build_basic_protocol_details_text(const PacketDetails& details) {
    std::ostringstream builder {};

    if (details.has_arp) {
        builder << "Protocol: ARP (Address Resolution Protocol)\n";
        if (!details.arp.fixed_header_truncated || details.arp.hardware_type != 0U) {
            builder << '\t' << "Hardware Type: " << format_arp_hardware_type(details.arp.hardware_type) << '\n';
        }
        if (!details.arp.fixed_header_truncated || details.arp.protocol_type != 0U) {
            builder << '\t' << "Protocol Type: " << format_arp_protocol_type(details.arp.protocol_type) << '\n';
        }
        if (!details.arp.fixed_header_truncated || details.arp.hardware_size != 0U) {
            builder << '\t' << "Hardware Size: " << static_cast<unsigned>(details.arp.hardware_size) << '\n';
        }
        if (!details.arp.fixed_header_truncated || details.arp.protocol_size != 0U) {
            builder << '\t' << "Protocol Size: " << static_cast<unsigned>(details.arp.protocol_size) << '\n';
        }
        if (!details.arp.fixed_header_truncated || details.arp.opcode != 0U) {
            builder << '\t' << "Opcode: " << format_arp_opcode(details.arp.opcode) << '\n';
        }
        builder << '\t' << format_arp_address_field(
                       "Sender MAC Address",
                       std::span<const std::uint8_t>(details.arp.sender_hardware_address.data(), details.arp.sender_hardware_address.size()),
                       details.arp.hardware_size,
                       format_arp_hardware_address(std::span<const std::uint8_t>(
                           details.arp.sender_hardware_address.data(),
                           details.arp.sender_hardware_address.size())))
                << '\n'
                << '\t' << format_arp_address_field(
                       "Sender Protocol Address",
                       std::span<const std::uint8_t>(details.arp.sender_protocol_address.data(), details.arp.sender_protocol_address.size()),
                       details.arp.protocol_size,
                       format_arp_protocol_address(
                           details.arp.protocol_type,
                           std::span<const std::uint8_t>(details.arp.sender_protocol_address.data(), details.arp.sender_protocol_address.size())))
                << '\n'
                << '\t' << format_arp_address_field(
                       "Target MAC Address",
                       std::span<const std::uint8_t>(details.arp.target_hardware_address.data(), details.arp.target_hardware_address.size()),
                       details.arp.hardware_size,
                       format_arp_hardware_address(std::span<const std::uint8_t>(
                           details.arp.target_hardware_address.data(),
                           details.arp.target_hardware_address.size())))
                << '\n'
                << '\t' << format_arp_address_field(
                       "Target Protocol Address",
                       std::span<const std::uint8_t>(details.arp.target_protocol_address.data(), details.arp.target_protocol_address.size()),
                       details.arp.protocol_size,
                       format_arp_protocol_address(
                           details.arp.protocol_type,
                           std::span<const std::uint8_t>(details.arp.target_protocol_address.data(), details.arp.target_protocol_address.size())));
        if (details.arp.fixed_header_truncated) {
            builder << '\n' << '\t' << "Warning: ARP fixed header is truncated.";
        } else if (details.arp.address_section_truncated) {
            builder << '\n' << '\t' << "Warning: ARP address section is truncated.";
        }
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
