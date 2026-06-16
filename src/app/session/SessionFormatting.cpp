#include "app/session/SessionFormatting.h"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace pfl::session_detail {

namespace {

constexpr std::uint16_t kEtherTypeArp = 0x0806U;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;
constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
constexpr std::uint16_t kEtherTypeQinq = 0x88A8U;
constexpr std::uint16_t kArpHardwareTypeEthernet = 1U;
constexpr std::uint16_t kArpProtocolTypeIpv4 = 0x0800U;
constexpr std::uint16_t kArpOpcodeRequest = 1U;
constexpr std::uint16_t kArpOpcodeReply = 2U;
constexpr std::string_view kNoProtocolDetailsMessage = "No protocol-specific details available for this packet.";
constexpr std::string_view kUnavailableProtocolDetailsMessage = "Protocol details unavailable for this packet.";

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

std::string format_protocol_summary_value(const std::uint8_t protocol) {
    switch (protocol) {
    case 1U:
        return "ICMP";
    case 6U:
        return "TCP";
    case 17U:
        return "UDP";
    case 58U:
        return "ICMPv6";
    default:
        return std::to_string(protocol);
    }
}

std::string format_ether_type_name(const std::uint16_t ether_type) {
    switch (ether_type) {
    case kEtherTypeArp:
        return "ARP";
    case kEtherTypeIpv4:
        return "IPv4";
    case kEtherTypeIpv6:
        return "IPv6";
    case kEtherTypeVlan:
        return "802.1Q VLAN";
    case kEtherTypeQinq:
        return "802.1ad QinQ";
    default:
        return {};
    }
}

std::string format_ether_type_value(const std::uint16_t ether_type) {
    const auto name = format_ether_type_name(ether_type);
    if (name.empty()) {
        return format_hex16_value(ether_type);
    }

    return name + " (" + format_hex16_value(ether_type) + ")";
}

std::uint16_t vlan_identifier(const std::uint16_t tci) noexcept {
    return static_cast<std::uint16_t>(tci & 0x0FFFU);
}

unsigned vlan_priority(const std::uint16_t tci) noexcept {
    return static_cast<unsigned>((tci >> 13U) & 0x7U);
}

unsigned vlan_drop_eligible_indicator(const std::uint16_t tci) noexcept {
    return static_cast<unsigned>((tci >> 12U) & 0x1U);
}

PacketSummaryField make_summary_field(std::string label, std::string value) {
    return PacketSummaryField {
        .label = std::move(label),
        .value = std::move(value),
    };
}

PacketSummaryField make_summary_line_field(const std::string& line) {
    const auto separator_index = line.find(": ");
    if (separator_index == std::string::npos) {
        return make_summary_field({}, line);
    }

    return make_summary_field(
        line.substr(0, separator_index),
        line.substr(separator_index + 2U)
    );
}

void append_layer_if_not_empty(std::vector<PacketSummaryLayer>& layers, PacketSummaryLayer layer) {
    if (!layer.fields.empty() || !layer.children.empty()) {
        layers.push_back(std::move(layer));
    }
}

std::string_view trim_ascii(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r' || text.front() == '\n')) {
        text.remove_prefix(1U);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r' || text.back() == '\n')) {
        text.remove_suffix(1U);
    }
    return text;
}

std::optional<std::string_view> first_non_empty_line(std::string_view text) {
    while (!text.empty()) {
        const auto newline = text.find('\n');
        const auto line = trim_ascii(text.substr(0U, newline));
        if (!line.empty()) {
            return line;
        }
        if (newline == std::string_view::npos) {
            break;
        }
        text.remove_prefix(newline + 1U);
    }
    return std::nullopt;
}

std::optional<std::string> find_protocol_detail_value(
    std::string_view text,
    const std::string_view prefix
) {
    while (!text.empty()) {
        const auto newline = text.find('\n');
        const auto line = trim_ascii(text.substr(0U, newline));
        if (line.size() > prefix.size() && line.substr(0U, prefix.size()) == prefix) {
            return std::string(trim_ascii(line.substr(prefix.size())));
        }
        if (newline == std::string_view::npos) {
            break;
        }
        text.remove_prefix(newline + 1U);
    }
    return std::nullopt;
}

void append_protocol_field_if_present(
    std::vector<PacketSummaryField>& fields,
    std::string label,
    const std::optional<std::string>& value
) {
    if (value.has_value() && !value->empty()) {
        fields.push_back(make_summary_field(std::move(label), *value));
    }
}

std::optional<PacketSummaryLayer> build_icmp_summary_layer(const PacketDetails& details) {
    if (!details.has_icmp) {
        return std::nullopt;
    }

    std::vector<PacketSummaryField> fields {
        make_summary_field("Type", std::to_string(details.icmp.type)),
        make_summary_field("Code", std::to_string(details.icmp.code)),
    };
    if (details.has_ipv4) {
        fields.push_back(make_summary_field("Source", format_ipv4_address(details.ipv4.src_addr)));
        fields.push_back(make_summary_field("Destination", format_ipv4_address(details.ipv4.dst_addr)));
    }

    return PacketSummaryLayer {
        .id = "icmp",
        .title = "Internet Control Message Protocol",
        .fields = std::move(fields),
    };
}

std::optional<PacketSummaryLayer> build_icmpv6_summary_layer(const PacketDetails& details) {
    if (!details.has_icmpv6) {
        return std::nullopt;
    }

    std::vector<PacketSummaryField> fields {
        make_summary_field("Type", std::to_string(details.icmpv6.type)),
        make_summary_field("Code", std::to_string(details.icmpv6.code)),
    };
    if (details.has_ipv6) {
        fields.push_back(make_summary_field("Source", format_ipv6_address(details.ipv6.src_addr)));
        fields.push_back(make_summary_field("Destination", format_ipv6_address(details.ipv6.dst_addr)));
    }

    return PacketSummaryLayer {
        .id = "icmpv6",
        .title = "Internet Control Message Protocol v6",
        .fields = std::move(fields),
    };
}

std::optional<PacketSummaryLayer> build_protocol_text_summary_layer(
    const PacketDetails& details,
    std::string_view protocol_details_text
) {
    protocol_details_text = trim_ascii(protocol_details_text);
    if (protocol_details_text.empty() ||
        protocol_details_text == kNoProtocolDetailsMessage ||
        protocol_details_text == kUnavailableProtocolDetailsMessage ||
        details.has_arp) {
        return std::nullopt;
    }

    if (const auto icmp_layer = build_icmp_summary_layer(details); icmp_layer.has_value()) {
        return icmp_layer;
    }
    if (const auto icmpv6_layer = build_icmpv6_summary_layer(details); icmpv6_layer.has_value()) {
        return icmpv6_layer;
    }

    const auto first_line = first_non_empty_line(protocol_details_text);
    if (!first_line.has_value()) {
        return std::nullopt;
    }

    if (*first_line == "TLS") {
        std::vector<PacketSummaryField> fields {};
        const auto handshake_type = find_protocol_detail_value(protocol_details_text, "Handshake Type:");
        const auto record_type = find_protocol_detail_value(protocol_details_text, "Record Type:");
        const auto sni = find_protocol_detail_value(protocol_details_text, "SNI:");
        append_protocol_field_if_present(fields, "Handshake Type", handshake_type);
        append_protocol_field_if_present(fields, "Record Type", record_type);
        append_protocol_field_if_present(fields, "Record Version", find_protocol_detail_value(protocol_details_text, "Record Version:"));
        append_protocol_field_if_present(fields, "SNI", sni);
        append_protocol_field_if_present(fields, "Selected TLS Version", find_protocol_detail_value(protocol_details_text, "Selected TLS Version:"));

        std::string title = "Transport Layer Security";
        if (handshake_type.has_value()) {
            title += ", " + *handshake_type;
        } else if (record_type.has_value()) {
            title += ", " + *record_type;
        }

        return PacketSummaryLayer {
            .id = "tls",
            .title = std::move(title),
            .fields = std::move(fields),
        };
    }

    if (*first_line == "QUIC") {
        std::vector<PacketSummaryField> fields {};
        const auto packet_type = find_protocol_detail_value(protocol_details_text, "Packet Type:");
        const auto tls_handshake_type = find_protocol_detail_value(protocol_details_text, "TLS Handshake Type:");
        const auto sni = find_protocol_detail_value(protocol_details_text, "SNI:");
        append_protocol_field_if_present(fields, "Packet Type", packet_type);
        append_protocol_field_if_present(fields, "Version", find_protocol_detail_value(protocol_details_text, "Version:"));
        append_protocol_field_if_present(fields, "TLS Handshake Type", tls_handshake_type);
        append_protocol_field_if_present(fields, "SNI", sni);

        std::string title = "QUIC";
        if (packet_type.has_value()) {
            title += ", " + *packet_type;
        }

        return PacketSummaryLayer {
            .id = "quic",
            .title = std::move(title),
            .fields = std::move(fields),
        };
    }

    if (*first_line == "DNS") {
        std::vector<PacketSummaryField> fields {};
        const auto message_type = find_protocol_detail_value(protocol_details_text, "Message Type:");
        const auto qname = find_protocol_detail_value(protocol_details_text, "QName:");
        const auto qtype = find_protocol_detail_value(protocol_details_text, "QType:");
        append_protocol_field_if_present(fields, "Message Type", message_type);
        append_protocol_field_if_present(fields, "QName", qname);
        append_protocol_field_if_present(fields, "QType", qtype);
        append_protocol_field_if_present(fields, "Transaction ID", find_protocol_detail_value(protocol_details_text, "Transaction ID:"));
        append_protocol_field_if_present(fields, "Response Code", find_protocol_detail_value(protocol_details_text, "Response Code:"));

        std::string title = "Domain Name System";
        if (message_type.has_value()) {
            title += ", " + *message_type;
            if (qtype.has_value() && qname.has_value() && *message_type == "Query") {
                title += " " + *qtype + " " + *qname;
            }
        }

        return PacketSummaryLayer {
            .id = "dns",
            .title = std::move(title),
            .fields = std::move(fields),
        };
    }

    if (*first_line == "HTTP") {
        std::vector<PacketSummaryField> fields {};
        const auto message_type = find_protocol_detail_value(protocol_details_text, "Message Type:");
        const auto method = find_protocol_detail_value(protocol_details_text, "Method:");
        const auto path = find_protocol_detail_value(protocol_details_text, "Path:");
        const auto status_code = find_protocol_detail_value(protocol_details_text, "Status Code:");
        append_protocol_field_if_present(fields, "Message Type", message_type);
        append_protocol_field_if_present(fields, "Method", method);
        append_protocol_field_if_present(fields, "Path", path);
        append_protocol_field_if_present(fields, "Version", find_protocol_detail_value(protocol_details_text, "Version:"));
        append_protocol_field_if_present(fields, "Host", find_protocol_detail_value(protocol_details_text, "Host:"));
        append_protocol_field_if_present(fields, "Status Code", status_code);

        std::string title = "Hypertext Transfer Protocol";
        if (method.has_value() && path.has_value()) {
            title += ", " + *method + " " + *path;
        } else if (status_code.has_value()) {
            title += ", Response " + *status_code;
        }

        return PacketSummaryLayer {
            .id = "http",
            .title = std::move(title),
            .fields = std::move(fields),
        };
    }

    return std::nullopt;
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

std::vector<PacketSummaryLayer> build_packet_summary_layers(
    const PacketDetails& details,
    const PacketRef& packet,
    const PacketSummaryOptions& options
) {
    std::vector<PacketSummaryLayer> layers {};
    layers.reserve(8U);

    append_layer_if_not_empty(layers, PacketSummaryLayer {
        .id = "frame",
        .title = "Frame " + std::to_string(details.packet_index),
        .fields = {
            make_summary_field("Packet index in file", std::to_string(details.packet_index)),
            make_summary_field("Timestamp", format_packet_timestamp_full(packet)),
            make_summary_field("Captured Length", std::to_string(details.captured_length) + " bytes"),
            make_summary_field("Original Length", std::to_string(details.original_length) + " bytes"),
        },
    });

    std::vector<PacketSummaryField> warning_fields {};
    if (packet.is_ip_fragmented) {
        warning_fields.push_back(make_summary_field({}, "Packet is IP-fragmented"));
    }
    if (details.captured_length != details.original_length) {
        warning_fields.push_back(make_summary_field({}, "Packet is truncated in capture"));
        warning_fields.push_back(make_summary_field("Captured Length", std::to_string(details.captured_length)));
        warning_fields.push_back(make_summary_field("Original Length", std::to_string(details.original_length)));
    }
    if (details.ipv4_bounds_from_captured_bytes) {
        warning_fields.push_back(make_summary_field({}, "IPv4 total length is unavailable; packet was parsed using captured bytes only"));
        warning_fields.push_back(make_summary_field({}, "Header interpretation is conservative (possible pre-offload packet)"));
    }
    if (!options.source_capture_accessible) {
        warning_fields.push_back(make_summary_field({}, "Byte-backed packet details are unavailable because the original source capture cannot be read."));
    }
    for (const auto& warning : options.checksum_warning_lines) {
        warning_fields.push_back(make_summary_line_field(warning));
    }
    append_layer_if_not_empty(layers, PacketSummaryLayer {
        .id = "warnings",
        .title = "Warnings",
        .fields = std::move(warning_fields),
        .warning = true,
        .marker_text = "Warning",
    });

    std::vector<PacketSummaryField> checksum_fields {};
    checksum_fields.reserve(options.checksum_summary_lines.size());
    for (const auto& line : options.checksum_summary_lines) {
        checksum_fields.push_back(make_summary_line_field(line));
    }
    append_layer_if_not_empty(layers, PacketSummaryLayer {
        .id = "checksums",
        .title = "Checksums",
        .fields = std::move(checksum_fields),
    });

    if (details.has_ethernet) {
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "ethernet",
            .title = "Ethernet II",
            .fields = {
                make_summary_field("EtherType", format_ether_type_value(details.ethernet.ether_type)),
            },
        });
    }

    if (details.has_vlan) {
        for (std::size_t index = 0; index < details.vlan_tags.size(); ++index) {
            const auto& tag = details.vlan_tags[index];
            std::string vlan_id = "vlan";
            if (details.vlan_tags.size() > 1U) {
                vlan_id += "-" + std::to_string(index + 1U);
            }
            append_layer_if_not_empty(layers, PacketSummaryLayer {
                .id = std::move(vlan_id),
                .title = "802.1Q Virtual LAN, PRI: " + std::to_string(vlan_priority(tag.tci)) +
                    ", DEI: " + std::to_string(vlan_drop_eligible_indicator(tag.tci)) +
                    ", ID: " + std::to_string(vlan_identifier(tag.tci)),
                .fields = {
                    make_summary_field("Priority", std::to_string(vlan_priority(tag.tci))),
                    make_summary_field("DEI", std::to_string(vlan_drop_eligible_indicator(tag.tci))),
                    make_summary_field("VLAN ID", std::to_string(vlan_identifier(tag.tci))),
                    make_summary_field("Tag Control Information", std::to_string(tag.tci)),
                    make_summary_field("Encapsulated EtherType", format_ether_type_value(tag.encapsulated_ether_type)),
                },
            });
        }
    }

    if (details.has_arp) {
        std::vector<PacketSummaryField> arp_fields {};
        const auto shared_lines = build_basic_summary_lines(details);
        arp_fields.reserve(shared_lines.size() + 5U);
        if (const auto presentation = describe_arp_packet(details); presentation.has_value()) {
            arp_fields.push_back(make_summary_field("Message", presentation->title));
            if (!presentation->detail.empty()) {
                arp_fields.push_back(make_summary_field({}, presentation->detail));
            }
        }
        arp_fields.push_back(make_summary_field("Hardware Type", format_arp_hardware_type(details.arp.hardware_type)));
        arp_fields.push_back(make_summary_field("Protocol Type", format_arp_protocol_type(details.arp.protocol_type)));
        arp_fields.push_back(make_summary_field("Hardware Size", std::to_string(details.arp.hardware_size)));
        arp_fields.push_back(make_summary_field("Protocol Size", std::to_string(details.arp.protocol_size)));
        arp_fields.push_back(make_summary_field("Opcode", format_arp_opcode(details.arp.opcode)));
        for (const auto& line : shared_lines) {
            if (line.rfind("Message: ", 0U) == 0U ||
                line == "ARP fixed header is truncated." ||
                line == "ARP address section is truncated.") {
                continue;
            }
            arp_fields.push_back(make_summary_line_field(line));
        }
        if (details.arp.fixed_header_truncated) {
            arp_fields.push_back(make_summary_field({}, "ARP fixed header is truncated."));
        } else if (details.arp.address_section_truncated) {
            arp_fields.push_back(make_summary_field({}, "ARP address section is truncated."));
        }

        std::string arp_title = "Address Resolution Protocol";
        if (const auto presentation = describe_arp_packet(details);
            presentation.has_value() && !presentation->detail.empty()) {
            arp_title += ", " + presentation->detail;
        }
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "arp",
            .title = std::move(arp_title),
            .fields = std::move(arp_fields),
            .warning = details.arp.fixed_header_truncated || details.arp.address_section_truncated,
            .marker_text = (details.arp.fixed_header_truncated || details.arp.address_section_truncated)
                ? "Warning"
                : std::string {},
        });
    }

    if (details.has_ipv4) {
        std::vector<PacketSummaryField> ipv4_fields {
            make_summary_field("Version", "4"),
            make_summary_field("Source", format_ipv4_address(details.ipv4.src_addr)),
            make_summary_field("Destination", format_ipv4_address(details.ipv4.dst_addr)),
            make_summary_field("Protocol", format_protocol_summary_value(details.ipv4.protocol)),
            make_summary_field("TTL", std::to_string(details.ipv4.ttl)),
            make_summary_field("Total Length", std::to_string(details.ipv4.total_length) + " bytes"),
        };
        if (packet.is_ip_fragmented) {
            ipv4_fields.push_back(make_summary_field("Fragmentation", "Packet is fragmented"));
        }
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "ipv4",
            .title = "Internet Protocol Version 4, Src: " +
                format_ipv4_address(details.ipv4.src_addr) +
                ", Dst: " + format_ipv4_address(details.ipv4.dst_addr),
            .fields = std::move(ipv4_fields),
        });
    }

    if (details.has_ipv6) {
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "ipv6",
            .title = "Internet Protocol Version 6, Src: " +
                format_ipv6_address(details.ipv6.src_addr) +
                ", Dst: " + format_ipv6_address(details.ipv6.dst_addr),
            .fields = {
                make_summary_field("Version", "6"),
                make_summary_field("Source", format_ipv6_address(details.ipv6.src_addr)),
                make_summary_field("Destination", format_ipv6_address(details.ipv6.dst_addr)),
                make_summary_field("Next Header", format_protocol_summary_value(details.ipv6.next_header)),
                make_summary_field("Hop Limit", std::to_string(details.ipv6.hop_limit)),
                make_summary_field("Payload Length", std::to_string(details.ipv6.payload_length) + " bytes"),
            },
        });
    }

    if (details.has_tcp) {
        std::vector<PacketSummaryField> tcp_fields {
            make_summary_field("Source Port", std::to_string(details.tcp.src_port)),
            make_summary_field("Destination Port", std::to_string(details.tcp.dst_port)),
            make_summary_field("Flags", format_tcp_flags_text(details.tcp.flags)),
            make_summary_field("Sequence Number", std::to_string(details.tcp.seq_number)),
            make_summary_field("Acknowledgment Number", std::to_string(details.tcp.ack_number)),
        };
        if (options.original_transport_payload_length.has_value()) {
            if (options.transport_payload_length.has_value() &&
                *options.transport_payload_length != *options.original_transport_payload_length) {
                tcp_fields.push_back(make_summary_field("Captured Payload Length", std::to_string(*options.transport_payload_length) + " bytes"));
                tcp_fields.push_back(make_summary_field("Original Payload Length", std::to_string(*options.original_transport_payload_length) + " bytes"));
            } else {
                tcp_fields.push_back(make_summary_field("Payload Length", std::to_string(*options.original_transport_payload_length) + " bytes"));
            }
        } else if (options.transport_payload_length.has_value()) {
            tcp_fields.push_back(make_summary_field("Payload Length", std::to_string(*options.transport_payload_length) + " bytes"));
        }
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "tcp",
            .title = "Transmission Control Protocol, Src Port: " +
                std::to_string(details.tcp.src_port) +
                ", Dst Port: " + std::to_string(details.tcp.dst_port) +
                ", Seq: " + std::to_string(details.tcp.seq_number) +
                ", Ack: " + std::to_string(details.tcp.ack_number) +
                ", Len: " + std::to_string(options.original_transport_payload_length.value_or(
                    options.transport_payload_length.value_or(0U))),
            .fields = std::move(tcp_fields),
        });
    }

    if (details.has_udp) {
        std::vector<PacketSummaryField> udp_fields {
            make_summary_field("Source Port", std::to_string(details.udp.src_port)),
            make_summary_field("Destination Port", std::to_string(details.udp.dst_port)),
            make_summary_field("Length", std::to_string(details.udp.length)),
        };
        if (options.original_transport_payload_length.has_value()) {
            if (options.transport_payload_length.has_value() &&
                *options.transport_payload_length != *options.original_transport_payload_length) {
                udp_fields.push_back(make_summary_field("Captured Payload Length", std::to_string(*options.transport_payload_length) + " bytes"));
                udp_fields.push_back(make_summary_field("Original Payload Length", std::to_string(*options.original_transport_payload_length) + " bytes"));
            } else {
                udp_fields.push_back(make_summary_field("Payload Length", std::to_string(*options.original_transport_payload_length) + " bytes"));
            }
        } else if (options.transport_payload_length.has_value()) {
            udp_fields.push_back(make_summary_field("Payload Length", std::to_string(*options.transport_payload_length) + " bytes"));
        }
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "udp",
            .title = "User Datagram Protocol, Src Port: " +
                std::to_string(details.udp.src_port) +
                ", Dst Port: " + std::to_string(details.udp.dst_port) +
                ", Len: " + std::to_string(details.udp.length),
            .fields = std::move(udp_fields),
        });
    }

    if (const auto protocol_layer = build_protocol_text_summary_layer(details, options.protocol_details_text);
        protocol_layer.has_value()) {
        append_layer_if_not_empty(layers, *protocol_layer);
    }

    return layers;
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
