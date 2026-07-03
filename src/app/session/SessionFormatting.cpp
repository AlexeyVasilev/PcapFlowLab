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
constexpr std::uint16_t kEtherTypeLegacyVlan = 0x9100U;
constexpr std::uint16_t kEtherTypeMplsUnicast = 0x8847U;
constexpr std::uint16_t kEtherTypeMplsMulticast = 0x8848U;
constexpr std::uint16_t kEtherTypePbb = 0x88E7U;
constexpr std::uint16_t kEtherTypeMacsec = 0x88E5U;
constexpr std::uint16_t kEtherTypePppoeDiscovery = 0x8863U;
constexpr std::uint16_t kEtherTypePppoeSession = 0x8864U;
constexpr std::uint16_t kIeee8023LengthCutoff = 0x0600U;
constexpr std::uint16_t kArpHardwareTypeEthernet = 1U;
constexpr std::uint16_t kArpProtocolTypeIpv4 = 0x0800U;
constexpr std::uint16_t kPppProtocolIpv4 = 0x0021U;
constexpr std::uint16_t kPppProtocolIpv6 = 0x0057U;
constexpr std::uint16_t kPppProtocolLcp = 0xc021U;
constexpr std::uint16_t kPppProtocolIpcp = 0x8021U;
constexpr std::uint16_t kPppProtocolIpv6cp = 0x8057U;
constexpr std::uint16_t kPppoeDiscoveryTagEndOfList = 0x0000U;
constexpr std::uint16_t kPppoeDiscoveryTagServiceName = 0x0101U;
constexpr std::uint16_t kPppoeDiscoveryTagAcName = 0x0102U;
constexpr std::uint16_t kPppoeDiscoveryTagHostUniq = 0x0103U;
constexpr std::uint16_t kPppoeDiscoveryTagAcCookie = 0x0104U;
constexpr std::uint16_t kPppoeDiscoveryTagRelaySessionId = 0x0110U;
constexpr std::uint16_t kPppoeDiscoveryTagServiceNameError = 0x0201U;
constexpr std::uint16_t kPppoeDiscoveryTagAcSystemError = 0x0202U;
constexpr std::uint16_t kPppoeDiscoveryTagGenericError = 0x0203U;
constexpr std::uint16_t kArpOpcodeRequest = 1U;
constexpr std::uint16_t kArpOpcodeReply = 2U;
constexpr std::uint8_t kIpProtocolIgmp = 2U;
constexpr std::uint8_t kIgmpTypeMembershipQuery = 0x11U;
constexpr std::uint8_t kIgmpTypeV1MembershipReport = 0x12U;
constexpr std::uint8_t kIgmpTypeV2MembershipReport = 0x16U;
constexpr std::uint8_t kIgmpTypeLeaveGroup = 0x17U;
constexpr std::uint8_t kIgmpTypeV3MembershipReport = 0x22U;
constexpr std::uint8_t kTcpOptionEndOfList = 0U;
constexpr std::uint8_t kTcpOptionNoOperation = 1U;
constexpr std::uint8_t kTcpOptionMaximumSegmentSize = 2U;
constexpr std::uint8_t kTcpOptionWindowScale = 3U;
constexpr std::uint8_t kTcpOptionSackPermitted = 4U;
constexpr std::uint8_t kTcpOptionSack = 5U;
constexpr std::uint8_t kTcpOptionTimestamp = 8U;
constexpr std::uint8_t kIpv4OptionEndOfList = 0U;
constexpr std::uint8_t kIpv4OptionNoOperation = 1U;
constexpr std::uint8_t kIpv4OptionRecordRoute = 7U;
constexpr std::uint8_t kIpv4OptionTimestamp = 68U;
constexpr std::uint8_t kIpv4OptionLooseSourceRoute = 131U;
constexpr std::uint8_t kIpv4OptionStrictSourceRoute = 137U;
constexpr std::uint8_t kIpv4OptionRouterAlert = 148U;
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

std::string format_hex_value(const std::uint32_t value, const int width = 0) {
    std::ostringstream builder {};
    builder << "0x" << std::hex << std::nouppercase;
    if (width > 0) {
        builder << std::setw(width) << std::setfill('0');
    }
    builder << value;
    return builder.str();
}

std::string format_hex16_value(const std::uint16_t value) {
    return format_hex_value(value, 4);
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

std::string format_mac_address(const std::array<std::uint8_t, 6>& address) {
    return format_hex_byte_sequence(std::span<const std::uint8_t>(address.data(), address.size()));
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
    case 2U:
        return "IGMP";
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

std::string format_protocol_summary_value_with_number(const std::uint8_t protocol) {
    const auto label = format_protocol_summary_value(protocol);
    if (label == std::to_string(protocol)) {
        return label;
    }

    return label + " (" + std::to_string(protocol) + ")";
}

std::string format_hex_byte_list(std::span<const std::uint8_t> bytes) {
    std::ostringstream builder {};
    builder << std::hex << std::nouppercase << std::setfill('0');

    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0U) {
            builder << ", ";
        }
        builder << "0x" << std::setw(2) << static_cast<unsigned>(bytes[index]);
    }

    return builder.str();
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
    case kEtherTypeLegacyVlan:
        return "Legacy VLAN";
    case kEtherTypeMplsUnicast:
        return "MPLS Unicast";
    case kEtherTypeMplsMulticast:
        return "MPLS Multicast";
    case kEtherTypePbb:
        return "PBB I-TAG";
    case kEtherTypeMacsec:
        return "MACsec";
    case kEtherTypePppoeDiscovery:
        return "PPPoE Discovery";
    case kEtherTypePppoeSession:
        return "PPPoE Session";
    default:
        return {};
    }
}

std::optional<std::string> format_mpls_label_name(const std::uint32_t label) {
    switch (label) {
    case 0U:
        return "IPv4 Explicit NULL";
    case 1U:
        return "Router Alert";
    case 2U:
        return "IPv6 Explicit NULL";
    case 3U:
        return "Implicit NULL / unusual on wire";
    default:
        return std::nullopt;
    }
}

std::string format_ether_type_value(const std::uint16_t ether_type) {
    const auto name = format_ether_type_name(ether_type);
    if (name.empty()) {
        return format_hex16_value(ether_type);
    }

    return name + " (" + format_hex16_value(ether_type) + ")";
}

std::string format_vlan_tpid_name(const std::uint16_t tpid) {
    switch (tpid) {
    case kEtherTypeVlan:
        return "802.1Q Virtual LAN";
    case kEtherTypeQinq:
        return "802.1ad QinQ";
    case kEtherTypeLegacyVlan:
        return "Legacy VLAN (0x9100)";
    default:
        return "VLAN";
    }
}

std::string format_vlan_summary_title(const VlanTagDetails& tag) {
    const auto priority = std::to_string(static_cast<unsigned>((tag.tci >> 13U) & 0x7U));
    const auto dei = std::to_string(static_cast<unsigned>((tag.tci >> 12U) & 0x1U));
    const auto id = std::to_string(static_cast<unsigned>(tag.tci & 0x0FFFU));

    if (tag.tpid == kEtherTypeQinq && tag.encapsulated_ether_type == kEtherTypePbb) {
        return "802.1ad B-TAG, PRI: " + priority + ", DEI: " + dei + ", ID: " + id;
    }

    return format_vlan_tpid_name(tag.tpid) + ", PRI: " + priority +
        ", DEI: " + dei + ", ID: " + id;
}

std::string format_inner_ethernet_title(const InnerEthernetDetails& details) {
    std::string title = details.uses_length_field ? "Inner IEEE 802.3" : "Inner Ethernet II";
    if (details.available_header_bytes >= 12U) {
        title += ", Src: " + format_mac_address(details.src_mac) +
            ", Dst: " + format_mac_address(details.dst_mac);
    }
    return title;
}

std::string format_pppoe_code(const std::uint8_t code) {
    switch (code) {
    case 0x00U:
        return "Session Data (0x00)";
    case 0x09U:
        return "PADI (0x09)";
    case 0x07U:
        return "PADO (0x07)";
    case 0x19U:
        return "PADR (0x19)";
    case 0x65U:
        return "PADS (0x65)";
    case 0xA7U:
        return "PADT (0xa7)";
    default:
        return format_hex_value(code, 2);
    }
}

std::string format_pbb_isid(const std::uint32_t isid) {
    return format_hex_value(isid, 6) + " (" + std::to_string(isid) + ")";
}

std::string format_macsec_packet_number(const std::uint32_t packet_number) {
    return format_hex_value(packet_number, 8) + " (" + std::to_string(packet_number) + ")";
}

bool has_plaintext_macsec_ether_type(const PacketDetails& details) noexcept {
    return details.has_macsec &&
        !details.macsec.encrypted &&
        !details.macsec.changed &&
        !details.macsec.sectag_truncated &&
        !details.macsec.packet_number_truncated &&
        !details.macsec.sci_truncated &&
        !details.macsec.icv_truncated &&
        details.macsec.protected_payload_length >= 2U &&
        details.macsec.protected_payload_preview.size() >= 2U;
}

std::uint16_t macsec_plaintext_ether_type(const PacketDetails& details) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(details.macsec.protected_payload_preview[0]) << 8U) |
        static_cast<std::uint16_t>(details.macsec.protected_payload_preview[1]));
}

PacketSummaryField make_summary_field(std::string label, std::string value);

std::uint8_t pbb_reserved_1(const PbbDetails& pbb) noexcept {
    return static_cast<std::uint8_t>((pbb.reserved >> 2U) & 0x1U);
}

std::uint8_t pbb_reserved_2(const PbbDetails& pbb) noexcept {
    return static_cast<std::uint8_t>(pbb.reserved & 0x3U);
}

void append_pbb_itag_summary_fields(std::vector<PacketSummaryField>& fields, const PbbDetails& pbb) {
    if (pbb.available_bytes >= 1U) {
        fields.push_back(make_summary_field("Priority", std::to_string(pbb.pcp)));
        fields.push_back(make_summary_field("Drop Eligible", pbb.dei ? "1" : "0"));
        fields.push_back(make_summary_field("NCA", pbb.nca ? "1" : "0"));
        fields.push_back(make_summary_field("Reserved 1", std::to_string(pbb_reserved_1(pbb))));
        fields.push_back(make_summary_field("Reserved 2", std::to_string(pbb_reserved_2(pbb))));
    }
    if (pbb.available_bytes >= 4U) {
        fields.push_back(make_summary_field("I-SID", format_pbb_isid(pbb.isid)));
    } else if (pbb.available_bytes > 0U) {
        fields.push_back(make_summary_field(
            "Available Bytes",
            std::to_string(static_cast<unsigned>(pbb.available_bytes)) + " of 4"
        ));
    }
}

PacketSummaryLayer build_inner_ethernet_summary_layer(const InnerEthernetDetails& details) {
    auto inner_ethernet_fields = std::vector<PacketSummaryField> {};
    if (details.available_header_bytes >= 6U) {
        inner_ethernet_fields.push_back(make_summary_field("Destination", format_mac_address(details.dst_mac)));
    }
    if (details.available_header_bytes >= 12U) {
        inner_ethernet_fields.push_back(make_summary_field("Source", format_mac_address(details.src_mac)));
    }
    if (details.available_header_bytes >= 14U) {
        if (details.uses_length_field) {
            inner_ethernet_fields.push_back(make_summary_field(
                "Length",
                std::to_string(details.ether_type) + " bytes"
            ));
        } else {
            inner_ethernet_fields.push_back(make_summary_field("Type", format_ether_type_value(details.ether_type)));
        }
    }
    if (details.header_truncated) {
        inner_ethernet_fields.push_back(make_summary_field("Warning", "Inner Ethernet header is truncated"));
    }

    return PacketSummaryLayer {
        .id = "ethernet-inner",
        .title = format_inner_ethernet_title(details),
        .fields = std::move(inner_ethernet_fields),
        .warning = details.header_truncated,
        .marker_text = details.header_truncated ? "Warning" : std::string {},
    };
}

std::string format_ppp_protocol(const std::uint16_t protocol) {
    switch (protocol) {
    case kPppProtocolIpv4:
        return "IPv4 (0x0021)";
    case kPppProtocolIpv6:
        return "IPv6 (0x0057)";
    case kPppProtocolLcp:
        return "LCP (0xc021)";
    case kPppProtocolIpcp:
        return "IPCP (0x8021)";
    case kPppProtocolIpv6cp:
        return "IPv6CP (0x8057)";
    default:
        return format_hex16_value(protocol);
    }
}

std::string format_pppoe_tag_type(const std::uint16_t tag_type) {
    switch (tag_type) {
    case kPppoeDiscoveryTagEndOfList:
        return "End-Of-List (0x0000)";
    case kPppoeDiscoveryTagServiceName:
        return "Service-Name (0x0101)";
    case kPppoeDiscoveryTagAcName:
        return "AC-Name (0x0102)";
    case kPppoeDiscoveryTagHostUniq:
        return "Host-Uniq (0x0103)";
    case kPppoeDiscoveryTagAcCookie:
        return "AC-Cookie (0x0104)";
    case kPppoeDiscoveryTagRelaySessionId:
        return "Relay-Session-Id (0x0110)";
    case kPppoeDiscoveryTagServiceNameError:
        return "Service-Name-Error (0x0201)";
    case kPppoeDiscoveryTagAcSystemError:
        return "AC-System-Error (0x0202)";
    case kPppoeDiscoveryTagGenericError:
        return "Generic-Error (0x0203)";
    default:
        return format_hex16_value(tag_type);
    }
}

bool is_printable_ascii(std::span<const std::uint8_t> bytes) noexcept {
    return std::all_of(bytes.begin(), bytes.end(), [](const auto byte) {
        return byte >= 0x20U && byte <= 0x7eU;
    });
}

std::string format_pppoe_tag_value(std::span<const std::uint8_t> value) {
    if (value.empty()) {
        return "empty";
    }
    if (is_printable_ascii(value)) {
        return std::string(value.begin(), value.end());
    }
    return format_hex_byte_list(value);
}

std::string format_ppp_control_code(const std::uint8_t code) {
    switch (code) {
    case 1U:
        return "Configure-Request (1)";
    case 2U:
        return "Configure-Ack (2)";
    case 3U:
        return "Configure-Nak (3)";
    case 4U:
        return "Configure-Reject (4)";
    case 5U:
        return "Terminate-Request (5)";
    case 6U:
        return "Terminate-Ack (6)";
    case 7U:
        return "Code-Reject (7)";
    case 8U:
        return "Protocol-Reject (8)";
    case 9U:
        return "Echo-Request (9)";
    case 10U:
        return "Echo-Reply (10)";
    case 11U:
        return "Discard-Request (11)";
    default:
        return std::to_string(static_cast<unsigned>(code));
    }
}

std::string format_ppp_control_option_name(const std::uint16_t protocol, const std::uint8_t type) {
    if (protocol == kPppProtocolLcp) {
        switch (type) {
        case 1U: return "Maximum Receive Unit (MRU)";
        case 2U: return "Async Control Character Map";
        case 3U: return "Authentication Protocol";
        case 5U: return "Magic Number";
        case 7U: return "Protocol Field Compression";
        case 8U: return "Address/Control Field Compression";
        default: break;
        }
    } else if (protocol == kPppProtocolIpcp) {
        switch (type) {
        case 2U: return "IP-Compression-Protocol";
        case 3U: return "IP Address";
        default: break;
        }
    } else if (protocol == kPppProtocolIpv6cp) {
        switch (type) {
        case 1U: return "Interface Identifier";
        case 2U: return "IPv6-Compression-Protocol";
        default: break;
        }
    }

    return "Option " + std::to_string(static_cast<unsigned>(type));
}

std::string format_ppp_control_option_value(const std::uint16_t protocol, const std::uint8_t type, std::span<const std::uint8_t> value) {
    if (value.empty()) {
        return "empty";
    }

    if (protocol == kPppProtocolLcp) {
        if (type == 1U && value.size() == 2U) {
            const auto mru = static_cast<std::uint16_t>((static_cast<std::uint16_t>(value[0]) << 8U) | value[1]);
            return std::to_string(mru) + " bytes";
        }
        if (type == 2U && value.size() == 4U) {
            const auto accm = (static_cast<std::uint32_t>(value[0]) << 24U) |
                (static_cast<std::uint32_t>(value[1]) << 16U) |
                (static_cast<std::uint32_t>(value[2]) << 8U) |
                static_cast<std::uint32_t>(value[3]);
            return format_hex_value(accm, 8);
        }
        if (type == 3U && value.size() >= 2U) {
            const auto auth_protocol =
                static_cast<std::uint16_t>((static_cast<std::uint16_t>(value[0]) << 8U) | value[1]);
            if (auth_protocol == 0xc023U) {
                return "PAP (0xc023)";
            }
            if (auth_protocol == 0xc223U) {
                return "CHAP (0xc223)";
            }
            return format_hex16_value(auth_protocol);
        }
        if (type == 5U && value.size() == 4U) {
            const auto magic = (static_cast<std::uint32_t>(value[0]) << 24U) |
                (static_cast<std::uint32_t>(value[1]) << 16U) |
                (static_cast<std::uint32_t>(value[2]) << 8U) |
                static_cast<std::uint32_t>(value[3]);
            return format_hex_value(magic, 8);
        }
    } else if (protocol == kPppProtocolIpcp) {
        if (type == 3U && value.size() == 4U) {
            return format_ipv4_address({
                value[0], value[1], value[2], value[3]
            });
        }
    } else if (protocol == kPppProtocolIpv6cp) {
        if (type == 1U && value.size() == 8U) {
            return format_hex_byte_sequence(value);
        }
    }

    if (is_printable_ascii(value)) {
        return std::string(value.begin(), value.end());
    }
    return format_hex_byte_list(value);
}

std::optional<PacketSummaryLayer> build_ppp_control_options_layer(const PacketDetails& details) {
    if (!details.pppoe.control.present) {
        return std::nullopt;
    }

    std::vector<PacketSummaryLayer> option_layers {};
    option_layers.reserve(details.pppoe.control.options.size());
    for (const auto& option : details.pppoe.control.options) {
        if (option.header_truncated) {
            option_layers.push_back(PacketSummaryLayer {
                .id = "ppp-control-option",
                .title = "Truncated option header",
                .warning = true,
                .marker_text = "Warning",
            });
            continue;
        }

        auto value_text = format_ppp_control_option_value(
            details.pppoe.ppp_protocol,
            option.type,
            std::span<const std::uint8_t>(option.value.data(), option.value.size())
        );
        if (option.value_truncated) {
            value_text += " (truncated)";
        }

        option_layers.push_back(PacketSummaryLayer {
            .id = "ppp-control-option",
            .title = format_ppp_control_option_name(details.pppoe.ppp_protocol, option.type),
            .fields = {
                PacketSummaryField {
                    .label = "Type",
                    .value = std::to_string(static_cast<unsigned>(option.type)),
                },
                PacketSummaryField {
                    .label = "Length",
                    .value = std::to_string(static_cast<unsigned>(option.declared_length)) + " bytes",
                },
                PacketSummaryField {
                    .label = "Value",
                    .value = std::move(value_text),
                },
            },
            .warning = option.value_truncated,
            .marker_text = option.value_truncated ? "Warning" : std::string {},
        });
    }

    return PacketSummaryLayer {
        .id = "ppp-control-options",
        .title = "Options",
        .children = std::move(option_layers),
        .expanded_by_default = true,
        .warning = details.pppoe.control.option_header_truncated || details.pppoe.control.option_value_truncated,
        .marker_text = (details.pppoe.control.option_header_truncated || details.pppoe.control.option_value_truncated)
            ? "Warning"
            : std::string {},
    };
}

std::optional<PacketSummaryLayer> build_unknown_ppp_payload_layer(const PacketDetails& details) {
    if (!details.has_pppoe ||
        details.pppoe.is_discovery ||
        details.pppoe.control.present ||
        details.pppoe.ppp_protocol == 0U ||
        details.pppoe.ppp_protocol == kPppProtocolIpv4 ||
        details.pppoe.ppp_protocol == kPppProtocolIpv6 ||
        details.pppoe.protocol_field_truncated ||
        details.pppoe.header_truncated) {
        return std::nullopt;
    }

    std::vector<PacketSummaryField> fields {
        PacketSummaryField {
            .label = "Length",
            .value = std::to_string(details.pppoe.unknown_ppp_payload_length) + " bytes",
        },
    };

    if (!details.pppoe.unknown_ppp_payload_preview.empty()) {
        auto preview_text = format_hex_byte_list(std::span<const std::uint8_t>(
            details.pppoe.unknown_ppp_payload_preview.data(),
            details.pppoe.unknown_ppp_payload_preview.size()
        ));
        fields.push_back(PacketSummaryField {
            .label = "Raw",
            .value = std::move(preview_text),
        });
    }
    if (details.pppoe.unknown_ppp_payload_preview_truncated) {
        fields.push_back(PacketSummaryField {
            .label = "Preview truncated",
            .value = "Yes",
        });
    }

    return PacketSummaryLayer {
        .id = "ppp-payload",
        .title = "Data",
        .fields = std::move(fields),
    };
}

std::optional<PacketSummaryLayer> build_unknown_inner_ethernet_payload_layer(const PacketDetails& details) {
    if (!details.has_unknown_inner_ethernet_payload) {
        return std::nullopt;
    }

    std::vector<PacketSummaryField> fields {
        PacketSummaryField {
            .label = "Length",
            .value = std::to_string(details.unknown_inner_ethernet_payload.payload_length) + " bytes",
        },
    };

    if (!details.unknown_inner_ethernet_payload.payload_preview.empty()) {
        auto preview_text = format_hex_byte_list(std::span<const std::uint8_t>(
            details.unknown_inner_ethernet_payload.payload_preview.data(),
            details.unknown_inner_ethernet_payload.payload_preview.size()
        ));
        fields.push_back(PacketSummaryField {
            .label = "Raw",
            .value = std::move(preview_text),
        });
    }

    if (details.unknown_inner_ethernet_payload.payload_preview_truncated) {
        fields.push_back(PacketSummaryField {
            .label = "Preview truncated",
            .value = "Yes",
        });
    }

    return PacketSummaryLayer {
        .id = "inner-payload",
        .title = "Data",
        .fields = std::move(fields),
    };
}

std::optional<PacketSummaryLayer> build_macsec_protected_payload_layer(const PacketDetails& details) {
    if (!details.has_macsec || details.macsec.protected_payload_length == 0U) {
        return std::nullopt;
    }

    std::vector<PacketSummaryField> fields {
        make_summary_field("Length", std::to_string(details.macsec.protected_payload_length) + " bytes"),
    };

    std::size_t preview_offset = 0U;
    if (has_plaintext_macsec_ether_type(details)) {
        fields.push_back(make_summary_field(
            "Plain EtherType",
            format_ether_type_value(macsec_plaintext_ether_type(details))
        ));
        fields.push_back(make_summary_field(
            "Data Length",
            std::to_string(details.macsec.protected_payload_length - 2U) + " bytes"
        ));
        preview_offset = 2U;
    }

    if (details.macsec.protected_payload_preview.size() > preview_offset) {
        fields.push_back(make_summary_field(
            "Raw",
            format_hex_byte_list(std::span<const std::uint8_t>(
                details.macsec.protected_payload_preview.data() + static_cast<std::ptrdiff_t>(preview_offset),
                details.macsec.protected_payload_preview.size() - preview_offset
            ))
        ));
    }

    const auto preview_payload_length = details.macsec.protected_payload_preview.size() > preview_offset
        ? (details.macsec.protected_payload_preview.size() - preview_offset)
        : 0U;
    const auto total_payload_length = details.macsec.protected_payload_length > preview_offset
        ? (details.macsec.protected_payload_length - preview_offset)
        : 0U;
    if (details.macsec.protected_payload_preview_truncated || total_payload_length > preview_payload_length) {
        fields.push_back(make_summary_field("Preview truncated", "Yes"));
    }

    return PacketSummaryLayer {
        .id = "macsec-payload",
        .title = "MACsec Protected Payload",
        .fields = std::move(fields),
    };
}

std::optional<PacketSummaryLayer> build_macsec_icv_layer(const PacketDetails& details) {
    if (!details.has_macsec || details.macsec.icv_length == 0U) {
        return std::nullopt;
    }

    std::vector<PacketSummaryField> fields {
        make_summary_field("Length", std::to_string(details.macsec.icv_length) + " bytes"),
    };
    if (!details.macsec.icv_preview.empty()) {
        fields.push_back(make_summary_field(
            "Raw",
            format_hex_byte_list(std::span<const std::uint8_t>(
                details.macsec.icv_preview.data(),
                details.macsec.icv_preview.size()
            ))
        ));
    }
    if (details.macsec.icv_preview_truncated) {
        fields.push_back(make_summary_field("Preview truncated", "Yes"));
    }

    return PacketSummaryLayer {
        .id = "macsec-icv",
        .title = "MACsec ICV",
        .fields = std::move(fields),
    };
}

std::optional<PacketSummaryLayer> build_unknown_llc_snap_payload_layer(const PacketDetails& details) {
    const auto make_payload_layer = [](std::string id,
                                       const std::size_t payload_length,
                                       const std::vector<std::uint8_t>& payload_preview,
                                       const bool preview_truncated) -> std::optional<PacketSummaryLayer> {
        if (payload_length == 0U && payload_preview.empty()) {
            return std::nullopt;
        }

        std::vector<PacketSummaryField> fields {
            PacketSummaryField {
                .label = "Length",
                .value = std::to_string(payload_length) + " bytes",
            },
        };

        if (!payload_preview.empty()) {
            auto preview_text = format_hex_byte_list(std::span<const std::uint8_t>(
                payload_preview.data(),
                payload_preview.size()
            ));
            fields.push_back(PacketSummaryField {
                .label = "Raw",
                .value = std::move(preview_text),
            });
        }
        if (preview_truncated) {
            fields.push_back(PacketSummaryField {
                .label = "Preview truncated",
                .value = "Yes",
            });
        }

        return PacketSummaryLayer {
            .id = std::move(id),
            .title = "Data",
            .fields = std::move(fields),
        };
    };

    if (details.has_snap &&
        !details.snap.header_truncated &&
        details.snap.payload_length > 0U &&
        (details.snap.pid != kEtherTypeArp &&
         details.snap.pid != kEtherTypeIpv4 &&
         details.snap.pid != kEtherTypeIpv6)) {
        return make_payload_layer(
            "snap-payload",
            details.snap.payload_length,
            details.snap.payload_preview,
            details.snap.payload_preview_truncated
        );
    }

    if (details.has_llc &&
        !details.llc.header_truncated &&
        !details.has_snap &&
        details.llc.payload_length > 0U) {
        return make_payload_layer(
            "llc-payload",
            details.llc.payload_length,
            details.llc.payload_preview,
            details.llc.payload_preview_truncated
        );
    }

    return std::nullopt;
}

std::optional<PacketSummaryLayer> build_ieee_802_3_trailer_layer(const PacketDetails& details) {
    if (!details.has_ethernet || details.ethernet.trailer_length == 0U) {
        return std::nullopt;
    }

    std::vector<PacketSummaryField> fields {
        PacketSummaryField {
            .label = "Length",
            .value = std::to_string(details.ethernet.trailer_length) + " bytes",
        },
    };

    if (!details.ethernet.trailer_preview.empty()) {
        fields.push_back(PacketSummaryField {
            .label = "Raw",
            .value = format_hex_byte_list(std::span<const std::uint8_t>(
                details.ethernet.trailer_preview.data(),
                details.ethernet.trailer_preview.size()
            )),
        });
    }

    if (details.ethernet.trailer_preview_truncated) {
        fields.push_back(PacketSummaryField {
            .label = "Preview truncated",
            .value = "Yes",
        });
    }

    return PacketSummaryLayer {
        .id = "trailer",
        .title = "Trailer",
        .fields = std::move(fields),
    };
}

bool ipv4_field_available(const PacketDetails& details, const std::size_t end_offset) noexcept {
    return details.has_ipv4 && details.ipv4.available_header_bytes >= end_offset;
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

std::string format_byte_count(const std::size_t bytes) {
    return std::to_string(bytes) + (bytes == 1U ? " byte" : " bytes");
}

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
        static_cast<std::uint16_t>(bytes[offset + 1U])
    );
}

std::uint32_t read_be32(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

PacketSummaryLayer make_tcp_option_layer(
    std::string id,
    std::string title,
    std::vector<PacketSummaryField> fields = {},
    const bool warning = false
) {
    return PacketSummaryLayer {
        .id = std::move(id),
        .title = std::move(title),
        .fields = std::move(fields),
        .expanded_by_default = warning,
        .warning = warning,
        .marker_text = warning ? std::string {"Warning"} : std::string {},
    };
}

PacketSummaryLayer make_malformed_tcp_option_layer(
    std::string title,
    std::span<const std::uint8_t> raw_bytes,
    std::vector<PacketSummaryField> fields = {}
) {
    if (!raw_bytes.empty()) {
        fields.push_back(make_summary_field("Raw", format_hex_byte_list(raw_bytes)));
    }
    return make_tcp_option_layer("tcp_option_malformed", std::move(title), std::move(fields), true);
}

std::optional<PacketSummaryLayer> build_tcp_options_summary_layer(std::span<const std::uint8_t> options_bytes) {
    if (options_bytes.empty()) {
        return std::nullopt;
    }

    std::vector<PacketSummaryLayer> option_layers {};
    const auto make_parent_layer = [&]() {
        return PacketSummaryLayer {
            .id = "tcp_options",
            .title = "TCP Options (" + format_byte_count(options_bytes.size()) + ")",
            .fields = {
                make_summary_field("Length", format_byte_count(options_bytes.size())),
                make_summary_field("Raw", format_hex_byte_list(options_bytes)),
            },
            .children = std::move(option_layers),
            .expanded_by_default = true,
        };
    };

    std::size_t offset = 0U;
    while (offset < options_bytes.size()) {
        const auto kind = options_bytes[offset];
        if (kind == kTcpOptionEndOfList) {
            option_layers.push_back(make_tcp_option_layer(
                "tcp_option_eol",
                "End of Option List (EOL)",
                {
                    make_summary_field("Kind", "0"),
                    make_summary_field("Length", "1 byte"),
                }
            ));

            const auto padding = options_bytes.subspan(offset + 1U);
            if (!padding.empty()) {
                const auto first_non_zero = std::find_if(padding.begin(), padding.end(), [](const auto byte) {
                    return byte != 0U;
                });
                if (first_non_zero != padding.end()) {
                    option_layers.push_back(make_malformed_tcp_option_layer(
                        "Non-zero padding after EOL",
                        padding,
                        {
                            make_summary_field("Length", format_byte_count(padding.size())),
                        }
                    ));
                }
            }
            break;
        }

        if (kind == kTcpOptionNoOperation) {
            option_layers.push_back(make_tcp_option_layer(
                "tcp_option_nop",
                "No-Operation (NOP)",
                {
                    make_summary_field("Kind", "1"),
                    make_summary_field("Length", "1 byte"),
                }
            ));
            ++offset;
            continue;
        }

        if (offset + 2U > options_bytes.size()) {
            option_layers.push_back(make_malformed_tcp_option_layer(
                "Malformed TCP Option: missing length field",
                options_bytes.subspan(offset),
                {
                    make_summary_field("Kind", std::to_string(kind)),
                }
            ));
            break;
        }

        const auto length = static_cast<std::size_t>(options_bytes[offset + 1U]);
        if (length == 0U || length == 1U) {
            option_layers.push_back(make_malformed_tcp_option_layer(
                "Malformed TCP Option: invalid length " + std::to_string(length),
                options_bytes.subspan(offset),
                {
                    make_summary_field("Kind", std::to_string(kind)),
                    make_summary_field("Length", std::to_string(length)),
                }
            ));
            break;
        }

        if (offset + length > options_bytes.size()) {
            const auto title = kind == kTcpOptionTimestamp
                ? std::string {"Malformed Timestamp Option"}
                : std::string {"Malformed TCP Option: length extends past TCP header"};
            option_layers.push_back(make_malformed_tcp_option_layer(
                title,
                options_bytes.subspan(offset),
                {
                    make_summary_field("Kind", std::to_string(kind)),
                    make_summary_field("Length", std::to_string(length)),
                    make_summary_field("Available Bytes", format_byte_count(options_bytes.size() - offset)),
                }
            ));
            break;
        }

        const auto option_bytes = options_bytes.subspan(offset, length);
        std::vector<PacketSummaryField> fields {
            make_summary_field("Kind", std::to_string(kind)),
            make_summary_field("Length", format_byte_count(length)),
        };

        switch (kind) {
        case kTcpOptionMaximumSegmentSize:
            if (length != 4U) {
                option_layers.push_back(make_malformed_tcp_option_layer(
                    "Malformed TCP Option: MSS length must be 4",
                    option_bytes,
                    std::move(fields)
                ));
                return make_parent_layer();
            }

            fields.push_back(make_summary_field("MSS", std::to_string(read_be16(option_bytes, 2U)) + " bytes"));
            option_layers.push_back(make_tcp_option_layer(
                "tcp_option_mss",
                "Maximum Segment Size: " + std::to_string(read_be16(option_bytes, 2U)) + " bytes",
                std::move(fields)
            ));
            break;

        case kTcpOptionWindowScale:
            if (length != 3U) {
                option_layers.push_back(make_malformed_tcp_option_layer(
                    "Malformed TCP Option: Window Scale length must be 3",
                    option_bytes,
                    std::move(fields)
                ));
                return make_parent_layer();
            }

            fields.push_back(make_summary_field("Shift Count", std::to_string(option_bytes[2U])));
            option_layers.push_back(make_tcp_option_layer(
                "tcp_option_window_scale",
                "Window Scale: " + std::to_string(option_bytes[2U]),
                std::move(fields)
            ));
            break;

        case kTcpOptionSackPermitted:
            if (length != 2U) {
                option_layers.push_back(make_malformed_tcp_option_layer(
                    "Malformed TCP Option: SACK Permitted length must be 2",
                    option_bytes,
                    std::move(fields)
                ));
                return make_parent_layer();
            }

            option_layers.push_back(make_tcp_option_layer(
                "tcp_option_sack_permitted",
                "SACK Permitted",
                std::move(fields)
            ));
            break;

        case kTcpOptionSack: {
            if (length < 10U || ((length - 2U) % 8U) != 0U) {
                option_layers.push_back(make_malformed_tcp_option_layer(
                    "Malformed TCP Option: invalid SACK length",
                    option_bytes,
                    std::move(fields)
                ));
                return make_parent_layer();
            }

            const auto block_count = (length - 2U) / 8U;
            for (std::size_t block_index = 0U; block_index < block_count; ++block_index) {
                const auto block_offset = 2U + (block_index * 8U);
                fields.push_back(make_summary_field(
                    "Block " + std::to_string(block_index + 1U) + " Left Edge",
                    std::to_string(read_be32(option_bytes, block_offset))
                ));
                fields.push_back(make_summary_field(
                    "Block " + std::to_string(block_index + 1U) + " Right Edge",
                    std::to_string(read_be32(option_bytes, block_offset + 4U))
                ));
            }

            option_layers.push_back(make_tcp_option_layer(
                "tcp_option_sack",
                "SACK: " + std::to_string(block_count) + (block_count == 1U ? " block" : " blocks"),
                std::move(fields)
            ));
            break;
        }

        case kTcpOptionTimestamp:
            if (length != 10U) {
                option_layers.push_back(make_malformed_tcp_option_layer(
                    "Malformed Timestamp Option",
                    option_bytes,
                    std::move(fields)
                ));
                return make_parent_layer();
            }

            fields.push_back(make_summary_field("Timestamp value", std::to_string(read_be32(option_bytes, 2U))));
            fields.push_back(make_summary_field("Timestamp echo reply", std::to_string(read_be32(option_bytes, 6U))));
            option_layers.push_back(make_tcp_option_layer(
                "tcp_option_timestamp",
                "Timestamps",
                std::move(fields)
            ));
            break;

        default:
            fields.push_back(make_summary_field("Raw", format_hex_byte_list(option_bytes)));
            option_layers.push_back(make_tcp_option_layer(
                "tcp_option_unknown",
                "Unknown Option " + std::to_string(kind) + " (" + format_byte_count(length) + ")",
                std::move(fields)
            ));
            break;
        }

        offset += length;
    }

    return make_parent_layer();
}

PacketSummaryLayer make_ipv4_option_layer(
    std::string id,
    std::string title,
    std::vector<PacketSummaryField> fields = {},
    const bool warning = false
) {
    return PacketSummaryLayer {
        .id = std::move(id),
        .title = std::move(title),
        .fields = std::move(fields),
        .expanded_by_default = warning,
        .warning = warning,
        .marker_text = warning ? std::string {"Warning"} : std::string {},
    };
}

PacketSummaryLayer make_malformed_ipv4_option_layer(
    std::string title,
    std::span<const std::uint8_t> raw_bytes,
    std::vector<PacketSummaryField> fields = {}
) {
    if (!raw_bytes.empty()) {
        fields.push_back(make_summary_field("Raw", format_hex_byte_list(raw_bytes)));
    }
    return make_ipv4_option_layer("ipv4_option_malformed", std::move(title), std::move(fields), true);
}

void append_ipv4_route_fields(
    std::vector<PacketSummaryField>& fields,
    std::span<const std::uint8_t> route_bytes,
    bool& warning
) {
    const auto route_count = route_bytes.size() / 4U;
    for (std::size_t index = 0U; index < route_count; ++index) {
        const auto route_offset = index * 4U;
        fields.push_back(make_summary_field(
            "Route Address " + std::to_string(index + 1U),
            format_ipv4_address(read_be32(route_bytes, route_offset))
        ));
    }

    if ((route_bytes.size() % 4U) != 0U) {
        fields.push_back(make_summary_field(
            "Warning",
            "Route data is not aligned to complete IPv4 addresses"
        ));
        warning = true;
    }
}

void append_ipv4_timestamp_fields(
    std::vector<PacketSummaryField>& fields,
    std::span<const std::uint8_t> timestamp_bytes,
    const std::uint8_t flag,
    bool& warning
) {
    if (timestamp_bytes.empty()) {
        return;
    }

    if (flag == 0U) {
        const auto timestamp_count = timestamp_bytes.size() / 4U;
        for (std::size_t index = 0U; index < timestamp_count; ++index) {
            fields.push_back(make_summary_field(
                "Timestamp " + std::to_string(index + 1U),
                std::to_string(read_be32(timestamp_bytes, index * 4U))
            ));
        }
        if ((timestamp_bytes.size() % 4U) != 0U) {
            fields.push_back(make_summary_field("Warning", "Timestamp data has trailing bytes"));
            warning = true;
        }
        return;
    }

    if (flag == 1U || flag == 3U) {
        const auto entry_count = timestamp_bytes.size() / 8U;
        for (std::size_t index = 0U; index < entry_count; ++index) {
            const auto entry_offset = index * 8U;
            fields.push_back(make_summary_field(
                "Entry " + std::to_string(index + 1U) + " Address",
                format_ipv4_address(read_be32(timestamp_bytes, entry_offset))
            ));
            fields.push_back(make_summary_field(
                "Entry " + std::to_string(index + 1U) + " Timestamp",
                std::to_string(read_be32(timestamp_bytes, entry_offset + 4U))
            ));
        }
        if ((timestamp_bytes.size() % 8U) != 0U) {
            fields.push_back(make_summary_field("Warning", "Timestamp data has trailing bytes"));
            warning = true;
        }
        return;
    }

    fields.push_back(make_summary_field("Timestamp Data", format_hex_byte_list(timestamp_bytes)));
}

std::optional<PacketSummaryLayer> build_ipv4_options_summary_layer(const PacketDetails& details) {
    const auto claimed_options_length = details.ipv4.header_length_bytes > 20U
        ? static_cast<std::size_t>(details.ipv4.header_length_bytes - 20U)
        : 0U;
    const auto options_bytes = std::span<const std::uint8_t>(details.ipv4.options_bytes.data(), details.ipv4.options_bytes.size());
    if (claimed_options_length == 0U && !details.ipv4.options_truncated) {
        return std::nullopt;
    }

    std::vector<PacketSummaryLayer> option_layers {};
    if (details.ipv4.options_truncated) {
        option_layers.push_back(make_malformed_ipv4_option_layer(
            "IPv4 options truncated",
            options_bytes,
            {
                make_summary_field("Expected Length", format_byte_count(claimed_options_length)),
                make_summary_field("Captured Length", format_byte_count(options_bytes.size())),
            }
        ));
    }

    const auto make_parent_layer = [&]() {
        std::vector<PacketSummaryField> fields {
            make_summary_field("Length", format_byte_count(claimed_options_length)),
        };
        if (!options_bytes.empty()) {
            fields.push_back(make_summary_field("Raw", format_hex_byte_list(options_bytes)));
        }
        return PacketSummaryLayer {
            .id = "ipv4_options",
            .title = "IPv4 Options (" + format_byte_count(claimed_options_length) + ")",
            .fields = std::move(fields),
            .children = std::move(option_layers),
            .expanded_by_default = true,
            .warning = details.ipv4.options_truncated,
            .marker_text = details.ipv4.options_truncated ? std::string {"Warning"} : std::string {},
        };
    };

    std::size_t offset = 0U;
    while (offset < options_bytes.size()) {
        const auto kind = options_bytes[offset];
        if (kind == kIpv4OptionEndOfList) {
            option_layers.push_back(make_ipv4_option_layer(
                "ipv4_option_eol",
                "End of Options List (EOL)",
                {
                    make_summary_field("Type", "0"),
                    make_summary_field("Length", "1 byte"),
                }
            ));

            const auto padding = options_bytes.subspan(offset + 1U);
            if (!padding.empty()) {
                const auto first_non_zero = std::find_if(padding.begin(), padding.end(), [](const auto byte) {
                    return byte != 0U;
                });
                if (first_non_zero != padding.end()) {
                    option_layers.push_back(make_malformed_ipv4_option_layer(
                        "Non-zero padding after EOL",
                        padding,
                        {
                            make_summary_field("Length", format_byte_count(padding.size())),
                        }
                    ));
                }
            }
            break;
        }

        if (kind == kIpv4OptionNoOperation) {
            option_layers.push_back(make_ipv4_option_layer(
                "ipv4_option_nop",
                "No-Operation (NOP)",
                {
                    make_summary_field("Type", "1"),
                    make_summary_field("Length", "1 byte"),
                }
            ));
            ++offset;
            continue;
        }

        if (offset + 2U > options_bytes.size()) {
            option_layers.push_back(make_malformed_ipv4_option_layer(
                "IPv4 option length field missing",
                options_bytes.subspan(offset),
                {
                    make_summary_field("Type", std::to_string(kind)),
                }
            ));
            break;
        }

        const auto length = static_cast<std::size_t>(options_bytes[offset + 1U]);
        if (length < 2U) {
            option_layers.push_back(make_malformed_ipv4_option_layer(
                "IPv4 option length is invalid",
                options_bytes.subspan(offset),
                {
                    make_summary_field("Type", std::to_string(kind)),
                    make_summary_field("Length", std::to_string(length)),
                }
            ));
            break;
        }

        if (offset + length > options_bytes.size()) {
            option_layers.push_back(make_malformed_ipv4_option_layer(
                "IPv4 option length exceeds header",
                options_bytes.subspan(offset),
                {
                    make_summary_field("Type", std::to_string(kind)),
                    make_summary_field("Length", std::to_string(length)),
                    make_summary_field("Available Bytes", format_byte_count(options_bytes.size() - offset)),
                }
            ));
            break;
        }

        const auto option_bytes = options_bytes.subspan(offset, length);
        std::vector<PacketSummaryField> fields {
            make_summary_field("Type", std::to_string(kind)),
            make_summary_field("Length", format_byte_count(length)),
        };
        bool warning = false;

        switch (kind) {
        case kIpv4OptionRecordRoute:
        case kIpv4OptionLooseSourceRoute:
        case kIpv4OptionStrictSourceRoute: {
            if (length < 3U) {
                option_layers.push_back(make_malformed_ipv4_option_layer(
                    "IPv4 option length is invalid",
                    option_bytes,
                    std::move(fields)
                ));
                return make_parent_layer();
            }

            fields.push_back(make_summary_field("Pointer", std::to_string(option_bytes[2U])));
            fields.push_back(make_summary_field("Raw", format_hex_byte_list(option_bytes)));
            append_ipv4_route_fields(fields, option_bytes.subspan(3U), warning);

            std::string title = "Record Route (RR)";
            std::string id = "ipv4_option_rr";
            if (kind == kIpv4OptionLooseSourceRoute) {
                title = "Loose Source Route (LSRR)";
                id = "ipv4_option_lsrr";
            } else if (kind == kIpv4OptionStrictSourceRoute) {
                title = "Strict Source Route (SSRR)";
                id = "ipv4_option_ssrr";
            }
            option_layers.push_back(make_ipv4_option_layer(id, std::move(title), std::move(fields), warning));
            break;
        }

        case kIpv4OptionTimestamp: {
            if (length < 4U) {
                option_layers.push_back(make_malformed_ipv4_option_layer(
                    "IPv4 timestamp option length is invalid",
                    option_bytes,
                    std::move(fields)
                ));
                return make_parent_layer();
            }

            const auto overflow = static_cast<std::uint8_t>((option_bytes[3U] >> 4U) & 0x0FU);
            const auto flag = static_cast<std::uint8_t>(option_bytes[3U] & 0x0FU);
            fields.push_back(make_summary_field("Pointer", std::to_string(option_bytes[2U])));
            fields.push_back(make_summary_field("Overflow", std::to_string(overflow)));
            fields.push_back(make_summary_field("Flag", std::to_string(flag)));
            fields.push_back(make_summary_field("Raw", format_hex_byte_list(option_bytes)));
            append_ipv4_timestamp_fields(fields, option_bytes.subspan(4U), flag, warning);
            option_layers.push_back(make_ipv4_option_layer(
                "ipv4_option_timestamp",
                "Timestamp",
                std::move(fields),
                warning
            ));
            break;
        }

        case kIpv4OptionRouterAlert: {
            fields.push_back(make_summary_field("Raw", format_hex_byte_list(option_bytes)));
            if (length != 4U) {
                fields.push_back(make_summary_field("Warning", "Router Alert length should be 4 bytes"));
                warning = true;
            } else {
                const auto value = read_be16(option_bytes, 2U);
                fields.push_back(make_summary_field("Value", std::to_string(value)));
                if (value == 0U) {
                    fields.push_back(make_summary_field("Meaning", "Router shall examine packet"));
                }
            }
            option_layers.push_back(make_ipv4_option_layer(
                "ipv4_option_router_alert",
                "Router Alert",
                std::move(fields),
                warning
            ));
            break;
        }

        default:
            fields.push_back(make_summary_field("Raw", format_hex_byte_list(option_bytes)));
            option_layers.push_back(make_ipv4_option_layer(
                "ipv4_option_unknown",
                "Unknown Option " + std::to_string(kind) + " (" + format_byte_count(length) + ")",
                std::move(fields)
            ));
            break;
        }

        offset += length;
    }

    return make_parent_layer();
}

void append_layer_if_not_empty(std::vector<PacketSummaryLayer>& layers, PacketSummaryLayer layer) {
    if (!layer.fields.empty() || !layer.children.empty()) {
        layers.push_back(std::move(layer));
    }
}

void append_vlan_summary_layers(
    std::vector<PacketSummaryLayer>& layers,
    const std::vector<VlanTagDetails>& tags
) {
    for (const auto& tag : tags) {
        auto vlan_fields = std::vector<PacketSummaryField> {
            make_summary_field("TPID", format_ether_type_value(tag.tpid)),
            make_summary_field("Priority", std::to_string(vlan_priority(tag.tci))),
            make_summary_field("DEI", std::to_string(vlan_drop_eligible_indicator(tag.tci))),
            make_summary_field("VLAN ID", std::to_string(vlan_identifier(tag.tci))),
        };
        if (tag.encapsulated_ether_type < kIeee8023LengthCutoff) {
            vlan_fields.push_back(make_summary_field(
                "Encapsulated Length",
                std::to_string(tag.encapsulated_ether_type) + " bytes"
            ));
        } else {
            vlan_fields.push_back(make_summary_field(
                "Encapsulated EtherType",
                format_ether_type_value(tag.encapsulated_ether_type)
            ));
        }
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "vlan",
            .title = format_vlan_summary_title(tag),
            .fields = std::move(vlan_fields),
        });
    }
}

void apply_default_summary_layer_expansion(std::vector<PacketSummaryLayer>& layers) {
    if (layers.empty()) {
        return;
    }

    std::optional<std::size_t> last_non_warning_index {};
    for (std::size_t index = 0; index < layers.size(); ++index) {
        auto& layer = layers[index];
        layer.expanded_by_default = layer.warning;
        if (!layer.warning) {
            last_non_warning_index = index;
        }
    }

    if (last_non_warning_index.has_value()) {
        layers[*last_non_warning_index].expanded_by_default = true;
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

std::string format_igmp_type_text(const IgmpDetails& igmp) {
    switch (igmp.type) {
    case kIgmpTypeMembershipQuery:
        return (igmp.max_resp_code == 0U) ? "General Query" : "Membership Query";
    case kIgmpTypeV1MembershipReport:
        return "Membership Report";
    case kIgmpTypeV2MembershipReport:
        return "Membership Report";
    case kIgmpTypeLeaveGroup:
        return "Leave Group";
    case kIgmpTypeV3MembershipReport:
        return "Membership Report";
    default:
        return "Unknown Type";
    }
}

std::string format_igmp_type_value(const IgmpDetails& igmp) {
    std::ostringstream builder {};
    builder << format_igmp_type_text(igmp) << " (" << format_hex_value(igmp.type, 2) << ")";
    return builder.str();
}

std::string infer_igmp_version_text(const IgmpDetails& igmp) {
    switch (igmp.type) {
    case kIgmpTypeMembershipQuery:
        return igmp.max_resp_code == 0U ? "IGMPv1" : "IGMPv2";
    case kIgmpTypeV1MembershipReport:
        return "IGMPv1";
    case kIgmpTypeV2MembershipReport:
    case kIgmpTypeLeaveGroup:
        return "IGMPv2";
    case kIgmpTypeV3MembershipReport:
        return "IGMPv3";
    default:
        return "IGMP";
    }
}

std::string build_igmp_summary_title(const PacketDetails& details) {
    const auto version = infer_igmp_version_text(details.igmp);
    if (details.igmp.type == kIgmpTypeMembershipQuery) {
        if (details.igmp.has_group_address && details.igmp.group_address != 0U) {
            return version + ", Group-Specific Query " + format_ipv4_address(details.igmp.group_address);
        }
        return version + ", General Query";
    }

    if (details.igmp.type == kIgmpTypeV3MembershipReport) {
        return version + ", Membership Report";
    }

    if (details.igmp.has_group_address && details.igmp.group_address != 0U) {
        return version + ", " + format_igmp_type_text(details.igmp) + ' ' + format_ipv4_address(details.igmp.group_address);
    }

    return version + ", " + format_igmp_type_text(details.igmp);
}

std::optional<PacketSummaryLayer> build_igmp_summary_layer(const PacketDetails& details) {
    if (!details.has_igmp) {
        return std::nullopt;
    }

    std::vector<PacketSummaryField> fields {
        make_summary_field("Type", format_igmp_type_value(details.igmp)),
        make_summary_field("Max Resp Code", std::to_string(details.igmp.max_resp_code)),
        make_summary_field("Checksum", format_hex16_value(details.igmp.checksum)),
    };
    if (details.igmp.has_group_address) {
        fields.push_back(make_summary_field("Group Address", format_ipv4_address(details.igmp.group_address)));
    }
    if (details.igmp.is_v3_membership_report) {
        fields.push_back(make_summary_field("Group Record Count", std::to_string(details.igmp.group_record_count)));
    }
    if (details.has_ipv4) {
        fields.push_back(make_summary_field("Source", format_ipv4_address(details.ipv4.src_addr)));
        fields.push_back(make_summary_field("Destination", format_ipv4_address(details.ipv4.dst_addr)));
    }
    if (details.igmp.header_truncated) {
        fields.push_back(make_summary_field({}, "IGMP header is truncated."));
    }

    return PacketSummaryLayer {
        .id = "igmp",
        .title = build_igmp_summary_title(details),
        .fields = std::move(fields),
        .expanded_by_default = details.igmp.header_truncated,
        .warning = details.igmp.header_truncated,
        .marker_text = details.igmp.header_truncated ? std::string {"Warning"} : std::string {},
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
        details.has_pppoe ||
        details.has_arp ||
        details.has_igmp) {
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
    builder << format_ipv4_address(endpoint.addr);
    if (endpoint.port != 0U) {
        builder << ':' << endpoint.port;
    }
    return builder.str();
}

std::string format_endpoint(const EndpointKeyV6& endpoint) {
    std::ostringstream builder {};
    builder << '[' << format_ipv6_address(endpoint.addr) << ']';
    if (endpoint.port != 0U) {
        builder << ':' << endpoint.port;
    }
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
    std::vector<std::string> lines {};
    if (details.has_igmp) {
        lines.push_back("Message: " + build_igmp_summary_title(details));
        if (details.igmp.has_group_address) {
            lines.push_back("Group Address: " + format_ipv4_address(details.igmp.group_address));
        }
        if (details.has_ipv4) {
            lines.push_back("Source: " + format_ipv4_address(details.ipv4.src_addr));
            lines.push_back("Destination: " + format_ipv4_address(details.ipv4.dst_addr));
        }
        if (details.igmp.is_v3_membership_report) {
            lines.push_back("Group Record Count: " + std::to_string(details.igmp.group_record_count));
        }
        if (details.igmp.header_truncated) {
            lines.push_back("IGMP header is truncated.");
        }
        return lines;
    }

    if (!details.has_arp) {
        return {};
    }

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
    if (details.has_ipv4 && details.ipv4.invalid_header_length) {
        warning_fields.push_back(make_summary_field({}, "IPv4 header length is invalid"));
    }
    if (details.has_ipv4 && details.ipv4.total_length_invalid) {
        warning_fields.push_back(make_summary_field({}, "IPv4 total length is smaller than the declared IPv4 header length"));
    }
    if (details.has_ipv4 && details.ipv4.header_truncated) {
        warning_fields.push_back(make_summary_field({}, "IPv4 header is truncated"));
    }
    if (details.has_ipv4 && details.ipv4.options_truncated) {
        warning_fields.push_back(make_summary_field({}, "IPv4 options truncated"));
    }
    if (details.vlan_tag_truncated) {
        warning_fields.push_back(make_summary_field({}, "VLAN tag header is truncated"));
        warning_fields.push_back(make_summary_field("VLAN TPID", format_ether_type_value(details.truncated_vlan_tpid)));
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

    const auto packet_number_in_file = details.packet_index + 1U;

    std::vector<PacketSummaryField> frame_fields {};
    if (options.flow_packet_index.has_value()) {
        frame_fields.push_back(make_summary_field("Packet number in flow", std::to_string(*options.flow_packet_index)));
    }
    frame_fields.push_back(make_summary_field("Packet number in file", std::to_string(packet_number_in_file)));
    frame_fields.push_back(make_summary_field("Timestamp", format_packet_timestamp_full(packet)));
    frame_fields.push_back(make_summary_field("Captured Length", std::to_string(details.captured_length) + " bytes"));
    frame_fields.push_back(make_summary_field("Original Length", std::to_string(details.original_length) + " bytes"));

    append_layer_if_not_empty(layers, PacketSummaryLayer {
        .id = "frame",
        .title = options.flow_packet_index.has_value()
            ? "Frame: Packet " + std::to_string(*options.flow_packet_index) +
                " in Flow, Packet " + std::to_string(packet_number_in_file) + " in file"
            : "Frame: Packet " + std::to_string(packet_number_in_file) + " in file",
        .fields = std::move(frame_fields),
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
        auto ethernet_fields = std::vector<PacketSummaryField> {
            make_summary_field("Source", format_mac_address(details.ethernet.src_mac)),
            make_summary_field("Destination", format_mac_address(details.ethernet.dst_mac)),
        };
        if (details.ethernet.uses_length_field) {
            ethernet_fields.push_back(make_summary_field(
                "Length",
                std::to_string(details.ethernet.ether_type) + " bytes"
            ));
            if (details.llc.captured_payload_exceeds_declared) {
                ethernet_fields.push_back(make_summary_field(
                    "Warning",
                    "Captured bytes extend beyond the declared IEEE 802.3 payload length"
                ));
            }
        } else {
            ethernet_fields.push_back(make_summary_field("Type", format_ether_type_value(details.ethernet.ether_type)));
        }
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "ethernet",
        .title = std::string(details.ethernet.uses_length_field ? "IEEE 802.3" : "Ethernet II") +
                ", Src: " + format_mac_address(details.ethernet.src_mac) +
                ", Dst: " + format_mac_address(details.ethernet.dst_mac),
            .fields = std::move(ethernet_fields),
        });
    }

    const bool has_nested_inner_ethernet = details.has_inner_ethernet && (details.has_mpls || details.has_pbb);
    const auto& outer_vlan_tags = details.has_pbb ? details.encapsulating_vlan_tags : details.vlan_tags;
    const bool has_outer_vlans = !outer_vlan_tags.empty();

    if (details.has_pbb && has_outer_vlans) {
        append_vlan_summary_layers(layers, outer_vlan_tags);
    } else if (has_outer_vlans && !has_nested_inner_ethernet) {
        append_vlan_summary_layers(layers, outer_vlan_tags);
    }

    if (details.vlan_tag_truncated && !has_nested_inner_ethernet) {
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "vlan",
            .title = format_vlan_tpid_name(details.truncated_vlan_tpid) + " (truncated)",
            .fields = {
                make_summary_field("TPID", format_ether_type_value(details.truncated_vlan_tpid)),
                make_summary_field("Warning", "VLAN tag header is truncated"),
            },
            .expanded_by_default = true,
            .warning = true,
            .marker_text = "Warning",
        });
    }

    if (details.has_llc && !has_nested_inner_ethernet) {
        std::vector<PacketSummaryField> llc_fields {};
        if (details.llc.available_header_bytes >= 1U) {
            llc_fields.push_back(make_summary_field("DSAP", format_hex_value(details.llc.dsap, 2)));
        }
        if (details.llc.available_header_bytes >= 2U) {
            llc_fields.push_back(make_summary_field("SSAP", format_hex_value(details.llc.ssap, 2)));
        }
        if (details.llc.available_header_bytes >= 3U) {
            llc_fields.push_back(make_summary_field("Control", format_hex_value(details.llc.control, 2)));
        }
        if (details.llc.header_truncated) {
            llc_fields.push_back(make_summary_field("Warning", "LLC header is truncated"));
        }
        if (details.llc.payload_length_exceeds_captured) {
            llc_fields.push_back(make_summary_field("Warning", "IEEE 802.3 payload length exceeds captured payload bytes"));
        }
        if (details.llc.captured_payload_exceeds_declared && !details.ethernet.uses_length_field) {
            llc_fields.push_back(make_summary_field("Warning", "Captured bytes extend beyond the declared IEEE 802.3 payload length"));
        }

        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "llc",
            .title = "LLC",
            .fields = std::move(llc_fields),
            .warning = details.llc.header_truncated,
            .marker_text = details.llc.header_truncated ? std::string {"Warning"} : std::string {},
        });
    }

    if (details.has_snap && !has_nested_inner_ethernet) {
        const auto oui_text = format_hex_byte_sequence(
            std::span<const std::uint8_t>(details.snap.oui.data(), details.snap.oui.size())
        );
        std::vector<PacketSummaryField> snap_fields {
            make_summary_field("OUI", oui_text),
        };
        if (!details.snap.header_truncated) {
            snap_fields.push_back(make_summary_field("PID", format_ether_type_value(details.snap.pid)));
        } else {
            snap_fields.push_back(make_summary_field("Warning", "SNAP header is truncated"));
        }

        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "snap",
            .title = "SNAP",
            .fields = std::move(snap_fields),
            .warning = details.snap.header_truncated,
            .marker_text = details.snap.header_truncated ? std::string {"Warning"} : std::string {},
        });
    }

    if (!has_nested_inner_ethernet) {
        if (const auto payload_layer = build_unknown_llc_snap_payload_layer(details); payload_layer.has_value()) {
            append_layer_if_not_empty(layers, *payload_layer);
        }
    }

    if (details.has_mpls) {
        for (const auto& label : details.mpls_labels) {
            std::vector<PacketSummaryField> mpls_fields {
                make_summary_field("Label", std::to_string(label.label)),
                make_summary_field("Traffic Class", std::to_string(label.traffic_class)),
                make_summary_field("Bottom of Stack", label.bottom_of_stack ? "1" : "0"),
                make_summary_field("TTL", std::to_string(label.ttl)),
            };
            if (const auto label_name = format_mpls_label_name(label.label); label_name.has_value()) {
                mpls_fields.push_back(make_summary_field("Label Name", *label_name));
            }

            append_layer_if_not_empty(layers, PacketSummaryLayer {
                .id = "mpls",
                .title = "MPLS Label, Label: " + std::to_string(label.label) +
                    ", TC: " + std::to_string(label.traffic_class) +
                    ", BoS: " + std::string(label.bottom_of_stack ? "1" : "0") +
                    ", TTL: " + std::to_string(label.ttl),
                .fields = std::move(mpls_fields),
            });
        }
    }

    if (details.has_mpls_pseudowire_control_word) {
        auto control_word_fields = std::vector<PacketSummaryField> {};
        if (details.mpls_pseudowire_control_word.available_bytes >= 2U) {
            control_word_fields.push_back(make_summary_field("Flags", format_hex16_value(details.mpls_pseudowire_control_word.flags)));
        }
        if (details.mpls_pseudowire_control_word.available_bytes >= 4U) {
            control_word_fields.push_back(make_summary_field("Sequence", std::to_string(details.mpls_pseudowire_control_word.sequence)));
        }
        if (details.mpls_pseudowire_control_word.truncated) {
            control_word_fields.push_back(make_summary_field("Warning", "MPLS pseudowire control word is truncated"));
        }
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "mpls-pw-control-word",
            .title = "MPLS Pseudowire Control Word",
            .fields = std::move(control_word_fields),
            .warning = details.mpls_pseudowire_control_word.truncated,
            .marker_text = details.mpls_pseudowire_control_word.truncated ? "Warning" : std::string {},
        });
    }

    if (details.has_pbb) {
        std::vector<PacketSummaryField> pbb_fields {};
        append_pbb_itag_summary_fields(pbb_fields, details.pbb);
        if (details.pbb.itag_truncated) {
            pbb_fields.push_back(make_summary_field("Warning", "PBB I-TAG is truncated"));
        }

        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "pbb",
            .title = "PBB I-TAG",
            .fields = std::move(pbb_fields),
            .warning = details.pbb.itag_truncated,
            .marker_text = details.pbb.itag_truncated ? "Warning" : std::string {},
        });
    }

    if (details.has_inner_ethernet && !details.has_vxlan) {
        append_layer_if_not_empty(layers, build_inner_ethernet_summary_layer(details.inner_ethernet));
    }

    if (details.has_vlan && has_nested_inner_ethernet) {
        append_vlan_summary_layers(layers, details.vlan_tags);
    }

    if (details.has_llc && has_nested_inner_ethernet) {
        std::vector<PacketSummaryField> llc_fields {};
        if (details.llc.available_header_bytes >= 1U) {
            llc_fields.push_back(make_summary_field("DSAP", format_hex_value(details.llc.dsap, 2)));
        }
        if (details.llc.available_header_bytes >= 2U) {
            llc_fields.push_back(make_summary_field("SSAP", format_hex_value(details.llc.ssap, 2)));
        }
        if (details.llc.available_header_bytes >= 3U) {
            llc_fields.push_back(make_summary_field("Control", format_hex_value(details.llc.control, 2)));
        }
        if (details.llc.header_truncated) {
            llc_fields.push_back(make_summary_field("Warning", "LLC header is truncated"));
        }
        if (details.llc.payload_length_exceeds_captured) {
            llc_fields.push_back(make_summary_field("Warning", "IEEE 802.3 payload length exceeds captured payload bytes"));
        }
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "llc",
            .title = "LLC",
            .fields = std::move(llc_fields),
            .warning = details.llc.header_truncated,
            .marker_text = details.llc.header_truncated ? std::string {"Warning"} : std::string {},
        });
    }

    if (details.has_snap && has_nested_inner_ethernet) {
        const auto oui_text = format_hex_byte_sequence(
            std::span<const std::uint8_t>(details.snap.oui.data(), details.snap.oui.size())
        );
        std::vector<PacketSummaryField> snap_fields {
            make_summary_field("OUI", oui_text),
        };
        if (!details.snap.header_truncated) {
            snap_fields.push_back(make_summary_field("PID", format_ether_type_value(details.snap.pid)));
        } else {
            snap_fields.push_back(make_summary_field("Warning", "SNAP header is truncated"));
        }

        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "snap",
            .title = "SNAP",
            .fields = std::move(snap_fields),
            .warning = details.snap.header_truncated,
            .marker_text = details.snap.header_truncated ? std::string {"Warning"} : std::string {},
        });
    }

    if (has_nested_inner_ethernet) {
        if (const auto payload_layer = build_unknown_llc_snap_payload_layer(details); payload_layer.has_value()) {
            append_layer_if_not_empty(layers, *payload_layer);
        }
        if (const auto payload_layer = build_unknown_inner_ethernet_payload_layer(details); payload_layer.has_value()) {
            append_layer_if_not_empty(layers, *payload_layer);
        }
    }

    if (details.has_macsec) {
        std::vector<PacketSummaryField> macsec_fields {};
        if (details.macsec.available_base_bytes >= 1U) {
            macsec_fields.push_back(make_summary_field("Version", std::to_string(details.macsec.version)));
            macsec_fields.push_back(make_summary_field("ES", details.macsec.es ? "1" : "0"));
            macsec_fields.push_back(make_summary_field("SC", details.macsec.sc ? "1" : "0"));
            macsec_fields.push_back(make_summary_field("SCB", details.macsec.scb ? "1" : "0"));
            macsec_fields.push_back(make_summary_field("Encrypted (E)", details.macsec.encrypted ? "1" : "0"));
            macsec_fields.push_back(make_summary_field("Changed (C)", details.macsec.changed ? "1" : "0"));
            macsec_fields.push_back(make_summary_field("Association Number", std::to_string(details.macsec.association_number)));
        }
        if (details.macsec.available_base_bytes >= 2U) {
            macsec_fields.push_back(make_summary_field("Short Length", std::to_string(details.macsec.short_length)));
        }
        if (details.macsec.packet_number_present) {
            macsec_fields.push_back(make_summary_field(
                "Packet Number",
                format_macsec_packet_number(details.macsec.packet_number)
            ));
        }
        if (details.macsec.sc && details.macsec.available_sci_bytes >= 6U) {
            macsec_fields.push_back(make_summary_field(
                "SCI System ID",
                format_mac_address(details.macsec.sci_system_id)
            ));
        }
        if (details.macsec.sc && details.macsec.available_sci_bytes >= 8U) {
            macsec_fields.push_back(make_summary_field(
                "SCI Port ID",
                format_hex16_value(details.macsec.sci_port_id)
            ));
        }
        if (details.macsec.sectag_truncated) {
            macsec_fields.push_back(make_summary_field("Warning", "MACsec SecTAG is truncated"));
        }
        if (details.macsec.packet_number_truncated) {
            macsec_fields.push_back(make_summary_field("Warning", "MACsec packet number is truncated"));
        }
        if (details.macsec.sci_truncated) {
            macsec_fields.push_back(make_summary_field("Warning", "MACsec SCI is truncated"));
        }
        if (details.macsec.icv_truncated) {
            macsec_fields.push_back(make_summary_field("Warning", "MACsec ICV is truncated"));
        }

        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "macsec",
            .title = "MACsec SecTAG",
            .fields = std::move(macsec_fields),
            .warning = details.macsec.sectag_truncated ||
                details.macsec.packet_number_truncated ||
                details.macsec.sci_truncated ||
                details.macsec.icv_truncated,
            .marker_text = (details.macsec.sectag_truncated ||
                details.macsec.packet_number_truncated ||
                details.macsec.sci_truncated ||
                details.macsec.icv_truncated)
                ? "Warning"
                : std::string {},
        });

        if (const auto payload_layer = build_macsec_protected_payload_layer(details); payload_layer.has_value()) {
            append_layer_if_not_empty(layers, *payload_layer);
        }
        if (const auto icv_layer = build_macsec_icv_layer(details); icv_layer.has_value()) {
            append_layer_if_not_empty(layers, *icv_layer);
        }
    }

    if (details.has_pppoe) {
        std::vector<PacketSummaryField> pppoe_fields {
            make_summary_field("Version", std::to_string(details.pppoe.version)),
            make_summary_field("Type", std::to_string(details.pppoe.type)),
            make_summary_field("Code", format_pppoe_code(details.pppoe.code)),
            make_summary_field("Session ID", format_hex16_value(details.pppoe.session_id)),
            make_summary_field("Payload Length", std::to_string(details.pppoe.payload_length) + " bytes"),
        };
        if (details.pppoe.is_discovery) {
            for (const auto& tag : details.pppoe.discovery_tags) {
                if (tag.header_truncated) {
                    pppoe_fields.push_back(make_summary_field("Warning", "PPPoE Discovery tag header is truncated"));
                    continue;
                }
                auto value_text = format_pppoe_tag_value(
                    std::span<const std::uint8_t>(tag.value.data(), tag.value.size())
                );
                if (tag.value_truncated) {
                    value_text += " (truncated)";
                }
                pppoe_fields.push_back(make_summary_field(format_pppoe_tag_type(tag.type), std::move(value_text)));
            }
            if (details.pppoe.discovery_tag_header_truncated) {
                pppoe_fields.push_back(make_summary_field("Warning", "PPPoE Discovery tag header is truncated"));
            }
            if (details.pppoe.discovery_tag_value_truncated) {
                pppoe_fields.push_back(make_summary_field("Warning", "PPPoE Discovery tag value is truncated"));
            }
        } else if (details.pppoe.protocol_field_truncated) {
            pppoe_fields.push_back(make_summary_field("Warning", "PPP protocol field is truncated"));
        }
        if (details.pppoe.header_truncated) {
            pppoe_fields.push_back(make_summary_field("Warning", "PPPoE header is truncated"));
        }
        if (details.pppoe.declared_payload_exceeds_captured) {
            pppoe_fields.push_back(make_summary_field(
                "Warning",
                "PPPoE payload length exceeds captured payload bytes"
            ));
        }
        if (details.pppoe.captured_payload_exceeds_declared) {
            pppoe_fields.push_back(make_summary_field(
                "Warning",
                "PPPoE payload length is shorter than captured payload bytes; trailing bytes ignored"
            ));
        }

        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "pppoe",
            .title = (details.pppoe.is_discovery
                ? "PPPoE Discovery, Code: " + format_pppoe_code(details.pppoe.code)
                : "PPPoE Session, Session ID: " + format_hex16_value(details.pppoe.session_id)),
            .fields = std::move(pppoe_fields),
            .warning = details.pppoe.header_truncated ||
                details.pppoe.protocol_field_truncated ||
                details.pppoe.payload_length_mismatch ||
                details.pppoe.discovery_tag_header_truncated ||
                details.pppoe.discovery_tag_value_truncated,
            .marker_text = (details.pppoe.header_truncated ||
                details.pppoe.protocol_field_truncated ||
                details.pppoe.payload_length_mismatch ||
                details.pppoe.discovery_tag_header_truncated ||
                details.pppoe.discovery_tag_value_truncated)
                ? "Warning"
                : std::string {},
        });

        if (!details.pppoe.is_discovery &&
            !details.pppoe.protocol_field_truncated &&
            details.pppoe.ppp_protocol != 0U) {
            std::vector<PacketSummaryLayer> ppp_children {};
            if (details.pppoe.control.present) {
                std::vector<PacketSummaryField> control_fields {
                    make_summary_field("Code", format_ppp_control_code(details.pppoe.control.code)),
                    make_summary_field("Identifier", std::to_string(static_cast<unsigned>(details.pppoe.control.identifier))),
                    make_summary_field("Length", std::to_string(details.pppoe.control.length) + " bytes"),
                };
                if (details.pppoe.control.header_truncated) {
                    control_fields.push_back(make_summary_field("Warning", "PPP control header is truncated"));
                }
                if (details.pppoe.control.payload_truncated) {
                    control_fields.push_back(make_summary_field("Warning", "PPP control payload is truncated"));
                }
                if (details.pppoe.control.option_header_truncated) {
                    control_fields.push_back(make_summary_field("Warning", "PPP control option header is truncated"));
                }
                if (details.pppoe.control.option_value_truncated) {
                    control_fields.push_back(make_summary_field("Warning", "PPP control option value is truncated"));
                }

                std::vector<PacketSummaryLayer> control_children {};
                if (const auto options_layer = build_ppp_control_options_layer(details); options_layer.has_value()) {
                    control_children.push_back(*options_layer);
                }

                ppp_children.push_back(PacketSummaryLayer {
                    .id = "ppp-control",
                    .title = format_ppp_protocol(details.pppoe.ppp_protocol) + ", " + format_ppp_control_code(details.pppoe.control.code),
                    .fields = std::move(control_fields),
                    .children = std::move(control_children),
                    .warning = details.pppoe.control.header_truncated ||
                        details.pppoe.control.payload_truncated ||
                        details.pppoe.control.option_header_truncated ||
                        details.pppoe.control.option_value_truncated,
                    .marker_text = (details.pppoe.control.header_truncated ||
                        details.pppoe.control.payload_truncated ||
                        details.pppoe.control.option_header_truncated ||
                        details.pppoe.control.option_value_truncated)
                        ? "Warning"
                        : std::string {},
                });
            }

            if (const auto payload_layer = build_unknown_ppp_payload_layer(details); payload_layer.has_value()) {
                ppp_children.push_back(*payload_layer);
            }

            append_layer_if_not_empty(layers, PacketSummaryLayer {
                .id = "ppp",
                .title = "PPP, Protocol: " + format_ppp_protocol(details.pppoe.ppp_protocol),
                .fields = {
                    make_summary_field("Protocol", format_ppp_protocol(details.pppoe.ppp_protocol)),
                },
                .children = std::move(ppp_children),
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
        std::vector<PacketSummaryField> ipv4_fields {};
        ipv4_fields.push_back(make_summary_field("Version", "4"));
        ipv4_fields.push_back(make_summary_field(
            "Internet Header Length",
            std::to_string(details.ipv4.header_length_bytes) + " bytes (" +
                std::to_string(details.ipv4.header_length_bytes / 4U) + ")"
        ));
        if (ipv4_field_available(details, 2U)) {
            ipv4_fields.push_back(make_summary_field("Differentiated Services Field", format_hex_value(details.ipv4.differentiated_services_field, 2)));
        }
        if (ipv4_field_available(details, 4U)) {
            ipv4_fields.push_back(make_summary_field("Total Length", std::to_string(details.ipv4.total_length) + " bytes"));
        }
        if (ipv4_field_available(details, 6U)) {
            ipv4_fields.push_back(make_summary_field("Identification", format_hex16_value(details.ipv4.identification)));
        }
        if (ipv4_field_available(details, 8U)) {
            ipv4_fields.push_back(make_summary_field("Flags", format_hex_value(details.ipv4.flags, 1)));
            ipv4_fields.push_back(make_summary_field("Fragment Offset", std::to_string(details.ipv4.fragment_offset)));
        }
        if (ipv4_field_available(details, 9U)) {
            ipv4_fields.push_back(make_summary_field("TTL", std::to_string(details.ipv4.ttl)));
        }
        if (ipv4_field_available(details, 10U)) {
            ipv4_fields.push_back(make_summary_field("Protocol", format_protocol_summary_value_with_number(details.ipv4.protocol)));
        }
        if (ipv4_field_available(details, 12U)) {
            ipv4_fields.push_back(make_summary_field("Header Checksum", format_hex16_value(details.ipv4.header_checksum)));
        }
        if (ipv4_field_available(details, 16U)) {
            ipv4_fields.push_back(make_summary_field("Source Address", format_ipv4_address(details.ipv4.src_addr)));
        }
        if (ipv4_field_available(details, 20U)) {
            ipv4_fields.push_back(make_summary_field("Destination Address", format_ipv4_address(details.ipv4.dst_addr)));
        }
        if (packet.is_ip_fragmented) {
            ipv4_fields.push_back(make_summary_field("Fragmentation", "Packet is fragmented"));
        }
        if (details.ipv4.header_truncated) {
            ipv4_fields.push_back(make_summary_field("Warning", "IPv4 header is truncated"));
        }
        if (details.ipv4.header_length_bytes > details.ipv4.available_header_bytes) {
            ipv4_fields.push_back(make_summary_field("Incomplete Header", "Captured IPv4 header bytes are fewer than the IHL"));
        }
        if (ipv4_field_available(details, 4U) && details.ipv4.total_length > details.ipv4.available_packet_bytes) {
            ipv4_fields.push_back(make_summary_field("Warning", "IPv4 total length exceeds captured packet bytes"));
        }
        std::vector<PacketSummaryLayer> ipv4_children {};
        if (const auto ipv4_options = build_ipv4_options_summary_layer(details); ipv4_options.has_value()) {
            ipv4_children.push_back(*ipv4_options);
        }
        auto ipv4_title = std::string {"IPv4"};
        if (ipv4_field_available(details, 16U)) {
            ipv4_title += ", Src: " + format_ipv4_address(details.ipv4.src_addr);
            if (ipv4_field_available(details, 20U)) {
                ipv4_title += ", Dst: " + format_ipv4_address(details.ipv4.dst_addr);
            }
        }
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "ipv4",
            .title = std::move(ipv4_title),
            .fields = std::move(ipv4_fields),
            .children = std::move(ipv4_children),
            .warning = details.ipv4.invalid_header_length || details.ipv4.total_length_invalid || details.ipv4.header_truncated,
            .marker_text = (details.ipv4.invalid_header_length || details.ipv4.total_length_invalid || details.ipv4.header_truncated)
                ? "Warning"
                : std::string {},
        });
    }

    if (details.has_ipv6) {
        std::vector<PacketSummaryField> ipv6_fields {
            make_summary_field("Version", "6"),
            make_summary_field("Traffic Class", format_hex_value(details.ipv6.traffic_class, 2)),
            make_summary_field("Flow Label", format_hex_value(details.ipv6.flow_label)),
            make_summary_field("Payload Length", std::to_string(details.ipv6.payload_length) + " bytes"),
            make_summary_field("Next Header", format_protocol_summary_value_with_number(details.ipv6.next_header)),
            make_summary_field("Hop Limit", std::to_string(details.ipv6.hop_limit)),
            make_summary_field("Source Address", format_ipv6_address(details.ipv6.src_addr)),
            make_summary_field("Destination Address", format_ipv6_address(details.ipv6.dst_addr)),
        };
        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "ipv6",
            .title = "IPv6, Src: " +
                format_ipv6_address(details.ipv6.src_addr) +
                ", Dst: " + format_ipv6_address(details.ipv6.dst_addr),
            .fields = std::move(ipv6_fields),
        });
    }

    if (const auto igmp_layer = build_igmp_summary_layer(details); igmp_layer.has_value()) {
        append_layer_if_not_empty(layers, *igmp_layer);
    }

    if (details.has_tcp) {
        std::vector<PacketSummaryField> tcp_fields {
            make_summary_field("Source Port", std::to_string(details.tcp.src_port)),
            make_summary_field("Destination Port", std::to_string(details.tcp.dst_port)),
            make_summary_field("Sequence Number (raw)", std::to_string(details.tcp.seq_number)),
            make_summary_field("Acknowledgment Number (raw)", std::to_string(details.tcp.ack_number)),
            make_summary_field(
                "Header Length",
                std::to_string(details.tcp.header_length_bytes) + " bytes (" +
                    std::to_string(details.tcp.header_length_bytes / 4U) + ")"
            ),
            make_summary_field("Flags", format_tcp_flags_text(details.tcp.flags)),
            make_summary_field("Window", std::to_string(details.tcp.window)),
            make_summary_field("Checksum", format_hex16_value(details.tcp.checksum)),
            make_summary_field("Urgent Pointer", std::to_string(details.tcp.urgent_pointer)),
        };
        std::vector<PacketSummaryLayer> tcp_children {};
        if (const auto tcp_options = build_tcp_options_summary_layer(details.tcp.options_bytes); tcp_options.has_value()) {
            tcp_children.push_back(*tcp_options);
        }
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
            .title = "TCP, Src Port: " +
                std::to_string(details.tcp.src_port) +
                ", Dst Port: " + std::to_string(details.tcp.dst_port),
            .fields = std::move(tcp_fields),
            .children = std::move(tcp_children),
        });
    }

    if (details.has_udp) {
        std::vector<PacketSummaryField> udp_fields {
            make_summary_field("Source Port", std::to_string(details.udp.src_port)),
            make_summary_field("Destination Port", std::to_string(details.udp.dst_port)),
            make_summary_field("Length", std::to_string(details.udp.length) + " bytes"),
            make_summary_field("Checksum", format_hex16_value(details.udp.checksum)),
        };
        if (details.udp.payload_truncated) {
            udp_fields.push_back(make_summary_field("Warning", "UDP length exceeds available packet bytes"));
        }
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
            .title = "UDP, Src Port: " +
                std::to_string(details.udp.src_port) +
                ", Dst Port: " + std::to_string(details.udp.dst_port),
            .fields = std::move(udp_fields),
            .warning = details.udp.payload_truncated,
            .marker_text = details.udp.payload_truncated ? std::string {"Warning"} : std::string {},
        });
    }

    if (details.has_vxlan) {
        std::vector<PacketSummaryField> vxlan_fields {
            make_summary_field("Flags", format_hex_value(details.vxlan.flags, 2)),
            make_summary_field("I Flag", details.vxlan.i_flag_set ? "Set" : "Not set"),
            make_summary_field("VNI", std::to_string(details.vxlan.vni)),
        };
        if (details.vxlan.has_inner_ethernet) {
            vxlan_fields.push_back(make_summary_field("Inner Payload", "Ethernet"));
            if (details.inner_ethernet.available_header_bytes >= 14U) {
                if (details.inner_ethernet.uses_length_field) {
                    vxlan_fields.push_back(make_summary_field(
                        "Inner Length",
                        std::to_string(details.inner_ethernet.ether_type) + " bytes"
                    ));
                } else {
                    vxlan_fields.push_back(make_summary_field(
                        "Inner EtherType",
                        format_ether_type_value(details.inner_ethernet.ether_type)
                    ));
                }
            }
        }
        if (details.vxlan.inner_ethernet_truncated) {
            vxlan_fields.push_back(make_summary_field("Warning", "Inner Ethernet header is truncated"));
        }

        std::vector<PacketSummaryLayer> vxlan_children {};
        if (details.has_inner_ethernet) {
            vxlan_children.push_back(build_inner_ethernet_summary_layer(details.inner_ethernet));
        }

        append_layer_if_not_empty(layers, PacketSummaryLayer {
            .id = "vxlan",
            .title = "VXLAN",
            .fields = std::move(vxlan_fields),
            .children = std::move(vxlan_children),
            .warning = details.vxlan.inner_ethernet_truncated,
            .marker_text = details.vxlan.inner_ethernet_truncated ? "Warning" : std::string {},
        });
    }

    if (const auto trailer_layer = build_ieee_802_3_trailer_layer(details); trailer_layer.has_value()) {
        append_layer_if_not_empty(layers, *trailer_layer);
    }

    if (const auto protocol_layer = build_protocol_text_summary_layer(details, options.protocol_details_text);
        protocol_layer.has_value()) {
        append_layer_if_not_empty(layers, *protocol_layer);
    }

    apply_default_summary_layer_expansion(layers);
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

    if (details.has_macsec) {
        builder << "Protocol: MACsec / IEEE 802.1AE";
        if (details.macsec.available_base_bytes >= 1U) {
            builder << '\n'
                    << '\t' << "Version: " << static_cast<unsigned>(details.macsec.version) << '\n'
                    << '\t' << "ES: " << (details.macsec.es ? "1" : "0") << '\n'
                    << '\t' << "SC: " << (details.macsec.sc ? "1" : "0") << '\n'
                    << '\t' << "SCB: " << (details.macsec.scb ? "1" : "0") << '\n'
                    << '\t' << "Encrypted (E): " << (details.macsec.encrypted ? "1" : "0") << '\n'
                    << '\t' << "Changed (C): " << (details.macsec.changed ? "1" : "0") << '\n'
                    << '\t' << "Association Number: " << static_cast<unsigned>(details.macsec.association_number);
        }
        if (details.macsec.available_base_bytes >= 2U) {
            builder << '\n' << '\t' << "Short Length: " << static_cast<unsigned>(details.macsec.short_length);
        }
        if (details.macsec.packet_number_present) {
            builder << '\n' << '\t' << "Packet Number: " << format_macsec_packet_number(details.macsec.packet_number);
        }
        if (details.macsec.sc && details.macsec.available_sci_bytes >= 6U) {
            builder << '\n' << '\t' << "SCI System ID: " << format_mac_address(details.macsec.sci_system_id);
        }
        if (details.macsec.sc && details.macsec.available_sci_bytes >= 8U) {
            builder << '\n' << '\t' << "SCI Port ID: " << format_hex16_value(details.macsec.sci_port_id);
        }
        builder << '\n' << '\t' << "Protected Payload Length: " << details.macsec.protected_payload_length << " bytes";
        if (has_plaintext_macsec_ether_type(details)) {
            builder << '\n' << '\t' << "Plain EtherType: "
                    << format_ether_type_value(macsec_plaintext_ether_type(details))
                    << '\n' << '\t' << "Data Length: " << (details.macsec.protected_payload_length - 2U) << " bytes";
        }
        if (details.macsec.icv_length > 0U) {
            builder << '\n' << '\t' << "ICV Length: " << details.macsec.icv_length << " bytes";
        }
        builder << '\n' << '\t' << "Protected payload is not decrypted.";
        if (details.macsec.sectag_truncated) {
            builder << '\n' << '\t' << "Warning: MACsec SecTAG is truncated.";
        }
        if (details.macsec.packet_number_truncated) {
            builder << '\n' << '\t' << "Warning: MACsec packet number is truncated.";
        }
        if (details.macsec.sci_truncated) {
            builder << '\n' << '\t' << "Warning: MACsec SCI is truncated.";
        }
        if (details.macsec.icv_truncated) {
            builder << '\n' << '\t' << "Warning: MACsec ICV is truncated.";
        }
        return builder.str();
    }

    if (details.has_pppoe) {
        builder << "Protocol: " << (details.pppoe.is_discovery ? "PPPoE Discovery" : "PPPoE Session") << '\n'
                << '\t' << "Version: " << static_cast<unsigned>(details.pppoe.version) << '\n'
                << '\t' << "Type: " << static_cast<unsigned>(details.pppoe.type) << '\n'
                << '\t' << "Code: " << format_pppoe_code(details.pppoe.code) << '\n'
                << '\t' << "Session ID: " << format_hex16_value(details.pppoe.session_id) << '\n'
                << '\t' << "Payload Length: " << details.pppoe.payload_length << " bytes";
        if (details.pppoe.is_discovery) {
            for (const auto& tag : details.pppoe.discovery_tags) {
                if (tag.header_truncated) {
                    builder << '\n' << '\t' << "Warning: PPPoE Discovery tag header is truncated.";
                    continue;
                }
                auto value_text = format_pppoe_tag_value(
                    std::span<const std::uint8_t>(tag.value.data(), tag.value.size())
                );
                if (tag.value_truncated) {
                    value_text += " (truncated)";
                }
                builder << '\n' << '\t' << format_pppoe_tag_type(tag.type) << ": " << value_text;
            }
            if (details.pppoe.discovery_tag_header_truncated) {
                builder << '\n' << '\t' << "Warning: PPPoE Discovery tag header is truncated.";
            }
            if (details.pppoe.discovery_tag_value_truncated) {
                builder << '\n' << '\t' << "Warning: PPPoE Discovery tag value is truncated.";
            }
        } else if (details.pppoe.protocol_field_truncated) {
            builder << '\n' << '\t' << "Warning: PPP protocol field is truncated.";
        } else if (details.pppoe.ppp_protocol != 0U) {
            if (details.pppoe.control.present) {
                builder << '\n' << '\t' << "PPP Control Code: " << format_ppp_control_code(details.pppoe.control.code)
                        << '\n' << '\t' << "PPP Control Identifier: " << static_cast<unsigned>(details.pppoe.control.identifier)
                        << '\n' << '\t' << "PPP Control Length: " << details.pppoe.control.length << " bytes";

                for (const auto& option : details.pppoe.control.options) {
                    if (option.header_truncated) {
                        builder << '\n' << '\t' << "Warning: PPP control option header is truncated.";
                        continue;
                    }

                    auto value_text = format_ppp_control_option_value(
                        details.pppoe.ppp_protocol,
                        option.type,
                        std::span<const std::uint8_t>(option.value.data(), option.value.size())
                    );
                    if (option.value_truncated) {
                        value_text += " (truncated)";
                    }
                    builder << '\n' << '\t'
                            << format_ppp_control_option_name(details.pppoe.ppp_protocol, option.type)
                            << ": " << value_text;
                }

                if (details.pppoe.control.header_truncated) {
                    builder << '\n' << '\t' << "Warning: PPP control header is truncated.";
                }
                if (details.pppoe.control.payload_truncated) {
                    builder << '\n' << '\t' << "Warning: PPP control payload is truncated.";
                }
                if (details.pppoe.control.option_header_truncated) {
                    builder << '\n' << '\t' << "Warning: PPP control option header is truncated.";
                }
                if (details.pppoe.control.option_value_truncated) {
                    builder << '\n' << '\t' << "Warning: PPP control option value is truncated.";
                }
            } else if (details.pppoe.ppp_protocol != kPppProtocolIpv4 &&
                       details.pppoe.ppp_protocol != kPppProtocolIpv6) {
                builder << '\n' << '\t' << "PPP Protocol: " << format_ppp_protocol(details.pppoe.ppp_protocol)
                        << '\n' << '\t' << "Data Length: " << details.pppoe.unknown_ppp_payload_length << " bytes";
                if (!details.pppoe.unknown_ppp_payload_preview.empty()) {
                    builder << '\n' << '\t' << "Data Raw Preview: "
                            << format_hex_byte_list(std::span<const std::uint8_t>(
                                   details.pppoe.unknown_ppp_payload_preview.data(),
                                   details.pppoe.unknown_ppp_payload_preview.size()
                               ));
                }
                if (details.pppoe.unknown_ppp_payload_preview_truncated) {
                    builder << '\n' << '\t' << "Raw preview truncated: yes";
                }
            }
        }
        if (details.pppoe.header_truncated) {
            builder << '\n' << '\t' << "Warning: PPPoE header is truncated.";
        }
        if (details.pppoe.declared_payload_exceeds_captured) {
            builder << '\n' << '\t' << "Warning: PPPoE payload length exceeds captured payload bytes.";
        }
        if (details.pppoe.captured_payload_exceeds_declared) {
            builder << '\n' << '\t'
                    << "Warning: PPPoE payload length is shorter than captured payload bytes; trailing bytes ignored.";
        }
        return builder.str();
    }

    if (details.has_vxlan) {
        builder << "Protocol: VXLAN\n"
                << '\t' << "Flags: " << format_hex_value(details.vxlan.flags, 2) << '\n'
                << '\t' << "I Flag: " << (details.vxlan.i_flag_set ? "Set" : "Not set") << '\n'
                << '\t' << "VNI: " << details.vxlan.vni;
        if (details.vxlan.has_inner_ethernet) {
            builder << '\n' << '\t' << "Inner Payload: Ethernet";
            if (details.inner_ethernet.available_header_bytes >= 14U) {
                if (details.inner_ethernet.uses_length_field) {
                    builder << '\n' << '\t' << "Inner Length: "
                            << details.inner_ethernet.ether_type << " bytes";
                } else {
                    builder << '\n' << '\t' << "Inner EtherType: "
                            << format_ether_type_value(details.inner_ethernet.ether_type);
                }
            }
        }
        if (details.inner_ethernet.header_truncated || details.vxlan.inner_ethernet_truncated) {
            builder << '\n' << '\t' << "Warning: Inner Ethernet header is truncated.";
        }
        return builder.str();
    }

    if (details.has_pbb && !details.has_arp && !details.has_ipv4 && !details.has_ipv6) {
        builder << "Protocol: PBB I-TAG";
        if (details.pbb.available_bytes >= 1U) {
            builder << '\n'
                    << '\t' << "Priority: " << static_cast<unsigned>(details.pbb.pcp) << '\n'
                    << '\t' << "Drop Eligible: " << (details.pbb.dei ? "1" : "0") << '\n'
                    << '\t' << "NCA: " << (details.pbb.nca ? "1" : "0") << '\n'
                    << '\t' << "Reserved 1: " << static_cast<unsigned>(pbb_reserved_1(details.pbb)) << '\n'
                    << '\t' << "Reserved 2: " << static_cast<unsigned>(pbb_reserved_2(details.pbb));
            if (details.pbb.available_bytes >= 4U) {
                builder << '\n' << '\t' << "I-SID: " << format_pbb_isid(details.pbb.isid);
            } else {
                builder << '\n' << '\t' << "Available Bytes: "
                        << static_cast<unsigned>(details.pbb.available_bytes) << " of 4";
            }
        }
        if (details.pbb.itag_truncated) {
            builder << '\n' << '\t' << "Warning: PBB I-TAG is truncated.";
        }
        if (details.has_inner_ethernet) {
            if (details.inner_ethernet.available_header_bytes >= 14U) {
                if (details.inner_ethernet.uses_length_field) {
                    builder << '\n' << '\t' << "Inner Length: "
                            << details.inner_ethernet.ether_type << " bytes";
                } else {
                    builder << '\n' << '\t' << "Inner EtherType: "
                            << format_ether_type_value(details.inner_ethernet.ether_type);
                }
            }
            if (details.inner_ethernet.header_truncated) {
                builder << '\n' << '\t' << "Warning: Inner Ethernet header is truncated.";
            }
        }
        return builder.str();
    }

    if (details.has_igmp) {
        builder << "Protocol: " << infer_igmp_version_text(details.igmp);
        if (details.igmp.type == kIgmpTypeMembershipQuery ||
            details.igmp.type == kIgmpTypeV1MembershipReport ||
            details.igmp.type == kIgmpTypeV2MembershipReport ||
            details.igmp.type == kIgmpTypeLeaveGroup) {
            builder << " (" << format_igmp_type_text(details.igmp) << ")";
        }
        builder << '\n'
                << '\t' << "Type: " << format_igmp_type_value(details.igmp) << '\n'
                << '\t' << "Max Resp Code: " << static_cast<unsigned>(details.igmp.max_resp_code) << '\n'
                << '\t' << "Checksum: " << format_hex16_value(details.igmp.checksum);
        if (details.igmp.has_group_address) {
            builder << '\n' << '\t' << "Group Address: " << format_ipv4_address(details.igmp.group_address);
        }
        if (details.igmp.is_v3_membership_report) {
            builder << '\n' << '\t' << "Group Record Count: " << details.igmp.group_record_count
                    << '\n' << '\t' << "Detailed IGMPv3 group-record parsing is deferred.";
        }
        if (details.has_ipv4) {
            builder << '\n' << '\t' << "Source: " << format_ipv4_address(details.ipv4.src_addr)
                    << '\n' << '\t' << "Destination: " << format_ipv4_address(details.ipv4.dst_addr);
        }
        if (details.igmp.header_truncated) {
            builder << '\n' << '\t' << "Warning: IGMP header is truncated.";
        }
        return builder.str();
    }

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

    if (details.has_ipv4 &&
        (details.ipv4.header_truncated || details.ipv4.invalid_header_length || details.ipv4.total_length_invalid)) {
        builder << "Protocol: IPv4\n"
                << '\t' << "Version: 4\n"
                << '\t' << "Internet Header Length: " << static_cast<unsigned>(details.ipv4.header_length_bytes)
                << " bytes (" << static_cast<unsigned>(details.ipv4.header_length_bytes / 4U) << ")";
        if (ipv4_field_available(details, 2U)) {
            builder << '\n' << '\t' << "Differentiated Services Field: "
                    << format_hex_value(details.ipv4.differentiated_services_field, 2);
        }
        if (ipv4_field_available(details, 4U)) {
            builder << '\n' << '\t' << "Total Length: " << details.ipv4.total_length << " bytes";
        }
        if (ipv4_field_available(details, 6U)) {
            builder << '\n' << '\t' << "Identification: " << format_hex16_value(details.ipv4.identification);
        }
        if (ipv4_field_available(details, 8U)) {
            builder << '\n' << '\t' << "Flags: " << format_hex_value(details.ipv4.flags, 1)
                    << '\n' << '\t' << "Fragment Offset: " << details.ipv4.fragment_offset;
        }
        if (ipv4_field_available(details, 9U)) {
            builder << '\n' << '\t' << "TTL: " << static_cast<unsigned>(details.ipv4.ttl);
        }
        if (ipv4_field_available(details, 10U)) {
            builder << '\n' << '\t' << "Protocol: " << format_protocol_summary_value_with_number(details.ipv4.protocol);
        }
        if (ipv4_field_available(details, 12U)) {
            builder << '\n' << '\t' << "Header Checksum: " << format_hex16_value(details.ipv4.header_checksum);
        }
        if (ipv4_field_available(details, 16U)) {
            builder << '\n' << '\t' << "Source Address: " << format_ipv4_address(details.ipv4.src_addr);
        }
        if (ipv4_field_available(details, 20U)) {
            builder << '\n' << '\t' << "Destination Address: " << format_ipv4_address(details.ipv4.dst_addr);
        }
        if (details.ipv4.header_truncated) {
            builder << '\n' << '\t' << "Warning: IPv4 header is truncated.";
        }
        if (details.ipv4.header_length_bytes > details.ipv4.available_header_bytes) {
            builder << '\n' << '\t' << "Warning: Captured IPv4 header bytes are fewer than the IHL.";
        }
        if (ipv4_field_available(details, 4U) && details.ipv4.total_length > details.ipv4.available_packet_bytes) {
            builder << '\n' << '\t' << "Warning: IPv4 total length exceeds captured packet bytes.";
        }
        return builder.str();
    }

    return std::nullopt;
}

}  // namespace pfl::session_detail
