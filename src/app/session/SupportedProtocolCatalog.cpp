#include "app/session/SupportedProtocolCatalog.h"

#include <algorithm>
#include <array>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace pfl::session_detail {

namespace {

constexpr std::array<SupportedProtocolCategoryDescriptor, 6> kCategoryDescriptors {{
    {SupportedProtocolCategory::link_and_encapsulation, "link_and_encapsulation", "Link & Encapsulation"},
    {SupportedProtocolCategory::network, "network", "Network"},
    {SupportedProtocolCategory::transport, "transport", "Transport"},
    {SupportedProtocolCategory::tunnels_and_overlays, "tunnels_and_overlays", "Tunnels & Overlays"},
    {SupportedProtocolCategory::security, "security", "Security"},
    {SupportedProtocolCategory::application, "application", "Application"},
}};

constexpr std::array<SupportedProtocolStatusDescriptor, 4> kStatusDescriptors {{
    {SupportedProtocolCapabilityStatus::yes, "yes", "Yes"},
    {SupportedProtocolCapabilityStatus::partial, "partial", "Partial"},
    {SupportedProtocolCapabilityStatus::no, "no", "No"},
    {SupportedProtocolCapabilityStatus::not_applicable, "not_applicable", "N/A"},
}};

constexpr std::array<SupportedProtocolCatalogRow, 35> kRows {{
    {"ethernet", "Ethernet II", SupportedProtocolCategory::link_and_encapsulation, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, "Ethernet II framing is decoded and shown in Packet Summary."},
    {"ieee_802_3_llc_snap", "IEEE 802.3 LLC/SNAP", SupportedProtocolCategory::link_and_encapsulation, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, "SNAP continuation is limited to supported IPv4, IPv6, and ARP payloads."},
    {"linux_sll_sll2", "Linux cooked capture (SLL/SLL2)", SupportedProtocolCategory::link_and_encapsulation, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, "Linux cooked capture headers are shown in Summary and supported inner decode continues."},
    {"vlan_qinq", "VLAN / QinQ", SupportedProtocolCategory::link_and_encapsulation, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, "Single-tag and QinQ stacks are decoded; stack depth is bounded."},
    {"macsec", "MACsec", SupportedProtocolCategory::link_and_encapsulation, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "SecTAG metadata is parsed, but protected payload remains opaque."},
    {"pbb_mac_in_mac", "PBB / MAC-in-MAC", SupportedProtocolCategory::link_and_encapsulation, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "I-TAG and supported inner Ethernet/IP continuations are handled conservatively."},
    {"mpls", "MPLS", SupportedProtocolCategory::link_and_encapsulation, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, "Label stacks are decoded; supported bottoms include IP and limited Ethernet pseudowire."},
    {"pppoe", "PPPoE", SupportedProtocolCategory::link_and_encapsulation, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "Session IP continuation is supported with basic Discovery and PPP control presentation."},
    {"arp", "ARP", SupportedProtocolCategory::network, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, "Structured request, reply, and probe information is available."},
    {"ipv4", "IPv4", SupportedProtocolCategory::network, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, "Header fields and bounded IPv4 options are presented."},
    {"ipv6", "IPv6", SupportedProtocolCategory::network, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, "Header fields are presented; upper-layer detail depends on the next protocol."},
    {"icmpv4", "ICMPv4", SupportedProtocolCategory::network, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "Common ICMPv4 messages are structured; quoted-packet recursion is not implemented."},
    {"icmpv6", "ICMPv6", SupportedProtocolCategory::network, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "Basic ICMPv6 details are shown; deeper NDP parsing is not implemented."},
    {"igmp", "IGMP", SupportedProtocolCategory::network, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "IGMPv1/v2 parsing is stronger; IGMPv3 support is currently more limited."},
    {"tcp", "TCP", SupportedProtocolCategory::transport, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::partial, "Headers and options are structured; plain Stream rows expose generic TCP payload data."},
    {"udp", "UDP", SupportedProtocolCategory::transport, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::partial, "Header parsing is structured; plain Stream rows expose generic UDP payload data."},
    {"sctp", "SCTP", SupportedProtocolCategory::transport, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::no, "Common header and first-chunk metadata are parsed; SCTP stream semantics are not implemented."},
    {"gre", "GRE", SupportedProtocolCategory::tunnels_and_overlays, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "GRE v0 supports selected direct IP, TEB, and MPLS continuation paths."},
    {"ip_in_ip", "IP-in-IP (IPv4/IPv6)", SupportedProtocolCategory::tunnels_and_overlays, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "Bounded IPv4/IPv6 encapsulation and supported inner transport continuation are handled."},
    {"vxlan", "VXLAN", SupportedProtocolCategory::tunnels_and_overlays, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "VXLAN/4789 supports bounded inner Ethernet/IP transport with VNI-aware flow identity."},
    {"geneve", "Geneve", SupportedProtocolCategory::tunnels_and_overlays, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "Version 0 Ethernet overlays on UDP/6081 support bounded options and inner transport."},
    {"gtpu", "GTP-U", SupportedProtocolCategory::tunnels_and_overlays, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "GTPv1-U T-PDU supports bounded inner IP transport with TEID-aware flow identity."},
    {"eoip", "MikroTik EoIP", SupportedProtocolCategory::tunnels_and_overlays, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "Strict MikroTik EoIP shapes support selected inner Ethernet/IP continuations."},
    {"ah", "IPsec AH", SupportedProtocolCategory::security, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "AH metadata and bounded inner continuation are supported; validation is not implemented."},
    {"esp", "IPsec ESP", SupportedProtocolCategory::security, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::not_applicable, "SPI and sequence metadata are shown; protected payload is not decrypted."},
    {"tls", "TLS", SupportedProtocolCategory::application, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::partial, "SNI from a segmented ClientHello may be unavailable at import and recovered after flow selection."},
    {"quic", "QUIC", SupportedProtocolCategory::application, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::partial, SupportedProtocolCapabilityStatus::partial, "Long-header QUIC is recognized; decryptable Initial traffic exposes richer TLS/CRYPTO detail."},
    {"http", "HTTP/1.x", SupportedProtocolCategory::application, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, "HTTP/1.x requests/responses and Host-derived Service information are supported."},
    {"dns", "DNS", SupportedProtocolCategory::application, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, "Structured DNS over UDP is shown; Stream does not reconstruct DNS transactions."},
    {"mdns", "mDNS", SupportedProtocolCategory::application, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::yes, "Multicast DNS and DNS-SD service information are parsed where available."},
    {"dhcp", "DHCPv4", SupportedProtocolCategory::application, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::no, SupportedProtocolCapabilityStatus::no, SupportedProtocolCapabilityStatus::no, "Recognized from BOOTP/DHCPv4 wire shape only; no dedicated message parser is exposed."},
    {"ssh", "SSH", SupportedProtocolCategory::application, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::no, SupportedProtocolCapabilityStatus::no, SupportedProtocolCapabilityStatus::no, "Recognized from SSH banner only; structured SSH message parsing is not implemented."},
    {"stun", "STUN", SupportedProtocolCategory::application, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::no, SupportedProtocolCapabilityStatus::no, SupportedProtocolCapabilityStatus::no, "Recognized from STUN message shape only; deeper STUN parsing is not implemented."},
    {"bittorrent", "BitTorrent", SupportedProtocolCategory::application, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::no, SupportedProtocolCapabilityStatus::no, SupportedProtocolCapabilityStatus::no, "Recognized from the canonical handshake only; deeper BitTorrent parsing is not implemented."},
    {"mail_protocols", "Mail protocols (SMTP / POP3 / IMAP)", SupportedProtocolCategory::application, SupportedProtocolCapabilityStatus::yes, SupportedProtocolCapabilityStatus::no, SupportedProtocolCapabilityStatus::no, SupportedProtocolCapabilityStatus::no, "Lightweight detection exists; structured mail-protocol parsing is not implemented."},
}};

std::string escape_markdown_table_cell(std::string_view value) {
    std::string escaped {};
    escaped.reserve(value.size());
    for (const char ch : value) {
        if (ch == '\\' || ch == '|') {
            escaped.push_back('\\');
        }
        if (ch == '\r' || ch == '\n') {
            escaped.push_back(' ');
            continue;
        }
        escaped.push_back(ch);
    }
    return escaped;
}

template <typename Range, typename Predicate>
const auto& find_descriptor(const Range& range, Predicate&& predicate, const char* error_text) {
    const auto it = std::find_if(range.begin(), range.end(), std::forward<Predicate>(predicate));
    if (it == range.end()) {
        throw std::logic_error(error_text);
    }
    return *it;
}

}  // namespace

std::span<const SupportedProtocolCategoryDescriptor> supported_protocol_category_descriptors() {
    return kCategoryDescriptors;
}

std::span<const SupportedProtocolStatusDescriptor> supported_protocol_status_descriptors() {
    return kStatusDescriptors;
}

std::span<const SupportedProtocolCatalogRow> supported_protocol_catalog_rows() {
    return kRows;
}

std::string_view supported_protocol_category_stable_id(const SupportedProtocolCategory category) {
    return find_descriptor(
        kCategoryDescriptors,
        [category](const auto& descriptor) { return descriptor.category == category; },
        "Missing supported protocol category descriptor."
    ).stable_id;
}

std::string_view supported_protocol_category_display_label(const SupportedProtocolCategory category) {
    return find_descriptor(
        kCategoryDescriptors,
        [category](const auto& descriptor) { return descriptor.category == category; },
        "Missing supported protocol category descriptor."
    ).display_label;
}

std::string_view supported_protocol_status_stable_id(const SupportedProtocolCapabilityStatus status) {
    return find_descriptor(
        kStatusDescriptors,
        [status](const auto& descriptor) { return descriptor.status == status; },
        "Missing supported protocol status descriptor."
    ).stable_id;
}

std::string_view supported_protocol_status_display_label(const SupportedProtocolCapabilityStatus status) {
    return find_descriptor(
        kStatusDescriptors,
        [status](const auto& descriptor) { return descriptor.status == status; },
        "Missing supported protocol status descriptor."
    ).display_label;
}

std::string render_supported_protocol_catalog_markdown_table() {
    return render_supported_protocol_catalog_markdown_table(kRows);
}

std::string render_supported_protocol_catalog_markdown_table(
    const std::span<const SupportedProtocolCatalogRow> rows
) {
    std::ostringstream out {};
    out << "| Category | Protocol | Recognition | Service | Packet Summary | Stream | Notes |\n"
        << "| --- | --- | --- | --- | --- | --- | --- |\n";

    for (const auto& row : rows) {
        out << "| " << escape_markdown_table_cell(supported_protocol_category_display_label(row.category))
            << " | " << escape_markdown_table_cell(row.protocol)
            << " | " << escape_markdown_table_cell(supported_protocol_status_display_label(row.recognition))
            << " | " << escape_markdown_table_cell(supported_protocol_status_display_label(row.service))
            << " | " << escape_markdown_table_cell(supported_protocol_status_display_label(row.packet_summary))
            << " | " << escape_markdown_table_cell(supported_protocol_status_display_label(row.stream))
            << " | " << escape_markdown_table_cell(row.notes)
            << " |\n";
    }

    return out.str();
}

}  // namespace pfl::session_detail
