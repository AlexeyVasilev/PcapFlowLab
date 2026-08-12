#include "app/session/SelectedPacketBytePresentation.h"

#include <algorithm>
#include <sstream>

#include "core/io/LinkType.h"
#include "core/services/DnsPacketProtocolAnalyzer.h"
#include "core/services/HexDumpService.h"
#include "core/services/TlsInspectionParser.h"

namespace pfl::session_detail {

namespace {

constexpr std::size_t kMaxViewOccurrence = 0xFFU;
constexpr std::uint32_t kLinuxSllHeaderSize = 16U;
constexpr std::uint32_t kLinuxSll2HeaderSize = 20U;
constexpr std::uint32_t kLlcHeaderSize = 3U;
constexpr std::uint32_t kSnapHeaderSize = 5U;
constexpr std::uint32_t kPbbHeaderSize = 4U;

constexpr SelectedPacketByteOwnerId kCapturedPacketOwnerId {
    .kind = SelectedPacketByteOwnerKind::captured_packet,
    .occurrence = 0U,
};

struct PayloadBranchResult {
    std::optional<SelectedPacketByteViewId> parent_id {};
    std::optional<PacketByteRange> child_payload_range {};
};

void append_quic_tls_handshake_views(
    SelectedPacketBytePresentation& presentation,
    QuicPresentationResult& quic_presentation,
    const QuicPresentationPacket& quic_packet,
    std::uint8_t packet_scope,
    const SelectedPacketByteOwnerId& owner_id,
    std::uint32_t owner_captured_length
);

bool packet_byte_range_equals(const PacketByteRange& lhs, const PacketByteRange& rhs) noexcept {
    return lhs.offset == rhs.offset &&
        lhs.declared_length == rhs.declared_length &&
        lhs.captured_length == rhs.captured_length &&
        lhs.truncated == rhs.truncated;
}

bool optional_packet_byte_range_equals(
    const std::optional<PacketByteRange>& lhs,
    const std::optional<PacketByteRange>& rhs
) noexcept {
    if (lhs.has_value() != rhs.has_value()) {
        return false;
    }
    return !lhs.has_value() || packet_byte_range_equals(*lhs, *rhs);
}

bool equivalent_view(
    const SelectedPacketByteViewDescriptor& existing,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewRole role,
    const SelectedPacketByteAssemblyKind assembly_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint32_t offset,
    const std::optional<std::uint32_t>& declared_length,
    const std::uint32_t captured_length,
    const bool truncated,
    const std::optional<PacketByteRange>& payload_range,
    const std::optional<std::uint32_t>& contributing_unit_count,
    const std::optional<SelectedPacketByteContributionUnitKind>& contributing_unit_kind,
    const std::optional<std::uint64_t>& quic_crypto_stream_offset,
    const std::optional<TlsRecordContentTypeKind>& tls_record_content_type_kind,
    const std::optional<std::uint8_t>& tls_record_content_type,
    const std::optional<TlsHandshakeKind>& tls_handshake_kind,
    const std::optional<std::uint8_t>& tls_handshake_type
) noexcept {
    return existing.parent_id == parent_id &&
        existing.owner_id == owner_id &&
        existing.owner_kind == owner_kind &&
        existing.role == role &&
        existing.assembly_kind == assembly_kind &&
        existing.id.kind == kind &&
        existing.id.scope == scope &&
        existing.offset == offset &&
        existing.declared_length == declared_length &&
        existing.captured_length == captured_length &&
        existing.truncated == truncated &&
        optional_packet_byte_range_equals(existing.payload_range, payload_range) &&
        existing.contributing_unit_count == contributing_unit_count &&
        existing.contributing_unit_kind == contributing_unit_kind &&
        existing.quic_crypto_stream_offset == quic_crypto_stream_offset &&
        existing.tls_record_content_type_kind == tls_record_content_type_kind &&
        existing.tls_record_content_type == tls_record_content_type &&
        existing.tls_handshake_kind == tls_handshake_kind &&
        existing.tls_handshake_type == tls_handshake_type;
}

std::optional<std::uint32_t> narrow_u32(const std::size_t value) noexcept {
    if (value > 0xFFFFFFFFU) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(value);
}

std::string tls_handshake_type_label(
    const TlsHandshakeKind kind,
    const std::optional<std::uint8_t> handshake_type
) {
    switch (kind) {
    case TlsHandshakeKind::client_hello:
        return "ClientHello";
    case TlsHandshakeKind::server_hello:
        return "ServerHello";
    case TlsHandshakeKind::new_session_ticket:
        return "NewSessionTicket";
    case TlsHandshakeKind::encrypted_extensions:
        return "EncryptedExtensions";
    case TlsHandshakeKind::certificate:
        return "Certificate";
    case TlsHandshakeKind::server_key_exchange:
        return "ServerKeyExchange";
    case TlsHandshakeKind::certificate_request:
        return "CertificateRequest";
    case TlsHandshakeKind::server_hello_done:
        return "ServerHelloDone";
    case TlsHandshakeKind::certificate_verify:
        return "CertificateVerify";
    case TlsHandshakeKind::client_key_exchange:
        return "ClientKeyExchange";
    case TlsHandshakeKind::finished:
        return "Finished";
    case TlsHandshakeKind::unknown:
        static_cast<void>(handshake_type);
        return "Unknown";
    }
    return "Unknown";
}

std::string owner_kind_key(const SelectedPacketByteOwnerKind kind) {
    switch (kind) {
    case SelectedPacketByteOwnerKind::captured_packet:
        return "captured_packet";
    case SelectedPacketByteOwnerKind::quic_initial_plaintext:
        return "quic_initial_plaintext";
    case SelectedPacketByteOwnerKind::quic_crypto_prefix:
        return "quic_crypto_prefix";
    case SelectedPacketByteOwnerKind::tls_reconstructed_record:
        return "tls_reconstructed_record";
    default:
        return "unknown";
    }
}

std::string view_role_key(const SelectedPacketByteViewRole role) {
    switch (role) {
    case SelectedPacketByteViewRole::protocol_unit:
        return "protocol_unit";
    case SelectedPacketByteViewRole::payload_fallback:
        return "payload_fallback";
    case SelectedPacketByteViewRole::derived_value:
        return "derived_value";
    default:
        return "unknown";
    }
}

std::string assembly_kind_key(const SelectedPacketByteAssemblyKind kind) {
    switch (kind) {
    case SelectedPacketByteAssemblyKind::packet_local:
        return "packet_local";
    case SelectedPacketByteAssemblyKind::reassembled:
        return "reassembled";
    default:
        return "packet_local";
    }
}

std::string contribution_unit_kind_key(const SelectedPacketByteContributionUnitKind kind) {
    switch (kind) {
    case SelectedPacketByteContributionUnitKind::tcp_segment:
        return "tcp_segment";
    case SelectedPacketByteContributionUnitKind::quic_crypto_frame:
        return "quic_crypto_frame";
    default:
        return "tcp_segment";
    }
}

std::string view_kind_key(const SelectedPacketByteViewKind kind) {
    switch (kind) {
    case SelectedPacketByteViewKind::frame:
        return "frame";
    case SelectedPacketByteViewKind::linux_sll:
        return "linux_sll";
    case SelectedPacketByteViewKind::linux_sll2:
        return "linux_sll2";
    case SelectedPacketByteViewKind::ethernet_payload:
        return "ethernet";
    case SelectedPacketByteViewKind::ieee8023_payload:
        return "ieee8023";
    case SelectedPacketByteViewKind::vlan_payload:
        return "vlan";
    case SelectedPacketByteViewKind::llc:
        return "llc";
    case SelectedPacketByteViewKind::snap:
        return "snap";
    case SelectedPacketByteViewKind::mpls_payload:
        return "mpls";
    case SelectedPacketByteViewKind::pbb:
        return "pbb";
    case SelectedPacketByteViewKind::pppoe:
        return "pppoe";
    case SelectedPacketByteViewKind::ppp:
        return "ppp";
    case SelectedPacketByteViewKind::arp:
        return "arp";
    case SelectedPacketByteViewKind::ipv4_payload:
        return "ipv4";
    case SelectedPacketByteViewKind::ipv6_payload:
        return "ipv6";
    case SelectedPacketByteViewKind::tcp_payload:
        return "tcp";
    case SelectedPacketByteViewKind::udp_payload:
        return "udp";
    case SelectedPacketByteViewKind::sctp_payload:
        return "sctp";
    case SelectedPacketByteViewKind::icmp:
        return "icmp";
    case SelectedPacketByteViewKind::icmpv6:
        return "icmpv6";
    case SelectedPacketByteViewKind::igmp:
        return "igmp";
    case SelectedPacketByteViewKind::data:
        return "data";
    case SelectedPacketByteViewKind::effective_transport_payload:
        return "effective_transport_payload";
    case SelectedPacketByteViewKind::inner_ethernet_payload:
        return "inner_ethernet";
    case SelectedPacketByteViewKind::inner_ieee8023_payload:
        return "inner_ieee8023";
    case SelectedPacketByteViewKind::inner_vlan_payload:
        return "inner_vlan";
    case SelectedPacketByteViewKind::inner_ipv4_payload:
        return "inner_ipv4";
    case SelectedPacketByteViewKind::inner_ipv6_payload:
        return "inner_ipv6";
    case SelectedPacketByteViewKind::inner_tcp_payload:
        return "inner_tcp";
    case SelectedPacketByteViewKind::inner_udp_payload:
        return "inner_udp";
    case SelectedPacketByteViewKind::inner_sctp_payload:
        return "inner_sctp";
    case SelectedPacketByteViewKind::gre_payload:
        return "gre";
    case SelectedPacketByteViewKind::eoip_payload:
        return "eoip";
    case SelectedPacketByteViewKind::vxlan_payload:
        return "vxlan";
    case SelectedPacketByteViewKind::geneve_payload:
        return "geneve";
    case SelectedPacketByteViewKind::gtpu_payload:
        return "gtpu";
    case SelectedPacketByteViewKind::ah_payload:
        return "ah";
    case SelectedPacketByteViewKind::esp:
        return "esp";
    case SelectedPacketByteViewKind::esp_protected_payload:
        return "esp_protected_payload";
    case SelectedPacketByteViewKind::quic_initial_packet:
        return "quic_initial_packet";
    case SelectedPacketByteViewKind::quic_zero_rtt_packet:
        return "quic_zero_rtt_packet";
    case SelectedPacketByteViewKind::quic_handshake_packet:
        return "quic_handshake_packet";
    case SelectedPacketByteViewKind::quic_retry_packet:
        return "quic_retry_packet";
    case SelectedPacketByteViewKind::quic_version_negotiation_packet:
        return "quic_version_negotiation_packet";
    case SelectedPacketByteViewKind::quic_protected_packet:
        return "quic_protected_packet";
    case SelectedPacketByteViewKind::quic_initial_protected_payload:
        return "quic_initial_protected_payload";
    case SelectedPacketByteViewKind::quic_initial_plaintext:
        return "quic_initial_plaintext";
    case SelectedPacketByteViewKind::quic_frame:
        return "quic_frame";
    case SelectedPacketByteViewKind::quic_crypto_data:
        return "quic_crypto_data";
    case SelectedPacketByteViewKind::quic_crypto_stream:
        return "quic_crypto_stream";
    case SelectedPacketByteViewKind::dns_message:
        return "dns";
    case SelectedPacketByteViewKind::tls_record:
        return "tls_record";
    case SelectedPacketByteViewKind::tls_handshake:
        return "tls_handshake";
    default:
        return "unknown";
    }
}

std::optional<SelectedPacketByteViewKind> parse_view_kind_key(const std::string_view key) {
    constexpr std::pair<std::string_view, SelectedPacketByteViewKind> kKinds[] {
        {"frame", SelectedPacketByteViewKind::frame},
        {"linux_sll", SelectedPacketByteViewKind::linux_sll},
        {"linux_sll2", SelectedPacketByteViewKind::linux_sll2},
        {"ethernet", SelectedPacketByteViewKind::ethernet_payload},
        {"ieee8023", SelectedPacketByteViewKind::ieee8023_payload},
        {"vlan", SelectedPacketByteViewKind::vlan_payload},
        {"llc", SelectedPacketByteViewKind::llc},
        {"snap", SelectedPacketByteViewKind::snap},
        {"mpls", SelectedPacketByteViewKind::mpls_payload},
        {"pbb", SelectedPacketByteViewKind::pbb},
        {"pppoe", SelectedPacketByteViewKind::pppoe},
        {"ppp", SelectedPacketByteViewKind::ppp},
        {"arp", SelectedPacketByteViewKind::arp},
        {"ipv4", SelectedPacketByteViewKind::ipv4_payload},
        {"ipv6", SelectedPacketByteViewKind::ipv6_payload},
        {"tcp", SelectedPacketByteViewKind::tcp_payload},
        {"udp", SelectedPacketByteViewKind::udp_payload},
        {"sctp", SelectedPacketByteViewKind::sctp_payload},
        {"icmp", SelectedPacketByteViewKind::icmp},
        {"icmpv6", SelectedPacketByteViewKind::icmpv6},
        {"igmp", SelectedPacketByteViewKind::igmp},
        {"data", SelectedPacketByteViewKind::data},
        {"effective_transport_payload", SelectedPacketByteViewKind::effective_transport_payload},
        {"inner_ethernet", SelectedPacketByteViewKind::inner_ethernet_payload},
        {"inner_ieee8023", SelectedPacketByteViewKind::inner_ieee8023_payload},
        {"inner_vlan", SelectedPacketByteViewKind::inner_vlan_payload},
        {"inner_ipv4", SelectedPacketByteViewKind::inner_ipv4_payload},
        {"inner_ipv6", SelectedPacketByteViewKind::inner_ipv6_payload},
        {"inner_tcp", SelectedPacketByteViewKind::inner_tcp_payload},
        {"inner_udp", SelectedPacketByteViewKind::inner_udp_payload},
        {"inner_sctp", SelectedPacketByteViewKind::inner_sctp_payload},
        {"gre", SelectedPacketByteViewKind::gre_payload},
        {"gre_payload", SelectedPacketByteViewKind::gre_payload},
        {"eoip", SelectedPacketByteViewKind::eoip_payload},
        {"eoip_payload", SelectedPacketByteViewKind::eoip_payload},
        {"vxlan", SelectedPacketByteViewKind::vxlan_payload},
        {"vxlan_payload", SelectedPacketByteViewKind::vxlan_payload},
        {"geneve", SelectedPacketByteViewKind::geneve_payload},
        {"geneve_payload", SelectedPacketByteViewKind::geneve_payload},
        {"gtpu", SelectedPacketByteViewKind::gtpu_payload},
        {"gtpu_payload", SelectedPacketByteViewKind::gtpu_payload},
        {"ah", SelectedPacketByteViewKind::ah_payload},
        {"ah_payload", SelectedPacketByteViewKind::ah_payload},
        {"esp", SelectedPacketByteViewKind::esp},
        {"esp_protected_payload", SelectedPacketByteViewKind::esp_protected_payload},
        {"quic_initial_packet", SelectedPacketByteViewKind::quic_initial_packet},
        {"quic_zero_rtt_packet", SelectedPacketByteViewKind::quic_zero_rtt_packet},
        {"quic_handshake_packet", SelectedPacketByteViewKind::quic_handshake_packet},
        {"quic_retry_packet", SelectedPacketByteViewKind::quic_retry_packet},
        {"quic_version_negotiation_packet", SelectedPacketByteViewKind::quic_version_negotiation_packet},
        {"quic_protected_packet", SelectedPacketByteViewKind::quic_protected_packet},
        {"quic_initial_protected_payload", SelectedPacketByteViewKind::quic_initial_protected_payload},
        {"quic_initial_plaintext", SelectedPacketByteViewKind::quic_initial_plaintext},
        {"quic_frame", SelectedPacketByteViewKind::quic_frame},
        {"quic_crypto_data", SelectedPacketByteViewKind::quic_crypto_data},
        {"quic_crypto_stream", SelectedPacketByteViewKind::quic_crypto_stream},
        {"dns", SelectedPacketByteViewKind::dns_message},
        {"tls_record", SelectedPacketByteViewKind::tls_record},
        {"tls_handshake", SelectedPacketByteViewKind::tls_handshake},
    };

    const auto it = std::find_if(
        std::begin(kKinds),
        std::end(kKinds),
        [&](const auto& entry) {
            return entry.first == key;
        }
    );
    if (it == std::end(kKinds)) {
        return std::nullopt;
    }
    return it->second;
}

std::string base_view_label(const SelectedPacketByteViewDescriptor& descriptor) {
    const auto is_complete =
        !descriptor.truncated &&
        (!descriptor.declared_length.has_value() || descriptor.captured_length == *descriptor.declared_length);

    switch (descriptor.id.kind) {
    case SelectedPacketByteViewKind::frame:
        return "Captured Packet";
    case SelectedPacketByteViewKind::linux_sll:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Linux cooked capture v1"
            : "Linux SLL Payload";
    case SelectedPacketByteViewKind::linux_sll2:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Linux cooked capture v2"
            : "Linux SLL2 Payload";
    case SelectedPacketByteViewKind::ethernet_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Ethernet II Frame"
            : "Ethernet Payload";
    case SelectedPacketByteViewKind::ieee8023_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "IEEE 802.3 Frame"
            : "IEEE 802.3 Payload";
    case SelectedPacketByteViewKind::vlan_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "802.1Q Encapsulation"
            : "VLAN Payload";
    case SelectedPacketByteViewKind::llc:
        return "LLC PDU";
    case SelectedPacketByteViewKind::snap:
        return "SNAP PDU";
    case SelectedPacketByteViewKind::mpls_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "MPLS Label Stack and Payload"
            : "MPLS Payload";
    case SelectedPacketByteViewKind::pbb:
        return "PBB Packet";
    case SelectedPacketByteViewKind::pppoe:
        return "PPPoE Packet";
    case SelectedPacketByteViewKind::ppp:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "PPP Packet"
            : "PPP Payload";
    case SelectedPacketByteViewKind::arp:
        return "ARP Packet";
    case SelectedPacketByteViewKind::ipv4_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "IPv4 Packet"
            : "IPv4 Payload";
    case SelectedPacketByteViewKind::ipv6_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "IPv6 Packet"
            : "IPv6 Payload";
    case SelectedPacketByteViewKind::tcp_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "TCP Segment"
            : "TCP Payload";
    case SelectedPacketByteViewKind::udp_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "UDP Datagram"
            : "UDP Payload";
    case SelectedPacketByteViewKind::sctp_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "SCTP Packet"
            : "SCTP Payload";
    case SelectedPacketByteViewKind::icmp:
        return "ICMP Message";
    case SelectedPacketByteViewKind::icmpv6:
        return "ICMPv6 Message";
    case SelectedPacketByteViewKind::igmp:
        return "IGMP Message";
    case SelectedPacketByteViewKind::data:
        return "Data";
    case SelectedPacketByteViewKind::effective_transport_payload:
        return "Transport Payload";
    case SelectedPacketByteViewKind::inner_ethernet_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Inner Ethernet II Frame"
            : "Inner Ethernet Payload";
    case SelectedPacketByteViewKind::inner_ieee8023_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Inner IEEE 802.3 Frame"
            : "Inner IEEE 802.3 Payload";
    case SelectedPacketByteViewKind::inner_vlan_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Inner 802.1Q Encapsulation"
            : "Inner VLAN Payload";
    case SelectedPacketByteViewKind::inner_ipv4_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Inner IPv4 Packet"
            : "Inner IPv4 Payload";
    case SelectedPacketByteViewKind::inner_ipv6_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Inner IPv6 Packet"
            : "Inner IPv6 Payload";
    case SelectedPacketByteViewKind::inner_tcp_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Inner TCP Segment"
            : "Inner TCP Payload";
    case SelectedPacketByteViewKind::inner_udp_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Inner UDP Datagram"
            : "Inner UDP Payload";
    case SelectedPacketByteViewKind::inner_sctp_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Inner SCTP Packet"
            : "Inner SCTP Payload";
    case SelectedPacketByteViewKind::gre_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "GRE Packet"
            : "GRE Payload";
    case SelectedPacketByteViewKind::eoip_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "EoIP Packet"
            : "EoIP Payload";
    case SelectedPacketByteViewKind::vxlan_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "VXLAN Packet"
            : "VXLAN Payload";
    case SelectedPacketByteViewKind::geneve_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "Geneve Packet"
            : "Geneve Payload";
    case SelectedPacketByteViewKind::gtpu_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "GTP-U Message"
            : "GTP-U Payload";
    case SelectedPacketByteViewKind::ah_payload:
        return descriptor.role == SelectedPacketByteViewRole::protocol_unit
            ? "AH Packet"
            : "AH Payload";
    case SelectedPacketByteViewKind::esp:
        return "ESP Packet";
    case SelectedPacketByteViewKind::esp_protected_payload:
        return "ESP Protected Payload";
    case SelectedPacketByteViewKind::quic_initial_packet:
        return "QUIC Initial Packet";
    case SelectedPacketByteViewKind::quic_zero_rtt_packet:
        return "QUIC 0-RTT Packet";
    case SelectedPacketByteViewKind::quic_handshake_packet:
        return "QUIC Handshake Packet";
    case SelectedPacketByteViewKind::quic_retry_packet:
        return "QUIC Retry Packet";
    case SelectedPacketByteViewKind::quic_version_negotiation_packet:
        return "QUIC Version Negotiation Packet";
    case SelectedPacketByteViewKind::quic_protected_packet:
        return "QUIC Protected Packet";
    case SelectedPacketByteViewKind::quic_initial_protected_payload:
        return "QUIC Initial Protected Payload";
    case SelectedPacketByteViewKind::quic_initial_plaintext:
        return "QUIC Initial Decrypted Payload";
    case SelectedPacketByteViewKind::quic_frame:
        return descriptor.quic_crypto_stream_offset.has_value() ? "CRYPTO Frame" : "QUIC Frame";
    case SelectedPacketByteViewKind::quic_crypto_data:
        return "CRYPTO Frame Data";
    case SelectedPacketByteViewKind::quic_crypto_stream:
        return "QUIC CRYPTO Stream";
    case SelectedPacketByteViewKind::dns_message:
        return "DNS Message";
    case SelectedPacketByteViewKind::tls_record:
        if (!is_complete) {
            return "TLS Record Fragment";
        }
        switch (descriptor.tls_record_content_type_kind.value_or(TlsRecordContentTypeKind::unknown)) {
        case TlsRecordContentTypeKind::handshake:
            return "TLS Handshake Record";
        case TlsRecordContentTypeKind::application_data:
            return "TLS Application Data Record";
        case TlsRecordContentTypeKind::alert:
            return "TLS Alert Record";
        case TlsRecordContentTypeKind::change_cipher_spec:
            return "TLS Change Cipher Spec Record";
        case TlsRecordContentTypeKind::unknown:
        default:
            return "TLS Record";
        }
    case SelectedPacketByteViewKind::tls_handshake: {
        auto label = std::string {"TLS Handshake Message"};
        const auto handshake_kind = descriptor.tls_handshake_kind.value_or(TlsHandshakeKind::unknown);
        const auto handshake_type = descriptor.tls_handshake_type;
        const auto handshake_title = tls_handshake_type_label(handshake_kind, handshake_type);
        if (!handshake_title.empty() && handshake_title != "Unknown") {
            label += ", " + handshake_title;
        }
        return label;
    }
    default:
        return "Bytes";
    }
}

std::string view_label(const SelectedPacketByteViewDescriptor& descriptor) {
    auto label = base_view_label(descriptor);
    if (descriptor.id.occurrence > 0U) {
        label += " #" + std::to_string(static_cast<std::size_t>(descriptor.id.occurrence) + 1U);
    }
    if (descriptor.assembly_kind == SelectedPacketByteAssemblyKind::reassembled) {
        label += " (Reassembled)";
    }
    return label;
}

std::string range_state(
    const std::optional<std::uint32_t>& declared_length,
    const std::uint32_t captured_length,
    const bool truncated
) {
    if (truncated) {
        return "truncated";
    }
    if (declared_length.has_value() && captured_length < *declared_length) {
        return "partial";
    }
    return "complete";
}

std::string descriptor_state(const SelectedPacketByteViewDescriptor& descriptor) {
    return range_state(descriptor.declared_length, descriptor.captured_length, descriptor.truncated);
}

std::optional<std::string> payload_state(const SelectedPacketByteViewDescriptor& descriptor) {
    if (!descriptor.payload_range.has_value()) {
        return std::nullopt;
    }
    return range_state(
        descriptor.payload_range->declared_length,
        descriptor.payload_range->captured_length,
        descriptor.payload_range->truncated
    );
}

std::optional<PacketByteRange> shift_payload_range(
    const PacketByteRange& range,
    const std::uint32_t delta
) {
    if (range.captured_length <= delta) {
        return std::nullopt;
    }

    std::optional<std::uint32_t> shifted_declared_length {};
    if (range.declared_length.has_value()) {
        if (*range.declared_length <= delta) {
            return std::nullopt;
        }
        shifted_declared_length = *range.declared_length - delta;
    }

    return PacketByteRange {
        .offset = range.offset + delta,
        .declared_length = shifted_declared_length,
        .captured_length = range.captured_length - delta,
        .truncated = range.truncated ||
            (shifted_declared_length.has_value() && (range.captured_length - delta) < *shifted_declared_length),
    };
}

std::optional<PacketByteRange> build_unit_range_from_payload(
    const std::uint32_t unit_offset,
    const PacketByteRange& payload_range
) {
    if (payload_range.offset < unit_offset) {
        return std::nullopt;
    }

    const auto header_length = payload_range.offset - unit_offset;
    const auto captured_length = header_length + payload_range.captured_length;
    std::optional<std::uint32_t> declared_length {};
    if (payload_range.declared_length.has_value()) {
        declared_length = header_length + *payload_range.declared_length;
    }

    return PacketByteRange {
        .offset = unit_offset,
        .declared_length = declared_length,
        .captured_length = captured_length,
        .truncated = payload_range.truncated ||
            (declared_length.has_value() && captured_length < *declared_length),
    };
}

std::optional<SelectedPacketByteOwnerId> append_derived_owner(
    std::vector<SelectedPacketByteDerivedOwner>& owners,
    const SelectedPacketByteOwnerKind kind,
    const std::size_t quic_packet_index,
    std::vector<std::uint8_t> bytes
) {
    if (bytes.empty()) {
        return std::nullopt;
    }

    const auto occurrence_count = static_cast<std::size_t>(std::count_if(
        owners.begin(),
        owners.end(),
        [&](const SelectedPacketByteDerivedOwner& owner) {
            return owner.id.kind == kind;
        }
    ));
    if (occurrence_count > kMaxViewOccurrence) {
        return std::nullopt;
    }

    const SelectedPacketByteOwnerId id {
        .kind = kind,
        .occurrence = static_cast<std::uint8_t>(occurrence_count),
    };
    owners.push_back(SelectedPacketByteDerivedOwner {
        .id = id,
        .quic_packet_index = quic_packet_index,
        .bytes = std::move(bytes),
    });
    return id;
}

SelectedPacketByteViewKind quic_packet_view_kind(const QuicPresentationShellType shell_type) noexcept {
    switch (shell_type) {
    case QuicPresentationShellType::initial:
        return SelectedPacketByteViewKind::quic_initial_packet;
    case QuicPresentationShellType::zero_rtt:
        return SelectedPacketByteViewKind::quic_zero_rtt_packet;
    case QuicPresentationShellType::handshake:
        return SelectedPacketByteViewKind::quic_handshake_packet;
    case QuicPresentationShellType::retry:
        return SelectedPacketByteViewKind::quic_retry_packet;
    case QuicPresentationShellType::version_negotiation:
        return SelectedPacketByteViewKind::quic_version_negotiation_packet;
    case QuicPresentationShellType::protected_payload:
    default:
        return SelectedPacketByteViewKind::quic_protected_packet;
    }
}

std::optional<SelectedPacketByteViewId> append_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewRole role,
    const SelectedPacketByteAssemblyKind assembly_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint32_t owner_byte_length,
    const std::uint32_t offset,
    const std::optional<std::uint32_t>& declared_length,
    const std::uint32_t captured_length,
    const bool truncated,
    const std::optional<PacketByteRange>& payload_range = std::nullopt,
    const std::optional<std::uint32_t>& contributing_unit_count = std::nullopt,
    const std::optional<SelectedPacketByteContributionUnitKind>& contributing_unit_kind = std::nullopt,
    const std::optional<std::uint64_t>& quic_crypto_stream_offset = std::nullopt,
    const std::optional<TlsRecordContentTypeKind>& tls_record_content_type_kind = std::nullopt,
    const std::optional<std::uint8_t>& tls_record_content_type = std::nullopt,
    const std::optional<TlsHandshakeKind>& tls_handshake_kind = std::nullopt,
    const std::optional<std::uint8_t>& tls_handshake_type = std::nullopt
) {
    if (captured_length == 0U ||
        offset >= owner_byte_length ||
        captured_length > owner_byte_length - offset) {
        return std::nullopt;
    }

    if (std::any_of(views.begin(), views.end(), [&](const SelectedPacketByteViewDescriptor& existing) {
            return equivalent_view(
                existing,
                parent_id,
                owner_id,
                owner_kind,
                role,
                assembly_kind,
                kind,
                scope,
                offset,
                declared_length,
                captured_length,
                truncated,
                payload_range,
                contributing_unit_count,
                contributing_unit_kind,
                quic_crypto_stream_offset,
                tls_record_content_type_kind,
                tls_record_content_type,
                tls_handshake_kind,
                tls_handshake_type
            );
        })) {
        return std::nullopt;
    }

    const auto occurrence_count = static_cast<std::size_t>(std::count_if(
        views.begin(),
        views.end(),
        [&](const SelectedPacketByteViewDescriptor& existing) {
            return existing.id.kind == kind && existing.id.scope == scope;
        }
    ));
    if (occurrence_count > kMaxViewOccurrence) {
        return std::nullopt;
    }

    const SelectedPacketByteViewId id {
        .kind = kind,
        .scope = scope,
        .occurrence = static_cast<std::uint8_t>(occurrence_count),
    };
    views.push_back(SelectedPacketByteViewDescriptor {
        .id = id,
        .parent_id = parent_id,
        .owner_id = owner_id,
        .owner_kind = owner_kind,
        .role = role,
        .assembly_kind = assembly_kind,
        .offset = offset,
        .declared_length = declared_length,
        .captured_length = captured_length,
        .truncated = truncated,
        .payload_range = payload_range,
        .contributing_unit_count = contributing_unit_count,
        .contributing_unit_kind = contributing_unit_kind,
        .quic_crypto_stream_offset = quic_crypto_stream_offset,
        .tls_record_content_type_kind = tls_record_content_type_kind,
        .tls_record_content_type = tls_record_content_type,
        .tls_handshake_kind = tls_handshake_kind,
        .tls_handshake_type = tls_handshake_type,
    });
    return id;
}

std::optional<SelectedPacketByteViewId> append_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint32_t owner_byte_length,
    const std::uint32_t offset,
    const std::optional<std::uint32_t>& declared_length,
    const std::uint32_t captured_length,
    const bool truncated,
    const std::optional<std::uint64_t>& quic_crypto_stream_offset = std::nullopt
) {
    return append_view(
        views,
        parent_id,
        owner_id,
        owner_kind,
        SelectedPacketByteViewRole::protocol_unit,
        SelectedPacketByteAssemblyKind::packet_local,
        kind,
        scope,
        owner_byte_length,
        offset,
        declared_length,
        captured_length,
        truncated,
        std::nullopt,
        quic_crypto_stream_offset
    );
}

std::optional<SelectedPacketByteViewId> append_protocol_unit_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewRole role,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& unit_range,
    const std::optional<PacketByteRange>& payload_range = std::nullopt,
    const std::optional<std::uint64_t>& quic_crypto_stream_offset = std::nullopt
) {
    return append_view(
        views,
        parent_id,
        owner_id,
        owner_kind,
        role,
        SelectedPacketByteAssemblyKind::packet_local,
        kind,
        scope,
        owner_captured_length,
        unit_range.offset,
        unit_range.declared_length,
        unit_range.captured_length,
        unit_range.truncated,
        payload_range,
        quic_crypto_stream_offset
    );
}

std::optional<SelectedPacketByteViewId> append_protocol_unit_from_payload_range(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint32_t owner_captured_length,
    const std::uint32_t unit_offset,
    const PacketByteRange& payload_range
) {
    const auto unit_range = build_unit_range_from_payload(unit_offset, payload_range);
    if (!unit_range.has_value()) {
        return std::nullopt;
    }

    return append_protocol_unit_view(
        views,
        parent_id,
        owner_id,
        owner_kind,
        SelectedPacketByteViewRole::protocol_unit,
        kind,
        scope,
        owner_captured_length,
        *unit_range,
        payload_range
    );
}

bool is_complete_captured_packet_root(
    const SelectedPacketByteViewDescriptor& view,
    const std::uint32_t owner_captured_length
) noexcept {
    return !view.parent_id.has_value() &&
        view.owner_kind == SelectedPacketByteOwnerKind::captured_packet &&
        view.role == SelectedPacketByteViewRole::protocol_unit &&
        view.offset == 0U &&
        view.captured_length == owner_captured_length;
}

void ensure_captured_packet_root_when_needed(SelectedPacketBytePresentation& presentation, const PacketRef& packet) {
    const auto already_has_complete_root = std::any_of(
        presentation.views.begin(),
        presentation.views.end(),
        [&](const SelectedPacketByteViewDescriptor& view) {
            if (view.id.kind == SelectedPacketByteViewKind::linux_sll ||
                view.id.kind == SelectedPacketByteViewKind::linux_sll2) {
                return false;
            }
            return is_complete_captured_packet_root(view, presentation.owner_captured_length);
        }
    );
    if (already_has_complete_root) {
        return;
    }

    const auto frame_id = append_view(
        presentation.views,
        std::nullopt,
        kCapturedPacketOwnerId,
        presentation.owner_kind,
        SelectedPacketByteViewRole::protocol_unit,
        SelectedPacketByteAssemblyKind::packet_local,
        SelectedPacketByteViewKind::frame,
        0U,
        presentation.owner_captured_length,
        0U,
        std::optional<std::uint32_t> {packet.original_length},
        packet.captured_length,
        packet.captured_length < packet.original_length
    );
    if (!frame_id.has_value()) {
        return;
    }

    for (auto& view : presentation.views) {
        if (view.id == *frame_id) {
            continue;
        }
        if (!view.parent_id.has_value() && view.owner_kind == SelectedPacketByteOwnerKind::captured_packet) {
            view.parent_id = frame_id;
        }
    }

    std::rotate(presentation.views.begin(), presentation.views.end() - 1, presentation.views.end());
}

std::optional<SelectedPacketByteViewId> append_payload_fallback_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& payload_range,
    const std::optional<std::uint64_t>& quic_crypto_stream_offset = std::nullopt
) {
    return append_protocol_unit_view(
        views,
        parent_id,
        owner_id,
        owner_kind,
        SelectedPacketByteViewRole::payload_fallback,
        kind,
        scope,
        owner_captured_length,
        payload_range,
        std::nullopt,
        quic_crypto_stream_offset
    );
}

std::optional<SelectedPacketByteViewId> append_arp_packet_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& parent_range,
    const ArpDetails& arp
) {
    const auto declared_length = static_cast<std::uint32_t>(
        8U + (2U * static_cast<std::uint32_t>(arp.hardware_size)) +
        (2U * static_cast<std::uint32_t>(arp.protocol_size))
    );
    const auto captured_length = std::min<std::uint32_t>(parent_range.captured_length, declared_length);
    return append_protocol_unit_view(
        views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        SelectedPacketByteViewRole::protocol_unit,
        SelectedPacketByteViewKind::arp,
        0U,
        owner_captured_length,
        PacketByteRange {
            .offset = parent_range.offset,
            .declared_length = std::optional<std::uint32_t> {declared_length},
            .captured_length = captured_length,
            .truncated = arp.fixed_header_truncated || arp.address_section_truncated || captured_length < declared_length,
        },
        std::nullopt
    );
}

PayloadBranchResult append_llc_snap_branch(
    const bool has_llc,
    const LlcDetails& llc,
    const bool has_snap,
    const SnapDetails& snap,
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::uint32_t owner_captured_length,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::optional<PacketByteRange>& carrier_payload_range
) {
    PayloadBranchResult result {
        .parent_id = parent_id,
        .child_payload_range = carrier_payload_range,
    };
    if (!has_llc || !llc.unit_range.has_value()) {
        return result;
    }

    const auto llc_payload_range = shift_payload_range(*llc.unit_range, kLlcHeaderSize);
    const auto llc_id = append_protocol_unit_view(
        views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        SelectedPacketByteViewRole::protocol_unit,
        SelectedPacketByteViewKind::llc,
        0U,
        owner_captured_length,
        *llc.unit_range,
        llc_payload_range
    );
    if (llc_id.has_value()) {
        result.parent_id = llc_id;
    }
    result.child_payload_range = llc_payload_range;

    if (!has_snap || !snap.unit_range.has_value()) {
        return result;
    }

    const auto snap_payload_range = shift_payload_range(*snap.unit_range, kSnapHeaderSize);
    const auto snap_id = append_protocol_unit_view(
        views,
        result.parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        SelectedPacketByteViewRole::protocol_unit,
        SelectedPacketByteViewKind::snap,
        0U,
        owner_captured_length,
        *snap.unit_range,
        snap_payload_range
    );
    if (snap_id.has_value()) {
        result.parent_id = snap_id;
    }
    result.child_payload_range = snap_payload_range;
    static_cast<void>(carrier_payload_range);
    return result;
}

PayloadBranchResult append_pppoe_branch(
    const PppoeSessionDetails& pppoe,
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::uint32_t owner_captured_length,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::optional<PacketByteRange>& carrier_payload_range
) {
    PayloadBranchResult result {
        .parent_id = parent_id,
        .child_payload_range = carrier_payload_range,
    };
    if (!pppoe.unit_range.has_value()) {
        return result;
    }

    const auto pppoe_id = append_protocol_unit_view(
        views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        SelectedPacketByteViewRole::protocol_unit,
        SelectedPacketByteViewKind::pppoe,
        0U,
        owner_captured_length,
        *pppoe.unit_range,
        pppoe.payload_range
    );
    if (pppoe_id.has_value()) {
        result.parent_id = pppoe_id;
    }

    if (pppoe.ppp_unit_range.has_value()) {
        const auto ppp_id = append_protocol_unit_view(
            views,
            result.parent_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::ppp,
            0U,
            owner_captured_length,
            *pppoe.ppp_unit_range,
            pppoe.ppp_payload_range
        );
        if (ppp_id.has_value()) {
            result.parent_id = ppp_id;
        }
    }

    if (pppoe.ppp_payload_range.has_value()) {
        result.child_payload_range = pppoe.ppp_payload_range;
    } else if (pppoe.payload_range.has_value()) {
        result.child_payload_range = pppoe.payload_range;
    } else {
        result.child_payload_range = std::nullopt;
    }
    return result;
}

std::optional<SelectedPacketByteViewId> append_tcp_segment_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& parent_range,
    const TcpDetails& tcp,
    const SelectedPacketByteViewKind kind
) {
    const auto header_length = static_cast<std::uint32_t>(tcp.header_length_bytes);
    if (header_length < 20U) {
        return std::nullopt;
    }

    std::optional<PacketByteRange> payload_range {};
    if (parent_range.captured_length > header_length &&
        (!parent_range.declared_length.has_value() || *parent_range.declared_length > header_length)) {
        payload_range = PacketByteRange {
            .offset = parent_range.offset + header_length,
            .declared_length = parent_range.declared_length.has_value()
                ? std::optional<std::uint32_t> {*parent_range.declared_length - header_length}
                : std::nullopt,
            .captured_length = parent_range.captured_length - header_length,
            .truncated = parent_range.truncated ||
                (parent_range.declared_length.has_value() &&
                 (parent_range.captured_length - header_length) < (*parent_range.declared_length - header_length)),
        };
    }

    return append_protocol_unit_view(
        views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        SelectedPacketByteViewRole::protocol_unit,
        kind,
        0U,
        owner_captured_length,
        parent_range,
        payload_range
    );
}

std::optional<SelectedPacketByteViewId> append_udp_datagram_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& parent_range,
    const UdpDetails& udp,
    const SelectedPacketByteViewKind kind
) {
    constexpr std::uint32_t kUdpHeaderSize = 8U;
    if (udp.length < kUdpHeaderSize || parent_range.captured_length < kUdpHeaderSize) {
        return std::nullopt;
    }

    const auto unit_captured_length = std::min<std::uint32_t>(
        parent_range.captured_length,
        static_cast<std::uint32_t>(udp.length)
    );
    const PacketByteRange unit_range {
        .offset = parent_range.offset,
        .declared_length = std::optional<std::uint32_t> {udp.length},
        .captured_length = unit_captured_length,
        .truncated = parent_range.truncated || unit_captured_length < udp.length,
    };

    std::optional<PacketByteRange> payload_range {};
    if (udp.length > kUdpHeaderSize && unit_captured_length > kUdpHeaderSize) {
        payload_range = PacketByteRange {
            .offset = parent_range.offset + kUdpHeaderSize,
            .declared_length = std::optional<std::uint32_t> {static_cast<std::uint32_t>(udp.length - kUdpHeaderSize)},
            .captured_length = unit_captured_length - kUdpHeaderSize,
            .truncated = unit_range.truncated || (unit_captured_length - kUdpHeaderSize) < (udp.length - kUdpHeaderSize),
        };
    }

    return append_protocol_unit_view(
        views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        SelectedPacketByteViewRole::protocol_unit,
        kind,
        0U,
        owner_captured_length,
        unit_range,
        payload_range
    );
}

std::optional<SelectedPacketByteViewId> append_sctp_packet_view(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& parent_range,
    const SelectedPacketByteViewKind kind
) {
    return append_protocol_unit_view(
        views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        SelectedPacketByteViewRole::protocol_unit,
        kind,
        0U,
        owner_captured_length,
        parent_range,
        std::nullopt
    );
}

std::optional<SelectedPacketByteViewId> append_vlan_payload_chain(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    std::optional<SelectedPacketByteViewId> parent_id,
    const std::uint32_t owner_captured_length,
    const PacketByteRange& carrier_range,
    const std::size_t vlan_count,
    const SelectedPacketByteViewKind kind
) {
    constexpr std::uint32_t kVlanHeaderSize = 4U;
    auto current_range = carrier_range;
    auto current_parent = parent_id;
    for (std::size_t index = 0U; index < vlan_count; ++index) {
        const auto payload_range = shift_payload_range(current_range, kVlanHeaderSize);
        if (!payload_range.has_value()) {
            break;
        }
        const auto appended = append_protocol_unit_from_payload_range(
            views,
            current_parent,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            kind,
            0U,
            owner_captured_length,
            current_range.offset,
            *payload_range
        );
        if (appended.has_value()) {
            current_parent = appended;
        }
        current_range = *payload_range;
    }
    return current_parent;
}

template <typename InnerPacket>
std::optional<SelectedPacketByteViewId> append_inner_network_branch(
    const InnerPacket& inner,
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::uint32_t owner_captured_length,
    std::optional<SelectedPacketByteViewId> parent_id,
    const std::optional<PacketByteRange>& parent_payload_range = std::nullopt
) {
    std::optional<PacketByteRange> network_range {};
    auto current_parent = parent_id;
    auto current_payload_range = parent_payload_range;

    if constexpr (requires { inner.has_arp; inner.arp; }) {
        if (inner.has_arp && current_payload_range.has_value()) {
            const auto appended = append_arp_packet_view(
                views,
                current_parent,
                owner_captured_length,
                *current_payload_range,
                inner.arp
            );
            return appended.has_value() ? appended : current_parent;
        }
    }

    if (inner.has_ipv4 && inner.ipv4.payload_range.has_value()) {
        network_range = inner.ipv4.payload_range;
        const auto network_offset = current_payload_range.has_value()
            ? current_payload_range->offset
            : (inner.ipv4.payload_range->offset >= static_cast<std::uint32_t>(inner.ipv4.header_length_bytes)
                ? inner.ipv4.payload_range->offset - static_cast<std::uint32_t>(inner.ipv4.header_length_bytes)
                : 0U);
        const auto appended = append_protocol_unit_from_payload_range(
            views,
            current_parent,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::inner_ipv4_payload,
            0U,
            owner_captured_length,
            network_offset,
            *inner.ipv4.payload_range
        );
        if (appended.has_value()) {
            current_parent = appended;
        }
    } else if (inner.has_ipv6 && inner.ipv6.payload_range.has_value()) {
        network_range = inner.ipv6.payload_range;
        const auto network_offset = current_payload_range.has_value()
            ? current_payload_range->offset
            : (inner.ipv6.payload_range->offset >= 40U ? inner.ipv6.payload_range->offset - 40U : 0U);
        const auto appended = append_protocol_unit_from_payload_range(
            views,
            current_parent,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::inner_ipv6_payload,
            0U,
            owner_captured_length,
            network_offset,
            *inner.ipv6.payload_range
        );
        if (appended.has_value()) {
            current_parent = appended;
        }
    }

    if (!network_range.has_value()) {
        return current_parent;
    }

    if (inner.has_tcp) {
        const auto appended = append_tcp_segment_view(
            views,
            current_parent,
            owner_captured_length,
            *network_range,
            inner.tcp,
            SelectedPacketByteViewKind::inner_tcp_payload
        );
        return appended.has_value() ? appended : current_parent;
    }
    if (inner.has_udp) {
        const auto appended = append_udp_datagram_view(
            views,
            current_parent,
            owner_captured_length,
            *network_range,
            inner.udp,
            SelectedPacketByteViewKind::inner_udp_payload
        );
        return appended.has_value() ? appended : current_parent;
    }
    if constexpr (requires { inner.has_sctp; inner.sctp.payload_range; }) {
        if (inner.has_sctp) {
            const auto appended = append_sctp_packet_view(
                views,
                current_parent,
                owner_captured_length,
                *network_range,
                SelectedPacketByteViewKind::inner_sctp_payload
            );
            return appended.has_value() ? appended : current_parent;
        }
    }

    return current_parent;
}

template <typename InnerPacket>
std::optional<SelectedPacketByteViewId> append_inner_ethernet_branch(
    const InnerPacket& inner,
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::uint32_t owner_captured_length,
    const std::optional<SelectedPacketByteViewId>& parent_id
) {
    auto current_parent = parent_id;
    std::optional<PacketByteRange> current_payload_range {};
    if (inner.has_inner_ethernet && inner.inner_ethernet.payload_range.has_value()) {
        const auto inner_unit_offset =
            inner.inner_ethernet.payload_range->offset >= 14U
                ? inner.inner_ethernet.payload_range->offset - 14U
                : 0U;
        const auto inner_ethernet_kind = inner.inner_ethernet.uses_length_field
            ? SelectedPacketByteViewKind::inner_ieee8023_payload
            : SelectedPacketByteViewKind::inner_ethernet_payload;
        const auto appended = append_protocol_unit_from_payload_range(
            views,
            current_parent,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            inner_ethernet_kind,
            0U,
            owner_captured_length,
            inner_unit_offset,
            *inner.inner_ethernet.payload_range
        );
        if (appended.has_value()) {
            current_parent = appended;
        }
        current_payload_range = inner.inner_ethernet.payload_range;
        current_parent = append_vlan_payload_chain(
            views,
            current_parent,
            owner_captured_length,
            *inner.inner_ethernet.payload_range,
            inner.vlan_tags.size(),
            SelectedPacketByteViewKind::inner_vlan_payload
        );
    }

    if constexpr (requires { inner.has_mpls; inner.mpls_payload_range; }) {
        if (inner.has_mpls && inner.mpls_payload_range.has_value()) {
            const auto mpls_offset = current_payload_range.has_value()
                ? current_payload_range->offset
                : inner.mpls_payload_range->offset;
            const auto appended = append_protocol_unit_from_payload_range(
                views,
                current_parent,
                kCapturedPacketOwnerId,
                SelectedPacketByteOwnerKind::captured_packet,
                SelectedPacketByteViewKind::mpls_payload,
                0U,
                owner_captured_length,
                mpls_offset,
                *inner.mpls_payload_range
            );
            if (appended.has_value()) {
                current_parent = appended;
            }
            current_payload_range = inner.mpls_payload_range;
        }
    }

    if constexpr (requires { inner.has_llc; inner.llc; inner.has_snap; inner.snap; }) {
        const auto llc_snap_branch = append_llc_snap_branch(
            inner.has_llc,
            inner.llc,
            inner.has_snap,
            inner.snap,
            views,
            owner_captured_length,
            current_parent,
            current_payload_range
        );
        current_parent = llc_snap_branch.parent_id;
        current_payload_range = llc_snap_branch.child_payload_range;
    }

    return append_inner_network_branch(inner, views, owner_captured_length, current_parent, current_payload_range);
}

std::optional<SelectedPacketByteViewId> append_top_level_transport_branch(
    const PacketDetails& details,
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::uint32_t owner_captured_length,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const std::optional<PacketByteRange>& parent_range
) {
    if (!parent_range.has_value()) {
        return parent_id;
    }

    if (details.has_tcp) {
        const auto appended = append_tcp_segment_view(
            views,
            parent_id,
            owner_captured_length,
            *parent_range,
            details.tcp,
            SelectedPacketByteViewKind::tcp_payload
        );
        return appended.has_value() ? appended : parent_id;
    }
    if (details.has_udp) {
        const auto appended = append_udp_datagram_view(
            views,
            parent_id,
            owner_captured_length,
            *parent_range,
            details.udp,
            SelectedPacketByteViewKind::udp_payload
        );
        return appended.has_value() ? appended : parent_id;
    }
    if (details.has_sctp) {
        const auto appended = append_sctp_packet_view(
            views,
            parent_id,
            owner_captured_length,
            *parent_range,
            SelectedPacketByteViewKind::sctp_payload
        );
        return appended.has_value() ? appended : parent_id;
    }
    if (details.has_icmp) {
        std::optional<PacketByteRange> payload_range {};
        if (parent_range->captured_length > 4U &&
            (!parent_range->declared_length.has_value() || *parent_range->declared_length > 4U)) {
            payload_range = shift_payload_range(*parent_range, 4U);
        }
        const auto appended = append_protocol_unit_view(
            views,
            parent_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::icmp,
            0U,
            owner_captured_length,
            *parent_range,
            payload_range
        );
        return appended.has_value() ? appended : parent_id;
    }
    if (details.has_icmpv6) {
        std::optional<PacketByteRange> payload_range {};
        if (parent_range->captured_length > 4U &&
            (!parent_range->declared_length.has_value() || *parent_range->declared_length > 4U)) {
            payload_range = shift_payload_range(*parent_range, 4U);
        }
        const auto appended = append_protocol_unit_view(
            views,
            parent_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::icmpv6,
            0U,
            owner_captured_length,
            *parent_range,
            payload_range
        );
        return appended.has_value() ? appended : parent_id;
    }
    if (details.has_igmp) {
        std::optional<PacketByteRange> payload_range {};
        if (parent_range->captured_length > 8U &&
            (!parent_range->declared_length.has_value() || *parent_range->declared_length > 8U)) {
            payload_range = shift_payload_range(*parent_range, 8U);
        }
        const auto appended = append_protocol_unit_view(
            views,
            parent_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::igmp,
            0U,
            owner_captured_length,
            *parent_range,
            payload_range
        );
        return appended.has_value() ? appended : parent_id;
    }

    return parent_id;
}

std::optional<SelectedPacketByteViewId> find_last_view_id(
    const std::vector<SelectedPacketByteViewDescriptor>& views,
    const SelectedPacketByteViewKind kind
) {
    for (auto it = views.rbegin(); it != views.rend(); ++it) {
        if (it->id.kind == kind) {
            return it->id;
        }
    }
    return std::nullopt;
}

std::optional<SelectedPacketByteViewId> resolve_packet_data_parent_id(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteBuildOptions& options,
    const std::optional<SelectedPacketByteViewId>& outer_tcp_id,
    const std::optional<SelectedPacketByteViewId>& outer_udp_id
) {
    if (!options.packet_data.has_value()) {
        return std::nullopt;
    }

    switch (options.packet_data->placement) {
    case PacketDataPlacement::after_tcp:
        return outer_tcp_id.has_value()
            ? outer_tcp_id
            : find_last_view_id(presentation.views, SelectedPacketByteViewKind::tcp_payload);
    case PacketDataPlacement::after_udp:
        return outer_udp_id.has_value()
            ? outer_udp_id
            : find_last_view_id(presentation.views, SelectedPacketByteViewKind::udp_payload);
    case PacketDataPlacement::after_inner_tcp:
        return find_last_view_id(presentation.views, SelectedPacketByteViewKind::inner_tcp_payload);
    case PacketDataPlacement::after_inner_udp:
        return find_last_view_id(presentation.views, SelectedPacketByteViewKind::inner_udp_payload);
    case PacketDataPlacement::none:
    default:
        return std::nullopt;
    }
}

void append_packet_data_view(
    SelectedPacketBytePresentation& presentation,
    const PacketDetails& details,
    const SelectedPacketByteBuildOptions& options,
    const std::optional<SelectedPacketByteViewId>& outer_tcp_id,
    const std::optional<SelectedPacketByteViewId>& outer_udp_id
) {
    if (!options.packet_data.has_value() ||
        !details.effective_transport_payload.has_value()) {
        return;
    }

    const auto& packet_data = *options.packet_data;
    if (packet_data.role != PacketDataRole::transport_payload ||
        packet_data.disposition != TransportPayloadDisposition::unclaimed_data ||
        packet_data.transport == PacketDataTransportKind::unknown ||
        packet_data.captured_length == 0U) {
        return;
    }

    const auto parent_id = resolve_packet_data_parent_id(
        presentation,
        options,
        outer_tcp_id,
        outer_udp_id
    );
    if (!parent_id.has_value()) {
        return;
    }

    const auto& effective_payload = *details.effective_transport_payload;
    append_view(
        presentation.views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        SelectedPacketByteViewRole::protocol_unit,
        SelectedPacketByteAssemblyKind::packet_local,
        SelectedPacketByteViewKind::data,
        0U,
        presentation.owner_captured_length,
        effective_payload.payload_offset,
        packet_data.declared_length_reliable
            ? std::optional<std::uint32_t> {packet_data.declared_length}
            : std::nullopt,
        packet_data.captured_length,
        effective_payload.payload_truncated
    );
}

void append_overlay_payload_branches(
    const PacketDetails& details,
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const std::uint32_t owner_captured_length,
    const std::optional<SelectedPacketByteViewId>& outer_ip_id,
    const std::optional<PacketByteRange>& outer_ip_range,
    const std::optional<SelectedPacketByteViewId>& outer_udp_id
) {
    if (details.has_ah &&
        details.ah.unit_range.has_value() &&
        details.ah.payload_range.has_value() &&
        outer_ip_id.has_value()) {
        const auto ah_id = append_protocol_unit_view(
            views,
            outer_ip_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::ah_payload,
            0U,
            owner_captured_length,
            *details.ah.unit_range,
            details.ah.payload_range
        );
        if (details.ah.has_inner_packet && details.ah.inner_packet != nullptr) {
            append_inner_network_branch(
                *details.ah.inner_packet,
                views,
                owner_captured_length,
                ah_id,
                details.ah.payload_range
            );
            return;
        }
        append_top_level_transport_branch(
            details,
            views,
            owner_captured_length,
            ah_id,
            details.ah.payload_range
        );
        return;
    }

    if (details.has_gre &&
        details.gre.unit_range.has_value() &&
        details.gre.payload_range.has_value() &&
        outer_ip_id.has_value()) {
        const auto gre_id = append_protocol_unit_view(
            views,
            outer_ip_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewRole::protocol_unit,
            details.gre.is_eoip
                ? SelectedPacketByteViewKind::eoip_payload
                : SelectedPacketByteViewKind::gre_payload,
            0U,
            owner_captured_length,
            *details.gre.unit_range,
            details.gre.payload_range
        );
        if (details.gre.has_inner_packet && details.gre.inner_packet != nullptr) {
            append_inner_ethernet_branch(*details.gre.inner_packet, views, owner_captured_length, gre_id);
        }
        return;
    }

    if (details.has_esp &&
        details.esp.unit_range.has_value() &&
        details.esp.protected_payload_range.has_value() &&
        outer_ip_id.has_value()) {
        const auto esp_id = append_protocol_unit_view(
            views,
            outer_ip_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::esp,
            0U,
            owner_captured_length,
            *details.esp.unit_range,
            details.esp.protected_payload_range
        );
        append_payload_fallback_view(
            views,
            esp_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewKind::esp_protected_payload,
            0U,
            owner_captured_length,
            *details.esp.protected_payload_range
        );
        return;
    }

    if (details.has_gtpu &&
        details.gtpu.unit_range.has_value() &&
        details.gtpu.payload_range.has_value() &&
        outer_udp_id.has_value()) {
        const auto gtpu_id = append_protocol_unit_view(
            views,
            outer_udp_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::gtpu_payload,
            0U,
            owner_captured_length,
            *details.gtpu.unit_range,
            details.gtpu.payload_range
        );
        if (details.gtpu.has_inner_packet && details.gtpu.inner_packet != nullptr) {
            append_inner_network_branch(
                *details.gtpu.inner_packet,
                views,
                owner_captured_length,
                gtpu_id,
                details.gtpu.payload_range
            );
        }
        return;
    }

    if (details.has_vxlan &&
        details.vxlan.unit_range.has_value() &&
        details.vxlan.payload_range.has_value() &&
        outer_udp_id.has_value()) {
        const auto vxlan_id = append_protocol_unit_view(
            views,
            outer_udp_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::vxlan_payload,
            0U,
            owner_captured_length,
            *details.vxlan.unit_range,
            details.vxlan.payload_range
        );
        if (details.vxlan.has_inner_packet && details.vxlan.inner_packet != nullptr) {
            append_inner_ethernet_branch(*details.vxlan.inner_packet, views, owner_captured_length, vxlan_id);
        }
        return;
    }

    if (details.has_geneve &&
        details.geneve.unit_range.has_value() &&
        details.geneve.payload_range.has_value() &&
        outer_udp_id.has_value()) {
        const auto geneve_id = append_protocol_unit_view(
            views,
            outer_udp_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::geneve_payload,
            0U,
            owner_captured_length,
            *details.geneve.unit_range,
            details.geneve.payload_range
        );
        if (details.geneve.has_inner_packet && details.geneve.inner_packet != nullptr) {
            append_inner_ethernet_branch(*details.geneve.inner_packet, views, owner_captured_length, geneve_id);
        }
        return;
    }

    if (details.has_ip_encapsulation && outer_ip_id.has_value()) {
        auto current_parent = outer_ip_id;
        auto current_payload_range = outer_ip_range;
        for (const auto& inner_layer : details.ip_encapsulation.inner_ip_layers) {
            if (inner_layer.has_ipv4 && inner_layer.ipv4.payload_range.has_value()) {
                const auto unit_offset = current_payload_range.has_value()
                    ? current_payload_range->offset
                    : (inner_layer.ipv4.payload_range->offset >= static_cast<std::uint32_t>(inner_layer.ipv4.header_length_bytes)
                        ? inner_layer.ipv4.payload_range->offset - static_cast<std::uint32_t>(inner_layer.ipv4.header_length_bytes)
                        : 0U);
                const auto appended = append_protocol_unit_from_payload_range(
                    views,
                    current_parent,
                    kCapturedPacketOwnerId,
                    SelectedPacketByteOwnerKind::captured_packet,
                    SelectedPacketByteViewKind::inner_ipv4_payload,
                    0U,
                    owner_captured_length,
                    unit_offset,
                    *inner_layer.ipv4.payload_range
                );
                if (appended.has_value()) {
                    current_parent = appended;
                }
                current_payload_range = inner_layer.ipv4.payload_range;
            } else if (inner_layer.has_ipv6 && inner_layer.ipv6.payload_range.has_value()) {
                const auto unit_offset = current_payload_range.has_value()
                    ? current_payload_range->offset
                    : (inner_layer.ipv6.payload_range->offset >= 40U ? inner_layer.ipv6.payload_range->offset - 40U : 0U);
                const auto appended = append_protocol_unit_from_payload_range(
                    views,
                    current_parent,
                    kCapturedPacketOwnerId,
                    SelectedPacketByteOwnerKind::captured_packet,
                    SelectedPacketByteViewKind::inner_ipv6_payload,
                    0U,
                    owner_captured_length,
                    unit_offset,
                    *inner_layer.ipv6.payload_range
                );
                if (appended.has_value()) {
                    current_parent = appended;
                }
                current_payload_range = inner_layer.ipv6.payload_range;
            }
        }

        if (current_parent.has_value() && !details.ip_encapsulation.inner_ip_layers.empty()) {
            const auto deepest_range = current_payload_range;
            if (details.ip_encapsulation.has_tcp && deepest_range.has_value()) {
                append_tcp_segment_view(
                    views,
                    current_parent,
                    owner_captured_length,
                    *deepest_range,
                    details.ip_encapsulation.tcp,
                    SelectedPacketByteViewKind::inner_tcp_payload
                );
            } else if (details.ip_encapsulation.has_udp && deepest_range.has_value()) {
                append_udp_datagram_view(
                    views,
                    current_parent,
                    owner_captured_length,
                    *deepest_range,
                    details.ip_encapsulation.udp,
                    SelectedPacketByteViewKind::inner_udp_payload
                );
            }
        }
    }

    if (!details.has_ah) {
        append_top_level_transport_branch(
            details,
            views,
            owner_captured_length,
            outer_ip_id,
            outer_ip_range
        );
    }
}

std::vector<std::optional<SelectedPacketByteViewId>> append_quic_packet_views(
    SelectedPacketBytePresentation& presentation,
    const QuicPresentationResult& quic_presentation,
    const SelectedPacketByteViewDescriptor* udp_payload_view
) {
    std::vector<std::optional<SelectedPacketByteViewId>> packet_ids(quic_presentation.packets.size());
    if (udp_payload_view == nullptr) {
        return packet_ids;
    }
    const auto udp_payload_id = udp_payload_view->id;
    const auto udp_payload_offset = udp_payload_view->payload_range.has_value()
        ? udp_payload_view->payload_range->offset
        : udp_payload_view->offset;

    for (std::size_t packet_index = 0U; packet_index < quic_presentation.packets.size(); ++packet_index) {
        if (packet_index > kMaxViewOccurrence) {
            continue;
        }
        const auto& quic_packet = quic_presentation.packets[packet_index];
        // QUIC parsing retains UDP-payload-relative envelope offsets. Rebase
        // them once here into captured-frame-relative selected-packet bytes.
        const auto packet_offset = narrow_u32(
            static_cast<std::size_t>(udp_payload_offset) + quic_packet.udp_payload_offset
        );
        const auto packet_length = narrow_u32(quic_packet.packet_bytes_consumed);
        if (!packet_offset.has_value() || !packet_length.has_value()) {
            continue;
        }

        const auto packet_id = append_view(
            presentation.views,
            udp_payload_id,
            kCapturedPacketOwnerId,
            SelectedPacketByteOwnerKind::captured_packet,
            quic_packet_view_kind(quic_packet.shell_type),
            static_cast<std::uint8_t>(packet_index),
            presentation.owner_captured_length,
            *packet_offset,
            std::optional<std::uint32_t> {*packet_length},
            *packet_length,
            false
        );
        if (!packet_id.has_value()) {
            continue;
        }
        packet_ids[packet_index] = packet_id;

        if (quic_packet.shell_type == QuicPresentationShellType::initial &&
            quic_packet.protected_payload_offset.has_value() &&
            quic_packet.protected_payload_length.has_value()) {
            const auto protected_offset = narrow_u32(
                static_cast<std::size_t>(udp_payload_offset) + *quic_packet.protected_payload_offset
            );
            const auto protected_length = narrow_u32(*quic_packet.protected_payload_length);
            if (protected_offset.has_value() && protected_length.has_value()) {
                append_view(
                    presentation.views,
                    packet_id,
                    kCapturedPacketOwnerId,
                    SelectedPacketByteOwnerKind::captured_packet,
                    SelectedPacketByteViewKind::quic_initial_protected_payload,
                    static_cast<std::uint8_t>(packet_index),
                    presentation.owner_captured_length,
                    *protected_offset,
                    std::optional<std::uint32_t> {*protected_length},
                    *protected_length,
                    false
                );
            }
        }
    }
    return packet_ids;
}

void append_quic_initial_plaintext_views(
    SelectedPacketBytePresentation& presentation,
    std::optional<QuicPresentationResult> quic_presentation,
    std::span<const std::optional<SelectedPacketByteViewId>> packet_ids
) {
    if (!quic_presentation.has_value() ||
        !quic_presentation->selected_initial_plaintext_packet_index.has_value() ||
        quic_presentation->selected_initial_plaintext_payload.empty()) {
        return;
    }

    const auto packet_index = *quic_presentation->selected_initial_plaintext_packet_index;
    if (packet_index >= quic_presentation->packets.size() || packet_index > kMaxViewOccurrence) {
        return;
    }

    const auto& quic_packet = quic_presentation->packets[packet_index];
    if (quic_packet.shell_type != QuicPresentationShellType::initial) {
        return;
    }

    const auto owner_id = append_derived_owner(
        presentation.derived_owners,
        SelectedPacketByteOwnerKind::quic_initial_plaintext,
        packet_index,
        std::move(quic_presentation->selected_initial_plaintext_payload)
    );
    if (!owner_id.has_value()) {
        return;
    }

    const auto* owner = presentation.find_derived_owner(*owner_id);
    if (owner == nullptr) {
        return;
    }
    const auto owner_length = narrow_u32(owner->bytes.size());
    if (!owner_length.has_value()) {
        return;
    }

    const auto packet_parent_id =
        packet_index < packet_ids.size()
            ? packet_ids[packet_index]
            : std::nullopt;

    const auto plaintext_id = append_view(
        presentation.views,
        packet_parent_id,
        *owner_id,
        SelectedPacketByteOwnerKind::quic_initial_plaintext,
        SelectedPacketByteViewKind::quic_initial_plaintext,
        static_cast<std::uint8_t>(packet_index),
        *owner_length,
        0U,
        std::optional<std::uint32_t> {*owner_length},
        *owner_length,
        false
    );
    if (!plaintext_id.has_value()) {
        return;
    }

    for (const auto& frame : quic_packet.frames) {
        const auto frame_offset = narrow_u32(frame.frame_offset);
        const auto frame_length = narrow_u32(frame.frame_length);
        if (!frame_offset.has_value() || !frame_length.has_value()) {
            continue;
        }

        const auto frame_id = append_view(
            presentation.views,
            plaintext_id,
            *owner_id,
            SelectedPacketByteOwnerKind::quic_initial_plaintext,
            SelectedPacketByteViewKind::quic_frame,
            static_cast<std::uint8_t>(packet_index),
            *owner_length,
            *frame_offset,
            std::optional<std::uint32_t> {*frame_length},
            *frame_length,
            false,
            frame.crypto_offset
        );
        if (frame.type != QuicPresentationFrameType::crypto ||
            !frame_id.has_value() ||
            !frame.crypto_data_offset_in_plaintext.has_value() ||
            !frame.crypto_length.has_value()) {
            continue;
        }

        const auto crypto_data_offset = narrow_u32(*frame.crypto_data_offset_in_plaintext);
        const auto crypto_data_length = narrow_u32(*frame.crypto_length);
        if (!crypto_data_offset.has_value() || !crypto_data_length.has_value()) {
            continue;
        }

        append_view(
            presentation.views,
            frame_id,
            *owner_id,
            SelectedPacketByteOwnerKind::quic_initial_plaintext,
            SelectedPacketByteViewKind::quic_crypto_data,
            static_cast<std::uint8_t>(packet_index),
            *owner_length,
            *crypto_data_offset,
            std::optional<std::uint32_t> {*crypto_data_length},
            *crypto_data_length,
            false,
            frame.crypto_offset
        );
    }

    append_quic_tls_handshake_views(
        presentation,
        *quic_presentation,
        quic_packet,
        static_cast<std::uint8_t>(packet_index),
        *owner_id,
        *owner_length
    );
}

bool has_confirmed_tls_context(const TlsInspectionParserContext& initial_parser_context) noexcept {
    return initial_parser_context.semantic_state == TlsInspectionSemanticState::post_change_cipher_spec ||
        initial_parser_context.negotiated_cipher_suite.has_value() ||
        initial_parser_context.negotiated_version.has_value();
}

bool tls_payload_is_owned_by_tls(
    std::span<const std::uint8_t> payload,
    const TlsInspectionParserContext& initial_parser_context
) {
    const auto header = inspect_tls_record_header(payload);
    if (!header.has_value()) {
        return false;
    }

    const bool confirmed_tls_context = has_confirmed_tls_context(initial_parser_context);
    if (header->declared_payload_length == 0U) {
        return header->content_type_kind == TlsRecordContentTypeKind::application_data &&
            confirmed_tls_context;
    }

    if (header->complete_record_available) {
        return true;
    }

    if (confirmed_tls_context) {
        return true;
    }

    return header->content_type_kind == TlsRecordContentTypeKind::handshake &&
        payload.size() >= 7U &&
        payload.size() > 5U;
}

const TlsSelectedPacketContribution* find_selected_packet_contribution(
    const TlsSelectedPacketRecordContext& context,
    const std::uint64_t flow_packet_index
) {
    const auto it = std::find_if(
        context.contributions.begin(),
        context.contributions.end(),
        [&](const TlsSelectedPacketContribution& contribution) {
            return contribution.flow_packet_index == flow_packet_index;
        }
    );
    return it == context.contributions.end() ? nullptr : &(*it);
}

bool selected_packet_starts_record(
    const TlsSelectedPacketRecordContext& context,
    const std::uint64_t flow_packet_index
) {
    return !context.contributions.empty() &&
        context.contributions.front().flow_packet_index == flow_packet_index;
}

std::size_t selected_packet_reassembled_tls_prefix_bytes(const SelectedPacketByteBuildOptions& options) {
    if (!options.flow_packet_index.has_value()) {
        return 0U;
    }

    std::size_t consumed_prefix_bytes = 0U;
    const auto flow_packet_index = *options.flow_packet_index;
    for (const auto& reconstructed_record : options.reconstructed_tls_records) {
        const auto* selected_contribution =
            find_selected_packet_contribution(reconstructed_record, flow_packet_index);
        if (selected_contribution == nullptr) {
            continue;
        }

        const auto record_offset = selected_contribution->record_offset;
        if (record_offset > consumed_prefix_bytes) {
            continue;
        }
        const auto contribution_end = record_offset + selected_contribution->captured_byte_count;
        if (contribution_end > consumed_prefix_bytes) {
            consumed_prefix_bytes = contribution_end;
        }
    }

    return consumed_prefix_bytes;
}

TlsInspectionParserContext selected_packet_starting_tls_context(const SelectedPacketByteBuildOptions& options) {
    if (!options.flow_packet_index.has_value()) {
        return options.tls_initial_parser_context;
    }

    if (options.tls_initial_parser_context.semantic_state != TlsInspectionSemanticState::unknown) {
        return options.tls_initial_parser_context;
    }

    const auto flow_packet_index = *options.flow_packet_index;
    for (const auto& reconstructed_record : options.reconstructed_tls_records) {
        if (selected_packet_starts_record(reconstructed_record, flow_packet_index)) {
            return reconstructed_record.initial_parser_context;
        }
    }

    return options.tls_initial_parser_context;
}

std::optional<PacketByteRange> tls_record_payload_range(
    const std::uint32_t record_offset,
    const TlsRecordModel& record
) {
    constexpr std::uint32_t kTlsRecordHeaderSize = 5U;
    if (record.available_bytes <= kTlsRecordHeaderSize) {
        return std::nullopt;
    }

    std::optional<std::uint32_t> declared_length {};
    if (record.declared_payload_length.has_value()) {
        declared_length = static_cast<std::uint32_t>(*record.declared_payload_length);
    }

    return PacketByteRange {
        .offset = record_offset + kTlsRecordHeaderSize,
        .declared_length = declared_length,
        .captured_length = static_cast<std::uint32_t>(record.available_bytes - kTlsRecordHeaderSize),
        .truncated = record.status != TlsRecordStatus::complete &&
            (!declared_length.has_value() || (record.available_bytes - kTlsRecordHeaderSize) < *declared_length),
    };
}

std::optional<PacketByteRange> tls_handshake_payload_range(
    const std::uint32_t handshake_offset,
    const TlsHandshakeModel& handshake
) {
    constexpr std::uint32_t kTlsHandshakeHeaderSize = 4U;
    if (handshake.available_bytes <= kTlsHandshakeHeaderSize) {
        return std::nullopt;
    }

    std::optional<std::uint32_t> declared_length {};
    if (handshake.declared_body_length.has_value()) {
        declared_length = static_cast<std::uint32_t>(*handshake.declared_body_length);
    }

    return PacketByteRange {
        .offset = handshake_offset + kTlsHandshakeHeaderSize,
        .declared_length = declared_length,
        .captured_length = static_cast<std::uint32_t>(handshake.available_bytes - kTlsHandshakeHeaderSize),
        .truncated = handshake.status != TlsHandshakeStatus::complete &&
            (!declared_length.has_value() || (handshake.available_bytes - kTlsHandshakeHeaderSize) < *declared_length),
    };
}

bool tls_record_requires_fragment_state(
    const TlsRecordModel& record,
    const std::optional<std::uint32_t>& declared_length
) {
    return record.status == TlsRecordStatus::partial_header ||
        (!declared_length.has_value() && record.status != TlsRecordStatus::complete);
}

bool tls_handshake_requires_fragment_state(
    const TlsHandshakeModel& handshake,
    const std::optional<std::uint32_t>& declared_length
) {
    return handshake.status == TlsHandshakeStatus::partial_header ||
        (!declared_length.has_value() && handshake.status != TlsHandshakeStatus::complete);
}

void append_tls_handshake_views(
    std::vector<SelectedPacketByteViewDescriptor>& views,
    const SelectedPacketByteViewId& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const std::uint32_t owner_captured_length,
    const std::uint8_t scope,
    const std::uint32_t base_offset,
    std::span<const TlsHandshakeModel> handshakes,
    const SelectedPacketByteAssemblyKind assembly_kind = SelectedPacketByteAssemblyKind::packet_local,
    const std::optional<std::uint32_t>& contributing_unit_count = std::nullopt,
    const std::optional<SelectedPacketByteContributionUnitKind>& contributing_unit_kind = std::nullopt,
    const std::optional<std::uint64_t> quic_crypto_stream_base = std::nullopt
) {
    for (const auto& handshake : handshakes) {
        const auto handshake_offset = narrow_u32(static_cast<std::size_t>(base_offset) + handshake.source_offset);
        const auto captured_length = narrow_u32(handshake.available_bytes);
        if (!handshake_offset.has_value() || !captured_length.has_value()) {
            continue;
        }

        std::optional<std::uint32_t> declared_length {};
        if (handshake.total_size.has_value()) {
            declared_length = narrow_u32(*handshake.total_size);
        }
        const auto payload_range = tls_handshake_payload_range(*handshake_offset, handshake);
        const auto stream_offset = quic_crypto_stream_base.has_value()
            ? std::optional<std::uint64_t> {*quic_crypto_stream_base + handshake.source_offset}
            : std::nullopt;
        const auto truncated = tls_handshake_requires_fragment_state(handshake, declared_length);
        append_view(
            views,
            parent_id,
            owner_id,
            owner_kind,
            SelectedPacketByteViewRole::protocol_unit,
            assembly_kind,
            SelectedPacketByteViewKind::tls_handshake,
            scope,
            owner_captured_length,
            *handshake_offset,
            declared_length,
            *captured_length,
            truncated,
            payload_range,
            contributing_unit_count,
            contributing_unit_kind,
            stream_offset,
            std::nullopt,
            std::nullopt,
            handshake.kind,
            handshake.type
        );
    }
}

void append_dns_message_view(
    SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& parent_id,
    const SelectedPacketByteViewDescriptor& parent_view,
    const DnsPacketMessageView& dns_view
) {
    PacketByteRange unit_range = dns_view.message_range;
    if (parent_view.payload_range.has_value() && !dns_view.tcp_length_prefixed) {
        unit_range = *parent_view.payload_range;
    }

    append_protocol_unit_view(
        presentation.views,
        parent_id,
        kCapturedPacketOwnerId,
        SelectedPacketByteOwnerKind::captured_packet,
        SelectedPacketByteViewRole::protocol_unit,
        SelectedPacketByteViewKind::dns_message,
        0U,
        presentation.owner_captured_length,
        unit_range,
        std::nullopt
    );
}

void append_tls_record_view(
    SelectedPacketBytePresentation& presentation,
    const std::optional<SelectedPacketByteViewId>& parent_id,
    const SelectedPacketByteOwnerId& owner_id,
    const SelectedPacketByteOwnerKind owner_kind,
    const std::uint32_t owner_captured_length,
    const std::uint8_t scope,
    const TlsRecordModel& record,
    const std::uint32_t base_offset,
    const SelectedPacketByteAssemblyKind assembly_kind = SelectedPacketByteAssemblyKind::packet_local,
    const std::optional<std::uint32_t>& contributing_unit_count = std::nullopt,
    const std::optional<SelectedPacketByteContributionUnitKind>& contributing_unit_kind = std::nullopt,
    const std::optional<std::uint64_t> quic_crypto_stream_base = std::nullopt
) {
    const auto record_offset = narrow_u32(static_cast<std::size_t>(base_offset) + record.source_offset);
    const auto captured_length = narrow_u32(record.available_bytes);
    if (!record_offset.has_value() || !captured_length.has_value()) {
        return;
    }

    std::optional<std::uint32_t> declared_length {};
    if (record.total_size.has_value()) {
        declared_length = narrow_u32(*record.total_size);
    }
    const auto payload_range = tls_record_payload_range(*record_offset, record);
    const auto truncated = tls_record_requires_fragment_state(record, declared_length);
    const auto record_id = append_view(
        presentation.views,
        parent_id,
        owner_id,
        owner_kind,
        SelectedPacketByteViewRole::protocol_unit,
        assembly_kind,
        SelectedPacketByteViewKind::tls_record,
        scope,
        owner_captured_length,
        *record_offset,
        declared_length,
        *captured_length,
        truncated,
        payload_range,
        contributing_unit_count,
        contributing_unit_kind,
        quic_crypto_stream_base,
        record.content_type_kind,
        record.content_type
    );
    if (!record_id.has_value()) {
        return;
    }

    if (record.content_type_kind == TlsRecordContentTypeKind::handshake &&
        record.handshake_payload_kind == TlsHandshakePayloadKind::plaintext &&
        !record.handshake_messages.empty()) {
        append_tls_handshake_views(
            presentation.views,
            *record_id,
            owner_id,
            owner_kind,
            owner_captured_length,
            record_id->occurrence,
            base_offset,
            std::span<const TlsHandshakeModel>(record.handshake_messages.data(), record.handshake_messages.size()),
            assembly_kind,
            contributing_unit_count,
            contributing_unit_kind,
            quic_crypto_stream_base
        );
    }
}

std::optional<std::vector<std::uint8_t>> build_quic_crypto_prefix_bytes(
    std::span<const std::uint8_t> plaintext_bytes,
    std::span<const QuicPresentationFrame> frames,
    std::span<const TlsHandshakeModel> handshakes
) {
    std::size_t max_required_bytes = 0U;
    for (const auto& handshake : handshakes) {
        max_required_bytes = std::max(max_required_bytes, handshake.source_offset + handshake.available_bytes);
    }
    if (max_required_bytes == 0U) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> prefix_bytes {};
    prefix_bytes.reserve(max_required_bytes);
    for (const auto& frame : frames) {
        if (frame.type != QuicPresentationFrameType::crypto ||
            !frame.crypto_offset.has_value() ||
            !frame.crypto_length.has_value() ||
            !frame.crypto_data_offset_in_plaintext.has_value()) {
            continue;
        }

        const auto crypto_offset = static_cast<std::size_t>(*frame.crypto_offset);
        if (crypto_offset > prefix_bytes.size()) {
            break;
        }

        const auto crypto_length = *frame.crypto_length;
        const auto plaintext_offset = *frame.crypto_data_offset_in_plaintext;
        if (plaintext_offset > plaintext_bytes.size() ||
            crypto_length > plaintext_bytes.size() - plaintext_offset) {
            break;
        }

        const auto copy_start = prefix_bytes.size() > crypto_offset
            ? prefix_bytes.size() - crypto_offset
            : 0U;
        if (copy_start >= crypto_length) {
            continue;
        }

        const auto max_copy_length = std::min<std::size_t>(
            crypto_length - copy_start,
            max_required_bytes > prefix_bytes.size() ? max_required_bytes - prefix_bytes.size() : 0U
        );
        if (max_copy_length == 0U) {
            continue;
        }

        prefix_bytes.insert(
            prefix_bytes.end(),
            plaintext_bytes.begin() + static_cast<std::ptrdiff_t>(plaintext_offset + copy_start),
            plaintext_bytes.begin() + static_cast<std::ptrdiff_t>(plaintext_offset + copy_start + max_copy_length)
        );
        if (prefix_bytes.size() >= max_required_bytes) {
            break;
        }
    }

    if (prefix_bytes.empty()) {
        return std::nullopt;
    }
    return prefix_bytes;
}

std::size_t required_quic_tls_handshake_prefix_bytes(
    std::span<const TlsHandshakeModel> handshakes
) {
    std::size_t required_bytes = 0U;
    for (const auto& handshake : handshakes) {
        required_bytes = std::max(required_bytes, handshake.source_offset + handshake.available_bytes);
    }
    return required_bytes;
}

const SelectedPacketByteViewDescriptor* find_view_in_scope(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope
) {
    for (const auto& view : presentation.views) {
        if (view.id.kind == kind && view.id.scope == scope) {
            return &view;
        }
    }
    return nullptr;
}

std::vector<const SelectedPacketByteViewDescriptor*> find_quic_crypto_parent_views(
    const SelectedPacketBytePresentation& presentation,
    const std::uint8_t scope,
    const TlsHandshakeModel& handshake
) {
    const auto handshake_begin = static_cast<std::uint64_t>(handshake.source_offset);
    const auto handshake_end = handshake_begin + handshake.available_bytes;

    std::vector<const SelectedPacketByteViewDescriptor*> matches {};
    for (const auto& view : presentation.views) {
        if (view.id.kind != SelectedPacketByteViewKind::quic_crypto_data ||
            view.id.scope != scope ||
            !view.quic_crypto_stream_offset.has_value()) {
            continue;
        }

        const auto frame_begin = *view.quic_crypto_stream_offset;
        const auto frame_end = frame_begin + view.captured_length;
        if (handshake_end > frame_begin && handshake_begin < frame_end) {
            matches.push_back(&view);
        }
    }

    return matches;
}

void append_quic_tls_handshake_views(
    SelectedPacketBytePresentation& presentation,
    QuicPresentationResult& quic_presentation,
    const QuicPresentationPacket& quic_packet,
    const std::uint8_t packet_scope,
    const SelectedPacketByteOwnerId& owner_id,
    const std::uint32_t owner_captured_length
) {
    static_cast<void>(owner_captured_length);
    if (quic_packet.tls_handshakes.empty()) {
        return;
    }

    const auto* owner = presentation.find_derived_owner(owner_id);
    if (owner == nullptr) {
        return;
    }

    const auto crypto_prefix_bytes = build_quic_crypto_prefix_bytes(
        std::span<const std::uint8_t>(owner->bytes.data(), owner->bytes.size()),
        std::span<const QuicPresentationFrame>(quic_packet.frames.data(), quic_packet.frames.size()),
        std::span<const TlsHandshakeModel>(quic_packet.tls_handshakes.data(), quic_packet.tls_handshakes.size())
    );
    const auto required_prefix_bytes = required_quic_tls_handshake_prefix_bytes(
        std::span<const TlsHandshakeModel>(quic_packet.tls_handshakes.data(), quic_packet.tls_handshakes.size())
    );
    const bool local_crypto_prefix_is_complete =
        crypto_prefix_bytes.has_value() &&
        crypto_prefix_bytes->size() >= required_prefix_bytes;

    if (local_crypto_prefix_is_complete) {
        const auto crypto_owner_id = append_derived_owner(
            presentation.derived_owners,
            SelectedPacketByteOwnerKind::quic_crypto_prefix,
            static_cast<std::size_t>(packet_scope),
            *crypto_prefix_bytes
        );
        if (!crypto_owner_id.has_value()) {
            return;
        }

        const auto* crypto_owner = presentation.find_derived_owner(*crypto_owner_id);
        if (crypto_owner == nullptr) {
            return;
        }
        const auto crypto_owner_length = narrow_u32(crypto_owner->bytes.size());
        if (!crypto_owner_length.has_value()) {
            return;
        }

        std::vector<std::vector<const SelectedPacketByteViewDescriptor*>> handshake_parent_views {};
        handshake_parent_views.reserve(quic_packet.tls_handshakes.size());
        bool needs_crypto_stream_parent = false;
        for (const auto& handshake : quic_packet.tls_handshakes) {
            auto matches = find_quic_crypto_parent_views(presentation, packet_scope, handshake);
            if (matches.empty() || matches.size() > 1U) {
                needs_crypto_stream_parent = true;
            }
            handshake_parent_views.push_back(std::move(matches));
        }

        std::optional<SelectedPacketByteViewId> crypto_stream_id {};
        std::optional<std::uint32_t> crypto_stream_frame_count {};
        if (needs_crypto_stream_parent) {
            const auto* plaintext_view = find_view_in_scope(
                presentation,
                SelectedPacketByteViewKind::quic_initial_plaintext,
                packet_scope
            );
            if (plaintext_view == nullptr) {
                return;
            }

            const auto frame_count = static_cast<std::uint32_t>(std::count_if(
                presentation.views.begin(),
                presentation.views.end(),
                [&](const SelectedPacketByteViewDescriptor& view) {
                    return view.id.kind == SelectedPacketByteViewKind::quic_crypto_data &&
                        view.id.scope == packet_scope;
                }
            ));
            if (frame_count == 0U) {
                return;
            }

            crypto_stream_frame_count = frame_count;
            crypto_stream_id = append_view(
                presentation.views,
                plaintext_view->id,
                *crypto_owner_id,
                SelectedPacketByteOwnerKind::quic_crypto_prefix,
                SelectedPacketByteViewRole::protocol_unit,
                SelectedPacketByteAssemblyKind::reassembled,
                SelectedPacketByteViewKind::quic_crypto_stream,
                packet_scope,
                *crypto_owner_length,
                0U,
                std::optional<std::uint32_t> {*crypto_owner_length},
                *crypto_owner_length,
                false,
                std::nullopt,
                crypto_stream_frame_count,
                SelectedPacketByteContributionUnitKind::quic_crypto_frame
            );
            if (!crypto_stream_id.has_value()) {
                return;
            }
        }

        for (std::size_t index = 0U; index < quic_packet.tls_handshakes.size(); ++index) {
            const auto& handshake = quic_packet.tls_handshakes[index];
            const auto& parent_views = handshake_parent_views[index];
            if (crypto_stream_id.has_value()) {
                append_tls_handshake_views(
                    presentation.views,
                    *crypto_stream_id,
                    *crypto_owner_id,
                    SelectedPacketByteOwnerKind::quic_crypto_prefix,
                    *crypto_owner_length,
                    packet_scope,
                    0U,
                    std::span<const TlsHandshakeModel>(&handshake, 1U),
                    SelectedPacketByteAssemblyKind::reassembled,
                    !parent_views.empty()
                        ? std::optional<std::uint32_t> {static_cast<std::uint32_t>(parent_views.size())}
                        : crypto_stream_frame_count,
                    SelectedPacketByteContributionUnitKind::quic_crypto_frame,
                    0U
                );
                continue;
            }

            if (parent_views.empty()) {
                continue;
            }

            append_tls_handshake_views(
                presentation.views,
                parent_views.front()->id,
                *crypto_owner_id,
                SelectedPacketByteOwnerKind::quic_crypto_prefix,
                *crypto_owner_length,
                packet_scope,
                0U,
                std::span<const TlsHandshakeModel>(&handshake, 1U),
                SelectedPacketByteAssemblyKind::packet_local,
                std::nullopt,
                std::nullopt,
                0U
            );
        }
        return;
    }

    if (quic_presentation.selected_crypto_prefix_payload.empty()) {
        return;
    }

    const auto crypto_owner_id = append_derived_owner(
        presentation.derived_owners,
        SelectedPacketByteOwnerKind::quic_crypto_prefix,
        static_cast<std::size_t>(packet_scope),
        std::move(quic_presentation.selected_crypto_prefix_payload)
    );
    if (!crypto_owner_id.has_value()) {
        return;
    }

    const auto* crypto_owner = presentation.find_derived_owner(*crypto_owner_id);
    if (crypto_owner == nullptr) {
        return;
    }
    const auto crypto_owner_length = narrow_u32(crypto_owner->bytes.size());
    if (!crypto_owner_length.has_value()) {
        return;
    }

    const auto* packet_view = find_view_in_scope(
        presentation,
        SelectedPacketByteViewKind::quic_initial_packet,
        packet_scope
    );
    const auto* plaintext_view = find_view_in_scope(
        presentation,
        SelectedPacketByteViewKind::quic_initial_plaintext,
        packet_scope
    );
    const auto parent_id =
        packet_view != nullptr
            ? std::optional<SelectedPacketByteViewId> {packet_view->id}
            : (plaintext_view != nullptr
                ? std::optional<SelectedPacketByteViewId> {plaintext_view->id}
                : std::nullopt);
    if (!parent_id.has_value()) {
        return;
    }

    const auto crypto_stream_id = append_view(
        presentation.views,
        parent_id,
        *crypto_owner_id,
        SelectedPacketByteOwnerKind::quic_crypto_prefix,
        SelectedPacketByteViewRole::protocol_unit,
        SelectedPacketByteAssemblyKind::reassembled,
        SelectedPacketByteViewKind::quic_crypto_stream,
        packet_scope,
        *crypto_owner_length,
        0U,
        std::optional<std::uint32_t> {*crypto_owner_length},
        *crypto_owner_length,
        false,
        std::nullopt,
        quic_presentation.selected_crypto_prefix_contributing_frame_count,
        SelectedPacketByteContributionUnitKind::quic_crypto_frame
    );
    if (!crypto_stream_id.has_value()) {
        return;
    }

    append_tls_handshake_views(
        presentation.views,
        *crypto_stream_id,
        *crypto_owner_id,
        SelectedPacketByteOwnerKind::quic_crypto_prefix,
        *crypto_owner_length,
        packet_scope,
        0U,
        std::span<const TlsHandshakeModel>(quic_packet.tls_handshakes.data(), quic_packet.tls_handshakes.size()),
        SelectedPacketByteAssemblyKind::reassembled,
        quic_presentation.selected_crypto_prefix_contributing_frame_count,
        SelectedPacketByteContributionUnitKind::quic_crypto_frame,
        0U
    );
}

}  // namespace

const SelectedPacketByteViewDescriptor* SelectedPacketBytePresentation::find_view(
    const SelectedPacketByteViewId& id
) const noexcept {
    const auto it = std::find_if(views.begin(), views.end(), [&](const SelectedPacketByteViewDescriptor& view) {
        return view.id == id;
    });
    return it != views.end() ? &(*it) : nullptr;
}

const SelectedPacketByteDerivedOwner* SelectedPacketBytePresentation::find_derived_owner(
    const SelectedPacketByteOwnerId& id
) const noexcept {
    const auto it = std::find_if(
        derived_owners.begin(),
        derived_owners.end(),
        [&](const SelectedPacketByteDerivedOwner& owner) {
            return owner.id == id;
        }
    );
    return it != derived_owners.end() ? &(*it) : nullptr;
}

SelectedPacketBytePresentation build_selected_packet_byte_presentation(
    const PacketDetails& details,
    const PacketRef& packet,
    SelectedPacketByteBuildOptions options
) {
    SelectedPacketBytePresentation presentation {};
    presentation.owner_captured_length = packet.captured_length;

    std::optional<SelectedPacketByteViewId> outer_parent {};
    std::optional<PacketByteRange> outer_payload_range {};
    std::optional<PacketByteRange> outer_ip_range {};
    const auto outer_vlan_count = details.has_pbb
        ? details.encapsulating_vlan_tags.size()
        : details.vlan_tags.size();

    if (details.has_linux_cooked &&
        details.linux_cooked.link_type == kLinkTypeLinuxSll &&
        packet.captured_length >= kLinuxSllHeaderSize) {
        const PacketByteRange sll_payload_range {
            .offset = kLinuxSllHeaderSize,
            .declared_length = packet.original_length >= kLinuxSllHeaderSize
                ? std::optional<std::uint32_t> {packet.original_length - kLinuxSllHeaderSize}
                : std::optional<std::uint32_t> {0U},
            .captured_length = packet.captured_length - kLinuxSllHeaderSize,
            .truncated = packet.captured_length < packet.original_length,
        };
        const auto sll_id = append_protocol_unit_view(
            presentation.views,
            outer_parent,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::linux_sll,
            0U,
            presentation.owner_captured_length,
            PacketByteRange {
                .offset = 0U,
                .declared_length = std::optional<std::uint32_t> {packet.original_length},
                .captured_length = packet.captured_length,
                .truncated = packet.captured_length < packet.original_length,
            },
            sll_payload_range
        );
        if (sll_id.has_value()) {
            outer_parent = sll_id;
        }
        outer_payload_range = sll_payload_range;
    } else if (details.has_linux_cooked &&
        details.linux_cooked.link_type == kLinkTypeLinuxSll2 &&
        packet.captured_length >= kLinuxSll2HeaderSize) {
        const PacketByteRange sll2_payload_range {
            .offset = kLinuxSll2HeaderSize,
            .declared_length = packet.original_length >= kLinuxSll2HeaderSize
                ? std::optional<std::uint32_t> {packet.original_length - kLinuxSll2HeaderSize}
                : std::optional<std::uint32_t> {0U},
            .captured_length = packet.captured_length - kLinuxSll2HeaderSize,
            .truncated = packet.captured_length < packet.original_length,
        };
        const auto sll2_id = append_protocol_unit_view(
            presentation.views,
            outer_parent,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::linux_sll2,
            0U,
            presentation.owner_captured_length,
            PacketByteRange {
                .offset = 0U,
                .declared_length = std::optional<std::uint32_t> {packet.original_length},
                .captured_length = packet.captured_length,
                .truncated = packet.captured_length < packet.original_length,
            },
            sll2_payload_range
        );
        if (sll2_id.has_value()) {
            outer_parent = sll2_id;
        }
        outer_payload_range = sll2_payload_range;
    } else if (details.has_ethernet && details.ethernet.payload_range.has_value()) {
        outer_payload_range = details.ethernet.payload_range;
        const auto outer_ethernet_kind = details.ethernet.uses_length_field
            ? SelectedPacketByteViewKind::ieee8023_payload
            : SelectedPacketByteViewKind::ethernet_payload;
        const auto ethernet_id = append_protocol_unit_from_payload_range(
            presentation.views,
            outer_parent,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            outer_ethernet_kind,
            0U,
            presentation.owner_captured_length,
            0U,
            *details.ethernet.payload_range
        );
        if (ethernet_id.has_value()) {
            outer_parent = ethernet_id;
        }
        outer_parent = append_vlan_payload_chain(
            presentation.views,
            outer_parent,
            presentation.owner_captured_length,
            *details.ethernet.payload_range,
            outer_vlan_count,
            SelectedPacketByteViewKind::vlan_payload
        );
        for (std::size_t index = 0U; outer_payload_range.has_value() && index < outer_vlan_count; ++index) {
            outer_payload_range = shift_payload_range(*outer_payload_range, 4U);
        }
    }

    if (details.mpls_payload_range.has_value()) {
        const auto mpls_offset = outer_payload_range.has_value()
            ? outer_payload_range->offset
            : details.mpls_payload_range->offset;
        const auto mpls_id = append_protocol_unit_from_payload_range(
            presentation.views,
            outer_parent,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            SelectedPacketByteViewKind::mpls_payload,
            0U,
            presentation.owner_captured_length,
            mpls_offset,
            *details.mpls_payload_range
        );
        if (mpls_id.has_value()) {
            outer_parent = mpls_id;
        }
        outer_payload_range = details.mpls_payload_range;
    }

    bool consumed_by_inner_link_branch = false;
    if (details.has_pbb && outer_parent.has_value() && details.pbb.unit_range.has_value()) {
        std::optional<PacketByteRange> pbb_payload_range {};
        if (details.pbb.unit_range->captured_length > kPbbHeaderSize) {
            pbb_payload_range = PacketByteRange {
                .offset = details.pbb.unit_range->offset + kPbbHeaderSize,
                .declared_length = details.pbb.unit_range->declared_length.has_value() &&
                        *details.pbb.unit_range->declared_length > kPbbHeaderSize
                    ? std::optional<std::uint32_t> {*details.pbb.unit_range->declared_length - kPbbHeaderSize}
                    : std::nullopt,
                .captured_length = details.pbb.unit_range->captured_length - kPbbHeaderSize,
                .truncated = details.pbb.unit_range->truncated,
            };
        }
        const auto pbb_id = append_protocol_unit_view(
            presentation.views,
            outer_parent,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            SelectedPacketByteViewRole::protocol_unit,
            SelectedPacketByteViewKind::pbb,
            0U,
            presentation.owner_captured_length,
            *details.pbb.unit_range,
            pbb_payload_range
        );
        append_inner_ethernet_branch(details, presentation.views, presentation.owner_captured_length, pbb_id);
        consumed_by_inner_link_branch = true;
    } else {
        const auto llc_snap_branch = append_llc_snap_branch(
            details.has_llc,
            details.llc,
            details.has_snap,
            details.snap,
            presentation.views,
            presentation.owner_captured_length,
            outer_parent,
            outer_payload_range
        );
        outer_parent = llc_snap_branch.parent_id;
        outer_payload_range = llc_snap_branch.child_payload_range;

        if (details.has_pppoe) {
            const auto pppoe_branch = append_pppoe_branch(
                details.pppoe,
                presentation.views,
                presentation.owner_captured_length,
                outer_parent,
                outer_payload_range
            );
            outer_parent = pppoe_branch.parent_id;
            outer_payload_range = pppoe_branch.child_payload_range;
        }
    }

    if (!consumed_by_inner_link_branch && details.has_arp && outer_parent.has_value() && outer_payload_range.has_value()) {
        append_arp_packet_view(
            presentation.views,
            outer_parent,
            presentation.owner_captured_length,
            *outer_payload_range,
            details.arp
        );
    }

    std::optional<SelectedPacketByteViewId> outer_ip_id {};
    std::optional<SelectedPacketByteViewId> outer_tcp_id {};
    if (!consumed_by_inner_link_branch && details.has_ipv4 && details.ipv4.payload_range.has_value()) {
        outer_ip_range = details.ipv4.payload_range;
        const auto outer_ipv4_offset = outer_payload_range.has_value()
            ? outer_payload_range->offset
            : (details.ipv4.payload_range->offset >= static_cast<std::uint32_t>(details.ipv4.header_length_bytes)
                ? details.ipv4.payload_range->offset - static_cast<std::uint32_t>(details.ipv4.header_length_bytes)
                : 0U);
        outer_ip_id = append_protocol_unit_from_payload_range(
            presentation.views,
            outer_parent,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            SelectedPacketByteViewKind::ipv4_payload,
            0U,
            presentation.owner_captured_length,
            outer_ipv4_offset,
            *details.ipv4.payload_range
        );
    } else if (!consumed_by_inner_link_branch && details.has_ipv6 && details.ipv6.payload_range.has_value()) {
        outer_ip_range = details.ipv6.payload_range;
        const auto outer_ipv6_offset = outer_payload_range.has_value()
            ? outer_payload_range->offset
            : (details.ipv6.payload_range->offset >= 40U ? details.ipv6.payload_range->offset - 40U : 0U);
        outer_ip_id = append_protocol_unit_from_payload_range(
            presentation.views,
            outer_parent,
            kCapturedPacketOwnerId,
            presentation.owner_kind,
            SelectedPacketByteViewKind::ipv6_payload,
            0U,
            presentation.owner_captured_length,
            outer_ipv6_offset,
            *details.ipv6.payload_range
        );
    }

    std::optional<SelectedPacketByteViewId> outer_udp_id {};
    if (!consumed_by_inner_link_branch && !details.has_ah && details.has_tcp && outer_ip_range.has_value()) {
        outer_tcp_id = append_tcp_segment_view(
            presentation.views,
            outer_ip_id,
            presentation.owner_captured_length,
            *outer_ip_range,
            details.tcp,
            SelectedPacketByteViewKind::tcp_payload
        );
    }
    if (!consumed_by_inner_link_branch && !details.has_ah && details.has_udp && outer_ip_range.has_value()) {
        outer_udp_id = append_udp_datagram_view(
            presentation.views,
            outer_ip_id,
            presentation.owner_captured_length,
            *outer_ip_range,
            details.udp,
            SelectedPacketByteViewKind::udp_payload
        );
    }

    const auto* outer_udp_view = outer_udp_id.has_value() ? presentation.find_view(*outer_udp_id) : nullptr;
    if (!consumed_by_inner_link_branch) {
        append_overlay_payload_branches(
            details,
            presentation.views,
            presentation.owner_captured_length,
            outer_ip_id,
            outer_ip_range,
            outer_udp_id
        );
    }
    const QuicPresentationResult empty_quic_presentation {};
    const auto& quic_presentation_ref =
        options.quic_presentation.has_value()
            ? *options.quic_presentation
            : empty_quic_presentation;
    const auto quic_packet_ids = append_quic_packet_views(
        presentation,
        quic_presentation_ref,
        outer_udp_view
    );
    append_quic_initial_plaintext_views(
        presentation,
        std::move(options.quic_presentation),
        std::span<const std::optional<SelectedPacketByteViewId>>(quic_packet_ids.data(), quic_packet_ids.size())
    );

    if (!options.packet_bytes.empty()) {
        DnsPacketProtocolAnalyzer dns_analyzer {};
        if (const auto dns_message = dns_analyzer.inspect_message(options.packet_bytes, packet.data_link_type);
            dns_message.has_value()) {
            if (outer_udp_id.has_value() &&
                !details.has_vxlan &&
                !details.has_geneve &&
                !details.has_gtpu &&
                quic_presentation_ref.packets.empty()) {
                if (const auto* udp_view = presentation.find_view(*outer_udp_id); udp_view != nullptr) {
                    append_dns_message_view(presentation, *outer_udp_id, *udp_view, *dns_message);
                }
            } else if (outer_tcp_id.has_value() && dns_message->tcp_length_prefixed) {
                if (const auto* tcp_view = presentation.find_view(*outer_tcp_id); tcp_view != nullptr) {
                    append_dns_message_view(presentation, *outer_tcp_id, *tcp_view, *dns_message);
                }
            }
        }
    }

    if (outer_tcp_id.has_value() && !options.packet_bytes.empty()) {
        const auto* tcp_view = presentation.find_view(*outer_tcp_id);
        if (tcp_view != nullptr && tcp_view->payload_range.has_value()) {
            const auto tls_payload_offset = static_cast<std::size_t>(tcp_view->payload_range->offset);
            const auto tls_payload_length = static_cast<std::size_t>(tcp_view->payload_range->captured_length);
            if (tls_payload_offset <= options.packet_bytes.size() &&
                tls_payload_length <= options.packet_bytes.size() - tls_payload_offset) {
                for (auto& reconstructed_record : options.reconstructed_tls_records) {
                    if (reconstructed_record.captured_bytes.empty()) {
                        continue;
                    }
                    TlsInspectionParser parser {};
                    const auto inspection = parser.inspect(
                        std::span<const std::uint8_t>(
                            reconstructed_record.captured_bytes.data(),
                            reconstructed_record.captured_bytes.size()
                        ),
                        reconstructed_record.initial_parser_context
                    );
                    const auto owner_id = append_derived_owner(
                        presentation.derived_owners,
                        SelectedPacketByteOwnerKind::tls_reconstructed_record,
                        0U,
                        std::move(reconstructed_record.captured_bytes)
                    );
                    if (!owner_id.has_value()) {
                        continue;
                    }
                    const auto* owner = presentation.find_derived_owner(*owner_id);
                    if (owner == nullptr) {
                        continue;
                    }
                    const auto owner_length = narrow_u32(owner->bytes.size());
                    if (!owner_length.has_value()) {
                        continue;
                    }
                    const auto contribution_count =
                        reconstructed_record.contributions.size() > 1U
                            ? std::optional<std::uint32_t> {
                                static_cast<std::uint32_t>(reconstructed_record.contributions.size())
                            }
                            : std::nullopt;
                    const auto assembly_kind =
                        contribution_count.has_value()
                            ? SelectedPacketByteAssemblyKind::reassembled
                            : SelectedPacketByteAssemblyKind::packet_local;
                    if (!inspection.records.empty()) {
                        append_tls_record_view(
                            presentation,
                            outer_tcp_id,
                            *owner_id,
                            SelectedPacketByteOwnerKind::tls_reconstructed_record,
                            *owner_length,
                            0U,
                            inspection.records.front(),
                            0U,
                            assembly_kind,
                            contribution_count,
                            contribution_count.has_value()
                                ? std::optional<SelectedPacketByteContributionUnitKind> {
                                    SelectedPacketByteContributionUnitKind::tcp_segment
                                }
                                : std::nullopt
                        );
                    }
                }

                const auto reassembled_prefix_bytes = std::min<std::size_t>(
                    selected_packet_reassembled_tls_prefix_bytes(options),
                    tls_payload_length
                );
                const auto remaining_payload = std::span<const std::uint8_t>(
                    options.packet_bytes.data() + static_cast<std::ptrdiff_t>(tls_payload_offset + reassembled_prefix_bytes),
                    tls_payload_length - reassembled_prefix_bytes
                );
                auto tls_context = selected_packet_starting_tls_context(options);
                if (tls_payload_is_owned_by_tls(remaining_payload, tls_context)) {
                    TlsInspectionParser parser {};
                    const auto inspection = parser.inspect(remaining_payload, tls_context);
                    for (const auto& record : inspection.records) {
                        append_tls_record_view(
                            presentation,
                            outer_tcp_id,
                            kCapturedPacketOwnerId,
                            SelectedPacketByteOwnerKind::captured_packet,
                            presentation.owner_captured_length,
                            0U,
                            record,
                            static_cast<std::uint32_t>(tls_payload_offset + reassembled_prefix_bytes)
                        );
                    }
                }
            }
        }
    }

    append_packet_data_view(
        presentation,
        details,
        options,
        outer_tcp_id,
        outer_udp_id
    );

    ensure_captured_packet_root_when_needed(presentation, packet);

    return presentation;
}

SelectedPacketBytePresentation build_captured_packet_fallback_presentation(
    const PacketRef& packet
) {
    SelectedPacketBytePresentation presentation {};
    presentation.owner_captured_length = packet.captured_length;

    static_cast<void>(append_view(
        presentation.views,
        std::nullopt,
        kCapturedPacketOwnerId,
        presentation.owner_kind,
        SelectedPacketByteViewRole::protocol_unit,
        SelectedPacketByteAssemblyKind::packet_local,
        SelectedPacketByteViewKind::frame,
        0U,
        presentation.owner_captured_length,
        0U,
        std::optional<std::uint32_t> {packet.original_length},
        packet.captured_length,
        packet.captured_length < packet.original_length
    ));

    return presentation;
}

std::optional<SelectedPacketByteMaterialization> materialize_selected_packet_byte_view(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes,
    const SelectedPacketByteRangeMode mode
) noexcept {
    const auto* view = presentation.find_view(id);
    if (view == nullptr) {
        return std::nullopt;
    }

    std::span<const std::uint8_t> resolved_owner_bytes {};
    if (view->owner_kind == SelectedPacketByteOwnerKind::captured_packet) {
        if (owner_bytes.size() < presentation.owner_captured_length) {
            return std::nullopt;
        }
        resolved_owner_bytes = owner_bytes;
    } else {
        const auto* owner = presentation.find_derived_owner(view->owner_id);
        if (owner == nullptr) {
            return std::nullopt;
        }
        resolved_owner_bytes = std::span<const std::uint8_t>(owner->bytes.data(), owner->bytes.size());
    }

    if (mode == SelectedPacketByteRangeMode::payload_only) {
        if (!view->payload_range.has_value()) {
            return std::nullopt;
        }
    }

    const auto offset = mode == SelectedPacketByteRangeMode::payload_only
        ? view->payload_range->offset
        : view->offset;
    const auto captured_length = mode == SelectedPacketByteRangeMode::payload_only
        ? view->payload_range->captured_length
        : view->captured_length;
    if (offset > resolved_owner_bytes.size() ||
        captured_length > resolved_owner_bytes.size() - offset) {
        return std::nullopt;
    }

    return SelectedPacketByteMaterialization {
        .descriptor = view,
        .mode = mode,
        .bytes = resolved_owner_bytes.subspan(offset, captured_length),
    };
}

std::optional<std::string> format_selected_packet_byte_view_hex_dump(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes,
    const HexDumpService& hex_dump_service,
    const SelectedPacketByteRangeMode mode
) {
    const auto materialized = materialize_selected_packet_byte_view(presentation, id, owner_bytes, mode);
    if (!materialized.has_value()) {
        return std::nullopt;
    }
    return hex_dump_service.format(materialized->bytes);
}

std::optional<SelectedPacketByteViewId> select_whole_captured_packet_view_id(
    const SelectedPacketBytePresentation& presentation
) noexcept {
    const auto frame_it = std::find_if(
        presentation.views.begin(),
        presentation.views.end(),
        [&](const SelectedPacketByteViewDescriptor& view) {
            return view.id.kind == SelectedPacketByteViewKind::frame &&
                view.owner_kind == SelectedPacketByteOwnerKind::captured_packet &&
                view.role == SelectedPacketByteViewRole::protocol_unit &&
                !view.parent_id.has_value() &&
                view.offset == 0U &&
                view.captured_length == presentation.owner_captured_length;
        }
    );
    if (frame_it != presentation.views.end()) {
        return frame_it->id;
    }

    const auto full_packet_root_it = std::find_if(
        presentation.views.begin(),
        presentation.views.end(),
        [&](const SelectedPacketByteViewDescriptor& view) {
            return view.owner_kind == SelectedPacketByteOwnerKind::captured_packet &&
                view.role == SelectedPacketByteViewRole::protocol_unit &&
                !view.parent_id.has_value() &&
                view.offset == 0U &&
                view.captured_length == presentation.owner_captured_length;
        }
    );
    if (full_packet_root_it != presentation.views.end()) {
        return full_packet_root_it->id;
    }

    return std::nullopt;
}

std::string format_selected_packet_byte_view_stable_id(const SelectedPacketByteViewId& id) {
    std::ostringstream out {};
    out << view_kind_key(id.kind) << ':' << static_cast<unsigned int>(id.scope) << ':' << static_cast<unsigned int>(id.occurrence);
    return out.str();
}

std::optional<SelectedPacketByteViewId> parse_selected_packet_byte_view_stable_id(const std::string_view stable_id) {
    const auto first_separator = stable_id.find(':');
    if (first_separator == std::string_view::npos) {
        return std::nullopt;
    }
    const auto second_separator = stable_id.find(':', first_separator + 1U);
    if (second_separator == std::string_view::npos) {
        return std::nullopt;
    }

    const auto kind_key = stable_id.substr(0U, first_separator);
    const auto parsed_kind = parse_view_kind_key(kind_key);
    if (!parsed_kind.has_value()) {
        return std::nullopt;
    }

    const auto scope_text = stable_id.substr(first_separator + 1U, second_separator - first_separator - 1U);
    const auto occurrence_text = stable_id.substr(second_separator + 1U);
    if (scope_text.empty() || occurrence_text.empty()) {
        return std::nullopt;
    }

    try {
        const auto scope_value = static_cast<unsigned long>(std::stoul(std::string {scope_text}));
        const auto occurrence_value = static_cast<unsigned long>(std::stoul(std::string {occurrence_text}));
        if (scope_value > 0xFFUL || occurrence_value > 0xFFUL) {
            return std::nullopt;
        }

        return SelectedPacketByteViewId {
            .kind = *parsed_kind,
            .scope = static_cast<std::uint8_t>(scope_value),
            .occurrence = static_cast<std::uint8_t>(occurrence_value),
        };
    } catch (...) {
        return std::nullopt;
    }
}

std::vector<SelectedPacketByteViewPresentationDescriptor> build_selected_packet_byte_view_descriptors(
    const SelectedPacketBytePresentation& presentation
) {
    std::vector<SelectedPacketByteViewPresentationDescriptor> descriptors {};
    descriptors.reserve(presentation.views.size());

    auto resolve_depth = [&](const SelectedPacketByteViewDescriptor& view) {
        std::size_t depth = 0U;
        auto parent_id = view.parent_id;
        while (parent_id.has_value()) {
            const auto* parent = presentation.find_view(*parent_id);
            if (parent == nullptr) {
                break;
            }
            ++depth;
            parent_id = parent->parent_id;
        }
        return depth;
    };

    for (const auto& view : presentation.views) {
        descriptors.push_back(SelectedPacketByteViewPresentationDescriptor {
            .stable_id = format_selected_packet_byte_view_stable_id(view.id),
            .label = view_label(view),
            .parent_stable_id = view.parent_id.has_value()
                ? std::optional<std::string> {format_selected_packet_byte_view_stable_id(*view.parent_id)}
                : std::nullopt,
            .depth = resolve_depth(view),
            .owner_kind = owner_kind_key(view.owner_kind),
            .role = view_role_key(view.role),
            .assembly_kind = assembly_kind_key(view.assembly_kind),
            .available_length = view.captured_length,
            .declared_length = view.declared_length,
            .state = descriptor_state(view),
            .supports_payload_only = view.payload_range.has_value(),
            .payload_available_length = view.payload_range.has_value()
                ? std::optional<std::uint32_t> {view.payload_range->captured_length}
                : std::nullopt,
            .payload_declared_length = view.payload_range.has_value()
                ? view.payload_range->declared_length
                : std::nullopt,
            .payload_state = payload_state(view),
            .contributing_unit_count = view.contributing_unit_count,
            .contributing_unit_kind = view.contributing_unit_kind.has_value()
                ? std::optional<std::string> {contribution_unit_kind_key(*view.contributing_unit_kind)}
                : std::nullopt,
            .quic_crypto_stream_offset = view.quic_crypto_stream_offset,
        });
    }

    return descriptors;
}

std::optional<SelectedPacketByteViewContent> format_selected_packet_byte_view_content(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    std::span<const std::uint8_t> owner_bytes,
    const HexDumpService& hex_dump_service,
    const SelectedPacketByteRangeMode mode
) {
    const auto materialized = materialize_selected_packet_byte_view(presentation, id, owner_bytes, mode);
    if (!materialized.has_value() || materialized->descriptor == nullptr) {
        return std::nullopt;
    }

    const auto available_length = mode == SelectedPacketByteRangeMode::payload_only
        ? materialized->descriptor->payload_range->captured_length
        : materialized->descriptor->captured_length;
    const auto declared_length = mode == SelectedPacketByteRangeMode::payload_only
        ? materialized->descriptor->payload_range->declared_length
        : materialized->descriptor->declared_length;
    const auto state = mode == SelectedPacketByteRangeMode::payload_only
        ? *payload_state(*materialized->descriptor)
        : descriptor_state(*materialized->descriptor);

    return SelectedPacketByteViewContent {
        .stable_id = format_selected_packet_byte_view_stable_id(id),
        .label = view_label(*materialized->descriptor),
        .mode = mode,
        .assembly_kind = assembly_kind_key(materialized->descriptor->assembly_kind),
        .available_length = available_length,
        .declared_length = declared_length,
        .state = state,
        .contributing_unit_count = materialized->descriptor->contributing_unit_count,
        .contributing_unit_kind = materialized->descriptor->contributing_unit_kind.has_value()
            ? std::optional<std::string> {contribution_unit_kind_key(*materialized->descriptor->contributing_unit_kind)}
            : std::nullopt,
        .formatted_text = hex_dump_service.format(materialized->bytes),
    };
}

}  // namespace pfl::session_detail
