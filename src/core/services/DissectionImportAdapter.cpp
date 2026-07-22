#include "core/services/DissectionImportAdapter.h"

namespace pfl {

namespace {

[[nodiscard]] constexpr std::uint16_t adapted_port_value(
    const bool has_ports,
    const std::uint16_t port
) noexcept {
    return has_ports ? port : static_cast<std::uint16_t>(0U);
}

PacketRef make_import_semantic_packet_ref(const dissection::ImportDissectionFacts& facts) noexcept {
    PacketRef packet_ref {};
    if (facts.has_transport_payload_length) {
        packet_ref.payload_length = facts.captured_transport_payload_length;
    }
    if (facts.has_tcp_flags && facts.terminal_protocol == ProtocolId::tcp) {
        packet_ref.tcp_flags = facts.tcp_flags;
    }
    packet_ref.is_ip_fragmented =
        (facts.has_ipv4_fragmentation && facts.ipv4_fragmentation.is_fragmented) ||
        (facts.has_ipv6_fragmentation && facts.ipv6_fragmentation.has_fragment_header);
    return packet_ref;
}

DecodedPacket make_ipv4_decoded_packet(const dissection::ImportDissectionFacts& facts) noexcept {
    DecodedPacket decoded {};
    decoded.ipv4 = IngestedPacketV4 {
        .flow_key = FlowKeyV4 {
            .src_addr = facts.src_addr_v4,
            .dst_addr = facts.dst_addr_v4,
            .src_port = adapted_port_value(facts.has_ports, facts.src_port),
            .dst_port = adapted_port_value(facts.has_ports, facts.dst_port),
            .protocol = facts.terminal_protocol,
        },
        .packet_ref = make_import_semantic_packet_ref(facts),
    };
    decoded.protocol_path_builder = facts.physical_path;
    return decoded;
}

DecodedPacket make_ipv6_decoded_packet(const dissection::ImportDissectionFacts& facts) noexcept {
    DecodedPacket decoded {};
    decoded.ipv6 = IngestedPacketV6 {
        .flow_key = FlowKeyV6 {
            .src_addr = facts.src_addr_v6,
            .dst_addr = facts.dst_addr_v6,
            .src_port = adapted_port_value(facts.has_ports, facts.src_port),
            .dst_port = adapted_port_value(facts.has_ports, facts.dst_port),
            .protocol = facts.terminal_protocol,
        },
        .packet_ref = make_import_semantic_packet_ref(facts),
    };
    decoded.protocol_path_builder = facts.physical_path;
    return decoded;
}

}  // namespace

DissectionImportDecision adapt_dissection_import_facts(
    const dissection::ImportDissectionFacts& facts
) noexcept {
    DissectionImportDecision decision {
        .outcome = facts.outcome,
        .decoded_packet = std::nullopt,
        .final_status = facts.final_status,
        .stop_reason = facts.stop_reason,
        .physical_path = facts.physical_path,
        .family = facts.family,
        .terminal_protocol = facts.terminal_protocol,
        .path_overflowed = facts.path_overflowed || facts.physical_path.overflowed(),
    };

    if (facts.outcome != dissection::ImportDissectionOutcome::recognized_flow ||
        decision.path_overflowed ||
        facts.terminal_protocol == ProtocolId::unknown ||
        !facts.has_flow_addresses) {
        return decision;
    }

    if (facts.family == dissection::DissectionAddressFamily::ipv4) {
        decision.decoded_packet = make_ipv4_decoded_packet(facts);
        return decision;
    }

    if (facts.family == dissection::DissectionAddressFamily::ipv6) {
        decision.decoded_packet = make_ipv6_decoded_packet(facts);
        return decision;
    }

    return decision;
}

}  // namespace pfl
