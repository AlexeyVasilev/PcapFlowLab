#include "app/session/SelectedFlowPacketSemantics.h"

#include "app/session/CaptureSession.h"
#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/RuntimeDissection.h"

namespace pfl::session_detail {

namespace {

std::optional<std::uint32_t> derive_original_transport_payload_length_from_metadata(
    const std::uint32_t captured_length,
    const std::uint32_t original_length,
    const std::uint32_t captured_transport_payload_length,
    const bool is_ip_fragmented
) {
    if (is_ip_fragmented) {
        return std::nullopt;
    }

    if (captured_length < captured_transport_payload_length || original_length < captured_length) {
        return std::nullopt;
    }

    if (original_length == captured_length) {
        return captured_transport_payload_length;
    }

    if (captured_transport_payload_length == 0U) {
        return std::nullopt;
    }

    const auto transport_payload_offset =
        static_cast<std::size_t>(captured_length) - static_cast<std::size_t>(captured_transport_payload_length);
    if (static_cast<std::size_t>(original_length) < transport_payload_offset) {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(static_cast<std::size_t>(original_length) - transport_payload_offset);
}

std::optional<std::uint32_t> derive_original_transport_payload_length_from_row_metadata(const PacketRow& row) {
    return derive_original_transport_payload_length_from_metadata(
        row.captured_length,
        row.original_length,
        row.payload_length,
        row.is_ip_fragmented
    );
}

void apply_transient_metadata_to_row(
    PacketRow& row,
    const TransientPacketDerivedMetadata& metadata
) {
    row.derived_payload_length =
        metadata.original_transport_payload_length.has_value()
            ? metadata.original_transport_payload_length
            : metadata.captured_transport_payload_length;
    row.derived_is_ip_fragmented = metadata.is_ip_fragmented;
    if (metadata.tcp_flags.has_value()) {
        row.derived_tcp_flags_text = format_tcp_flags_text(*metadata.tcp_flags);
    }
}

bool supports_transient_transport_payload_length(const ProtocolId protocol) noexcept {
    return protocol == ProtocolId::tcp ||
           protocol == ProtocolId::udp ||
           protocol == ProtocolId::sctp;
}

dissection::RuntimeDissectionFacts derive_runtime_facts(
    const std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
) {
    return dissection::derive_runtime_dissection_facts(
        packet_bytes,
        packet.captured_length,
        packet.original_length,
        packet.data_link_type
    );
}

TransientPacketDerivedMetadata transient_metadata_from_runtime_facts(
    const dissection::RuntimeDissectionFacts& facts
) {
    TransientPacketDerivedMetadata metadata {};
    if (supports_transient_transport_payload_length(facts.terminal_protocol)) {
        metadata.captured_transport_payload_length = facts.captured_transport_payload_length;
        metadata.original_transport_payload_length = facts.original_transport_payload_length;
        metadata.terminal_transport_payload_bounds = facts.terminal_transport_payload_bounds;
    }
    if (facts.terminal_protocol == ProtocolId::tcp) {
        metadata.tcp_flags = facts.tcp_flags;
    }
    metadata.is_ip_fragmented = facts.is_ip_fragmented;
    return metadata;
}

}  // namespace

std::optional<bool> derive_ip_fragmentation_state_from_packet_details(
    const std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet,
    const PacketDetails& details
) {
    if (details.has_ipv4) {
        return details.ipv4.fragment_offset != 0U || (details.ipv4.flags & 0x01U) != 0U;
    }

    if (details.has_ipv6) {
        const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
        if (!network.has_value() || network->protocol_type != detail::kEtherTypeIpv6) {
            return std::nullopt;
        }

        const auto payload = detail::parse_ipv6_payload(packet_bytes, network->payload_offset);
        if (!payload.has_value()) {
            return std::nullopt;
        }

        return payload->has_fragment_header;
    }

    return std::nullopt;
}

TransientPacketDerivedMetadata derive_transient_packet_metadata(
    const std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
) {
    return transient_metadata_from_runtime_facts(derive_runtime_facts(packet_bytes, packet));
}

TransientPacketDerivedMetadata derive_transient_packet_metadata(
    const CaptureSession& session,
    const PacketRef& packet
) {
    const auto packet_bytes = session.read_packet_data(packet);
    if (packet_bytes.empty()) {
        return {};
    }

    return derive_transient_packet_metadata(
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        packet
    );
}

std::optional<std::uint32_t> derive_captured_transport_payload_length_from_headers(
    const std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
) {
    const auto facts = derive_runtime_facts(packet_bytes, packet);
    if (!supports_transient_transport_payload_length(facts.terminal_protocol)) {
        return std::nullopt;
    }

    return facts.captured_transport_payload_length;
}

std::optional<std::uint32_t> derive_original_transport_payload_length_from_headers(
    const std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
) {
    const auto facts = derive_runtime_facts(packet_bytes, packet);
    if (!supports_transient_transport_payload_length(facts.terminal_protocol)) {
        return std::nullopt;
    }

    return facts.original_transport_payload_length;
}

std::optional<std::uint32_t> derive_captured_transport_payload_length_from_headers(
    const CaptureSession& session,
    const PacketRef& packet
) {
    const auto packet_bytes = session.read_packet_data(packet);
    if (packet_bytes.empty()) {
        return std::nullopt;
    }

    return derive_captured_transport_payload_length_from_headers(
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        packet
    );
}

std::optional<std::uint32_t> derive_original_transport_payload_length_from_headers(
    const CaptureSession& session,
    const PacketRef& packet
) {
    const auto packet_bytes = session.read_packet_data(packet);
    if (packet_bytes.empty()) {
        return std::nullopt;
    }

    return derive_original_transport_payload_length_from_headers(
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        packet
    );
}

void apply_original_transport_payload_lengths(CaptureSession& session, std::vector<PacketRow>& rows) {
    for (auto& row : rows) {
        std::optional<PacketRef> packet {};
        if (!row.is_ip_fragmented) {
            packet = session.find_packet(row.packet_index);
        }

        if (row.original_length == row.captured_length && packet.has_value()) {
            const auto exact_transport_payload_length = derive_original_transport_payload_length_from_headers(session, *packet);
            if (exact_transport_payload_length.has_value()) {
                row.payload_length = *exact_transport_payload_length;
                continue;
            }
        }

        if (const auto original_transport_payload_length =
                derive_original_transport_payload_length_from_row_metadata(row);
            original_transport_payload_length.has_value()) {
            row.payload_length = *original_transport_payload_length;
            continue;
        }

        if (row.is_ip_fragmented) {
            continue;
        }

        if (!packet.has_value()) {
            continue;
        }

        const auto original_transport_payload_length = derive_original_transport_payload_length_from_headers(session, *packet);
        if (original_transport_payload_length.has_value()) {
            row.payload_length = *original_transport_payload_length;
        }
    }
}

void populate_transient_packet_row_metadata(
    CaptureSession& session,
    const std::size_t flow_index,
    std::vector<PacketRow>& rows
) {
    for (auto& row : rows) {
        row.derived_payload_length.reset();
        row.derived_is_ip_fragmented.reset();
        row.derived_tcp_flags_text.reset();

        if (const auto cached_metadata = session.selected_flow_cached_packet_metadata(flow_index, row.packet_index);
            cached_metadata.has_value()) {
            apply_transient_metadata_to_row(row, *cached_metadata);
            continue;
        }

        const auto packet = session.find_packet(row.packet_index);
        if (!packet.has_value()) {
            continue;
        }

        const auto metadata = derive_transient_packet_metadata(session, *packet);
        apply_transient_metadata_to_row(row, metadata);
    }
}

}  // namespace pfl::session_detail
