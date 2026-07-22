#pragma once

#include <optional>
#include <span>
#include <string>

#include "core/decode/PacketDecoder.h"
#include "core/domain/CaptureState.h"
#include "core/services/FlowHintService.h"
#include "core/services/PacketIngestor.h"

namespace pfl {

[[nodiscard]] ProtocolPathId intern_protocol_path_id_for_flow_identity(
    CaptureState& state,
    const ProtocolPathBuilder& decoded_protocol_path
);

[[nodiscard]] PacketRef packet_ref_from_raw_packet(const RawPcapPacket& packet);

[[nodiscard]] std::string classify_unrecognized_packet_reason(
    const RawPcapPacket& packet,
    std::span<const std::uint8_t> packet_bytes
);

[[nodiscard]] bool ingest_fallback_arp_packet(
    const RawPcapPacket& packet,
    std::span<const std::uint8_t> packet_bytes,
    PacketIngestor& ingestor,
    const FlowHintService& hint_service
);

[[nodiscard]] bool requires_full_packet_for_hint_detection(
    const PacketRef& packet_ref,
    ProtocolId protocol
) noexcept;

[[nodiscard]] std::optional<std::uint32_t> derive_captured_transport_payload_length_from_prefix(
    const RawPcapPacket& packet,
    ProtocolId protocol
);

template <typename Connection, typename FlowKey>
void apply_import_hints_if_needed(const RawPcapPacket& packet,
                                  std::span<const std::uint8_t> packet_bytes,
                                  const PacketRef& packet_ref,
                                  Connection& connection,
                                  const FlowKey& flow_key,
                                  const FlowHintService& hint_service) {
    if (packet_ref.is_ip_fragmented || !connection.should_attempt_hint_detection(packet_ref, flow_key.protocol)) {
        return;
    }

    connection.apply_hints(hint_service.detect(packet_bytes, packet.data_link_type, flow_key));
    connection.note_hint_detection_attempt(packet_ref, flow_key.protocol);
}

void apply_decoded_packet_import(
    const RawPcapPacket& packet,
    DecodedPacket& decoded,
    CaptureState& state,
    const FlowHintService& hint_service
);

void apply_unrecognized_packet_import(
    const RawPcapPacket& packet,
    std::span<const std::uint8_t> packet_bytes,
    CaptureState& state,
    const FlowHintService& hint_service
);

}  // namespace pfl
