#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>

#include "core/decode/PacketDecoder.h"
#include "core/dissection/CommonDirectDissection.h"
#include "core/domain/CaptureState.h"
#include "core/domain/TerminalTransportPayloadBounds.h"
#include "core/services/FlowHintService.h"
#include "core/services/PacketIngestor.h"
#include "core/services/DissectionImportAdapter.h"

namespace pfl {

struct PacketBytesMaterializer {
    using Callback = bool (*)(void* context);

    Callback callback {nullptr};
    void* context {nullptr};

    [[nodiscard]] bool ensure_full_packet_bytes() const {
        return callback == nullptr || callback(context);
    }
};

struct UnifiedImportPacketResult {
    dissection::ImportDissectionFacts facts {};
    DissectionImportDecision decision {};
};

[[nodiscard]] ProtocolPathId intern_protocol_path_id_for_flow_identity(
    CaptureState& state,
    const ProtocolPathBuilder& decoded_protocol_path,
    const AnalysisSettings& settings
);

[[nodiscard]] std::optional<ProtocolPath> normalize_protocol_path_for_flow_identity(
    ProtocolPathView path,
    const AnalysisSettings& settings
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

[[nodiscard]] bool apply_legacy_unrecognized_packet_import(
    const RawPcapPacket& packet,
    std::span<const std::uint8_t> packet_bytes,
    CaptureState& state,
    const FlowHintService& hint_service
);

[[nodiscard]] bool requires_full_packet_for_hint_detection(
    const PacketRef& packet_ref,
    ProtocolId protocol
) noexcept;

[[nodiscard]] std::optional<std::uint32_t> derive_captured_terminal_transport_payload_length(
    const RawPcapPacket& packet,
    const TerminalTransportPayloadBounds& bounds
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

[[nodiscard]] UnifiedImportPacketResult run_unified_import_packet(
    const RawPcapPacket& packet,
    const dissection::DissectionRegistry& registry
);

[[nodiscard]] bool apply_decoded_packet_import(
    const RawPcapPacket& packet,
    DecodedPacket& decoded,
    CaptureState& state,
    const FlowHintService& hint_service
);

[[nodiscard]] bool apply_decoded_packet_import(
    RawPcapPacket& packet,
    DecodedPacket& decoded,
    CaptureState& state,
    const FlowHintService& hint_service,
    PacketBytesMaterializer materializer = {}
);

[[nodiscard]] bool apply_unified_import_packet_result(
    RawPcapPacket& packet,
    UnifiedImportPacketResult& result,
    CaptureState& state,
    const FlowHintService& hint_service,
    PacketBytesMaterializer materializer = {}
);

[[nodiscard]] bool process_packet_with_unified_dissection(
    RawPcapPacket& packet,
    CaptureState& state,
    const dissection::DissectionRegistry& registry,
    const FlowHintService& hint_service,
    PacketBytesMaterializer materializer = {},
    UnifiedImportPacketResult* result = nullptr
);

void apply_unrecognized_packet_import(
    const RawPcapPacket& packet,
    std::span<const std::uint8_t> packet_bytes,
    CaptureState& state
);

}  // namespace pfl
