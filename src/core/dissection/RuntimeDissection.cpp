#include "core/dissection/RuntimeDissection.h"

#include "core/dissection/CommonDirectDissection.h"
#include "core/dissection/DissectionEngine.h"
#include "core/dissection/DissectionRegistry.h"
#include "core/dissection/PacketSlice.h"

#include <limits>

namespace pfl::dissection {

namespace {

const DissectionRegistry* common_direct_runtime_registry() {
    static const auto registry_result = make_common_direct_registry();
    if (!registry_result.ok()) {
        return nullptr;
    }

    return &*registry_result.registry;
}

std::optional<std::uint32_t> declared_payload_length_from_bounds(
    const TerminalTransportPayloadBounds& bounds
) noexcept {
    if (bounds.declared_end_offset < bounds.payload_offset) {
        return std::nullopt;
    }

    const auto payload_length = bounds.declared_end_offset - bounds.payload_offset;
    if (payload_length > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(payload_length);
}

std::optional<bool> effective_ip_fragmentation(const ImportDissectionFacts& facts) noexcept {
    switch (facts.family) {
    case DissectionAddressFamily::ipv4:
        if (!facts.has_ipv4_fragmentation) {
            return std::nullopt;
        }
        return facts.ipv4_fragmentation.is_fragmented;
    case DissectionAddressFamily::ipv6:
        if (!facts.has_ipv6_fragmentation) {
            return std::nullopt;
        }
        return facts.ipv6_fragmentation.has_fragment_header;
    case DissectionAddressFamily::unknown:
        break;
    }

    return std::nullopt;
}

}  // namespace

RuntimeDissectionFacts derive_runtime_dissection_facts(
    const std::span<const std::uint8_t> packet_bytes,
    const std::uint32_t captured_length,
    const std::uint32_t original_length,
    const std::uint32_t data_link_type
) {
    RuntimeDissectionFacts facts {};
    const auto* registry = common_direct_runtime_registry();
    if (registry == nullptr) {
        return facts;
    }

    ImportDissectionCollector collector {};
    const DissectionEngine engine {};
    const auto result = engine.run(
        *registry,
        make_link_type_selector(data_link_type),
        make_root_packet_slice(
            ByteSourceId::captured_frame(),
            packet_bytes,
            captured_length,
            original_length
        ),
        collector.consumer()
    );
    collector.finish(result);

    const auto& collected = collector.facts();
    facts.terminal_protocol = collected.terminal_protocol;
    if (collected.has_transport_payload_length) {
        facts.captured_transport_payload_length = collected.captured_transport_payload_length;
    }
    facts.terminal_transport_payload_bounds = collected.terminal_transport_payload_bounds;
    if (facts.terminal_transport_payload_bounds.has_value()) {
        facts.original_transport_payload_length = declared_payload_length_from_bounds(
            *facts.terminal_transport_payload_bounds
        );
    }
    if (collected.has_tcp_flags) {
        facts.tcp_flags = collected.tcp_flags;
    }
    facts.is_ip_fragmented = effective_ip_fragmentation(collected);
    facts.final_status = collected.final_status;
    facts.stop_reason = collected.stop_reason;
    facts.step_count = collected.step_count;
    facts.traversed_depth = collected.traversed_depth;
    return facts;
}

}  // namespace pfl::dissection
