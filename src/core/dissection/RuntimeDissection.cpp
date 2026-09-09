#include "core/dissection/RuntimeDissection.h"

#include "core/dissection/CommonDirectDissection.h"
#include "core/dissection/DissectionEngine.h"
#include "core/dissection/DissectionRegistry.h"
#include "core/dissection/PacketSlice.h"

namespace pfl::dissection {

namespace {

const DissectionRegistry* common_direct_runtime_registry() {
    static const auto registry_result = make_common_direct_registry();
    if (!registry_result.ok()) {
        return nullptr;
    }

    return &*registry_result.registry;
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
    facts.terminal_transport_payload_bounds = collected.terminal_transport_payload_bounds;
    facts.final_status = collected.final_status;
    facts.stop_reason = collected.stop_reason;
    facts.step_count = collected.step_count;
    facts.traversed_depth = collected.traversed_depth;
    return facts;
}

}  // namespace pfl::dissection
