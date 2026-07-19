#pragma once

#include <array>
#include <cstdint>
#include <optional>

#include "core/dissection/DissectionEngine.h"
#include "core/io/LinkType.h"

namespace pfl::dissection {

enum class ImportDissectionOutcome : std::uint8_t {
    unrecognized = 0,
    recognized_flow,
    recognized_non_flow,
};

struct ImportIpv4Fragmentation {
    bool is_fragmented {false};
    bool more_fragments {false};
    std::uint16_t fragment_offset_units {0U};

    [[nodiscard]] friend constexpr bool operator==(const ImportIpv4Fragmentation&, const ImportIpv4Fragmentation&) = default;
};

struct ImportIpv6Fragmentation {
    bool has_fragment_header {false};
    bool more_fragments {false};
    std::uint16_t fragment_offset_units {0U};
    bool is_atomic_fragment {false};

    [[nodiscard]] friend constexpr bool operator==(const ImportIpv6Fragmentation&, const ImportIpv6Fragmentation&) = default;
};

struct ImportDissectionFacts {
    ProtocolPathBuilder physical_path {};
    ImportDissectionOutcome outcome {ImportDissectionOutcome::unrecognized};
    DissectionAddressFamily family {DissectionAddressFamily::unknown};
    ProtocolId terminal_protocol {ProtocolId::unknown};
    bool has_flow_addresses {false};
    std::uint32_t src_addr_v4 {0U};
    std::uint32_t dst_addr_v4 {0U};
    std::array<std::uint8_t, 16> src_addr_v6 {};
    std::array<std::uint8_t, 16> dst_addr_v6 {};
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    bool has_ports {false};
    bool has_transport_payload_length {false};
    std::uint32_t captured_transport_payload_length {0U};
    bool has_tcp_flags {false};
    std::uint8_t tcp_flags {0U};
    bool has_ipv4_fragmentation {false};
    ImportIpv4Fragmentation ipv4_fragmentation {};
    bool has_ipv6_fragmentation {false};
    ImportIpv6Fragmentation ipv6_fragmentation {};
    bool has_arp_addresses {false};
    ArpFacts arp_addresses {};
    ParseStatus final_status {ParseStatus::opaque};
    StopReason stop_reason {StopReason::none};
    std::size_t step_count {0U};
    std::size_t traversed_depth {0U};
    bool path_overflowed {false};
};

class ImportDissectionCollector {
public:
    void consume(const DissectionStep& step) noexcept;
    void finish(const DissectionEngineResult& result) noexcept;

    [[nodiscard]] const ImportDissectionFacts& facts() const noexcept {
        return facts_;
    }

    [[nodiscard]] DissectionConsumer consumer() noexcept {
        return DissectionConsumer {
            .on_step = &ImportDissectionCollector::consume_step,
            .context = this,
        };
    }

private:
    static void consume_step(void* context, const DissectionStep& step) noexcept;

    ImportDissectionFacts facts_ {};
    TerminalDisposition terminal_disposition_ {TerminalDisposition::none};
    std::optional<std::uint32_t> igmp_effective_destination_v4_ {};
};

[[nodiscard]] constexpr ProtocolSelector make_link_type_selector(const std::uint32_t link_type) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::link_type,
        .value = link_type,
    };
}

[[nodiscard]] DissectionRegistryBuildResult make_common_direct_registry();

}  // namespace pfl::dissection
