#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "core/dissection/PacketSlice.h"

namespace pfl::dissection {

struct NextDissection {
    ProtocolSelector selector {};
    PacketSlice slice {};

    [[nodiscard]] friend bool operator==(const NextDissection&, const NextDissection&) = default;
};

struct DissectionStep {
    LayerKey layer_key {};
    ByteRange full_range {};
    ByteRange header_range {};
    std::optional<ByteRange> payload_range {};
    std::optional<NextDissection> next {};
    std::optional<IdentityContribution> identity_contribution {};
    std::optional<TerminalFlowFact> terminal_flow {};
    std::optional<ArpAddressFact> arp_addresses {};
    std::optional<TransportPayloadFact> transport_payload {};
    std::optional<TcpControlFact> tcp_control {};
    std::optional<Ipv4FragmentationFact> ipv4_fragmentation {};
    ParseStatus status {ParseStatus::opaque};
    StopReason stop_reason {StopReason::none};
};

using DissectorFn = DissectionStep (*)(const PacketSlice&);

struct DissectorRegistration {
    ProtocolSelector selector {};
    DissectorFn dissector {nullptr};
};

enum class DissectionRegistryBuildStatus : std::uint8_t {
    success = 0,
    duplicate_selector,
    null_dissector,
};

class DissectionRegistry;
struct DissectionRegistryBuildResult;

class DissectionRegistry {
public:
    [[nodiscard]] static DissectionRegistryBuildResult build(
        std::span<const DissectorRegistration> registrations
    );

    [[nodiscard]] DissectorFn find(const ProtocolSelector& selector) const noexcept;
    [[nodiscard]] std::size_t entry_count() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

private:
    struct Entry {
        std::uint32_t selector_value {0U};
        DissectorFn dissector {nullptr};
    };

    std::array<std::vector<Entry>, selector_domain_count> entries_by_domain_ {};
    std::size_t entry_count_ {0U};
};

struct DissectionRegistryBuildResult {
    DissectionRegistryBuildStatus status {DissectionRegistryBuildStatus::success};
    std::optional<ProtocolSelector> conflicting_selector {};
    std::optional<std::size_t> conflicting_registration_index {};
    std::optional<DissectionRegistry> registry {};

    [[nodiscard]] bool ok() const noexcept {
        return status == DissectionRegistryBuildStatus::success && registry.has_value();
    }
};

}  // namespace pfl::dissection
