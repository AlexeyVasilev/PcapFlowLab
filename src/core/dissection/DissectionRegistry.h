#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "core/dissection/PacketSlice.h"

namespace pfl::dissection {

struct ProtocolHandoff {
    ProtocolSelector selector {};
    std::optional<PacketSlice> child {};

    [[nodiscard]] friend bool operator==(const ProtocolHandoff&, const ProtocolHandoff&) = default;
};

enum class PathContributionPolicy : std::uint8_t {
    immediate = 0,
    terminal_success,
};

struct DissectionStep {
    DissectionLayerKind layer {DissectionLayerKind::unknown};
    std::optional<LayerKey> path_contribution {};
    PathContributionPolicy path_contribution_policy {PathContributionPolicy::immediate};
    LayerBounds bounds {};
    std::optional<ProtocolHandoff> handoff {};
    LayerFacts facts {};
    TerminalDisposition terminal_disposition {TerminalDisposition::none};
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
