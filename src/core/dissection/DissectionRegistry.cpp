#include "core/dissection/DissectionRegistry.h"

#include <algorithm>
#include <utility>

namespace pfl::dissection {

namespace {

std::size_t domain_index(const SelectorDomain domain) noexcept {
    return static_cast<std::size_t>(domain);
}

}  // namespace

DissectionRegistryBuildResult DissectionRegistry::build(const std::span<const DissectorRegistration> registrations) {
    DissectionRegistry registry {};

    for (std::size_t index = 0U; index < registrations.size(); ++index) {
        const auto& registration = registrations[index];
        if (registration.dissector == nullptr) {
            return DissectionRegistryBuildResult {
                .status = DissectionRegistryBuildStatus::null_dissector,
                .conflicting_selector = registration.selector,
                .conflicting_registration_index = index,
            };
        }

        registry.entries_by_domain_[domain_index(registration.selector.domain)].push_back(Entry {
            .selector_value = registration.selector.value,
            .dissector = registration.dissector,
        });
        ++registry.entry_count_;
    }

    for (std::size_t domain = 0U; domain < registry.entries_by_domain_.size(); ++domain) {
        auto& entries = registry.entries_by_domain_[domain];
        std::sort(entries.begin(), entries.end(), [](const Entry& left, const Entry& right) {
            return left.selector_value < right.selector_value;
        });

        const auto duplicate = std::adjacent_find(entries.begin(), entries.end(), [](const Entry& left, const Entry& right) {
            return left.selector_value == right.selector_value;
        });
        if (duplicate != entries.end()) {
            return DissectionRegistryBuildResult {
                .status = DissectionRegistryBuildStatus::duplicate_selector,
                .conflicting_selector = ProtocolSelector {
                    .domain = static_cast<SelectorDomain>(domain),
                    .value = duplicate->selector_value,
                },
            };
        }
    }

    return DissectionRegistryBuildResult {
        .status = DissectionRegistryBuildStatus::success,
        .registry = std::move(registry),
    };
}

DissectorFn DissectionRegistry::find(const ProtocolSelector& selector) const noexcept {
    const auto& entries = entries_by_domain_[domain_index(selector.domain)];
    const auto found = std::lower_bound(entries.begin(), entries.end(), selector.value, [](const Entry& entry, const std::uint32_t value) {
        return entry.selector_value < value;
    });
    if (found == entries.end() || found->selector_value != selector.value) {
        return nullptr;
    }

    return found->dissector;
}

std::size_t DissectionRegistry::entry_count() const noexcept {
    return entry_count_;
}

bool DissectionRegistry::empty() const noexcept {
    return entry_count_ == 0U;
}

}  // namespace pfl::dissection
