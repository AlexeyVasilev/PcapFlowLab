#include "core/domain/NonTerminalIpContext.h"

#include <algorithm>
#include <utility>

namespace pfl {

namespace {

[[nodiscard]] std::size_t hash_address_bytes(const std::array<std::uint8_t, 16>& bytes) noexcept {
    std::size_t seed = static_cast<std::size_t>(0xcbf29ce484222325ULL);
    for (const auto byte : bytes) {
        seed ^= static_cast<std::size_t>(byte);
        seed *= static_cast<std::size_t>(0x100000001b3ULL);
    }
    return seed;
}

[[nodiscard]] bool context_view_equals_context(
    const NonTerminalIpContextView view,
    const NonTerminalIpContext& context
) noexcept {
    if (view.size() != context.size()) {
        return false;
    }

    for (std::size_t index = 0; index < view.size(); ++index) {
        if (view[index] != context[index]) {
            return false;
        }
    }

    return true;
}

[[nodiscard]] std::size_t hash_context_view(const NonTerminalIpContextView view) noexcept {
    auto seed = std::hash<std::size_t> {}(view.size());
    for (const auto& level : view) {
        seed = detail::hash_combine(seed, NonTerminalIpLevelHash {}(level));
    }
    return seed;
}

[[nodiscard]] bool swapped_context_is_less(const NonTerminalIpContextView observed) noexcept {
    for (std::size_t index = 0; index < observed.size(); ++index) {
        const auto swapped = swap_non_terminal_ip_level_direction(observed[index]);
        if (swapped < observed[index]) {
            return true;
        }
        if (observed[index] < swapped) {
            return false;
        }
    }
    return false;
}

[[nodiscard]] NonTerminalIpContext make_context_from_view(
    const NonTerminalIpContextView observed,
    const bool swap_directions
) {
    std::vector<NonTerminalIpLevel> levels {};
    levels.reserve(observed.size());
    for (const auto& level : observed) {
        levels.push_back(swap_directions ? swap_non_terminal_ip_level_direction(level) : level);
    }
    return NonTerminalIpContext {std::move(levels)};
}

template <typename Endpoint>
[[nodiscard]] NonTerminalIpContext canonicalize_by_terminal_endpoints(
    const NonTerminalIpContextView observed,
    const Endpoint& terminal_source,
    const Endpoint& terminal_destination
) {
    if (terminal_source < terminal_destination) {
        return make_context_from_view(observed, false);
    }
    if (terminal_destination < terminal_source) {
        return make_context_from_view(observed, true);
    }

    return make_context_from_view(observed, swapped_context_is_less(observed));
}

}  // namespace

std::size_t NonTerminalIpLevelHash::operator()(const NonTerminalIpLevel& level) const noexcept {
    auto seed = std::hash<std::uint8_t> {}(static_cast<std::uint8_t>(level.family));
    seed = detail::hash_combine(seed, hash_address_bytes(level.source));
    seed = detail::hash_combine(seed, hash_address_bytes(level.destination));
    return seed;
}

NonTerminalIpContext::NonTerminalIpContext(std::initializer_list<NonTerminalIpLevel> levels)
    : levels_(levels) {}

NonTerminalIpContext::NonTerminalIpContext(std::vector<NonTerminalIpLevel> levels)
    : levels_(std::move(levels)) {}

bool NonTerminalIpContext::operator==(const NonTerminalIpContext& other) const noexcept {
    return levels_ == other.levels_;
}

std::size_t NonTerminalIpContext::size() const noexcept {
    return levels_.size();
}

bool NonTerminalIpContext::empty() const noexcept {
    return levels_.empty();
}

const NonTerminalIpLevel& NonTerminalIpContext::operator[](const std::size_t index) const noexcept {
    return levels_[index];
}

const std::vector<NonTerminalIpLevel>& NonTerminalIpContext::levels() const noexcept {
    return levels_;
}

NonTerminalIpContextView NonTerminalIpContext::view() const noexcept {
    return NonTerminalIpContextView {levels_.data(), levels_.size()};
}

std::vector<NonTerminalIpLevel>::const_iterator NonTerminalIpContext::begin() const noexcept {
    return levels_.begin();
}

std::vector<NonTerminalIpLevel>::const_iterator NonTerminalIpContext::end() const noexcept {
    return levels_.end();
}

std::size_t NonTerminalIpContextHash::operator()(const NonTerminalIpContext& context) const noexcept {
    return hash_context_view(context.view());
}

bool NonTerminalIpContextBuilder::push(const NonTerminalIpLevel level) noexcept {
    if (overflowed_ || size_ >= kMaxNonTerminalIpContextLevels) {
        overflowed_ = true;
        return false;
    }

    levels_[size_] = level;
    ++size_;
    return true;
}

bool NonTerminalIpContextBuilder::push_ipv4(const std::uint32_t source, const std::uint32_t destination) noexcept {
    return push(NonTerminalIpLevel::ipv4(source, destination));
}

bool NonTerminalIpContextBuilder::push_ipv6(
    const std::array<std::uint8_t, 16>& source,
    const std::array<std::uint8_t, 16>& destination
) noexcept {
    return push(NonTerminalIpLevel::ipv6(source, destination));
}

bool NonTerminalIpContextBuilder::full() const noexcept {
    return size_ == kMaxNonTerminalIpContextLevels;
}

bool NonTerminalIpContextBuilder::overflowed() const noexcept {
    return overflowed_;
}

std::size_t NonTerminalIpContextBuilder::size() const noexcept {
    return size_;
}

bool NonTerminalIpContextBuilder::empty() const noexcept {
    return size_ == 0U;
}

const NonTerminalIpLevel& NonTerminalIpContextBuilder::operator[](const std::size_t index) const noexcept {
    return levels_[index];
}

NonTerminalIpContextView NonTerminalIpContextBuilder::view() const noexcept {
    return NonTerminalIpContextView {levels_.data(), size_};
}

std::optional<NonTerminalIpContext> NonTerminalIpContextBuilder::to_context() const {
    if (overflowed_) {
        return std::nullopt;
    }

    return make_context_from_view(view(), false);
}

void NonTerminalIpContextBuilder::clear() noexcept {
    size_ = 0U;
    overflowed_ = false;
}

NonTerminalIpContextId NonTerminalIpContextRegistry::intern(const NonTerminalIpContextView context) {
    if (context.empty()) {
        return kEmptyNonTerminalIpContextId;
    }

    const auto hash = hash_context_view(context);
    if (const auto found = ids_by_hash_.find(hash); found != ids_by_hash_.end()) {
        for (const auto id : found->second) {
            const auto* stored_context = find(id);
            if (stored_context != nullptr && context_view_equals_context(context, *stored_context)) {
                return id;
            }
        }
    }

    return insert_unique_context(make_context_from_view(context, false), hash);
}

NonTerminalIpContextId NonTerminalIpContextRegistry::intern(const NonTerminalIpContext& context) {
    return intern(context.view());
}

NonTerminalIpContextId NonTerminalIpContextRegistry::intern(NonTerminalIpContext&& context) {
    if (context.empty()) {
        return kEmptyNonTerminalIpContextId;
    }

    if (const auto found = ids_.find(context); found != ids_.end()) {
        return found->second;
    }

    const auto hash = hash_context_view(context.view());
    return insert_unique_context(std::move(context), hash);
}

const NonTerminalIpContext* NonTerminalIpContextRegistry::find(const NonTerminalIpContextId id) const noexcept {
    if (id == kEmptyNonTerminalIpContextId) {
        return nullptr;
    }

    const auto index = static_cast<std::size_t>(id - 1U);
    if (index >= contexts_.size()) {
        return nullptr;
    }

    return &contexts_[index];
}

std::size_t NonTerminalIpContextRegistry::size() const noexcept {
    return contexts_.size();
}

const std::vector<NonTerminalIpContext>& NonTerminalIpContextRegistry::contexts() const noexcept {
    return contexts_;
}

NonTerminalIpContextId NonTerminalIpContextRegistry::insert_unique_context(
    NonTerminalIpContext context,
    const std::size_t hash
) {
    contexts_.push_back(std::move(context));
    const auto id = static_cast<NonTerminalIpContextId>(contexts_.size());
    ids_.emplace(contexts_.back(), id);
    ids_by_hash_[hash].push_back(id);
    return id;
}

NonTerminalIpLevel swap_non_terminal_ip_level_direction(NonTerminalIpLevel level) noexcept {
    std::swap(level.source, level.destination);
    return level;
}

NonTerminalIpContext canonicalize_non_terminal_ip_context(
    const NonTerminalIpContextView observed,
    const EndpointKeyV4& terminal_source,
    const EndpointKeyV4& terminal_destination
) {
    return canonicalize_by_terminal_endpoints(observed, terminal_source, terminal_destination);
}

NonTerminalIpContext canonicalize_non_terminal_ip_context(
    const NonTerminalIpContextView observed,
    const EndpointKeyV6& terminal_source,
    const EndpointKeyV6& terminal_destination
) {
    return canonicalize_by_terminal_endpoints(observed, terminal_source, terminal_destination);
}

}  // namespace pfl
