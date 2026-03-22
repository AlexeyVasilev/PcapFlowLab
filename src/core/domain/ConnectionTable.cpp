#include "core/domain/ConnectionTable.h"

namespace pfl {

ConnectionV4& ConnectionTableV4::get_or_create(const ConnectionKeyV4& key) {
    auto [iterator, inserted] = connections_.try_emplace(key);
    if (inserted) {
        iterator->second.key = key;
    }
    return iterator->second;
}

const ConnectionV4* ConnectionTableV4::find(const ConnectionKeyV4& key) const noexcept {
    const auto iterator = connections_.find(key);
    if (iterator == connections_.end()) {
        return nullptr;
    }
    return &iterator->second;
}

std::vector<const ConnectionV4*> ConnectionTableV4::list() const {
    std::vector<const ConnectionV4*> rows {};
    rows.reserve(connections_.size());

    for (const auto& [key, connection] : connections_) {
        static_cast<void>(key);
        rows.push_back(&connection);
    }

    return rows;
}

std::size_t ConnectionTableV4::size() const noexcept {
    return connections_.size();
}

void ConnectionTableV4::clear() noexcept {
    connections_.clear();
}

ConnectionV6& ConnectionTableV6::get_or_create(const ConnectionKeyV6& key) {
    auto [iterator, inserted] = connections_.try_emplace(key);
    if (inserted) {
        iterator->second.key = key;
    }
    return iterator->second;
}

const ConnectionV6* ConnectionTableV6::find(const ConnectionKeyV6& key) const noexcept {
    const auto iterator = connections_.find(key);
    if (iterator == connections_.end()) {
        return nullptr;
    }
    return &iterator->second;
}

std::vector<const ConnectionV6*> ConnectionTableV6::list() const {
    std::vector<const ConnectionV6*> rows {};
    rows.reserve(connections_.size());

    for (const auto& [key, connection] : connections_) {
        static_cast<void>(key);
        rows.push_back(&connection);
    }

    return rows;
}

std::size_t ConnectionTableV6::size() const noexcept {
    return connections_.size();
}

void ConnectionTableV6::clear() noexcept {
    connections_.clear();
}

}  // namespace pfl
