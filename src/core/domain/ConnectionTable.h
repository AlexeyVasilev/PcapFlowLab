#pragma once

#include <cstddef>
#include <unordered_map>
#include <vector>

#include "core/domain/Connection.h"

namespace pfl {

class ConnectionTableV4 {
public:
    ConnectionV4& get_or_create(const ConnectionKeyV4& key);
    [[nodiscard]] const ConnectionV4* find(const ConnectionKeyV4& key) const noexcept;
    [[nodiscard]] std::vector<const ConnectionV4*> list() const;
    [[nodiscard]] std::size_t size() const noexcept;
    void clear() noexcept;

private:
    std::unordered_map<ConnectionKeyV4, ConnectionV4> connections_ {};
};

class ConnectionTableV6 {
public:
    ConnectionV6& get_or_create(const ConnectionKeyV6& key);
    [[nodiscard]] const ConnectionV6* find(const ConnectionKeyV6& key) const noexcept;
    [[nodiscard]] std::vector<const ConnectionV6*> list() const;
    [[nodiscard]] std::size_t size() const noexcept;
    void clear() noexcept;

private:
    std::unordered_map<ConnectionKeyV6, ConnectionV6> connections_ {};
};

}  // namespace pfl
