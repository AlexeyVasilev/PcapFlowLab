#include "core/domain/ConnectionKey.h"

namespace pfl {

namespace {

EndpointKeyV4 make_endpoint_key(std::uint32_t addr, std::uint16_t port) noexcept {
    return EndpointKeyV4 {
        .addr = addr,
        .port = port,
    };
}

EndpointKeyV6 make_endpoint_key(const std::array<std::uint8_t, 16>& addr, std::uint16_t port) noexcept {
    return EndpointKeyV6 {
        .addr = addr,
        .port = port,
    };
}

std::size_t hash_endpoint(const EndpointKeyV4& endpoint) noexcept {
    auto seed = detail::hash_combine(0U, std::hash<std::uint32_t> {}(endpoint.addr));
    return detail::hash_combine(seed, std::hash<std::uint16_t> {}(endpoint.port));
}

std::size_t hash_endpoint(const EndpointKeyV6& endpoint) noexcept {
    auto seed = detail::hash_combine(0U, detail::hash_array16(endpoint.addr));
    return detail::hash_combine(seed, std::hash<std::uint16_t> {}(endpoint.port));
}

}  // namespace

ConnectionKeyV4 make_connection_key(const FlowKeyV4& key) noexcept {
    const auto source = make_endpoint_key(key.src_addr, key.src_port);
    const auto destination = make_endpoint_key(key.dst_addr, key.dst_port);

    if (source <= destination) {
        return {
            .first = source,
            .second = destination,
            .protocol = key.protocol,
        };
    }

    return {
        .first = destination,
        .second = source,
        .protocol = key.protocol,
    };
}

ConnectionKeyV6 make_connection_key(const FlowKeyV6& key) noexcept {
    const auto source = make_endpoint_key(key.src_addr, key.src_port);
    const auto destination = make_endpoint_key(key.dst_addr, key.dst_port);

    if (source <= destination) {
        return {
            .first = source,
            .second = destination,
            .protocol = key.protocol,
        };
    }

    return {
        .first = destination,
        .second = source,
        .protocol = key.protocol,
    };
}

Direction resolve_direction(const ConnectionKeyV4& connection_key, const FlowKeyV4& flow_key) noexcept {
    if (connection_key.first.addr == flow_key.src_addr &&
        connection_key.first.port == flow_key.src_port &&
        connection_key.second.addr == flow_key.dst_addr &&
        connection_key.second.port == flow_key.dst_port) {
        return Direction::a_to_b;
    }

    return Direction::b_to_a;
}

Direction resolve_direction(const ConnectionKeyV6& connection_key, const FlowKeyV6& flow_key) noexcept {
    if (connection_key.first.addr == flow_key.src_addr &&
        connection_key.first.port == flow_key.src_port &&
        connection_key.second.addr == flow_key.dst_addr &&
        connection_key.second.port == flow_key.dst_port) {
        return Direction::a_to_b;
    }

    return Direction::b_to_a;
}

std::size_t ConnectionKeyV4Hash::operator()(const ConnectionKeyV4& key) const noexcept {
    auto seed = detail::hash_combine(0U, hash_endpoint(key.first));
    seed = detail::hash_combine(seed, hash_endpoint(key.second));
    seed = detail::hash_combine(seed, std::hash<std::uint8_t> {}(static_cast<std::uint8_t>(key.protocol)));
    return seed;
}

std::size_t ConnectionKeyV6Hash::operator()(const ConnectionKeyV6& key) const noexcept {
    auto seed = detail::hash_combine(0U, hash_endpoint(key.first));
    seed = detail::hash_combine(seed, hash_endpoint(key.second));
    seed = detail::hash_combine(seed, std::hash<std::uint8_t> {}(static_cast<std::uint8_t>(key.protocol)));
    return seed;
}

}  // namespace pfl
