#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "core/domain/FlowKey.h"
#include "core/domain/PacketRef.h"

namespace pfl {

struct DirectionalEndpointKeyV4 {
    std::uint32_t src_addr {0};
    std::uint32_t dst_addr {0};
    std::uint16_t src_port {0};
    std::uint16_t dst_port {0};

    [[nodiscard]] friend constexpr bool operator==(
        const DirectionalEndpointKeyV4&,
        const DirectionalEndpointKeyV4&
    ) = default;
};

struct DirectionalEndpointKeyV6 {
    std::array<std::uint8_t, 16> src_addr {};
    std::array<std::uint8_t, 16> dst_addr {};
    std::uint16_t src_port {0};
    std::uint16_t dst_port {0};

    [[nodiscard]] friend constexpr bool operator==(
        const DirectionalEndpointKeyV6&,
        const DirectionalEndpointKeyV6&
    ) = default;
};

[[nodiscard]] constexpr DirectionalEndpointKeyV4 directional_endpoint_key(const FlowKeyV4& key) noexcept {
    return DirectionalEndpointKeyV4 {
        .src_addr = key.src_addr,
        .dst_addr = key.dst_addr,
        .src_port = key.src_port,
        .dst_port = key.dst_port,
    };
}

[[nodiscard]] constexpr DirectionalEndpointKeyV6 directional_endpoint_key(const FlowKeyV6& key) noexcept {
    return DirectionalEndpointKeyV6 {
        .src_addr = key.src_addr,
        .dst_addr = key.dst_addr,
        .src_port = key.src_port,
        .dst_port = key.dst_port,
    };
}

struct FlowV4 {
    DirectionalEndpointKeyV4 key {};
    std::vector<PacketRef> packets {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};

    [[nodiscard]] bool empty() const noexcept;
};

struct FlowV6 {
    DirectionalEndpointKeyV6 key {};
    std::vector<PacketRef> packets {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};

    [[nodiscard]] bool empty() const noexcept;
};

}  // namespace pfl
