#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>

#include "TestSupport.h"
#include "core/domain/ConnectionKey.h"

namespace pfl::tests {

namespace {

std::uint32_t ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return (static_cast<std::uint32_t>(a) << 24U) |
           (static_cast<std::uint32_t>(b) << 16U) |
           (static_cast<std::uint32_t>(c) << 8U) |
           static_cast<std::uint32_t>(d);
}

std::array<std::uint8_t, 16> ipv6(std::initializer_list<std::uint8_t> bytes) {
    std::array<std::uint8_t, 16> address {};
    std::size_t index = 0;
    for (const auto byte : bytes) {
        address[index] = byte;
        ++index;
    }
    return address;
}

}  // namespace

void run_flow_key_tests() {
    const FlowKeyV4 flow_v4_ab {
        .src_addr = ipv4(10, 0, 0, 1),
        .dst_addr = ipv4(10, 0, 0, 2),
        .src_port = 40000,
        .dst_port = 443,
        .protocol = ProtocolId::tcp,
    };
    const FlowKeyV4 flow_v4_ba {
        .src_addr = ipv4(10, 0, 0, 2),
        .dst_addr = ipv4(10, 0, 0, 1),
        .src_port = 443,
        .dst_port = 40000,
        .protocol = ProtocolId::tcp,
    };

    const auto connection_v4_ab = make_connection_key(flow_v4_ab);
    const auto connection_v4_ba = make_connection_key(flow_v4_ba);

    PFL_EXPECT(connection_v4_ab == connection_v4_ba);
    PFL_EXPECT(resolve_direction(connection_v4_ab, flow_v4_ab) == Direction::a_to_b);
    PFL_EXPECT(resolve_direction(connection_v4_ab, flow_v4_ba) == Direction::b_to_a);
    PFL_EXPECT(flow_v4_ab == flow_v4_ab);
    PFL_EXPECT(flow_v4_ab != flow_v4_ba);

    const FlowKeyV6 flow_v6_ab {
        .src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
        .dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}),
        .src_port = 5353,
        .dst_port = 5354,
        .protocol = ProtocolId::udp,
    };
    const FlowKeyV6 flow_v6_ba {
        .src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}),
        .dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
        .src_port = 5354,
        .dst_port = 5353,
        .protocol = ProtocolId::udp,
    };

    const auto connection_v6_ab = make_connection_key(flow_v6_ab);
    const auto connection_v6_ba = make_connection_key(flow_v6_ba);

    PFL_EXPECT(connection_v6_ab == connection_v6_ba);
    PFL_EXPECT(resolve_direction(connection_v6_ab, flow_v6_ab) == Direction::a_to_b);
    PFL_EXPECT(resolve_direction(connection_v6_ab, flow_v6_ba) == Direction::b_to_a);

    const auto flow_v4_hash_1 = std::hash<FlowKeyV4> {}(flow_v4_ab);
    const auto flow_v4_hash_2 = std::hash<FlowKeyV4> {}(flow_v4_ab);
    const auto connection_v4_hash_1 = std::hash<ConnectionKeyV4> {}(connection_v4_ab);
    const auto connection_v4_hash_2 = std::hash<ConnectionKeyV4> {}(connection_v4_ba);
    const auto flow_v6_hash_1 = std::hash<FlowKeyV6> {}(flow_v6_ab);
    const auto flow_v6_hash_2 = std::hash<FlowKeyV6> {}(flow_v6_ab);
    const auto connection_v6_hash_1 = std::hash<ConnectionKeyV6> {}(connection_v6_ab);
    const auto connection_v6_hash_2 = std::hash<ConnectionKeyV6> {}(connection_v6_ba);

    PFL_EXPECT(flow_v4_hash_1 == flow_v4_hash_2);
    PFL_EXPECT(connection_v4_hash_1 == connection_v4_hash_2);
    PFL_EXPECT(flow_v6_hash_1 == flow_v6_hash_2);
    PFL_EXPECT(connection_v6_hash_1 == connection_v6_hash_2);
}

}  // namespace pfl::tests
