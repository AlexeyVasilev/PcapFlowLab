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

    const auto flow_v4_path_1 = FlowKeyV4 {
        .src_addr = flow_v4_ab.src_addr,
        .dst_addr = flow_v4_ab.dst_addr,
        .src_port = flow_v4_ab.src_port,
        .dst_port = flow_v4_ab.dst_port,
        .protocol = flow_v4_ab.protocol,
        .protocol_path_id = 1U,
    };
    const auto flow_v4_path_1_copy = FlowKeyV4 {
        .src_addr = flow_v4_ab.src_addr,
        .dst_addr = flow_v4_ab.dst_addr,
        .src_port = flow_v4_ab.src_port,
        .dst_port = flow_v4_ab.dst_port,
        .protocol = flow_v4_ab.protocol,
        .protocol_path_id = 1U,
    };
    const auto flow_v4_path_2 = FlowKeyV4 {
        .src_addr = flow_v4_ab.src_addr,
        .dst_addr = flow_v4_ab.dst_addr,
        .src_port = flow_v4_ab.src_port,
        .dst_port = flow_v4_ab.dst_port,
        .protocol = flow_v4_ab.protocol,
        .protocol_path_id = 2U,
    };
    const auto reverse_flow_v4_path_1 = FlowKeyV4 {
        .src_addr = flow_v4_ba.src_addr,
        .dst_addr = flow_v4_ba.dst_addr,
        .src_port = flow_v4_ba.src_port,
        .dst_port = flow_v4_ba.dst_port,
        .protocol = flow_v4_ba.protocol,
        .protocol_path_id = 1U,
    };

    PFL_EXPECT(flow_v4_path_1 == flow_v4_path_1_copy);
    PFL_EXPECT(flow_v4_path_1 != flow_v4_path_2);
    PFL_EXPECT(make_connection_key(flow_v4_path_1) == make_connection_key(reverse_flow_v4_path_1));
    PFL_EXPECT(make_connection_key(flow_v4_path_1) != make_connection_key(flow_v4_path_2));

    const auto arp_request = FlowKeyV4 {
        .src_addr = ipv4(192, 168, 1, 10),
        .dst_addr = ipv4(192, 168, 1, 1),
        .src_port = 0,
        .dst_port = 0,
        .protocol = ProtocolId::arp,
        .protocol_path_id = 7U,
    };
    const auto arp_reply = FlowKeyV4 {
        .src_addr = ipv4(192, 168, 1, 1),
        .dst_addr = ipv4(192, 168, 1, 10),
        .src_port = 0,
        .dst_port = 0,
        .protocol = ProtocolId::arp,
        .protocol_path_id = 7U,
    };
    const auto icmp_same_carrier = FlowKeyV4 {
        .src_addr = arp_request.src_addr,
        .dst_addr = arp_request.dst_addr,
        .src_port = 0,
        .dst_port = 0,
        .protocol = ProtocolId::icmp,
        .protocol_path_id = 7U,
    };
    const auto arp_other_path = FlowKeyV4 {
        .src_addr = arp_request.src_addr,
        .dst_addr = arp_request.dst_addr,
        .src_port = 0,
        .dst_port = 0,
        .protocol = ProtocolId::arp,
        .protocol_path_id = 8U,
    };

    const auto arp_connection_request = make_connection_key(arp_request);
    const auto arp_connection_reply = make_connection_key(arp_reply);
    const auto icmp_connection_same_carrier = make_connection_key(icmp_same_carrier);
    const auto arp_connection_other_path = make_connection_key(arp_other_path);

    PFL_EXPECT(arp_connection_request == arp_connection_reply);
    PFL_EXPECT(arp_connection_request.first.port == 0U);
    PFL_EXPECT(arp_connection_request.second.port == 0U);
    PFL_EXPECT(resolve_direction(arp_connection_request, arp_request) == Direction::b_to_a);
    PFL_EXPECT(resolve_direction(arp_connection_request, arp_reply) == Direction::a_to_b);
    PFL_EXPECT(arp_connection_request != icmp_connection_same_carrier);
    PFL_EXPECT(arp_connection_request != arp_connection_other_path);

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

    const auto flow_v6_path_1 = FlowKeyV6 {
        .src_addr = flow_v6_ab.src_addr,
        .dst_addr = flow_v6_ab.dst_addr,
        .src_port = flow_v6_ab.src_port,
        .dst_port = flow_v6_ab.dst_port,
        .protocol = flow_v6_ab.protocol,
        .protocol_path_id = 11U,
    };
    const auto flow_v6_path_2 = FlowKeyV6 {
        .src_addr = flow_v6_ab.src_addr,
        .dst_addr = flow_v6_ab.dst_addr,
        .src_port = flow_v6_ab.src_port,
        .dst_port = flow_v6_ab.dst_port,
        .protocol = flow_v6_ab.protocol,
        .protocol_path_id = 12U,
    };
    const auto reverse_flow_v6_path_1 = FlowKeyV6 {
        .src_addr = flow_v6_ba.src_addr,
        .dst_addr = flow_v6_ba.dst_addr,
        .src_port = flow_v6_ba.src_port,
        .dst_port = flow_v6_ba.dst_port,
        .protocol = flow_v6_ba.protocol,
        .protocol_path_id = 11U,
    };

    PFL_EXPECT(flow_v6_path_1 != flow_v6_path_2);
    PFL_EXPECT(make_connection_key(flow_v6_path_1) == make_connection_key(reverse_flow_v6_path_1));
    PFL_EXPECT(make_connection_key(flow_v6_path_1) != make_connection_key(flow_v6_path_2));

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
