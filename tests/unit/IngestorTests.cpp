#include <array>
#include <cstddef>
#include <cstdint>

#include "TestSupport.h"
#include "core/domain/CaptureState.h"
#include "core/domain/IngestedPacket.h"
#include "core/services/PacketIngestor.h"

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

PacketRef packet_ref(std::uint64_t index, std::uint32_t original_length) {
    return PacketRef {
        .packet_index = index,
        .byte_offset = index * 64U,
        .captured_length = original_length,
        .original_length = original_length,
    };
}

}  // namespace

void run_ingestor_tests() {
    {
        CaptureState state {};
        PacketIngestor ingestor {state};
        const IngestedPacketV4 packet {
            .flow_key = FlowKeyV4 {
                .src_addr = ipv4(10, 0, 0, 1),
                .dst_addr = ipv4(10, 0, 0, 2),
                .src_port = 12000,
                .dst_port = 443,
                .protocol = ProtocolId::tcp,
            },
            .packet_ref = packet_ref(1, 100),
        };

        ingestor.ingest(packet);

        PFL_EXPECT(state.ipv4_connections.size() == 1);
        PFL_EXPECT(state.summary.packet_count == 1);
        PFL_EXPECT(state.summary.flow_count == 1);
        PFL_EXPECT(state.summary.total_bytes == 100);

        const auto* connection = state.ipv4_connections.find(make_connection_key(packet.flow_key));
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(connection->has_flow_a);
        PFL_EXPECT(!connection->has_flow_b);
        PFL_EXPECT(connection->flow_a.packet_count == 1);
        PFL_EXPECT(connection->flow_a.packets.size() == 1);
    }

    {
        CaptureState state {};
        PacketIngestor ingestor {state};
        const FlowKeyV4 flow_key {
            .src_addr = ipv4(10, 0, 0, 1),
            .dst_addr = ipv4(10, 0, 0, 2),
            .src_port = 12000,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        };

        ingestor.ingest(IngestedPacketV4 {.flow_key = flow_key, .packet_ref = packet_ref(1, 100)});
        ingestor.ingest(IngestedPacketV4 {.flow_key = flow_key, .packet_ref = packet_ref(2, 101)});

        const auto* connection = state.ipv4_connections.find(make_connection_key(flow_key));
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(state.ipv4_connections.size() == 1);
        PFL_EXPECT(state.summary.packet_count == 2);
        PFL_EXPECT(state.summary.flow_count == 1);
        PFL_EXPECT(connection->flow_a.packet_count == 2);
        PFL_EXPECT(!connection->has_flow_b);
    }

    {
        CaptureState state {};
        PacketIngestor ingestor {state};
        const FlowKeyV4 flow_a {
            .src_addr = ipv4(10, 0, 0, 1),
            .dst_addr = ipv4(10, 0, 0, 2),
            .src_port = 12000,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        };
        const FlowKeyV4 flow_b {
            .src_addr = ipv4(10, 0, 0, 2),
            .dst_addr = ipv4(10, 0, 0, 1),
            .src_port = 443,
            .dst_port = 12000,
            .protocol = ProtocolId::tcp,
        };

        ingestor.ingest(IngestedPacketV4 {.flow_key = flow_a, .packet_ref = packet_ref(1, 100)});
        ingestor.ingest(IngestedPacketV4 {.flow_key = flow_b, .packet_ref = packet_ref(2, 101)});

        const auto* connection = state.ipv4_connections.find(make_connection_key(flow_a));
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(state.ipv4_connections.size() == 1);
        PFL_EXPECT(state.summary.flow_count == 1);
        PFL_EXPECT(connection->has_flow_b);
        PFL_EXPECT(connection->flow_b.packet_count == 1);
        PFL_EXPECT(connection->packet_count == 2);
    }

    {
        CaptureState state {};
        PacketIngestor ingestor {state};

        ingestor.ingest(IngestedPacketV4 {
            .flow_key = FlowKeyV4 {
                .src_addr = ipv4(10, 0, 0, 1),
                .dst_addr = ipv4(10, 0, 0, 2),
                .src_port = 12000,
                .dst_port = 443,
                .protocol = ProtocolId::tcp,
            },
            .packet_ref = packet_ref(1, 100),
        });
        ingestor.ingest(IngestedPacketV4 {
            .flow_key = FlowKeyV4 {
                .src_addr = ipv4(10, 0, 0, 3),
                .dst_addr = ipv4(10, 0, 0, 4),
                .src_port = 22000,
                .dst_port = 80,
                .protocol = ProtocolId::tcp,
            },
            .packet_ref = packet_ref(2, 110),
        });

        PFL_EXPECT(state.ipv4_connections.size() == 2);
        PFL_EXPECT(state.summary.flow_count == 2);
        PFL_EXPECT(state.summary.packet_count == 2);
    }

    {
        CaptureState state {};
        PacketIngestor ingestor {state};
        const IngestedPacketV6 packet {
            .flow_key = FlowKeyV6 {
                .src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
                .dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}),
                .src_port = 5000,
                .dst_port = 5001,
                .protocol = ProtocolId::udp,
            },
            .packet_ref = packet_ref(10, 80),
        };

        ingestor.ingest(packet);

        PFL_EXPECT(state.ipv6_connections.size() == 1);
        PFL_EXPECT(state.summary.packet_count == 1);
        PFL_EXPECT(state.summary.flow_count == 1);
        PFL_EXPECT(state.summary.total_bytes == 80);

        const auto* connection = state.ipv6_connections.find(make_connection_key(packet.flow_key));
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(connection->has_flow_a);
        PFL_EXPECT(connection->flow_a.packet_count == 1);
    }
}

}  // namespace pfl::tests
