#include <array>
#include <cstddef>
#include <cstdint>

#include "TestSupport.h"
#include "core/domain/CaptureState.h"
#include "core/domain/Connection.h"
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

PacketRef packet_ref(std::uint64_t index,
                     std::uint32_t original_length,
                     std::uint32_t payload_length = 0U,
                     bool is_ip_fragmented = false) {
    return PacketRef {
        .packet_index = index,
        .byte_offset = index * 64U,
        .captured_length = original_length,
        .original_length = original_length,
        .payload_length = payload_length,
        .is_ip_fragmented = is_ip_fragmented,
    };
}

}  // namespace

void run_connection_tests() {
    const FlowKeyV4 flow_v4_ab {
        .src_addr = ipv4(10, 0, 0, 1),
        .dst_addr = ipv4(10, 0, 0, 2),
        .src_port = 12345,
        .dst_port = 443,
        .protocol = ProtocolId::tcp,
    };
    const FlowKeyV4 flow_v4_ba {
        .src_addr = ipv4(10, 0, 0, 2),
        .dst_addr = ipv4(10, 0, 0, 1),
        .src_port = 443,
        .dst_port = 12345,
        .protocol = ProtocolId::tcp,
    };

    ConnectionV4 connection_v4 {
        .key = make_connection_key(flow_v4_ab),
    };

    connection_v4.add_packet(flow_v4_ab, packet_ref(1, 100));
    PFL_EXPECT(connection_v4.has_flow_a);
    PFL_EXPECT(!connection_v4.has_flow_b);
    PFL_EXPECT(connection_v4.flow_a.key == flow_v4_ab);
    PFL_EXPECT(connection_v4.flow_a.packet_count == 1);

    connection_v4.add_packet(flow_v4_ab, packet_ref(2, 110));
    PFL_EXPECT(connection_v4.flow_a.packet_count == 2);
    PFL_EXPECT(connection_v4.flow_a.packets.size() == 2);

    connection_v4.add_packet(flow_v4_ba, packet_ref(3, 120));
    PFL_EXPECT(connection_v4.has_flow_b);
    PFL_EXPECT(connection_v4.flow_b.key == flow_v4_ba);
    PFL_EXPECT(connection_v4.flow_b.packet_count == 1);

    connection_v4.add_packet(flow_v4_ba, packet_ref(4, 130));
    PFL_EXPECT(connection_v4.flow_b.packet_count == 2);
    PFL_EXPECT(connection_v4.flow_b.packets.size() == 2);

    PFL_EXPECT(connection_v4.packet_count == 4);
    PFL_EXPECT(connection_v4.total_bytes == 460);
    PFL_EXPECT(connection_v4.flow_a.total_bytes == 210);
    PFL_EXPECT(connection_v4.flow_b.total_bytes == 250);

    const FlowKeyV6 flow_v6_ab {
        .src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
        .dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}),
        .src_port = 5000,
        .dst_port = 5001,
        .protocol = ProtocolId::udp,
    };
    const FlowKeyV6 flow_v6_ba {
        .src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}),
        .dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
        .src_port = 5001,
        .dst_port = 5000,
        .protocol = ProtocolId::udp,
    };

    ConnectionV6 connection_v6 {
        .key = make_connection_key(flow_v6_ab),
    };

    connection_v6.add_packet(flow_v6_ab, packet_ref(10, 80));
    connection_v6.add_packet(flow_v6_ba, packet_ref(11, 81));
    connection_v6.add_packet(flow_v6_ba, packet_ref(12, 82));

    PFL_EXPECT(connection_v6.has_flow_a);
    PFL_EXPECT(connection_v6.has_flow_b);
    PFL_EXPECT(connection_v6.flow_a.key == flow_v6_ab);
    PFL_EXPECT(connection_v6.flow_b.key == flow_v6_ba);
    PFL_EXPECT(connection_v6.flow_a.packet_count == 1);
    PFL_EXPECT(connection_v6.flow_b.packet_count == 2);
    PFL_EXPECT(connection_v6.packet_count == 3);
    PFL_EXPECT(connection_v6.total_bytes == 243);

    const FlowV4 empty_flow_v4 {};
    const FlowV6 empty_flow_v6 {};

    PFL_EXPECT(empty_flow_v4.empty());
    PFL_EXPECT(empty_flow_v6.empty());

    {
        ConnectionV4 http_connection {};
        http_connection.protocol_hint = FlowProtocolHint::http;
        PFL_EXPECT(!http_connection.hint_detection_settled());
        PFL_EXPECT(http_connection.should_attempt_hint_detection(packet_ref(20, 64, 24), ProtocolId::tcp));
        PFL_EXPECT(!http_connection.should_attempt_hint_detection(packet_ref(21, 64, 0), ProtocolId::tcp));

        for (std::uint8_t attempt = 0; attempt < kMaxUnresolvedHintPayloadAttemptsPerConnection; ++attempt) {
            http_connection.note_hint_detection_attempt(packet_ref(30U + attempt, 96, 24), ProtocolId::tcp);
        }

        PFL_EXPECT(http_connection.hint_search_state.unresolved_payload_attempt_count ==
                   kMaxUnresolvedHintPayloadAttemptsPerConnection);
        PFL_EXPECT(http_connection.hint_search_state.unresolved_payload_attempt_budget_exhausted);
        PFL_EXPECT(!http_connection.should_attempt_hint_detection(packet_ref(99, 96, 24), ProtocolId::tcp));
    }

    {
        ConnectionV4 settled_service_connection {};
        settled_service_connection.service_hint = "example.org";
        PFL_EXPECT(settled_service_connection.hint_detection_settled());
        PFL_EXPECT(!settled_service_connection.should_attempt_hint_detection(packet_ref(40, 128, 64), ProtocolId::tcp));
        settled_service_connection.note_hint_detection_attempt(packet_ref(41, 128, 64), ProtocolId::tcp);
        PFL_EXPECT(settled_service_connection.hint_search_state.unresolved_payload_attempt_count == 0U);
        PFL_EXPECT(!settled_service_connection.hint_search_state.unresolved_payload_attempt_budget_exhausted);
    }

    {
        ConnectionV6 ssh_connection {};
        ssh_connection.protocol_hint = FlowProtocolHint::ssh;
        PFL_EXPECT(ssh_connection.hint_detection_settled());
        PFL_EXPECT(!ssh_connection.should_attempt_hint_detection(packet_ref(50, 90, 12), ProtocolId::tcp));
    }

    {
        CaptureState state {};
        PacketIngestor ingestor {state};
        const auto packet = IngestedPacketV4 {
            .flow_key = flow_v4_ab,
            .packet_ref = packet_ref(60, 144, 48),
        };

        auto& ingested_connection = ingestor.ingest(packet);
        const auto key = make_connection_key(flow_v4_ab);
        const auto* stored_connection = state.ipv4_connections.find(key);

        PFL_REQUIRE(stored_connection != nullptr);
        PFL_EXPECT(&ingested_connection == stored_connection);
        PFL_EXPECT(ingested_connection.packet_count == 1U);
        PFL_EXPECT(ingested_connection.total_bytes == 144U);
        PFL_EXPECT(state.summary.packet_count == 1U);
        PFL_EXPECT(state.summary.total_bytes == 144U);
        PFL_EXPECT(state.summary.flow_count == 1U);
    }

    {
        CaptureState state {};
        PacketIngestor ingestor {state};
        const auto packet = IngestedPacketV6 {
            .flow_key = flow_v6_ab,
            .packet_ref = packet_ref(61, 188, 64),
        };

        auto& ingested_connection = ingestor.ingest(packet);
        const auto key = make_connection_key(flow_v6_ab);
        const auto* stored_connection = state.ipv6_connections.find(key);

        PFL_REQUIRE(stored_connection != nullptr);
        PFL_EXPECT(&ingested_connection == stored_connection);
        PFL_EXPECT(ingested_connection.packet_count == 1U);
        PFL_EXPECT(ingested_connection.total_bytes == 188U);
        PFL_EXPECT(state.summary.packet_count == 1U);
        PFL_EXPECT(state.summary.total_bytes == 188U);
        PFL_EXPECT(state.summary.flow_count == 1U);
    }
}

}  // namespace pfl::tests
