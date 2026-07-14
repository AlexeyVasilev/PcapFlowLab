#include <cstddef>
#include <cstdint>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/services/CaptureImporter.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_pcapng_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 12345, 443);

    {
        const auto path = write_temp_pcap(
            "pfl_pcapng_single_tcp.pcapng",
            make_pcapng({
                make_pcapng_section_header_block(),
                make_pcapng_interface_description_block(1, 65535, true, std::uint8_t {6}),
                make_pcapng_enhanced_packet_block(0, 1, 100, tcp_packet),
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        PFL_EXPECT(session.summary().flow_count == 1);
        PFL_EXPECT(session.state().ipv4_connections.size() == 1);

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(packet->ts_sec == 1);
        PFL_EXPECT(packet->ts_usec == 100);
        PFL_EXPECT(session.read_packet_data(*packet) == tcp_packet);
    }

    {
        const auto reverse_tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 2), ipv4(10, 1, 0, 1), 443, 12345);
        const auto path = write_temp_pcap(
            "pfl_pcapng_reverse_flow.pcapng",
            make_pcapng({
                make_pcapng_section_header_block(),
                make_pcapng_interface_description_block(),
                make_pcapng_enhanced_packet_block(0, 1, 100, tcp_packet),
                make_pcapng_enhanced_packet_block(0, 1, 200, reverse_tcp_packet),
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 2);
        PFL_EXPECT(session.summary().flow_count == 1);
        PFL_EXPECT(session.state().ipv4_connections.size() == 1);

        const auto connections = session.state().ipv4_connections.list();
        PFL_REQUIRE(connections.size() == 1U);
        const auto* connection = connections.front();
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(connection->has_flow_a);
        PFL_EXPECT(connection->has_flow_b);
        PFL_EXPECT(connection->flow_a.packet_count == 1);
        PFL_EXPECT(connection->flow_b.packet_count == 1);
        PFL_EXPECT(connection->flow_a.packets.front().packet_index == 0);
        PFL_EXPECT(connection->flow_b.packets.front().packet_index == 1);

        session.prepare_selected_flow_packet_cache(0U, 2U);
        const auto cache_info = session.selected_flow_packet_cache_info();
        PFL_EXPECT(cache_info.has_value());
        PFL_EXPECT(cache_info->flow_index == 0U);
        PFL_EXPECT(cache_info->cached_packet_window_count == 2U);
        PFL_EXPECT(cache_info->cached_packet_contribution_count == 2U);
        PFL_EXPECT(cache_info->window_fully_cached);

        const auto flow_packets = session.flow_packets(0U);
        PFL_EXPECT(flow_packets.has_value());
        PFL_EXPECT(flow_packets->size() == 2U);
        PFL_EXPECT(session.read_packet_data((*flow_packets)[0]) == tcp_packet);
        PFL_EXPECT(session.read_packet_data((*flow_packets)[1]) == reverse_tcp_packet);
    }

    {
        const auto path = write_temp_pcap(
            "pfl_pcapng_non_ethernet.pcapng",
            make_pcapng({
                make_pcapng_section_header_block(),
                make_pcapng_interface_description_block(101, 65535),
                make_pcapng_enhanced_packet_block(0, 1, 50, tcp_packet),
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 0);
        PFL_EXPECT(session.summary().flow_count == 0);
        PFL_EXPECT(session.list_flows().empty());
    }

    {
        auto malformed = make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0, 1, 100, tcp_packet),
        });
        malformed[32] = 0x08;
        malformed[33] = 0x00;
        malformed[34] = 0x00;
        malformed[35] = 0x00;
        const auto malformed_path = write_temp_pcap("pfl_pcapng_bad_length.pcapng", malformed);

        CaptureSession session {};
        PFL_EXPECT(!session.open_capture(malformed_path));
    }

    {
        auto truncated = make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0, 1, 100, tcp_packet),
        });
        truncated.pop_back();
        const auto truncated_path = write_temp_pcap("pfl_pcapng_truncated.pcapng", truncated);

        CaptureImporter importer {};
        CaptureState state {};
        PFL_EXPECT(!importer.import_capture(truncated_path, state));
    }
}

}  // namespace pfl::tests
