#include <filesystem>
#include <optional>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "core/index/CaptureIndexReader.h"
#include "core/services/CaptureImporter.h"

namespace pfl::tests {

namespace {

std::uint64_t fragmentation_count(const std::vector<FlowRow>& rows) {
    std::uint64_t count {0};
    for (const auto& row : rows) {
        count += row.fragmented_packet_count;
    }
    return count;
}

}  // namespace

void run_fragmentation_tests() {
    const auto ipv4_mf_packet = make_ethernet_ipv4_fragment_packet(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 6, 0x2000U, {0x16, 0x03, 0x03, 0x00, 0x10});
    const auto ipv4_offset_packet = make_ethernet_ipv4_fragment_packet(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 17, 0x0001U, {0xde, 0xad, 0xbe, 0xef});
    const auto ipv6_fragment_packet = make_ethernet_ipv6_fragment_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
        58,
        make_ipv6_icmpv6_message(128, 0)
    );
    const auto normal_tcp_packet = make_ethernet_ipv4_tcp_packet(
        ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 12345, 443);
    const auto normal_udp_packet = make_ethernet_ipv6_udp_with_hop_by_hop_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}),
        50000,
        53
    );

    const auto capture_path = write_temp_pcap(
        "pfl_fragmentation.pcap",
        make_classic_pcap({
            {100, ipv4_mf_packet},
            {200, ipv4_offset_packet},
            {300, ipv6_fragment_packet},
            {400, normal_tcp_packet},
            {500, normal_udp_packet},
        })
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(capture_path));

    const auto packet0 = session.find_packet(0);
    const auto packet1 = session.find_packet(1);
    const auto packet2 = session.find_packet(2);
    const auto packet3 = session.find_packet(3);
    const auto packet4 = session.find_packet(4);
    PFL_REQUIRE(packet0.has_value());
    PFL_REQUIRE(packet1.has_value());
    PFL_REQUIRE(packet2.has_value());
    PFL_REQUIRE(packet3.has_value());
    PFL_REQUIRE(packet4.has_value());

    PFL_EXPECT(session_detail::derive_transient_packet_metadata(session, *packet0).is_ip_fragmented.value_or(false));
    PFL_EXPECT(session_detail::derive_transient_packet_metadata(session, *packet1).is_ip_fragmented.value_or(false));
    PFL_EXPECT(session_detail::derive_transient_packet_metadata(session, *packet2).is_ip_fragmented.value_or(false));
    PFL_EXPECT(!session_detail::derive_transient_packet_metadata(session, *packet3).is_ip_fragmented.value_or(false));
    PFL_EXPECT(!session_detail::derive_transient_packet_metadata(session, *packet4).is_ip_fragmented.value_or(false));

    const auto details0 = session.read_packet_details(*packet0);
    PFL_REQUIRE(details0.has_value());
    PFL_EXPECT(details0->has_ipv4);
    PFL_EXPECT(!details0->has_tcp);
    PFL_EXPECT(!details0->has_udp);
    PFL_EXPECT(!details0->has_icmp);

    const auto details1 = session.read_packet_details(*packet1);
    PFL_REQUIRE(details1.has_value());
    PFL_EXPECT(details1->has_ipv4);
    PFL_EXPECT(!details1->has_tcp);
    PFL_EXPECT(!details1->has_udp);

    const auto details2 = session.read_packet_details(*packet2);
    PFL_REQUIRE(details2.has_value());
    PFL_EXPECT(details2->has_ipv6);
    PFL_EXPECT(!details2->has_icmpv6);
    PFL_EXPECT(!details2->has_udp);
    PFL_EXPECT(!details2->has_tcp);

    const auto details3 = session.read_packet_details(*packet3);
    PFL_REQUIRE(details3.has_value());
    PFL_EXPECT(details3->has_tcp);
    PFL_EXPECT(!details3->has_ipv6);

    const auto details4 = session.read_packet_details(*packet4);
    PFL_REQUIRE(details4.has_value());
    PFL_EXPECT(details4->has_ipv6);
    PFL_EXPECT(details4->has_udp);

    PFL_EXPECT(session.read_packet_payload_hex_dump(*packet0).empty());
    PFL_EXPECT(session.read_packet_payload_hex_dump(*packet1).empty());
    PFL_EXPECT(session.read_packet_payload_hex_dump(*packet2).empty());

    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 5);
    PFL_EXPECT(fragmentation_count(rows) == 3U);

    std::size_t fragmented_flows {0};
    for (const auto& row : rows) {
        if (row.has_fragmented_packets) {
            ++fragmented_flows;
            PFL_EXPECT(row.fragmented_packet_count == 1U);
        } else {
            PFL_EXPECT(row.fragmented_packet_count == 0U);
        }
    }
    PFL_EXPECT(fragmented_flows == 3U);

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_fragmentation.idx";
    std::filesystem::remove(index_path);
    PFL_EXPECT(session.save_index(index_path));

    CaptureSession loaded_session {};
    PFL_EXPECT(loaded_session.load_index(index_path));
    const auto loaded_rows = loaded_session.list_flows();
    PFL_EXPECT(fragmentation_count(loaded_rows) == 3U);
    const auto loaded_packet0 = loaded_session.find_packet(0);
    const auto loaded_packet2 = loaded_session.find_packet(2);
    PFL_REQUIRE(loaded_packet0.has_value());
    PFL_REQUIRE(loaded_packet2.has_value());
    PFL_EXPECT(session_detail::derive_transient_packet_metadata(loaded_session, *loaded_packet0).is_ip_fragmented.value_or(false));
    PFL_EXPECT(session_detail::derive_transient_packet_metadata(loaded_session, *loaded_packet2).is_ip_fragmented.value_or(false));

    const auto mf_flow_packets = session.list_flow_packets(0);
    PFL_REQUIRE(!mf_flow_packets.empty());
    PFL_EXPECT(mf_flow_packets.front().row_number == 1U);
}

}  // namespace pfl::tests
