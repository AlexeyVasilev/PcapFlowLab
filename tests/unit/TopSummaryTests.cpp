#include <cstdint>
#include <filesystem>
#include <utility>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

void expect_top_summary_equal(const CaptureTopSummary& left, const CaptureTopSummary& right) {
    PFL_EXPECT(left.endpoints_by_bytes.size() == right.endpoints_by_bytes.size());
    PFL_EXPECT(left.ports_by_bytes.size() == right.ports_by_bytes.size());

    for (std::size_t index = 0; index < left.endpoints_by_bytes.size(); ++index) {
        PFL_EXPECT(left.endpoints_by_bytes[index].endpoint == right.endpoints_by_bytes[index].endpoint);
        PFL_EXPECT(left.endpoints_by_bytes[index].packet_count == right.endpoints_by_bytes[index].packet_count);
        PFL_EXPECT(left.endpoints_by_bytes[index].total_bytes == right.endpoints_by_bytes[index].total_bytes);
    }

    for (std::size_t index = 0; index < left.ports_by_bytes.size(); ++index) {
        PFL_EXPECT(left.ports_by_bytes[index].port == right.ports_by_bytes[index].port);
        PFL_EXPECT(left.ports_by_bytes[index].packet_count == right.ports_by_bytes[index].packet_count);
        PFL_EXPECT(left.ports_by_bytes[index].total_bytes == right.ports_by_bytes[index].total_bytes);
    }
}

void expect_top_summary_prefix_equal(
    const CaptureTopSummary& expected_prefix,
    const CaptureTopSummary& actual,
    const std::size_t prefix_length
) {
    PFL_EXPECT(expected_prefix.endpoints_by_bytes.size() >= prefix_length);
    PFL_EXPECT(expected_prefix.ports_by_bytes.size() >= prefix_length);
    PFL_EXPECT(actual.endpoints_by_bytes.size() >= prefix_length);
    PFL_EXPECT(actual.ports_by_bytes.size() >= prefix_length);

    for (std::size_t index = 0; index < prefix_length; ++index) {
        PFL_EXPECT(expected_prefix.endpoints_by_bytes[index].endpoint == actual.endpoints_by_bytes[index].endpoint);
        PFL_EXPECT(expected_prefix.endpoints_by_bytes[index].packet_count == actual.endpoints_by_bytes[index].packet_count);
        PFL_EXPECT(expected_prefix.endpoints_by_bytes[index].total_bytes == actual.endpoints_by_bytes[index].total_bytes);
        PFL_EXPECT(expected_prefix.ports_by_bytes[index].port == actual.ports_by_bytes[index].port);
        PFL_EXPECT(expected_prefix.ports_by_bytes[index].packet_count == actual.ports_by_bytes[index].packet_count);
        PFL_EXPECT(expected_prefix.ports_by_bytes[index].total_bytes == actual.ports_by_bytes[index].total_bytes);
    }
}

}  // namespace

void run_top_summary_tests() {
    const auto tcp_ab = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80);
    const auto tcp_ba = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 80, 1111);
    const auto udp_ac = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 3), 1111, 22);
    const auto udp_de = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 4), ipv4(10, 0, 0, 5), 53000, 53);

    const auto capture_path = write_temp_pcap(
        "pfl_top_summary.pcap",
        make_classic_pcap({
            {100, tcp_ab},
            {200, tcp_ba},
            {300, udp_ac},
            {400, udp_de},
        })
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(capture_path));

    const auto summary = session.top_summary();
    PFL_EXPECT(summary.endpoints_by_bytes.size() == 5);
    PFL_EXPECT(summary.ports_by_bytes.size() == 5);

    PFL_EXPECT(summary.endpoints_by_bytes[0].endpoint == "10.0.0.1:1111");
    PFL_EXPECT(summary.endpoints_by_bytes[0].packet_count == 3);
    PFL_EXPECT(summary.endpoints_by_bytes[0].total_bytes == tcp_ab.size() + tcp_ba.size() + udp_ac.size());

    PFL_EXPECT(summary.endpoints_by_bytes[1].endpoint == "10.0.0.2:80");
    PFL_EXPECT(summary.endpoints_by_bytes[1].packet_count == 2);
    PFL_EXPECT(summary.endpoints_by_bytes[1].total_bytes == tcp_ab.size() + tcp_ba.size());

    PFL_EXPECT(summary.ports_by_bytes[0].port == 1111);
    PFL_EXPECT(summary.ports_by_bytes[0].packet_count == 3);
    PFL_EXPECT(summary.ports_by_bytes[0].total_bytes == tcp_ab.size() + tcp_ba.size() + udp_ac.size());

    PFL_EXPECT(summary.ports_by_bytes[1].port == 80);
    PFL_EXPECT(summary.ports_by_bytes[1].packet_count == 2);
    PFL_EXPECT(summary.ports_by_bytes[1].total_bytes == tcp_ab.size() + tcp_ba.size());

    const auto limited = session.top_summary(2);
    PFL_EXPECT(limited.endpoints_by_bytes.size() == 2);
    PFL_EXPECT(limited.ports_by_bytes.size() == 2);
    PFL_EXPECT(limited.endpoints_by_bytes[0].endpoint == summary.endpoints_by_bytes[0].endpoint);
    PFL_EXPECT(limited.ports_by_bytes[0].port == summary.ports_by_bytes[0].port);

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_top_summary.idx";
    std::filesystem::remove(index_path);
    PFL_EXPECT(session.save_index(index_path));

    CaptureSession loaded_session {};
    PFL_EXPECT(loaded_session.load_index(index_path));
    expect_top_summary_equal(summary, loaded_session.top_summary());

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> top_many_packets {};
    top_many_packets.reserve(25U);
    for (std::uint8_t index = 0U; index < 25U; ++index) {
        top_many_packets.push_back({
            static_cast<std::uint32_t>(1000U + index),
            make_ethernet_ipv4_udp_packet(
                ipv4(10, 50, 0, static_cast<std::uint8_t>(index + 1U)),
                ipv4(10, 51, 0, static_cast<std::uint8_t>(index + 1U)),
                static_cast<std::uint16_t>(4000U + index),
                static_cast<std::uint16_t>(5000U + index)
            ),
        });
    }

    const auto many_capture_path = write_temp_pcap(
        "pfl_top_summary_large_limit.pcap",
        make_classic_pcap(top_many_packets)
    );
    CaptureSession many_session {};
    PFL_EXPECT(many_session.open_capture(many_capture_path));

    const auto top_five = many_session.top_summary();
    const auto top_twenty = many_session.top_summary(20U);
    const auto top_twenty_five = many_session.top_summary(25U);
    PFL_EXPECT(top_five.endpoints_by_bytes.size() == 5U);
    PFL_EXPECT(top_five.ports_by_bytes.size() == 5U);
    PFL_EXPECT(top_twenty.endpoints_by_bytes.size() == 20U);
    PFL_EXPECT(top_twenty.ports_by_bytes.size() == 20U);
    PFL_EXPECT(top_twenty_five.endpoints_by_bytes.size() == 25U);
    PFL_EXPECT(top_twenty_five.ports_by_bytes.size() == 25U);
    expect_top_summary_prefix_equal(top_twenty, top_twenty_five, 20U);
    expect_top_summary_prefix_equal(top_five, top_twenty, 5U);
}

}  // namespace pfl::tests
