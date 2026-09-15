#include <cstdint>
#include <filesystem>
#include <string>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

struct ExpectedFlowShape {
    std::uint64_t capture_packet_count {0};
    std::uint64_t capture_flow_count {0};
    std::uint64_t flow_packet_count {0};
    std::string address_a {};
    std::uint16_t port_a {0};
    std::string address_b {};
    std::uint16_t port_b {0};
};

FlowRow require_single_tcp_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == expected.capture_packet_count);
    PFL_EXPECT(session.summary().flow_count == expected.capture_flow_count);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    const auto& row = rows[0];
    PFL_EXPECT(row.protocol_text == "TCP");
    PFL_EXPECT(row.packet_count == expected.flow_packet_count);
    PFL_EXPECT(row.address_a == expected.address_a);
    PFL_EXPECT(row.port_a == expected.port_a);
    PFL_EXPECT(row.address_b == expected.address_b);
    PFL_EXPECT(row.port_b == expected.port_b);
    return row;
}

void expect_bittorrent_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_tcp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint == "bittorrent");
    PFL_EXPECT(row.service_hint.empty());
}

void expect_not_bittorrent_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_tcp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint != "bittorrent");
    PFL_EXPECT(row.service_hint.empty());
}

ExpectedFlowShape typical_ports_one_packet() {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.50",
        .port_a = 51413U,
        .address_b = "192.0.2.60",
        .port_b = 6881U,
    };
}

}  // namespace

void run_bittorrent_pcap_fixture_tests() {
    expect_bittorrent_flow(
        "parsing/bittorrent/01_bittorrent_handshake_typical_ports.pcap",
        typical_ports_one_packet());

    expect_bittorrent_flow(
        "parsing/bittorrent/02_bittorrent_bidirectional_nonstandard_ports.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 2U,
            .capture_flow_count = 1U,
            .flow_packet_count = 2U,
            .address_a = "192.0.2.50",
            .port_a = 53000U,
            .address_b = "192.0.2.60",
            .port_b = 55000U,
        });

    expect_bittorrent_flow(
        "parsing/bittorrent/03_bittorrent_handshake_plus_keepalive.pcap",
        typical_ports_one_packet());

    expect_not_bittorrent_flow(
        "parsing/bittorrent/04_bittorrent_invalid_pstrlen.pcap",
        typical_ports_one_packet());

    expect_not_bittorrent_flow(
        "parsing/bittorrent/05_bittorrent_invalid_protocol_string.pcap",
        typical_ports_one_packet());

    expect_not_bittorrent_flow(
        "parsing/bittorrent/06_bittorrent_short_67_byte_handshake.pcap",
        typical_ports_one_packet());
}

}  // namespace pfl::tests
