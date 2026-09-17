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

void expect_pop3_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_tcp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint == "pop3");
    PFL_EXPECT(row.service_hint.empty());
}

void expect_not_pop3_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_tcp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint != "pop3");
    PFL_EXPECT(row.service_hint.empty());
}

ExpectedFlowShape client_to_server_port110_one_packet() {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.90",
        .port_a = 55000U,
        .address_b = "192.0.2.100",
        .port_b = 110U,
    };
}

}  // namespace

void run_pop3_pcap_fixture_tests() {
    expect_pop3_flow(
        "parsing/pop3/01_pop3_greeting_user_port110.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 2U,
            .capture_flow_count = 1U,
            .flow_packet_count = 2U,
            .address_a = "192.0.2.100",
            .port_a = 110U,
            .address_b = "192.0.2.90",
            .port_b = 55000U,
        });

    expect_pop3_flow(
        "parsing/pop3/02_pop3_pass_port110.pcap",
        client_to_server_port110_one_packet());

    expect_pop3_flow(
        "parsing/pop3/03_pop3_user_after_unmatched_payload.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 2U,
            .capture_flow_count = 1U,
            .flow_packet_count = 2U,
            .address_a = "192.0.2.90",
            .port_a = 55000U,
            .address_b = "192.0.2.100",
            .port_b = 110U,
        });

    expect_not_pop3_flow(
        "parsing/pop3/04_pop3_user_port1110_not_detected.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.90",
            .port_a = 55000U,
            .address_b = "192.0.2.100",
            .port_b = 1110U,
        });

    expect_not_pop3_flow(
        "parsing/pop3/05_pop3_invalid_usxr_port110.pcap",
        client_to_server_port110_one_packet());
}

}  // namespace pfl::tests
