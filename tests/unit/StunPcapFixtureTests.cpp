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

FlowRow require_single_udp_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == expected.capture_packet_count);
    PFL_EXPECT(session.summary().flow_count == expected.capture_flow_count);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    const auto& row = rows[0];
    PFL_EXPECT(row.protocol_text == "UDP");
    PFL_EXPECT(row.packet_count == expected.flow_packet_count);
    PFL_EXPECT(row.address_a == expected.address_a);
    PFL_EXPECT(row.port_a == expected.port_a);
    PFL_EXPECT(row.address_b == expected.address_b);
    PFL_EXPECT(row.port_b == expected.port_b);
    return row;
}

void expect_stun_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_udp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint == "stun");
    PFL_EXPECT(row.service_hint.empty());
}

void expect_not_stun_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_udp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint != "stun");
    PFL_EXPECT(row.service_hint.empty());
}

}  // namespace

void run_stun_pcap_fixture_tests() {
    expect_stun_flow(
        "parsing/stun/01_stun_binding_request_3478.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 3478U,
        });

    expect_stun_flow(
        "parsing/stun/02_stun_binding_request_response.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 2U,
            .capture_flow_count = 1U,
            .flow_packet_count = 2U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 3478U,
        });

    expect_stun_flow(
        "parsing/stun/03_stun_binding_request_nonstandard_port.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 45678U,
        });

    expect_not_stun_flow(
        "parsing/stun/04_stun_bad_magic_cookie.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 3478U,
        });

    expect_not_stun_flow(
        "parsing/stun/05_stun_invalid_top_bits.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 3478U,
        });

    expect_not_stun_flow(
        "parsing/stun/06_stun_declared_length_mismatch.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 3478U,
        });
}

}  // namespace pfl::tests
