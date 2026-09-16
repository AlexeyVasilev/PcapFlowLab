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

void expect_smtp_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_tcp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint == "smtp");
    PFL_EXPECT(row.service_hint.empty());
}

void expect_not_smtp_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_tcp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint != "smtp");
    PFL_EXPECT(row.service_hint.empty());
}

ExpectedFlowShape client_to_server_port25_one_packet() {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.70",
        .port_a = 54000U,
        .address_b = "192.0.2.80",
        .port_b = 25U,
    };
}

}  // namespace

void run_smtp_pcap_fixture_tests() {
    expect_smtp_flow(
        "parsing/smtp/01_smtp_greeting_ehlo_port25.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 2U,
            .capture_flow_count = 1U,
            .flow_packet_count = 2U,
            .address_a = "192.0.2.80",
            .port_a = 25U,
            .address_b = "192.0.2.70",
            .port_b = 54000U,
        });

    expect_smtp_flow(
        "parsing/smtp/02_smtp_helo_port25.pcap",
        client_to_server_port25_one_packet());

    expect_smtp_flow(
        "parsing/smtp/03_smtp_mail_from_port587.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.70",
            .port_a = 54000U,
            .address_b = "192.0.2.80",
            .port_b = 587U,
        });

    expect_smtp_flow(
        "parsing/smtp/04_smtp_ehlo_after_unmatched_payload.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 2U,
            .capture_flow_count = 1U,
            .flow_packet_count = 2U,
            .address_a = "192.0.2.70",
            .port_a = 54000U,
            .address_b = "192.0.2.80",
            .port_b = 25U,
        });

    expect_not_smtp_flow(
        "parsing/smtp/05_smtp_ehlo_port2525_not_detected.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.70",
            .port_a = 54000U,
            .address_b = "192.0.2.80",
            .port_b = 2525U,
        });

    expect_not_smtp_flow(
        "parsing/smtp/06_smtp_invalid_ehxlo_port25.pcap",
        client_to_server_port25_one_packet());
}

}  // namespace pfl::tests
