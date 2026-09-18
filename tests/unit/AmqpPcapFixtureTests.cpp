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

void expect_no_detected_application_protocol(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_tcp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint.empty());
    PFL_EXPECT(row.service_hint.empty());
}

void expect_detected_amqp_protocol(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_tcp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint == "amqp");
    PFL_EXPECT(row.service_hint.empty());
}

ExpectedFlowShape client_to_server_one_packet(const std::uint16_t server_port) {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.150",
        .port_a = 58000U,
        .address_b = "192.0.2.160",
        .port_b = server_port,
    };
}

void expect_target_positive_detection() {
    expect_detected_amqp_protocol(
        "parsing/amqp/01_amqp091_header_port5672.pcap",
        client_to_server_one_packet(5672U));

    expect_detected_amqp_protocol(
        "parsing/amqp/02_amqp091_header_nonstandard_port.pcap",
        client_to_server_one_packet(35672U));

    expect_detected_amqp_protocol(
        "parsing/amqp/03_amqp10_core_header_port5672.pcap",
        client_to_server_one_packet(5672U));

    expect_detected_amqp_protocol(
        "parsing/amqp/04_amqp10_sasl_header_nonstandard_port.pcap",
        client_to_server_one_packet(35672U));

    expect_detected_amqp_protocol(
        "parsing/amqp/05_amqp10_tls_header_nonstandard_port.pcap",
        client_to_server_one_packet(35672U));
}

void expect_permanent_negative_baseline() {
    expect_no_detected_application_protocol(
        "parsing/amqp/06_amqp_garbage_port5672.pcap",
        client_to_server_one_packet(5672U));

    expect_no_detected_application_protocol(
        "parsing/amqp/07_amqp091_wrong_version.pcap",
        client_to_server_one_packet(5672U));

    expect_no_detected_application_protocol(
        "parsing/amqp/08_amqp10_unsupported_protocol_id.pcap",
        client_to_server_one_packet(5672U));

    expect_no_detected_application_protocol(
        "parsing/amqp/09_amqp10_wrong_revision.pcap",
        client_to_server_one_packet(5672U));

    expect_no_detected_application_protocol(
        "parsing/amqp/10_amqp_truncated_header.pcap",
        client_to_server_one_packet(5672U));
}

}  // namespace

void run_amqp_pcap_fixture_tests() {
    expect_target_positive_detection();
    expect_permanent_negative_baseline();
}

}  // namespace pfl::tests
