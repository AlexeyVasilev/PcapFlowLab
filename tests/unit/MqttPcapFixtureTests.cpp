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

void expect_mqtt_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_tcp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint == "mqtt");
    PFL_EXPECT(row.service_hint.empty());
}

ExpectedFlowShape client_to_server_port1883_one_packet() {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.130",
        .port_a = 57000U,
        .address_b = "192.0.2.140",
        .port_b = 1883U,
    };
}

}  // namespace

void run_mqtt_pcap_fixture_tests() {
    expect_mqtt_flow(
        "parsing/mqtt/01_mqtt311_connect_port1883.pcap",
        client_to_server_port1883_one_packet());

    expect_mqtt_flow(
        "parsing/mqtt/02_mqtt5_rich_connect_nonstandard_port.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.130",
            .port_a = 57000U,
            .address_b = "192.0.2.140",
            .port_b = 31883U,
        });

    expect_mqtt_flow(
        "parsing/mqtt/03_mqtt31_connect_port1883.pcap",
        client_to_server_port1883_one_packet());

    expect_mqtt_flow(
        "parsing/mqtt/04_mqtt311_connect_plus_pingreq_same_payload.pcap",
        client_to_server_port1883_one_packet());

    expect_no_detected_application_protocol(
        "parsing/mqtt/05_mqtt_garbage_port1883.pcap",
        client_to_server_port1883_one_packet());

    expect_no_detected_application_protocol(
        "parsing/mqtt/06_mqtt_invalid_fixed_header_flags.pcap",
        client_to_server_port1883_one_packet());

    expect_no_detected_application_protocol(
        "parsing/mqtt/07_mqtt_protocol_name_level_mismatch.pcap",
        client_to_server_port1883_one_packet());

    expect_no_detected_application_protocol(
        "parsing/mqtt/08_mqtt_invalid_connect_flags_reserved_bit.pcap",
        client_to_server_port1883_one_packet());

    expect_no_detected_application_protocol(
        "parsing/mqtt/09_mqtt_declared_remaining_length_too_large.pcap",
        client_to_server_port1883_one_packet());

    expect_no_detected_application_protocol(
        "parsing/mqtt/10_mqtt_client_id_length_exceeds_frame.pcap",
        client_to_server_port1883_one_packet());
}

}  // namespace pfl::tests
