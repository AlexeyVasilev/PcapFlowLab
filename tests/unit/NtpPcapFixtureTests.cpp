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

void expect_no_detected_application_protocol(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_udp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint.empty());
    PFL_EXPECT(row.service_hint.empty());
}

void expect_detected_ntp_protocol(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_udp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint == "ntp");
    PFL_EXPECT(row.service_hint.empty());
}

ExpectedFlowShape client_to_server_one_packet(const std::uint16_t server_port) {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.170",
        .port_a = 59000U,
        .address_b = "192.0.2.180",
        .port_b = server_port,
    };
}

ExpectedFlowShape server_to_client_one_packet() {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.180",
        .port_a = 123U,
        .address_b = "192.0.2.170",
        .port_b = 59000U,
    };
}

void expect_target_positive_detection() {
    // Target: NTPv4 mode-3 client request, ephemeral -> UDP/123.
    expect_detected_ntp_protocol(
        "parsing/ntp/01_ntpv4_client_request_port123.pcap",
        client_to_server_one_packet(123U));

    // Target: NTPv4 mode-4 server response, UDP/123 -> ephemeral.
    expect_detected_ntp_protocol(
        "parsing/ntp/02_ntpv4_server_response_port123.pcap",
        server_to_client_one_packet());

    // Target: NTPv3 mode-3 client request.
    expect_detected_ntp_protocol(
        "parsing/ntp/03_ntpv3_client_request_port123.pcap",
        client_to_server_one_packet(123U));

    // Target: NTPv3 mode-4 server response.
    expect_detected_ntp_protocol(
        "parsing/ntp/04_ntpv3_server_response_port123.pcap",
        server_to_client_one_packet());

    // Target: NTPv4 mode-4 stratum-0 KoD-style RATE response.
    expect_detected_ntp_protocol(
        "parsing/ntp/05_ntpv4_kod_rate_response.pcap",
        server_to_client_one_packet());
}

void expect_permanent_negative_or_unsupported_baseline() {
    // Invariant: UDP/123 alone must not imply NTP.
    expect_no_detected_application_protocol(
        "parsing/ntp/06_ntp_garbage_port123.pcap",
        client_to_server_one_packet(123U));

    // Invariant: valid-looking NTP content on non-NTP ports is insufficient.
    expect_no_detected_application_protocol(
        "parsing/ntp/07_ntpv4_client_wrong_ports.pcap",
        client_to_server_one_packet(30123U));

    // First PFL support intentionally excludes NTPv2; this is not malformed NTP.
    expect_no_detected_application_protocol(
        "parsing/ntp/08_ntpv2_client_port123.pcap",
        client_to_server_one_packet(123U));

    // First PFL support intentionally excludes broadcast mode 5; this may be valid-family NTP.
    expect_no_detected_application_protocol(
        "parsing/ntp/09_ntpv4_broadcast_mode5.pcap",
        server_to_client_one_packet());

    // Invariant: an incomplete 47-byte basic header must not detect as NTP.
    expect_no_detected_application_protocol(
        "parsing/ntp/10_ntpv4_truncated_47_byte_header.pcap",
        client_to_server_one_packet(123U));
}

}  // namespace

void run_ntp_pcap_fixture_tests() {
    expect_target_positive_detection();
    expect_permanent_negative_or_unsupported_baseline();
}

}  // namespace pfl::tests
