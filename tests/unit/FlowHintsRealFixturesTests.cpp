#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

/*
 * Regression fixtures ported from the old project.
 * The capture files are reused as fixture data only; assertions target the
 * current Pcap Flow Lab API and current single-packet hint extraction limits.
 */

struct FixtureExpectation {
    std::filesystem::path relative_path {};
    std::string expected_protocol_hint {};
    std::optional<std::string> expected_service_hint {};
};

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

bool has_matching_flow(const std::vector<FlowRow>& rows,
                       const std::string& protocol_hint,
                       const std::optional<std::string>& service_hint) {
    for (const auto& row : rows) {
        if (row.protocol_hint != protocol_hint) {
            continue;
        }

        if (service_hint.has_value() && row.service_hint != *service_hint) {
            continue;
        }

        return true;
    }

    return false;
}

void expect_fixture(const FixtureExpectation& expectation) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(expectation.relative_path)));
    PFL_EXPECT(session.summary().packet_count > 0);

    const auto rows = session.list_flows();
    PFL_EXPECT(!rows.empty());

    if (expectation.expected_protocol_hint.empty()) {
        return;
    }

    PFL_EXPECT(has_matching_flow(rows, expectation.expected_protocol_hint, expectation.expected_service_hint));
}

}  // namespace

void run_flow_hints_real_fixtures_tests() {
    const std::vector<FixtureExpectation> fixtures {
        {.relative_path = "parsing/http/http_get_1.pcap", .expected_protocol_hint = "http", .expected_service_hint = "www.kresla-darom.ru"},
        {.relative_path = "parsing/http/http_answer_2.pcap", .expected_protocol_hint = "http"},
        {.relative_path = "parsing/dns/dns_request_1.pcap", .expected_protocol_hint = "dns", .expected_service_hint = "gsp85-ssl.ls.apple.com"},
        {.relative_path = "parsing/dns/dns_response_2.pcap", .expected_protocol_hint = "dns", .expected_service_hint = "_dns.resolver.arpa"},
        {.relative_path = "parsing/tls/tls_client_hello_1.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "auth.split.io"},
        {.relative_path = "parsing/tls/tls_1_2_change_cipher_spec_2.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_2_app_data_3.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_2_server_hello_4.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_2_new_session_ticket_9.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_3_client_hello_5.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "p101-fmf.icloud.com"},
        {.relative_path = "parsing/tls/tls_1_3_server_hello_6.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_3_app_data_7.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_3_change_cipher_spec_8.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/quic/quic_initial_ch_1.pcap", .expected_protocol_hint = "quic"},
        {.relative_path = "parsing/quic/quic_initial_sh_2.pcap", .expected_protocol_hint = "quic"},
        {.relative_path = "parsing/quic/quic_handshake_3.pcap", .expected_protocol_hint = "quic"},
        {.relative_path = "parsing/quic/quic_protected_payload_4.pcap", .expected_protocol_hint = ""},
    };

    for (const auto& fixture : fixtures) {
        expect_fixture(fixture);
    }
}

}  // namespace pfl::tests
