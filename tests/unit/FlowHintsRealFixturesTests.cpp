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
 * current Pcap Flow Lab API and current bounded QUIC Initial SNI extraction.
 */

struct FixtureExpectation {
    std::filesystem::path relative_path {};
    std::string expected_protocol_hint {};
    std::optional<std::string> expected_service_hint {};
};

struct QuicSniFixtureExpectation {
    std::filesystem::path relative_path {};
    std::optional<std::string> expected_sni {};
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

std::optional<std::size_t> find_flow_index_with_protocol_hint(const std::vector<FlowRow>& rows,
                                                              const std::string& protocol_hint) {
    for (std::size_t index = 0U; index < rows.size(); ++index) {
        if (rows[index].protocol_hint == protocol_hint) {
            return index;
        }
    }

    return std::nullopt;
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

void expect_quic_sni_fixture(const QuicSniFixtureExpectation& expectation) {
    CaptureImportOptions deep_options {};
    deep_options.mode = ImportMode::deep;

    CaptureSession deep_session {};
    PFL_EXPECT(deep_session.open_capture(fixture_path(expectation.relative_path), deep_options));
    const auto deep_rows = deep_session.list_flows();
    PFL_EXPECT(!deep_rows.empty());

    const auto deep_quic_flow_index = find_flow_index_with_protocol_hint(deep_rows, "quic");
    PFL_EXPECT(deep_quic_flow_index.has_value());

    const auto& deep_quic_row = deep_rows[*deep_quic_flow_index];
    const auto deep_sni = deep_quic_row.service_hint.empty()
        ? std::optional<std::string> {}
        : std::optional<std::string> {deep_quic_row.service_hint};

    if (expectation.expected_sni.has_value()) {
        PFL_EXPECT(deep_sni.has_value());
        PFL_EXPECT(*deep_sni == *expectation.expected_sni);
    } else {
        PFL_EXPECT(!deep_sni.has_value());
    }

    CaptureSession fast_session {};
    PFL_EXPECT(fast_session.open_capture(fixture_path(expectation.relative_path)));
    const auto fast_rows = fast_session.list_flows();
    PFL_EXPECT(!fast_rows.empty());

    const auto fast_quic_flow_index = find_flow_index_with_protocol_hint(fast_rows, "quic");
    PFL_EXPECT(fast_quic_flow_index.has_value());

    const auto fast_sni = fast_session.derive_quic_service_hint_for_flow(*fast_quic_flow_index);
    if (expectation.expected_sni.has_value()) {
        PFL_EXPECT(fast_sni.has_value());
        PFL_EXPECT(*fast_sni == *expectation.expected_sni);
    } else {
        PFL_EXPECT(!fast_sni.has_value());
    }

    PFL_EXPECT(fast_sni == deep_sni);
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
        {.relative_path = "parsing/quic/quic_test_3.pcap", .expected_protocol_hint = "quic"},
    };

    for (const auto& fixture : fixtures) {
        expect_fixture(fixture);
    }

    const std::vector<QuicSniFixtureExpectation> quic_sni_fixtures {
        {.relative_path = "parsing/quic/quic_test_1.pcap", .expected_sni = std::optional<std::string> {"rr1---sn-ug5on-unxs.googlevideo.com"}},
        {.relative_path = "parsing/quic/quic_test_2.pcap", .expected_sni = std::optional<std::string> {"www.youtube.com"}},
        {.relative_path = "parsing/quic/quic_test_3.pcap", .expected_sni = std::optional<std::string> {"log22-normal-useast1a.tiktokv.com"}},
        {.relative_path = "parsing/quic/quic_test_4.pcap", .expected_sni = std::nullopt},
        {.relative_path = "parsing/quic/quic_test_5.pcap", .expected_sni = std::nullopt},
    };

    for (const auto& fixture : quic_sni_fixtures) {
        expect_quic_sni_fixture(fixture);
    }
}

}  // namespace pfl::tests
