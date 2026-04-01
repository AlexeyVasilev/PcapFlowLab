#include <optional>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "ParsingRawFixtures.h"
#include "core/domain/FlowHints.h"
#include "core/domain/FlowKey.h"
#include "core/domain/ProtocolId.h"
#include "core/services/FlowHintService.h"

namespace pfl::tests {

namespace {

/*
 * Parser-level regression fixtures ported from the legacy raw .h test data.
 * These complement the end-to-end .pcap fixture tests and assert only the
 * current cheap hint extraction semantics of Pcap Flow Lab.
 */

enum class RawFixtureExpectationMode : std::uint8_t {
    expect_exact_hint,
    expect_service_empty_only,
};

struct RawFixtureExpectation {
    const char* name {nullptr};
    std::span<const std::uint8_t> (*packet_bytes)();
    ProtocolId protocol {ProtocolId::unknown};
    std::uint16_t src_port {0};
    std::uint16_t dst_port {0};
    FlowProtocolHint expected_protocol_hint {FlowProtocolHint::unknown};
    std::optional<std::string> expected_service_hint {};
    RawFixtureExpectationMode mode {RawFixtureExpectationMode::expect_exact_hint};
};

FlowKeyV4 make_flow_key(const ProtocolId protocol, const std::uint16_t src_port, const std::uint16_t dst_port) {
    return FlowKeyV4 {
        .src_addr = 0x0A000001U,
        .dst_addr = 0x0A000002U,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol,
    };
}

void expect_fixture(const RawFixtureExpectation& expectation) {
    FlowHintService service {};
    const auto packet_bytes = expectation.packet_bytes();
    const auto hint = service.detect(packet_bytes, make_flow_key(expectation.protocol, expectation.src_port, expectation.dst_port));

    if (expectation.mode == RawFixtureExpectationMode::expect_service_empty_only) {
        PFL_EXPECT(hint.service_hint.empty());
        return;
    }

    PFL_EXPECT(hint.protocol_hint == expectation.expected_protocol_hint);
    if (expectation.expected_service_hint.has_value()) {
        PFL_EXPECT(hint.service_hint == *expectation.expected_service_hint);
    } else {
        PFL_EXPECT(hint.service_hint.empty());
    }
}

}  // namespace

void run_flow_hints_raw_fixtures_tests() {
    using namespace legacy_raw_fixtures;

    const std::vector<RawFixtureExpectation> fixtures {
        {.name = "http_get_1", .packet_bytes = &http_get_1, .protocol = ProtocolId::tcp, .src_port = 54586, .dst_port = 1081, .expected_protocol_hint = FlowProtocolHint::http, .expected_service_hint = std::string {"www.kresla-darom.ru"}},
        {.name = "http_answer_2", .packet_bytes = &http_answer_2, .protocol = ProtocolId::tcp, .src_port = 80, .dst_port = 54586, .expected_protocol_hint = FlowProtocolHint::http},
        {.name = "dns_request_1", .packet_bytes = &dns_request_1, .protocol = ProtocolId::udp, .src_port = 52169, .dst_port = 53, .expected_protocol_hint = FlowProtocolHint::dns, .expected_service_hint = std::string {"gsp85-ssl.ls.apple.com"}},
        {.name = "dns_response_2", .packet_bytes = &dns_response_2, .protocol = ProtocolId::udp, .src_port = 53, .dst_port = 53583, .expected_protocol_hint = FlowProtocolHint::dns, .expected_service_hint = std::string {"_dns.resolver.arpa"}},
        {.name = "tls_1_2_client_hello_1", .packet_bytes = &tls_1_2_client_hello_1, .protocol = ProtocolId::tcp, .src_port = 42644, .dst_port = 443, .expected_protocol_hint = FlowProtocolHint::tls, .expected_service_hint = std::string {"auth.split.io"}},
        {.name = "tls_1_2_change_cipher_spec_2", .packet_bytes = &tls_1_2_change_cipher_spec_2, .protocol = ProtocolId::tcp, .src_port = 443, .dst_port = 42644, .expected_protocol_hint = FlowProtocolHint::tls},
        {.name = "tls_1_2_app_data_3", .packet_bytes = &tls_1_2_app_data_3, .protocol = ProtocolId::tcp, .src_port = 443, .dst_port = 42644, .expected_protocol_hint = FlowProtocolHint::tls},
        {.name = "tls_1_2_server_hello_4", .packet_bytes = &tls_1_2_server_hello_4, .protocol = ProtocolId::tcp, .src_port = 443, .dst_port = 42644, .expected_protocol_hint = FlowProtocolHint::tls},
        {.name = "tls_1_2_new_session_ticket_9", .packet_bytes = &tls_1_2_new_session_ticket_9, .protocol = ProtocolId::tcp, .src_port = 443, .dst_port = 42644, .expected_protocol_hint = FlowProtocolHint::tls},
        {.name = "tls_1_3_client_hello_5", .packet_bytes = &tls_1_3_client_hello_5, .protocol = ProtocolId::tcp, .src_port = 43218, .dst_port = 443, .expected_protocol_hint = FlowProtocolHint::tls, .expected_service_hint = std::string {"p101-fmf.icloud.com"}},
        {.name = "tls_1_3_server_hello_6", .packet_bytes = &tls_1_3_server_hello_6, .protocol = ProtocolId::tcp, .src_port = 443, .dst_port = 43218, .expected_protocol_hint = FlowProtocolHint::tls},
        {.name = "tls_1_3_app_data_7", .packet_bytes = &tls_1_3_app_data_7, .protocol = ProtocolId::tcp, .src_port = 443, .dst_port = 43218, .expected_protocol_hint = FlowProtocolHint::tls},
        {.name = "tls_1_3_change_cipher_spec_8", .packet_bytes = &tls_1_3_change_cipher_spec_8, .protocol = ProtocolId::tcp, .src_port = 443, .dst_port = 43218, .expected_protocol_hint = FlowProtocolHint::tls},
        {.name = "quic_initial_ch_1", .packet_bytes = &quic_initial_ch_1, .protocol = ProtocolId::udp, .src_port = 56567, .dst_port = 443, .expected_protocol_hint = FlowProtocolHint::quic},
        {.name = "quic_initial_sh_2", .packet_bytes = &quic_initial_sh_2, .protocol = ProtocolId::udp, .src_port = 443, .dst_port = 54203, .expected_protocol_hint = FlowProtocolHint::quic},
        {.name = "quic_handshake_3", .packet_bytes = &quic_handshake_3, .protocol = ProtocolId::udp, .src_port = 443, .dst_port = 54030, .expected_protocol_hint = FlowProtocolHint::quic},
        {.name = "quic_protected_payload_4", .packet_bytes = &quic_protected_payload_4, .protocol = ProtocolId::udp, .src_port = 443, .dst_port = 54030, .mode = RawFixtureExpectationMode::expect_service_empty_only},
    };


    {
        FlowHintService quic_service {AnalysisSettings {}, true};

        const auto client_hint = quic_service.detect(quic_initial_ch_1(), make_flow_key(ProtocolId::udp, 56567, 443));
        PFL_EXPECT(client_hint.protocol_hint == FlowProtocolHint::quic);
        PFL_EXPECT(client_hint.service_hint == "bag.itunes.apple.com");

        const auto server_initial_hint = quic_service.detect(quic_initial_sh_2(), make_flow_key(ProtocolId::udp, 443, 54203));
        PFL_EXPECT(server_initial_hint.protocol_hint == FlowProtocolHint::quic);
        PFL_EXPECT(server_initial_hint.service_hint.empty());

        const auto handshake_hint = quic_service.detect(quic_handshake_3(), make_flow_key(ProtocolId::udp, 443, 54030));
        PFL_EXPECT(handshake_hint.protocol_hint == FlowProtocolHint::quic);
        PFL_EXPECT(handshake_hint.service_hint.empty());
    }
    for (const auto& fixture : fixtures) {
        expect_fixture(fixture);
    }
}

}  // namespace pfl::tests

