#include "TestSupport.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

void run_protocol_recognition_stats_tests() {
    {
        CaptureSession session {};
        auto& state = session.state();

        auto& quic_v1 = state.ipv4_connections.get_or_create(ConnectionKeyV4 {
            .first = EndpointKeyV4 {.addr = 0x0A000001U, .port = 53000U},
            .second = EndpointKeyV4 {.addr = 0x0A000002U, .port = 443U},
            .protocol = ProtocolId::udp,
        });
        quic_v1.protocol_hint = FlowProtocolHint::quic;
        quic_v1.service_hint = "v1.example";
        quic_v1.quic_version = QuicVersionHint::v1;

        auto& quic_draft29 = state.ipv4_connections.get_or_create(ConnectionKeyV4 {
            .first = EndpointKeyV4 {.addr = 0x0A000003U, .port = 53001U},
            .second = EndpointKeyV4 {.addr = 0x0A000004U, .port = 443U},
            .protocol = ProtocolId::udp,
        });
        quic_draft29.protocol_hint = FlowProtocolHint::quic;
        quic_draft29.service_hint.clear();
        quic_draft29.quic_version = QuicVersionHint::draft29;

        auto& quic_v2 = state.ipv6_connections.get_or_create(ConnectionKeyV6 {
            .first = EndpointKeyV6 {.addr = std::array<std::uint8_t, 16> {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, .port = 53002U},
            .second = EndpointKeyV6 {.addr = std::array<std::uint8_t, 16> {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, .port = 443U},
            .protocol = ProtocolId::udp,
        });
        quic_v2.protocol_hint = FlowProtocolHint::quic;
        quic_v2.service_hint = "v2.example";
        quic_v2.quic_version = QuicVersionHint::v2;

        auto& quic_unknown = state.ipv6_connections.get_or_create(ConnectionKeyV6 {
            .first = EndpointKeyV6 {.addr = std::array<std::uint8_t, 16> {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}, .port = 53003U},
            .second = EndpointKeyV6 {.addr = std::array<std::uint8_t, 16> {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}, .port = 443U},
            .protocol = ProtocolId::udp,
        });
        quic_unknown.protocol_hint = FlowProtocolHint::quic;
        quic_unknown.service_hint.clear();
        quic_unknown.quic_version = QuicVersionHint::unknown;

        auto& non_quic = state.ipv4_connections.get_or_create(ConnectionKeyV4 {
            .first = EndpointKeyV4 {.addr = 0xC0A80101U, .port = 1234U},
            .second = EndpointKeyV4 {.addr = 0xC0A80102U, .port = 443U},
            .protocol = ProtocolId::tcp,
        });
        non_quic.protocol_hint = FlowProtocolHint::tls;
        non_quic.service_hint = "tls.example";
        non_quic.quic_version = QuicVersionHint::v1;

        const auto stats = session.quic_recognition_stats();
        PFL_EXPECT(stats.total_flows == 4U);
        PFL_EXPECT(stats.with_sni == 2U);
        PFL_EXPECT(stats.without_sni == 2U);
        PFL_EXPECT(stats.version_v1 == 1U);
        PFL_EXPECT(stats.version_draft29 == 1U);
        PFL_EXPECT(stats.version_v2 == 1U);
        PFL_EXPECT(stats.version_unknown == 1U);
        PFL_EXPECT(stats.with_sni + stats.without_sni == stats.total_flows);
        PFL_EXPECT(stats.version_v1 + stats.version_draft29 + stats.version_v2 + stats.version_unknown == stats.total_flows);
    }

    {
        CaptureSession session {};
        auto& state = session.state();

        auto& non_quic = state.ipv4_connections.get_or_create(ConnectionKeyV4 {
            .first = EndpointKeyV4 {.addr = 0x0A010001U, .port = 5000U},
            .second = EndpointKeyV4 {.addr = 0x0A010002U, .port = 80U},
            .protocol = ProtocolId::tcp,
        });
        non_quic.protocol_hint = FlowProtocolHint::http;
        non_quic.service_hint = "www.example.com";

        const auto stats = session.quic_recognition_stats();
        PFL_EXPECT(stats.total_flows == 0U);
        PFL_EXPECT(stats.with_sni == 0U);
        PFL_EXPECT(stats.without_sni == 0U);
        PFL_EXPECT(stats.version_v1 == 0U);
        PFL_EXPECT(stats.version_draft29 == 0U);
        PFL_EXPECT(stats.version_v2 == 0U);
        PFL_EXPECT(stats.version_unknown == 0U);
    }

    {
        CaptureSession session {};
        auto& state = session.state();

        auto& tls12 = state.ipv4_connections.get_or_create(ConnectionKeyV4 {
            .first = EndpointKeyV4 {.addr = 0x0A020001U, .port = 5100U},
            .second = EndpointKeyV4 {.addr = 0x0A020002U, .port = 443U},
            .protocol = ProtocolId::tcp,
        });
        tls12.protocol_hint = FlowProtocolHint::tls;
        tls12.service_hint = "tls12.example";
        tls12.tls_version = TlsVersionHint::tls12;

        auto& tls13 = state.ipv4_connections.get_or_create(ConnectionKeyV4 {
            .first = EndpointKeyV4 {.addr = 0x0A020003U, .port = 5101U},
            .second = EndpointKeyV4 {.addr = 0x0A020004U, .port = 443U},
            .protocol = ProtocolId::tcp,
        });
        tls13.protocol_hint = FlowProtocolHint::tls;
        tls13.service_hint.clear();
        tls13.tls_version = TlsVersionHint::tls13;

        auto& tls_unknown = state.ipv6_connections.get_or_create(ConnectionKeyV6 {
            .first = EndpointKeyV6 {.addr = std::array<std::uint8_t, 16> {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}, .port = 5102U},
            .second = EndpointKeyV6 {.addr = std::array<std::uint8_t, 16> {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11}, .port = 443U},
            .protocol = ProtocolId::tcp,
        });
        tls_unknown.protocol_hint = FlowProtocolHint::tls;
        tls_unknown.service_hint.clear();
        tls_unknown.tls_version = TlsVersionHint::unknown;

        auto& non_tls = state.ipv4_connections.get_or_create(ConnectionKeyV4 {
            .first = EndpointKeyV4 {.addr = 0xC0A80201U, .port = 5200U},
            .second = EndpointKeyV4 {.addr = 0xC0A80202U, .port = 443U},
            .protocol = ProtocolId::udp,
        });
        non_tls.protocol_hint = FlowProtocolHint::quic;
        non_tls.service_hint = "quic.example";
        non_tls.tls_version = TlsVersionHint::tls13;

        const auto tls_stats = session.tls_recognition_stats();
        PFL_EXPECT(tls_stats.total_flows == 3U);
        PFL_EXPECT(tls_stats.with_sni == 1U);
        PFL_EXPECT(tls_stats.without_sni == 2U);
        PFL_EXPECT(tls_stats.version_tls12 == 1U);
        PFL_EXPECT(tls_stats.version_tls13 == 1U);
        PFL_EXPECT(tls_stats.version_unknown == 1U);
        PFL_EXPECT(tls_stats.with_sni + tls_stats.without_sni == tls_stats.total_flows);
        PFL_EXPECT(tls_stats.version_tls12 + tls_stats.version_tls13 + tls_stats.version_unknown == tls_stats.total_flows);
    }

    {
        CaptureSession session {};
        auto& state = session.state();

        auto& non_tls = state.ipv4_connections.get_or_create(ConnectionKeyV4 {
            .first = EndpointKeyV4 {.addr = 0x0A030001U, .port = 5300U},
            .second = EndpointKeyV4 {.addr = 0x0A030002U, .port = 443U},
            .protocol = ProtocolId::udp,
        });
        non_tls.protocol_hint = FlowProtocolHint::quic;
        non_tls.service_hint = "quic-only.example";

        const auto tls_stats = session.tls_recognition_stats();
        PFL_EXPECT(tls_stats.total_flows == 0U);
        PFL_EXPECT(tls_stats.with_sni == 0U);
        PFL_EXPECT(tls_stats.without_sni == 0U);
        PFL_EXPECT(tls_stats.version_tls12 == 0U);
        PFL_EXPECT(tls_stats.version_tls13 == 0U);
        PFL_EXPECT(tls_stats.version_unknown == 0U);
    }
}

}  // namespace pfl::tests

