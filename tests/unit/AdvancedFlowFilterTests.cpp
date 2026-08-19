#include <array>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/AdvancedFlowFilter.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path("tests/data") / relative_path;
}

using session_detail::AdvancedFlowFilterCompileStatus;
using session_detail::AdvancedFlowFilterEndpointScope;
using session_detail::AdvancedFlowFilterDirectionality;
using session_detail::AdvancedFlowFilterEvaluationStatus;
using session_detail::AdvancedFlowFilterInclusiveRange;
using session_detail::AdvancedFlowFilterPortScope;
using session_detail::AdvancedFlowFilterProtocolPathMatchKind;
using session_detail::AdvancedFlowFilterProtocolPathPredicate;
using session_detail::AdvancedFlowFilterServicePredicate;
using session_detail::AdvancedFlowFilterServicePredicateKind;
using session_detail::AdvancedFlowFilterSpec;
using session_detail::AdvancedFlowFilterStringCaseSensitivity;
using session_detail::CompiledAdvancedFlowFilter;

struct FlowFilterFixture {
    CaptureSession session {};
    AnalysisSettings default_settings {};
    AnalysisSettings possible_tls_quic_settings {
        .http_use_path_as_service_hint = false,
        .use_possible_tls_quic = true,
        .ignore_vlan_and_mpls_layers_when_grouping_flows = false,
        .ignore_gtpu_teids_when_grouping_inner_flows = false,
    };
    ProtocolPathId tcp_path_id {kInvalidProtocolPathId};
    ProtocolPathId udp_path_id {kInvalidProtocolPathId};
    ProtocolPathId ipv6_udp_path_id {kInvalidProtocolPathId};
    ProtocolPathId vxlan_tcp_path_id {kInvalidProtocolPathId};
    ProtocolPathId gtpu_tcp_path_id {kInvalidProtocolPathId};
};

FlowKeyV4 reverse_flow_key(const FlowKeyV4& key) {
    return FlowKeyV4 {
        .src_addr = key.dst_addr,
        .dst_addr = key.src_addr,
        .src_port = key.dst_port,
        .dst_port = key.src_port,
        .protocol = key.protocol,
    };
}

ConnectionV4 make_ipv4_connection(
    const std::optional<FlowKeyV4>& flow_a_key,
    const std::optional<FlowKeyV4>& flow_b_key,
    const ProtocolPathId protocol_path_id,
    const std::uint64_t flow_a_packet_count,
    const std::uint64_t flow_b_packet_count,
    const std::uint64_t flow_a_original_bytes,
    const std::uint64_t flow_b_original_bytes,
    const std::uint64_t captured_bytes,
    const std::uint64_t first_timestamp_us,
    const std::uint64_t last_timestamp_us,
    const FlowProtocolHint protocol_hint,
    std::string service_hint,
    const std::uint64_t fragmented_packet_count,
    const std::uint64_t truncated_packet_count,
    const std::uint64_t tcp_syn_count,
    const std::uint64_t tcp_fin_count,
    const std::uint64_t tcp_rst_count,
    const std::uint32_t max_original_packet_length,
    const std::uint32_t max_captured_packet_length,
    const QuicVersionHint quic_version = QuicVersionHint::unknown,
    const TlsVersionHint tls_version = TlsVersionHint::unknown
) {
    PFL_REQUIRE(flow_a_key.has_value() || flow_b_key.has_value());

    ConnectionV4 connection {};
    connection.key = make_connection_key(flow_a_key.has_value() ? *flow_a_key : *flow_b_key);
    connection.key.protocol_path_id = protocol_path_id;
    connection.has_flow_a = flow_a_key.has_value();
    connection.has_flow_b = flow_b_key.has_value();
    if (flow_a_key.has_value()) {
        connection.flow_a.key = *flow_a_key;
        connection.flow_a.packet_count = flow_a_packet_count;
        connection.flow_a.total_bytes = flow_a_original_bytes;
    }
    if (flow_b_key.has_value()) {
        connection.flow_b.key = *flow_b_key;
        connection.flow_b.packet_count = flow_b_packet_count;
        connection.flow_b.total_bytes = flow_b_original_bytes;
    }
    connection.packet_count = flow_a_packet_count + flow_b_packet_count;
    connection.total_bytes = flow_a_original_bytes + flow_b_original_bytes;
    connection.has_fragmented_packets = fragmented_packet_count > 0U;
    connection.fragmented_packet_count = fragmented_packet_count;
    connection.protocol_hint = protocol_hint;
    connection.service_hint = std::move(service_hint);
    connection.quic_version = quic_version;
    connection.tls_version = tls_version;
    connection.aggregate_stats = ConnectionAggregateStats {
        .first_timestamp_us = first_timestamp_us,
        .last_timestamp_us = last_timestamp_us,
        .captured_bytes = captured_bytes,
        .truncated_packet_count = truncated_packet_count,
        .tcp_syn_count = tcp_syn_count,
        .tcp_fin_count = tcp_fin_count,
        .tcp_rst_count = tcp_rst_count,
        .max_original_packet_length = max_original_packet_length,
        .max_captured_packet_length = max_captured_packet_length,
    };
    return connection;
}

ConnectionV6 make_ipv6_connection(
    const FlowKeyV6& flow_a_key,
    const ProtocolPathId protocol_path_id,
    const std::uint64_t packet_count,
    const std::uint64_t total_bytes,
    const std::uint64_t captured_bytes,
    const FlowProtocolHint protocol_hint = FlowProtocolHint::unknown,
    std::string service_hint = {},
    const QuicVersionHint quic_version = QuicVersionHint::unknown,
    const TlsVersionHint tls_version = TlsVersionHint::unknown
) {
    ConnectionV6 connection {};
    connection.key = make_connection_key(flow_a_key);
    connection.key.protocol_path_id = protocol_path_id;
    connection.has_flow_a = true;
    connection.flow_a.key = flow_a_key;
    connection.flow_a.packet_count = packet_count;
    connection.flow_a.total_bytes = total_bytes;
    connection.packet_count = packet_count;
    connection.total_bytes = total_bytes;
    connection.protocol_hint = protocol_hint;
    connection.service_hint = std::move(service_hint);
    connection.quic_version = quic_version;
    connection.tls_version = tls_version;
    connection.aggregate_stats.captured_bytes = captured_bytes;
    connection.aggregate_stats.first_timestamp_us = 100U;
    connection.aggregate_stats.last_timestamp_us = 200U;
    connection.aggregate_stats.max_original_packet_length = 96U;
    connection.aggregate_stats.max_captured_packet_length = 96U;
    return connection;
}

FlowFilterFixture build_fixture() {
    FlowFilterFixture fixture {};
    auto& state = fixture.session.state();

    fixture.tcp_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::tcp()}
    });
    fixture.udp_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::udp()}
    });
    fixture.ipv6_udp_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv6(), LayerKey::udp()}
    });
    fixture.vxlan_tcp_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::udp(), LayerKey::vxlan(100U), LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::tcp()}
    });
    fixture.gtpu_tcp_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::udp(), LayerKey::gtpu(0x12345678U), LayerKey::ipv4(), LayerKey::tcp()}
    });

    const FlowKeyV4 tls_flow_ab {
        .src_addr = ipv4(10, 0, 0, 10),
        .dst_addr = ipv4(10, 0, 0, 20),
        .src_port = 41000,
        .dst_port = 443,
        .protocol = ProtocolId::tcp,
    };
    state.ipv4_connections.get_or_create(make_connection_key(tls_flow_ab)) = make_ipv4_connection(
        tls_flow_ab,
        reverse_flow_key(tls_flow_ab),
        fixture.tcp_path_id,
        70U,
        50U,
        70000U,
        50000U,
        118000U,
        1000000U,
        6000000U,
        FlowProtocolHint::tls,
        "Alpha.Example",
        0U,
        0U,
        1U,
        1U,
        0U,
        1514U,
        1400U,
        QuicVersionHint::unknown,
        TlsVersionHint::tls13
    );

    const FlowKeyV4 vxlan_http_flow_ab {
        .src_addr = ipv4(10, 0, 0, 30),
        .dst_addr = ipv4(10, 0, 0, 40),
        .src_port = 41001,
        .dst_port = 80,
        .protocol = ProtocolId::tcp,
    };
    state.ipv4_connections.get_or_create(make_connection_key(vxlan_http_flow_ab)) = make_ipv4_connection(
        vxlan_http_flow_ab,
        std::nullopt,
        fixture.vxlan_tcp_path_id,
        20U,
        0U,
        20000U,
        0U,
        18000U,
        2000000U,
        4500000U,
        FlowProtocolHint::http,
        "nested.example",
        0U,
        0U,
        1U,
        0U,
        0U,
        1200U,
        1100U
    );

    const FlowKeyV4 tcp_unknown_443_flow_ab {
        .src_addr = ipv4(10, 0, 0, 50),
        .dst_addr = ipv4(10, 0, 0, 60),
        .src_port = 42000,
        .dst_port = 443,
        .protocol = ProtocolId::tcp,
    };
    state.ipv4_connections.get_or_create(make_connection_key(tcp_unknown_443_flow_ab)) = make_ipv4_connection(
        tcp_unknown_443_flow_ab,
        std::nullopt,
        fixture.tcp_path_id,
        60U,
        0U,
        6000U,
        0U,
        5900U,
        3000000U,
        4000000U,
        FlowProtocolHint::unknown,
        "",
        0U,
        0U,
        1U,
        0U,
        0U,
        256U,
        200U
    );

    const FlowKeyV4 dns_flow_ab {
        .src_addr = ipv4(10, 0, 0, 70),
        .dst_addr = ipv4(10, 0, 0, 71),
        .src_port = 53000,
        .dst_port = 53,
        .protocol = ProtocolId::udp,
    };
    state.ipv4_connections.get_or_create(make_connection_key(dns_flow_ab)) = make_ipv4_connection(
        dns_flow_ab,
        std::nullopt,
        fixture.udp_path_id,
        12U,
        0U,
        900U,
        0U,
        880U,
        4000000U,
        4200000U,
        FlowProtocolHint::dns,
        "beta.example",
        2U,
        1U,
        0U,
        0U,
        0U,
        200U,
        180U
    );

    const FlowKeyV4 udp_unknown_443_flow_ab {
        .src_addr = ipv4(10, 0, 0, 80),
        .dst_addr = ipv4(10, 0, 0, 81),
        .src_port = 55000,
        .dst_port = 443,
        .protocol = ProtocolId::udp,
    };
    state.ipv4_connections.get_or_create(make_connection_key(udp_unknown_443_flow_ab)) = make_ipv4_connection(
        udp_unknown_443_flow_ab,
        std::nullopt,
        fixture.udp_path_id,
        8U,
        0U,
        800U,
        0U,
        760U,
        4500000U,
        4550000U,
        FlowProtocolHint::unknown,
        "",
        0U,
        0U,
        0U,
        0U,
        1U,
        160U,
        150U
    );

    const FlowKeyV4 gtpu_flow_ab {
        .src_addr = ipv4(10, 0, 0, 90),
        .dst_addr = ipv4(10, 0, 0, 91),
        .src_port = 2152,
        .dst_port = 2152,
        .protocol = ProtocolId::tcp,
    };
    state.ipv4_connections.get_or_create(make_connection_key(gtpu_flow_ab)) = make_ipv4_connection(
        gtpu_flow_ab,
        std::nullopt,
        fixture.gtpu_tcp_path_id,
        6U,
        0U,
        700U,
        0U,
        640U,
        5000000U,
        5100000U,
        FlowProtocolHint::tls,
        "teid.example",
        0U,
        0U,
        0U,
        0U,
        0U,
        140U,
        128U,
        QuicVersionHint::unknown,
        TlsVersionHint::tls12
    );

    const FlowKeyV6 ipv6_udp_flow_ab {
        .src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31}),
        .dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32}),
        .src_port = 54000,
        .dst_port = 54001,
        .protocol = ProtocolId::udp,
    };
    state.ipv6_connections.get_or_create(make_connection_key(ipv6_udp_flow_ab)) = make_ipv6_connection(
        ipv6_udp_flow_ab,
        fixture.ipv6_udp_path_id,
        4U,
        400U,
        350U
    );

    const FlowKeyV4 quic_flow_ab {
        .src_addr = ipv4(10, 0, 0, 92),
        .dst_addr = ipv4(10, 0, 0, 93),
        .src_port = 56000,
        .dst_port = 443,
        .protocol = ProtocolId::udp,
    };
    state.ipv4_connections.get_or_create(make_connection_key(quic_flow_ab)) = make_ipv4_connection(
        quic_flow_ab,
        std::nullopt,
        fixture.udp_path_id,
        7U,
        0U,
        770U,
        0U,
        720U,
        5200000U,
        5210000U,
        FlowProtocolHint::quic,
        "quic-v1.example",
        0U,
        0U,
        0U,
        0U,
        0U,
        150U,
        140U,
        QuicVersionHint::v1,
        TlsVersionHint::unknown
    );

    return fixture;
}

std::vector<session_detail::ListedConnectionRef> listed_connections_for_fixture(FlowFilterFixture& fixture) {
    return session_detail::list_connections(fixture.session.state());
}

CompiledAdvancedFlowFilter require_compiled_filter(
    const AdvancedFlowFilterSpec& spec,
    const ProtocolPathRegistry& registry,
    const AnalysisSettings& settings
) {
    const auto compile_result = session_detail::compile_advanced_flow_filter(spec, registry, settings);
    PFL_REQUIRE(compile_result.status == AdvancedFlowFilterCompileStatus::ok);
    return compile_result.filter;
}

CompiledAdvancedFlowFilter require_compiled_filter(
    const AdvancedFlowFilterSpec& spec,
    const FlowFilterFixture& fixture,
    const AnalysisSettings& settings
) {
    return require_compiled_filter(spec, fixture.session.state().protocol_path_registry, settings);
}

std::vector<std::size_t> evaluate_matching_indices(
    std::span<const session_detail::ListedConnectionRef> connections,
    const CompiledAdvancedFlowFilter& filter
) {
    const auto result = session_detail::evaluate_advanced_flow_filter(connections, filter);
    PFL_REQUIRE(result.status == AdvancedFlowFilterEvaluationStatus::ok);
    return result.matching_flow_indices;
}

void expect_indices_equal(const std::vector<std::size_t>& actual, const std::vector<std::size_t>& expected) {
    PFL_EXPECT(actual == expected);
}

std::vector<std::size_t> evaluate_matching_indices_for_session(
    CaptureSession& session,
    const AdvancedFlowFilterSpec& spec,
    const AnalysisSettings& settings
) {
    const auto connections = session_detail::list_connections(session.state());
    const auto filter = require_compiled_filter(spec, session.state().protocol_path_registry, settings);
    return evaluate_matching_indices(connections, filter);
}

void run_protocol_and_candidate_scope_tests() {
    ScopedTestContext context {"advanced_flow_filter/protocol_and_scope"};
    auto fixture = build_fixture();
    const auto connections = listed_connections_for_fixture(fixture);
    PFL_REQUIRE(connections.size() == 8U);

    {
        const AdvancedFlowFilterSpec spec {};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U});
    }

    {
        const AdvancedFlowFilterSpec spec {};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        const std::vector<std::size_t> candidate_scope {4U, 1U, 4U, 0U};
        const auto result = session_detail::evaluate_advanced_flow_filter(
            connections,
            filter,
            std::span<const std::size_t>(candidate_scope)
        );
        PFL_REQUIRE(result.status == AdvancedFlowFilterEvaluationStatus::ok);
        expect_indices_equal(result.matching_flow_indices, {0U, 1U, 4U});
    }

    {
        const AdvancedFlowFilterSpec spec {};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        const std::vector<std::size_t> candidate_scope {0U, 99U};
        const auto result = session_detail::evaluate_advanced_flow_filter(
            connections,
            filter,
            std::span<const std::size_t>(candidate_scope)
        );
        PFL_EXPECT(result.status == AdvancedFlowFilterEvaluationStatus::invalid_candidate_index);
        PFL_EXPECT(result.invalid_candidate_index == 99U);
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.flow_protocol.include = {ProtocolId::tcp};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 5U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.flow_protocol.exclude = {ProtocolId::udp};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 5U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.flow_protocol.include = {ProtocolId::tcp, ProtocolId::udp};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.detected_protocol.include = {FlowProtocolHint::dns};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.detected_protocol.include = {FlowProtocolHint::possible_tls};
        const auto disabled_filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, disabled_filter), std::vector<std::size_t> {});

        const auto enabled_filter = require_compiled_filter(spec, fixture, fixture.possible_tls_quic_settings);
        expect_indices_equal(evaluate_matching_indices(connections, enabled_filter), {2U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.detected_protocol.include = {FlowProtocolHint::possible_quic};
        const auto enabled_filter = require_compiled_filter(spec, fixture, fixture.possible_tls_quic_settings);
        expect_indices_equal(evaluate_matching_indices(connections, enabled_filter), {4U});
    }
}

void run_protocol_path_tests() {
    ScopedTestContext context {"advanced_flow_filter/protocol_path"};
    auto fixture = build_fixture();
    const auto connections = listed_connections_for_fixture(fixture);

    {
        AdvancedFlowFilterSpec spec {};
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::exact_path,
            .layers = {
                {.kind = ProtocolLayerKind::ethernet_ii},
                {.kind = ProtocolLayerKind::ipv4},
                {.kind = ProtocolLayerKind::udp},
            },
        });
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U, 4U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::path_prefix,
            .layers = {
                {.kind = ProtocolLayerKind::ethernet_ii},
                {.kind = ProtocolLayerKind::ipv4},
                {.kind = ProtocolLayerKind::udp},
            },
        });
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {1U, 3U, 4U, 5U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {
                {.kind = ProtocolLayerKind::vxlan},
            },
        });
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {1U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {
                {.kind = ProtocolLayerKind::gtpu, .identifier = ProtocolLayerIdentifier {
                    .kind = ProtocolLayerIdentifierKind::gtpu_teid,
                    .value = 0x12345678U,
                }},
            },
        });
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {5U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::exact_path,
            .layers = {
                {.kind = ProtocolLayerKind::ethernet_ii},
                {.kind = ProtocolLayerKind::ipv4},
                {.kind = ProtocolLayerKind::udp},
                {.kind = ProtocolLayerKind::vxlan, .identifier = ProtocolLayerIdentifier {
                    .kind = ProtocolLayerIdentifierKind::vxlan_vni,
                    .value = 100U,
                }},
                {.kind = ProtocolLayerKind::ethernet_ii},
                {.kind = ProtocolLayerKind::ipv4},
                {.kind = ProtocolLayerKind::tcp},
            },
        });
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::exact_path,
            .layers = {
                {.kind = ProtocolLayerKind::ethernet_ii},
                {.kind = ProtocolLayerKind::ipv4},
                {.kind = ProtocolLayerKind::udp},
            },
        });
        spec.protocol_path.exclude.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {
                {.kind = ProtocolLayerKind::vxlan},
            },
        });
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U, 4U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {
                {.kind = ProtocolLayerKind::unknown},
            },
        });
        const auto compile_result =
            session_detail::compile_advanced_flow_filter(spec, fixture.session.state().protocol_path_registry, fixture.default_settings);
        PFL_EXPECT(compile_result.status == AdvancedFlowFilterCompileStatus::invalid_protocol_path_predicate);
    }
}

void run_port_and_aggregate_tests() {
    ScopedTestContext context {"advanced_flow_filter/ports_and_aggregate"};
    auto fixture = build_fixture();
    const auto connections = listed_connections_for_fixture(fixture);

    {
        AdvancedFlowFilterSpec spec {};
        spec.ports.include = {
            {.scope = AdvancedFlowFilterPortScope::either_endpoint, .range = {.first = 443U, .last = 443U}},
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 2U, 4U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.ports.include = {
            {.scope = AdvancedFlowFilterPortScope::either_endpoint, .range = {.first = 52000U, .last = 55000U}},
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U, 4U, 6U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.ports.include = {
            {.scope = AdvancedFlowFilterPortScope::endpoint_a, .range = {.first = 53000U, .last = 53000U}},
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.ports.include = {
            {.scope = AdvancedFlowFilterPortScope::endpoint_b, .range = {.first = 53U, .last = 53U}},
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.ports.include = {
            {.scope = AdvancedFlowFilterPortScope::either_endpoint, .range = {.first = 1U, .last = 65535U}},
        };
        spec.ports.exclude = {
            {.scope = AdvancedFlowFilterPortScope::either_endpoint, .range = {.first = 1U, .last = 1023U}},
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {5U, 6U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.aggregate.packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 60U, .max = 120U};
        spec.aggregate.original_bytes = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 1000U, .max = 130000U};
        spec.aggregate.captured_bytes = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 5000U, .max = 120000U};
        spec.aggregate.duration_us = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 900000U, .max = 6000000U};
        spec.aggregate.fragmented_packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 0U, .max = 0U};
        spec.aggregate.truncated_packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 0U, .max = 0U};
        spec.aggregate.tcp_syn_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 1U, .max = 1U};
        spec.aggregate.tcp_fin_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 0U, .max = 1U};
        spec.aggregate.tcp_rst_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 0U, .max = 0U};
        spec.aggregate.max_original_packet_length = AdvancedFlowFilterInclusiveRange<std::uint32_t> {.min = 200U, .max = 1600U};
        spec.aggregate.max_captured_packet_length = AdvancedFlowFilterInclusiveRange<std::uint32_t> {.min = 150U, .max = 1500U};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 2U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.aggregate.fragmented_packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 2U, .max = 2U};
        spec.aggregate.truncated_packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 1U, .max = 1U};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.aggregate.packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 10U, .max = 9U};
        const auto compile_result =
            session_detail::compile_advanced_flow_filter(spec, fixture.session.state().protocol_path_registry, fixture.default_settings);
        PFL_EXPECT(compile_result.status == AdvancedFlowFilterCompileStatus::invalid_numeric_range);
    }
}

void run_directionality_and_service_tests() {
    ScopedTestContext context {"advanced_flow_filter/directionality_and_service"};
    auto fixture = build_fixture();
    const auto connections = listed_connections_for_fixture(fixture);

    {
        AdvancedFlowFilterSpec spec {};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.directionality.include = {AdvancedFlowFilterDirectionality::bidirectional};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.directionality.include = {AdvancedFlowFilterDirectionality::unidirectional};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {1U, 2U, 3U, 4U, 5U, 6U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.directionality.exclude = {AdvancedFlowFilterDirectionality::bidirectional};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {1U, 2U, 3U, 4U, 5U, 6U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.directionality.exclude = {AdvancedFlowFilterDirectionality::unidirectional};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.directionality.include = {AdvancedFlowFilterDirectionality::unidirectional};
        spec.flow_protocol.include = {ProtocolId::udp};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U, 4U, 6U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.service.include = {
            {.kind = AdvancedFlowFilterServicePredicateKind::known},
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 3U, 5U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.service.include = {
            {.kind = AdvancedFlowFilterServicePredicateKind::unknown},
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {2U, 4U, 6U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.service.include = {
            {
                .kind = AdvancedFlowFilterServicePredicateKind::equals,
                .value = "alpha.example",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
            {
                .kind = AdvancedFlowFilterServicePredicateKind::starts_with,
                .value = "BETA",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };
        spec.service.exclude = {
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "nested",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 3U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.service.include = {
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "EXAMPLE",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };
        spec.flow_protocol.include = {ProtocolId::tcp};
        spec.ports.include = {
            {.scope = AdvancedFlowFilterPortScope::either_endpoint, .range = {.first = 443U, .last = 443U}},
        };
        spec.aggregate.packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 100U, .max = std::nullopt};
        spec.aggregate.fragmented_packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 0U, .max = 0U};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.service.include = {
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "",
            },
        };
        const auto compile_result =
            session_detail::compile_advanced_flow_filter(spec, fixture.session.state().protocol_path_registry, fixture.default_settings);
        PFL_EXPECT(compile_result.status == AdvancedFlowFilterCompileStatus::invalid_service_predicate);
    }
}

void run_address_and_version_tests() {
    ScopedTestContext context {"advanced_flow_filter/address_and_version"};
    auto fixture = build_fixture();
    const auto connections = listed_connections_for_fixture(fixture);

    {
        AdvancedFlowFilterSpec spec {};
        spec.addresses.ipv4_include = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::exact,
                .scope = AdvancedFlowFilterEndpointScope::endpoint_b,
                .value = ipv4(10, 0, 0, 20),
                .prefix_length = 32U,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.addresses.ipv4_include = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
                .scope = AdvancedFlowFilterEndpointScope::either_endpoint,
                .value = ipv4(10, 0, 0, 0),
                .prefix_length = 26U,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.addresses.ipv4_include = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
                .scope = AdvancedFlowFilterEndpointScope::either_endpoint,
                .value = ipv4(10, 0, 0, 64),
                .prefix_length = 26U,
            },
        };
        spec.addresses.ipv4_exclude = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::exact,
                .scope = AdvancedFlowFilterEndpointScope::endpoint_a,
                .value = ipv4(10, 0, 0, 92),
                .prefix_length = 32U,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U, 4U, 5U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.addresses.ipv6_include = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::exact,
                .scope = AdvancedFlowFilterEndpointScope::endpoint_a,
                .value = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31}),
                .prefix_length = 128U,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {6U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.addresses.ipv6_include = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
                .scope = AdvancedFlowFilterEndpointScope::either_endpoint,
                .value = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
                .prefix_length = 64U,
            },
        };
        spec.flow_protocol.include = {ProtocolId::udp};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {6U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.addresses.ipv4_include = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
                .scope = AdvancedFlowFilterEndpointScope::either_endpoint,
                .value = ipv4(10, 0, 0, 0),
                .prefix_length = 33U,
            },
        };
        const auto compile_result =
            session_detail::compile_advanced_flow_filter(spec, fixture.session.state().protocol_path_registry, fixture.default_settings);
        PFL_EXPECT(compile_result.status == AdvancedFlowFilterCompileStatus::invalid_address_predicate);
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.addresses.ipv6_include = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::exact,
                .scope = AdvancedFlowFilterEndpointScope::endpoint_a,
                .value = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31}),
                .prefix_length = 64U,
            },
        };
        const auto compile_result =
            session_detail::compile_advanced_flow_filter(spec, fixture.session.state().protocol_path_registry, fixture.default_settings);
        PFL_EXPECT(compile_result.status == AdvancedFlowFilterCompileStatus::invalid_address_predicate);
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.tls_version.include = {TlsVersionHint::tls13};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.detected_protocol.include = {FlowProtocolHint::tls};
        spec.tls_version.exclude = {TlsVersionHint::tls13};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {5U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.quic_version.include = {QuicVersionHint::v1};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.flow_protocol.include = {ProtocolId::udp};
        spec.quic_version.include = {QuicVersionHint::v1};
        spec.service.include = {
            {
                .kind = AdvancedFlowFilterServicePredicateKind::starts_with,
                .value = "quic-",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {7U});
    }
}

void run_index_roundtrip_tests() {
    ScopedTestContext context {"advanced_flow_filter/index_roundtrip"};

    {
        const auto capture_path = write_temp_pcap(
            "pfl_advanced_flow_filter_address_roundtrip.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, make_ethernet_ipv4_tcp_packet(ipv4(192, 0, 2, 10), ipv4(198, 51, 100, 10), 41000U, 443U)},
                {200U, make_ethernet_ipv4_udp_packet(ipv4(192, 0, 2, 20), ipv4(198, 51, 100, 20), 53000U, 53U)},
                {300U, make_ethernet_ipv6_udp_with_hop_by_hop_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x41}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42}),
                    54000U,
                    54001U
                )},
            })
        );
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_advanced_flow_filter_address_roundtrip.idx";

        CaptureSession raw_session {};
        PFL_REQUIRE(raw_session.open_capture(capture_path));

        AdvancedFlowFilterSpec spec {};
        spec.addresses.ipv4_include = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::exact,
                .scope = AdvancedFlowFilterEndpointScope::endpoint_a,
                .value = ipv4(192, 0, 2, 10),
                .prefix_length = 32U,
            },
        };

        const auto raw_matches = evaluate_matching_indices_for_session(raw_session, spec, AnalysisSettings {});
        PFL_EXPECT(!raw_matches.empty());
        PFL_REQUIRE(raw_session.save_index(index_path));

        CaptureSession loaded_session {};
        PFL_REQUIRE(loaded_session.load_index(index_path));
        expect_indices_equal(
            evaluate_matching_indices_for_session(loaded_session, spec, AnalysisSettings {}),
            raw_matches
        );
    }

    {
        const auto capture_path = fixture_path("parsing/tls/tls_1_2_server_hello_4.pcap");
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_advanced_flow_filter_tls_roundtrip.idx";

        CaptureSession raw_session {};
        PFL_REQUIRE(raw_session.open_capture(capture_path));

        AdvancedFlowFilterSpec spec {};
        spec.tls_version.include = {TlsVersionHint::tls12};
        const auto raw_matches = evaluate_matching_indices_for_session(raw_session, spec, AnalysisSettings {});
        PFL_EXPECT(!raw_matches.empty());
        PFL_REQUIRE(raw_session.save_index(index_path));

        CaptureSession loaded_session {};
        PFL_REQUIRE(loaded_session.load_index(index_path));
        expect_indices_equal(
            evaluate_matching_indices_for_session(loaded_session, spec, AnalysisSettings {}),
            raw_matches
        );
    }

    {
        const auto capture_path = fixture_path("parsing/quic/quic_example_2.pcap");
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_advanced_flow_filter_quic_roundtrip.idx";

        CaptureSession raw_session {};
        PFL_REQUIRE(raw_session.open_capture(capture_path));

        AdvancedFlowFilterSpec spec {};
        spec.quic_version.include = {QuicVersionHint::v1};
        const auto raw_matches = evaluate_matching_indices_for_session(raw_session, spec, AnalysisSettings {});
        PFL_EXPECT(!raw_matches.empty());
        PFL_REQUIRE(raw_session.save_index(index_path));

        CaptureSession loaded_session {};
        PFL_REQUIRE(loaded_session.load_index(index_path));
        expect_indices_equal(
            evaluate_matching_indices_for_session(loaded_session, spec, AnalysisSettings {}),
            raw_matches
        );
    }
}

void run_metadata_only_evaluation_tests() {
    ScopedTestContext context {"advanced_flow_filter/metadata_only"};

    CaptureSession session {};
    auto& state = session.state();
    const auto path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::tcp()}
    });

    const FlowKeyV4 key {
        .src_addr = ipv4(192, 0, 2, 10),
        .dst_addr = ipv4(198, 51, 100, 10),
        .src_port = 50000,
        .dst_port = 443,
        .protocol = ProtocolId::tcp,
    };

    auto& connection = state.ipv4_connections.get_or_create(make_connection_key(key));
    connection = make_ipv4_connection(
        key,
        std::nullopt,
        path_id,
        25U,
        0U,
        2500U,
        0U,
        2048U,
        1000U,
        5000U,
        FlowProtocolHint::unknown,
        "byte-free.example",
        0U,
        0U,
        1U,
        0U,
        0U,
        512U,
        480U
    );
    connection.flow_a.packets.clear();
    connection.flow_b.packets.clear();

    const auto connections = session_detail::list_connections(state);
    PFL_REQUIRE(connections.size() == 1U);

    AdvancedFlowFilterSpec spec {};
    spec.aggregate.captured_bytes = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 2048U, .max = 2048U};
    spec.aggregate.duration_us = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 4000U, .max = 4000U};
    spec.service.include = {
        {
            .kind = AdvancedFlowFilterServicePredicateKind::contains,
            .value = "BYTE-FREE",
            .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
        },
    };

    const auto compile_result =
        session_detail::compile_advanced_flow_filter(spec, state.protocol_path_registry, AnalysisSettings {});
    PFL_REQUIRE(compile_result.status == AdvancedFlowFilterCompileStatus::ok);

    const auto result = session_detail::evaluate_advanced_flow_filter(connections, compile_result.filter);
    PFL_REQUIRE(result.status == AdvancedFlowFilterEvaluationStatus::ok);
    expect_indices_equal(result.matching_flow_indices, {0U});
}

}  // namespace

void run_advanced_flow_filter_tests() {
    run_protocol_and_candidate_scope_tests();
    run_protocol_path_tests();
    run_port_and_aggregate_tests();
    run_directionality_and_service_tests();
    run_address_and_version_tests();
    run_index_roundtrip_tests();
    run_metadata_only_evaluation_tests();
}

}  // namespace pfl::tests
