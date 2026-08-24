#include <array>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/AdvancedFlowFilter.h"
#include "app/session/AdvancedFlowFilterFormat.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path("tests/data") / relative_path;
}

using session_detail::AdvancedFlowFilterCompileStatus;
using session_detail::AdvancedFlowFilterDocument;
using session_detail::AdvancedFlowFilterDocumentSectionStates;
using session_detail::AdvancedFlowFilterEndpointScope;
using session_detail::AdvancedFlowFilterDirectionality;
using session_detail::AdvancedFlowFilterEvaluationStatus;
using session_detail::AdvancedFlowFilterInclusiveRange;
using session_detail::AdvancedFlowFilterTextFormatStatus;
using session_detail::AdvancedFlowFilterTextParseStatus;
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

session_detail::AdvancedFlowFilterTextParseResult require_parse_success(const std::string_view text) {
    const auto result = session_detail::parse_advanced_flow_filter_text(text);
    PFL_REQUIRE(result.status == AdvancedFlowFilterTextParseStatus::ok);
    return result;
}

session_detail::AdvancedFlowFilterDocument make_default_document(const AdvancedFlowFilterSpec& spec) {
    session_detail::AdvancedFlowFilterDocument document {};
    document.configured_spec = spec;
    return document;
}

std::string require_format_success(const session_detail::AdvancedFlowFilterDocument& document) {
    const auto result = session_detail::format_advanced_flow_filter_text(document);
    PFL_REQUIRE(result.status == AdvancedFlowFilterTextFormatStatus::ok);
    return result.text;
}

void expect_parse_status(
    const std::string_view text,
    const AdvancedFlowFilterTextParseStatus expected_status
) {
    const auto result = session_detail::parse_advanced_flow_filter_text(text);
    PFL_EXPECT(result.status == expected_status);
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

void expect_round_trip_stable(const AdvancedFlowFilterSpec& spec) {
    const auto document = make_default_document(spec);
    const auto first_text = require_format_success(document);
    const auto reparsed = require_parse_success(first_text);
    const auto second_text = require_format_success(reparsed.document);
    PFL_EXPECT(first_text == second_text);
    PFL_EXPECT(reparsed.document == document);
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
        const std::vector<std::size_t> candidate_scope {};
        const auto result = session_detail::evaluate_advanced_flow_filter(
            connections,
            filter,
            std::span<const std::size_t>(candidate_scope)
        );
        PFL_REQUIRE(result.status == AdvancedFlowFilterEvaluationStatus::ok);
        expect_indices_equal(result.matching_flow_indices, {});
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
        spec.flow_protocol.include = {ProtocolId::udp};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        const std::vector<std::size_t> candidate_scope {7U};
        const auto result = session_detail::evaluate_advanced_flow_filter(
            connections,
            filter,
            std::span<const std::size_t>(candidate_scope)
        );
        PFL_REQUIRE(result.status == AdvancedFlowFilterEvaluationStatus::ok);
        expect_indices_equal(result.matching_flow_indices, {7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.flow_protocol.include = {ProtocolId::udp};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        const std::vector<std::size_t> candidate_scope {6U, 3U, 6U, 7U, 4U};
        const auto result = session_detail::evaluate_advanced_flow_filter(
            connections,
            filter,
            std::span<const std::size_t>(candidate_scope)
        );
        PFL_REQUIRE(result.status == AdvancedFlowFilterEvaluationStatus::ok);
        expect_indices_equal(result.matching_flow_indices, {3U, 4U, 6U, 7U});
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U, 4U, 6U, 7U});
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
                {.kind = ProtocolLayerKind::vxlan, .identifier = ProtocolLayerIdentifier {
                    .kind = ProtocolLayerIdentifierKind::vxlan_vni,
                    .value = 100U,
                }},
                {.kind = ProtocolLayerKind::ethernet_ii},
                {.kind = ProtocolLayerKind::ipv4},
            },
        });
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {{
                .kind = ProtocolLayerKind::vxlan,
                .identifier = ProtocolLayerIdentifier {
                    .kind = ProtocolLayerIdentifierKind::vxlan_vni,
                    .value = 200U,
                },
            }},
        });
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::path_prefix,
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
            },
        });
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {{
                .kind = ProtocolLayerKind::vxlan,
                .identifier = ProtocolLayerIdentifier {
                    .kind = ProtocolLayerIdentifierKind::vxlan_vni,
                    .value = 100U,
                },
            }},
        });
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {1U});
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
        spec.directionality.include = {static_cast<AdvancedFlowFilterDirectionality>(2)};
        const auto compile_result =
            session_detail::compile_advanced_flow_filter(spec, fixture.session.state().protocol_path_registry, fixture.default_settings);
        PFL_EXPECT(compile_result.status == AdvancedFlowFilterCompileStatus::invalid_directionality_predicate);
        PFL_REQUIRE(compile_result.issue.has_value());
        PFL_EXPECT(compile_result.issue->category == "directionality");
        PFL_EXPECT(compile_result.issue->predicate_index == 0U);
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.directionality.exclude = {static_cast<AdvancedFlowFilterDirectionality>(2)};
        const auto compile_result =
            session_detail::compile_advanced_flow_filter(spec, fixture.session.state().protocol_path_registry, fixture.default_settings);
        PFL_EXPECT(compile_result.status == AdvancedFlowFilterCompileStatus::invalid_directionality_predicate);
        PFL_REQUIRE(compile_result.issue.has_value());
        PFL_EXPECT(compile_result.issue->category == "directionality");
        PFL_EXPECT(compile_result.issue->predicate_index == 0U);
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
            {.kind = AdvancedFlowFilterServicePredicateKind::unknown},
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "youtube",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.service.include = {
            {.kind = AdvancedFlowFilterServicePredicateKind::known},
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "nested",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {1U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.service.include = {
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "ALPHA",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "beta",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 3U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.service.include = {
            {.kind = AdvancedFlowFilterServicePredicateKind::known},
            {.kind = AdvancedFlowFilterServicePredicateKind::unknown},
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "quic",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.service.exclude = {
            {.kind = AdvancedFlowFilterServicePredicateKind::unknown},
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "nested",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 3U, 5U, 7U});
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

void run_address_family_tests() {
    ScopedTestContext context {"advanced_flow_filter/address_family"};
    auto fixture = build_fixture();
    const auto connections = listed_connections_for_fixture(fixture);

    {
        AdvancedFlowFilterSpec spec {};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.include = {FlowAddressFamily::ipv4};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 3U, 4U, 5U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.include = {FlowAddressFamily::ipv6};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {6U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.include = {FlowAddressFamily::ipv4, FlowAddressFamily::ipv6};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.exclude = {FlowAddressFamily::ipv6};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 3U, 4U, 5U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.exclude = {FlowAddressFamily::ipv4};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {6U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.include = {FlowAddressFamily::ipv4, FlowAddressFamily::ipv6};
        spec.address_family.exclude = {FlowAddressFamily::ipv6};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 3U, 4U, 5U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.include = {FlowAddressFamily::ipv4};
        spec.address_family.exclude = {FlowAddressFamily::ipv4};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.include = {FlowAddressFamily::ipv4};
        spec.flow_protocol.include = {ProtocolId::udp};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        expect_indices_equal(evaluate_matching_indices(connections, filter), {3U, 4U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.include = {FlowAddressFamily::ipv4};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        const std::vector<std::size_t> candidate_scope {6U, 7U};
        const auto result = session_detail::evaluate_advanced_flow_filter(
            connections,
            filter,
            std::span<const std::size_t>(candidate_scope)
        );
        PFL_REQUIRE(result.status == AdvancedFlowFilterEvaluationStatus::ok);
        expect_indices_equal(result.matching_flow_indices, {7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.include = {FlowAddressFamily::ipv4};
        const auto filter = require_compiled_filter(spec, fixture, fixture.default_settings);
        const std::vector<std::size_t> candidate_scope {0U, 6U, 7U};
        const auto scoped_result = session_detail::evaluate_advanced_flow_filter(
            connections,
            filter,
            std::span<const std::size_t>(candidate_scope)
        );
        PFL_REQUIRE(scoped_result.status == AdvancedFlowFilterEvaluationStatus::ok);
        expect_indices_equal(scoped_result.matching_flow_indices, {0U, 7U});
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 3U, 4U, 5U, 7U});
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.include = {static_cast<FlowAddressFamily>(255)};
        const auto compile_result =
            session_detail::compile_advanced_flow_filter(spec, fixture.session.state().protocol_path_registry, fixture.default_settings);
        PFL_EXPECT(compile_result.status == AdvancedFlowFilterCompileStatus::invalid_address_family_predicate);
        PFL_EXPECT(compile_result.issue.has_value());
        PFL_EXPECT(compile_result.issue->category == "address_family");
        PFL_EXPECT(compile_result.issue->predicate_index == 0U);
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.address_family.exclude = {static_cast<FlowAddressFamily>(255)};
        const auto compile_result =
            session_detail::compile_advanced_flow_filter(spec, fixture.session.state().protocol_path_registry, fixture.default_settings);
        PFL_EXPECT(compile_result.status == AdvancedFlowFilterCompileStatus::invalid_address_family_predicate);
        PFL_EXPECT(compile_result.issue.has_value());
        PFL_EXPECT(compile_result.issue->category == "address_family");
        PFL_EXPECT(compile_result.issue->predicate_index == 0U);
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

void run_document_model_tests() {
    ScopedTestContext context {"advanced_flow_filter/document_model"};
    auto fixture = build_fixture();
    const auto connections = listed_connections_for_fixture(fixture);
    const std::vector<std::size_t> all_indices {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U};

    {
        const AdvancedFlowFilterDocument document {};
        PFL_EXPECT(document == AdvancedFlowFilterDocument {});
        PFL_EXPECT(session_detail::make_effective_advanced_flow_filter_spec(document) == AdvancedFlowFilterSpec {});
        PFL_EXPECT(session_detail::count_configured_advanced_flow_filter_atomic_rules(document) == 0U);
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 0U);
        PFL_EXPECT(session_detail::is_default_advanced_flow_filter_document(document));
    }

    {
        AdvancedFlowFilterDocument document {};
        document.configured_spec.address_family.include = {FlowAddressFamily::ipv6};

        PFL_EXPECT(session_detail::count_configured_advanced_flow_filter_atomic_rules(document) == 1U);
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 1U);

        auto effective = session_detail::make_effective_advanced_flow_filter_spec(document);
        PFL_EXPECT(effective.address_family.include.size() == 1U);
        PFL_EXPECT(effective.address_family.include.front() == FlowAddressFamily::ipv6);
        expect_indices_equal(
            evaluate_matching_indices(connections, require_compiled_filter(effective, fixture, fixture.default_settings)),
            {6U}
        );

        document.section_states.address_family = false;
        effective = session_detail::make_effective_advanced_flow_filter_spec(document);
        PFL_EXPECT(effective.address_family == session_detail::AdvancedFlowFilterAddressFamilyCriteria {});
        PFL_EXPECT(session_detail::count_configured_advanced_flow_filter_atomic_rules(document) == 1U);
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 0U);
        PFL_EXPECT(!session_detail::is_default_advanced_flow_filter_document(document));
        expect_indices_equal(
            evaluate_matching_indices(connections, require_compiled_filter(effective, fixture, fixture.default_settings)),
            all_indices
        );

        document.section_states.address_family = true;
        effective = session_detail::make_effective_advanced_flow_filter_spec(document);
        PFL_EXPECT(effective.address_family.include.size() == 1U);
        PFL_EXPECT(effective.address_family.include.front() == FlowAddressFamily::ipv6);
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 1U);
    }

    {
        AdvancedFlowFilterDocument document {};
        document.configured_spec.aggregate.packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 10U, .max = 20U};
        document.configured_spec.aggregate.original_bytes = AdvancedFlowFilterInclusiveRange<std::uint64_t> {};
        document.configured_spec.aggregate.captured_bytes = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 1024U};
        document.configured_spec.aggregate.duration_us = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.max = 5000U};

        PFL_EXPECT(session_detail::count_configured_advanced_flow_filter_atomic_rules(document) == 4U);
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 4U);

        document.section_states.traffic = false;
        const auto effective = session_detail::make_effective_advanced_flow_filter_spec(document);
        PFL_EXPECT(effective.aggregate == session_detail::AdvancedFlowFilterAggregateCriteria {});
        PFL_EXPECT(session_detail::count_configured_advanced_flow_filter_atomic_rules(document) == 4U);
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 0U);
    }

    {
        AdvancedFlowFilterDocument document {};
        document.configured_spec.ports.include = {
            {.scope = AdvancedFlowFilterPortScope::either_endpoint, .range = {.first = 443U, .last = 443U}},
        };
        document.configured_spec.ports.exclude = {
            {.scope = AdvancedFlowFilterPortScope::endpoint_b, .range = {.first = 1U, .last = 1023U}},
        };
        document.configured_spec.addresses.ipv4_include = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::exact,
                .scope = AdvancedFlowFilterEndpointScope::endpoint_a,
                .value = ipv4(10, 0, 0, 10),
                .prefix_length = 32U,
            },
        };
        document.configured_spec.service.include = {
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "alpha",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };

        PFL_EXPECT(session_detail::count_configured_advanced_flow_filter_atomic_rules(document) == 4U);
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 4U);

        document.section_states.service = false;
        const auto effective = session_detail::make_effective_advanced_flow_filter_spec(document);
        PFL_EXPECT(effective.ports.include.size() == 1U);
        PFL_EXPECT(effective.ports.exclude.size() == 1U);
        PFL_EXPECT(effective.addresses.ipv4_include.size() == 1U);
        PFL_EXPECT(effective.service == session_detail::AdvancedFlowFilterServiceCriteria {});
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 3U);
    }

    {
        AdvancedFlowFilterDocument document {};
        document.configured_spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::exact_path,
            .layers = {
                {.kind = ProtocolLayerKind::ethernet_ii},
                {.kind = ProtocolLayerKind::ipv4},
                {.kind = ProtocolLayerKind::tcp},
            },
        });
        document.configured_spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {
                {.kind = ProtocolLayerKind::vxlan, .identifier = ProtocolLayerIdentifier {
                    .kind = ProtocolLayerIdentifierKind::vxlan_vni,
                    .value = 100U,
                }},
            },
        });
        document.configured_spec.protocol_path.exclude.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {
                {.kind = ProtocolLayerKind::gtpu, .identifier = ProtocolLayerIdentifier {
                    .kind = ProtocolLayerIdentifierKind::gtpu_teid,
                    .value = 0x12345678U,
                }},
            },
        });

        PFL_EXPECT(session_detail::count_configured_advanced_flow_filter_atomic_rules(document) == 3U);
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 3U);

        auto effective = session_detail::make_effective_advanced_flow_filter_spec(document);
        PFL_EXPECT(effective.protocol_path.include.size() == 2U);
        PFL_EXPECT(effective.protocol_path.exclude.size() == 1U);

        document.section_states.contains_layer = false;
        effective = session_detail::make_effective_advanced_flow_filter_spec(document);
        PFL_EXPECT(effective.protocol_path.include.size() == 1U);
        PFL_EXPECT(effective.protocol_path.include.front().match_kind == AdvancedFlowFilterProtocolPathMatchKind::exact_path);
        PFL_EXPECT(effective.protocol_path.exclude.empty());
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 1U);
        expect_indices_equal(
            evaluate_matching_indices(connections, require_compiled_filter(effective, fixture, fixture.default_settings)),
            {0U, 2U, 5U}
        );

        document.section_states.contains_layer = true;
        document.section_states.protocol_path = false;
        effective = session_detail::make_effective_advanced_flow_filter_spec(document);
        PFL_EXPECT(effective.protocol_path.include.size() == 1U);
        PFL_EXPECT(effective.protocol_path.include.front().match_kind == AdvancedFlowFilterProtocolPathMatchKind::contains_layer);
        PFL_EXPECT(effective.protocol_path.exclude.size() == 1U);
        PFL_EXPECT(effective.protocol_path.exclude.front().match_kind == AdvancedFlowFilterProtocolPathMatchKind::contains_layer);
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 2U);
        expect_indices_equal(
            evaluate_matching_indices(connections, require_compiled_filter(effective, fixture, fixture.default_settings)),
            {1U}
        );

        document.section_states.contains_layer = false;
        effective = session_detail::make_effective_advanced_flow_filter_spec(document);
        PFL_EXPECT(effective.protocol_path == session_detail::AdvancedFlowFilterProtocolPathCriteria {});
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 0U);
    }

    {
        AdvancedFlowFilterDocument left {};
        left.configured_spec.directionality.include = {AdvancedFlowFilterDirectionality::unidirectional};
        AdvancedFlowFilterDocument right = left;
        PFL_EXPECT(left == right);

        right.section_states.contains_layer = false;
        PFL_EXPECT(!(left == right));

        right = left;
        right.configured_spec.directionality.exclude = {AdvancedFlowFilterDirectionality::bidirectional};
        PFL_EXPECT(!(left == right));
    }

    {
        AdvancedFlowFilterDocument document {};
        document.section_states.ports = false;
        PFL_EXPECT(session_detail::count_configured_advanced_flow_filter_atomic_rules(document) == 0U);
        PFL_EXPECT(session_detail::count_active_advanced_flow_filter_atomic_rules(document) == 0U);
        PFL_EXPECT(!session_detail::is_default_advanced_flow_filter_document(document));
        PFL_EXPECT(document.section_states != AdvancedFlowFilterDocumentSectionStates {});
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

void run_text_format_tests() {
    ScopedTestContext context {"advanced_flow_filter/text_format"};
    auto fixture = build_fixture();
    const auto connections = listed_connections_for_fixture(fixture);

    {
        const auto parsed = require_parse_success("format_version = 2\n");
        const auto filter = require_compiled_filter(
            session_detail::make_effective_advanced_flow_filter_spec(parsed.document),
            fixture,
            fixture.default_settings
        );
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U});
        PFL_EXPECT(parsed.document.section_states == session_detail::AdvancedFlowFilterDocumentSectionStates {});
        PFL_EXPECT(require_format_success(parsed.document) == std::string("format_version = 2\n"));
    }

    {
        const auto parsed = require_parse_success(
            "\xEF\xBB\xBF# comment\r\n"
            "format_version = 2\r\n"
            "\r\n"
            "flow_protocol.include = TCP\r\n"
            "service.contains.ci.include = \"#hash\"   # trailing comment\r\n"
        );
        const auto& spec = parsed.document.configured_spec;
        PFL_EXPECT(spec.flow_protocol.include == std::vector<ProtocolId> {ProtocolId::tcp});
        PFL_REQUIRE(spec.service.include.size() == 1U);
        PFL_EXPECT(spec.service.include.front().value == "#hash");
        PFL_EXPECT(
            require_format_success(parsed.document) ==
            std::string(
                "format_version = 2\n"
                "flow_protocol.include = tcp\n"
                "service.contains.ci.include = \"#hash\"\n"
            )
        );
    }

    {
        expect_parse_status("# only comment\n", AdvancedFlowFilterTextParseStatus::missing_format_version);
        expect_parse_status("flow_protocol.include = tcp\n", AdvancedFlowFilterTextParseStatus::missing_format_version);

        const auto duplicate_version = session_detail::parse_advanced_flow_filter_text(
            "format_version = 2\nformat_version = 2\n"
        );
        PFL_EXPECT(duplicate_version.status == AdvancedFlowFilterTextParseStatus::duplicate_format_version);
        PFL_REQUIRE(duplicate_version.issue.has_value());
        PFL_EXPECT(duplicate_version.issue->line == 2U);

        expect_parse_status("format_version = 1\n", AdvancedFlowFilterTextParseStatus::unsupported_format_version);
        expect_parse_status("format_version = 99\n", AdvancedFlowFilterTextParseStatus::unsupported_format_version);

        const auto unknown_key = session_detail::parse_advanced_flow_filter_text(
            "format_version = 2\nunknown.key = value\n"
        );
        PFL_EXPECT(unknown_key.status == AdvancedFlowFilterTextParseStatus::unknown_key);
        PFL_REQUIRE(unknown_key.issue.has_value());
        PFL_EXPECT(unknown_key.issue->line == 2U);
        PFL_EXPECT(unknown_key.issue->key == "unknown.key");

        expect_parse_status("format_version = 2\nflow_protocol.include tcp\n", AdvancedFlowFilterTextParseStatus::malformed_assignment);
        expect_parse_status("format_version = 2\npacket_count.min = 1\npacket_count.min = 2\n",
                            AdvancedFlowFilterTextParseStatus::duplicate_scalar_key);

        const auto invalid_enum = session_detail::parse_advanced_flow_filter_text(
            "format_version = 2\ndirectionality.include = any\n"
        );
        PFL_EXPECT(invalid_enum.status == AdvancedFlowFilterTextParseStatus::invalid_enum_token);
        PFL_REQUIRE(invalid_enum.issue.has_value());
        PFL_EXPECT(invalid_enum.issue->line == 2U);
        PFL_EXPECT(invalid_enum.issue->key == "directionality.include");
        PFL_EXPECT(invalid_enum.issue->token == "any");
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "section.address_family.enabled = false\n"
            "section.flow_protocol.enabled = FALSE\n"
            "section.detected_protocol.enabled = false\n"
            "section.tls_version.enabled = false\n"
            "section.quic_version.enabled = false\n"
            "section.directionality.enabled = false\n"
            "section.ports.enabled = false\n"
            "section.ip_addresses.enabled = false\n"
            "section.traffic.enabled = false\n"
            "section.service.enabled = false\n"
            "section.protocol_path.enabled = false\n"
            "section.contains_layer.enabled = false\n"
        );
        PFL_EXPECT(parsed.document.section_states.address_family == false);
        PFL_EXPECT(parsed.document.section_states.flow_protocol == false);
        PFL_EXPECT(parsed.document.section_states.detected_protocol == false);
        PFL_EXPECT(parsed.document.section_states.tls_version == false);
        PFL_EXPECT(parsed.document.section_states.quic_version == false);
        PFL_EXPECT(parsed.document.section_states.directionality == false);
        PFL_EXPECT(parsed.document.section_states.ports == false);
        PFL_EXPECT(parsed.document.section_states.ip_addresses == false);
        PFL_EXPECT(parsed.document.section_states.traffic == false);
        PFL_EXPECT(parsed.document.section_states.service == false);
        PFL_EXPECT(parsed.document.section_states.protocol_path == false);
        PFL_EXPECT(parsed.document.section_states.contains_layer == false);
        PFL_EXPECT(
            require_format_success(parsed.document) ==
            std::string(
                "format_version = 2\n"
                "section.address_family.enabled = false\n"
                "section.flow_protocol.enabled = false\n"
                "section.detected_protocol.enabled = false\n"
                "section.tls_version.enabled = false\n"
                "section.quic_version.enabled = false\n"
                "section.directionality.enabled = false\n"
                "section.ports.enabled = false\n"
                "section.ip_addresses.enabled = false\n"
                "section.traffic.enabled = false\n"
                "section.service.enabled = false\n"
                "section.protocol_path.enabled = false\n"
                "section.contains_layer.enabled = false\n"
            )
        );

        const auto explicit_true = require_parse_success(
            "format_version = 2\n"
            "section.ports.enabled = true\n"
            "port.either.include = 443\n"
        );
        PFL_EXPECT(explicit_true.document.section_states.ports == true);
        PFL_EXPECT(
            require_format_success(explicit_true.document) ==
            std::string(
                "format_version = 2\n"
                "port.either.include = 443\n"
            )
        );

        expect_parse_status(
            "format_version = 2\nsection.unknown.enabled = false\n",
            AdvancedFlowFilterTextParseStatus::unknown_key
        );
        expect_parse_status(
            "format_version = 2\nsection.ports.enabled = maybe\n",
            AdvancedFlowFilterTextParseStatus::invalid_value
        );
        expect_parse_status(
            "format_version = 2\nsection.ports.enabled = false\nsection.ports.enabled = true\n",
            AdvancedFlowFilterTextParseStatus::duplicate_scalar_key
        );
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "address_family.include = IPv4\n"
            "address_family.include = ipv6\n"
            "address_family.exclude = IPV6\n"
        );
        const auto& spec = parsed.document.configured_spec;
        PFL_EXPECT((spec.address_family.include == std::vector<FlowAddressFamily> {
            FlowAddressFamily::ipv4,
            FlowAddressFamily::ipv6,
        }));
        PFL_EXPECT((spec.address_family.exclude == std::vector<FlowAddressFamily> {
            FlowAddressFamily::ipv6,
        }));
        PFL_EXPECT(
            require_format_success(parsed.document) ==
            std::string(
                "format_version = 2\n"
                "address_family.include = ipv4\n"
                "address_family.include = ipv6\n"
                "address_family.exclude = ipv6\n"
            )
        );
    }

    {
        const auto invalid_family = session_detail::parse_advanced_flow_filter_text(
            "format_version = 2\n"
            "address_family.include = ipx\n"
        );
        PFL_EXPECT(invalid_family.status == AdvancedFlowFilterTextParseStatus::invalid_enum_token);
        PFL_REQUIRE(invalid_family.issue.has_value());
        PFL_EXPECT(invalid_family.issue->line == 2U);
        PFL_EXPECT(invalid_family.issue->key == "address_family.include");
        PFL_EXPECT(invalid_family.issue->token == "ipx");
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "address_family.include = IPv4\n"
            "flow_protocol.include = TCP\n"
            "flow_protocol.include = udp\n"
            "flow_protocol.exclude = IcmpV6\n"
            "detected_protocol.include = TLS\n"
            "detected_protocol.exclude = mDns\n"
            "tls_version.include = TLS1_3\n"
            "quic_version.exclude = Draft29\n"
            "directionality.include = BIDIRECTIONAL\n"
        );

        const auto& spec = parsed.document.configured_spec;
        PFL_EXPECT((spec.flow_protocol.include == std::vector<ProtocolId> {ProtocolId::tcp, ProtocolId::udp}));
        PFL_EXPECT((spec.flow_protocol.exclude == std::vector<ProtocolId> {ProtocolId::icmpv6}));
        PFL_EXPECT((spec.detected_protocol.include == std::vector<FlowProtocolHint> {FlowProtocolHint::tls}));
        PFL_EXPECT((spec.detected_protocol.exclude == std::vector<FlowProtocolHint> {FlowProtocolHint::mdns}));
        PFL_EXPECT((spec.tls_version.include == std::vector<TlsVersionHint> {TlsVersionHint::tls13}));
        PFL_EXPECT((spec.quic_version.exclude == std::vector<QuicVersionHint> {QuicVersionHint::draft29}));
        PFL_EXPECT((spec.address_family.include == std::vector<FlowAddressFamily> {FlowAddressFamily::ipv4}));
        PFL_EXPECT((
            spec.directionality.include ==
            std::vector<AdvancedFlowFilterDirectionality> {AdvancedFlowFilterDirectionality::bidirectional}
        ));

        PFL_EXPECT(
            require_format_success(parsed.document) ==
            std::string(
                "format_version = 2\n"
                "address_family.include = ipv4\n"
                "flow_protocol.include = tcp\n"
                "flow_protocol.include = udp\n"
                "flow_protocol.exclude = icmpv6\n"
                "detected_protocol.include = tls\n"
                "detected_protocol.exclude = mdns\n"
                "tls_version.include = tls1_3\n"
                "quic_version.exclude = draft29\n"
                "directionality.include = bidirectional\n"
            )
        );
    }

    expect_parse_status(
        "format_version = 2\n"
        "detected_protocol.include = possible_tls\n",
        AdvancedFlowFilterTextParseStatus::invalid_enum_token
    );
    expect_parse_status(
        "format_version = 2\n"
        "detected_protocol.include = possible_quic\n",
        AdvancedFlowFilterTextParseStatus::invalid_enum_token
    );

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "port.either.include = 443\n"
            "port.a.include = 53000-53010\n"
            "port.b.exclude = 1-1023\n"
        );
        const auto& spec = parsed.document.configured_spec;
        PFL_REQUIRE(spec.ports.include.size() == 2U);
        PFL_EXPECT(spec.ports.include[0].scope == AdvancedFlowFilterPortScope::either_endpoint);
        PFL_EXPECT(spec.ports.include[0].range.first == 443U);
        PFL_EXPECT(spec.ports.include[0].range.last == 443U);
        PFL_EXPECT(spec.ports.include[1].scope == AdvancedFlowFilterPortScope::endpoint_a);
        PFL_EXPECT(spec.ports.include[1].range.first == 53000U);
        PFL_EXPECT(spec.ports.include[1].range.last == 53010U);
        PFL_REQUIRE(spec.ports.exclude.size() == 1U);
        PFL_EXPECT(spec.ports.exclude[0].scope == AdvancedFlowFilterPortScope::endpoint_b);
        PFL_EXPECT(spec.ports.exclude[0].range.first == 1U);
        PFL_EXPECT(spec.ports.exclude[0].range.last == 1023U);

        expect_parse_status("format_version = 2\nport.either.include = 65536\n", AdvancedFlowFilterTextParseStatus::numeric_overflow);
        expect_parse_status("format_version = 2\nport.either.include = 9000-8000\n", AdvancedFlowFilterTextParseStatus::invalid_value);
        expect_parse_status("format_version = 2\nport.either.include = 100-200-300\n", AdvancedFlowFilterTextParseStatus::invalid_value);
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "packet_count.min = 100\n"
            "packet_count.max = 200\n"
            "original_bytes.min = 1MiB\n"
            "original_bytes.max = 1536B\n"
            "captured_bytes.min = 2048\n"
            "captured_bytes.max = 2GiB\n"
            "duration.min = 1500ms\n"
            "duration.max = 2h\n"
            "fragmented_packet_count.min = 1\n"
            "fragmented_packet_count.max = 2\n"
            "truncated_packet_count.min = 3\n"
            "truncated_packet_count.max = 4\n"
            "tcp_syn_count.min = 5\n"
            "tcp_syn_count.max = 6\n"
            "tcp_fin_count.min = 7\n"
            "tcp_fin_count.max = 8\n"
            "tcp_rst_count.min = 9\n"
            "tcp_rst_count.max = 10\n"
            "max_original_packet_length.min = 1500\n"
            "max_original_packet_length.max = 9000B\n"
            "max_captured_packet_length.min = 1024B\n"
            "max_captured_packet_length.max = 1KiB\n"
        );

        const auto& spec = parsed.document.configured_spec;
        PFL_REQUIRE(spec.aggregate.packet_count.has_value());
        PFL_EXPECT(spec.aggregate.packet_count->min == 100U);
        PFL_EXPECT(spec.aggregate.packet_count->max == 200U);
        PFL_REQUIRE(spec.aggregate.original_bytes.has_value());
        PFL_EXPECT(spec.aggregate.original_bytes->min == 1048576U);
        PFL_EXPECT(spec.aggregate.original_bytes->max == 1536U);
        PFL_REQUIRE(spec.aggregate.captured_bytes.has_value());
        PFL_EXPECT(spec.aggregate.captured_bytes->min == 2048U);
        PFL_EXPECT(spec.aggregate.captured_bytes->max == 2147483648ULL);
        PFL_REQUIRE(spec.aggregate.duration_us.has_value());
        PFL_EXPECT(spec.aggregate.duration_us->min == 1500000U);
        PFL_EXPECT(spec.aggregate.duration_us->max == 7200000000ULL);
        PFL_REQUIRE(spec.aggregate.max_original_packet_length.has_value());
        PFL_EXPECT(spec.aggregate.max_original_packet_length->min == 1500U);
        PFL_EXPECT(spec.aggregate.max_original_packet_length->max == 9000U);
        PFL_REQUIRE(spec.aggregate.max_captured_packet_length.has_value());
        PFL_EXPECT(spec.aggregate.max_captured_packet_length->min == 1024U);
        PFL_EXPECT(spec.aggregate.max_captured_packet_length->max == 1024U);

        expect_parse_status("format_version = 2\noriginal_bytes.min = 1MB\n", AdvancedFlowFilterTextParseStatus::invalid_value);
        expect_parse_status("format_version = 2\ncaptured_bytes.min = 16777216TiB\n", AdvancedFlowFilterTextParseStatus::numeric_overflow);
        expect_parse_status("format_version = 2\nduration.min = 18446744073709551615h\n", AdvancedFlowFilterTextParseStatus::numeric_overflow);
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "ip.either.include = 192.0.2.10\n"
            "ip.a.exclude = 10.0.0.0/8\n"
            "ip.b.include = 2001:db8::1\n"
            "ip.either.exclude = 2001:db8::/32\n"
        );
        const auto& spec = parsed.document.configured_spec;
        PFL_REQUIRE(spec.addresses.ipv4_include.size() == 1U);
        PFL_EXPECT(spec.addresses.ipv4_include[0].match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::exact);
        PFL_EXPECT(spec.addresses.ipv4_include[0].prefix_length == 32U);
        PFL_REQUIRE(spec.addresses.ipv4_exclude.size() == 1U);
        PFL_EXPECT(spec.addresses.ipv4_exclude[0].match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr);
        PFL_EXPECT(spec.addresses.ipv4_exclude[0].prefix_length == 8U);
        PFL_REQUIRE(spec.addresses.ipv6_include.size() == 1U);
        PFL_EXPECT(spec.addresses.ipv6_include[0].match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::exact);
        PFL_EXPECT(spec.addresses.ipv6_include[0].prefix_length == 128U);
        PFL_REQUIRE(spec.addresses.ipv6_exclude.size() == 1U);
        PFL_EXPECT(spec.addresses.ipv6_exclude[0].match_kind == session_detail::AdvancedFlowFilterAddressMatchKind::cidr);
        PFL_EXPECT(spec.addresses.ipv6_exclude[0].prefix_length == 32U);

        expect_parse_status("format_version = 2\nip.either.include = 300.1.2.3\n", AdvancedFlowFilterTextParseStatus::invalid_ip_address);
        expect_parse_status("format_version = 2\nip.either.include = 2001:::1\n", AdvancedFlowFilterTextParseStatus::invalid_ip_address);
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "service.state.include = known\n"
            "service.state.exclude = unknown\n"
            "service.equals.ci.include = \"Example # Service\"\n"
            "service.starts_with.cs.exclude = \"TEST\\\\prefix\"\n"
            "service.contains.ci.include = \"line\\nvalue\\t#\"\n"
        );
        const auto& spec = parsed.document.configured_spec;
        PFL_REQUIRE(spec.service.include.size() == 3U);
        PFL_EXPECT(spec.service.include[0].kind == AdvancedFlowFilterServicePredicateKind::known);
        PFL_EXPECT(spec.service.include[1].kind == AdvancedFlowFilterServicePredicateKind::equals);
        PFL_EXPECT(spec.service.include[1].value == "Example # Service");
        PFL_EXPECT(spec.service.include[2].value == "line\nvalue\t#");
        PFL_REQUIRE(spec.service.exclude.size() == 2U);
        PFL_EXPECT(spec.service.exclude[0].kind == AdvancedFlowFilterServicePredicateKind::unknown);
        PFL_EXPECT(spec.service.exclude[1].value == "TEST\\prefix");

        expect_parse_status("format_version = 2\nservice.contains.ci.include = \"bad\\q\"\n", AdvancedFlowFilterTextParseStatus::invalid_escape);
        expect_parse_status("format_version = 2\nservice.contains.ci.include = \"unterminated\n", AdvancedFlowFilterTextParseStatus::unterminated_string);
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "protocol_path.exact.include = EthernetII > IPv4 > TCP\n"
            "protocol_path.prefix.include = EthernetII > VLAN(vid=100) > MPLS(label=16050) > IPv6\n"
            "protocol_path.contains.include = VXLAN(vni=42)\n"
            "protocol_path.contains.exclude = Geneve(vni=7)\n"
            "protocol_path.contains.include = GTP-U(teid=0x12345678)\n"
            "protocol_path.contains.include = GRE(key=0x00001234)\n"
            "protocol_path.contains.include = PBB(isid=0x123456)\n"
            "protocol_path.contains.include = AH(spi=0x11111111)\n"
            "protocol_path.contains.include = ESP(spi=0x01020304)\n"
            "protocol_path.contains.include = IEEE 802.3\n"
            "protocol_path.contains.include = LLC/SNAP\n"
            "protocol_path.contains.include = LinuxSll\n"
            "protocol_path.contains.include = LinuxSll2\n"
            "protocol_path.contains.include = MPLS PW\n"
            "protocol_path.contains.include = PPPoE\n"
            "protocol_path.contains.include = PPP\n"
            "protocol_path.contains.include = MACsec\n"
            "protocol_path.contains.include = SCTP\n"
            "protocol_path.contains.include = ICMP\n"
            "protocol_path.contains.include = ICMPv6\n"
            "protocol_path.contains.include = ARP\n"
            "protocol_path.contains.include = UDP\n"
        );
        const auto& spec = parsed.document.configured_spec;
        PFL_REQUIRE(spec.protocol_path.include.size() == 20U);
        PFL_REQUIRE(spec.protocol_path.exclude.size() == 1U);
        PFL_EXPECT(spec.protocol_path.include[0].match_kind == AdvancedFlowFilterProtocolPathMatchKind::exact_path);
        PFL_EXPECT(spec.protocol_path.include[1].match_kind == AdvancedFlowFilterProtocolPathMatchKind::path_prefix);
        PFL_EXPECT(spec.protocol_path.include[2].match_kind == AdvancedFlowFilterProtocolPathMatchKind::contains_layer);
        PFL_EXPECT(spec.protocol_path.include[2].layers[0].kind == ProtocolLayerKind::vxlan);
        PFL_EXPECT(spec.protocol_path.include[2].layers[0].identifier->value == 42U);
        PFL_EXPECT(spec.protocol_path.include[4].layers[0].identifier->kind == ProtocolLayerIdentifierKind::gre_key);

        expect_parse_status("format_version = 2\nprotocol_path.contains.include = VLAN(vid=100) > IPv4\n",
                            AdvancedFlowFilterTextParseStatus::invalid_protocol_path_syntax);
        expect_parse_status("format_version = 2\nprotocol_path.contains.include = UnknownLayer\n",
                            AdvancedFlowFilterTextParseStatus::invalid_protocol_path_syntax);
        expect_parse_status("format_version = 2\nprotocol_path.contains.include = VLAN(foo=1)\n",
                            AdvancedFlowFilterTextParseStatus::invalid_protocol_path_syntax);

        const auto identifier_bearing_paths = require_parse_success(
            "format_version = 2\n"
            "protocol_path.prefix.include = EthernetII > IPv4 > UDP > Geneve(vni=100)\n"
            "protocol_path.exact.include = EthernetII > IPv4 > UDP > GTP-U(teid=0x01020304) > IPv4 > TCP\n"
            "protocol_path.contains.include = AH(spi=0x11111111)\n"
        );
        PFL_REQUIRE(identifier_bearing_paths.document.configured_spec.protocol_path.include.size() == 3U);
        const auto& geneve_prefix = identifier_bearing_paths.document.configured_spec.protocol_path.include[0];
        PFL_EXPECT(geneve_prefix.match_kind == AdvancedFlowFilterProtocolPathMatchKind::path_prefix);
        PFL_REQUIRE(geneve_prefix.layers.size() == 4U);
        PFL_EXPECT(geneve_prefix.layers[3].kind == ProtocolLayerKind::geneve);
        PFL_REQUIRE(geneve_prefix.layers[3].identifier.has_value());
        PFL_EXPECT(geneve_prefix.layers[3].identifier->kind == ProtocolLayerIdentifierKind::geneve_vni);
        PFL_EXPECT(geneve_prefix.layers[3].identifier->value == 100U);

        const auto& gtpu_exact = identifier_bearing_paths.document.configured_spec.protocol_path.include[1];
        PFL_EXPECT(gtpu_exact.match_kind == AdvancedFlowFilterProtocolPathMatchKind::exact_path);
        PFL_REQUIRE(gtpu_exact.layers.size() == 6U);
        PFL_EXPECT(gtpu_exact.layers[3].kind == ProtocolLayerKind::gtpu);
        PFL_REQUIRE(gtpu_exact.layers[3].identifier.has_value());
        PFL_EXPECT(gtpu_exact.layers[3].identifier->kind == ProtocolLayerIdentifierKind::gtpu_teid);
        PFL_EXPECT(gtpu_exact.layers[3].identifier->value == 0x01020304U);

        const auto& ah_contains = identifier_bearing_paths.document.configured_spec.protocol_path.include[2];
        PFL_EXPECT(ah_contains.match_kind == AdvancedFlowFilterProtocolPathMatchKind::contains_layer);
        PFL_REQUIRE(ah_contains.layers.size() == 1U);
        PFL_EXPECT(ah_contains.layers[0].kind == ProtocolLayerKind::ah);
        PFL_REQUIRE(ah_contains.layers[0].identifier.has_value());
        PFL_EXPECT(ah_contains.layers[0].identifier->kind == ProtocolLayerIdentifierKind::ah_spi);
        PFL_EXPECT(ah_contains.layers[0].identifier->value == 0x11111111U);

        const auto invalid_protocol_path = session_detail::parse_advanced_flow_filter_text(
            "format_version = 2\nprotocol_path.contains.include = ESP(key=1)\n"
        );
        PFL_EXPECT(invalid_protocol_path.status == AdvancedFlowFilterTextParseStatus::invalid_protocol_path_syntax);
        PFL_REQUIRE(invalid_protocol_path.issue.has_value());
        PFL_EXPECT(invalid_protocol_path.issue->line == 2U);
        PFL_EXPECT(invalid_protocol_path.issue->key == "protocol_path.contains.include");
        PFL_EXPECT(invalid_protocol_path.issue->token == "ESP(key=1)");

        const auto quoted_equals_service = require_parse_success(
            "format_version = 2\n"
            "service.contains.ci.include = \"a=b\"\n"
        );
        PFL_REQUIRE(quoted_equals_service.document.configured_spec.service.include.size() == 1U);
        PFL_EXPECT(quoted_equals_service.document.configured_spec.service.include[0].value == "a=b");
    }

    {
        const auto formatted_shape = require_parse_success(
            "format_version = 2\n"
            "protocol_path.prefix.include = EthernetII > IPv4 > UDP > Geneve > EthernetII > IPv4 > TCP\n"
            "protocol_path.prefix.include = EthernetII > IPv4 > UDP > Geneve(vni=100)\n"
            "protocol_path.exact.include = EthernetII > IPv4 > UDP > GTP-U(teid=0x01020304) > IPv4 > TCP\n"
            "protocol_path.contains.include = VLAN\n"
        );
        PFL_REQUIRE(formatted_shape.document.configured_spec.protocol_path.include.size() == 4U);
    }

    {
        const auto realistic_tls_text =
            "format_version = 2\n"
            "flow_protocol.include = tcp\n"
            "detected_protocol.include = tls\n"
            "tls_version.include = tls1_3\n"
            "port.either.include = 443\n"
            "packet_count.min = 100\n"
            "original_bytes.min = 1KiB\n"
            "duration.min = 1s\n"
            "ip.either.include = 10.0.0.0/8\n"
            "directionality.include = bidirectional\n"
            "service.contains.ci.include = \"example\"\n";
        const auto parsed = require_parse_success(realistic_tls_text);
        const auto filter = require_compiled_filter(
            session_detail::make_effective_advanced_flow_filter_spec(parsed.document),
            fixture,
            fixture.default_settings
        );
        expect_indices_equal(evaluate_matching_indices(connections, filter), {0U});
        expect_round_trip_stable(parsed.document.configured_spec);
    }

    {
        const auto realistic_quic_text =
            "format_version = 2\n"
            "flow_protocol.include = udp\n"
            "detected_protocol.include = quic\n"
            "quic_version.include = v1\n"
            "port.either.include = 443\n"
            "packet_count.min = 7\n"
            "captured_bytes.min = 720B\n"
            "duration.max = 10s\n"
            "ip.a.include = 10.0.0.92\n"
            "directionality.include = unidirectional\n"
            "service.starts_with.ci.include = \"quic-\"\n";
        const auto parsed = require_parse_success(realistic_quic_text);
        const auto filter = require_compiled_filter(
            session_detail::make_effective_advanced_flow_filter_spec(parsed.document),
            fixture,
            fixture.default_settings
        );
        expect_indices_equal(evaluate_matching_indices(connections, filter), {7U});
        expect_round_trip_stable(parsed.document.configured_spec);
    }

    {
        session_detail::AdvancedFlowFilterDocument document {};
        auto& spec = document.configured_spec;
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {{.kind = ProtocolLayerKind::vlan, .identifier = ProtocolLayerIdentifier {
                .kind = ProtocolLayerIdentifierKind::vlan_vid,
                .value = 100U,
            }}},
        });
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::path_prefix,
            .layers = {
                {.kind = ProtocolLayerKind::ethernet_ii},
                {.kind = ProtocolLayerKind::ipv4},
                {.kind = ProtocolLayerKind::udp},
                {.kind = ProtocolLayerKind::geneve, .identifier = ProtocolLayerIdentifier {
                    .kind = ProtocolLayerIdentifierKind::geneve_vni,
                    .value = 100U,
                }},
            },
        });
        spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::exact_path,
            .layers = {
                {.kind = ProtocolLayerKind::ethernet_ii},
                {.kind = ProtocolLayerKind::ipv4},
                {.kind = ProtocolLayerKind::udp},
                {.kind = ProtocolLayerKind::gtpu, .identifier = ProtocolLayerIdentifier {
                    .kind = ProtocolLayerIdentifierKind::gtpu_teid,
                    .value = 0x01020304U,
                }},
                {.kind = ProtocolLayerKind::ipv4},
                {.kind = ProtocolLayerKind::tcp},
            },
        });
        spec.flow_protocol.include = {ProtocolId::tcp, ProtocolId::udp};
        spec.detected_protocol.include = {FlowProtocolHint::tls, FlowProtocolHint::quic};
        spec.tls_version.include = {TlsVersionHint::tls13};
        spec.quic_version.exclude = {QuicVersionHint::draft29};
        spec.ports.include = {
            {.scope = AdvancedFlowFilterPortScope::either_endpoint, .range = {.first = 443U, .last = 443U}},
            {.scope = AdvancedFlowFilterPortScope::endpoint_a, .range = {.first = 41000U, .last = 41000U}},
        };
        spec.aggregate.packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 1U, .max = 1000U};
        spec.aggregate.original_bytes = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 1536U, .max = 1048576U};
        spec.aggregate.captured_bytes = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 1024U, .max = 2147483648ULL};
        spec.aggregate.duration_us = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 1000U, .max = 1000000U};
        spec.aggregate.fragmented_packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 0U, .max = 10U};
        spec.aggregate.truncated_packet_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 0U, .max = 10U};
        spec.aggregate.tcp_syn_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 0U, .max = 10U};
        spec.aggregate.tcp_fin_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 0U, .max = 10U};
        spec.aggregate.tcp_rst_count = AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 0U, .max = 10U};
        spec.aggregate.max_original_packet_length = AdvancedFlowFilterInclusiveRange<std::uint32_t> {.min = 1500U, .max = 9000U};
        spec.aggregate.max_captured_packet_length = AdvancedFlowFilterInclusiveRange<std::uint32_t> {.min = 1024U, .max = 4096U};
        spec.directionality.include = {AdvancedFlowFilterDirectionality::bidirectional};
        spec.addresses.ipv4_include = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::cidr,
                .scope = AdvancedFlowFilterEndpointScope::either_endpoint,
                .value = ipv4(10, 0, 0, 0),
                .prefix_length = 24U,
            },
        };
        spec.addresses.ipv6_exclude = {
            {
                .match_kind = session_detail::AdvancedFlowFilterAddressMatchKind::exact,
                .scope = AdvancedFlowFilterEndpointScope::endpoint_b,
                .value = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32}),
                .prefix_length = 128U,
            },
        };
        spec.service.include = {
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "example",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
            {
                .kind = AdvancedFlowFilterServicePredicateKind::starts_with,
                .value = "Alpha",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::case_sensitive,
            },
        };

        const auto first_text = require_format_success(document);
        const auto reparsed = require_parse_success(first_text);
        const auto second_text = require_format_success(reparsed.document);
        PFL_EXPECT(first_text == second_text);
        PFL_EXPECT(first_text.find("format_version = 2\n") == 0U);
        PFL_EXPECT(first_text.find("protocol_path.prefix.include = EthernetII > IPv4 > UDP > Geneve(vni=100)\n") != std::string::npos);
        PFL_EXPECT(first_text.find("protocol_path.exact.include = EthernetII > IPv4 > UDP > GTP-U(teid=0x01020304) > IPv4 > TCP\n") != std::string::npos);
        PFL_EXPECT(first_text.find("address_family.include = ipv4\n") != std::string::npos);
        PFL_EXPECT(first_text.find("flow_protocol.include = tcp\nflow_protocol.include = udp\n") != std::string::npos);
        PFL_EXPECT(reparsed.document == document);
    }

    {
        session_detail::AdvancedFlowFilterDocument document {};
        document.configured_spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
            .layers = {{
                .kind = ProtocolLayerKind::vlan,
                .identifier = ProtocolLayerIdentifier {
                    .kind = ProtocolLayerIdentifierKind::esp_spi,
                    .value = 1U,
                },
            }},
        });

        const auto formatted = session_detail::format_advanced_flow_filter_text(document);
        PFL_EXPECT(formatted.status == AdvancedFlowFilterTextFormatStatus::unrepresentable_spec);
        PFL_REQUIRE(formatted.issue.has_value());
        PFL_EXPECT(formatted.issue->category == "protocol_path");
    }

    {
        session_detail::AdvancedFlowFilterDocument document {};
        document.configured_spec.detected_protocol.include = {FlowProtocolHint::possible_tls};

        const auto formatted = session_detail::format_advanced_flow_filter_text(document);
        PFL_EXPECT(formatted.status == AdvancedFlowFilterTextFormatStatus::unrepresentable_spec);
        PFL_REQUIRE(formatted.issue.has_value());
        PFL_EXPECT(formatted.issue->category == "detected_protocol");
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.ports.include = {{
            .scope = AdvancedFlowFilterPortScope::either_endpoint,
            .range = {.first = 9000U, .last = 8000U},
        }};

        const auto formatted = session_detail::format_advanced_flow_filter_text(make_default_document(spec));
        PFL_EXPECT(formatted.status == AdvancedFlowFilterTextFormatStatus::unrepresentable_spec);
        PFL_REQUIRE(formatted.issue.has_value());
        PFL_EXPECT(formatted.issue->category == "ports");
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.ports.exclude = {{
            .scope = AdvancedFlowFilterPortScope::either_endpoint,
            .range = {.first = 9000U, .last = 8000U},
        }};

        const auto formatted = session_detail::format_advanced_flow_filter_text(make_default_document(spec));
        PFL_EXPECT(formatted.status == AdvancedFlowFilterTextFormatStatus::unrepresentable_spec);
        PFL_REQUIRE(formatted.issue.has_value());
        PFL_EXPECT(formatted.issue->category == "ports");
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.ports.include = {{
            .scope = AdvancedFlowFilterPortScope::endpoint_a,
            .range = {.first = 443U, .last = 443U},
        }};
        expect_round_trip_stable(spec);
    }

    {
        AdvancedFlowFilterSpec spec {};
        spec.ports.exclude = {{
            .scope = AdvancedFlowFilterPortScope::endpoint_b,
            .range = {.first = 8000U, .last = 9000U},
        }};
        expect_round_trip_stable(spec);
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "section.ports.enabled = false\n"
            "port.either.include = 443\n"
            "port.either.include = 8443\n"
        );
        PFL_EXPECT(parsed.document.section_states.ports == false);
        PFL_REQUIRE(parsed.document.configured_spec.ports.include.size() == 2U);
        PFL_EXPECT(parsed.document.configured_spec.ports.include[0].range.first == 443U);
        PFL_EXPECT(parsed.document.configured_spec.ports.include[1].range.first == 8443U);
        PFL_EXPECT(
            require_format_success(parsed.document) ==
            std::string(
                "format_version = 2\n"
                "section.ports.enabled = false\n"
                "port.either.include = 443\n"
                "port.either.include = 8443\n"
            )
        );
        const auto effective = session_detail::make_effective_advanced_flow_filter_spec(parsed.document);
        PFL_EXPECT(effective.ports == session_detail::AdvancedFlowFilterPortCriteria {});
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "section.protocol_path.enabled = false\n"
            "protocol_path.prefix.include = EthernetII > IPv4\n"
            "protocol_path.contains.include = VXLAN(vni=100)\n"
        );
        PFL_EXPECT(parsed.document.section_states.protocol_path == false);
        PFL_EXPECT(parsed.document.section_states.contains_layer == true);
        PFL_REQUIRE(parsed.document.configured_spec.protocol_path.include.size() == 2U);
        PFL_EXPECT(parsed.document.configured_spec.protocol_path.include[0].match_kind == AdvancedFlowFilterProtocolPathMatchKind::path_prefix);
        PFL_EXPECT(parsed.document.configured_spec.protocol_path.include[1].match_kind == AdvancedFlowFilterProtocolPathMatchKind::contains_layer);
        PFL_EXPECT(parsed.document == require_parse_success(require_format_success(parsed.document)).document);
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "section.contains_layer.enabled = false\n"
            "protocol_path.exact.include = EthernetII > IPv4 > TCP\n"
            "protocol_path.contains.exclude = GTP-U(teid=0x12345678)\n"
        );
        PFL_EXPECT(parsed.document.section_states.protocol_path == true);
        PFL_EXPECT(parsed.document.section_states.contains_layer == false);
        PFL_REQUIRE(parsed.document.configured_spec.protocol_path.include.size() == 1U);
        PFL_REQUIRE(parsed.document.configured_spec.protocol_path.exclude.size() == 1U);
        PFL_EXPECT(parsed.document == require_parse_success(require_format_success(parsed.document)).document);
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "section.traffic.enabled = false\n"
            "packet_count.min = 10\n"
            "packet_count.max = 20\n"
            "captured_bytes.min = 1KiB\n"
            "duration.max = 5s\n"
        );
        PFL_EXPECT(parsed.document.section_states.traffic == false);
        PFL_REQUIRE(parsed.document.configured_spec.aggregate.packet_count.has_value());
        PFL_EXPECT(parsed.document.configured_spec.aggregate.packet_count->min == 10U);
        PFL_EXPECT(parsed.document.configured_spec.aggregate.packet_count->max == 20U);
        PFL_REQUIRE(parsed.document.configured_spec.aggregate.captured_bytes.has_value());
        PFL_EXPECT(parsed.document.configured_spec.aggregate.captured_bytes->min == 1024U);
        PFL_REQUIRE(parsed.document.configured_spec.aggregate.duration_us.has_value());
        PFL_EXPECT(parsed.document.configured_spec.aggregate.duration_us->max == 5000000U);
        PFL_EXPECT(parsed.document == require_parse_success(require_format_success(parsed.document)).document);
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "section.ip_addresses.enabled = false\n"
            "section.service.enabled = false\n"
            "ip.either.include = 10.0.0.0/8\n"
            "service.contains.ci.include = \"example\"\n"
            "flow_protocol.include = tcp\n"
        );
        PFL_EXPECT(parsed.document.section_states.ip_addresses == false);
        PFL_EXPECT(parsed.document.section_states.service == false);
        PFL_REQUIRE(parsed.document.configured_spec.addresses.ipv4_include.size() == 1U);
        PFL_REQUIRE(parsed.document.configured_spec.service.include.size() == 1U);
        const auto formatted = require_format_success(parsed.document);
        PFL_EXPECT(formatted.find(
            "section.ip_addresses.enabled = false\n"
            "section.service.enabled = false\n"
        ) != std::string::npos);
        PFL_EXPECT(parsed.document == require_parse_success(formatted).document);
    }

    {
        const auto parsed = require_parse_success(
            "format_version = 2\n"
            "section.address_family.enabled = false\n"
            "address_family.include = ipv6\n"
        );
        PFL_EXPECT(parsed.document.section_states.address_family == false);
        PFL_EXPECT(parsed.document.configured_spec.address_family.include == std::vector<FlowAddressFamily> {FlowAddressFamily::ipv6});
        const auto effective = session_detail::make_effective_advanced_flow_filter_spec(parsed.document);
        PFL_EXPECT(effective.address_family == session_detail::AdvancedFlowFilterAddressFamilyCriteria {});
        PFL_EXPECT(parsed.document == require_parse_success(require_format_success(parsed.document)).document);
    }

    {
        session_detail::AdvancedFlowFilterDocument document {};
        document.section_states.service = false;
        document.section_states.ports = false;
        document.section_states.address_family = false;
        document.configured_spec.service.include = {
            {
                .kind = AdvancedFlowFilterServicePredicateKind::contains,
                .value = "example",
                .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
            },
        };
        document.configured_spec.ports.include = {
            {.scope = AdvancedFlowFilterPortScope::either_endpoint, .range = {.first = 443U, .last = 443U}},
        };
        document.configured_spec.address_family.include = {FlowAddressFamily::ipv4};
        const auto text = require_format_success(document);
        PFL_EXPECT(
            text.find(
                "section.address_family.enabled = false\n"
                "section.ports.enabled = false\n"
                "section.service.enabled = false\n"
            ) == std::string("format_version = 2\n").size()
        );
        PFL_EXPECT(document == require_parse_success(text).document);
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
    run_address_family_tests();
    run_address_and_version_tests();
    run_document_model_tests();
    run_index_roundtrip_tests();
    run_text_format_tests();
    run_metadata_only_evaluation_tests();
}

}  // namespace pfl::tests
