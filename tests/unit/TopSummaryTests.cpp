#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <utility>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/SessionFlowHelpers.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

struct AggregateCounts {
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

CaptureTopSummary build_reference_top_summary(const CaptureSession& session, const std::size_t limit) {
    const auto connections = session_detail::list_connections(session.state());
    std::map<std::string, AggregateCounts> endpoint_rows {};
    std::map<std::uint16_t, AggregateCounts> port_rows {};
    std::vector<TopFlowRow> top_flows {};
    top_flows.reserve(connections.size());

    for (std::size_t index = 0; index < connections.size(); ++index) {
        const auto row = session_detail::make_flow_row(index, connections[index], AnalysisSettings {});
        PFL_REQUIRE(row.has_value());

        auto observe_endpoint = [&](const std::string& endpoint) {
            auto& aggregate = endpoint_rows[endpoint];
            ++aggregate.flow_count;
            aggregate.packet_count += row->packet_count;
            aggregate.total_bytes += row->total_bytes;
        };
        observe_endpoint(row->endpoint_a);
        if (row->endpoint_b != row->endpoint_a) {
            observe_endpoint(row->endpoint_b);
        }

        auto observe_port = [&](const std::uint16_t port) {
            if (port == 0U) {
                return;
            }
            auto& aggregate = port_rows[port];
            ++aggregate.flow_count;
            aggregate.packet_count += row->packet_count;
            aggregate.total_bytes += row->total_bytes;
        };
        observe_port(row->port_a);
        if (row->port_b != row->port_a) {
            observe_port(row->port_b);
        }

        top_flows.push_back(TopFlowRow {
            .flow_index = index,
            .family = row->family,
            .protocol = connections[index].family == FlowAddressFamily::ipv4
                ? connections[index].ipv4->key.protocol
                : connections[index].ipv6->key.protocol,
            .protocol_path_id = row->protocol_path_id,
            .protocol_hint = connections[index].family == FlowAddressFamily::ipv4
                ? connections[index].ipv4->protocol_hint
                : connections[index].ipv6->protocol_hint,
            .service_hint = row->service_hint,
            .packet_count = row->packet_count,
            .captured_bytes = session_detail::captured_bytes(connections[index]),
            .total_bytes = row->total_bytes,
        });
    }

    std::vector<TopEndpointRow> top_endpoints {};
    top_endpoints.reserve(endpoint_rows.size());
    for (const auto& [endpoint, aggregate] : endpoint_rows) {
        top_endpoints.push_back(TopEndpointRow {
            .endpoint = endpoint,
            .flow_count = aggregate.flow_count,
            .packet_count = aggregate.packet_count,
            .total_bytes = aggregate.total_bytes,
        });
    }
    std::sort(top_endpoints.begin(), top_endpoints.end(), [](const TopEndpointRow& left, const TopEndpointRow& right) {
        if (left.total_bytes != right.total_bytes) {
            return left.total_bytes > right.total_bytes;
        }
        if (left.packet_count != right.packet_count) {
            return left.packet_count > right.packet_count;
        }
        return left.endpoint < right.endpoint;
    });
    if (top_endpoints.size() > limit) {
        top_endpoints.resize(limit);
    }

    std::vector<TopPortRow> top_ports {};
    top_ports.reserve(port_rows.size());
    for (const auto& [port, aggregate] : port_rows) {
        top_ports.push_back(TopPortRow {
            .port = port,
            .flow_count = aggregate.flow_count,
            .packet_count = aggregate.packet_count,
            .total_bytes = aggregate.total_bytes,
        });
    }
    std::sort(top_ports.begin(), top_ports.end(), [](const TopPortRow& left, const TopPortRow& right) {
        if (left.total_bytes != right.total_bytes) {
            return left.total_bytes > right.total_bytes;
        }
        if (left.packet_count != right.packet_count) {
            return left.packet_count > right.packet_count;
        }
        return left.port < right.port;
    });
    if (top_ports.size() > limit) {
        top_ports.resize(limit);
    }

    std::sort(top_flows.begin(), top_flows.end(), [](const TopFlowRow& left, const TopFlowRow& right) {
        if (left.total_bytes != right.total_bytes) {
            return left.total_bytes > right.total_bytes;
        }
        if (left.packet_count != right.packet_count) {
            return left.packet_count > right.packet_count;
        }
        return left.flow_index < right.flow_index;
    });
    if (top_flows.size() > 10U) {
        top_flows.resize(10U);
    }

    return CaptureTopSummary {
        .endpoints_by_bytes = std::move(top_endpoints),
        .ports_by_bytes = std::move(top_ports),
        .flows_by_original_bytes = std::move(top_flows),
    };
}

void expect_top_summary_equal(const CaptureTopSummary& left, const CaptureTopSummary& right) {
    PFL_EXPECT(left.endpoints_by_bytes.size() == right.endpoints_by_bytes.size());
    PFL_EXPECT(left.ports_by_bytes.size() == right.ports_by_bytes.size());
    PFL_EXPECT(left.flows_by_original_bytes.size() == right.flows_by_original_bytes.size());

    for (std::size_t index = 0; index < left.endpoints_by_bytes.size(); ++index) {
        PFL_EXPECT(left.endpoints_by_bytes[index].endpoint == right.endpoints_by_bytes[index].endpoint);
        PFL_EXPECT(left.endpoints_by_bytes[index].flow_count == right.endpoints_by_bytes[index].flow_count);
        PFL_EXPECT(left.endpoints_by_bytes[index].packet_count == right.endpoints_by_bytes[index].packet_count);
        PFL_EXPECT(left.endpoints_by_bytes[index].total_bytes == right.endpoints_by_bytes[index].total_bytes);
    }

    for (std::size_t index = 0; index < left.ports_by_bytes.size(); ++index) {
        PFL_EXPECT(left.ports_by_bytes[index].port == right.ports_by_bytes[index].port);
        PFL_EXPECT(left.ports_by_bytes[index].flow_count == right.ports_by_bytes[index].flow_count);
        PFL_EXPECT(left.ports_by_bytes[index].packet_count == right.ports_by_bytes[index].packet_count);
        PFL_EXPECT(left.ports_by_bytes[index].total_bytes == right.ports_by_bytes[index].total_bytes);
    }

    for (std::size_t index = 0; index < left.flows_by_original_bytes.size(); ++index) {
        PFL_EXPECT(left.flows_by_original_bytes[index].flow_index == right.flows_by_original_bytes[index].flow_index);
        PFL_EXPECT(left.flows_by_original_bytes[index].family == right.flows_by_original_bytes[index].family);
        PFL_EXPECT(left.flows_by_original_bytes[index].protocol == right.flows_by_original_bytes[index].protocol);
        PFL_EXPECT(left.flows_by_original_bytes[index].protocol_hint == right.flows_by_original_bytes[index].protocol_hint);
        PFL_EXPECT(left.flows_by_original_bytes[index].service_hint == right.flows_by_original_bytes[index].service_hint);
        PFL_EXPECT(left.flows_by_original_bytes[index].protocol_path_id == right.flows_by_original_bytes[index].protocol_path_id);
        PFL_EXPECT(left.flows_by_original_bytes[index].packet_count == right.flows_by_original_bytes[index].packet_count);
        PFL_EXPECT(left.flows_by_original_bytes[index].captured_bytes == right.flows_by_original_bytes[index].captured_bytes);
        PFL_EXPECT(left.flows_by_original_bytes[index].total_bytes == right.flows_by_original_bytes[index].total_bytes);
    }
}

void expect_top_summary_prefix_equal(
    const CaptureTopSummary& expected_prefix,
    const CaptureTopSummary& actual,
    const std::size_t prefix_length
) {
    PFL_EXPECT(expected_prefix.endpoints_by_bytes.size() >= prefix_length);
    PFL_EXPECT(expected_prefix.ports_by_bytes.size() >= prefix_length);
    PFL_EXPECT(actual.endpoints_by_bytes.size() >= prefix_length);
    PFL_EXPECT(actual.ports_by_bytes.size() >= prefix_length);
    PFL_EXPECT(expected_prefix.flows_by_original_bytes.size() == actual.flows_by_original_bytes.size());
    for (std::size_t index = 0; index < expected_prefix.flows_by_original_bytes.size(); ++index) {
        PFL_EXPECT(expected_prefix.flows_by_original_bytes[index].flow_index == actual.flows_by_original_bytes[index].flow_index);
        PFL_EXPECT(expected_prefix.flows_by_original_bytes[index].family == actual.flows_by_original_bytes[index].family);
        PFL_EXPECT(expected_prefix.flows_by_original_bytes[index].protocol == actual.flows_by_original_bytes[index].protocol);
        PFL_EXPECT(expected_prefix.flows_by_original_bytes[index].protocol_hint == actual.flows_by_original_bytes[index].protocol_hint);
        PFL_EXPECT(expected_prefix.flows_by_original_bytes[index].service_hint == actual.flows_by_original_bytes[index].service_hint);
        PFL_EXPECT(expected_prefix.flows_by_original_bytes[index].protocol_path_id == actual.flows_by_original_bytes[index].protocol_path_id);
        PFL_EXPECT(expected_prefix.flows_by_original_bytes[index].packet_count == actual.flows_by_original_bytes[index].packet_count);
        PFL_EXPECT(expected_prefix.flows_by_original_bytes[index].captured_bytes == actual.flows_by_original_bytes[index].captured_bytes);
        PFL_EXPECT(expected_prefix.flows_by_original_bytes[index].total_bytes == actual.flows_by_original_bytes[index].total_bytes);
    }

    for (std::size_t index = 0; index < prefix_length; ++index) {
        PFL_EXPECT(expected_prefix.endpoints_by_bytes[index].endpoint == actual.endpoints_by_bytes[index].endpoint);
        PFL_EXPECT(expected_prefix.endpoints_by_bytes[index].flow_count == actual.endpoints_by_bytes[index].flow_count);
        PFL_EXPECT(expected_prefix.endpoints_by_bytes[index].packet_count == actual.endpoints_by_bytes[index].packet_count);
        PFL_EXPECT(expected_prefix.endpoints_by_bytes[index].total_bytes == actual.endpoints_by_bytes[index].total_bytes);
        PFL_EXPECT(expected_prefix.ports_by_bytes[index].port == actual.ports_by_bytes[index].port);
        PFL_EXPECT(expected_prefix.ports_by_bytes[index].flow_count == actual.ports_by_bytes[index].flow_count);
        PFL_EXPECT(expected_prefix.ports_by_bytes[index].packet_count == actual.ports_by_bytes[index].packet_count);
        PFL_EXPECT(expected_prefix.ports_by_bytes[index].total_bytes == actual.ports_by_bytes[index].total_bytes);
    }
}

}  // namespace

void run_top_summary_tests() {
    const auto tcp_ab = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80);
    const auto tcp_ba = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 80, 1111);
    const auto udp_ac = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 3), 1111, 22);
    const auto udp_de = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 4), ipv4(10, 0, 0, 5), 53000, 53);

    const auto capture_path = write_temp_pcap(
        "pfl_top_summary.pcap",
        make_classic_pcap({
            {100, tcp_ab},
            {200, tcp_ba},
            {300, udp_ac},
            {400, udp_de},
        })
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(capture_path));

    const auto summary = session.top_summary();
    PFL_EXPECT(summary.endpoints_by_bytes.size() == 5);
    PFL_EXPECT(summary.ports_by_bytes.size() == 5);

    PFL_EXPECT(summary.endpoints_by_bytes[0].endpoint == "10.0.0.1:1111");
    PFL_EXPECT(summary.endpoints_by_bytes[0].flow_count == 2);
    PFL_EXPECT(summary.endpoints_by_bytes[0].packet_count == 3);
    PFL_EXPECT(summary.endpoints_by_bytes[0].total_bytes == tcp_ab.size() + tcp_ba.size() + udp_ac.size());

    PFL_EXPECT(summary.endpoints_by_bytes[1].endpoint == "10.0.0.2:80");
    PFL_EXPECT(summary.endpoints_by_bytes[1].flow_count == 1);
    PFL_EXPECT(summary.endpoints_by_bytes[1].packet_count == 2);
    PFL_EXPECT(summary.endpoints_by_bytes[1].total_bytes == tcp_ab.size() + tcp_ba.size());

    PFL_EXPECT(summary.ports_by_bytes[0].port == 1111);
    PFL_EXPECT(summary.ports_by_bytes[0].flow_count == 2);
    PFL_EXPECT(summary.ports_by_bytes[0].packet_count == 3);
    PFL_EXPECT(summary.ports_by_bytes[0].total_bytes == tcp_ab.size() + tcp_ba.size() + udp_ac.size());

    PFL_EXPECT(summary.ports_by_bytes[1].port == 80);
    PFL_EXPECT(summary.ports_by_bytes[1].flow_count == 1);
    PFL_EXPECT(summary.ports_by_bytes[1].packet_count == 2);
    PFL_EXPECT(summary.ports_by_bytes[1].total_bytes == tcp_ab.size() + tcp_ba.size());
    PFL_EXPECT(summary.flows_by_original_bytes.size() == 3U);
    PFL_EXPECT(summary.flows_by_original_bytes[0].flow_index == 0U);
    PFL_EXPECT(summary.flows_by_original_bytes[0].packet_count == 2U);

    const auto limited = session.top_summary(2);
    PFL_EXPECT(limited.endpoints_by_bytes.size() == 2);
    PFL_EXPECT(limited.ports_by_bytes.size() == 2);
    PFL_EXPECT(limited.flows_by_original_bytes.size() == summary.flows_by_original_bytes.size());
    PFL_EXPECT(limited.endpoints_by_bytes[0].endpoint == summary.endpoints_by_bytes[0].endpoint);
    PFL_EXPECT(limited.ports_by_bytes[0].port == summary.ports_by_bytes[0].port);

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_top_summary.idx";
    std::filesystem::remove(index_path);
    PFL_EXPECT(session.save_index(index_path));

    CaptureSession loaded_session {};
    PFL_EXPECT(loaded_session.load_index(index_path));
    expect_top_summary_equal(summary, loaded_session.top_summary());

    const auto reference_summary = build_reference_top_summary(session, 5U);
    expect_top_summary_equal(reference_summary, summary);

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> top_many_packets {};
    top_many_packets.reserve(25U);
    for (std::uint8_t index = 0U; index < 25U; ++index) {
        top_many_packets.push_back({
            static_cast<std::uint32_t>(1000U + index),
            make_ethernet_ipv4_udp_packet(
                ipv4(10, 50, 0, static_cast<std::uint8_t>(index + 1U)),
                ipv4(10, 51, 0, static_cast<std::uint8_t>(index + 1U)),
                static_cast<std::uint16_t>(4000U + index),
                static_cast<std::uint16_t>(5000U + index)
            ),
        });
    }

    const auto many_capture_path = write_temp_pcap(
        "pfl_top_summary_large_limit.pcap",
        make_classic_pcap(top_many_packets)
    );
    CaptureSession many_session {};
    PFL_EXPECT(many_session.open_capture(many_capture_path));

    const auto top_five = many_session.top_summary();
    const auto top_twenty = many_session.top_summary(20U);
    const auto top_twenty_five = many_session.top_summary(25U);
    PFL_EXPECT(top_five.endpoints_by_bytes.size() == 5U);
    PFL_EXPECT(top_five.ports_by_bytes.size() == 5U);
    PFL_EXPECT(top_five.flows_by_original_bytes.size() == 10U);
    PFL_EXPECT(top_five.flows_by_original_bytes.front().flow_index == 0U);
    PFL_EXPECT(top_five.flows_by_original_bytes.back().flow_index == 9U);
    PFL_EXPECT(top_twenty.endpoints_by_bytes.size() == 20U);
    PFL_EXPECT(top_twenty.ports_by_bytes.size() == 20U);
    PFL_EXPECT(top_twenty.flows_by_original_bytes.size() == 10U);
    PFL_EXPECT(top_twenty_five.endpoints_by_bytes.size() == 25U);
    PFL_EXPECT(top_twenty_five.ports_by_bytes.size() == 25U);
    PFL_EXPECT(top_twenty_five.flows_by_original_bytes.size() == 10U);
    expect_top_summary_prefix_equal(top_twenty, top_twenty_five, 20U);
    expect_top_summary_prefix_equal(top_five, top_twenty, 5U);

    const auto same_port_capture_path = write_temp_pcap(
        "pfl_top_summary_same_port_once.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_udp_packet(ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 4500, 4500)},
        })
    );
    CaptureSession same_port_session {};
    PFL_EXPECT(same_port_session.open_capture(same_port_capture_path));
    const auto same_port_summary = same_port_session.top_summary();
    PFL_REQUIRE(!same_port_summary.ports_by_bytes.empty());
    PFL_EXPECT(same_port_summary.ports_by_bytes[0].port == 4500U);
    PFL_EXPECT(same_port_summary.ports_by_bytes[0].flow_count == 1U);
    PFL_EXPECT(same_port_summary.ports_by_bytes[0].packet_count == 1U);
    PFL_EXPECT(same_port_summary.ports_by_bytes[0].total_bytes > 0U);

    const auto exact_reference_capture_path = write_temp_pcap(
        "pfl_top_summary_exact_reference.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_udp_packet(ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 51001, 443)},
            {110, make_ethernet_ipv4_udp_packet(ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 51001, 443)},
            {120, make_ethernet_ipv4_udp_packet(ipv4(10, 1, 0, 3), ipv4(10, 1, 0, 4), 4500, 4500)},
            {130, make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 5), ipv4(10, 1, 0, 6), 52001, 80)},
            {140, make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 5), ipv4(10, 1, 0, 6), 52001, 80)},
            {150, make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 5), ipv4(10, 1, 0, 6), 52001, 80)},
            {160, make_ethernet_ipv4_udp_packet(ipv4(10, 1, 0, 7), ipv4(10, 1, 0, 8), 0, 53)},
            {170, make_ethernet_ipv4_udp_packet(ipv4(10, 1, 0, 7), ipv4(10, 1, 0, 8), 0, 53)},
            {180, make_ethernet_ipv4_udp_packet(ipv4(10, 1, 0, 9), ipv4(10, 1, 0, 1), 53001, 443)},
        })
    );
    CaptureSession exact_reference_session {};
    PFL_EXPECT(exact_reference_session.open_capture(exact_reference_capture_path));
    expect_top_summary_equal(
        build_reference_top_summary(exact_reference_session, 5U),
        exact_reference_session.top_summary(5U)
    );
    expect_top_summary_equal(
        build_reference_top_summary(exact_reference_session, 20U),
        exact_reference_session.top_summary(20U)
    );

    const auto ranking_truncated_packet = make_ethernet_ipv4_udp_packet(
        ipv4(10, 2, 0, 1),
        ipv4(10, 2, 0, 2),
        54001,
        53
    );
    const auto ranking_tcp_packet = make_ethernet_ipv4_tcp_packet(
        ipv4(10, 2, 0, 3),
        ipv4(10, 2, 0, 4),
        55001,
        80
    );
    const auto tie_udp_packet = make_ethernet_ipv4_udp_packet(
        ipv4(10, 2, 0, 5),
        ipv4(10, 2, 0, 6),
        56001,
        443
    );
    const auto tie_ipv6_packet = make_ethernet_ipv6_udp_with_hop_by_hop_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}),
        57001,
        443
    );
    const auto top_flow_ranking_capture_path = write_temp_pcap(
        "pfl_top_summary_top_flows_ranking.pcap",
        make_classic_pcap_with_captured_lengths({
            {100U, ranking_truncated_packet, 100U},
            {110U, ranking_truncated_packet, 100U},
            {120U, ranking_tcp_packet, static_cast<std::uint32_t>(ranking_tcp_packet.size())},
            {130U, ranking_tcp_packet, static_cast<std::uint32_t>(ranking_tcp_packet.size())},
            {140U, ranking_tcp_packet, static_cast<std::uint32_t>(ranking_tcp_packet.size())},
            {150U, tie_udp_packet, static_cast<std::uint32_t>(tie_udp_packet.size())},
            {160U, tie_udp_packet, static_cast<std::uint32_t>(tie_udp_packet.size())},
            {170U, tie_udp_packet, static_cast<std::uint32_t>(tie_udp_packet.size())},
            {180U, tie_udp_packet, static_cast<std::uint32_t>(tie_udp_packet.size())},
            {190U, tie_udp_packet, static_cast<std::uint32_t>(tie_udp_packet.size())},
            {200U, tie_ipv6_packet, static_cast<std::uint32_t>(tie_ipv6_packet.size())},
            {210U, tie_ipv6_packet, static_cast<std::uint32_t>(tie_ipv6_packet.size())},
            {220U, tie_ipv6_packet, static_cast<std::uint32_t>(tie_ipv6_packet.size())},
        })
    );
    CaptureSession top_flow_ranking_session {};
    PFL_EXPECT(top_flow_ranking_session.open_capture(top_flow_ranking_capture_path));
    const auto top_flow_ranking_summary = top_flow_ranking_session.top_summary(5U);
    PFL_REQUIRE(top_flow_ranking_summary.flows_by_original_bytes.size() >= 4U);
    PFL_EXPECT(top_flow_ranking_summary.flows_by_original_bytes[0].flow_index == 2U);
    PFL_EXPECT(top_flow_ranking_summary.flows_by_original_bytes[0].total_bytes == 210U);
    PFL_EXPECT(top_flow_ranking_summary.flows_by_original_bytes[0].packet_count == 5U);
    PFL_EXPECT(top_flow_ranking_summary.flows_by_original_bytes[1].flow_index == 3U);
    PFL_EXPECT(top_flow_ranking_summary.flows_by_original_bytes[1].total_bytes == 210U);
    PFL_EXPECT(top_flow_ranking_summary.flows_by_original_bytes[1].packet_count == 3U);
    PFL_EXPECT(top_flow_ranking_summary.flows_by_original_bytes[2].flow_index == 0U);
    PFL_EXPECT(top_flow_ranking_summary.flows_by_original_bytes[2].total_bytes == 200U);
    PFL_EXPECT(top_flow_ranking_summary.flows_by_original_bytes[2].captured_bytes
        < top_flow_ranking_summary.flows_by_original_bytes[3].captured_bytes);
    PFL_EXPECT(top_flow_ranking_summary.flows_by_original_bytes[2].total_bytes
        > top_flow_ranking_summary.flows_by_original_bytes[3].total_bytes);
}

}  // namespace pfl::tests
