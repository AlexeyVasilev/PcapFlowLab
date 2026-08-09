#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/CaptureSession.h"
#include "core/domain/Connection.h"
#include "core/io/PcapReader.h"
#include "core/io/PcapWriter.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

std::vector<RawPcapPacket> read_all_packets(const std::filesystem::path& path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(path));

    std::vector<RawPcapPacket> packets {};
    while (const auto packet = reader.read_next()) {
        packets.push_back(*packet);
    }

    return packets;
}

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

RawPcapPacket read_first_packet(const std::filesystem::path& path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(path));
    const auto packet = reader.read_next();
    PFL_REQUIRE(packet.has_value());
    return *packet;
}

std::vector<std::filesystem::path> list_exported_pcaps(const std::filesystem::path& directory) {
    std::vector<std::filesystem::path> paths {};
    if (!std::filesystem::exists(directory)) {
        return paths;
    }

    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file() && entry.path().extension() == ".pcap") {
            paths.push_back(entry.path());
        }
    }
    return paths;
}

std::vector<std::string> read_text_file_lines(const std::filesystem::path& path) {
    std::ifstream stream {path, std::ios::binary};
    PFL_EXPECT(stream.is_open());

    std::vector<std::string> lines {};
    std::string line {};
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream stream {path, std::ios::binary};
    PFL_EXPECT(stream.is_open());
    return {
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>()
    };
}

std::vector<std::string> split_csv_line(const std::string& line) {
    std::vector<std::string> fields {};
    std::string field {};
    bool in_quotes = false;

    for (std::size_t index = 0; index < line.size(); ++index) {
        const char ch = line[index];
        if (in_quotes) {
            if (ch == '"') {
                if (index + 1U < line.size() && line[index + 1U] == '"') {
                    field.push_back('"');
                    ++index;
                } else {
                    in_quotes = false;
                }
            } else {
                field.push_back(ch);
            }
            continue;
        }

        if (ch == '"') {
            in_quotes = true;
            continue;
        }

        if (ch == ',') {
            fields.push_back(field);
            field.clear();
            continue;
        }

        field.push_back(ch);
    }

    fields.push_back(field);
    return fields;
}

std::vector<std::vector<std::string>> parse_csv_file(const std::filesystem::path& path) {
    std::ifstream stream {path, std::ios::binary};
    PFL_EXPECT(stream.is_open());

    const std::string text {
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>()
    };

    std::vector<std::vector<std::string>> rows {};
    std::vector<std::string> current_row {};
    std::string current_field {};
    bool in_quotes = false;

    for (std::size_t index = 0U; index < text.size(); ++index) {
        const char ch = text[index];
        if (in_quotes) {
            if (ch == '"') {
                if (index + 1U < text.size() && text[index + 1U] == '"') {
                    current_field.push_back('"');
                    ++index;
                } else {
                    in_quotes = false;
                }
            } else {
                current_field.push_back(ch);
            }
            continue;
        }

        if (ch == '"') {
            in_quotes = true;
            continue;
        }

        if (ch == ',') {
            current_row.push_back(current_field);
            current_field.clear();
            continue;
        }

        if (ch == '\r') {
            continue;
        }

        if (ch == '\n') {
            current_row.push_back(current_field);
            current_field.clear();
            rows.push_back(current_row);
            current_row.clear();
            continue;
        }

        current_field.push_back(ch);
    }

    if (!current_field.empty() || !current_row.empty()) {
        current_row.push_back(current_field);
        rows.push_back(current_row);
    }

    return rows;
}

std::optional<std::size_t> find_flow_index_by_service_hint(
    const std::vector<FlowRow>& rows,
    const std::string_view service_hint
) {
    for (const auto& row : rows) {
        if (row.service_hint == service_hint) {
            return row.index;
        }
    }

    return std::nullopt;
}

CaptureSession build_flow_info_export_session() {
    CaptureSession session {};
    auto& state = session.state();

    const auto vxlan_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::udp(), LayerKey::vxlan(100U), LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::tcp()}
    });
    const auto gtpu_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::udp(), LayerKey::gtpu(0x01020304U), LayerKey::ipv4(), LayerKey::tcp()}
    });

    const FlowKeyV4 alpha_flow {
        .src_addr = ipv4(192, 0, 2, 10),
        .dst_addr = ipv4(198, 51, 100, 20),
        .src_port = 41000,
        .dst_port = 80,
        .protocol = ProtocolId::tcp,
    };
    ConnectionV4 alpha_connection {};
    alpha_connection.key = make_connection_key(alpha_flow);
    alpha_connection.key.protocol_path_id = vxlan_path_id;
    alpha_connection.protocol_hint = FlowProtocolHint::http;
    alpha_connection.service_hint = "alpha,\"quoted\",example";
    alpha_connection.add_packet(
        alpha_flow,
        PacketRef {
            .packet_index = 0U,
            .captured_length = 120U,
            .original_length = 120U,
            .ts_sec = 1U,
            .ts_usec = 100U,
        }
    );
    alpha_connection.add_packet(
        alpha_flow,
        PacketRef {
            .packet_index = 1U,
            .captured_length = 120U,
            .original_length = 120U,
            .ts_sec = 1U,
            .ts_usec = 250U,
        }
    );
    state.ipv4_connections.get_or_create(alpha_connection.key) = alpha_connection;

    const FlowKeyV4 beta_flow {
        .src_addr = ipv4(203, 0, 113, 10),
        .dst_addr = ipv4(203, 0, 113, 20),
        .src_port = 53000,
        .dst_port = 443,
        .protocol = ProtocolId::tcp,
    };
    ConnectionV4 beta_connection {};
    beta_connection.key = make_connection_key(beta_flow);
    beta_connection.key.protocol_path_id = gtpu_path_id;
    beta_connection.protocol_hint = FlowProtocolHint::tls;
    beta_connection.service_hint = "beta.example";
    beta_connection.add_packet(
        beta_flow,
        PacketRef {
            .packet_index = 2U,
            .captured_length = 90U,
            .original_length = 90U,
            .ts_sec = 2U,
            .ts_usec = 100U,
        }
    );
    state.ipv4_connections.get_or_create(beta_connection.key) = beta_connection;

    return session;
}

CaptureSession build_flow_info_export_session_with_control_characters() {
    CaptureSession session {};
    auto& state = session.state();

    const auto protocol_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::tcp()}
    });

    const FlowKeyV4 flow {
        .src_addr = ipv4(198, 18, 0, 10),
        .dst_addr = ipv4(198, 18, 0, 20),
        .src_port = 45000,
        .dst_port = 80,
        .protocol = ProtocolId::tcp,
    };
    ConnectionV4 connection {};
    connection.key = make_connection_key(flow);
    connection.key.protocol_path_id = protocol_path_id;
    connection.protocol_hint = FlowProtocolHint::http;
    connection.service_hint = "tab\tcomma,value \"quoted\"\r\nnext line";
    connection.add_packet(
        flow,
        PacketRef {
            .packet_index = 0U,
            .captured_length = 96U,
            .original_length = 96U,
            .ts_sec = 5U,
            .ts_usec = 10U,
        }
    );
    connection.add_packet(
        flow,
        PacketRef {
            .packet_index = 1U,
            .captured_length = 96U,
            .original_length = 96U,
            .ts_sec = 5U,
            .ts_usec = 40U,
        }
    );
    state.ipv4_connections.get_or_create(connection.key) = connection;

    return session;
}

}  // namespace

void run_export_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);

    {
        const auto path = std::filesystem::temp_directory_path() / "pfl_writer_basic.pcap";
        PcapWriter writer {};
        PFL_EXPECT(writer.open(path));
        PFL_EXPECT(writer.is_open());

        const PacketRef first_packet {
            .packet_index = 0,
            .captured_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .original_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .ts_sec = 10,
            .ts_usec = 20,
        };
        const PacketRef second_packet {
            .packet_index = 1,
            .captured_length = static_cast<std::uint32_t>(udp_packet.size()),
            .original_length = static_cast<std::uint32_t>(udp_packet.size()),
            .ts_sec = 11,
            .ts_usec = 21,
        };

        PFL_EXPECT(writer.write_packet(first_packet, tcp_packet));
        PFL_EXPECT(writer.write_packet(second_packet, udp_packet));
        writer.close();

        const auto packets = read_all_packets(path);
        PFL_EXPECT(packets.size() == 2);
        PFL_EXPECT(packets[0].ts_sec == 10);
        PFL_EXPECT(packets[0].ts_usec == 20);
        PFL_EXPECT(packets[0].bytes == tcp_packet);
        PFL_EXPECT(packets[1].ts_sec == 11);
        PFL_EXPECT(packets[1].ts_usec == 21);
        PFL_EXPECT(packets[1].bytes == udp_packet);
    }

    {
        const auto forward_packet = make_ethernet_ipv4_tcp_packet(ipv4(192, 168, 0, 1), ipv4(192, 168, 0, 2), 12345, 443);
        const auto reverse_packet = make_ethernet_ipv4_tcp_packet(ipv4(192, 168, 0, 2), ipv4(192, 168, 0, 1), 443, 12345);
        const auto source_path = write_temp_pcap(
            "pfl_export_roundtrip_source.pcap",
            make_classic_pcap({{100, forward_packet}, {200, reverse_packet}, {300, forward_packet}, {400, reverse_packet}})
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_export_roundtrip_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(session.export_flow_to_pcap(0, output_path));

        CaptureSession exported_session {};
        PFL_EXPECT(exported_session.open_capture(output_path));
        PFL_EXPECT(exported_session.summary().packet_count == 4);
        PFL_EXPECT(exported_session.summary().flow_count == 1);
        PFL_EXPECT(exported_session.list_flows().size() == 1);

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 4);
        PFL_EXPECT(exported_packets[0].bytes == forward_packet);
        PFL_EXPECT(exported_packets[1].bytes == reverse_packet);
        PFL_EXPECT(exported_packets[2].bytes == forward_packet);
        PFL_EXPECT(exported_packets[3].bytes == reverse_packet);
        PFL_EXPECT(exported_packets[0].ts_usec == 100);
        PFL_EXPECT(exported_packets[1].ts_usec == 200);
        PFL_EXPECT(exported_packets[2].ts_usec == 300);
        PFL_EXPECT(exported_packets[3].ts_usec == 400);
    }

    {
        const auto forward_packet = make_ethernet_ipv4_tcp_packet(ipv4(192, 168, 1, 1), ipv4(192, 168, 1, 2), 22345, 443);
        const auto reverse_packet = make_ethernet_ipv4_tcp_packet(ipv4(192, 168, 1, 2), ipv4(192, 168, 1, 1), 443, 22345);
        const auto source_path = write_temp_pcap(
            "pfl_export_direct_initial_cancel_source.pcap",
            make_classic_pcap({{100, forward_packet}, {200, reverse_packet}})
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_export_direct_initial_cancel_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));

        std::atomic_bool cancel_requested {true};
        const SmartSingleFileExportOptions options {
            .cancel_requested = [&]() {
                return cancel_requested.load();
            },
        };

        PFL_EXPECT(!session.export_flows_to_pcap({0U}, output_path, options));
        if (std::filesystem::exists(output_path)) {
            PFL_EXPECT(read_all_packets(output_path).empty());
        }
    }


    {
        const auto http_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 12345, 80, std::vector<std::uint8_t>{static_cast<std::uint8_t>('G'), static_cast<std::uint8_t>('E'), static_cast<std::uint8_t>('T'), static_cast<std::uint8_t>(' ')}, 0x18);
        const auto dns_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 2, 0, 1), ipv4(10, 2, 0, 2), 53000, 53, std::vector<std::uint8_t>{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        const auto generic_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 3, 0, 1), ipv4(10, 3, 0, 2), 22000, 443);

        const auto source_path = write_temp_pcap(
            "pfl_export_multi_flow_source.pcap",
            make_classic_pcap({
                {100, http_packet},
                {200, dns_packet},
                {300, generic_packet},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_export_multi_flow_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 3);

        std::vector<std::size_t> selected_flow_indices {};
        for (const auto& row : rows) {
            if (row.protocol_hint == "http" || row.protocol_hint == "dns") {
                selected_flow_indices.push_back(row.index);
            }
        }
        PFL_EXPECT(selected_flow_indices.size() == 2);
        PFL_EXPECT(session.export_flows_to_pcap(selected_flow_indices, output_path));

        CaptureSession exported_session {};
        PFL_EXPECT(exported_session.open_capture(output_path));
        PFL_EXPECT(exported_session.summary().packet_count == 2);
        PFL_EXPECT(exported_session.summary().flow_count == 2);

        const auto stats = exported_session.protocol_summary();
        PFL_EXPECT(stats.hint_http.flow_count == 1);
        PFL_EXPECT(stats.hint_dns.flow_count == 1);
        PFL_EXPECT(stats.hint_unknown.flow_count == 0);
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_export_invalid_source.pcap",
            make_classic_pcap({{100, tcp_packet}})
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_export_invalid_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(!session.export_flow_to_pcap(99, output_path));
        PFL_EXPECT(!std::filesystem::exists(output_path));
    }

    {
        const auto flow_a_packet_1 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 10, 0, 1), ipv4(10, 10, 0, 2), 11001, 443, std::vector<std::uint8_t>{0xA1}, 0x18);
        const auto flow_a_packet_2 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 10, 0, 1), ipv4(10, 10, 0, 2), 11001, 443, std::vector<std::uint8_t>{0xA2}, 0x18);
        const auto flow_a_packet_3 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 10, 0, 1), ipv4(10, 10, 0, 2), 11001, 443, std::vector<std::uint8_t>{0xA3}, 0x18);
        const auto flow_a_packet_4 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 10, 0, 1), ipv4(10, 10, 0, 2), 11001, 443, std::vector<std::uint8_t>{0xA4}, 0x18);
        const auto flow_b_packet_1 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 22001, 53, std::vector<std::uint8_t>{0xB1});
        const auto flow_b_packet_2 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 22001, 53, std::vector<std::uint8_t>{0xB2});
        const auto flow_b_packet_3 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 22001, 53, std::vector<std::uint8_t>{0xB3});
        const auto flow_b_packet_4 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 22001, 53, std::vector<std::uint8_t>{0xB4});

        const auto source_path = write_temp_pcap(
            "pfl_smart_export_sparse_source.pcap",
            make_classic_pcap({
                {100, flow_a_packet_1},
                {200, flow_b_packet_1},
                {300, flow_a_packet_2},
                {400, flow_b_packet_2},
                {500, flow_a_packet_3},
                {600, flow_b_packet_3},
                {700, flow_a_packet_4},
                {800, flow_b_packet_4},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_sparse_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 2);

        SmartFlowExportRequest request {};
        for (const auto& row : rows) {
            request.flow_indices.push_back(row.index);
        }
        request.base_mode = SmartFlowExportBaseMode::first_n_packets;
        request.first_n_packets = 1U;
        request.include_last_packet = true;
        request.include_every_kth_packet_after_base = true;
        request.every_kth_packet = 2U;

        PFL_EXPECT(session.export_smart_flows_to_pcap(request, output_path));

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 6U);
        PFL_EXPECT(exported_packets[0].bytes == flow_a_packet_1);
        PFL_EXPECT(exported_packets[1].bytes == flow_b_packet_1);
        PFL_EXPECT(exported_packets[2].bytes == flow_a_packet_3);
        PFL_EXPECT(exported_packets[3].bytes == flow_b_packet_3);
        PFL_EXPECT(exported_packets[4].bytes == flow_a_packet_4);
        PFL_EXPECT(exported_packets[5].bytes == flow_b_packet_4);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[5].ts_usec == 800U);
    }

    {
        const auto packet_1 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(172, 16, 0, 1), ipv4(172, 16, 0, 2), 33001, 33002, std::vector<std::uint8_t>{0x01});
        const auto packet_2 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(172, 16, 0, 1), ipv4(172, 16, 0, 2), 33001, 33002, std::vector<std::uint8_t>{0x02});
        const auto packet_3 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(172, 16, 0, 1), ipv4(172, 16, 0, 2), 33001, 33002, std::vector<std::uint8_t>{0x03});

        const auto source_path = write_temp_pcap(
            "pfl_smart_export_original_bytes_source.pcap",
            make_classic_pcap_with_captured_lengths({
                {.ts_usec = 100U, .captured_bytes = packet_1, .original_length = 100U},
                {.ts_usec = 200U, .captured_bytes = packet_2, .original_length = 100U},
                {.ts_usec = 300U, .captured_bytes = packet_3, .original_length = 100U},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_original_bytes_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);

        SmartFlowExportRequest request {};
        request.flow_indices.push_back(rows.front().index);
        request.base_mode = SmartFlowExportBaseMode::first_m_original_bytes;
        request.first_m_original_bytes = 150U;

        PFL_EXPECT(session.export_smart_flows_to_pcap(request, output_path));

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 2U);
        PFL_EXPECT(exported_packets[0].bytes == packet_1);
        PFL_EXPECT(exported_packets[1].bytes == packet_2);
        PFL_EXPECT(exported_packets[0].original_length == 100U);
        PFL_EXPECT(exported_packets[1].original_length == 100U);
    }

    {
        const auto malformed_packet = read_first_packet(fixture_path("parsing/tcp_options/19_tcp_syn_tcp_header_snaplen_truncated.pcap"));
        const auto source_path = write_temp_pcap(
            "pfl_smart_export_unrecognized_packet_list_source.pcap",
            make_classic_pcap_with_captured_lengths({
                {.ts_usec = 100U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
                {.ts_usec = 200U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
                {.ts_usec = 300U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_unrecognized_packet_list_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(session.unrecognized_packet_count() == 3U);
        const auto rows = session.list_unrecognized_packets();
        PFL_REQUIRE(rows.size() == 3U);

        SmartPacketListExportRequest request {};
        request.retention.base_mode = SmartFlowExportBaseMode::first_n_packets;
        request.retention.first_n_packets = 2U;
        for (const auto& row : rows) {
            request.packet_indices.push_back(static_cast<std::size_t>(row.packet_index));
        }

        PFL_EXPECT(session.export_smart_packets_to_pcap(request, output_path));

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 2U);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[1].ts_usec == 200U);
        PFL_EXPECT(exported_packets[0].bytes == malformed_packet.bytes);
        PFL_EXPECT(exported_packets[1].bytes == malformed_packet.bytes);
    }

    {
        const auto packet_1 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(172, 31, 0, 1), ipv4(172, 31, 0, 2), 34001, 34002, std::vector<std::uint8_t>{0x11});
        const auto packet_2 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(172, 31, 0, 1), ipv4(172, 31, 0, 2), 34001, 34002, std::vector<std::uint8_t>{0x22});
        const auto packet_3 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(172, 31, 0, 1), ipv4(172, 31, 0, 2), 34001, 34002, std::vector<std::uint8_t>{0x33});
        const auto packet_4 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(172, 31, 0, 1), ipv4(172, 31, 0, 2), 34001, 34002, std::vector<std::uint8_t>{0x44});
        const auto packet_5 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(172, 31, 0, 1), ipv4(172, 31, 0, 2), 34001, 34002, std::vector<std::uint8_t>{0x55});

        const auto source_path = write_temp_pcap(
            "pfl_smart_export_packet_list_normalized_source.pcap",
            make_classic_pcap({
                {100, packet_1},
                {200, packet_2},
                {300, packet_3},
                {400, packet_4},
                {500, packet_5},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_packet_list_normalized_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));

        SmartPacketListExportRequest request {};
        request.retention.base_mode = SmartFlowExportBaseMode::first_n_packets;
        request.retention.first_n_packets = 2U;
        request.retention.include_last_packet = true;
        request.retention.include_every_kth_packet_after_base = true;
        request.retention.every_kth_packet = 2U;
        request.packet_indices = {4U, 2U, 2U, 3U, 0U, 1U};

        PFL_EXPECT(session.export_smart_packets_to_pcap(request, output_path));

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 4U);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[1].ts_usec == 200U);
        PFL_EXPECT(exported_packets[2].ts_usec == 400U);
        PFL_EXPECT(exported_packets[3].ts_usec == 500U);
        PFL_EXPECT(exported_packets[0].bytes == packet_1);
        PFL_EXPECT(exported_packets[1].bytes == packet_2);
        PFL_EXPECT(exported_packets[2].bytes == packet_4);
        PFL_EXPECT(exported_packets[3].bytes == packet_5);
    }

    {
        const auto malformed_packet = read_first_packet(fixture_path("parsing/tcp_options/19_tcp_syn_tcp_header_snaplen_truncated.pcap"));
        const auto source_path = write_temp_pcap(
            "pfl_smart_export_unrecognized_source.pcap",
            make_classic_pcap_with_captured_lengths({
                {.ts_usec = 100U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
                {.ts_usec = 200U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
                {.ts_usec = 300U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_unrecognized_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(session.unrecognized_packet_count() == 3U);

        const SmartPacketRetentionOptions options {
            .base_mode = SmartFlowExportBaseMode::first_m_original_bytes,
            .first_m_original_bytes = 150U,
        };
        PFL_EXPECT(session.export_smart_unrecognized_packets_to_pcap(options, output_path));

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 2U);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[1].ts_usec == 200U);
    }

    {
        const auto malformed_packet = read_first_packet(fixture_path("parsing/tcp_options/19_tcp_syn_tcp_header_snaplen_truncated.pcap"));
        const auto source_path = write_temp_pcap(
            "pfl_smart_export_unrecognized_only_source.pcap",
            make_classic_pcap_with_captured_lengths({
                {.ts_usec = 100U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
                {.ts_usec = 200U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_unrecognized_only_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 2U);

        const SmartPacketRetentionOptions options {
            .base_mode = SmartFlowExportBaseMode::all_packets,
        };
        PFL_EXPECT(session.export_smart_unrecognized_packets_to_pcap(options, output_path));

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 2U);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[1].ts_usec == 200U);
    }

    {
        const auto malformed_packet = read_first_packet(fixture_path("parsing/tcp_options/19_tcp_syn_tcp_header_snaplen_truncated.pcap"));
        const auto source_path = write_temp_pcap(
            "pfl_smart_export_unrecognized_sparse_source.pcap",
            make_classic_pcap_with_captured_lengths({
                {.ts_usec = 100U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
                {.ts_usec = 200U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
                {.ts_usec = 300U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
                {.ts_usec = 400U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
                {.ts_usec = 500U, .captured_bytes = malformed_packet.bytes, .original_length = 100U},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_unrecognized_sparse_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(session.unrecognized_packet_count() == 5U);

        const SmartPacketRetentionOptions options {
            .base_mode = SmartFlowExportBaseMode::first_n_packets,
            .first_n_packets = 2U,
            .include_last_packet = true,
            .include_every_kth_packet_after_base = true,
            .every_kth_packet = 2U,
        };
        PFL_EXPECT(session.export_smart_unrecognized_packets_to_pcap(options, output_path));

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 4U);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[1].ts_usec == 200U);
        PFL_EXPECT(exported_packets[2].ts_usec == 400U);
        PFL_EXPECT(exported_packets[3].ts_usec == 500U);
    }

    {
        const auto source_path = fixture_path("parsing/tcp_options/01_tcp_syn_no_options.pcap");
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_unrecognized_empty_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const SmartPacketRetentionOptions options {
            .base_mode = SmartFlowExportBaseMode::all_packets,
        };
        PFL_EXPECT(!session.export_smart_unrecognized_packets_to_pcap(options, output_path));

        SmartPacketListExportRequest invalid_request {};
        invalid_request.packet_indices.push_back(999999U);
        invalid_request.retention = options;
        PFL_EXPECT(!session.export_smart_packets_to_pcap(invalid_request, output_path));
    }

    {
        std::vector<ClassicPcapCapturedRecord> packets {};
        packets.reserve(1500);
        for (std::uint32_t packet_index = 0; packet_index < 1500U; ++packet_index) {
            packets.push_back(ClassicPcapCapturedRecord {
                .ts_usec = 100U + packet_index,
                .captured_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 70, 0, 1), ipv4(10, 70, 0, 2), 37001, 37002, std::vector<std::uint8_t>{static_cast<std::uint8_t>(packet_index & 0xFFU)}
                ),
                .original_length = 200U,
            });
        }

        const auto source_path = write_temp_pcap(
            "pfl_smart_export_single_file_progress_source.pcap",
            make_classic_pcap_with_captured_lengths(packets)
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_single_file_progress_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);

        SmartFlowExportRequest request {};
        request.flow_indices.push_back(rows.front().index);
        request.base_mode = SmartFlowExportBaseMode::all_packets;

        std::uint64_t progress_updates = 0U;
        bool saw_final_progress = false;
        const SmartSingleFileExportOptions export_options {
            .progress_callback = [&](const SmartSingleFileExportProgress& progress) {
                ++progress_updates;
                if (progress.packets_processed == 1500U &&
                    progress.total_packets_to_scan == 1500U &&
                    progress.exported_packets_written == 1500U &&
                    progress.total_selected_packets == 1500U) {
                    saw_final_progress = true;
                }
            },
        };

        std::string error_text {};
        PFL_EXPECT(session.export_smart_flows_to_pcap(request, output_path, export_options, &error_text));
        PFL_EXPECT(error_text.empty());
        PFL_EXPECT(progress_updates >= 1U);
        PFL_EXPECT(saw_final_progress);

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 1500U);
    }

    {
        const auto malformed_packet = read_first_packet(fixture_path("parsing/tcp_options/19_tcp_syn_tcp_header_snaplen_truncated.pcap"));
        std::vector<ClassicPcapCapturedRecord> packets {};
        packets.reserve(1500);
        for (std::uint32_t packet_index = 0; packet_index < 1500U; ++packet_index) {
            packets.push_back(ClassicPcapCapturedRecord {
                .ts_usec = 100U + packet_index,
                .captured_bytes = malformed_packet.bytes,
                .original_length = 200U,
            });
        }

        const auto source_path = write_temp_pcap(
            "pfl_smart_export_unrecognized_single_file_cancel_source.pcap",
            make_classic_pcap_with_captured_lengths(packets)
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_unrecognized_single_file_cancel_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(session.unrecognized_packet_count() == 1500U);

        const SmartPacketRetentionOptions options {
            .base_mode = SmartFlowExportBaseMode::all_packets,
        };

        std::atomic_bool cancel_requested {false};
        std::uint64_t progress_updates = 0U;
        const SmartSingleFileExportOptions export_options {
            .progress_callback = [&](const SmartSingleFileExportProgress& progress) {
                if (progress.packets_processed >= 1000U) {
                    ++progress_updates;
                    cancel_requested.store(true);
                }
            },
            .cancel_requested = [&]() {
                return cancel_requested.load();
            },
        };

        std::string error_text {};
        PFL_EXPECT(!session.export_smart_unrecognized_packets_to_pcap(options, output_path, export_options, &error_text));
        PFL_EXPECT(error_text == "Smart export cancelled by user.");
        PFL_EXPECT(progress_updates >= 1U);
        if (std::filesystem::exists(output_path)) {
            PFL_EXPECT(!read_all_packets(output_path).empty());
        }
    }

    {
        const auto flow_a_ab_1 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 50, 0, 1), ipv4(10, 50, 0, 2), 15001, 443, std::vector<std::uint8_t>{0xA1}, 0x18);
        const auto flow_a_ba_1 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 50, 0, 2), ipv4(10, 50, 0, 1), 443, 15001, std::vector<std::uint8_t>{0xA2}, 0x18);
        const auto flow_a_ab_2 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 50, 0, 1), ipv4(10, 50, 0, 2), 15001, 443, std::vector<std::uint8_t>{0xA3}, 0x18);
        const auto flow_b_ab_1 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 26001, 53, std::vector<std::uint8_t>{0xB1});
        const auto flow_b_ba_1 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 60, 0, 2), ipv4(10, 60, 0, 1), 53, 26001, std::vector<std::uint8_t>{0xB2});
        const auto flow_b_ab_2 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 26001, 53, std::vector<std::uint8_t>{0xB3});

        const auto source_path = write_temp_pcap(
            "pfl_smart_export_per_flow_source.pcap",
            make_classic_pcap({
                {100, flow_a_ab_1},
                {200, flow_b_ab_1},
                {300, flow_a_ba_1},
                {400, flow_b_ba_1},
                {500, flow_a_ab_2},
                {600, flow_b_ab_2},
            })
        );

        const auto output_directory = std::filesystem::temp_directory_path() / "pfl_smart_export_per_flow_output";
        std::filesystem::remove_all(output_directory);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 2U);

        SmartFlowExportRequest request {};
        for (const auto& row : rows) {
            request.flow_indices.push_back(row.index);
        }
        request.base_mode = SmartFlowExportBaseMode::all_packets;

        PFL_EXPECT(session.export_smart_flows_to_folder(request, output_directory));

        const auto manifest_path = output_directory / "flows_manifest.csv";
        PFL_EXPECT(std::filesystem::exists(manifest_path));
        std::ifstream manifest_stream {manifest_path, std::ios::binary};
        PFL_EXPECT(manifest_stream.is_open());
        const std::string manifest_text {std::istreambuf_iterator<char>(manifest_stream), std::istreambuf_iterator<char>()};
        PFL_EXPECT(manifest_text.find("flow_id,file_name,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,exported_packet_count,exported_captured_bytes,exported_original_bytes,protocol_path") != std::string::npos);
        PFL_EXPECT(manifest_text.find("\"EthernetII->IPv4->TCP\"") != std::string::npos);
        PFL_EXPECT(manifest_text.find("\"EthernetII->IPv4->UDP\"") != std::string::npos);
        PFL_EXPECT(manifest_text.find("EthernetII -> IPv4 -> TCP") == std::string::npos);
        const auto manifest_lines = read_text_file_lines(manifest_path);
        PFL_REQUIRE(manifest_lines.size() >= 3U);
        const auto first_manifest_row = split_csv_line(manifest_lines[1]);
        PFL_REQUIRE(first_manifest_row.size() == 20U);
        PFL_EXPECT(first_manifest_row.back() == "EthernetII->IPv4->TCP");

        std::vector<std::filesystem::path> exported_pcaps {};
        for (const auto& entry : std::filesystem::directory_iterator(output_directory)) {
            if (entry.is_regular_file() && entry.path().extension() == ".pcap") {
                exported_pcaps.push_back(entry.path());
            }
        }
        PFL_EXPECT(exported_pcaps.size() == 2U);

        bool found_tcp_flow = false;
        bool found_udp_flow = false;
        for (const auto& exported_path : exported_pcaps) {
            const auto exported_packets = read_all_packets(exported_path);
            if (exported_packets.size() == 3U && exported_packets[0].bytes == flow_a_ab_1) {
                PFL_EXPECT(exported_packets[1].bytes == flow_a_ba_1);
                PFL_EXPECT(exported_packets[2].bytes == flow_a_ab_2);
                found_tcp_flow = true;
            } else if (exported_packets.size() == 3U && exported_packets[0].bytes == flow_b_ab_1) {
                PFL_EXPECT(exported_packets[1].bytes == flow_b_ba_1);
                PFL_EXPECT(exported_packets[2].bytes == flow_b_ab_2);
                found_udp_flow = true;
            }
        }

        PFL_EXPECT(found_tcp_flow);
        PFL_EXPECT(found_udp_flow);
    }

    {
        CaptureSession session {};
        auto& state = session.state();

        const FlowKeyV4 valid_flow {
            .src_addr = ipv4(203, 0, 113, 10),
            .dst_addr = ipv4(203, 0, 113, 20),
            .src_port = 45000,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        };
        ConnectionV4 valid_connection {};
        valid_connection.key = make_connection_key(valid_flow);
        const PacketRef valid_packet {
            .packet_index = 0U,
            .captured_length = 64U,
            .original_length = 64U,
            .ts_sec = 1U,
            .ts_usec = 100U,
        };
        valid_connection.add_packet(valid_flow, valid_packet);
        state.ipv4_connections.get_or_create(valid_connection.key) = valid_connection;

        ConnectionKeyV4 empty_key {};
        empty_key.protocol = ProtocolId::tcp;
        state.ipv4_connections.get_or_create(empty_key);

        const auto output_path = std::filesystem::temp_directory_path() / "pfl_all_flows_info_excludes_empty_connection.csv";
        std::filesystem::remove(output_path);
        PFL_EXPECT(session.export_all_flows_info_csv(output_path));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 2U);
        PFL_EXPECT(csv_lines[1].find("203.0.113.10") != std::string::npos);
        PFL_EXPECT(csv_lines[1].find("203.0.113.20") != std::string::npos);
        PFL_EXPECT(csv_lines[1].find("0.0.0.0") == std::string::npos);
        PFL_EXPECT(csv_lines[1].find("::") == std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap")));

        const auto output_path = std::filesystem::temp_directory_path() / "pfl_all_flows_info_vxlan.csv";
        std::filesystem::remove(output_path);
        PFL_EXPECT(session.export_all_flows_info_csv(output_path));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() >= 3U);
        PFL_EXPECT(csv_lines.front() ==
            "flow_id,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,protocol_path");
        PFL_EXPECT(csv_lines.front().find("file_name") == std::string::npos);
        PFL_EXPECT(csv_lines.front().find("exported_packet_count") == std::string::npos);
        PFL_EXPECT(csv_lines[1].find("\"EthernetII->IPv4->UDP->VXLAN(vni=100)") != std::string::npos);
        PFL_EXPECT(csv_lines[2].find("\"EthernetII->IPv4->UDP->VXLAN(vni=200)") != std::string::npos);
        PFL_EXPECT(csv_lines[1].find("EthernetII ->") == std::string::npos);
        const auto first_row = split_csv_line(csv_lines[1]);
        PFL_REQUIRE(first_row.size() == 16U);
        PFL_EXPECT(first_row[15].find("EthernetII->IPv4->UDP->VXLAN(vni=100)") != std::string::npos);
    }

    {
        const auto output_directory = std::filesystem::temp_directory_path() / "pfl_smart_export_manifest_header_parity";
        std::filesystem::remove_all(output_directory);

        CaptureSession smart_session {};
        PFL_REQUIRE(smart_session.open_capture(fixture_path("parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap")));
        SmartFlowExportRequest request {};
        request.flow_indices.push_back(0U);
        request.base_mode = SmartFlowExportBaseMode::all_packets;
        PFL_EXPECT(smart_session.export_smart_flows_to_folder(request, output_directory));

        const auto manifest_lines = read_text_file_lines(output_directory / "flows_manifest.csv");
        PFL_REQUIRE(!manifest_lines.empty());

        const auto standalone_output_path = std::filesystem::temp_directory_path() / "pfl_all_flows_info_direct.csv";
        std::filesystem::remove(standalone_output_path);
        PFL_EXPECT(smart_session.export_all_flows_info_csv(standalone_output_path));
        const auto standalone_lines = read_text_file_lines(standalone_output_path);
        PFL_REQUIRE(!standalone_lines.empty());

        PFL_EXPECT(manifest_lines.front() ==
            "flow_id,file_name,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,exported_packet_count,exported_captured_bytes,exported_original_bytes,protocol_path");
        PFL_EXPECT(standalone_lines.front() ==
            "flow_id,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,protocol_path");
        PFL_EXPECT(manifest_lines.front().find("file_name") != std::string::npos);
        PFL_EXPECT(standalone_lines.front().find("file_name") == std::string::npos);
        PFL_EXPECT(manifest_lines[1].find("\"EthernetII->IPv4->UDP->VXLAN(vni=100)->EthernetII->IPv4->TCP\"") != std::string::npos);
        const auto standalone_first_row = split_csv_line(standalone_lines[1]);
        PFL_REQUIRE(standalone_first_row.size() == 16U);
        PFL_EXPECT(standalone_first_row.back() == "EthernetII->IPv4->UDP->VXLAN(vni=100)->EthernetII->IPv4->TCP");
    }

    {
        auto session = build_flow_info_export_session();
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);

        const auto alpha_index = find_flow_index_by_service_hint(rows, "alpha,\"quoted\",example");
        const auto beta_index = find_flow_index_by_service_hint(rows, "beta.example");
        PFL_REQUIRE(alpha_index.has_value());
        PFL_REQUIRE(beta_index.has_value());

        const auto output_path = std::filesystem::temp_directory_path() / "pfl_subset_flows_info_explicit_order.csv";
        std::filesystem::remove(output_path);

        const std::vector<std::size_t> explicit_subset {*beta_index, *alpha_index};
        PFL_EXPECT(session.export_flows_info_csv(explicit_subset, output_path));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 3U);
        PFL_EXPECT(csv_lines.front() ==
            "flow_id,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,protocol_path");

        const auto first_row = split_csv_line(csv_lines[1]);
        const auto second_row = split_csv_line(csv_lines[2]);
        PFL_REQUIRE(first_row.size() == 16U);
        PFL_REQUIRE(second_row.size() == 16U);
        PFL_EXPECT(first_row[0] == std::to_string(*beta_index + 1U));
        PFL_EXPECT(second_row[0] == std::to_string(*alpha_index + 1U));
        PFL_EXPECT(first_row[4] == "beta.example");
        PFL_EXPECT(second_row[4] == "alpha,\"quoted\",example");
        PFL_EXPECT(first_row[15] == "EthernetII->IPv4->UDP->GTP-U(teid=16909060)->IPv4->TCP");
        PFL_EXPECT(second_row[15] == "EthernetII->IPv4->UDP->VXLAN(vni=100)->EthernetII->IPv4->TCP");
    }

    {
        auto session = build_flow_info_export_session();
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_subset_flows_info_empty.csv";
        std::filesystem::remove(output_path);

        const std::vector<std::size_t> empty_subset {};
        PFL_EXPECT(session.export_flows_info_csv(empty_subset, output_path));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 1U);
        PFL_EXPECT(csv_lines.front() ==
            "flow_id,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,protocol_path");
    }

    {
        auto session = build_flow_info_export_session();
        session_detail::FlowQuery query {};
        query.selected_flow_indices = std::vector<std::size_t> {0U, 1U};
        query.text_filter = "example";
        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::service,
            .direction = session_detail::FlowQuerySortDirection::descending,
        };
        query.limit = 1U;

        const auto query_result = session.query_flows(query);
        PFL_REQUIRE(query_result.status == session_detail::FlowQueryStatus::ok);
        PFL_REQUIRE(query_result.ordered_flow_indices.size() == 1U);

        const auto output_path = std::filesystem::temp_directory_path() / "pfl_subset_flows_info_query_result.csv";
        std::filesystem::remove(output_path);
        PFL_EXPECT(session.export_flows_info_csv(query_result.ordered_flow_indices, output_path));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 2U);
        const auto only_row = split_csv_line(csv_lines[1]);
        PFL_REQUIRE(only_row.size() == 16U);
        PFL_EXPECT(only_row[0] == std::to_string(query_result.ordered_flow_indices.front() + 1U));
        PFL_EXPECT(only_row[4] == "beta.example");
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_subset_flows_info_index_only_source.pcap",
            make_classic_pcap({
                {100U, make_ethernet_ipv4_udp_packet(ipv4(10, 120, 0, 1), ipv4(10, 120, 0, 2), 40123, 53)},
                {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 120, 0, 2), ipv4(10, 120, 0, 1), 53, 40123)},
            })
        );
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_subset_flows_info_index_only.idx";
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_subset_flows_info_index_only.csv";
        std::filesystem::remove(index_path);
        std::filesystem::remove(output_path);

        CaptureSession source_session {};
        PFL_REQUIRE(source_session.open_capture(source_path));
        PFL_REQUIRE(source_session.save_index(index_path));
        std::filesystem::remove(source_path);

        CaptureSession indexed_session {};
        PFL_REQUIRE(indexed_session.load_index(index_path));
        PFL_EXPECT(indexed_session.opened_from_index());
        PFL_EXPECT(!indexed_session.has_source_capture());

        const auto query_result = indexed_session.query_flows(session_detail::FlowQuery {});
        PFL_REQUIRE(query_result.status == session_detail::FlowQueryStatus::ok);
        PFL_REQUIRE(query_result.ordered_flow_indices.size() == 1U);
        PFL_EXPECT(indexed_session.export_flows_info_csv(query_result.ordered_flow_indices, output_path));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 2U);
        const auto only_row = split_csv_line(csv_lines[1]);
        PFL_REQUIRE(only_row.size() == 16U);
        PFL_EXPECT(only_row[0] == "1");
        PFL_EXPECT(only_row[2] == "UDP");
    }

    {
        CaptureSession arp_session {};
        PFL_REQUIRE(arp_session.open_capture(fixture_path("parsing/arp/01_arp_request_ipv4.pcap")));

        const auto output_path = std::filesystem::temp_directory_path() / "pfl_all_flows_info_arp.csv";
        std::filesystem::remove(output_path);
        PFL_EXPECT(arp_session.export_all_flows_info_csv(output_path));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 2U);
        PFL_EXPECT(csv_lines[1].find("\"Who has 10.10.12.1? Tell 10.10.12.2\"") != std::string::npos);

        const auto rows = parse_csv_file(output_path);
        PFL_REQUIRE(rows.size() == 2U);
        PFL_REQUIRE(rows[0].size() == 16U);
        PFL_REQUIRE(rows[1].size() == 16U);
        PFL_EXPECT(rows[1][1] == "IPv4");
        PFL_EXPECT(rows[1][2] == "ARP");
        PFL_EXPECT(rows[1][4] == "Who has 10.10.12.1? Tell 10.10.12.2");
        PFL_EXPECT(rows[1][5] == "10.10.12.2");
        PFL_EXPECT(rows[1][6] == "0");
        PFL_EXPECT(rows[1][7] == "10.10.12.1");
        PFL_EXPECT(rows[1][8] == "0");
        PFL_EXPECT(rows[1][9] == "1");
        PFL_EXPECT(!rows[1][10].empty());
        PFL_EXPECT(!rows[1][11].empty());
        PFL_EXPECT(!rows[1][12].empty());
        PFL_EXPECT(!rows[1][13].empty());
        PFL_EXPECT(!rows[1][14].empty());
        PFL_EXPECT(!rows[1][15].empty());
    }

    {
        CaptureSession igmp_session {};
        PFL_REQUIRE(igmp_session.open_capture(fixture_path("parsing/igmp/02_igmpv2_membership_report_mdns_group.pcap")));

        const auto output_path = std::filesystem::temp_directory_path() / "pfl_all_flows_info_igmp.csv";
        std::filesystem::remove(output_path);
        PFL_EXPECT(igmp_session.export_all_flows_info_csv(output_path));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 2U);
        PFL_EXPECT(csv_lines[1].find("\"Membership Report 224.0.0.251\"") != std::string::npos);

        const auto rows = parse_csv_file(output_path);
        PFL_REQUIRE(rows.size() == 2U);
        PFL_REQUIRE(rows[0].size() == 16U);
        PFL_REQUIRE(rows[1].size() == 16U);
        PFL_EXPECT(rows[1][1] == "IPv4");
        PFL_EXPECT(rows[1][2] == "IGMP");
        PFL_EXPECT(rows[1][3] == "igmpv2");
        PFL_EXPECT(rows[1][4] == "Membership Report 224.0.0.251");
        PFL_EXPECT(rows[1][5] == "192.0.2.10");
        PFL_EXPECT(rows[1][6] == "0");
        PFL_EXPECT(rows[1][7] == "224.0.0.251");
        PFL_EXPECT(rows[1][8] == "0");
        PFL_EXPECT(rows[1][9] == "1");
        PFL_EXPECT(!rows[1][10].empty());
        PFL_EXPECT(!rows[1][11].empty());
        PFL_EXPECT(!rows[1][12].empty());
        PFL_EXPECT(!rows[1][13].empty());
        PFL_EXPECT(!rows[1][14].empty());
        PFL_EXPECT(!rows[1][15].empty());
    }

    {
        auto session = build_flow_info_export_session_with_control_characters();
        const auto all_output_path = std::filesystem::temp_directory_path() / "pfl_all_flows_info_controls.csv";
        const auto subset_output_path = std::filesystem::temp_directory_path() / "pfl_subset_flows_info_controls.csv";
        std::filesystem::remove(all_output_path);
        std::filesystem::remove(subset_output_path);

        PFL_EXPECT(session.export_all_flows_info_csv(all_output_path));
        PFL_EXPECT(session.export_flows_info_csv(std::vector<std::size_t> {0U}, subset_output_path));

        const auto all_csv_text = read_text_file(all_output_path);
        const auto subset_csv_text = read_text_file(subset_output_path);
        PFL_EXPECT(all_csv_text.find("\"tab\tcomma,value \"\"quoted\"\"\r\nnext line\"") != std::string::npos);
        PFL_EXPECT(subset_csv_text.find("\"tab\tcomma,value \"\"quoted\"\"\r\nnext line\"") != std::string::npos);

        const auto all_rows = parse_csv_file(all_output_path);
        const auto subset_rows = parse_csv_file(subset_output_path);
        PFL_REQUIRE(all_rows.size() == 2U);
        PFL_REQUIRE(subset_rows.size() == 2U);
        PFL_REQUIRE(all_rows[1].size() == 16U);
        PFL_REQUIRE(subset_rows[1].size() == 16U);
        PFL_EXPECT(all_rows[1] == subset_rows[1]);
        PFL_EXPECT(all_rows[1][0] == "1");
        PFL_EXPECT(all_rows[1][3] == "http");
        PFL_EXPECT(all_rows[1][4] == "tab\tcomma,value \"quoted\"\r\nnext line");
        PFL_EXPECT(all_rows[1][5] == "198.18.0.10");
        PFL_EXPECT(all_rows[1][6] == "45000");
        PFL_EXPECT(all_rows[1][7] == "198.18.0.20");
        PFL_EXPECT(all_rows[1][8] == "80");
        PFL_EXPECT(all_rows[1][9] == "2");
        PFL_EXPECT(all_rows[1][15] == "EthernetII->IPv4->TCP");
    }

    {
        auto session = build_flow_info_export_session();
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_all_flows_info_single_token_quote_policy.csv";
        std::filesystem::remove(output_path);
        PFL_EXPECT(session.export_all_flows_info_csv(output_path));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 3U);
        PFL_EXPECT(csv_lines[1].find("\"alpha,\"\"quoted\"\",example\"") != std::string::npos);
        PFL_EXPECT(csv_lines[2].find(",beta.example,") != std::string::npos);
        PFL_EXPECT(csv_lines[2].find("\"beta.example\"") == std::string::npos);
    }

    {
        const auto packet_1 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(192, 0, 2, 10), ipv4(198, 51, 100, 20), 40001, 443, std::vector<std::uint8_t>{0x11}, 0x18);
        const auto packet_2 = make_ethernet_ipv6_udp_with_hop_by_hop_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}),
            5353,
            53
        );

        const auto source_path = write_temp_pcap(
            "pfl_smart_export_filename_sanitization_source.pcap",
            make_classic_pcap({
                {100, packet_1},
                {200, packet_2},
            })
        );
        const auto output_directory = std::filesystem::temp_directory_path() / "pfl_smart_export_filename_sanitization_output";
        std::filesystem::remove_all(output_directory);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 2U);

        SmartFlowExportRequest request {};
        for (const auto& row : rows) {
            request.flow_indices.push_back(row.index);
        }
        request.base_mode = SmartFlowExportBaseMode::all_packets;

        PFL_EXPECT(session.export_smart_flows_to_folder(request, output_directory));

        const auto exported_pcaps = list_exported_pcaps(output_directory);
        PFL_EXPECT(exported_pcaps.size() == 2U);

        bool saw_dotted_ipv4_name = false;
        bool saw_sanitized_ipv6_name = false;
        for (const auto& exported_path : exported_pcaps) {
            const auto file_name = exported_path.filename().string();
            PFL_EXPECT(file_name.rfind("00000", 0U) == 0U);
            if (file_name.find("192.0.2.10_40001-198.51.100.20_443") != std::string::npos) {
                saw_dotted_ipv4_name = true;
            }
            if (file_name.find("2001") != std::string::npos &&
                file_name.find("db8") != std::string::npos) {
                PFL_EXPECT(file_name.find(':') == std::string::npos);
                saw_sanitized_ipv6_name = true;
            }
        }

        PFL_EXPECT(saw_dotted_ipv4_name);
        PFL_EXPECT(saw_sanitized_ipv6_name);
    }

    {
        const auto packet_1 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 70, 0, 1), ipv4(10, 70, 0, 2), 37001, 37002, std::vector<std::uint8_t>{0x01});
        const auto packet_2 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 70, 0, 1), ipv4(10, 70, 0, 2), 37001, 37002, std::vector<std::uint8_t>{0x02});
        const auto packet_3 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 70, 0, 1), ipv4(10, 70, 0, 2), 37001, 37002, std::vector<std::uint8_t>{0x03});
        const auto packet_4 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 70, 0, 1), ipv4(10, 70, 0, 2), 37001, 37002, std::vector<std::uint8_t>{0x04});

        const auto source_path = write_temp_pcap(
            "pfl_smart_export_overlap_dedup_source.pcap",
            make_classic_pcap({
                {100, packet_1},
                {200, packet_2},
                {300, packet_3},
                {400, packet_4},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_smart_export_overlap_dedup_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);

        SmartFlowExportRequest request {};
        request.flow_indices.push_back(rows.front().index);
        request.base_mode = SmartFlowExportBaseMode::first_n_packets;
        request.first_n_packets = 1U;
        request.include_last_packet = true;
        request.include_every_kth_packet_after_base = true;
        request.every_kth_packet = 1U;

        PFL_EXPECT(session.export_smart_flows_to_pcap(request, output_path));

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 4U);
        PFL_EXPECT(exported_packets[0].bytes == packet_1);
        PFL_EXPECT(exported_packets[1].bytes == packet_2);
        PFL_EXPECT(exported_packets[2].bytes == packet_3);
        PFL_EXPECT(exported_packets[3].bytes == packet_4);
    }

    {
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {};
        packets.reserve(4);
        packets.push_back({100, make_ethernet_ipv4_tcp_packet(ipv4(10, 80, 0, 1), ipv4(10, 80, 0, 2), 38001, 443)});
        packets.push_back({200, make_ethernet_ipv4_tcp_packet(ipv4(10, 81, 0, 1), ipv4(10, 81, 0, 2), 38002, 443)});
        packets.push_back({300, make_ethernet_ipv4_tcp_packet(ipv4(10, 82, 0, 1), ipv4(10, 82, 0, 2), 38003, 443)});
        packets.push_back({400, make_ethernet_ipv4_tcp_packet(ipv4(10, 83, 0, 1), ipv4(10, 83, 0, 2), 38004, 443)});

        const auto source_path = write_temp_pcap(
            "pfl_smart_export_cancel_preparing_source.pcap",
            make_classic_pcap(packets)
        );
        const auto output_directory = std::filesystem::temp_directory_path() / "pfl_smart_export_cancel_preparing_output";
        std::filesystem::remove_all(output_directory);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 4U);

        SmartFlowExportRequest request {};
        for (const auto& row : rows) {
            request.flow_indices.push_back(row.index);
        }
        request.base_mode = SmartFlowExportBaseMode::all_packets;

        std::atomic_bool cancel_requested {false};
        std::uint64_t preparing_updates = 0U;
        const SmartPerFlowExportOptions options {
            .buffer_budget_bytes = 128U * 1024U * 1024U,
            .progress_callback = [&](const SmartPerFlowExportProgress& progress) {
                if (progress.phase == SmartPerFlowExportPhase::preparing && progress.packets_processed >= 1U) {
                    ++preparing_updates;
                    cancel_requested.store(true);
                }
            },
            .cancel_requested = [&]() {
                return cancel_requested.load();
            },
        };

        std::string error_text {};
        PFL_EXPECT(!session.export_smart_flows_to_folder(request, output_directory, options, &error_text));
        PFL_EXPECT(error_text == "Smart export cancelled by user.");
        PFL_EXPECT(preparing_updates >= 1U);
        PFL_EXPECT(!std::filesystem::exists(output_directory / "flows_manifest.csv"));
    }

    {
        std::vector<ClassicPcapCapturedRecord> packets {};
        packets.reserve(1500);
        for (std::uint32_t packet_index = 0; packet_index < 1500U; ++packet_index) {
            packets.push_back(ClassicPcapCapturedRecord {
                .ts_usec = 100U + packet_index,
                .captured_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 90, 0, 1), ipv4(10, 90, 0, 2), 39001, 39002, std::vector<std::uint8_t>{static_cast<std::uint8_t>(packet_index & 0xFFU)}
                ),
                .original_length = 200U,
            });
        }

        const auto source_path = write_temp_pcap(
            "pfl_smart_export_cancel_writing_source.pcap",
            make_classic_pcap_with_captured_lengths(packets)
        );
        const auto output_directory = std::filesystem::temp_directory_path() / "pfl_smart_export_cancel_writing_output";
        std::filesystem::remove_all(output_directory);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);

        SmartFlowExportRequest request {};
        request.flow_indices.push_back(rows.front().index);
        request.base_mode = SmartFlowExportBaseMode::all_packets;

        std::atomic_bool cancel_requested {false};
        std::uint64_t writing_updates = 0U;
        const SmartPerFlowExportOptions options {
            .buffer_budget_bytes = 1U * 1024U * 1024U,
            .progress_callback = [&](const SmartPerFlowExportProgress& progress) {
                if (progress.phase == SmartPerFlowExportPhase::writing && progress.packets_processed >= 1000U) {
                    ++writing_updates;
                    cancel_requested.store(true);
                }
            },
            .cancel_requested = [&]() {
                return cancel_requested.load();
            },
        };

        std::string error_text {};
        PFL_EXPECT(!session.export_smart_flows_to_folder(request, output_directory, options, &error_text));
        PFL_EXPECT(error_text == "Smart export cancelled by user.");
        PFL_EXPECT(writing_updates >= 1U);
        PFL_EXPECT(!std::filesystem::exists(output_directory / "flows_manifest.csv"));
        const auto exported_pcaps = list_exported_pcaps(output_directory);
        PFL_EXPECT(exported_pcaps.size() == 1U);
        PFL_EXPECT(!read_all_packets(exported_pcaps.front()).empty());

        std::string retry_error_text {};
        PFL_EXPECT(session.export_smart_flows_to_folder(request, output_directory, SmartPerFlowExportOptions {}, &retry_error_text));
        PFL_EXPECT(std::filesystem::exists(output_directory / "flows_manifest.csv"));
    }

    {
        const auto first_packet = make_ethernet_ipv4_udp_packet(
            ipv4(10, 100, 0, 1), ipv4(10, 100, 0, 2), 41001, 53);
        const auto second_packet = make_ethernet_ipv4_tcp_packet(
            ipv4(10, 101, 0, 1), ipv4(10, 101, 0, 2), 41002, 443);
        const auto source_path = write_temp_pcap(
            "pfl_adapter_direct_export_source.pcap",
            make_classic_pcap({
                {100U, first_packet},
                {200U, second_packet},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_adapter_direct_export_output.pcap";
        std::filesystem::remove(output_path);

        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(source_path).opened);
        const auto flows = adapter.get_flows();
        PFL_REQUIRE(flows.size() == 2U);

        const auto result = adapter.export_flows_to_pcap(output_path, {flows[1].flow_index, flows[0].flow_index});
        PFL_EXPECT(result.exported);
        PFL_EXPECT(result.output_path == output_path.string());

        const auto exported_packets = read_all_packets(output_path);
        PFL_REQUIRE(exported_packets.size() == 2U);
        PFL_EXPECT(exported_packets[0].bytes == first_packet);
        PFL_EXPECT(exported_packets[1].bytes == second_packet);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[1].ts_usec == 200U);
    }

    {
        const auto flow_a_packet_1 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 110, 0, 1), ipv4(10, 110, 0, 2), 42001, 443, std::vector<std::uint8_t>{0xA1}, 0x18);
        const auto flow_a_packet_2 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 110, 0, 1), ipv4(10, 110, 0, 2), 42001, 443, std::vector<std::uint8_t>{0xA2}, 0x18);
        const auto flow_a_packet_3 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 110, 0, 1), ipv4(10, 110, 0, 2), 42001, 443, std::vector<std::uint8_t>{0xA3}, 0x18);
        const auto flow_a_packet_4 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 110, 0, 1), ipv4(10, 110, 0, 2), 42001, 443, std::vector<std::uint8_t>{0xA4}, 0x18);
        const auto flow_b_packet_1 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 120, 0, 1), ipv4(10, 120, 0, 2), 43001, 53, std::vector<std::uint8_t>{0xB1});
        const auto flow_b_packet_2 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 120, 0, 1), ipv4(10, 120, 0, 2), 43001, 53, std::vector<std::uint8_t>{0xB2});
        const auto flow_b_packet_3 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 120, 0, 1), ipv4(10, 120, 0, 2), 43001, 53, std::vector<std::uint8_t>{0xB3});
        const auto flow_b_packet_4 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 120, 0, 1), ipv4(10, 120, 0, 2), 43001, 53, std::vector<std::uint8_t>{0xB4});

        const auto source_path = write_temp_pcap(
            "pfl_adapter_smart_single_source.pcap",
            make_classic_pcap({
                {100U, flow_a_packet_1},
                {200U, flow_b_packet_1},
                {300U, flow_a_packet_2},
                {400U, flow_b_packet_2},
                {500U, flow_a_packet_3},
                {600U, flow_b_packet_3},
                {700U, flow_a_packet_4},
                {800U, flow_b_packet_4},
            })
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_adapter_smart_single_output.pcap";
        std::filesystem::remove(output_path);

        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(source_path).opened);
        const auto flows = adapter.get_flows();
        PFL_REQUIRE(flows.size() == 2U);

        SmartFlowExportRequest request {};
        request.flow_indices = {flows[0].flow_index, flows[1].flow_index};
        request.base_mode = SmartFlowExportBaseMode::first_n_packets;
        request.first_n_packets = 1U;
        request.include_last_packet = true;
        request.include_every_kth_packet_after_base = true;
        request.every_kth_packet = 2U;

        std::uint64_t progress_updates = 0U;
        const auto result = adapter.export_smart_flows_to_pcap(
            output_path,
            request,
            SmartSingleFileExportOptions {
                .progress_callback = [&](const SmartSingleFileExportProgress&) {
                    ++progress_updates;
                },
            }
        );
        PFL_EXPECT(result.exported);
        PFL_EXPECT(progress_updates >= 1U);

        const auto exported_packets = read_all_packets(output_path);
        PFL_REQUIRE(exported_packets.size() == 6U);
        PFL_EXPECT(exported_packets[0].bytes == flow_a_packet_1);
        PFL_EXPECT(exported_packets[1].bytes == flow_b_packet_1);
        PFL_EXPECT(exported_packets[2].bytes == flow_a_packet_3);
        PFL_EXPECT(exported_packets[3].bytes == flow_b_packet_3);
        PFL_EXPECT(exported_packets[4].bytes == flow_a_packet_4);
        PFL_EXPECT(exported_packets[5].bytes == flow_b_packet_4);
    }

    {
        const auto flow_a_packet = make_ethernet_ipv4_tcp_packet(
            ipv4(10, 130, 0, 1), ipv4(10, 130, 0, 2), 44001, 443);
        const auto flow_b_packet = make_ethernet_ipv4_udp_packet(
            ipv4(10, 131, 0, 1), ipv4(10, 131, 0, 2), 45001, 53);
        const auto source_path = write_temp_pcap(
            "pfl_adapter_smart_folder_source.pcap",
            make_classic_pcap({
                {100U, flow_a_packet},
                {200U, flow_b_packet},
            })
        );
        const auto output_directory = std::filesystem::temp_directory_path() / "pfl_adapter_smart_folder_output";
        std::filesystem::remove_all(output_directory);
        std::filesystem::create_directories(output_directory);
        {
            std::ofstream keep_stream(output_directory / "keep.txt", std::ios::binary | std::ios::trunc);
            keep_stream << "keep";
        }

        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(source_path).opened);
        const auto flows = adapter.get_flows();
        PFL_REQUIRE(flows.size() == 2U);

        SmartFlowExportRequest request {};
        request.flow_indices = {flows[0].flow_index, flows[1].flow_index};
        request.base_mode = SmartFlowExportBaseMode::all_packets;

        std::uint64_t progress_updates = 0U;
        const auto result = adapter.export_smart_flows_to_folder(
            output_directory,
            request,
            SmartPerFlowExportOptions {
                .buffer_budget_bytes = 1U * 1024U * 1024U,
                .progress_callback = [&](const SmartPerFlowExportProgress&) {
                    ++progress_updates;
                },
            }
        );
        PFL_EXPECT(result.exported);
        PFL_EXPECT(progress_updates >= 1U);
        PFL_EXPECT(std::filesystem::exists(output_directory / "keep.txt"));

        const auto exported_pcaps = list_exported_pcaps(output_directory);
        PFL_EXPECT(exported_pcaps.size() == 2U);

        const auto manifest_rows = parse_csv_file(output_directory / "flows_manifest.csv");
        PFL_REQUIRE(manifest_rows.size() == 3U);
        PFL_REQUIRE(manifest_rows[1].size() >= 2U);
        PFL_REQUIRE(manifest_rows[2].size() >= 2U);
        PFL_EXPECT(manifest_rows[1][0] == "1");
        PFL_EXPECT(manifest_rows[2][0] == "2");
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_adapter_attach_source_original.pcap",
            make_classic_pcap({{100U, tcp_packet}, {200U, udp_packet}})
        );
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_adapter_attach_source.idx";
        const auto moved_source_path = std::filesystem::temp_directory_path() / "pfl_adapter_attach_source_moved.pcap";
        const auto mismatched_source_path = std::filesystem::temp_directory_path() / "pfl_adapter_attach_source_mismatch.pcap";
        const auto export_path = std::filesystem::temp_directory_path() / "pfl_adapter_attach_source_export.pcap";
        std::filesystem::remove(index_path);
        std::filesystem::remove(moved_source_path);
        std::filesystem::remove(mismatched_source_path);
        std::filesystem::remove(export_path);

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(source_path));
        PFL_REQUIRE(session.save_index(index_path));
        std::filesystem::rename(source_path, moved_source_path);

        auto mismatched_bytes = make_classic_pcap({{100U, tcp_packet}, {200U, udp_packet}});
        PFL_REQUIRE(!mismatched_bytes.empty());
        mismatched_bytes.back() ^= 0xFFU;
        {
            std::ofstream mismatched_stream(mismatched_source_path, std::ios::binary | std::ios::trunc);
            mismatched_stream.write(
                reinterpret_cast<const char*>(mismatched_bytes.data()),
                static_cast<std::streamsize>(mismatched_bytes.size())
            );
        }
        std::filesystem::last_write_time(mismatched_source_path, std::filesystem::last_write_time(moved_source_path));

        FrontendSessionAdapter adapter {};
        const auto open_result = adapter.open_capture(index_path);
        PFL_REQUIRE(open_result.opened);
        PFL_EXPECT(open_result.opened_from_index);

        const auto unavailable = adapter.source_availability();
        PFL_EXPECT(unavailable.opened_from_index);
        PFL_EXPECT(!unavailable.has_source_capture);
        PFL_EXPECT(!unavailable.source_capture_accessible);

        const auto export_without_source = adapter.export_flows_to_pcap(export_path, {0U});
        PFL_EXPECT(!export_without_source.exported);
        PFL_EXPECT(export_without_source.error_text == "Original source capture is unavailable. Reattach the capture file to export flows.");

        const auto mismatched_attach = adapter.attach_source_capture(mismatched_source_path);
        PFL_EXPECT(!mismatched_attach.attached);
        PFL_EXPECT(mismatched_attach.error_text == "Selected file does not match the expected source capture.");
        PFL_EXPECT(!mismatched_attach.source_availability.has_source_capture);

        const auto valid_attach = adapter.attach_source_capture(moved_source_path);
        PFL_EXPECT(valid_attach.attached);
        PFL_EXPECT(valid_attach.source_availability.has_source_capture);
        PFL_EXPECT(valid_attach.source_availability.source_capture_accessible);
    }
}

}  // namespace pfl::tests


