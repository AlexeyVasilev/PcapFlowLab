#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
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
        PFL_EXPECT(manifest_text.find("flow_id,file_name,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,exported_packet_count,exported_captured_bytes,exported_original_bytes") != std::string::npos);

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
}

}  // namespace pfl::tests


