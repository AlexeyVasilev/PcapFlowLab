#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>

#include "../../core/open_context.h"
#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/decode/PacketDecoder.h"
#include "core/domain/CaptureState.h"
#include "core/io/PcapReader.h"
#include "core/services/CaptureImporter.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_import_tests() {
    constexpr std::size_t kMinCapturedLengthForStagedImportBytes = 16U * 1024U;
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);

    {
        const auto path = write_temp_pcap("pfl_reader_basic.pcap", make_classic_pcap({{100, tcp_packet}}));
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));
        PFL_EXPECT(reader.data_link_type() == 1);

        const auto packet = reader.read_next();
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(packet->packet_index == 0);
        PFL_EXPECT(packet->ts_sec == 1);
        PFL_EXPECT(packet->ts_usec == 100);
        PFL_EXPECT(packet->captured_length == tcp_packet.size());
        PFL_EXPECT(packet->original_length == tcp_packet.size());
        PFL_EXPECT(packet->data_offset == 40);
        PFL_EXPECT(packet->bytes == tcp_packet);
        PFL_EXPECT(!reader.read_next().has_value());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_reader_prefix_materialize.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));

        auto first_packet = reader.read_next_prefix(16U);
        PFL_EXPECT(first_packet.has_value());
        PFL_EXPECT(first_packet->packet_index == 0U);
        PFL_EXPECT(first_packet->captured_length == tcp_packet.size());
        PFL_EXPECT(first_packet->original_length == tcp_packet.size());
        PFL_EXPECT(first_packet->bytes.size() == 16U);
        PFL_EXPECT(std::equal(first_packet->bytes.begin(), first_packet->bytes.end(), tcp_packet.begin()));
        PFL_EXPECT(reader.next_input_offset() == first_packet->data_offset + 16U);
        PFL_EXPECT(!reader.read_next_prefix(8U).has_value());
        PFL_EXPECT(reader.has_error());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_reader_prefix_materialize_sequential.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));

        auto first_packet = reader.read_next_prefix(16U);
        PFL_EXPECT(first_packet.has_value());
        PFL_EXPECT(reader.materialize_packet_bytes(*first_packet));
        PFL_EXPECT(first_packet->bytes == tcp_packet);
        PFL_EXPECT(reader.next_input_offset() == first_packet->data_offset + first_packet->captured_length);
        PFL_EXPECT(reader.finish_prefix_packet(*first_packet));
        PFL_EXPECT(reader.next_input_offset() == first_packet->data_offset + first_packet->captured_length);

        auto second_packet = reader.read_next_prefix(8U);
        PFL_EXPECT(second_packet.has_value());
        PFL_EXPECT(second_packet->packet_index == 1U);
        PFL_EXPECT(second_packet->captured_length == udp_packet.size());
        PFL_EXPECT(second_packet->original_length == udp_packet.size());
        PFL_EXPECT(second_packet->bytes.size() == 8U);
        PFL_EXPECT(std::equal(second_packet->bytes.begin(), second_packet->bytes.end(), udp_packet.begin()));
        PFL_EXPECT(reader.materialize_packet_bytes(*second_packet));
        PFL_EXPECT(second_packet->bytes == udp_packet);
        PFL_EXPECT(!reader.read_next_prefix(8U).has_value());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_reader_prefix_finalize_only.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));

        auto first_packet = reader.read_next_prefix(16U);
        PFL_EXPECT(first_packet.has_value());
        PFL_EXPECT(reader.next_input_offset() == first_packet->data_offset + 16U);
        PFL_EXPECT(reader.finish_prefix_packet(*first_packet));
        PFL_EXPECT(reader.next_input_offset() == first_packet->data_offset + first_packet->captured_length);

        auto second_packet = reader.read_next_prefix(8U);
        PFL_EXPECT(second_packet.has_value());
        PFL_EXPECT(second_packet->packet_index == 1U);
        PFL_EXPECT(second_packet->bytes.size() == 8U);
        PFL_EXPECT(reader.finish_prefix_packet(*second_packet));
        PFL_EXPECT(!reader.read_next_prefix(8U).has_value());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_reader_import_small_full_read_threshold.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));

        auto first_packet = reader.read_next_import_packet(16U, kMinCapturedLengthForStagedImportBytes);
        PFL_EXPECT(first_packet.has_value());
        PFL_EXPECT(first_packet->packet_index == 0U);
        PFL_EXPECT(first_packet->bytes == tcp_packet);
        PFL_EXPECT(first_packet->bytes.size() == first_packet->captured_length);
        PFL_EXPECT(reader.next_input_offset() == first_packet->data_offset + first_packet->captured_length);

        auto second_packet = reader.read_next_import_packet(8U, kMinCapturedLengthForStagedImportBytes);
        PFL_EXPECT(second_packet.has_value());
        PFL_EXPECT(second_packet->packet_index == 1U);
        PFL_EXPECT(second_packet->bytes == udp_packet);
        PFL_EXPECT(second_packet->bytes.size() == second_packet->captured_length);
        PFL_EXPECT(!reader.read_next_import_packet(8U, kMinCapturedLengthForStagedImportBytes).has_value());
    }

    {
        const auto larger_small_tcp_packet = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 0, 1, 1), ipv4(10, 0, 1, 2), 15000, 443, 48U, 0x18);
        const auto path = write_temp_pcap(
            "pfl_reader_import_into_reuses_small_buffer.pcap",
            make_classic_pcap({{100, larger_small_tcp_packet}, {200, udp_packet}})
        );
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));

        RawPcapPacket packet {};
        PFL_EXPECT(reader.read_next_import_packet_into(packet, 16U, kMinCapturedLengthForStagedImportBytes));
        PFL_EXPECT(packet.packet_index == 0U);
        PFL_EXPECT(packet.bytes == larger_small_tcp_packet);
        PFL_EXPECT(packet.bytes.size() == packet.captured_length);
        PFL_EXPECT(packet.bytes.capacity() >= larger_small_tcp_packet.size());

        PFL_EXPECT(reader.read_next_import_packet_into(packet, 8U, kMinCapturedLengthForStagedImportBytes));
        PFL_EXPECT(packet.packet_index == 1U);
        PFL_EXPECT(packet.bytes == udp_packet);
        PFL_EXPECT(packet.bytes.size() == packet.captured_length);
        PFL_EXPECT(packet.captured_length == udp_packet.size());
        PFL_EXPECT(!reader.read_next_import_packet_into(packet, 8U, kMinCapturedLengthForStagedImportBytes));
        PFL_EXPECT(!reader.has_error());
    }

    {
        const auto large_tcp_packet = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 0, 2, 1),
            ipv4(10, 0, 2, 2),
            22345,
            443,
            static_cast<std::uint16_t>(kMinCapturedLengthForStagedImportBytes + 1024U - 40U),
            0x18
        );
        const auto path = write_temp_pcap(
            "pfl_reader_import_large_staged_threshold.pcap",
            make_classic_pcap({{100, large_tcp_packet}, {200, udp_packet}})
        );
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));

        auto first_packet = reader.read_next_import_packet(192U, kMinCapturedLengthForStagedImportBytes);
        PFL_EXPECT(first_packet.has_value());
        PFL_EXPECT(first_packet->packet_index == 0U);
        PFL_EXPECT(first_packet->captured_length == large_tcp_packet.size());
        PFL_EXPECT(first_packet->bytes.size() == 192U);
        PFL_EXPECT(std::equal(first_packet->bytes.begin(), first_packet->bytes.end(), large_tcp_packet.begin()));
        PFL_EXPECT(reader.next_input_offset() == first_packet->data_offset + 192U);
        PFL_EXPECT(!reader.read_next_import_packet(8U, kMinCapturedLengthForStagedImportBytes).has_value());
        PFL_EXPECT(reader.has_error());
    }

    {
        const auto large_tcp_packet = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 0, 2, 11),
            ipv4(10, 0, 2, 12),
            32345,
            443,
            static_cast<std::uint16_t>(kMinCapturedLengthForStagedImportBytes + 1024U - 40U),
            0x18
        );
        const auto path = write_temp_pcap(
            "pfl_reader_import_into_staged_then_small.pcap",
            make_classic_pcap({{100, large_tcp_packet}, {200, udp_packet}})
        );
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));

        RawPcapPacket packet {};
        PFL_EXPECT(reader.read_next_import_packet_into(packet, 192U, kMinCapturedLengthForStagedImportBytes));
        PFL_EXPECT(packet.packet_index == 0U);
        PFL_EXPECT(packet.captured_length == large_tcp_packet.size());
        PFL_EXPECT(packet.bytes.size() == 192U);
        PFL_EXPECT(reader.next_input_offset() == packet.data_offset + 192U);
        PFL_EXPECT(reader.materialize_packet_bytes(packet));
        PFL_EXPECT(packet.bytes == large_tcp_packet);
        PFL_EXPECT(reader.read_next_import_packet_into(packet, 8U, kMinCapturedLengthForStagedImportBytes));
        PFL_EXPECT(packet.packet_index == 1U);
        PFL_EXPECT(packet.bytes == udp_packet);
        PFL_EXPECT(packet.bytes.size() == packet.captured_length);
        PFL_EXPECT(!reader.read_next_import_packet_into(packet, 8U, kMinCapturedLengthForStagedImportBytes));
        PFL_EXPECT(!reader.has_error());
    }

    {
        const auto large_tcp_packet = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 0, 2, 21),
            ipv4(10, 0, 2, 22),
            42345,
            443,
            static_cast<std::uint16_t>(kMinCapturedLengthForStagedImportBytes + 1024U - 40U),
            0x18
        );
        const auto path = write_temp_pcap(
            "pfl_reader_import_into_small_then_staged.pcap",
            make_classic_pcap({{100, udp_packet}, {200, large_tcp_packet}})
        );
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));

        RawPcapPacket packet {};
        PFL_EXPECT(reader.read_next_import_packet_into(packet, 8U, kMinCapturedLengthForStagedImportBytes));
        PFL_EXPECT(packet.packet_index == 0U);
        PFL_EXPECT(packet.bytes == udp_packet);
        PFL_EXPECT(packet.bytes.size() == packet.captured_length);
        PFL_EXPECT(reader.read_next_import_packet_into(packet, 192U, kMinCapturedLengthForStagedImportBytes));
        PFL_EXPECT(packet.packet_index == 1U);
        PFL_EXPECT(packet.captured_length == large_tcp_packet.size());
        PFL_EXPECT(packet.bytes.size() == 192U);
        PFL_EXPECT(reader.next_input_offset() == packet.data_offset + 192U);
        PFL_EXPECT(reader.finish_prefix_packet(packet));
        PFL_EXPECT(!reader.read_next_import_packet_into(packet, 8U, kMinCapturedLengthForStagedImportBytes));
        PFL_EXPECT(!reader.has_error());
    }

    {
        PacketDecoder decoder {};
        const RawPcapPacket raw_packet {
            .packet_index = 3,
            .ts_sec = 1,
            .ts_usec = 10,
            .captured_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .original_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .data_offset = 128,
            .bytes = tcp_packet,
        };

        const auto decoded = decoder.decode_ethernet(raw_packet);
        PFL_EXPECT(decoded.ipv4.has_value());
        PFL_EXPECT(!decoded.ipv6.has_value());
        PFL_EXPECT(decoded.ipv4->flow_key.src_addr == ipv4(10, 0, 0, 1));
        PFL_EXPECT(decoded.ipv4->flow_key.dst_addr == ipv4(10, 0, 0, 2));
        PFL_EXPECT(decoded.ipv4->flow_key.src_port == 12345);
        PFL_EXPECT(decoded.ipv4->flow_key.dst_port == 443);
        PFL_EXPECT(decoded.ipv4->flow_key.protocol == ProtocolId::tcp);
        PFL_EXPECT(decoded.ipv4->packet_ref.packet_index == 3);
        PFL_EXPECT(decoded.ipv4->packet_ref.byte_offset == 128);
        PFL_EXPECT(decoded.ipv4->packet_ref.ts_sec == 1);
        PFL_EXPECT(decoded.ipv4->packet_ref.ts_usec == 10);
    }

    {
        PacketDecoder decoder {};
        const RawPcapPacket raw_packet {
            .packet_index = 4,
            .ts_sec = 1,
            .ts_usec = 11,
            .captured_length = static_cast<std::uint32_t>(udp_packet.size()),
            .original_length = static_cast<std::uint32_t>(udp_packet.size()),
            .data_offset = 256,
            .bytes = udp_packet,
        };

        const auto decoded = decoder.decode_ethernet(raw_packet);
        PFL_EXPECT(decoded.ipv4.has_value());
        PFL_EXPECT(decoded.ipv4->flow_key.src_addr == ipv4(10, 0, 0, 3));
        PFL_EXPECT(decoded.ipv4->flow_key.dst_addr == ipv4(10, 0, 0, 4));
        PFL_EXPECT(decoded.ipv4->flow_key.src_port == 5353);
        PFL_EXPECT(decoded.ipv4->flow_key.dst_port == 53);
        PFL_EXPECT(decoded.ipv4->flow_key.protocol == ProtocolId::udp);
        PFL_EXPECT(decoded.ipv4->packet_ref.ts_sec == 1);
        PFL_EXPECT(decoded.ipv4->packet_ref.ts_usec == 11);
    }

    {
        PacketDecoder decoder {};
        const auto full_udp_packet = make_ethernet_ipv4_udp_packet_with_payload(
            ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6), 53530, 443, 8);
        auto captured_udp_packet = full_udp_packet;
        captured_udp_packet.resize(full_udp_packet.size() - 4U);

        const RawPcapPacket raw_packet {
            .packet_index = 5,
            .ts_sec = 1,
            .ts_usec = 12,
            .captured_length = static_cast<std::uint32_t>(captured_udp_packet.size()),
            .original_length = static_cast<std::uint32_t>(full_udp_packet.size()),
            .data_offset = 320,
            .bytes = captured_udp_packet,
        };

        const auto decoded = decoder.decode_ethernet(raw_packet);
        PFL_EXPECT(decoded.ipv4.has_value());
        PFL_EXPECT(decoded.ipv4->flow_key.src_addr == ipv4(10, 0, 0, 5));
        PFL_EXPECT(decoded.ipv4->flow_key.dst_addr == ipv4(10, 0, 0, 6));
        PFL_EXPECT(decoded.ipv4->flow_key.src_port == 53530);
        PFL_EXPECT(decoded.ipv4->flow_key.dst_port == 443);
        PFL_EXPECT(decoded.ipv4->flow_key.protocol == ProtocolId::udp);
        PFL_EXPECT(decoded.ipv4->packet_ref.payload_length == 4U);
        PFL_EXPECT(decoded.ipv4->packet_ref.captured_length == captured_udp_packet.size());
        PFL_EXPECT(decoded.ipv4->packet_ref.original_length == full_udp_packet.size());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_import_counts.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );

        CaptureState state {};
        CaptureImporter importer {};
        PFL_EXPECT(importer.import_capture(path, state));
        PFL_EXPECT(state.summary.packet_count == 2);
        PFL_EXPECT(state.summary.flow_count == 2);
        PFL_EXPECT(state.ipv4_connections.size() == 2);
    }

    {
        CaptureSession session {};
        const auto path =
            std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "tls" / "tls_1_3_client_hello_5.pcap";
        PFL_EXPECT(session.open_capture(path));

        const auto rows = session.list_flows();
        const auto flow_it = std::find_if(rows.begin(), rows.end(), [](const FlowRow& row) {
            return row.protocol_hint == "tls";
        });
        PFL_EXPECT(flow_it != rows.end());
        PFL_EXPECT(flow_it->service_hint == "p101-fmf.icloud.com");
    }

    {
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {};
        packets.reserve(11U);
        for (std::uint32_t index = 0U; index < 11U; ++index) {
            packets.push_back({
                100U + index,
                make_ethernet_ipv4_tcp_packet_with_payload(
                    ipv4(10, 10, 0, 1),
                    ipv4(10, 10, 0, 2),
                    41000,
                    41001,
                    512U,
                    0x18
                ),
            });
        }

        const auto path = write_temp_pcap("pfl_import_prefix_payload_lengths_after_hint_budget.pcap",
                                          make_classic_pcap(packets));

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 11U);
        PFL_EXPECT(session.summary().flow_count == 1U);

        const auto flow_packets = session.list_flow_packets(0);
        PFL_EXPECT(flow_packets.size() == 11U);
        PFL_EXPECT(flow_packets.back().payload_length == 512U);

        const auto packet = session.find_packet(10U);
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(packet->payload_length == 512U);
    }

    {
        const auto large_import_packet = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 0, 3, 1),
            ipv4(10, 0, 3, 2),
            33001,
            443,
            static_cast<std::uint16_t>(kMinCapturedLengthForStagedImportBytes + 1024U - 40U),
            0x18
        );
        const auto path = write_temp_pcap(
            "pfl_import_large_packet_staged_threshold.pcap",
            make_classic_pcap({{100, large_import_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);

        const auto rows = session.list_flow_packets(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows.front().captured_length == large_import_packet.size());
        PFL_EXPECT(rows.front().payload_length ==
                   static_cast<std::uint32_t>(large_import_packet.size() - 14U - 20U - 20U));
    }

    {
        const auto full_udp_packet = make_ethernet_ipv4_udp_packet_with_payload(
            ipv4(10, 0, 1, 1), ipv4(10, 0, 1, 2), 54000, 443, 8);
        auto captured_udp_packet = full_udp_packet;
        captured_udp_packet.resize(full_udp_packet.size() - 4U);

        const auto path = write_temp_pcap(
            "pfl_import_truncated_udp_visible.pcap",
            make_classic_pcap_with_captured_lengths({
                ClassicPcapCapturedRecord {
                    .ts_usec = 100U,
                    .captured_bytes = captured_udp_packet,
                    .original_length = static_cast<std::uint32_t>(full_udp_packet.size()),
                },
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(packet->captured_length == captured_udp_packet.size());
        PFL_EXPECT(packet->original_length == full_udp_packet.size());
        PFL_EXPECT(packet->payload_length == 4U);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "udp" / "udp_truncated_quic_like_payload_3.pcap"
        ));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(packet->captured_length == 74U);
        PFL_EXPECT(packet->original_length == 332U);
        PFL_EXPECT(packet->payload_length == 32U);

        const auto rows = session.list_flow_packets(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows.front().payload_length == 32U);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "tcp" / "ipv4_pre_offload_like_tcp_1.pcap"
        ));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(packet->captured_length == 60U);
        PFL_EXPECT(packet->original_length == 60U);

        const auto rows = session.list_flow_packets(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows.front().captured_length == 60U);
        PFL_EXPECT(rows.front().original_length == 60U);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "udp" / "udp_truncated_manual_1.pcap"
        ));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);

        const auto packet = session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(packet->captured_length == 60U);
        PFL_EXPECT(packet->original_length == 142U);

        const auto rows = session.list_flow_packets(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows.front().captured_length == 60U);
        PFL_EXPECT(rows.front().original_length == 142U);
    }

    {
        const auto reverse_tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 443, 12345);
        const auto path = write_temp_pcap(
            "pfl_import_reverse_flow.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, reverse_tcp_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 2);
        PFL_EXPECT(session.summary().flow_count == 1);
        PFL_EXPECT(session.state().ipv4_connections.size() == 1);

        const auto key = make_connection_key(FlowKeyV4 {
            .src_addr = ipv4(10, 0, 0, 1),
            .dst_addr = ipv4(10, 0, 0, 2),
            .src_port = 12345,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        });
        const auto* connection = session.state().ipv4_connections.find(key);
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(connection->has_flow_a);
        PFL_EXPECT(connection->has_flow_b);
        PFL_EXPECT(connection->flow_a.packet_count == 1);
        PFL_EXPECT(connection->flow_b.packet_count == 1);
    }

    {
        const auto path = write_temp_pcap(
            "pfl_import_with_null_context.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );

        CaptureState state {};
        CaptureImporter importer {};
        PFL_EXPECT(importer.import_capture(path, state, static_cast<OpenContext*>(nullptr)));
        PFL_EXPECT(state.summary.packet_count == 2);
        PFL_EXPECT(state.summary.flow_count == 2);
    }

    {
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {};
        packets.reserve(1001);
        for (std::uint32_t index = 0; index < 1001U; ++index) {
            packets.push_back({100U + index, tcp_packet});
        }

        const auto path = write_temp_pcap(
            "pfl_import_progress_context.pcap",
            make_classic_pcap(packets)
        );

        CaptureState state {};
        CaptureImporter importer {};
        OpenContext ctx {};
        std::uint32_t callback_count = 0U;
        OpenProgress last_progress {};
        ctx.on_progress = [&](const OpenProgress& progress) {
            ++callback_count;
            last_progress = progress;
        };

        PFL_EXPECT(importer.import_capture(path, state, &ctx));
        PFL_EXPECT(ctx.progress.packets_processed == 1001U);
        PFL_EXPECT(ctx.progress.bytes_processed == static_cast<std::uint64_t>(tcp_packet.size()) * 1001U);
        PFL_EXPECT(ctx.progress.total_bytes == static_cast<std::uint64_t>(std::filesystem::file_size(path)));
        PFL_EXPECT(callback_count == 2U);
        PFL_EXPECT(last_progress.packets_processed == ctx.progress.packets_processed);
        PFL_EXPECT(last_progress.bytes_processed == ctx.progress.bytes_processed);
        PFL_EXPECT(state.summary.packet_count == 1001U);
        PFL_EXPECT(state.summary.flow_count == 1U);
    }
    {
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {};
        packets.reserve(5000);
        for (std::uint32_t index = 0; index < 5000U; ++index) {
            packets.push_back({100U + index, tcp_packet});
        }

        const auto path = write_temp_pcap(
            "pfl_import_cancelled_context.pcap",
            make_classic_pcap(packets)
        );

        CaptureState state {};
        CaptureImporter importer {};
        OpenContext ctx {};
        std::uint32_t callback_count = 0U;
        ctx.on_progress = [&](const OpenProgress&) {
            ++callback_count;
        };
        ctx.request_cancel();

        PFL_EXPECT(!importer.import_capture(path, state, &ctx));
        PFL_EXPECT(ctx.progress.packets_processed == 0U);
        PFL_EXPECT(ctx.progress.bytes_processed == 0U);
        PFL_EXPECT(ctx.progress.total_bytes == static_cast<std::uint64_t>(std::filesystem::file_size(path)));
        PFL_EXPECT(callback_count == 1U);
        PFL_EXPECT(state.summary.packet_count == 0U);
        PFL_EXPECT(state.summary.flow_count == 0U);
    }
    {
        auto truncated_bytes = make_classic_pcap({{100, tcp_packet}, {200, udp_packet}});
        truncated_bytes.resize(truncated_bytes.size() - 5U);
        const auto path = write_temp_pcap("pfl_import_partial_success.pcap", truncated_bytes);

        CaptureState state {};
        CaptureImporter importer {};
        OpenContext ctx {};
        const auto result = importer.import_capture_result(path, state, &ctx);

        PFL_EXPECT(result == CaptureImportResult::partial_success_with_warning);
        PFL_EXPECT(state.summary.packet_count == 1U);
        PFL_EXPECT(state.summary.flow_count == 1U);
        PFL_EXPECT(ctx.failure.has_file_offset);
        PFL_EXPECT(ctx.failure.has_packet_index);
        PFL_EXPECT(ctx.failure.packet_index == 1U);
        PFL_EXPECT(ctx.failure.packets_processed == 1U);
        PFL_EXPECT(!ctx.failure.reason.empty());

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.has_capture());
        PFL_EXPECT(session.is_partial_open());
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);
        PFL_EXPECT(session.partial_open_failure().has_packet_index);
        PFL_EXPECT(session.partial_open_failure().packet_index == 1U);
        PFL_EXPECT(session.find_packet(0).has_value());
        PFL_EXPECT(!session.find_packet(1).has_value());
    }
}

}  // namespace pfl::tests










