#include <filesystem>
#include <variant>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexReader.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

void expect_matching_rows(const std::vector<FlowRow>& left, const std::vector<FlowRow>& right) {
    PFL_EXPECT(left.size() == right.size());
    for (std::size_t index = 0; index < left.size(); ++index) {
        PFL_EXPECT(left[index].index == right[index].index);
        PFL_EXPECT(left[index].family == right[index].family);
        PFL_EXPECT(left[index].packet_count == right[index].packet_count);
        PFL_EXPECT(left[index].total_bytes == right[index].total_bytes);
        PFL_EXPECT(left[index].key == right[index].key);
        PFL_EXPECT(left[index].protocol_hint == right[index].protocol_hint);
        PFL_EXPECT(left[index].service_hint == right[index].service_hint);
        PFL_EXPECT(left[index].has_fragmented_packets == right[index].has_fragmented_packets);
        PFL_EXPECT(left[index].fragmented_packet_count == right[index].fragmented_packet_count);
    }
}

void expect_matching_packets(const std::vector<PacketRef>& left, const std::vector<PacketRef>& right) {
    PFL_EXPECT(left.size() == right.size());
    for (std::size_t index = 0; index < left.size(); ++index) {
        PFL_EXPECT(left[index] == right[index]);
    }
}

void expect_matching_stream_rows(const std::vector<StreamItemRow>& left, const std::vector<StreamItemRow>& right) {
    PFL_EXPECT(left.size() == right.size());
    for (std::size_t index = 0; index < left.size(); ++index) {
        PFL_EXPECT(left[index].direction_text == right[index].direction_text);
        PFL_EXPECT(left[index].label == right[index].label);
        PFL_EXPECT(left[index].byte_count == right[index].byte_count);
        PFL_EXPECT(left[index].packet_count == right[index].packet_count);
        PFL_EXPECT(left[index].packet_indices == right[index].packet_indices);
    }
}

void append_be16(std::vector<std::uint8_t>& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_be24(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::vector<std::uint8_t> make_tls_handshake_record_for_index_test(const std::uint8_t handshake_type, const std::vector<std::uint8_t>& body) {
    std::vector<std::uint8_t> handshake {};
    handshake.push_back(handshake_type);
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<std::uint8_t> record {};
    record.push_back(0x16U);
    append_be16(record, 0x0303U);
    append_be16(record, static_cast<std::uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}
}  // namespace

void run_index_tests() {
    const auto forward_packet = make_ethernet_ipv4_tcp_packet(ipv4(172, 16, 0, 10), ipv4(172, 16, 0, 20), 40000, 443);
    const auto reverse_packet = make_ethernet_ipv4_tcp_packet(ipv4(172, 16, 0, 20), ipv4(172, 16, 0, 10), 443, 40000);
    const auto source_path = write_temp_pcap(
        "pfl_index_roundtrip_source.pcap",
        make_classic_pcap({{100, forward_packet}, {200, reverse_packet}})
    );
    const auto index_path = std::filesystem::temp_directory_path() / "pfl_capture_state.idx";
    const auto exported_path = std::filesystem::temp_directory_path() / "pfl_index_exported_flow.pcap";
    std::filesystem::remove(index_path);
    std::filesystem::remove(exported_path);

    CaptureSession original_session {};
    PFL_EXPECT(original_session.open_capture(source_path));
    PFL_EXPECT(original_session.has_capture());
    PFL_EXPECT(original_session.has_source_capture());
    PFL_EXPECT(!original_session.opened_from_index());
    PFL_EXPECT(original_session.summary().packet_count == 2);
    PFL_EXPECT(original_session.summary().flow_count == 1);
    const auto original_rows = original_session.list_flows();
    const auto original_packets = original_session.flow_packets(0);
    PFL_EXPECT(original_packets.has_value());
    PFL_EXPECT(original_session.save_index(index_path));
    PFL_EXPECT(std::filesystem::exists(index_path));

    {
        CaptureSession loaded_session {};
        PFL_EXPECT(loaded_session.load_index(index_path));
        PFL_EXPECT(loaded_session.has_capture());
        PFL_EXPECT(loaded_session.has_source_capture());
        PFL_EXPECT(loaded_session.opened_from_index());
        PFL_EXPECT(loaded_session.capture_path() == source_path);
        PFL_EXPECT(loaded_session.summary().packet_count == original_session.summary().packet_count);
        PFL_EXPECT(loaded_session.summary().flow_count == original_session.summary().flow_count);
        PFL_EXPECT(loaded_session.summary().total_bytes == original_session.summary().total_bytes);
        expect_matching_rows(loaded_session.list_flows(), original_rows);

        const auto loaded_packets = loaded_session.flow_packets(0);
        PFL_EXPECT(loaded_packets.has_value());
        expect_matching_packets(*loaded_packets, *original_packets);

        const auto first_packet = loaded_session.find_packet(0);
        PFL_EXPECT(first_packet.has_value());
        PFL_EXPECT(first_packet->ts_usec == 100);
        PFL_EXPECT(first_packet->captured_length == forward_packet.size());

        const auto second_packet = loaded_session.find_packet(1);
        PFL_EXPECT(second_packet.has_value());
        PFL_EXPECT(second_packet->ts_usec == 200);
        PFL_EXPECT(second_packet->captured_length == reverse_packet.size());

        const auto reloaded_bytes = loaded_session.read_packet_data(*first_packet);
        PFL_EXPECT(reloaded_bytes == forward_packet);

        const auto details = loaded_session.read_packet_details(*first_packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->ipv4.src_addr == ipv4(172, 16, 0, 10));
        PFL_EXPECT(details->ipv4.dst_addr == ipv4(172, 16, 0, 20));
        PFL_EXPECT(details->tcp.src_port == 40000);
        PFL_EXPECT(details->tcp.dst_port == 443);

        PFL_EXPECT(!loaded_session.read_packet_hex_dump(*first_packet).empty());
        PFL_EXPECT(loaded_session.export_flow_to_pcap(0, exported_path));
    }

    {
        CaptureSession exported_session {};
        PFL_EXPECT(exported_session.open_capture(exported_path));
        PFL_EXPECT(exported_session.summary().packet_count == 2);
        PFL_EXPECT(exported_session.summary().flow_count == 1);
        PFL_EXPECT(exported_session.list_flows().size() == 1);
    }

    {
        CaptureSession capture_input_session {};
        PFL_EXPECT(capture_input_session.open_input(source_path));
        PFL_EXPECT(capture_input_session.summary().packet_count == 2);
        PFL_EXPECT(capture_input_session.capture_path() == source_path);

        CaptureSession index_input_session {};
        PFL_EXPECT(index_input_session.open_input(index_path));
        PFL_EXPECT(index_input_session.summary().packet_count == 2);
        PFL_EXPECT(index_input_session.capture_path() == source_path);
        expect_matching_rows(index_input_session.list_flows(), original_rows);

        PFL_EXPECT(!looks_like_index_file(source_path));
        PFL_EXPECT(looks_like_index_file(index_path));
        PFL_EXPECT(validate_index_magic(index_path));
        PFL_EXPECT(!validate_index_magic(source_path));
    }

    {
        CaptureIndexReader reader {};
        CaptureState loaded_state {};
        std::filesystem::path loaded_capture_path {};
        CaptureSourceInfo source_info {};
        PFL_EXPECT(reader.read(index_path, loaded_state, loaded_capture_path, &source_info));
        PFL_EXPECT(loaded_capture_path == source_path);
        PFL_EXPECT(source_info.capture_path == source_path);
        PFL_EXPECT(loaded_state.summary.packet_count == 2);
        PFL_EXPECT(loaded_state.summary.flow_count == 1);
        PFL_EXPECT(loaded_state.ipv4_connections.size() == 1);
        PFL_EXPECT(loaded_state.ipv6_connections.size() == 0);
        PFL_EXPECT(source_info.content_fingerprint != 0U);
        PFL_EXPECT(validate_capture_source(source_info));

        auto mismatched_info = source_info;
        mismatched_info.file_size += 1;
        PFL_EXPECT(!validate_capture_source(mismatched_info, source_path));
    }

    {
        const auto truncated_index_path = write_temp_binary_file("pfl_capture_state_truncated.idx", {0x50, 0x46, 0x4c});
        CaptureSession session {};
        PFL_EXPECT(!session.load_index(truncated_index_path));

        CaptureIndexReader reader {};
        CaptureState state {};
        std::filesystem::path capture_path {};
        PFL_EXPECT(!reader.read(truncated_index_path, state, capture_path));
    }

    {
        CaptureSourceInfo source_info {};
        PFL_EXPECT(read_capture_source_info(source_path, source_info));
        PFL_EXPECT(validate_capture_source(source_info, source_path));

        auto mismatched_info = source_info;
        mismatched_info.last_write_time += 1;
        PFL_EXPECT(!validate_capture_source(mismatched_info, source_path));
    }

    {
        const auto missing_source_path = write_temp_pcap(
            "pfl_index_missing_source.pcap",
            make_classic_pcap({{100, forward_packet}, {200, reverse_packet}})
        );
        const auto missing_index_path = std::filesystem::temp_directory_path() / "pfl_missing_source.idx";
        const auto moved_source_path = std::filesystem::temp_directory_path() / "pfl_index_missing_source.gone.pcap";
        const auto mismatched_source_path = std::filesystem::temp_directory_path() / "pfl_index_missing_source_mismatch.pcap";
        const auto should_not_export_path = std::filesystem::temp_directory_path() / "pfl_should_not_export.pcap";
        std::filesystem::remove(missing_index_path);
        std::filesystem::remove(moved_source_path);
        std::filesystem::remove(mismatched_source_path);
        std::filesystem::remove(should_not_export_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(missing_source_path));
        PFL_EXPECT(session.save_index(missing_index_path));

        CaptureSourceInfo expected_source_info {};
        PFL_EXPECT(read_capture_source_info(missing_source_path, expected_source_info));

        std::filesystem::rename(missing_source_path, moved_source_path);

        CaptureSession loaded_session {};
        PFL_EXPECT(loaded_session.load_index(missing_index_path));
        PFL_EXPECT(loaded_session.has_capture());
        PFL_EXPECT(!loaded_session.has_source_capture());
        PFL_EXPECT(loaded_session.opened_from_index());
        PFL_EXPECT(loaded_session.capture_path() == missing_source_path);
        PFL_EXPECT(loaded_session.summary().packet_count == 2);
        PFL_EXPECT(loaded_session.list_flows().size() == 1);

        const auto packet = loaded_session.find_packet(0);
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(loaded_session.read_packet_data(*packet).empty());
        PFL_EXPECT(!loaded_session.read_packet_details(*packet).has_value());
        PFL_EXPECT(loaded_session.read_packet_hex_dump(*packet).empty());
        PFL_EXPECT(!loaded_session.export_flow_to_pcap(0, should_not_export_path));
        PFL_EXPECT(!loaded_session.save_index(std::filesystem::temp_directory_path() / "pfl_should_not_save.idx"));

        auto mismatched_bytes = make_classic_pcap({{100, forward_packet}, {200, reverse_packet}});
        PFL_EXPECT(!mismatched_bytes.empty());
        mismatched_bytes.back() ^= 0xFFU;
        std::ofstream mismatched_stream(mismatched_source_path, std::ios::binary | std::ios::trunc);
        mismatched_stream.write(reinterpret_cast<const char*>(mismatched_bytes.data()), static_cast<std::streamsize>(mismatched_bytes.size()));
        mismatched_stream.close();
        std::filesystem::last_write_time(mismatched_source_path, std::filesystem::last_write_time(moved_source_path));

        CaptureSourceInfo mismatched_source_info {};
        PFL_EXPECT(read_capture_source_info(mismatched_source_path, mismatched_source_info));
        PFL_EXPECT(mismatched_source_info.file_size == expected_source_info.file_size);
        PFL_EXPECT(mismatched_source_info.last_write_time == expected_source_info.last_write_time);
        PFL_EXPECT(mismatched_source_info.content_fingerprint != expected_source_info.content_fingerprint);

        PFL_EXPECT(!loaded_session.attach_source_capture(mismatched_source_path));
        PFL_EXPECT(!loaded_session.has_source_capture());
        PFL_EXPECT(loaded_session.capture_path() == missing_source_path);

        PFL_EXPECT(loaded_session.attach_source_capture(moved_source_path));
        PFL_EXPECT(loaded_session.has_source_capture());
        PFL_EXPECT(loaded_session.capture_path() == moved_source_path);
        PFL_EXPECT(!loaded_session.read_packet_data(*packet).empty());
        PFL_EXPECT(loaded_session.read_packet_details(*packet).has_value());
        PFL_EXPECT(!loaded_session.read_packet_hex_dump(*packet).empty());
        PFL_EXPECT(loaded_session.export_flow_to_pcap(0, should_not_export_path));
        PFL_EXPECT(loaded_session.save_index(std::filesystem::temp_directory_path() / "pfl_attached_source_save.idx"));
    }

    {
        const auto tls_record = make_tls_handshake_record_for_index_test(0x02U, {0x10, 0x11, 0x12, 0x13, 0x14, 0x15});
        const auto packet_a_payload = std::vector<std::uint8_t>(tls_record.begin(), tls_record.begin() + 7);
        const auto packet_b_payload = std::vector<std::uint8_t>(tls_record.begin() + 7, tls_record.end());
        const auto source_stream_path = write_temp_pcap(
            "pfl_index_stream_roundtrip_source.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2), 53000, 443, packet_a_payload, 0x18)},
                {200, make_ethernet_ipv4_tcp_packet_with_bytes_payload(ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2), 53000, 443, packet_b_payload, 0x18)},
            })
        );
        const auto stream_index_path = std::filesystem::temp_directory_path() / "pfl_index_stream_roundtrip.idx";
        std::filesystem::remove(stream_index_path);

        CaptureSession original_stream_session {};
        PFL_EXPECT(original_stream_session.open_capture(source_stream_path, CaptureImportOptions {.mode = ImportMode::fast}));
        const auto original_stream_rows = original_stream_session.list_flow_stream_items(0);
        const auto expected_stream_packet_indices = std::vector<std::uint64_t> {0, 1};
        PFL_EXPECT(original_stream_rows.size() == 1);
        PFL_EXPECT(original_stream_rows[0].label == "TLS ServerHello");
        PFL_EXPECT(original_stream_rows[0].packet_indices == expected_stream_packet_indices);
        PFL_EXPECT(original_stream_session.save_index(stream_index_path));

        CaptureSession loaded_stream_session {};
        PFL_EXPECT(loaded_stream_session.load_index(stream_index_path));
        PFL_EXPECT(loaded_stream_session.has_source_capture());
        const auto loaded_stream_rows = loaded_stream_session.list_flow_stream_items(0);
        expect_matching_stream_rows(loaded_stream_rows, original_stream_rows);
        PFL_EXPECT(loaded_stream_session.summary().packet_count == original_stream_session.summary().packet_count);
        PFL_EXPECT(loaded_stream_session.summary().flow_count == original_stream_session.summary().flow_count);
        PFL_EXPECT(loaded_stream_session.summary().total_bytes == original_stream_session.summary().total_bytes);
    }
}

}  // namespace pfl::tests
