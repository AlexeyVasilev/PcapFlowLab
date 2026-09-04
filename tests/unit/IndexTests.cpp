#include <algorithm>
#include <filesystem>
#include <sstream>
#include <variant>
#include <vector>

#include "../../core/open_context.h"
#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexReader.h"
#include "core/index/Serialization.h"
#include "core/services/CaptureImportApplication.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

void expect_matching_rows(const std::vector<FlowRow>& left, const std::vector<FlowRow>& right) {
    PFL_EXPECT(left.size() == right.size());
    for (std::size_t index = 0; index < left.size(); ++index) {
        PFL_EXPECT(left[index].index == right[index].index);
        PFL_EXPECT(left[index].family == right[index].family);
        PFL_EXPECT(left[index].packet_count == right[index].packet_count);
        PFL_EXPECT(left[index].total_bytes == right[index].total_bytes);
        PFL_EXPECT(left[index].key == right[index].key);
        PFL_EXPECT(left[index].protocol_path_id == right[index].protocol_path_id);
        PFL_EXPECT(left[index].protocol_hint == right[index].protocol_hint);
        PFL_EXPECT(left[index].service_hint == right[index].service_hint);
        PFL_EXPECT(left[index].has_fragmented_packets == right[index].has_fragmented_packets);
        PFL_EXPECT(left[index].fragmented_packet_count == right[index].fragmented_packet_count);
        PFL_EXPECT(left[index].protocol_text == right[index].protocol_text);
        PFL_EXPECT(left[index].address_a == right[index].address_a);
        PFL_EXPECT(left[index].port_a == right[index].port_a);
        PFL_EXPECT(left[index].endpoint_a == right[index].endpoint_a);
        PFL_EXPECT(left[index].address_b == right[index].address_b);
        PFL_EXPECT(left[index].port_b == right[index].port_b);
        PFL_EXPECT(left[index].endpoint_b == right[index].endpoint_b);
    }
}

void expect_matching_packets(const std::vector<PacketRef>& left, const std::vector<PacketRef>& right) {
    PFL_EXPECT(left.size() == right.size());
    for (std::size_t index = 0; index < left.size(); ++index) {
        PFL_EXPECT(left[index].packet_index == right[index].packet_index);
        PFL_EXPECT(left[index].byte_offset == right[index].byte_offset);
        PFL_EXPECT(left[index].data_link_type == right[index].data_link_type);
        PFL_EXPECT(left[index].captured_length == right[index].captured_length);
        PFL_EXPECT(left[index].original_length == right[index].original_length);
        PFL_EXPECT(left[index].ts_sec == right[index].ts_sec);
        PFL_EXPECT(left[index].ts_usec == right[index].ts_usec);
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

void expect_index_roundtrip_preserves_protocol_path_identity(
    const std::filesystem::path& relative_fixture_path,
    const std::size_t expected_flow_count
) {
    auto fixture_stem = relative_fixture_path.filename().string();
    std::replace(fixture_stem.begin(), fixture_stem.end(), '.', '_');
    const auto index_path =
        std::filesystem::temp_directory_path() / ("pfl_protocol_path_roundtrip_" + fixture_stem + ".idx");
    std::filesystem::remove(index_path);

    CaptureSession original_session {};
    PFL_REQUIRE(original_session.open_capture(fixture_path(relative_fixture_path)));
    const auto original_rows = original_session.list_flows();
    PFL_EXPECT(original_rows.size() == expected_flow_count);
    std::vector<std::vector<PacketRef>> original_packets_by_flow {};
    original_packets_by_flow.reserve(original_rows.size());
    for (std::size_t flow_index = 0; flow_index < original_rows.size(); ++flow_index) {
        const auto packets = original_session.flow_packets(flow_index);
        PFL_REQUIRE(packets.has_value());
        original_packets_by_flow.push_back(*packets);
    }

    PFL_REQUIRE(original_session.save_index(index_path));

    CaptureSession loaded_session {};
    PFL_REQUIRE(loaded_session.load_index(index_path));
    PFL_EXPECT(loaded_session.opened_from_index());
    const auto loaded_rows = loaded_session.list_flows();
    PFL_EXPECT(loaded_rows.size() == expected_flow_count);
    expect_matching_rows(loaded_rows, original_rows);

    for (std::size_t flow_index = 0; flow_index < loaded_rows.size(); ++flow_index) {
        const auto loaded_packets = loaded_session.flow_packets(flow_index);
        PFL_REQUIRE(loaded_packets.has_value());
        expect_matching_packets(*loaded_packets, original_packets_by_flow[flow_index]);
    }
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
        CaptureState locator_state {};
        append_capture_packet_locator_entry(locator_state, 0U, 24U);
        append_capture_packet_locator_entry(locator_state, 1U, 24U + kCapturePacketLocatorStrideBytes - 1U);
        append_capture_packet_locator_entry(locator_state, 2U, 24U + kCapturePacketLocatorStrideBytes);
        append_capture_packet_locator_entry(locator_state, 3U, 24U + kCapturePacketLocatorStrideBytes + 128U);

        PFL_EXPECT(locator_state.packet_locator.size() == 2U);
        PFL_EXPECT(locator_state.packet_locator[0].packet_index == 0U);
        PFL_EXPECT(locator_state.packet_locator[0].file_offset == 24U);
        PFL_EXPECT(locator_state.packet_locator[1].packet_index == 2U);
        PFL_EXPECT(locator_state.packet_locator[1].file_offset == 24U + kCapturePacketLocatorStrideBytes);
    }

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

        const auto first_source_packet = loaded_session.lookup_source_packet(0U);
        PFL_EXPECT(first_source_packet.status == SourcePacketLookupStatus::found);
        PFL_REQUIRE(first_source_packet.packet.has_value());
        PFL_REQUIRE(first_source_packet.source_packet.has_value());
        PFL_EXPECT(first_source_packet.packet->packet_index == 0U);
        PFL_EXPECT(first_source_packet.packet->ts_usec == 100U);
        PFL_EXPECT(first_source_packet.packet->captured_length == forward_packet.size());
        PFL_EXPECT(first_source_packet.source_packet->bytes == forward_packet);

        const auto out_of_range_source_packet = loaded_session.lookup_source_packet(2U);
        PFL_EXPECT(out_of_range_source_packet.status == SourcePacketLookupStatus::out_of_range);
        PFL_EXPECT(!out_of_range_source_packet.packet.has_value());
        PFL_EXPECT(!out_of_range_source_packet.source_packet.has_value());

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
        CaptureSourceInfo source_info {};
        detail::CaptureIndexV16CompleteReadResult read_result {};
        PFL_REQUIRE(reader.read_v16_complete(index_path, read_result));
        source_info = CaptureSourceInfo {
            .capture_path = detail::filesystem_path_from_generic_utf8(read_result.header.source_capture_path_utf8),
            .format = read_result.header.source_format,
            .file_size = read_result.header.source_file_size,
            .last_write_time = read_result.header.source_last_write_time,
            .content_fingerprint = read_result.header.source_content_fingerprint,
        };
        PFL_EXPECT(source_info.capture_path == source_path);
        PFL_EXPECT(read_result.fast_statistics_tier.capture_statistics_snapshot.total_packet_count == 2);
        PFL_EXPECT(read_result.fast_statistics_tier.capture_statistics_snapshot.total_flow_count == 1);
        PFL_EXPECT(read_result.metadata.ipv4_connections.size() == 1);
        PFL_EXPECT(read_result.metadata.ipv6_connections.empty());
        PFL_EXPECT(read_result.metadata.packet_locator_sections.size() == 1U);
        PFL_EXPECT(read_result.metadata.packet_locator_sections.front().entry_count == original_session.state().packet_locator.size());
        PFL_EXPECT(source_info.content_fingerprint != 0U);
        PFL_EXPECT(validate_capture_source(source_info));

        auto mismatched_info = source_info;
        mismatched_info.file_size += 1;
        PFL_EXPECT(!validate_capture_source(mismatched_info, source_path));
    }

    {
        ConnectionV4 empty_connection_v4 {};
        std::stringstream empty_v4_stream(std::ios::in | std::ios::out | std::ios::binary);
        PFL_REQUIRE(detail::write_connection(empty_v4_stream, empty_connection_v4));
        empty_v4_stream.seekg(0);
        ConnectionV4 decoded_empty_v4 {};
        PFL_EXPECT(!detail::read_connection(empty_v4_stream, decoded_empty_v4));

        ConnectionV6 empty_connection_v6 {};
        std::stringstream empty_v6_stream(std::ios::in | std::ios::out | std::ios::binary);
        PFL_REQUIRE(detail::write_connection(empty_v6_stream, empty_connection_v6));
        empty_v6_stream.seekg(0);
        ConnectionV6 decoded_empty_v6 {};
        PFL_EXPECT(!detail::read_connection(empty_v6_stream, decoded_empty_v6));

        const FlowKeyV4 one_direction_flow {
            .src_addr = ipv4(198, 51, 100, 10),
            .dst_addr = ipv4(198, 51, 100, 20),
            .src_port = 46000,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        };
        ConnectionV4 one_direction_connection {};
        one_direction_connection.key = make_connection_key(one_direction_flow);
        one_direction_connection.add_packet(one_direction_flow, PacketRef {
            .packet_index = 0U,
            .ts_sec = 0U,
            .ts_usec = 100U,
            .captured_length = static_cast<std::uint32_t>(forward_packet.size()),
            .original_length = static_cast<std::uint32_t>(forward_packet.size()),
        });
        std::stringstream one_direction_stream(std::ios::in | std::ios::out | std::ios::binary);
        PFL_REQUIRE(detail::write_connection(one_direction_stream, one_direction_connection));
        one_direction_stream.seekg(0);
        ConnectionV4 decoded_one_direction {};
        PFL_REQUIRE(detail::read_connection(one_direction_stream, decoded_one_direction));
        PFL_EXPECT(decoded_one_direction.has_flow_a);
        PFL_EXPECT(!decoded_one_direction.has_flow_b);
        PFL_EXPECT(first_observed_endpoint_a(decoded_one_direction)->addr == one_direction_flow.src_addr);
        PFL_EXPECT(first_observed_endpoint_b(decoded_one_direction)->addr == one_direction_flow.dst_addr);

        ConnectionV4 bidirectional_connection {};
        bidirectional_connection.key = make_connection_key(one_direction_flow);
        bidirectional_connection.add_packet(one_direction_flow, PacketRef {
            .packet_index = 0U,
            .ts_sec = 0U,
            .ts_usec = 100U,
            .captured_length = static_cast<std::uint32_t>(forward_packet.size()),
            .original_length = static_cast<std::uint32_t>(forward_packet.size()),
        });
        bidirectional_connection.add_packet(FlowKeyV4 {
            .src_addr = one_direction_flow.dst_addr,
            .dst_addr = one_direction_flow.src_addr,
            .src_port = one_direction_flow.dst_port,
            .dst_port = one_direction_flow.src_port,
            .protocol = one_direction_flow.protocol,
        }, PacketRef {
            .packet_index = 1U,
            .ts_sec = 0U,
            .ts_usec = 200U,
            .captured_length = static_cast<std::uint32_t>(reverse_packet.size()),
            .original_length = static_cast<std::uint32_t>(reverse_packet.size()),
        });
        std::stringstream bidirectional_stream(std::ios::in | std::ios::out | std::ios::binary);
        PFL_REQUIRE(detail::write_connection(bidirectional_stream, bidirectional_connection));
        bidirectional_stream.seekg(0);
        ConnectionV4 decoded_bidirectional {};
        PFL_REQUIRE(detail::read_connection(bidirectional_stream, decoded_bidirectional));
        PFL_EXPECT(decoded_bidirectional.has_flow_a);
        PFL_EXPECT(decoded_bidirectional.has_flow_b);
        PFL_EXPECT(first_observed_endpoint_a(decoded_bidirectional)->addr == one_direction_flow.src_addr);
        PFL_EXPECT(first_observed_endpoint_b(decoded_bidirectional)->addr == one_direction_flow.dst_addr);
        PFL_EXPECT(kCaptureIndexVersion == 16U);
    }
    {
        OpenContext ctx {};
        std::uint32_t callback_count = 0U;
        ctx.on_progress = [&](const OpenProgress&) {
            ++callback_count;
        };
        ctx.request_cancel();

        CaptureSession cancelled_session {};
        PFL_EXPECT(!cancelled_session.load_index(index_path, &ctx));
        PFL_EXPECT(!cancelled_session.has_capture());
        PFL_EXPECT(ctx.progress.total_bytes == static_cast<std::uint64_t>(std::filesystem::file_size(index_path)));
        PFL_EXPECT(callback_count >= 1U);

        CaptureIndexReader cancelled_reader {};
        detail::CaptureIndexV16CompleteReadResult cancelled_read_result {};
        PFL_EXPECT(!cancelled_reader.read_v16_complete(index_path, cancelled_read_result, &ctx));
        PFL_EXPECT(cancelled_read_result.fast_statistics_tier.capture_statistics_snapshot.total_packet_count == 0U);
    }

    {
        const auto truncated_index_path = write_temp_binary_file("pfl_capture_state_truncated.idx", {0x50, 0x46, 0x4c});
        CaptureSession session {};
        PFL_EXPECT(!session.load_index(truncated_index_path));
        PFL_EXPECT(session.last_open_error_text().find("incomplete or was not finalized") != std::string::npos);

        CaptureIndexReader reader {};
        detail::CaptureIndexV16CompleteReadResult read_result {};
        PFL_EXPECT(!reader.read_v16_complete(truncated_index_path, read_result));
    }

    {
        CaptureSourceInfo source_info {};
        PFL_EXPECT(read_capture_source_info(source_path, source_info));
        PFL_EXPECT(validate_capture_source(source_info, source_path));

        auto mismatched_info = source_info;
        mismatched_info.content_fingerprint += 1;
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

        const auto missing_source_packet = loaded_session.lookup_source_packet(0U);
        PFL_EXPECT(missing_source_packet.status == SourcePacketLookupStatus::source_unavailable);
        PFL_EXPECT(!missing_source_packet.packet.has_value());
        PFL_EXPECT(!missing_source_packet.source_packet.has_value());

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
        const auto same_address_capture_path = write_temp_pcap(
            "pfl_index_same_address_orientation_source.pcap",
            make_classic_pcap({{
                100,
                make_ethernet_ipv4_tcp_packet(ipv4(127, 0, 0, 1), ipv4(127, 0, 0, 1), 50000, 443)
            }})
        );
        const auto same_address_index_path = std::filesystem::temp_directory_path() / "pfl_index_same_address_orientation.idx";
        std::filesystem::remove(same_address_index_path);

        CaptureSession original_same_address_session {};
        PFL_REQUIRE(original_same_address_session.open_capture(same_address_capture_path));
        const auto original_same_address_rows = original_same_address_session.list_flows();
        PFL_REQUIRE(original_same_address_rows.size() == 1U);
        PFL_EXPECT(original_same_address_rows[0].endpoint_a == "127.0.0.1:50000");
        PFL_EXPECT(original_same_address_rows[0].endpoint_b == "127.0.0.1:443");
        PFL_REQUIRE(original_same_address_session.save_index(same_address_index_path));

        CaptureSession loaded_same_address_session {};
        PFL_REQUIRE(loaded_same_address_session.load_index(same_address_index_path));
        expect_matching_rows(loaded_same_address_session.list_flows(), original_same_address_rows);
    }

    {
        const auto reverse_first_capture_path = write_temp_pcap(
            "pfl_index_first_observed_orientation_source.pcap",
            make_classic_pcap({
                {200, make_ethernet_ipv4_tcp_packet(ipv4(203, 0, 113, 20), ipv4(203, 0, 113, 10), 443, 50000)},
                {100, make_ethernet_ipv4_tcp_packet(ipv4(203, 0, 113, 10), ipv4(203, 0, 113, 20), 50000, 443)},
            })
        );
        const auto reverse_first_index_path = std::filesystem::temp_directory_path() / "pfl_index_first_observed_orientation.idx";
        std::filesystem::remove(reverse_first_index_path);

        CaptureSession original_reverse_first_session {};
        PFL_REQUIRE(original_reverse_first_session.open_capture(reverse_first_capture_path));
        const auto original_reverse_first_rows = original_reverse_first_session.list_flows();
        PFL_REQUIRE(original_reverse_first_rows.size() == 1U);
        PFL_EXPECT(original_reverse_first_rows[0].endpoint_a == "203.0.113.20:443");
        PFL_EXPECT(original_reverse_first_rows[0].endpoint_b == "203.0.113.10:50000");
        const auto original_reverse_first_packets = original_reverse_first_session.list_flow_packets(0);
        PFL_REQUIRE(original_reverse_first_packets.size() == 2U);
        PFL_EXPECT(original_reverse_first_packets[0].direction_text == "A\xE2\x86\x92" "B");
        PFL_EXPECT(original_reverse_first_packets[1].direction_text == "B\xE2\x86\x92" "A");
        PFL_REQUIRE(original_reverse_first_session.save_index(reverse_first_index_path));

        CaptureSession loaded_reverse_first_session {};
        PFL_REQUIRE(loaded_reverse_first_session.load_index(reverse_first_index_path));
        expect_matching_rows(loaded_reverse_first_session.list_flows(), original_reverse_first_rows);
        const auto loaded_reverse_first_packets = loaded_reverse_first_session.list_flow_packets(0);
        PFL_REQUIRE(loaded_reverse_first_packets.size() == original_reverse_first_packets.size());
        for (std::size_t index = 0U; index < loaded_reverse_first_packets.size(); ++index) {
            PFL_EXPECT(loaded_reverse_first_packets[index].direction_text == original_reverse_first_packets[index].direction_text);
        }
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
        PFL_EXPECT(original_stream_session.open_capture(source_stream_path, CaptureImportOptions {}));
        const auto original_stream_rows = original_stream_session.list_flow_stream_items(0);
        const auto expected_stream_packet_indices = std::vector<std::uint64_t> {0, 1};
        PFL_EXPECT(original_stream_rows.size() == 1);
        PFL_EXPECT(original_stream_rows[0].label == "TLS ServerHello");
        PFL_EXPECT(original_stream_rows[0].packet_indices == expected_stream_packet_indices);
        PFL_EXPECT(original_stream_session.save_index(stream_index_path));

        CaptureSession loaded_stream_session {};
        PFL_EXPECT(loaded_stream_session.load_index(stream_index_path));
        PFL_EXPECT(loaded_stream_session.has_source_capture());
        PFL_EXPECT(loaded_stream_session.state().ipv4_connections.size() == 0U);
        const auto loaded_stream_rows = loaded_stream_session.list_flow_stream_items(0);
        expect_matching_stream_rows(loaded_stream_rows, original_stream_rows);
        const auto loaded_stream_prefix_rows = loaded_stream_session.list_flow_stream_items_for_packet_prefix(0, 2U, 2U);
        expect_matching_stream_rows(loaded_stream_prefix_rows, original_stream_rows);
        PFL_EXPECT(loaded_stream_session.summary().packet_count == original_stream_session.summary().packet_count);
        PFL_EXPECT(loaded_stream_session.summary().flow_count == original_stream_session.summary().flow_count);
        PFL_EXPECT(loaded_stream_session.summary().total_bytes == original_stream_session.summary().total_bytes);
    }

    {
        const auto http_stream_index_path = std::filesystem::temp_directory_path() / "pfl_index_http_stream_roundtrip.idx";
        std::filesystem::remove(http_stream_index_path);

        CaptureSession original_http_stream_session {};
        PFL_EXPECT(original_http_stream_session.open_capture(
            fixture_path(std::filesystem::path("parsing/http/http_get_1.pcap")),
            CaptureImportOptions {}
        ));
        const auto original_http_stream_rows = original_http_stream_session.list_flow_stream_items(0);
        PFL_REQUIRE(!original_http_stream_rows.empty());
        PFL_EXPECT(original_http_stream_session.save_index(http_stream_index_path));

        CaptureSession loaded_http_stream_session {};
        PFL_EXPECT(loaded_http_stream_session.load_index(http_stream_index_path));
        PFL_EXPECT(loaded_http_stream_session.has_source_capture());
        PFL_EXPECT(loaded_http_stream_session.state().ipv4_connections.size() == 0U);
        const auto loaded_http_stream_rows = loaded_http_stream_session.list_flow_stream_items(0);
        expect_matching_stream_rows(loaded_http_stream_rows, original_http_stream_rows);
    }

    expect_index_roundtrip_preserves_protocol_path_identity(
        std::filesystem::path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap"),
        2U
    );
    expect_index_roundtrip_preserves_protocol_path_identity(
        std::filesystem::path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap"),
        2U
    );
    expect_index_roundtrip_preserves_protocol_path_identity(
        std::filesystem::path("parsing/mpls/23_mpls_same_inner_flow_different_labels.pcap"),
        2U
    );

    {
        auto truncated_bytes = make_classic_pcap({{100, forward_packet}, {200, reverse_packet}});
        truncated_bytes.resize(truncated_bytes.size() - 5U);
        const auto partial_capture_path = write_temp_pcap("pfl_partial_index_allowed.pcap", truncated_bytes);
        const auto partial_index_path = std::filesystem::temp_directory_path() / "pfl_partial_index_allowed.idx";
        std::filesystem::remove(partial_index_path);

        CaptureSession partial_session {};
        PFL_EXPECT(partial_session.open_capture(partial_capture_path));
        PFL_EXPECT(partial_session.is_partial_open());
        PFL_EXPECT(partial_session.save_index(partial_index_path));
        PFL_EXPECT(std::filesystem::exists(partial_index_path));

        CaptureSession reloaded_partial_session {};
        PFL_EXPECT(reloaded_partial_session.load_index(partial_index_path));
        PFL_EXPECT(reloaded_partial_session.summary().packet_count == 1U);
        PFL_EXPECT(reloaded_partial_session.summary().flow_count == 1U);
    }

    {
        const auto existing_index_path = std::filesystem::temp_directory_path() / "pfl_index_atomic_existing.idx";
        const auto cancelled_index_path = std::filesystem::temp_directory_path() / "pfl_index_atomic_cancelled.idx";
        std::filesystem::remove(existing_index_path);
        std::filesystem::remove(cancelled_index_path);

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(source_path));
        PFL_REQUIRE(session.save_index(existing_index_path));

        {
            std::ifstream baseline_stream(existing_index_path, std::ios::binary);
            std::ofstream cancelled_stream(cancelled_index_path, std::ios::binary | std::ios::trunc);
            cancelled_stream << baseline_stream.rdbuf();
        }

        bool saw_progress = false;
        bool cancel_requested = false;
        const CaptureSession::IndexSaveOptions options {
            .progress_callback = [&](const CaptureSession::IndexSaveProgress& progress) {
                saw_progress = true;
                (void)progress;
            },
            .cancel_requested = [&cancel_requested]() {
                const bool result = cancel_requested;
                cancel_requested = true;
                return result;
            },
        };

        std::string error_text {};
        PFL_EXPECT(!session.save_index(cancelled_index_path, options, &error_text));
        PFL_EXPECT(saw_progress);
        PFL_EXPECT(error_text == "Index save cancelled by user.");
        PFL_EXPECT(std::filesystem::exists(cancelled_index_path));
        PFL_EXPECT(validate_index_magic(cancelled_index_path));

        CaptureSession cancelled_loaded_session {};
        PFL_EXPECT(cancelled_loaded_session.load_index(cancelled_index_path));
        PFL_EXPECT(cancelled_loaded_session.summary().packet_count == 2U);
        PFL_EXPECT(cancelled_loaded_session.summary().flow_count == 1U);
    }
}

}  // namespace pfl::tests


