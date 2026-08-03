#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "core/services/HexDumpService.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

CaptureImportOptions fast_options() {
    return CaptureImportOptions {
        .settings = AnalysisSettings {},
    };
}

std::vector<std::uint8_t> make_text_bytes(const std::string_view text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
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

std::vector<std::uint8_t> make_tls_record(
    const std::uint8_t content_type,
    const std::uint16_t version,
    const std::vector<std::uint8_t>& body
) {
    std::vector<std::uint8_t> record {};
    record.reserve(5U + body.size());
    record.push_back(content_type);
    append_be16(record, version);
    append_be16(record, static_cast<std::uint16_t>(body.size()));
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

std::vector<std::uint8_t> make_tls_handshake_record(
    const std::uint8_t handshake_type,
    const std::vector<std::uint8_t>& body = {},
    const std::uint16_t version = 0x0303U
) {
    std::vector<std::uint8_t> handshake {};
    handshake.reserve(4U + body.size());
    handshake.push_back(handshake_type);
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return make_tls_record(0x16U, version, handshake);
}

const StreamItemRow* find_stream_row_by_label(
    const std::vector<StreamItemRow>& rows,
    const std::string_view label
) {
    const auto it = std::find_if(rows.begin(), rows.end(), [&](const StreamItemRow& row) {
        return row.label == label;
    });
    return it == rows.end() ? nullptr : &(*it);
}

const StreamItemRow* find_stream_row_by_label_and_packets(
    const std::vector<StreamItemRow>& rows,
    const std::string_view label,
    const std::vector<std::uint64_t>& packet_indices
) {
    const auto it = std::find_if(rows.begin(), rows.end(), [&](const StreamItemRow& row) {
        return row.label == label && row.packet_indices == packet_indices;
    });
    return it == rows.end() ? nullptr : &(*it);
}

const StreamItemRow* find_stream_row_by_prefix(
    const std::vector<StreamItemRow>& rows,
    const std::string_view prefix
) {
    const auto it = std::find_if(rows.begin(), rows.end(), [&](const StreamItemRow& row) {
        return row.label.rfind(prefix, 0U) == 0U;
    });
    return it == rows.end() ? nullptr : &(*it);
}

session_detail::SelectedStreamItemDataPresentation require_selected_stream_item_data(
    CaptureSession& session,
    const std::size_t flow_index,
    const std::size_t packet_budget,
    const std::size_t item_limit,
    const std::uint64_t stream_item_index
) {
    const auto presentation = session.derive_selected_flow_stream_item_data(
        flow_index,
        packet_budget,
        item_limit,
        stream_item_index
    );
    PFL_EXPECT(presentation.stream_item_index == stream_item_index);
    return presentation;
}

std::vector<std::uint8_t> require_materialized_selected_stream_item_data(
    CaptureSession& session,
    const std::size_t flow_index,
    const std::size_t packet_budget,
    const std::size_t item_limit,
    const std::uint64_t stream_item_index
) {
    const auto materialized = session.materialize_selected_flow_stream_item_data(
        flow_index,
        packet_budget,
        item_limit,
        stream_item_index
    );
    PFL_REQUIRE(materialized.has_value());
    return *materialized;
}

void expect_hex_dump_matches(
    CaptureSession& session,
    const std::size_t flow_index,
    const std::size_t packet_budget,
    const std::size_t item_limit,
    const std::uint64_t stream_item_index,
    const std::vector<std::uint8_t>& expected_bytes
) {
    const auto hex_dump = session.format_selected_flow_stream_item_data_hex_dump(
        flow_index,
        packet_budget,
        item_limit,
        stream_item_index
    );
    PFL_REQUIRE(hex_dump.has_value());
    HexDumpService service {};
    PFL_EXPECT(*hex_dump == service.format(std::span<const std::uint8_t>(expected_bytes.data(), expected_bytes.size())));
}

}  // namespace

void run_selected_stream_item_data_presentation_tests() {
    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tcp/tcp_generic_payload_7.pcap"), fast_options()));

        const auto rows = session.list_flow_stream_items_for_packet_prefix(0U, 30U, 32U);
        PFL_REQUIRE(!rows.empty());
        const auto& row = rows.front();
        PFL_EXPECT(row.label == "TCP Payload");
        PFL_EXPECT(row.packet_indices.size() == 1U);

        const auto presentation = require_selected_stream_item_data(session, 0U, 30U, 32U, row.stream_item_index);
        PFL_EXPECT(presentation.semantic_kind == session_detail::StreamItemDataSemanticKind::tcp_payload);
        PFL_EXPECT(presentation.source_kind == session_detail::StreamItemDataSourceKind::captured_packet_range);
        PFL_EXPECT(presentation.state == session_detail::StreamItemDataState::complete);
        PFL_EXPECT(presentation.available_length == row.byte_count);
        PFL_EXPECT(presentation.captured_packet_range.has_value());
        PFL_EXPECT(presentation.captured_packet_range->packet_index == row.packet_indices.front());
        PFL_EXPECT(presentation.owned_bytes.empty());

        const auto packet = session.find_packet(row.packet_indices.front());
        PFL_REQUIRE(packet.has_value());
        const auto payload = session.read_selected_flow_transport_payload(0U, *packet);
        const auto trim_prefix_bytes = session.selected_flow_tcp_payload_trim_prefix_bytes(0U, packet->packet_index);
        PFL_REQUIRE(payload.size() >= trim_prefix_bytes + row.byte_count);
        const auto expected_bytes = std::vector<std::uint8_t>(
            payload.begin() + static_cast<std::ptrdiff_t>(trim_prefix_bytes),
            payload.begin() + static_cast<std::ptrdiff_t>(trim_prefix_bytes + row.byte_count)
        );
        const auto materialized = require_materialized_selected_stream_item_data(
            session,
            0U,
            30U,
            32U,
            row.stream_item_index
        );
        PFL_EXPECT(materialized == expected_bytes);
        expect_hex_dump_matches(session, 0U, 30U, 32U, row.stream_item_index, expected_bytes);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_get_1.pcap"), fast_options()));

        const auto rows = session.list_flow_stream_items_for_packet_prefix(0U, 30U, 16U);
        const auto* row = find_stream_row_by_prefix(rows, "HTTP ");
        PFL_REQUIRE(row != nullptr);

        const auto presentation = require_selected_stream_item_data(session, 0U, 30U, 16U, row->stream_item_index);
        PFL_EXPECT(presentation.semantic_kind == session_detail::StreamItemDataSemanticKind::http_message);
        PFL_EXPECT(presentation.source_kind == session_detail::StreamItemDataSourceKind::unavailable);
        PFL_EXPECT(!presentation.unavailable_reason.empty());
        PFL_EXPECT(!session.materialize_selected_flow_stream_item_data(0U, 30U, 16U, row->stream_item_index).has_value());
        PFL_EXPECT(!session.format_selected_flow_stream_item_data_hex_dump(0U, 30U, 16U, row->stream_item_index).has_value());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_client_hello_1.pcap"), fast_options()));

        const auto rows = session.list_flow_stream_items_for_packet_prefix(0U, 30U, 16U);
        const auto* row = find_stream_row_by_label(rows, "TLS ClientHello");
        PFL_REQUIRE(row != nullptr);
        PFL_EXPECT(row->packet_indices.size() == 1U);
        PFL_EXPECT(!row->summary_payload_bytes.empty());

        const auto presentation = require_selected_stream_item_data(session, 0U, 30U, 16U, row->stream_item_index);
        PFL_EXPECT(presentation.semantic_kind == session_detail::StreamItemDataSemanticKind::tls_record);
        PFL_EXPECT(presentation.semantic_kind != session_detail::StreamItemDataSemanticKind::tls_handshake);
        PFL_EXPECT(presentation.source_kind == session_detail::StreamItemDataSourceKind::captured_packet_range);
        PFL_EXPECT(presentation.state == session_detail::StreamItemDataState::complete);
        PFL_EXPECT(presentation.assembly_kind == session_detail::StreamItemDataAssemblyKind::packet_local);
        PFL_EXPECT(presentation.available_length == row->summary_payload_bytes.size());
        PFL_EXPECT(presentation.declared_length == std::optional<std::uint32_t> {
            static_cast<std::uint32_t>(row->summary_payload_bytes.size())});

        const auto materialized = require_materialized_selected_stream_item_data(
            session,
            0U,
            30U,
            16U,
            row->stream_item_index
        );
        PFL_EXPECT(materialized == row->summary_payload_bytes);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_split_client_hello_10.pcap"), fast_options()));

        const auto rows = session.list_flow_stream_items_for_packet_prefix(0U, 5U, 16U);
        const auto* row = find_stream_row_by_label(rows, "TLS ClientHello");
        PFL_REQUIRE(row != nullptr);
        PFL_EXPECT(row->packet_count > 1U);
        PFL_EXPECT(!row->summary_payload_bytes.empty());

        const auto presentation = require_selected_stream_item_data(session, 0U, 5U, 16U, row->stream_item_index);
        PFL_EXPECT(presentation.semantic_kind == session_detail::StreamItemDataSemanticKind::tls_record);
        PFL_EXPECT(presentation.source_kind == session_detail::StreamItemDataSourceKind::retained_item_bytes);
        PFL_EXPECT(presentation.assembly_kind == session_detail::StreamItemDataAssemblyKind::reassembled);
        PFL_EXPECT(presentation.contributing_unit_count == std::optional<std::uint32_t> {row->packet_count});
        PFL_EXPECT(
            presentation.contributing_unit_kind ==
            std::optional<session_detail::StreamItemDataContributionUnitKind> {
                session_detail::StreamItemDataContributionUnitKind::tcp_segment
            });
        PFL_EXPECT(presentation.owned_bytes == row->summary_payload_bytes);

        const auto materialized = require_materialized_selected_stream_item_data(
            session,
            0U,
            5U,
            16U,
            row->stream_item_index
        );
        PFL_EXPECT(materialized == row->summary_payload_bytes);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ack_wrong_pkn_1.pcap"), fast_options()));

        const auto rows = session.list_flow_stream_items_for_packet_prefix(0U, 30U, 16U);
        const auto* row = find_stream_row_by_label(rows, "QUIC Initial");
        PFL_REQUIRE(row != nullptr);
        PFL_REQUIRE(row->quic_stream_presentation.has_value());
        PFL_EXPECT(
            row->quic_stream_presentation->semantic_kind == session_detail::QuicStreamItemSemanticKind::coarse_initial);

        const auto presentation = require_selected_stream_item_data(session, 0U, 30U, 16U, row->stream_item_index);
        PFL_EXPECT(presentation.semantic_kind == session_detail::StreamItemDataSemanticKind::quic_packet);
        PFL_EXPECT(presentation.source_kind == session_detail::StreamItemDataSourceKind::captured_packet_range);
        PFL_EXPECT(presentation.captured_packet_range.has_value());
        PFL_EXPECT(!presentation.quic_crypto_stream_offset.has_value());
        PFL_EXPECT(presentation.available_length == row->byte_count);

        const auto materialized = require_materialized_selected_stream_item_data(
            session,
            0U,
            30U,
            16U,
            row->stream_item_index
        );
        PFL_EXPECT(materialized.size() == row->byte_count);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ack_decrypt_ok_1.pcap"), fast_options()));

        const auto rows = session.list_flow_stream_items_for_packet_prefix(0U, 30U, 16U);
        const auto* row = find_stream_row_by_label(rows, "QUIC Initial: ACK");
        PFL_REQUIRE(row != nullptr);

        const auto presentation = require_selected_stream_item_data(session, 0U, 30U, 16U, row->stream_item_index);
        PFL_EXPECT(presentation.semantic_kind == session_detail::StreamItemDataSemanticKind::quic_frame);
        PFL_EXPECT(presentation.source_kind == session_detail::StreamItemDataSourceKind::reconstructed_item);
        PFL_EXPECT(presentation.state == session_detail::StreamItemDataState::complete);
        PFL_EXPECT(!presentation.quic_crypto_stream_offset.has_value());
        PFL_EXPECT(presentation.available_length == row->byte_count);

        const auto materialized = require_materialized_selected_stream_item_data(
            session,
            0U,
            30U,
            16U,
            row->stream_item_index
        );
        PFL_EXPECT(materialized.size() == row->byte_count);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_example_2.pcap"), fast_options()));

        const auto rows = session.list_flow_stream_items_for_packet_prefix(0U, 30U, 32U);
        const auto* crypto_row = find_stream_row_by_label_and_packets(rows, "QUIC Initial: CRYPTO", {2U});
        const auto* zero_rtt_row = find_stream_row_by_label_and_packets(rows, "0-RTT", {2U});
        const auto* handshake_row = find_stream_row_by_label_and_packets(rows, "Handshake", {15U});
        const auto* protected_payload_row = find_stream_row_by_label_and_packets(rows, "Protected payload", {15U});
        PFL_REQUIRE(crypto_row != nullptr);
        PFL_REQUIRE(zero_rtt_row != nullptr);
        PFL_REQUIRE(handshake_row != nullptr);
        PFL_REQUIRE(protected_payload_row != nullptr);

        const auto crypto_presentation = require_selected_stream_item_data(
            session,
            0U,
            30U,
            32U,
            crypto_row->stream_item_index
        );
        PFL_EXPECT(crypto_presentation.semantic_kind == session_detail::StreamItemDataSemanticKind::quic_frame);
        PFL_EXPECT(crypto_presentation.semantic_kind != session_detail::StreamItemDataSemanticKind::quic_crypto_data);
        PFL_EXPECT(crypto_presentation.source_kind == session_detail::StreamItemDataSourceKind::reconstructed_item);
        PFL_EXPECT(crypto_presentation.quic_crypto_stream_offset.has_value());
        PFL_EXPECT(crypto_presentation.available_length == crypto_row->byte_count);

        const auto zero_rtt_presentation = require_selected_stream_item_data(
            session,
            0U,
            30U,
            32U,
            zero_rtt_row->stream_item_index
        );
        const auto handshake_presentation = require_selected_stream_item_data(
            session,
            0U,
            30U,
            32U,
            handshake_row->stream_item_index
        );
        const auto protected_payload_presentation = require_selected_stream_item_data(
            session,
            0U,
            30U,
            32U,
            protected_payload_row->stream_item_index
        );
        PFL_EXPECT(zero_rtt_presentation.source_kind == session_detail::StreamItemDataSourceKind::captured_packet_range);
        PFL_EXPECT(handshake_presentation.source_kind == session_detail::StreamItemDataSourceKind::captured_packet_range);
        PFL_EXPECT(protected_payload_presentation.source_kind ==
            session_detail::StreamItemDataSourceKind::captured_packet_range);
        PFL_REQUIRE(handshake_presentation.captured_packet_range.has_value());
        PFL_REQUIRE(protected_payload_presentation.captured_packet_range.has_value());
        PFL_EXPECT(handshake_presentation.captured_packet_range->packet_index ==
            protected_payload_presentation.captured_packet_range->packet_index);
        PFL_EXPECT(handshake_presentation.captured_packet_range->offset !=
            protected_payload_presentation.captured_packet_range->offset);
    }

    {
        constexpr std::string_view http_gap_request_one =
            "GET /one HTTP/1.1\r\n"
            "Host: gap.example\r\n"
            "\r\n";
        constexpr std::string_view http_gap_request_two =
            "GET /two HTTP/1.1\r\n"
            "Host: gap.example\r\n"
            "\r\n";

        const auto http_gap_payload_a = make_text_bytes(http_gap_request_one);
        const auto http_gap_payload_b = make_text_bytes(http_gap_request_two);
        const auto http_gap_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            ipv4(10, 46, 2, 1), ipv4(10, 46, 2, 2), 53024, 80, http_gap_payload_a, 4000U, 0U, 0x18);
        const auto http_gap_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            ipv4(10, 46, 2, 1),
            ipv4(10, 46, 2, 2),
            53024,
            80,
            http_gap_payload_b,
            4000U + static_cast<std::uint32_t>(http_gap_payload_a.size()) + 13U,
            0U,
            0x18);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            write_temp_pcap(
                "pfl_selected_stream_item_data_http_gap.pcap",
                make_classic_pcap({{100U, http_gap_packet_a}, {200U, http_gap_packet_b}})
            ),
            fast_options()
        ));
        session.set_selected_flow_tcp_payload_suppression(0U, {}, 2U);

        const auto rows = session.list_flow_stream_items_for_packet_prefix(0U, 2U, 10U);
        const auto* gap_row = find_stream_row_by_label(rows, "HTTP Gap");
        PFL_REQUIRE(gap_row != nullptr);

        const auto presentation = require_selected_stream_item_data(session, 0U, 2U, 10U, gap_row->stream_item_index);
        PFL_EXPECT(presentation.source_kind == session_detail::StreamItemDataSourceKind::unavailable);
        PFL_EXPECT(presentation.state == session_detail::StreamItemDataState::synthetic);
        PFL_EXPECT(!session.materialize_selected_flow_stream_item_data(0U, 2U, 10U, gap_row->stream_item_index).has_value());
        PFL_EXPECT(!session.format_selected_flow_stream_item_data_hex_dump(0U, 2U, 10U, gap_row->stream_item_index).has_value());
    }

    {
        const auto client_hello_record = make_tls_handshake_record(0x01U, std::vector<std::uint8_t>(96U, 0x31U));
        const auto split_offset = client_hello_record.size() - 1U;

        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> tls_window_packets {};
        tls_window_packets.reserve(31U);
        for (std::uint32_t index = 0U; index < 29U; ++index) {
            tls_window_packets.push_back({
                5000U + index,
                make_ethernet_ipv4_tcp_packet(ipv4(10, 64, 0, 1), ipv4(10, 64, 0, 2), 54040, 443)
            });
        }
        tls_window_packets.push_back({
            5029U,
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 64, 0, 1),
                ipv4(10, 64, 0, 2),
                54040,
                443,
                std::vector<std::uint8_t>(
                    client_hello_record.begin(),
                    client_hello_record.begin() + static_cast<std::ptrdiff_t>(split_offset)
                ),
                0x18)
        });
        tls_window_packets.push_back({
            5030U,
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 64, 0, 1),
                ipv4(10, 64, 0, 2),
                54040,
                443,
                std::vector<std::uint8_t>(
                    client_hello_record.begin() + static_cast<std::ptrdiff_t>(split_offset),
                    client_hello_record.end()
                ),
                0x18)
        });

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            write_temp_pcap(
                "pfl_selected_stream_item_data_tls_window_incomplete.pcap",
                make_classic_pcap(tls_window_packets)
            ),
            fast_options()
        ));

        const auto rows = session.list_flow_stream_items_for_packet_prefix(0U, 30U, 8U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].label.find("(partial)") != std::string::npos);

        const auto presentation = require_selected_stream_item_data(session, 0U, 30U, 8U, rows[0].stream_item_index);
        PFL_EXPECT(presentation.semantic_kind == session_detail::StreamItemDataSemanticKind::tls_record);
        PFL_EXPECT(presentation.state == session_detail::StreamItemDataState::window_incomplete);
        PFL_EXPECT(presentation.available_length == rows[0].summary_payload_bytes.size());

        const auto materialized = require_materialized_selected_stream_item_data(
            session,
            0U,
            30U,
            8U,
            rows[0].stream_item_index
        );
        PFL_EXPECT(materialized == rows[0].summary_payload_bytes);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            fixture_path("parsing/tls/tls_1_3_many_records_continuation_11.pcap"),
            fast_options()
        ));

        const auto first_page_rows = session.list_flow_stream_items_for_packet_prefix(0U, 30U, 15U);
        PFL_REQUIRE(first_page_rows.size() == 15U);
        PFL_EXPECT(first_page_rows.back().stream_item_index == 15U);

        const auto inside_window = require_selected_stream_item_data(session, 0U, 30U, 15U, 15U);
        PFL_EXPECT(inside_window.source_kind != session_detail::StreamItemDataSourceKind::unavailable);

        const auto outside_window = require_selected_stream_item_data(session, 0U, 30U, 15U, 16U);
        PFL_EXPECT(outside_window.source_kind == session_detail::StreamItemDataSourceKind::unavailable);
        PFL_EXPECT(!session.materialize_selected_flow_stream_item_data(0U, 30U, 15U, 16U).has_value());

        const auto extended_rows = session.list_flow_stream_items_for_packet_prefix(0U, 60U, 30U);
        PFL_REQUIRE(extended_rows.size() >= 16U);
        const auto sixteenth = std::find_if(extended_rows.begin(), extended_rows.end(), [](const StreamItemRow& row) {
            return row.stream_item_index == 16U;
        });
        PFL_REQUIRE(sixteenth != extended_rows.end());
        const auto second_page_presentation = require_selected_stream_item_data(session, 0U, 60U, 30U, 16U);
        PFL_EXPECT(second_page_presentation.source_kind != session_detail::StreamItemDataSourceKind::unavailable);
    }

    {
        auto original = session_detail::SelectedStreamItemDataPresentation {
            .stream_item_index = 77U,
            .semantic_kind = session_detail::StreamItemDataSemanticKind::other,
            .source_kind = session_detail::StreamItemDataSourceKind::retained_item_bytes,
            .state = session_detail::StreamItemDataState::complete,
            .assembly_kind = session_detail::StreamItemDataAssemblyKind::packet_local,
            .available_length = 3U,
            .declared_length = std::optional<std::uint32_t> {3U},
            .captured_packet_range = std::nullopt,
            .contributing_unit_count = std::nullopt,
            .contributing_unit_kind = std::nullopt,
            .quic_crypto_stream_offset = std::nullopt,
            .owned_bytes = std::vector<std::uint8_t> {0xAAU, 0xBBU, 0xCCU},
            .unavailable_reason = {},
        };

        auto moved = std::move(original);
        const auto materialized = session_detail::materialize_selected_stream_item_data(moved, {});
        PFL_REQUIRE(materialized.has_value());
        PFL_EXPECT(*materialized == std::vector<std::uint8_t>({0xAAU, 0xBBU, 0xCCU}));
    }
}

}  // namespace pfl::tests
