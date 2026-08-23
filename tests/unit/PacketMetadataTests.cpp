#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <string_view>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/SelectedPacketSummaryPreparation.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SessionFlowHelpers.h"
#include "core/decode/PacketDecoder.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> make_pppoe_session_packet(
    const std::uint16_t ppp_protocol,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x88, 0x64,
        0x11, 0x00,
        0x00, 0x01,
    };
    append_be16(bytes, static_cast<std::uint16_t>(2U + payload.size()));
    append_be16(bytes, ppp_protocol);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_ipv4_tcp_first_fragment_with_complete_header(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint8_t tcp_flags
) {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        5U,
        tcp_flags
    );
    const auto tcp_payload = std::vector<std::uint8_t>(tcp_packet.begin() + 34, tcp_packet.end());
    return make_ethernet_ipv4_fragment_packet(src_addr, dst_addr, 6U, 0x2000U, tcp_payload);
}

bool summary_layers_contain_value(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string_view value
) {
    for (const auto& layer : layers) {
        for (const auto& field : layer.fields) {
            if (field.value == value) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace

void run_packet_metadata_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 1),
        ipv4(10, 0, 0, 2),
        12345,
        443,
        5,
        0x12
    );
    const auto udp_packet = make_ethernet_ipv4_udp_packet_with_payload(
        ipv4(10, 0, 0, 3),
        ipv4(10, 0, 0, 4),
        5353,
        53,
        7
    );
    const auto ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    const auto ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
    const auto ipv6_udp_packet = make_ethernet_ipv6_udp_with_hop_by_hop_packet(ipv6_src, ipv6_dst, 5353, 53);

    {
        const auto path = write_temp_pcap(
            "pfl_packet_metadata_tcp_udp.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));

        const auto tcp_ref = session.find_packet(0);
        PFL_REQUIRE(tcp_ref.has_value());

        const auto udp_ref = session.find_packet(1);
        PFL_REQUIRE(udp_ref.has_value());

        const auto tcp_metadata = session_detail::derive_transient_packet_metadata(session, *tcp_ref);
        PFL_REQUIRE(tcp_metadata.captured_transport_payload_length.has_value());
        PFL_REQUIRE(tcp_metadata.original_transport_payload_length.has_value());
        PFL_REQUIRE(tcp_metadata.tcp_flags.has_value());
        PFL_REQUIRE(tcp_metadata.is_ip_fragmented.has_value());
        PFL_EXPECT(*tcp_metadata.captured_transport_payload_length == 5U);
        PFL_EXPECT(*tcp_metadata.original_transport_payload_length == 5U);
        PFL_EXPECT(*tcp_metadata.tcp_flags == 0x12U);
        PFL_EXPECT(!*tcp_metadata.is_ip_fragmented);

        const auto udp_metadata = session_detail::derive_transient_packet_metadata(session, *udp_ref);
        PFL_REQUIRE(udp_metadata.captured_transport_payload_length.has_value());
        PFL_EXPECT(*udp_metadata.captured_transport_payload_length == 7U);
        PFL_EXPECT(!udp_metadata.tcp_flags.has_value());

        const auto rows = session.list_flow_packets(0);
        PFL_REQUIRE(!rows.empty());
        PFL_EXPECT(rows.front().payload_length == 0U);
        PFL_EXPECT(rows.front().tcp_flags_text.empty());

        auto uncached_rows = rows;
        session_detail::populate_transient_packet_row_metadata(session, 0U, uncached_rows);
        PFL_REQUIRE(!uncached_rows.empty());
        PFL_REQUIRE(uncached_rows.front().derived_payload_length.has_value());
        PFL_REQUIRE(uncached_rows.front().derived_tcp_flags_text.has_value());
        PFL_REQUIRE(uncached_rows.front().derived_is_ip_fragmented.has_value());
        PFL_EXPECT(*uncached_rows.front().derived_payload_length == 5U);
        PFL_EXPECT(*uncached_rows.front().derived_tcp_flags_text == "ACK|SYN");
        PFL_EXPECT(!*uncached_rows.front().derived_is_ip_fragmented);

        auto enriched_rows = rows;
        session.prepare_selected_flow_packet_cache(0U, enriched_rows.size());
        const auto cached_tcp_metadata = session.selected_flow_cached_packet_metadata(0U, tcp_ref->packet_index);
        PFL_REQUIRE(cached_tcp_metadata.has_value());
        PFL_EXPECT(cached_tcp_metadata->captured_transport_payload_length == 5U);
        PFL_EXPECT(cached_tcp_metadata->original_transport_payload_length == 5U);
        PFL_EXPECT(cached_tcp_metadata->tcp_flags == 0x12U);
        PFL_EXPECT(cached_tcp_metadata->is_ip_fragmented == false);
        PFL_EXPECT(!session.selected_flow_cached_packet_metadata(0U, udp_ref->packet_index).has_value());

        session_detail::populate_transient_packet_row_metadata(session, 0U, enriched_rows);
        session_detail::apply_original_transport_payload_lengths(session, enriched_rows);
        PFL_REQUIRE(!enriched_rows.empty());
        PFL_EXPECT(enriched_rows.front().payload_length == 5);

        PFL_REQUIRE(enriched_rows.front().derived_payload_length.has_value());
        PFL_REQUIRE(enriched_rows.front().derived_tcp_flags_text.has_value());
        PFL_REQUIRE(enriched_rows.front().derived_is_ip_fragmented.has_value());
        PFL_EXPECT(*enriched_rows.front().derived_payload_length == 5U);
        PFL_EXPECT(*enriched_rows.front().derived_tcp_flags_text == "ACK|SYN");
        PFL_EXPECT(!*enriched_rows.front().derived_is_ip_fragmented);

        const auto payload_slice = session.read_selected_flow_transport_payload_slice(0U, *tcp_ref, 0U, 5U);
        PFL_EXPECT(payload_slice.size() == 5U);

        const auto stale_packet_bytes = session.read_packet_data(*tcp_ref);
        const auto stale_packet_details = session.read_packet_details(*tcp_ref);
        PFL_REQUIRE(!stale_packet_bytes.empty());
        PFL_REQUIRE(stale_packet_details.has_value());
        auto summary_preparation = session_detail::prepare_selected_packet_summary(
            session,
            *stale_packet_details,
            *tcp_ref,
            0U,
            1U,
            enriched_rows.size(),
            tcp_metadata.captured_transport_payload_length,
            tcp_metadata.original_transport_payload_length
        );
        const auto summary_layers =
            session_detail::build_packet_summary_layers(*stale_packet_details, *tcp_ref, summary_preparation.make_options());
        PFL_EXPECT(!summary_preparation.make_options().is_ip_fragmented.value_or(true));
        PFL_EXPECT(!summary_layers_contain_value(summary_layers, "Packet is IP-fragmented"));
    }

    {
        const auto fragmented_tcp_packet = make_ipv4_tcp_first_fragment_with_complete_header(
            ipv4(10, 10, 0, 1),
            ipv4(10, 10, 0, 2),
            41000U,
            443U,
            0x12U
        );
        const auto path = write_temp_pcap(
            "pfl_packet_metadata_fragmented_unknown_payload.pcap",
            make_classic_pcap({{100U, fragmented_tcp_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));

        const auto packet_ref = session.find_packet(0U);
        PFL_REQUIRE(packet_ref.has_value());
        session.prepare_selected_flow_packet_cache(0U, 1U);

        const auto cached_metadata = session.selected_flow_cached_packet_metadata(0U, packet_ref->packet_index);
        PFL_REQUIRE(cached_metadata.has_value());
        PFL_EXPECT(!cached_metadata->captured_transport_payload_length.has_value());
        PFL_EXPECT(!cached_metadata->original_transport_payload_length.has_value());
        PFL_EXPECT(cached_metadata->tcp_flags == 0x12U);
        PFL_EXPECT(cached_metadata->is_ip_fragmented == true);
        PFL_EXPECT(!session.selected_flow_cached_packet_metadata(0U, packet_ref->packet_index + 1U).has_value());

        auto rows = session.list_flow_packets(0U);
        PFL_REQUIRE(rows.size() == 1U);
        session_detail::populate_transient_packet_row_metadata(session, 0U, rows);
        PFL_EXPECT(!rows.front().derived_payload_length.has_value());
        PFL_REQUIRE(rows.front().derived_tcp_flags_text.has_value());
        PFL_EXPECT(*rows.front().derived_tcp_flags_text == "ACK|SYN");
        PFL_REQUIRE(rows.front().derived_is_ip_fragmented.has_value());
        PFL_EXPECT(*rows.front().derived_is_ip_fragmented);
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_packet_metadata_roundtrip.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_packet_metadata.idx";
        std::filesystem::remove(index_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(session.save_index(index_path));

        CaptureSession loaded_session {};
        PFL_EXPECT(loaded_session.load_index(index_path));

        const auto tcp_ref = loaded_session.find_packet(0);
        PFL_REQUIRE(tcp_ref.has_value());

        const auto udp_ref = loaded_session.find_packet(1);
        PFL_REQUIRE(udp_ref.has_value());

        const auto tcp_metadata = session_detail::derive_transient_packet_metadata(loaded_session, *tcp_ref);
        PFL_REQUIRE(tcp_metadata.captured_transport_payload_length.has_value());
        PFL_REQUIRE(tcp_metadata.tcp_flags.has_value());
        PFL_EXPECT(*tcp_metadata.captured_transport_payload_length == 5U);
        PFL_EXPECT(*tcp_metadata.tcp_flags == 0x12U);

        const auto udp_metadata = session_detail::derive_transient_packet_metadata(loaded_session, *udp_ref);
        PFL_REQUIRE(udp_metadata.captured_transport_payload_length.has_value());
        PFL_EXPECT(*udp_metadata.captured_transport_payload_length == 7U);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "udp" / "udp_truncated_quic_like_payload_3.pcap"
        ));

        const auto rows = session.list_flow_packets(0);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows.front().captured_length == 74U);
        PFL_EXPECT(rows.front().original_length == 332U);
        PFL_EXPECT(rows.front().payload_length == 32U);

        auto enriched_rows = rows;
        session_detail::apply_original_transport_payload_lengths(session, enriched_rows);
        PFL_REQUIRE(enriched_rows.size() == 1U);
        PFL_EXPECT(enriched_rows.front().payload_length == 290U);
    }

    {
        PacketDecoder decoder {};

        auto malformed_tcp = tcp_packet;
        malformed_tcp[16] = 0x00;
        malformed_tcp[17] = 0x10;

        const RawPcapPacket raw_tcp {
            .packet_index = 0,
            .ts_sec = 1,
            .ts_usec = 0,
            .captured_length = static_cast<std::uint32_t>(malformed_tcp.size()),
            .original_length = static_cast<std::uint32_t>(malformed_tcp.size()),
            .data_offset = 40,
            .bytes = malformed_tcp,
        };
        PFL_EXPECT(!decoder.decode_ethernet(raw_tcp).has_value());

        auto malformed_udp = udp_packet;
        malformed_udp[38] = 0x00;
        malformed_udp[39] = 0x06;

        const RawPcapPacket raw_udp {
            .packet_index = 1,
            .ts_sec = 1,
            .ts_usec = 0,
            .captured_length = static_cast<std::uint32_t>(malformed_udp.size()),
            .original_length = static_cast<std::uint32_t>(malformed_udp.size()),
            .data_offset = 80,
            .bytes = malformed_udp,
        };
        PFL_EXPECT(!decoder.decode_ethernet(raw_udp).has_value());

        const auto bounded_udp = make_pppoe_session_packet(0x0021U, strip_ethernet_header(malformed_udp));
        const RawPcapPacket raw_bounded_udp {
            .packet_index = 2,
            .ts_sec = 1,
            .ts_usec = 0,
            .captured_length = static_cast<std::uint32_t>(bounded_udp.size()),
            .original_length = static_cast<std::uint32_t>(bounded_udp.size()),
            .data_offset = 120,
            .bytes = bounded_udp,
        };
        PFL_EXPECT(!decoder.decode_ethernet(raw_bounded_udp).has_value());

        auto malformed_ipv6_udp = ipv6_udp_packet;
        malformed_ipv6_udp[66] = 0x00;
        malformed_ipv6_udp[67] = 0x06;

        const RawPcapPacket raw_ipv6_udp {
            .packet_index = 3,
            .ts_sec = 1,
            .ts_usec = 0,
            .captured_length = static_cast<std::uint32_t>(malformed_ipv6_udp.size()),
            .original_length = static_cast<std::uint32_t>(malformed_ipv6_udp.size()),
            .data_offset = 160,
            .bytes = malformed_ipv6_udp,
        };
        PFL_EXPECT(!decoder.decode_ethernet(raw_ipv6_udp).has_value());

        const auto bounded_ipv6_udp = make_pppoe_session_packet(0x0057U, strip_ethernet_header(malformed_ipv6_udp));
        const RawPcapPacket raw_bounded_ipv6_udp {
            .packet_index = 4,
            .ts_sec = 1,
            .ts_usec = 0,
            .captured_length = static_cast<std::uint32_t>(bounded_ipv6_udp.size()),
            .original_length = static_cast<std::uint32_t>(bounded_ipv6_udp.size()),
            .data_offset = 200,
            .bytes = bounded_ipv6_udp,
        };
        PFL_EXPECT(!decoder.decode_ethernet(raw_bounded_ipv6_udp).has_value());
    }
}

}  // namespace pfl::tests
