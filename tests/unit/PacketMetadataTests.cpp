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

bool mutate_packet_ref_fields(
    CaptureSession& session,
    const std::uint64_t packet_index,
    const std::uint32_t payload_length,
    const std::uint8_t tcp_flags,
    const bool is_ip_fragmented
) {
    const auto mutate_packets = [&](auto& packets) {
        const auto it = std::find_if(packets.begin(), packets.end(), [&](const PacketRef& packet) {
            return packet.packet_index == packet_index;
        });
        if (it == packets.end()) {
            return false;
        }

        it->payload_length = payload_length;
        it->tcp_flags = tcp_flags;
        it->is_ip_fragmented = is_ip_fragmented;
        return true;
    };

    for (const auto& connection : session_detail::list_connections(session.state())) {
        if (connection.family == FlowAddressFamily::ipv4 && connection.ipv4 != nullptr) {
            auto& mutable_connection = session.state().ipv4_connections.get_or_create(connection.ipv4->key);
            if (mutate_packets(mutable_connection.flow_a.packets) || mutate_packets(mutable_connection.flow_b.packets)) {
                return true;
            }
            continue;
        }

        if (connection.family == FlowAddressFamily::ipv6 && connection.ipv6 != nullptr) {
            auto& mutable_connection = session.state().ipv6_connections.get_or_create(connection.ipv6->key);
            if (mutate_packets(mutable_connection.flow_a.packets) || mutate_packets(mutable_connection.flow_b.packets)) {
                return true;
            }
        }
    }

    return false;
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
        PFL_EXPECT(tcp_ref->payload_length == 5);
        PFL_EXPECT(tcp_ref->tcp_flags == 0x12);

        const auto udp_ref = session.find_packet(1);
        PFL_REQUIRE(udp_ref.has_value());
        PFL_EXPECT(udp_ref->payload_length == 7);
        PFL_EXPECT(udp_ref->tcp_flags == 0);

        const auto rows = session.list_flow_packets(0);
        PFL_REQUIRE(!rows.empty());
        PFL_EXPECT(rows.front().payload_length == 5);
        PFL_EXPECT(rows.front().tcp_flags_text == "ACK|SYN");

        auto enriched_rows = rows;
        session_detail::apply_original_transport_payload_lengths(session, enriched_rows);
        PFL_REQUIRE(!enriched_rows.empty());
        PFL_EXPECT(enriched_rows.front().payload_length == 5);

        PFL_REQUIRE(mutate_packet_ref_fields(session, 0U, 0U, 0U, true));

        const auto stale_tcp_ref = session.find_packet(0U);
        PFL_REQUIRE(stale_tcp_ref.has_value());

        const auto derived_metadata = session_detail::derive_transient_packet_metadata(session, *stale_tcp_ref);
        PFL_REQUIRE(derived_metadata.captured_transport_payload_length.has_value());
        PFL_REQUIRE(derived_metadata.original_transport_payload_length.has_value());
        PFL_REQUIRE(derived_metadata.tcp_flags.has_value());
        PFL_REQUIRE(derived_metadata.is_ip_fragmented.has_value());
        PFL_EXPECT(*derived_metadata.captured_transport_payload_length == 5U);
        PFL_EXPECT(*derived_metadata.original_transport_payload_length == 5U);
        PFL_EXPECT(*derived_metadata.tcp_flags == 0x12U);
        PFL_EXPECT(!*derived_metadata.is_ip_fragmented);

        auto stale_rows = session.list_flow_packets(0);
        PFL_REQUIRE(!stale_rows.empty());
        PFL_EXPECT(stale_rows.front().payload_length == 0U);
        PFL_EXPECT(stale_rows.front().tcp_flags_text.empty());
        PFL_EXPECT(stale_rows.front().is_ip_fragmented);

        session.prepare_selected_flow_packet_cache(0U, stale_rows.size());
        session_detail::populate_transient_packet_row_metadata(session, stale_rows);
        PFL_REQUIRE(stale_rows.front().derived_payload_length.has_value());
        PFL_REQUIRE(stale_rows.front().derived_tcp_flags_text.has_value());
        PFL_REQUIRE(stale_rows.front().derived_is_ip_fragmented.has_value());
        PFL_EXPECT(*stale_rows.front().derived_payload_length == 5U);
        PFL_EXPECT(*stale_rows.front().derived_tcp_flags_text == "ACK|SYN");
        PFL_EXPECT(!*stale_rows.front().derived_is_ip_fragmented);

        const auto payload_slice = session.read_selected_flow_transport_payload_slice(0U, *stale_tcp_ref, 0U, 5U);
        PFL_EXPECT(payload_slice.size() == 5U);

        const auto stale_packet_bytes = session.read_packet_data(*stale_tcp_ref);
        const auto stale_packet_details = session.read_packet_details(*stale_tcp_ref);
        PFL_REQUIRE(!stale_packet_bytes.empty());
        PFL_REQUIRE(stale_packet_details.has_value());
        auto summary_preparation = session_detail::prepare_selected_packet_summary(
            session,
            *stale_packet_details,
            *stale_tcp_ref,
            0U,
            1U,
            stale_rows.size(),
            derived_metadata.captured_transport_payload_length,
            derived_metadata.original_transport_payload_length
        );
        const auto summary_layers =
            session_detail::build_packet_summary_layers(*stale_packet_details, *stale_tcp_ref, summary_preparation.make_options());
        PFL_EXPECT(!summary_preparation.make_options().is_ip_fragmented.value_or(true));
        PFL_EXPECT(!summary_layers_contain_value(summary_layers, "Packet is IP-fragmented"));
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
        PFL_EXPECT(tcp_ref->payload_length == 5);
        PFL_EXPECT(tcp_ref->tcp_flags == 0x12);

        const auto udp_ref = loaded_session.find_packet(1);
        PFL_REQUIRE(udp_ref.has_value());
        PFL_EXPECT(udp_ref->payload_length == 7);
        PFL_EXPECT(udp_ref->tcp_flags == 0);
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
