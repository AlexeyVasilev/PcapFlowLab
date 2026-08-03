#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "PcapTestUtils.h"
#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/SelectedPacketBytePresentation.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SelectedPacketSummaryPreparation.h"

namespace pfl::tests {

namespace {

using session_detail::SelectedPacketByteMaterialization;
using session_detail::SelectedPacketBytePresentation;
using session_detail::SelectedPacketByteViewDescriptor;
using session_detail::SelectedPacketByteViewId;
using session_detail::SelectedPacketByteViewKind;

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    return *packet;
}

SelectedPacketBytePresentation require_presentation(CaptureSession& session, const PacketRef& packet) {
    const auto presentation = session.derive_selected_packet_byte_presentation(packet);
    PFL_REQUIRE(presentation.has_value());
    return *presentation;
}

SelectedPacketBytePresentation require_flow_aware_presentation(CaptureSession& session, const PacketRef& packet) {
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());

    std::optional<std::size_t> flow_index {};
    std::optional<std::uint64_t> flow_packet_index {};
    std::optional<std::size_t> loaded_packet_window_count {};
    for (const auto& flow_row : session.list_flows()) {
        const auto packet_rows = session.list_flow_packets(flow_row.index);
        const auto packet_it = std::find_if(packet_rows.begin(), packet_rows.end(), [&](const PacketRow& row) {
            return row.packet_index == packet.packet_index;
        });
        if (packet_it == packet_rows.end()) {
            continue;
        }

        flow_index = flow_row.index;
        PFL_REQUIRE(packet_it->row_number > 0U);
        flow_packet_index = packet_it->row_number - 1U;
        loaded_packet_window_count = packet_rows.size();
        break;
    }
    PFL_REQUIRE(flow_index.has_value());
    PFL_REQUIRE(flow_packet_index.has_value());
    PFL_REQUIRE(loaded_packet_window_count.has_value());

    const auto packet_bytes = session.read_packet_data(packet);
    auto packet_summary_preparation = session_detail::prepare_selected_packet_summary(
        session,
        *details,
        packet,
        flow_index,
        flow_packet_index,
        loaded_packet_window_count,
        session.read_packet_protocol_details_text(packet),
        std::optional<std::uint32_t> {packet.payload_length},
        session_detail::derive_original_transport_payload_length_from_headers(session, packet)
    );
    return session_detail::build_selected_packet_byte_presentation(
        *details,
        packet,
        session_detail::SelectedPacketByteBuildOptions {
            .packet_bytes = std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
            .flow_packet_index = packet_summary_preparation.flow_packet_index,
            .tls_initial_parser_context = packet_summary_preparation.tls_initial_parser_context,
            .reconstructed_tls_records = std::move(packet_summary_preparation.reconstructed_tls_records),
            .quic_presentation = std::move(packet_summary_preparation.quic_presentation),
        }
    );
}

std::vector<std::uint8_t> make_dns_query_payload() {
    std::vector<std::uint8_t> payload {};
    append_be16(payload, 0x1234U);
    append_be16(payload, 0x0100U);
    append_be16(payload, 1U);
    append_be16(payload, 0U);
    append_be16(payload, 0U);
    append_be16(payload, 0U);
    payload.push_back(3U);
    payload.insert(payload.end(), {'a', 'p', 'i'});
    payload.push_back(7U);
    payload.insert(payload.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e'});
    payload.push_back(0U);
    append_be16(payload, 1U);
    append_be16(payload, 1U);
    return payload;
}

std::vector<std::uint8_t> bytes_payload(std::string_view text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

const SelectedPacketByteViewDescriptor* require_view_in_scope(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint8_t occurrence = 0U
) {
    const auto* view = presentation.find_view(SelectedPacketByteViewId {
        .kind = kind,
        .scope = scope,
        .occurrence = occurrence,
    });
    PFL_REQUIRE(view != nullptr);
    return view;
}

const SelectedPacketByteViewDescriptor* require_view(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t occurrence = 0U
) {
    return require_view_in_scope(presentation, kind, 0U, occurrence);
}

const SelectedPacketByteViewDescriptor* find_view_in_scope(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint8_t occurrence = 0U
) {
    return presentation.find_view(SelectedPacketByteViewId {
        .kind = kind,
        .scope = scope,
        .occurrence = occurrence,
    });
}

const SelectedPacketByteViewDescriptor* find_view(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t occurrence = 0U
) {
    return find_view_in_scope(presentation, kind, 0U, occurrence);
}

std::size_t require_kind_index_in_scope(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t scope,
    const std::uint8_t occurrence = 0U
) {
    for (std::size_t index = 0U; index < presentation.views.size(); ++index) {
        if (presentation.views[index].id == SelectedPacketByteViewId {
                .kind = kind,
                .scope = scope,
                .occurrence = occurrence,
            }) {
            return index;
        }
    }
    PFL_REQUIRE(false);
    return 0U;
}

std::size_t require_kind_index(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t occurrence = 0U
) {
    return require_kind_index_in_scope(presentation, kind, 0U, occurrence);
}

SelectedPacketByteMaterialization require_materialized_view(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    const std::vector<std::uint8_t>& owner_bytes,
    const session_detail::SelectedPacketByteRangeMode mode = session_detail::SelectedPacketByteRangeMode::whole_unit
) {
    const auto materialized = session_detail::materialize_selected_packet_byte_view(
        presentation,
        id,
        std::span<const std::uint8_t>(owner_bytes.data(), owner_bytes.size()),
        mode
    );
    PFL_REQUIRE(materialized.has_value());
    PFL_REQUIRE(materialized->descriptor != nullptr);
    return *materialized;
}

void expect_materialized_view_aliases_owner_bytes(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    const std::vector<std::uint8_t>& owner_bytes,
    const session_detail::SelectedPacketByteRangeMode mode = session_detail::SelectedPacketByteRangeMode::whole_unit
) {
    const auto materialized = require_materialized_view(presentation, id, owner_bytes, mode);
    const auto expected_offset = mode == session_detail::SelectedPacketByteRangeMode::payload_only
        ? materialized.descriptor->payload_range->offset
        : materialized.descriptor->offset;
    const auto expected_length = mode == session_detail::SelectedPacketByteRangeMode::payload_only
        ? materialized.descriptor->payload_range->captured_length
        : materialized.descriptor->captured_length;
    PFL_EXPECT(materialized.bytes.data() == owner_bytes.data() + expected_offset);
    PFL_EXPECT(materialized.bytes.size() == expected_length);
}

void expect_parent_in_scope(
    const SelectedPacketByteViewDescriptor& child,
    const SelectedPacketByteViewKind parent_kind,
    const std::uint8_t parent_scope,
    const std::uint8_t parent_occurrence = 0U
) {
    PFL_REQUIRE(child.parent_id.has_value());
    const SelectedPacketByteViewId expected_parent {
        .kind = parent_kind,
        .scope = parent_scope,
        .occurrence = parent_occurrence,
    };
    PFL_EXPECT(*child.parent_id == expected_parent);
}

void expect_parent(
    const SelectedPacketByteViewDescriptor& child,
    const SelectedPacketByteViewKind parent_kind,
    const std::uint8_t parent_occurrence = 0U
) {
    expect_parent_in_scope(child, parent_kind, 0U, parent_occurrence);
}

void expect_ascii_prefix(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    const std::vector<std::uint8_t>& owner_bytes,
    const std::string_view expected_prefix,
    const session_detail::SelectedPacketByteRangeMode mode = session_detail::SelectedPacketByteRangeMode::whole_unit
) {
    const auto materialized = require_materialized_view(presentation, id, owner_bytes, mode);
    PFL_REQUIRE(materialized.bytes.size() >= expected_prefix.size());
    for (std::size_t index = 0U; index < expected_prefix.size(); ++index) {
        PFL_EXPECT(materialized.bytes[index] == static_cast<std::uint8_t>(expected_prefix[index]));
    }
}

std::vector<std::string> collect_labels(const SelectedPacketBytePresentation& presentation) {
    const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);
    std::vector<std::string> labels {};
    labels.reserve(descriptors.size());
    for (const auto& descriptor : descriptors) {
        labels.push_back(descriptor.label);
    }
    return labels;
}

void expect_materialized_view_aliases_derived_owner(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewDescriptor& view
) {
    const auto* owner = presentation.find_derived_owner(view.owner_id);
    PFL_REQUIRE(owner != nullptr);
    const auto materialized = session_detail::materialize_selected_packet_byte_view(
        presentation,
        view.id,
        std::span<const std::uint8_t> {}
    );
    PFL_REQUIRE(materialized.has_value());
    PFL_REQUIRE(materialized->descriptor != nullptr);
    PFL_EXPECT(materialized->bytes.data() == owner->bytes.data() + materialized->descriptor->offset);
    PFL_EXPECT(materialized->bytes.size() == materialized->descriptor->captured_length);
}

void run_selected_packet_byte_presentation_tests_impl() {
    {
        const auto path = write_temp_pcap(
            "pfl_selected_packet_byte_tcp_views.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 1, 0, 1),
                    ipv4(10, 1, 0, 2),
                    12345,
                    443,
                    std::vector<std::uint8_t> {
                        static_cast<std::uint8_t>('A'),
                        static_cast<std::uint8_t>('B'),
                        static_cast<std::uint8_t>('C'),
                        static_cast<std::uint8_t>('D'),
                    }
                )
            }})
        );

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(path));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* frame = require_view(presentation, SelectedPacketByteViewKind::frame);
        const auto* ethernet_payload = require_view(presentation, SelectedPacketByteViewKind::ethernet_payload);
        const auto* ipv4_payload = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* tcp_payload = require_view(presentation, SelectedPacketByteViewKind::tcp_payload);
        const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);
        const std::vector<std::string> expected_labels {
            "Frame",
            "Ethernet II Frame",
            "IPv4 Packet",
            "TCP Segment",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        PFL_EXPECT(frame->offset == 0U);
        PFL_EXPECT(frame->captured_length == packet.captured_length);
        PFL_EXPECT(ethernet_payload->offset == 0U);
        PFL_EXPECT(ethernet_payload->captured_length == packet.captured_length);
        PFL_EXPECT(ipv4_payload->offset == 14U);
        PFL_EXPECT(tcp_payload->offset == 34U);
        PFL_REQUIRE(descriptors.size() == 4U);
        PFL_EXPECT(descriptors[0].stable_id == "frame:0:0");
        PFL_EXPECT(descriptors[1].stable_id == "ethernet:0:0");
        PFL_EXPECT(descriptors[2].stable_id == "ipv4:0:0");
        PFL_EXPECT(descriptors[3].stable_id == "tcp:0:0");
        PFL_EXPECT(descriptors[0].stable_id != descriptors[1].stable_id);
        PFL_EXPECT(descriptors[0].available_length == descriptors[1].available_length);
        PFL_EXPECT(!descriptors[0].supports_payload_only);
        PFL_EXPECT(descriptors[1].supports_payload_only);
        PFL_EXPECT(descriptors[2].supports_payload_only);
        PFL_EXPECT(descriptors[3].supports_payload_only);
        expect_parent(*ethernet_payload, SelectedPacketByteViewKind::frame);
        expect_parent(*ipv4_payload, SelectedPacketByteViewKind::ethernet_payload);
        expect_parent(*tcp_payload, SelectedPacketByteViewKind::ipv4_payload);
        expect_materialized_view_aliases_owner_bytes(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::tcp_payload, .occurrence = 0U},
            bytes
        );
        expect_materialized_view_aliases_owner_bytes(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::tcp_payload, .occurrence = 0U},
            bytes,
            session_detail::SelectedPacketByteRangeMode::payload_only
        );

        const auto tcp_dump = session.format_selected_packet_byte_view_hex_dump(
            packet,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::tcp_payload, .occurrence = 0U}
        );
        PFL_REQUIRE(tcp_dump.has_value());
        PFL_EXPECT(tcp_dump->find("30 39 01 bb") != std::string::npos);
        expect_ascii_prefix(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::tcp_payload, .occurrence = 0U},
            bytes,
            "ABCD",
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::effective_transport_payload) == nullptr);
    }

    {
        const auto full_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 2, 0, 1),
            ipv4(10, 2, 0, 2),
            53000,
            53001,
            std::vector<std::uint8_t> {
                static_cast<std::uint8_t>('a'),
                static_cast<std::uint8_t>('b'),
                static_cast<std::uint8_t>('c'),
                static_cast<std::uint8_t>('d'),
                static_cast<std::uint8_t>('e'),
                static_cast<std::uint8_t>('f'),
                static_cast<std::uint8_t>('g'),
            }
        );
        std::vector<std::uint8_t> captured_packet(
            full_packet.begin(),
            full_packet.begin() + static_cast<std::ptrdiff_t>(full_packet.size() - 3U)
        );
        const auto path = write_temp_pcap(
            "pfl_selected_packet_byte_udp_truncated.pcap",
            make_classic_pcap_with_captured_lengths({
                ClassicPcapCapturedRecord {
                    .ts_usec = 100U,
                    .captured_bytes = captured_packet,
                    .original_length = static_cast<std::uint32_t>(full_packet.size()),
                }
            })
        );

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(path));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* udp_payload = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        PFL_EXPECT(udp_payload->captured_length == 12U);
        PFL_EXPECT(udp_payload->declared_length == std::optional<std::uint32_t> {15U});
        PFL_EXPECT(udp_payload->truncated);
        PFL_REQUIRE(udp_payload->payload_range.has_value());
        PFL_EXPECT(udp_payload->payload_range->captured_length == 4U);
        PFL_EXPECT(udp_payload->payload_range->declared_length == std::optional<std::uint32_t> {7U});
        PFL_EXPECT(udp_payload->payload_range->truncated);
        expect_materialized_view_aliases_owner_bytes(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::udp_payload, .occurrence = 0U},
            bytes
        );
        expect_materialized_view_aliases_owner_bytes(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::udp_payload, .occurrence = 0U},
            bytes,
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/dns/dns_request_1.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* udp_payload = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        PFL_REQUIRE(udp_payload->payload_range.has_value());
        const auto* dns_message = require_view(presentation, SelectedPacketByteViewKind::dns_message);
        expect_parent(*dns_message, SelectedPacketByteViewKind::udp_payload);
        PFL_EXPECT(dns_message->offset == udp_payload->payload_range->offset);
        PFL_EXPECT(dns_message->captured_length == udp_payload->payload_range->captured_length);
        PFL_EXPECT(dns_message->declared_length == udp_payload->payload_range->declared_length);
        PFL_EXPECT(!dns_message->payload_range.has_value());

        const auto materialized = require_materialized_view(presentation, dns_message->id, bytes);
        PFL_REQUIRE(materialized.bytes.size() >= 4U);
        PFL_EXPECT(materialized.bytes[0] == 0xC7U);
        PFL_EXPECT(materialized.bytes[1] == 0x07U);
        PFL_EXPECT(materialized.bytes[2] == 0x01U);
        PFL_EXPECT(materialized.bytes[3] == 0x00U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/dns/dns_response_2.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* udp_payload = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        PFL_REQUIRE(udp_payload->payload_range.has_value());
        const auto* dns_message = require_view(presentation, SelectedPacketByteViewKind::dns_message);
        expect_parent(*dns_message, SelectedPacketByteViewKind::udp_payload);
        PFL_EXPECT(dns_message->offset == udp_payload->payload_range->offset);
        PFL_EXPECT(dns_message->captured_length == udp_payload->payload_range->captured_length);

        const auto materialized = require_materialized_view(presentation, dns_message->id, bytes);
        PFL_REQUIRE(materialized.bytes.size() >= 4U);
        PFL_EXPECT(materialized.bytes[0] == 0x1DU);
        PFL_EXPECT(materialized.bytes[1] == 0xE6U);
        PFL_EXPECT(materialized.bytes[2] == 0x85U);
        PFL_EXPECT(materialized.bytes[3] == 0x80U);
    }

    {
        const auto path = write_temp_pcap(
            "pfl_selected_packet_byte_false_dns_port_53.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 2, 1, 1),
                    ipv4(10, 2, 1, 2),
                    53000,
                    53,
                    bytes_payload("not-dns-payload"))
            }})
        );

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(path));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);
        PFL_REQUIRE(require_view(presentation, SelectedPacketByteViewKind::udp_payload) != nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::dns_message) == nullptr);
    }

    {
        auto dns_over_tcp_payload = make_dns_query_payload();
        const auto dns_message_length = static_cast<std::uint16_t>(dns_over_tcp_payload.size());
        dns_over_tcp_payload.insert(
            dns_over_tcp_payload.begin(),
            {
                static_cast<std::uint8_t>((dns_message_length >> 8U) & 0xFFU),
                static_cast<std::uint8_t>(dns_message_length & 0xFFU),
            }
        );

        const auto path = write_temp_pcap(
            "pfl_selected_packet_byte_dns_over_tcp.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 2, 2, 1),
                    ipv4(10, 2, 2, 2),
                    52000,
                    53,
                    dns_over_tcp_payload,
                    0x18)
            }})
        );

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(path));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* tcp_segment = require_view(presentation, SelectedPacketByteViewKind::tcp_payload);
        PFL_REQUIRE(tcp_segment->payload_range.has_value());
        const auto* dns_message = require_view(presentation, SelectedPacketByteViewKind::dns_message);
        expect_parent(*dns_message, SelectedPacketByteViewKind::tcp_payload);
        PFL_EXPECT(dns_message->offset == tcp_segment->payload_range->offset + 2U);
        PFL_EXPECT(dns_message->captured_length + 2U == tcp_segment->payload_range->captured_length);

        const auto materialized = require_materialized_view(presentation, dns_message->id, bytes);
        PFL_REQUIRE(materialized.bytes.size() >= 4U);
        PFL_EXPECT(materialized.bytes[0] == 0x12U);
        PFL_EXPECT(materialized.bytes[1] == 0x34U);
        PFL_EXPECT(materialized.bytes[2] == 0x01U);
        PFL_EXPECT(materialized.bytes[3] == 0x00U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vlan/05_qinq_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const std::vector<std::string> expected_labels {
            "Frame",
            "Ethernet II Frame",
            "802.1Q Encapsulation",
            "802.1Q Encapsulation #2",
            "IPv4 Packet",
            "UDP Datagram",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        expect_parent(*require_view(presentation, SelectedPacketByteViewKind::vlan_payload, 0U), SelectedPacketByteViewKind::ethernet_payload);
        expect_parent(*require_view(presentation, SelectedPacketByteViewKind::vlan_payload, 1U), SelectedPacketByteViewKind::vlan_payload, 0U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/arp/08_arp_request_with_ethernet_padding.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const std::vector<std::string> expected_labels {
            "Frame",
            "Ethernet II Frame",
            "ARP Packet",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        const auto* ethernet_view = require_view(presentation, SelectedPacketByteViewKind::ethernet_payload);
        const auto* arp_view = require_view(presentation, SelectedPacketByteViewKind::arp);
        expect_parent(*ethernet_view, SelectedPacketByteViewKind::frame);
        expect_parent(*arp_view, SelectedPacketByteViewKind::ethernet_payload);
        PFL_EXPECT(arp_view->offset == 14U);
        PFL_EXPECT(arp_view->captured_length == 28U);
        PFL_EXPECT(arp_view->declared_length == std::optional<std::uint32_t> {28U});
        PFL_EXPECT(!arp_view->payload_range.has_value());
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/tls/tls_client_hello_1.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* tcp_segment = require_view(presentation, SelectedPacketByteViewKind::tcp_payload);
        PFL_REQUIRE(tcp_segment->payload_range.has_value());
        const auto* tls_record = require_view(presentation, SelectedPacketByteViewKind::tls_record);
        const auto* tls_handshake = require_view(presentation, SelectedPacketByteViewKind::tls_handshake);
        expect_parent(*tls_record, SelectedPacketByteViewKind::tcp_payload);
        expect_parent(*tls_handshake, SelectedPacketByteViewKind::tls_record);
        PFL_EXPECT(tls_record->owner_kind == session_detail::SelectedPacketByteOwnerKind::captured_packet);
        PFL_EXPECT(tls_handshake->owner_kind == session_detail::SelectedPacketByteOwnerKind::captured_packet);
        PFL_EXPECT(tls_record->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::packet_local);
        PFL_EXPECT(tls_handshake->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::packet_local);
        PFL_EXPECT(!tls_record->contributing_unit_count.has_value());
        PFL_EXPECT(!tls_handshake->contributing_unit_count.has_value());
        PFL_EXPECT(tls_record->offset == tcp_segment->payload_range->offset);
        PFL_REQUIRE(tls_record->payload_range.has_value());
        PFL_REQUIRE(tls_handshake->payload_range.has_value());

        const auto labels = collect_labels(presentation);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Record") != labels.end());
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Message, ClientHello") != labels.end());

        const auto whole_record = require_materialized_view(presentation, tls_record->id, bytes);
        const auto record_payload = require_materialized_view(
            presentation,
            tls_record->id,
            bytes,
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
        const auto whole_handshake = require_materialized_view(presentation, tls_handshake->id, bytes);
        const auto handshake_payload = require_materialized_view(
            presentation,
            tls_handshake->id,
            bytes,
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
        PFL_REQUIRE(whole_record.bytes.size() >= 3U);
        PFL_REQUIRE(record_payload.bytes.size() >= 1U);
        PFL_REQUIRE(whole_handshake.bytes.size() >= 1U);
        PFL_REQUIRE(handshake_payload.bytes.size() >= 2U);
        PFL_EXPECT(whole_record.bytes[0] == 0x16U);
        PFL_EXPECT(whole_record.bytes[1] == 0x03U);
        PFL_EXPECT(whole_record.bytes[2] == 0x01U);
        PFL_EXPECT(record_payload.bytes[0] == 0x01U);
        PFL_EXPECT(whole_handshake.bytes[0] == 0x01U);
        PFL_EXPECT(handshake_payload.bytes[0] == 0x03U);
        PFL_EXPECT(handshake_payload.bytes[1] == 0x03U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/tls/tls_1_2_server_hello_4.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* tls_record = require_view(presentation, SelectedPacketByteViewKind::tls_record);
        const auto* tls_handshake = require_view(presentation, SelectedPacketByteViewKind::tls_handshake);
        expect_parent(*tls_record, SelectedPacketByteViewKind::tcp_payload);
        expect_parent(*tls_handshake, SelectedPacketByteViewKind::tls_record);
        const auto labels = collect_labels(presentation);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Record") != labels.end());
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Message, ServerHello") != labels.end());
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/tls/tls_1_2_app_data_3.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* tls_record = require_view(presentation, SelectedPacketByteViewKind::tls_record);
        expect_parent(*tls_record, SelectedPacketByteViewKind::tcp_payload);
        const auto labels = collect_labels(presentation);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Application Data Record") != labels.end());
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::tls_handshake) == nullptr);
    }

    {
        const auto path = write_temp_pcap(
            "pfl_selected_packet_byte_tls_partial_client_hello.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 3, 0, 1),
                    ipv4(10, 3, 0, 2),
                    41003,
                    443,
                    {0x16U, 0x03U, 0x03U, 0x00U, 0x08U, 0x01U, 0x02U},
                    0x18)
            }})
        );

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(path));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* tls_record = require_view(presentation, SelectedPacketByteViewKind::tls_record);
        const auto* tls_handshake = require_view(presentation, SelectedPacketByteViewKind::tls_handshake);
        PFL_EXPECT(tls_record->truncated);
        PFL_EXPECT(tls_handshake->truncated);
        const auto labels = collect_labels(presentation);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Record Fragment") != labels.end());
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Message, ClientHello") != labels.end());
        const auto record_payload = require_materialized_view(
            presentation,
            tls_record->id,
            bytes,
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
        PFL_REQUIRE(!record_payload.bytes.empty());
        PFL_EXPECT(record_payload.bytes[0] == 0x01U);
    }

    {
        const auto path = write_temp_pcap(
            "pfl_selected_packet_byte_tls_zero_length_handshake_like.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 3, 1, 1),
                    ipv4(10, 3, 1, 2),
                    41004,
                    443,
                    {0x16U, 0x03U, 0x03U, 0x00U, 0x00U},
                    0x18)
            }})
        );

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(path));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::tls_record) == nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::tls_handshake) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/tls/tls_1_3_split_client_hello_10.pcap")));

        const auto packet3 = require_packet(session, 2U);
        const auto packet4 = require_packet(session, 3U);
        const auto packet5 = require_packet(session, 4U);
        const auto packet3_presentation = require_flow_aware_presentation(session, packet3);
        const auto packet4_presentation = require_flow_aware_presentation(session, packet4);
        const auto packet5_presentation = require_flow_aware_presentation(session, packet5);

        PFL_EXPECT(find_view(packet3_presentation, SelectedPacketByteViewKind::tls_record) == nullptr);
        PFL_EXPECT(find_view(packet3_presentation, SelectedPacketByteViewKind::tls_handshake) == nullptr);

        const auto* packet4_tls_record = require_view(packet4_presentation, SelectedPacketByteViewKind::tls_record);
        const auto* packet4_tls_handshake = require_view(packet4_presentation, SelectedPacketByteViewKind::tls_handshake);
        const auto* packet5_tls_record = require_view(packet5_presentation, SelectedPacketByteViewKind::tls_record);
        const auto* packet5_tls_handshake = require_view(packet5_presentation, SelectedPacketByteViewKind::tls_handshake);
        PFL_EXPECT(packet4_tls_record->owner_kind == session_detail::SelectedPacketByteOwnerKind::tls_reconstructed_record);
        PFL_EXPECT(packet4_tls_handshake->owner_kind == session_detail::SelectedPacketByteOwnerKind::tls_reconstructed_record);
        PFL_EXPECT(packet5_tls_record->owner_kind == session_detail::SelectedPacketByteOwnerKind::tls_reconstructed_record);
        PFL_EXPECT(packet5_tls_handshake->owner_kind == session_detail::SelectedPacketByteOwnerKind::tls_reconstructed_record);
        PFL_EXPECT(packet4_tls_record->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::reassembled);
        PFL_EXPECT(packet4_tls_handshake->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::reassembled);
        PFL_EXPECT(packet5_tls_record->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::reassembled);
        PFL_EXPECT(packet5_tls_handshake->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::reassembled);
        PFL_EXPECT(packet4_tls_record->contributing_unit_count == std::optional<std::uint32_t> {2U});
        PFL_EXPECT(packet4_tls_handshake->contributing_unit_count == std::optional<std::uint32_t> {2U});
        PFL_EXPECT(packet5_tls_record->contributing_unit_count == std::optional<std::uint32_t> {2U});
        PFL_EXPECT(packet5_tls_handshake->contributing_unit_count == std::optional<std::uint32_t> {2U});
        PFL_EXPECT(packet4_tls_record->contributing_unit_kind ==
            std::optional<session_detail::SelectedPacketByteContributionUnitKind> {
                session_detail::SelectedPacketByteContributionUnitKind::tcp_segment
            });
        PFL_EXPECT(packet4_tls_handshake->contributing_unit_kind ==
            std::optional<session_detail::SelectedPacketByteContributionUnitKind> {
                session_detail::SelectedPacketByteContributionUnitKind::tcp_segment
            });
        expect_parent(*packet4_tls_record, SelectedPacketByteViewKind::tcp_payload);
        expect_parent(*packet4_tls_handshake, SelectedPacketByteViewKind::tls_record);
        expect_parent(*packet5_tls_record, SelectedPacketByteViewKind::tcp_payload);
        expect_parent(*packet5_tls_handshake, SelectedPacketByteViewKind::tls_record);
        PFL_EXPECT(packet4_tls_record->offset == 0U);
        PFL_EXPECT(packet5_tls_record->offset == 0U);
        PFL_EXPECT(packet4_tls_record->captured_length == packet5_tls_record->captured_length);
        PFL_EXPECT(std::find(
            collect_labels(packet4_presentation).begin(),
            collect_labels(packet4_presentation).end(),
            "TLS Handshake Record (Reassembled)") != collect_labels(packet4_presentation).end());
        PFL_EXPECT(std::find(
            collect_labels(packet5_presentation).begin(),
            collect_labels(packet5_presentation).end(),
            "TLS Handshake Message, ClientHello (Reassembled)") != collect_labels(packet5_presentation).end());
        expect_materialized_view_aliases_derived_owner(packet4_presentation, *packet4_tls_record);
        expect_materialized_view_aliases_derived_owner(packet4_presentation, *packet4_tls_handshake);
        expect_materialized_view_aliases_derived_owner(packet5_presentation, *packet5_tls_record);
        expect_materialized_view_aliases_derived_owner(packet5_presentation, *packet5_tls_handshake);
    }

    {
        const auto path = write_temp_pcap(
            "pfl_selected_packet_byte_icmp_unit.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_icmp_packet(ipv4(10, 30, 0, 1), ipv4(10, 30, 0, 2), 8U, 0U)
            }})
        );

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(path));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const std::vector<std::string> expected_labels {
            "Frame",
            "Ethernet II Frame",
            "IPv4 Packet",
            "ICMP Message",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        const auto* icmp_view = require_view(presentation, SelectedPacketByteViewKind::icmp);
        expect_parent(*icmp_view, SelectedPacketByteViewKind::ipv4_payload);
        PFL_REQUIRE(icmp_view->payload_range.has_value());
        PFL_EXPECT(icmp_view->payload_range->offset == icmp_view->offset + 4U);
    }

    {
        const auto ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
        const auto ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
        const auto path = write_temp_pcap(
            "pfl_selected_packet_byte_icmpv6_unit.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(ipv6_src, ipv6_dst, 128U, 0U)
            }})
        );

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(path));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const std::vector<std::string> expected_labels {
            "Frame",
            "Ethernet II Frame",
            "IPv6 Packet",
            "ICMPv6 Message",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        const auto* ipv6_view = require_view(presentation, SelectedPacketByteViewKind::ipv6_payload);
        const auto* icmpv6_view = require_view(presentation, SelectedPacketByteViewKind::icmpv6);
        PFL_REQUIRE(ipv6_view->payload_range.has_value());
        expect_parent(*icmpv6_view, SelectedPacketByteViewKind::ipv6_payload);
        PFL_EXPECT(icmpv6_view->offset >= ipv6_view->payload_range->offset);
        PFL_REQUIRE(icmpv6_view->payload_range.has_value());
        PFL_EXPECT(icmpv6_view->payload_range->offset == icmpv6_view->offset + 4U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/igmp/02_igmpv2_membership_report_mdns_group.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const std::vector<std::string> expected_labels {
            "Frame",
            "Ethernet II Frame",
            "IPv4 Packet",
            "IGMP Message",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        const auto* igmp_view = require_view(presentation, SelectedPacketByteViewKind::igmp);
        expect_parent(*igmp_view, SelectedPacketByteViewKind::ipv4_payload);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/32_gtpu_inner_ipv4_udp_data.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* gtpu_payload = require_view(presentation, SelectedPacketByteViewKind::gtpu_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_udp = require_view(presentation, SelectedPacketByteViewKind::inner_udp_payload);
        PFL_EXPECT(require_kind_index(presentation, SelectedPacketByteViewKind::udp_payload) <
            require_kind_index(presentation, SelectedPacketByteViewKind::gtpu_payload));
        PFL_EXPECT(require_kind_index(presentation, SelectedPacketByteViewKind::gtpu_payload) <
            require_kind_index(presentation, SelectedPacketByteViewKind::inner_ipv4_payload));
        PFL_EXPECT(require_kind_index(presentation, SelectedPacketByteViewKind::inner_ipv4_payload) <
            require_kind_index(presentation, SelectedPacketByteViewKind::inner_udp_payload));
        expect_parent(*gtpu_payload, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::gtpu_payload);
        expect_parent(*inner_udp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_EXPECT(gtpu_payload->offset == inner_ipv4->offset);
        PFL_EXPECT(inner_udp->captured_length > 48U);
        PFL_REQUIRE(inner_udp->payload_range.has_value());
        PFL_EXPECT(inner_udp->payload_range->captured_length == 48U);
        expect_ascii_prefix(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::inner_udp_payload, .occurrence = 0U},
            bytes,
            "INNER-UDP-DATA",
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/33_gtpu_inner_ipv4_tcp_data.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* gtpu_payload = require_view(presentation, SelectedPacketByteViewKind::gtpu_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_tcp = require_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload);
        expect_parent(*gtpu_payload, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::gtpu_payload);
        expect_parent(*inner_tcp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_EXPECT(inner_tcp->captured_length > 48U);
        PFL_REQUIRE(inner_tcp->payload_range.has_value());
        PFL_EXPECT(inner_tcp->payload_range->captured_length == 48U);
        expect_ascii_prefix(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::inner_tcp_payload, .occurrence = 0U},
            bytes,
            "INNER-TCP-DATA",
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/34_gtpu_inner_ipv4_tcp_ack_only.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        PFL_REQUIRE(find_view(presentation, SelectedPacketByteViewKind::gtpu_payload) != nullptr);
        PFL_REQUIRE(find_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload) != nullptr);
        const auto* inner_tcp = require_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload);
        PFL_EXPECT(!inner_tcp->payload_range.has_value());
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::tcp_payload) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gre/15_gre_mpls_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* gre_payload = require_view(presentation, SelectedPacketByteViewKind::gre_payload);
        const auto* mpls_payload = require_view(presentation, SelectedPacketByteViewKind::mpls_payload, 0U);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_udp = require_view(presentation, SelectedPacketByteViewKind::inner_udp_payload);
        expect_parent(*gre_payload, SelectedPacketByteViewKind::ipv4_payload);
        expect_parent(*mpls_payload, SelectedPacketByteViewKind::gre_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::mpls_payload, 0U);
        expect_parent(*inner_udp, SelectedPacketByteViewKind::inner_ipv4_payload);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/eoip/04_ipv4_eoip_inner_vlan_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* eoip_payload = require_view(presentation, SelectedPacketByteViewKind::eoip_payload);
        const auto* inner_ethernet = require_view(presentation, SelectedPacketByteViewKind::inner_ethernet_payload);
        const auto* inner_vlan = require_view(presentation, SelectedPacketByteViewKind::inner_vlan_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_udp = require_view(presentation, SelectedPacketByteViewKind::inner_udp_payload);
        expect_parent(*eoip_payload, SelectedPacketByteViewKind::ipv4_payload);
        expect_parent(*inner_ethernet, SelectedPacketByteViewKind::eoip_payload);
        expect_parent(*inner_vlan, SelectedPacketByteViewKind::inner_ethernet_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::inner_vlan_payload);
        expect_parent(*inner_udp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_EXPECT(eoip_payload->offset == inner_ethernet->offset);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/13_vxlan_inner_vlan_ipv4_tcp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* vxlan_payload = require_view(presentation, SelectedPacketByteViewKind::vxlan_payload);
        const auto* inner_ethernet = require_view(presentation, SelectedPacketByteViewKind::inner_ethernet_payload);
        const auto* inner_vlan = require_view(presentation, SelectedPacketByteViewKind::inner_vlan_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_tcp = require_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload);
        expect_parent(*vxlan_payload, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ethernet, SelectedPacketByteViewKind::vxlan_payload);
        expect_parent(*inner_vlan, SelectedPacketByteViewKind::inner_ethernet_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::inner_vlan_payload);
        expect_parent(*inner_tcp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_EXPECT(vxlan_payload->offset == inner_ethernet->offset);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/17_geneve_with_options_inner_ipv4_tcp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* geneve_payload = require_view(presentation, SelectedPacketByteViewKind::geneve_payload);
        const auto* inner_ethernet = require_view(presentation, SelectedPacketByteViewKind::inner_ethernet_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_tcp = require_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload);
        expect_parent(*geneve_payload, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ethernet, SelectedPacketByteViewKind::geneve_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::inner_ethernet_payload);
        expect_parent(*inner_tcp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_EXPECT(geneve_payload->offset == inner_ethernet->offset);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/sctp/18_sctp_vxlan_inner_ipv4_data_s1ap.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* vxlan_payload = require_view(presentation, SelectedPacketByteViewKind::vxlan_payload);
        const auto* inner_ethernet = require_view(presentation, SelectedPacketByteViewKind::inner_ethernet_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_sctp = require_view(presentation, SelectedPacketByteViewKind::inner_sctp_payload);
        expect_parent(*vxlan_payload, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ethernet, SelectedPacketByteViewKind::vxlan_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::inner_ethernet_payload);
        expect_parent(*inner_sctp, SelectedPacketByteViewKind::inner_ipv4_payload);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/sctp/20_sctp_gtpu_inner_ipv4_data_s1ap.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* gtpu_payload = require_view(presentation, SelectedPacketByteViewKind::gtpu_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_sctp = require_view(presentation, SelectedPacketByteViewKind::inner_sctp_payload);
        expect_parent(*gtpu_payload, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::gtpu_payload);
        expect_parent(*inner_sctp, SelectedPacketByteViewKind::inner_ipv4_payload);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/ah/12_ipv4_ah_inner_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* ah_payload = require_view(presentation, SelectedPacketByteViewKind::ah_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_udp = require_view(presentation, SelectedPacketByteViewKind::inner_udp_payload);
        expect_parent(*ah_payload, SelectedPacketByteViewKind::ipv4_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::ah_payload);
        expect_parent(*inner_udp, SelectedPacketByteViewKind::inner_ipv4_payload);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/ah/13_ipv4_ah_inner_ipv6_tcp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* ah_payload = require_view(presentation, SelectedPacketByteViewKind::ah_payload);
        const auto* inner_ipv6 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv6_payload);
        expect_parent(*ah_payload, SelectedPacketByteViewKind::ipv4_payload);
        expect_parent(*inner_ipv6, SelectedPacketByteViewKind::ah_payload);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/esp/01_ipv4_esp_basic.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* esp_payload = require_view(presentation, SelectedPacketByteViewKind::esp_protected_payload);
        expect_parent(*esp_payload, SelectedPacketByteViewKind::ipv4_payload);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload) == nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::inner_udp_payload) == nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/ip_encapsulation/12_nested_ipv4_in_ipv4_in_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::gre_payload) == nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::gtpu_payload) == nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::vxlan_payload) == nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::geneve_payload) == nullptr);
        PFL_REQUIRE(find_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload, 0U) != nullptr);
        PFL_REQUIRE(find_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload, 1U) != nullptr);
        PFL_REQUIRE(find_view(presentation, SelectedPacketByteViewKind::inner_udp_payload) != nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/08_gtpu_truncated_inner_ipv4.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* gtpu_payload = require_view(presentation, SelectedPacketByteViewKind::gtpu_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_EXPECT(gtpu_payload->captured_length >= inner_ipv4->captured_length);
        PFL_EXPECT(inner_ipv4->truncated);
        expect_materialized_view_aliases_owner_bytes(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::inner_ipv4_payload, .occurrence = 0U},
            bytes
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/quic/quic_initial_ch_1.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* udp_payload = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        const auto* quic_packet = require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_packet, 0U);
        const auto* protected_payload =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_protected_payload, 0U);
        const auto* plaintext =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
        const auto* crypto_frame = require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_frame, 0U);
        const auto* crypto_data =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U);
        const auto* tls_handshake =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::tls_handshake, 0U);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_stream, 0U) == nullptr);
        PFL_EXPECT(quic_packet->owner_kind == session_detail::SelectedPacketByteOwnerKind::captured_packet);
        PFL_EXPECT(plaintext->owner_kind == session_detail::SelectedPacketByteOwnerKind::quic_initial_plaintext);
        PFL_EXPECT(tls_handshake->owner_kind == session_detail::SelectedPacketByteOwnerKind::quic_crypto_prefix);
        PFL_EXPECT(tls_handshake->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::packet_local);
        PFL_EXPECT(!tls_handshake->contributing_unit_count.has_value());
        PFL_EXPECT(quic_packet->offset >= udp_payload->offset);
        PFL_EXPECT(quic_packet->offset + quic_packet->captured_length <= udp_payload->offset + udp_payload->captured_length);
        expect_parent(*quic_packet, SelectedPacketByteViewKind::udp_payload);
        expect_parent_in_scope(*protected_payload, SelectedPacketByteViewKind::quic_initial_packet, 0U);
        expect_parent_in_scope(*plaintext, SelectedPacketByteViewKind::quic_initial_packet, 0U);
        expect_parent_in_scope(*crypto_frame, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
        expect_parent_in_scope(*crypto_data, SelectedPacketByteViewKind::quic_frame, 0U);
        expect_parent_in_scope(*tls_handshake, SelectedPacketByteViewKind::quic_crypto_data, 0U);
        expect_materialized_view_aliases_owner_bytes(presentation, quic_packet->id, bytes);
        expect_materialized_view_aliases_derived_owner(presentation, *plaintext);
        expect_materialized_view_aliases_derived_owner(presentation, *crypto_frame);
        expect_materialized_view_aliases_derived_owner(presentation, *crypto_data);
        expect_materialized_view_aliases_derived_owner(presentation, *tls_handshake);

        const auto frame_materialized = require_materialized_view(presentation, crypto_frame->id, bytes);
        const auto crypto_data_materialized = require_materialized_view(presentation, crypto_data->id, bytes);
        const auto tls_handshake_materialized = require_materialized_view(presentation, tls_handshake->id, bytes);
        PFL_REQUIRE(!frame_materialized.bytes.empty());
        PFL_REQUIRE(!crypto_data_materialized.bytes.empty());
        PFL_REQUIRE(!tls_handshake_materialized.bytes.empty());
        PFL_EXPECT(frame_materialized.bytes.size() > crypto_data_materialized.bytes.size());
        PFL_EXPECT(frame_materialized.bytes[0] != crypto_data_materialized.bytes[0]);
        PFL_EXPECT(crypto_data_materialized.bytes[0] == 0x01U);
        PFL_EXPECT(tls_handshake_materialized.bytes[0] == 0x01U);
        PFL_EXPECT(crypto_data->quic_crypto_stream_offset.has_value());
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::tls_record, 0U) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/quic/quic_example_1.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* first_crypto_frame =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_frame, 0U, 0U);
        const auto* second_crypto_frame =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_frame, 0U, 1U);
        const auto* first_crypto_data =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U, 0U);
        const auto* second_crypto_data =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U, 1U);
        PFL_EXPECT(first_crypto_frame->owner_id == second_crypto_frame->owner_id);
        PFL_EXPECT(first_crypto_data->owner_id == second_crypto_data->owner_id);
        PFL_EXPECT(first_crypto_data->offset != second_crypto_data->offset);
        PFL_EXPECT(first_crypto_data->quic_crypto_stream_offset != second_crypto_data->quic_crypto_stream_offset);
        expect_materialized_view_aliases_derived_owner(presentation, *first_crypto_data);
        expect_materialized_view_aliases_derived_owner(presentation, *second_crypto_data);

        const auto first_materialized = require_materialized_view(presentation, first_crypto_data->id, bytes);
        const auto second_materialized = require_materialized_view(presentation, second_crypto_data->id, bytes);
        PFL_REQUIRE(!first_materialized.bytes.empty());
        PFL_REQUIRE(!second_materialized.bytes.empty());
        PFL_EXPECT(first_materialized.bytes[0] == 0x01U);
        PFL_EXPECT(second_materialized.bytes[0] == 0x01U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/quic/quic_initial_ack_decrypt_ok_1.pcap")));
        const auto packet = require_packet(session, 7U);
        const auto presentation = require_presentation(session, packet);

        const auto* quic_packet = require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_packet, 0U);
        const auto* plaintext =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
        const auto* ack_frame = require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_frame, 0U);
        PFL_EXPECT(quic_packet->owner_kind == session_detail::SelectedPacketByteOwnerKind::captured_packet);
        PFL_EXPECT(plaintext->owner_kind == session_detail::SelectedPacketByteOwnerKind::quic_initial_plaintext);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U) == nullptr);
        PFL_EXPECT(!ack_frame->quic_crypto_stream_offset.has_value());
        expect_parent_in_scope(*plaintext, SelectedPacketByteViewKind::quic_initial_packet, 0U);
        expect_parent_in_scope(*ack_frame, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/quic/quic_initial_ack_wrong_pkn_1.pcap")));
        const auto packet = require_packet(session, 7U);
        const auto presentation = require_presentation(session, packet);

        PFL_REQUIRE(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_packet, 0U) != nullptr);
        if (const auto* protected_payload =
                find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_protected_payload, 0U);
            protected_payload != nullptr) {
            expect_parent_in_scope(*protected_payload, SelectedPacketByteViewKind::quic_initial_packet, 0U);
        }
        PFL_EXPECT(presentation.derived_owners.empty());
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_plaintext, 0U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_frame, 0U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::tls_handshake, 0U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::tls_record, 0U) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/quic/quic_example_2.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_flow_aware_presentation(session, packet);

        const auto* plaintext =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
        const auto* first_crypto_frame =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_frame, 0U, 0U);
        const auto* second_crypto_frame =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_frame, 0U, 1U);
        const auto* first_crypto_data =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U, 0U);
        const auto* second_crypto_data =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U, 1U);
        const auto* crypto_stream =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_stream, 0U);
        const auto* tls_handshake =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::tls_handshake, 0U);

        expect_parent_in_scope(*plaintext, SelectedPacketByteViewKind::quic_initial_packet, 0U);
        expect_parent_in_scope(*first_crypto_frame, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
        expect_parent_in_scope(*second_crypto_frame, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
        expect_parent_in_scope(*first_crypto_data, SelectedPacketByteViewKind::quic_frame, 0U, 0U);
        expect_parent_in_scope(*second_crypto_data, SelectedPacketByteViewKind::quic_frame, 0U, 1U);
        expect_parent_in_scope(*crypto_stream, SelectedPacketByteViewKind::quic_initial_packet, 0U);
        expect_parent_in_scope(*tls_handshake, SelectedPacketByteViewKind::quic_crypto_stream, 0U);
        PFL_EXPECT(crypto_stream->owner_kind == session_detail::SelectedPacketByteOwnerKind::quic_crypto_prefix);
        PFL_EXPECT(tls_handshake->owner_kind == session_detail::SelectedPacketByteOwnerKind::quic_crypto_prefix);
        PFL_EXPECT(crypto_stream->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::reassembled);
        PFL_EXPECT(tls_handshake->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::reassembled);
        PFL_EXPECT(crypto_stream->contributing_unit_count == std::optional<std::uint32_t> {4U});
        PFL_EXPECT(tls_handshake->contributing_unit_count == std::optional<std::uint32_t> {4U});
        PFL_EXPECT(crypto_stream->contributing_unit_kind ==
            std::optional<session_detail::SelectedPacketByteContributionUnitKind> {
                session_detail::SelectedPacketByteContributionUnitKind::quic_crypto_frame
            });
        PFL_EXPECT(tls_handshake->contributing_unit_kind ==
            std::optional<session_detail::SelectedPacketByteContributionUnitKind> {
                session_detail::SelectedPacketByteContributionUnitKind::quic_crypto_frame
            });
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::tls_record, 0U) == nullptr);
        const auto labels = collect_labels(presentation);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "QUIC CRYPTO Stream (Reassembled)") != labels.end());
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Message, ClientHello (Reassembled)") != labels.end());
        const auto crypto_stream_materialized = require_materialized_view(presentation, crypto_stream->id, std::vector<std::uint8_t> {});
        const auto tls_handshake_materialized = require_materialized_view(presentation, tls_handshake->id, std::vector<std::uint8_t> {});
        PFL_REQUIRE(!crypto_stream_materialized.bytes.empty());
        PFL_REQUIRE(!tls_handshake_materialized.bytes.empty());
        PFL_EXPECT(crypto_stream_materialized.bytes[0] == 0x01U);
        PFL_EXPECT(tls_handshake_materialized.bytes[0] == 0x01U);
        PFL_EXPECT(first_crypto_data->owner_kind == session_detail::SelectedPacketByteOwnerKind::quic_initial_plaintext);
        PFL_EXPECT(second_crypto_data->owner_kind == session_detail::SelectedPacketByteOwnerKind::quic_initial_plaintext);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/quic/quic_example_2.pcap")));
        const auto packet = require_packet(session, 2U);
        const auto presentation = require_flow_aware_presentation(session, packet);

        const auto* udp_payload = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        const auto* initial_packet =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_packet, 0U);
        const auto* zero_rtt_packet =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_zero_rtt_packet, 1U);
        const auto* plaintext =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
        const auto* first_crypto_frame =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_frame, 0U, 0U);
        const auto* second_crypto_frame =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_frame, 0U, 1U);
        const auto* first_crypto_data =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U, 0U);
        const auto* second_crypto_data =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U, 1U);
        const auto* crypto_stream =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_stream, 0U);
        const auto* tls_handshake =
            require_view_in_scope(presentation, SelectedPacketByteViewKind::tls_handshake, 0U);
        PFL_EXPECT(initial_packet->offset >= udp_payload->offset);
        PFL_EXPECT(zero_rtt_packet->offset >= udp_payload->offset);
        PFL_EXPECT(initial_packet->offset + initial_packet->captured_length <= zero_rtt_packet->offset);
        expect_parent(*initial_packet, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*zero_rtt_packet, SelectedPacketByteViewKind::udp_payload);
        expect_parent_in_scope(*plaintext, SelectedPacketByteViewKind::quic_initial_packet, 0U);
        expect_parent_in_scope(*first_crypto_frame, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
        expect_parent_in_scope(*second_crypto_frame, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
        expect_parent_in_scope(*first_crypto_data, SelectedPacketByteViewKind::quic_frame, 0U, 0U);
        expect_parent_in_scope(*second_crypto_data, SelectedPacketByteViewKind::quic_frame, 0U, 1U);
        expect_parent_in_scope(*crypto_stream, SelectedPacketByteViewKind::quic_initial_plaintext, 0U);
        expect_parent_in_scope(*tls_handshake, SelectedPacketByteViewKind::quic_crypto_stream, 0U);
        PFL_EXPECT(crypto_stream->owner_kind == session_detail::SelectedPacketByteOwnerKind::quic_crypto_prefix);
        PFL_EXPECT(tls_handshake->owner_kind == session_detail::SelectedPacketByteOwnerKind::quic_crypto_prefix);
        PFL_EXPECT(crypto_stream->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::reassembled);
        PFL_EXPECT(tls_handshake->assembly_kind == session_detail::SelectedPacketByteAssemblyKind::reassembled);
        PFL_EXPECT(crypto_stream->contributing_unit_count == std::optional<std::uint32_t> {2U});
        PFL_EXPECT(tls_handshake->contributing_unit_count == std::optional<std::uint32_t> {2U});
        PFL_EXPECT(crypto_stream->contributing_unit_kind ==
            std::optional<session_detail::SelectedPacketByteContributionUnitKind> {
                session_detail::SelectedPacketByteContributionUnitKind::quic_crypto_frame
            });
        PFL_EXPECT(tls_handshake->contributing_unit_kind ==
            std::optional<session_detail::SelectedPacketByteContributionUnitKind> {
                session_detail::SelectedPacketByteContributionUnitKind::quic_crypto_frame
            });
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::tls_record, 0U) == nullptr);
        const auto labels = collect_labels(presentation);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "QUIC CRYPTO Stream (Reassembled)") != labels.end());
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Message, ClientHello (Reassembled)") != labels.end());
        const auto crypto_stream_materialized = require_materialized_view(presentation, crypto_stream->id, std::vector<std::uint8_t> {});
        const auto tls_handshake_materialized = require_materialized_view(presentation, tls_handshake->id, std::vector<std::uint8_t> {});
        PFL_REQUIRE(!crypto_stream_materialized.bytes.empty());
        PFL_REQUIRE(!tls_handshake_materialized.bytes.empty());
        PFL_EXPECT(crypto_stream_materialized.bytes[0] == 0x01U);
        PFL_EXPECT(tls_handshake_materialized.bytes[0] == 0x01U);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_frame, 1U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 1U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_plaintext, 1U) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/quic/quic_example_1.pcap")));
        const auto packet = require_packet(session, 14U);
        const auto presentation = require_presentation(session, packet);

        PFL_REQUIRE(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_handshake_packet, 0U) != nullptr);
        PFL_REQUIRE(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_protected_packet, 1U) != nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_plaintext, 0U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/quic/quic_protected_payload_4.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        PFL_REQUIRE(find_view(presentation, SelectedPacketByteViewKind::udp_payload) != nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_packet, 0U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_zero_rtt_packet, 0U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_handshake_packet, 0U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_protected_packet, 0U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_initial_plaintext, 0U) == nullptr);
        PFL_EXPECT(find_view_in_scope(presentation, SelectedPacketByteViewKind::quic_crypto_data, 0U) == nullptr);
    }

    {
        session_detail::SelectedPacketBytePresentation moved_from {};
        moved_from.derived_owners.push_back(session_detail::SelectedPacketByteDerivedOwner {
            .id = {
                .kind = session_detail::SelectedPacketByteOwnerKind::quic_initial_plaintext,
                .occurrence = 0U,
            },
            .quic_packet_index = 0U,
            .bytes = {0xAAU, 0xBBU, 0xCCU, 0xDDU},
        });
        moved_from.views.push_back(session_detail::SelectedPacketByteViewDescriptor {
            .id = {
                .kind = SelectedPacketByteViewKind::quic_initial_plaintext,
                .scope = 0U,
                .occurrence = 0U,
            },
            .owner_id = moved_from.derived_owners[0].id,
            .owner_kind = session_detail::SelectedPacketByteOwnerKind::quic_initial_plaintext,
            .offset = 1U,
            .declared_length = 2U,
            .captured_length = 2U,
        });

        auto moved = std::move(moved_from);
        const auto materialized = session_detail::materialize_selected_packet_byte_view(
            moved,
            SelectedPacketByteViewId {
                .kind = SelectedPacketByteViewKind::quic_initial_plaintext,
                .scope = 0U,
                .occurrence = 0U,
            },
            std::span<const std::uint8_t> {}
        );
        PFL_REQUIRE(materialized.has_value());
        PFL_REQUIRE(materialized->descriptor != nullptr);
        PFL_EXPECT(materialized->bytes.size() == 2U);
        PFL_EXPECT(materialized->bytes[0] == 0xBBU);
        PFL_EXPECT(materialized->bytes.data() == moved.derived_owners[0].bytes.data() + 1);
    }

    {
        const session_detail::SelectedPacketBytePresentation malformed {
            .owner_kind = session_detail::SelectedPacketByteOwnerKind::captured_packet,
            .owner_captured_length = 8U,
            .views = {
                session_detail::SelectedPacketByteViewDescriptor {
                    .id = SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::frame, .occurrence = 0U},
                    .owner_kind = session_detail::SelectedPacketByteOwnerKind::captured_packet,
                    .offset = 6U,
                    .captured_length = 4U,
                }
            },
        };
        const std::vector<std::uint8_t> owner_bytes(8U, 0xAAU);
        const auto materialized = session_detail::materialize_selected_packet_byte_view(
            malformed,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::frame, .occurrence = 0U},
            std::span<const std::uint8_t>(owner_bytes.data(), owner_bytes.size())
        );
        PFL_EXPECT(!materialized.has_value());
    }
}

}  // namespace

void run_selected_packet_byte_presentation_tests() {
    run_selected_packet_byte_presentation_tests_impl();
}

}  // namespace pfl::tests
