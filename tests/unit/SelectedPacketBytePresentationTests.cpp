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
#include "core/services/HexDumpService.h"

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
        std::optional<std::uint32_t> {packet.payload_length},
        session_detail::derive_original_transport_payload_length_from_headers(session, packet)
    );
    return session_detail::build_selected_packet_byte_presentation(
        *details,
        packet,
        session_detail::SelectedPacketByteBuildOptions {
            .packet_bytes = std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
            .flow_packet_index = packet_summary_preparation.flow_packet_index,
            .packet_data = packet_summary_preparation.packet_data,
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

std::size_t count_views(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewKind kind
) {
    return static_cast<std::size_t>(std::count_if(
        presentation.views.begin(),
        presentation.views.end(),
        [&](const SelectedPacketByteViewDescriptor& view) {
            return view.id.kind == kind;
        }
    ));
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

void expect_hex_prefix(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    const std::vector<std::uint8_t>& owner_bytes,
    const std::vector<std::uint8_t>& expected_prefix,
    const session_detail::SelectedPacketByteRangeMode mode = session_detail::SelectedPacketByteRangeMode::whole_unit
) {
    const auto materialized = require_materialized_view(presentation, id, owner_bytes, mode);
    PFL_REQUIRE(materialized.bytes.size() >= expected_prefix.size());
    for (std::size_t index = 0U; index < expected_prefix.size(); ++index) {
        PFL_EXPECT(materialized.bytes[index] == expected_prefix[index]);
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

        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::frame) == nullptr);
        const auto* ethernet_payload = require_view(presentation, SelectedPacketByteViewKind::ethernet_payload);
        const auto* ipv4_payload = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* tcp_payload = require_view(presentation, SelectedPacketByteViewKind::tcp_payload);
        const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);
        const std::vector<std::string> expected_labels {
            "Ethernet II Frame",
            "IPv4 Packet",
            "TCP Segment",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        PFL_EXPECT(ethernet_payload->offset == 0U);
        PFL_EXPECT(ethernet_payload->captured_length == packet.captured_length);
        PFL_EXPECT(ipv4_payload->offset == 14U);
        PFL_EXPECT(tcp_payload->offset == 34U);
        PFL_REQUIRE(descriptors.size() == 3U);
        PFL_EXPECT(descriptors[0].stable_id == "ethernet:0:0");
        PFL_EXPECT(descriptors[1].stable_id == "ipv4:0:0");
        PFL_EXPECT(descriptors[2].stable_id == "tcp:0:0");
        PFL_EXPECT(descriptors[0].supports_payload_only);
        PFL_EXPECT(descriptors[1].supports_payload_only);
        PFL_EXPECT(descriptors[2].supports_payload_only);
        PFL_EXPECT(!ethernet_payload->parent_id.has_value());
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

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        const auto* tcp_data = require_view(flow_aware_presentation, SelectedPacketByteViewKind::data);
        expect_parent(*tcp_data, SelectedPacketByteViewKind::tcp_payload);
        PFL_EXPECT(tcp_data->captured_length == 4U);
        PFL_EXPECT(!tcp_data->payload_range.has_value());
        expect_ascii_prefix(flow_aware_presentation, tcp_data->id, bytes, "ABCD");
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/packet_byte_views/01_ethernet_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);

        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::frame) == nullptr);
        const auto* ethernet_payload = require_view(presentation, SelectedPacketByteViewKind::ethernet_payload);
        const auto* ipv4_payload = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* udp_payload = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        PFL_REQUIRE(descriptors.size() == 3U);
        PFL_EXPECT(descriptors[0].stable_id == "ethernet:0:0");
        PFL_EXPECT(descriptors[1].stable_id == "ipv4:0:0");
        PFL_EXPECT(descriptors[2].stable_id == "udp:0:0");
        const std::vector<std::string> expected_labels {
            "Ethernet II Frame",
            "IPv4 Packet",
            "UDP Datagram",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        PFL_EXPECT(!ethernet_payload->parent_id.has_value());
        PFL_EXPECT(ethernet_payload->offset == 0U);
        PFL_EXPECT(ethernet_payload->captured_length == packet.captured_length);
        expect_parent(*ipv4_payload, SelectedPacketByteViewKind::ethernet_payload);
        expect_parent(*udp_payload, SelectedPacketByteViewKind::ipv4_payload);
        expect_materialized_view_aliases_owner_bytes(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::ethernet_payload, .occurrence = 0U},
            bytes
        );
        PFL_EXPECT(bytes.size() == static_cast<std::size_t>(packet.captured_length));
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/linux_cooked/01_sll_ipv4_tcp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);

        const auto* frame = require_view(presentation, SelectedPacketByteViewKind::frame);
        const auto* linux_sll = require_view(presentation, SelectedPacketByteViewKind::linux_sll);
        const auto* ipv4_payload = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* tcp_payload = require_view(presentation, SelectedPacketByteViewKind::tcp_payload);
        const std::vector<std::string> expected_labels {
            "Captured Packet",
            "Linux cooked capture v1",
            "IPv4 Packet",
            "TCP Segment",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        PFL_REQUIRE(descriptors.size() == 4U);
        PFL_EXPECT(descriptors[0].stable_id == "frame:0:0");
        PFL_EXPECT(descriptors[1].stable_id == "linux_sll:0:0");
        PFL_EXPECT(descriptors[2].stable_id == "ipv4:0:0");
        PFL_EXPECT(descriptors[3].stable_id == "tcp:0:0");
        PFL_EXPECT(!frame->parent_id.has_value());
        PFL_EXPECT(frame->offset == 0U);
        PFL_EXPECT(frame->captured_length == 56U);
        PFL_EXPECT(frame->declared_length == std::optional<std::uint32_t> {56U});
        expect_parent(*linux_sll, SelectedPacketByteViewKind::frame);
        PFL_EXPECT(linux_sll->offset == 0U);
        PFL_EXPECT(linux_sll->captured_length == 56U);
        PFL_EXPECT(linux_sll->declared_length == std::optional<std::uint32_t> {56U});
        PFL_REQUIRE(linux_sll->payload_range.has_value());
        PFL_EXPECT(linux_sll->payload_range->offset == 16U);
        PFL_EXPECT(linux_sll->payload_range->captured_length == 40U);
        PFL_EXPECT(linux_sll->payload_range->declared_length == std::optional<std::uint32_t> {40U});
        expect_parent(*ipv4_payload, SelectedPacketByteViewKind::linux_sll);
        expect_parent(*tcp_payload, SelectedPacketByteViewKind::ipv4_payload);
        PFL_EXPECT(ipv4_payload->offset == 16U);
        PFL_EXPECT(ipv4_payload->captured_length == 40U);
        PFL_EXPECT(ipv4_payload->declared_length == std::optional<std::uint32_t> {40U});
        PFL_EXPECT(tcp_payload->offset == 36U);
        expect_materialized_view_aliases_owner_bytes(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::frame, .occurrence = 0U},
            bytes
        );
        expect_materialized_view_aliases_owner_bytes(
            presentation,
            linux_sll->id,
            bytes
        );
        expect_hex_prefix(
            presentation,
            linux_sll->id,
            bytes,
            {
                0x12U, 0x34U,
                0x34U, 0x56U,
                0x00U, 0x06U,
                0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x60U, 0x70U, 0x80U,
                0x08U, 0x00U,
            }
        );
        expect_hex_prefix(
            presentation,
            linux_sll->id,
            bytes,
            {0x45U, 0x00U},
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/linux_cooked/05_sll2_ipv4_tcp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);

        const auto* frame = require_view(presentation, SelectedPacketByteViewKind::frame);
        const auto* linux_sll2 = require_view(presentation, SelectedPacketByteViewKind::linux_sll2);
        const auto* ipv4_payload = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* tcp_payload = require_view(presentation, SelectedPacketByteViewKind::tcp_payload);
        const std::vector<std::string> expected_labels {
            "Captured Packet",
            "Linux cooked capture v2",
            "IPv4 Packet",
            "TCP Segment",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        PFL_REQUIRE(descriptors.size() == 4U);
        PFL_EXPECT(descriptors[0].stable_id == "frame:0:0");
        PFL_EXPECT(descriptors[1].stable_id == "linux_sll2:0:0");
        PFL_EXPECT(descriptors[2].stable_id == "ipv4:0:0");
        PFL_EXPECT(descriptors[3].stable_id == "tcp:0:0");
        PFL_EXPECT(!frame->parent_id.has_value());
        PFL_EXPECT(frame->offset == 0U);
        PFL_EXPECT(frame->captured_length == packet.captured_length);
        PFL_EXPECT(frame->declared_length == std::optional<std::uint32_t> {packet.original_length});
        expect_parent(*linux_sll2, SelectedPacketByteViewKind::frame);
        PFL_EXPECT(linux_sll2->offset == 0U);
        PFL_EXPECT(linux_sll2->captured_length == packet.captured_length);
        PFL_EXPECT(linux_sll2->declared_length == std::optional<std::uint32_t> {packet.original_length});
        PFL_REQUIRE(linux_sll2->payload_range.has_value());
        PFL_EXPECT(linux_sll2->payload_range->offset == 20U);
        PFL_EXPECT(linux_sll2->payload_range->captured_length == packet.captured_length - 20U);
        PFL_EXPECT(linux_sll2->payload_range->declared_length ==
            std::optional<std::uint32_t> {packet.original_length - 20U});
        expect_parent(*ipv4_payload, SelectedPacketByteViewKind::linux_sll2);
        expect_parent(*tcp_payload, SelectedPacketByteViewKind::ipv4_payload);
        PFL_EXPECT(ipv4_payload->offset == 20U);
        PFL_EXPECT(ipv4_payload->captured_length == packet.captured_length - 20U);
        PFL_EXPECT(ipv4_payload->declared_length == std::optional<std::uint32_t> {packet.original_length - 20U});
        PFL_EXPECT(tcp_payload->offset == 40U);
        expect_materialized_view_aliases_owner_bytes(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::frame, .occurrence = 0U},
            bytes
        );
        expect_materialized_view_aliases_owner_bytes(
            presentation,
            linux_sll2->id,
            bytes
        );
        expect_hex_prefix(
            presentation,
            linux_sll2->id,
            bytes,
            {
                0x08U, 0x00U,
                0x00U, 0x00U,
                0x01U, 0x02U, 0x03U, 0x04U,
                0x0fU, 0x0eU,
                0x7fU,
                0x06U,
                0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U,
            }
        );
        expect_hex_prefix(
            presentation,
            linux_sll2->id,
            bytes,
            {0x45U, 0x00U},
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
    }

    {
        const std::vector<std::uint8_t> captured_packet {
            0x00U, 0x11U, 0x22U, 0x33U, 0x44U,
            0x55U, 0x66U, 0x77U, 0x88U, 0x99U,
        };
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/packet_byte_views/02_truncated_ethernet_header.pcap")));

        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);

        PFL_REQUIRE(descriptors.size() == 1U);
        PFL_EXPECT(descriptors[0].stable_id == "frame:0:0");
        PFL_EXPECT(descriptors[0].label == "Captured Packet");
        PFL_EXPECT(descriptors[0].depth == 0U);
        PFL_EXPECT(!descriptors[0].parent_stable_id.has_value());
        PFL_EXPECT(descriptors[0].available_length == captured_packet.size());
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::ethernet_payload) == nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::ipv4_payload) == nullptr);

        const auto materialized = require_materialized_view(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::frame, .occurrence = 0U},
            bytes
        );
        PFL_EXPECT(materialized.bytes.size() == captured_packet.size());
        PFL_EXPECT(std::equal(materialized.bytes.begin(), materialized.bytes.end(), captured_packet.begin(), captured_packet.end()));
    }

    {
        const auto path = write_temp_pcap(
            "pfl_selected_packet_byte_zero_length_payload_only.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_tcp_packet(
                    ipv4(10, 1, 1, 1),
                    ipv4(10, 1, 1, 2),
                    23456,
                    443
                )
            }})
        );

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(path));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        const auto* tcp_payload = require_view(presentation, SelectedPacketByteViewKind::tcp_payload);
        PFL_REQUIRE(tcp_payload->payload_range.has_value());
        PFL_EXPECT(tcp_payload->payload_range->captured_length == 0U);

        const auto materialized = session_detail::materialize_selected_packet_byte_view(
            presentation,
            tcp_payload->id,
            std::span<const std::uint8_t>(bytes.data(), bytes.size()),
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
        PFL_REQUIRE(materialized.has_value());
        PFL_EXPECT(materialized->bytes.empty());

        HexDumpService hex_dump_service {};
        const auto content = session_detail::format_selected_packet_byte_view_content(
            presentation,
            tcp_payload->id,
            std::span<const std::uint8_t>(bytes.data(), bytes.size()),
            hex_dump_service,
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
        PFL_REQUIRE(content.has_value());
        PFL_EXPECT(content->stable_id == "tcp:0:0");
        PFL_EXPECT(content->available_length == 0U);
        PFL_EXPECT(content->formatted_text.empty());
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

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        PFL_EXPECT(find_view(flow_aware_presentation, SelectedPacketByteViewKind::data) == nullptr);
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
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        PFL_REQUIRE(require_view(presentation, SelectedPacketByteViewKind::udp_payload) != nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::dns_message) == nullptr);

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        const auto* udp_data = require_view(flow_aware_presentation, SelectedPacketByteViewKind::data);
        expect_parent(*udp_data, SelectedPacketByteViewKind::udp_payload);
        PFL_EXPECT(udp_data->captured_length == 15U);
        PFL_EXPECT(!udp_data->payload_range.has_value());
        expect_ascii_prefix(flow_aware_presentation, udp_data->id, bytes, "not-dns-payload");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_selected_packet_byte_search_bsdp_data.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 2, 1, 3),
                    ipv4(10, 2, 1, 4),
                    68,
                    67,
                    bytes_payload("SEARCH BSDP/0.1"))
            }})
        );

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(path));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        const auto* udp_data = require_view(flow_aware_presentation, SelectedPacketByteViewKind::data);
        expect_parent(*udp_data, SelectedPacketByteViewKind::udp_payload);
        PFL_EXPECT(find_view(flow_aware_presentation, SelectedPacketByteViewKind::dns_message) == nullptr);
        PFL_EXPECT(find_view_in_scope(flow_aware_presentation, SelectedPacketByteViewKind::quic_initial_packet, 0U) == nullptr);
        expect_ascii_prefix(flow_aware_presentation, udp_data->id, bytes, "SEARCH BSDP/0.1");
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
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vlan/01_vlan_ipv4_tcp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        const auto labels = collect_labels(presentation);

        const auto* vlan = require_view(presentation, SelectedPacketByteViewKind::vlan_payload);
        const auto* ipv4 = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "802.1Q Encapsulation") != labels.end());
        expect_parent(*vlan, SelectedPacketByteViewKind::ethernet_payload);
        expect_parent(*ipv4, SelectedPacketByteViewKind::vlan_payload);
        PFL_REQUIRE(vlan->payload_range.has_value());
        PFL_EXPECT(vlan->offset == 14U);
        PFL_EXPECT(vlan->payload_range->offset == 18U);
        expect_hex_prefix(
            presentation,
            vlan->id,
            bytes,
            {0x81U, 0x00U, 0x00U, 0x64U, 0x08U, 0x00U}
        );
        expect_hex_prefix(
            presentation,
            vlan->id,
            bytes,
            {0x45U, 0x00U},
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
        PFL_EXPECT(count_views(presentation, SelectedPacketByteViewKind::vlan_payload) == 1U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vlan/05_qinq_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        const auto labels = collect_labels(presentation);

        const std::vector<std::string> expected_labels {
            "Ethernet II Frame",
            "802.1Q Encapsulation",
            "802.1Q Encapsulation #2",
            "IPv4 Packet",
            "UDP Datagram",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        const auto* outer_vlan = require_view(presentation, SelectedPacketByteViewKind::vlan_payload, 0U);
        const auto* inner_vlan = require_view(presentation, SelectedPacketByteViewKind::vlan_payload, 1U);
        const auto* ipv4 = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        expect_parent(*outer_vlan, SelectedPacketByteViewKind::ethernet_payload);
        expect_parent(*inner_vlan, SelectedPacketByteViewKind::vlan_payload, 0U);
        expect_parent(*ipv4, SelectedPacketByteViewKind::vlan_payload, 1U);
        PFL_REQUIRE(outer_vlan->payload_range.has_value());
        PFL_REQUIRE(inner_vlan->payload_range.has_value());
        PFL_EXPECT(outer_vlan->offset == 14U);
        PFL_EXPECT(inner_vlan->offset == 18U);
        PFL_EXPECT(inner_vlan->payload_range->offset == 22U);
        expect_hex_prefix(
            presentation,
            outer_vlan->id,
            bytes,
            {0x88U, 0xA8U, 0x00U, 0xC8U, 0x81U, 0x00U}
        );
        expect_hex_prefix(
            presentation,
            inner_vlan->id,
            bytes,
            {0x81U, 0x00U, 0x00U, 0xC9U, 0x08U, 0x00U}
        );
        expect_hex_prefix(
            presentation,
            inner_vlan->id,
            bytes,
            {0x45U, 0x00U},
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/arp/08_arp_request_with_ethernet_padding.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const std::vector<std::string> expected_labels {
            "Ethernet II Frame",
            "ARP Packet",
        };
        PFL_EXPECT(collect_labels(presentation) == expected_labels);
        const auto* ethernet_view = require_view(presentation, SelectedPacketByteViewKind::ethernet_payload);
        const auto* arp_view = require_view(presentation, SelectedPacketByteViewKind::arp);
        PFL_EXPECT(!ethernet_view->parent_id.has_value());
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

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        PFL_EXPECT(find_view(flow_aware_presentation, SelectedPacketByteViewKind::data) == nullptr);
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

        const auto bytes = session.read_packet_data(packet);
        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        const auto* data_view = require_view(flow_aware_presentation, SelectedPacketByteViewKind::data);
        expect_parent(*data_view, SelectedPacketByteViewKind::tcp_payload);
        PFL_EXPECT(data_view->captured_length == 5U);
        expect_materialized_view_aliases_owner_bytes(flow_aware_presentation, data_view->id, bytes);
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
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/llc_snap/02_llc_snap_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* ieee8023 = require_view(presentation, SelectedPacketByteViewKind::ieee8023_payload);
        const auto* llc = require_view(presentation, SelectedPacketByteViewKind::llc);
        const auto* snap = require_view(presentation, SelectedPacketByteViewKind::snap);
        const auto* ipv4 = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* udp = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);

        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::ethernet_payload) == nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::frame) == nullptr);
        PFL_EXPECT(count_views(presentation, SelectedPacketByteViewKind::ieee8023_payload) == 1U);
        PFL_EXPECT(count_views(presentation, SelectedPacketByteViewKind::llc) == 1U);
        PFL_EXPECT(count_views(presentation, SelectedPacketByteViewKind::snap) == 1U);
        PFL_EXPECT(std::any_of(descriptors.begin(), descriptors.end(), [](const auto& descriptor) {
            return descriptor.stable_id == "ieee8023:0:0" && descriptor.label == "IEEE 802.3 Frame";
        }));
        PFL_EXPECT(std::any_of(descriptors.begin(), descriptors.end(), [](const auto& descriptor) {
            return descriptor.stable_id == "llc:0:0" && descriptor.label == "LLC PDU";
        }));
        PFL_EXPECT(std::any_of(descriptors.begin(), descriptors.end(), [](const auto& descriptor) {
            return descriptor.stable_id == "snap:0:0" && descriptor.label == "SNAP PDU";
        }));
        expect_parent(*llc, SelectedPacketByteViewKind::ieee8023_payload);
        expect_parent(*snap, SelectedPacketByteViewKind::llc);
        expect_parent(*ipv4, SelectedPacketByteViewKind::snap);
        expect_parent(*udp, SelectedPacketByteViewKind::ipv4_payload);
        PFL_REQUIRE(ieee8023->declared_length.has_value());
        PFL_REQUIRE(ieee8023->payload_range.has_value());
        PFL_REQUIRE(llc->payload_range.has_value());
        PFL_REQUIRE(snap->payload_range.has_value());
        PFL_EXPECT(ieee8023->offset == 0U);
        PFL_EXPECT(ieee8023->payload_range->offset == 14U);
        PFL_EXPECT(llc->offset == ieee8023->payload_range->offset);
        PFL_EXPECT(snap->offset == llc->payload_range->offset);
        PFL_EXPECT(ipv4->offset == snap->payload_range->offset);
        PFL_EXPECT(ieee8023->captured_length == ieee8023->payload_range->offset + ieee8023->payload_range->captured_length);
        PFL_EXPECT(*ieee8023->declared_length == ieee8023->payload_range->offset + *ieee8023->payload_range->declared_length);
        PFL_EXPECT(llc->captured_length <= bytes.size() - llc->offset);
        PFL_EXPECT(snap->captured_length <= bytes.size() - snap->offset);

        const auto ieee8023_materialized = require_materialized_view(presentation, ieee8023->id, bytes);
        const auto llc_materialized = require_materialized_view(presentation, llc->id, bytes);
        const auto snap_materialized = require_materialized_view(presentation, snap->id, bytes);
        PFL_REQUIRE(ieee8023_materialized.bytes.size() >= 14U);
        PFL_REQUIRE(llc_materialized.bytes.size() >= 3U);
        PFL_REQUIRE(snap_materialized.bytes.size() >= 5U);
        PFL_EXPECT(ieee8023_materialized.bytes[12] == 0x00U);
        PFL_EXPECT(llc_materialized.bytes[0] == 0xAAU);
        PFL_EXPECT(llc_materialized.bytes[1] == 0xAAU);
        PFL_EXPECT(llc_materialized.bytes[2] == 0x03U);
        PFL_EXPECT(snap_materialized.bytes[0] == 0x00U);
        PFL_EXPECT(snap_materialized.bytes[1] == 0x00U);
        PFL_EXPECT(snap_materialized.bytes[2] == 0x00U);
        PFL_EXPECT(snap_materialized.bytes[3] == 0x08U);
        PFL_EXPECT(snap_materialized.bytes[4] == 0x00U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/llc_snap/10_llc_non_snap_ipx_like.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* ieee8023 = require_view(presentation, SelectedPacketByteViewKind::ieee8023_payload);
        const auto* llc = require_view(presentation, SelectedPacketByteViewKind::llc);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::snap) == nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::ipv4_payload) == nullptr);
        PFL_EXPECT(!ieee8023->parent_id.has_value());
        expect_parent(*llc, SelectedPacketByteViewKind::ieee8023_payload);
        PFL_REQUIRE(ieee8023->payload_range.has_value());
        PFL_REQUIRE(llc->payload_range.has_value());
        PFL_EXPECT(llc->offset == ieee8023->payload_range->offset);
        const auto llc_materialized = require_materialized_view(presentation, llc->id, bytes);
        PFL_REQUIRE(llc_materialized.bytes.size() >= 3U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/llc_snap/20_llc_snap_padding_after_declared_payload.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* ieee8023 = require_view(presentation, SelectedPacketByteViewKind::ieee8023_payload);
        const auto* llc = require_view(presentation, SelectedPacketByteViewKind::llc);
        PFL_REQUIRE(ieee8023->declared_length.has_value());
        PFL_REQUIRE(ieee8023->payload_range.has_value());
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::frame) != nullptr);
        PFL_EXPECT(collect_labels(presentation).front() == "Captured Packet");
        expect_parent(*ieee8023, SelectedPacketByteViewKind::frame);
        PFL_EXPECT(ieee8023->captured_length == *ieee8023->declared_length);
        PFL_EXPECT(bytes.size() > ieee8023->captured_length);
        PFL_EXPECT(ieee8023->payload_range->offset == llc->offset);
        const auto ieee8023_materialized = require_materialized_view(presentation, ieee8023->id, bytes);
        PFL_EXPECT(ieee8023_materialized.bytes.size() == ieee8023->captured_length);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/pppoe/02_pppoe_session_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* ethernet = require_view(presentation, SelectedPacketByteViewKind::ethernet_payload);
        const auto* pppoe = require_view(presentation, SelectedPacketByteViewKind::pppoe);
        const auto* ppp = require_view(presentation, SelectedPacketByteViewKind::ppp);
        const auto* ipv4 = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* udp = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);

        PFL_EXPECT(count_views(presentation, SelectedPacketByteViewKind::pppoe) == 1U);
        PFL_EXPECT(count_views(presentation, SelectedPacketByteViewKind::ppp) == 1U);
        PFL_EXPECT(std::any_of(descriptors.begin(), descriptors.end(), [](const auto& descriptor) {
            return descriptor.stable_id == "pppoe:0:0" && descriptor.label == "PPPoE Packet";
        }));
        PFL_EXPECT(std::any_of(descriptors.begin(), descriptors.end(), [](const auto& descriptor) {
            return descriptor.stable_id == "ppp:0:0" && descriptor.label == "PPP Packet";
        }));
        expect_parent(*pppoe, SelectedPacketByteViewKind::ethernet_payload);
        expect_parent(*ppp, SelectedPacketByteViewKind::pppoe);
        expect_parent(*ipv4, SelectedPacketByteViewKind::ppp);
        expect_parent(*udp, SelectedPacketByteViewKind::ipv4_payload);
        PFL_REQUIRE(ethernet->payload_range.has_value());
        PFL_REQUIRE(pppoe->payload_range.has_value());
        PFL_REQUIRE(ppp->payload_range.has_value());
        PFL_EXPECT(pppoe->offset == ethernet->payload_range->offset);
        PFL_EXPECT(pppoe->payload_range->offset == pppoe->offset + 6U);
        PFL_EXPECT(ppp->offset == pppoe->payload_range->offset);
        PFL_EXPECT(ppp->payload_range->offset == ppp->offset + 2U);
        PFL_EXPECT(ipv4->offset == ppp->payload_range->offset);
        PFL_EXPECT(ppp->captured_length == pppoe->payload_range->captured_length);
        PFL_EXPECT(ppp->declared_length == pppoe->payload_range->declared_length);
        PFL_EXPECT(pppoe->captured_length <= bytes.size() - pppoe->offset);

        const auto pppoe_materialized = require_materialized_view(presentation, pppoe->id, bytes);
        const auto ppp_materialized = require_materialized_view(presentation, ppp->id, bytes);
        PFL_REQUIRE(pppoe_materialized.bytes.size() >= 8U);
        PFL_REQUIRE(ppp_materialized.bytes.size() >= 2U);
        for (std::size_t index = 0U; index < 6U; ++index) {
            PFL_EXPECT(pppoe_materialized.bytes[index] == bytes[pppoe->offset + index]);
        }
        PFL_EXPECT(pppoe_materialized.bytes[6] == 0x00U);
        PFL_EXPECT(pppoe_materialized.bytes[7] == 0x21U);
        PFL_EXPECT(ppp_materialized.bytes[0] == 0x00U);
        PFL_EXPECT(ppp_materialized.bytes[1] == 0x21U);
        expect_hex_prefix(
            presentation,
            ppp->id,
            bytes,
            {0x45U, 0x00U},
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/pppoe/04_pppoe_session_ipv6_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* ppp = require_view(presentation, SelectedPacketByteViewKind::ppp);
        const auto* ipv6 = require_view(presentation, SelectedPacketByteViewKind::ipv6_payload);
        const auto* udp = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*ppp, SelectedPacketByteViewKind::pppoe);
        expect_parent(*ipv6, SelectedPacketByteViewKind::ppp);
        expect_parent(*udp, SelectedPacketByteViewKind::ipv6_payload);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/pppoe/08_pppoe_discovery_padi.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        PFL_REQUIRE(find_view(presentation, SelectedPacketByteViewKind::pppoe) != nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::ppp) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/pbb/05_pbb_arp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* pbb = require_view(presentation, SelectedPacketByteViewKind::pbb);
        const auto* inner_ethernet = require_view(presentation, SelectedPacketByteViewKind::inner_ethernet_payload);
        const auto* arp = require_view(presentation, SelectedPacketByteViewKind::arp);
        const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);

        PFL_EXPECT(count_views(presentation, SelectedPacketByteViewKind::pbb) == 1U);
        PFL_EXPECT(std::any_of(descriptors.begin(), descriptors.end(), [](const auto& descriptor) {
            return descriptor.stable_id == "pbb:0:0" && descriptor.label == "PBB Packet";
        }));
        expect_parent(*pbb, SelectedPacketByteViewKind::ethernet_payload);
        expect_parent(*inner_ethernet, SelectedPacketByteViewKind::pbb);
        expect_parent(*arp, SelectedPacketByteViewKind::inner_ethernet_payload);
        PFL_EXPECT(pbb->offset + 4U == inner_ethernet->offset);
        PFL_EXPECT(pbb->captured_length > inner_ethernet->captured_length);
        PFL_EXPECT(pbb->captured_length <= bytes.size() - pbb->offset);

        const auto pbb_materialized = require_materialized_view(presentation, pbb->id, bytes);
        PFL_REQUIRE(pbb_materialized.bytes.size() >= 4U);
        for (std::size_t index = 0U; index < 4U; ++index) {
            PFL_EXPECT(pbb_materialized.bytes[index] == bytes[pbb->offset + index]);
        }
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/32_gtpu_inner_ipv4_udp_data.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        const auto labels = collect_labels(presentation);

        const auto* gtpu_message = require_view(presentation, SelectedPacketByteViewKind::gtpu_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_udp = require_view(presentation, SelectedPacketByteViewKind::inner_udp_payload);
        PFL_EXPECT(require_kind_index(presentation, SelectedPacketByteViewKind::udp_payload) <
            require_kind_index(presentation, SelectedPacketByteViewKind::gtpu_payload));
        PFL_EXPECT(require_kind_index(presentation, SelectedPacketByteViewKind::gtpu_payload) <
            require_kind_index(presentation, SelectedPacketByteViewKind::inner_ipv4_payload));
        PFL_EXPECT(require_kind_index(presentation, SelectedPacketByteViewKind::inner_ipv4_payload) <
            require_kind_index(presentation, SelectedPacketByteViewKind::inner_udp_payload));
        expect_parent(*gtpu_message, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::gtpu_payload);
        expect_parent(*inner_udp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_REQUIRE(gtpu_message->payload_range.has_value());
        PFL_EXPECT(gtpu_message->captured_length > gtpu_message->payload_range->captured_length);
        PFL_EXPECT(gtpu_message->payload_range->offset == inner_ipv4->offset);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "GTP-U Payload") == labels.end());
        expect_hex_prefix(
            presentation,
            gtpu_message->id,
            bytes,
            {0x30U, 0xFFU, 0x00U, 0x4CU}
        );
        expect_hex_prefix(
            presentation,
            gtpu_message->id,
            bytes,
            {0x45U, 0x00U},
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
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

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        const auto* udp_data = require_view(flow_aware_presentation, SelectedPacketByteViewKind::data);
        expect_parent(*udp_data, SelectedPacketByteViewKind::inner_udp_payload);
        PFL_EXPECT(udp_data->captured_length == 48U);
        PFL_EXPECT(!udp_data->payload_range.has_value());
        expect_ascii_prefix(flow_aware_presentation, udp_data->id, bytes, "INNER-UDP-DATA");
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/33_gtpu_inner_ipv4_tcp_data.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* gtpu_message = require_view(presentation, SelectedPacketByteViewKind::gtpu_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_tcp = require_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload);
        expect_parent(*gtpu_message, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::gtpu_payload);
        expect_parent(*inner_tcp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_REQUIRE(gtpu_message->payload_range.has_value());
        PFL_EXPECT(gtpu_message->payload_range->offset == inner_ipv4->offset);
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

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        const auto* tcp_data = require_view(flow_aware_presentation, SelectedPacketByteViewKind::data);
        expect_parent(*tcp_data, SelectedPacketByteViewKind::inner_tcp_payload);
        PFL_EXPECT(tcp_data->captured_length == 48U);
        PFL_EXPECT(!tcp_data->payload_range.has_value());
        expect_ascii_prefix(flow_aware_presentation, tcp_data->id, bytes, "INNER-TCP-DATA");
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/34_gtpu_inner_ipv4_tcp_ack_only.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);
        const auto labels = collect_labels(presentation);

        const auto* gtpu_message = require_view(presentation, SelectedPacketByteViewKind::gtpu_payload);
        PFL_REQUIRE(find_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload) != nullptr);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "GTP-U Message") != labels.end());
        PFL_REQUIRE(gtpu_message->payload_range.has_value());
        const auto* inner_tcp = require_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload);
        PFL_EXPECT(!inner_tcp->payload_range.has_value());
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::tcp_payload) == nullptr);

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        PFL_EXPECT(find_view(flow_aware_presentation, SelectedPacketByteViewKind::data) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(
            fixture_path("parsing/gtpu/35_gtpu_bidirectional_different_teids_same_inner_tcp.pcap"),
            CaptureImportOptions {
                .settings = AnalysisSettings {
                    .ignore_gtpu_teids_when_grouping_inner_flows = true,
                },
            }));

        const auto first_packet = require_packet(session, 0U);
        const auto first_presentation = require_presentation(session, first_packet);
        const auto* first_gtpu_message = require_view(first_presentation, SelectedPacketByteViewKind::gtpu_payload);
        const auto* first_inner_ipv4 = require_view(first_presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        expect_parent(*first_gtpu_message, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*first_inner_ipv4, SelectedPacketByteViewKind::gtpu_payload);

        const auto second_packet = require_packet(session, 1U);
        const auto second_presentation = require_presentation(session, second_packet);
        const auto* second_gtpu_message = require_view(second_presentation, SelectedPacketByteViewKind::gtpu_payload);
        const auto* second_inner_ipv4 = require_view(second_presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        expect_parent(*second_gtpu_message, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*second_inner_ipv4, SelectedPacketByteViewKind::gtpu_payload);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gre/15_gre_mpls_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto bytes = session.read_packet_data(packet);
        const auto labels = collect_labels(presentation);
        const auto* gre_packet = require_view(presentation, SelectedPacketByteViewKind::gre_payload);
        const auto* mpls_payload = require_view(presentation, SelectedPacketByteViewKind::mpls_payload, 0U);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_udp = require_view(presentation, SelectedPacketByteViewKind::inner_udp_payload);
        expect_parent(*gre_packet, SelectedPacketByteViewKind::ipv4_payload);
        expect_parent(*mpls_payload, SelectedPacketByteViewKind::gre_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::mpls_payload, 0U);
        expect_parent(*inner_udp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_REQUIRE(gre_packet->payload_range.has_value());
        PFL_EXPECT(gre_packet->payload_range->offset == mpls_payload->offset);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "GRE Payload") == labels.end());
        expect_hex_prefix(
            presentation,
            gre_packet->id,
            bytes,
            {0x00U, 0x00U, 0x88U, 0x47U}
        );
        expect_hex_prefix(
            presentation,
            gre_packet->id,
            bytes,
            {0x03U, 0xE9U},
            session_detail::SelectedPacketByteRangeMode::payload_only
        );

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        const auto* udp_data = require_view(flow_aware_presentation, SelectedPacketByteViewKind::data);
        expect_parent(*udp_data, SelectedPacketByteViewKind::inner_udp_payload);
        PFL_EXPECT(!udp_data->payload_range.has_value());
        expect_materialized_view_aliases_owner_bytes(flow_aware_presentation, udp_data->id, bytes);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/eoip/04_ipv4_eoip_inner_vlan_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto bytes = session.read_packet_data(packet);
        const auto labels = collect_labels(presentation);
        const auto* eoip_packet = require_view(presentation, SelectedPacketByteViewKind::eoip_payload);
        const auto* inner_ethernet = require_view(presentation, SelectedPacketByteViewKind::inner_ethernet_payload);
        const auto* inner_vlan = require_view(presentation, SelectedPacketByteViewKind::inner_vlan_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_udp = require_view(presentation, SelectedPacketByteViewKind::inner_udp_payload);
        expect_parent(*eoip_packet, SelectedPacketByteViewKind::ipv4_payload);
        expect_parent(*inner_ethernet, SelectedPacketByteViewKind::eoip_payload);
        expect_parent(*inner_vlan, SelectedPacketByteViewKind::inner_ethernet_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::inner_vlan_payload);
        expect_parent(*inner_udp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_REQUIRE(eoip_packet->payload_range.has_value());
        PFL_EXPECT(eoip_packet->payload_range->offset == inner_ethernet->offset);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "EoIP Payload") == labels.end());
        expect_hex_prefix(
            presentation,
            eoip_packet->id,
            bytes,
            {0x20U, 0x01U, 0x64U, 0x00U}
        );
        expect_hex_prefix(
            presentation,
            eoip_packet->id,
            bytes,
            {0x81U, 0x02U},
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/mpls/25_vlan_and_stacked_mpls_asymmetric_bidirectional_tcp.pcap")));

        const auto first_packet = require_packet(session, 0U);
        const auto first_presentation = require_presentation(session, first_packet);
        const auto* first_outer_ethernet = require_view(first_presentation, SelectedPacketByteViewKind::ethernet_payload);
        const auto* first_vlan = require_view(first_presentation, SelectedPacketByteViewKind::vlan_payload, 0U);
        const auto* first_mpls = require_view(first_presentation, SelectedPacketByteViewKind::mpls_payload, 0U);
        const auto* first_ipv4 = require_view(first_presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* first_tcp = require_view(first_presentation, SelectedPacketByteViewKind::tcp_payload);
        const auto expected_first_labels = std::vector<std::string> {
            "Captured Packet",
            "Ethernet II Frame",
            "802.1Q Encapsulation",
            "MPLS Label Stack and Payload",
            "IPv4 Packet",
            "TCP Segment",
        };
        expect_parent(*first_outer_ethernet, SelectedPacketByteViewKind::frame);
        expect_parent(*first_vlan, SelectedPacketByteViewKind::ethernet_payload);
        expect_parent(*first_mpls, SelectedPacketByteViewKind::vlan_payload, 0U);
        expect_parent(*first_ipv4, SelectedPacketByteViewKind::mpls_payload, 0U);
        expect_parent(*first_tcp, SelectedPacketByteViewKind::ipv4_payload);
        PFL_EXPECT(collect_labels(first_presentation) == expected_first_labels);

        const auto second_packet = require_packet(session, 1U);
        const auto second_presentation = require_presentation(session, second_packet);
        const auto* second_outer_ethernet = require_view(second_presentation, SelectedPacketByteViewKind::ethernet_payload);
        const auto* second_outer_vlan = require_view(second_presentation, SelectedPacketByteViewKind::vlan_payload, 0U);
        const auto* second_inner_vlan = require_view(second_presentation, SelectedPacketByteViewKind::vlan_payload, 1U);
        const auto* second_ipv4 = require_view(second_presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* second_tcp = require_view(second_presentation, SelectedPacketByteViewKind::tcp_payload);
        const auto expected_second_labels = std::vector<std::string> {
            "Captured Packet",
            "Ethernet II Frame",
            "802.1Q Encapsulation",
            "802.1Q Encapsulation",
            "IPv4 Packet",
            "TCP Segment",
        };
        expect_parent(*second_outer_ethernet, SelectedPacketByteViewKind::frame);
        expect_parent(*second_outer_vlan, SelectedPacketByteViewKind::ethernet_payload);
        expect_parent(*second_inner_vlan, SelectedPacketByteViewKind::vlan_payload, 0U);
        expect_parent(*second_ipv4, SelectedPacketByteViewKind::vlan_payload, 1U);
        expect_parent(*second_tcp, SelectedPacketByteViewKind::ipv4_payload);
        PFL_EXPECT(collect_labels(second_presentation) == expected_second_labels);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/13_vxlan_inner_vlan_ipv4_tcp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);

        const auto* vxlan_payload = require_view(presentation, SelectedPacketByteViewKind::vxlan_payload);
        const auto* inner_ethernet = require_view(presentation, SelectedPacketByteViewKind::inner_ethernet_payload);
        const auto* inner_vlan = require_view(presentation, SelectedPacketByteViewKind::inner_vlan_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_tcp = require_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload);
        const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);
        expect_parent(*vxlan_payload, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ethernet, SelectedPacketByteViewKind::vxlan_payload);
        expect_parent(*inner_vlan, SelectedPacketByteViewKind::inner_ethernet_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::inner_vlan_payload);
        expect_parent(*inner_tcp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_EXPECT(std::any_of(descriptors.begin(), descriptors.end(), [](const auto& descriptor) {
            return descriptor.stable_id == "vxlan:0:0" && descriptor.label == "VXLAN Packet";
        }));
        PFL_EXPECT(vxlan_payload->offset + 8U == inner_ethernet->offset);
        PFL_EXPECT(vxlan_payload->captured_length == inner_ethernet->captured_length + 8U);

        const auto vxlan_materialized = require_materialized_view(presentation, vxlan_payload->id, bytes);
        PFL_REQUIRE(vxlan_materialized.bytes.size() >= 8U);
        for (std::size_t index = 0U; index < 8U; ++index) {
            PFL_EXPECT(vxlan_materialized.bytes[index] == bytes[vxlan_payload->offset + index]);
        }
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/17_geneve_with_options_inner_ipv4_tcp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto bytes = session.read_packet_data(packet);
        const auto labels = collect_labels(presentation);
        const auto* geneve_packet = require_view(presentation, SelectedPacketByteViewKind::geneve_payload);
        const auto* inner_ethernet = require_view(presentation, SelectedPacketByteViewKind::inner_ethernet_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_tcp = require_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload);
        expect_parent(*geneve_packet, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ethernet, SelectedPacketByteViewKind::geneve_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::inner_ethernet_payload);
        expect_parent(*inner_tcp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_REQUIRE(geneve_packet->payload_range.has_value());
        PFL_EXPECT(geneve_packet->payload_range->offset == inner_ethernet->offset);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "Geneve Payload") == labels.end());
        expect_hex_prefix(
            presentation,
            geneve_packet->id,
            bytes,
            {0x02U, 0x00U, 0x65U, 0x58U}
        );
        expect_hex_prefix(
            presentation,
            geneve_packet->id,
            bytes,
            {0x51U, 0x02U},
            session_detail::SelectedPacketByteRangeMode::payload_only
        );
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

        const auto* gtpu_message = require_view(presentation, SelectedPacketByteViewKind::gtpu_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_sctp = require_view(presentation, SelectedPacketByteViewKind::inner_sctp_payload);
        expect_parent(*gtpu_message, SelectedPacketByteViewKind::udp_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::gtpu_payload);
        expect_parent(*inner_sctp, SelectedPacketByteViewKind::inner_ipv4_payload);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/ah/12_ipv4_ah_inner_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        const auto labels = collect_labels(presentation);

        const auto* ah_packet = require_view(presentation, SelectedPacketByteViewKind::ah_payload);
        const auto* inner_ipv4 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* inner_udp = require_view(presentation, SelectedPacketByteViewKind::inner_udp_payload);
        expect_parent(*ah_packet, SelectedPacketByteViewKind::ipv4_payload);
        expect_parent(*inner_ipv4, SelectedPacketByteViewKind::ah_payload);
        expect_parent(*inner_udp, SelectedPacketByteViewKind::inner_ipv4_payload);
        PFL_REQUIRE(ah_packet->payload_range.has_value());
        PFL_EXPECT(ah_packet->payload_range->offset == inner_ipv4->offset);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "AH Payload") == labels.end());
        expect_hex_prefix(
            presentation,
            ah_packet->id,
            bytes,
            {0x04U, 0x04U, 0x00U, 0x00U}
        );
        expect_hex_prefix(
            presentation,
            ah_packet->id,
            bytes,
            {0x45U, 0x00U},
            session_detail::SelectedPacketByteRangeMode::payload_only
        );

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        const auto* udp_data = require_view(flow_aware_presentation, SelectedPacketByteViewKind::data);
        expect_parent(*udp_data, SelectedPacketByteViewKind::inner_udp_payload);
        PFL_EXPECT(udp_data->captured_length == 4U);
        expect_materialized_view_aliases_owner_bytes(flow_aware_presentation, udp_data->id, bytes);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/ah/13_ipv4_ah_inner_ipv6_tcp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* ah_packet = require_view(presentation, SelectedPacketByteViewKind::ah_payload);
        const auto* inner_ipv6 = require_view(presentation, SelectedPacketByteViewKind::inner_ipv6_payload);
        expect_parent(*ah_packet, SelectedPacketByteViewKind::ipv4_payload);
        expect_parent(*inner_ipv6, SelectedPacketByteViewKind::ah_payload);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::inner_tcp_payload) == nullptr);

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        PFL_EXPECT(find_view(flow_aware_presentation, SelectedPacketByteViewKind::data) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/esp/01_ipv4_esp_basic.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto bytes = session.read_packet_data(packet);
        const auto presentation = require_presentation(session, packet);
        const auto labels = collect_labels(presentation);

        const auto* esp_packet = require_view(presentation, SelectedPacketByteViewKind::esp);
        const auto* esp_payload = require_view(presentation, SelectedPacketByteViewKind::esp_protected_payload);
        expect_parent(*esp_packet, SelectedPacketByteViewKind::ipv4_payload);
        expect_parent(*esp_payload, SelectedPacketByteViewKind::esp);
        PFL_REQUIRE(esp_packet->payload_range.has_value());
        PFL_EXPECT(esp_packet->payload_range->offset == esp_payload->offset);
        PFL_EXPECT(std::find(labels.begin(), labels.end(), "ESP Packet") != labels.end());
        expect_hex_prefix(
            presentation,
            esp_packet->id,
            bytes,
            {0x01U, 0x02U, 0x03U, 0x04U, 0x00U, 0x00U, 0x00U, 0x01U}
        );
        expect_hex_prefix(
            presentation,
            esp_payload->id,
            bytes,
            {0x05U, 0x06U, 0x07U, 0x08U}
        );
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

        const auto flow_aware_presentation = require_flow_aware_presentation(session, packet);
        PFL_EXPECT(find_view(flow_aware_presentation, SelectedPacketByteViewKind::data) == nullptr);
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
