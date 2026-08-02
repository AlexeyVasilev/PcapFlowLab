#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "app/session/SelectedPacketBytePresentation.h"

namespace pfl::tests {

namespace {

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

SelectedPacketBytePresentation require_presentation(
    CaptureSession& session,
    const PacketRef& packet
) {
    const auto presentation = session.derive_selected_packet_byte_presentation(packet);
    PFL_REQUIRE(presentation.has_value());
    return *presentation;
}

const SelectedPacketByteViewDescriptor* require_view(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t occurrence = 0U
) {
    const auto* view = presentation.find_view(SelectedPacketByteViewId {
        .kind = kind,
        .occurrence = occurrence,
    });
    PFL_REQUIRE(view != nullptr);
    return view;
}

const SelectedPacketByteViewDescriptor* find_view(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewKind kind,
    const std::uint8_t occurrence = 0U
) {
    return presentation.find_view(SelectedPacketByteViewId {
        .kind = kind,
        .occurrence = occurrence,
    });
}

std::vector<SelectedPacketByteViewKind> collect_kinds(const SelectedPacketBytePresentation& presentation) {
    std::vector<SelectedPacketByteViewKind> kinds {};
    kinds.reserve(presentation.views.size());
    for (const auto& view : presentation.views) {
        kinds.push_back(view.id.kind);
    }
    return kinds;
}

void expect_materialized_view_aliases_owner_bytes(
    const SelectedPacketBytePresentation& presentation,
    const SelectedPacketByteViewId& id,
    const std::vector<std::uint8_t>& owner_bytes
) {
    const auto materialized = session_detail::materialize_selected_packet_byte_view(
        presentation,
        id,
        std::span<const std::uint8_t>(owner_bytes.data(), owner_bytes.size())
    );
    PFL_REQUIRE(materialized.has_value());
    PFL_REQUIRE(materialized->descriptor != nullptr);
    PFL_EXPECT(materialized->bytes.data() == owner_bytes.data() + materialized->descriptor->offset);
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
        const auto* ipv4_payload = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* tcp_payload = require_view(presentation, SelectedPacketByteViewKind::tcp_payload);
        PFL_EXPECT(frame->offset == 0U);
        PFL_EXPECT(frame->captured_length == packet.captured_length);
        PFL_EXPECT(ipv4_payload->offset == 34U);
        PFL_EXPECT(ipv4_payload->captured_length == 24U);
        PFL_EXPECT(tcp_payload->offset == 54U);
        PFL_EXPECT(tcp_payload->captured_length == 4U);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::effective_transport_payload) == nullptr);

        expect_materialized_view_aliases_owner_bytes(
            presentation,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::tcp_payload, .occurrence = 0U},
            bytes
        );

        const auto tcp_dump = session.format_selected_packet_byte_view_hex_dump(
            packet,
            SelectedPacketByteViewId {.kind = SelectedPacketByteViewKind::tcp_payload, .occurrence = 0U}
        );
        PFL_REQUIRE(tcp_dump.has_value());
        PFL_EXPECT(tcp_dump->find("41 42 43 44") != std::string::npos);
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
        std::vector<std::uint8_t> captured_packet(full_packet.begin(), full_packet.begin() + static_cast<std::ptrdiff_t>(full_packet.size() - 3U));
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
        const auto presentation = require_presentation(session, packet);

        const auto* udp_payload = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        PFL_EXPECT(udp_payload->captured_length == 4U);
        PFL_EXPECT(udp_payload->declared_length == std::optional<std::uint32_t> {7U});
        PFL_EXPECT(udp_payload->truncated);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::effective_transport_payload) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vlan/05_qinq_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const std::vector<SelectedPacketByteViewKind> expected_kinds {
            SelectedPacketByteViewKind::frame,
            SelectedPacketByteViewKind::ethernet_payload,
            SelectedPacketByteViewKind::vlan_payload,
            SelectedPacketByteViewKind::vlan_payload,
            SelectedPacketByteViewKind::ipv4_payload,
            SelectedPacketByteViewKind::udp_payload,
        };
        PFL_EXPECT(collect_kinds(presentation) == expected_kinds);
        PFL_EXPECT(require_view(presentation, SelectedPacketByteViewKind::vlan_payload, 0U)->id.occurrence == 0U);
        PFL_EXPECT(require_view(presentation, SelectedPacketByteViewKind::vlan_payload, 1U)->id.occurrence == 1U);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::effective_transport_payload) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/mpls/14_qinq_mpls_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* mpls_payload = require_view(presentation, SelectedPacketByteViewKind::mpls_payload);
        const auto* ipv4_payload = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        PFL_EXPECT(mpls_payload->offset < ipv4_payload->offset);
        PFL_EXPECT(mpls_payload->captured_length > ipv4_payload->captured_length);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/32_gtpu_inner_ipv4_udp_data.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* top_level_udp = require_view(presentation, SelectedPacketByteViewKind::udp_payload);
        const auto* inner_ipv4_payload = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* terminal_payload = require_view(presentation, SelectedPacketByteViewKind::effective_transport_payload);
        PFL_EXPECT(top_level_udp->offset < inner_ipv4_payload->offset);
        PFL_EXPECT(inner_ipv4_payload->offset < terminal_payload->offset);
        PFL_EXPECT(terminal_payload->captured_length > 0U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/34_gtpu_inner_ipv4_tcp_ack_only.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::effective_transport_payload) == nullptr);
        PFL_EXPECT(find_view(presentation, SelectedPacketByteViewKind::tcp_payload) == nullptr);
        PFL_REQUIRE(find_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload) != nullptr);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/ip_encapsulation/02_ipv4_in_ipv4_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto presentation = require_presentation(session, packet);

        const auto* top_level_ipv4_payload = require_view(presentation, SelectedPacketByteViewKind::ipv4_payload);
        const auto* inner_ipv4_payload = require_view(presentation, SelectedPacketByteViewKind::inner_ipv4_payload);
        const auto* terminal_payload = require_view(presentation, SelectedPacketByteViewKind::effective_transport_payload);
        PFL_EXPECT(top_level_ipv4_payload->offset < inner_ipv4_payload->offset);
        PFL_EXPECT(inner_ipv4_payload->offset < terminal_payload->offset);
    }
}

}  // namespace

void run_selected_packet_byte_presentation_tests() {
    run_selected_packet_byte_presentation_tests_impl();
}

}  // namespace pfl::tests
