#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/SessionFormatting.h"
#include "core/io/PcapReader.h"
#include "core/services/PacketDetailsService.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

PacketRef make_packet_ref(const RawPcapPacket& packet) {
    PacketRef ref {};
    ref.packet_index = packet.packet_index;
    ref.byte_offset = packet.data_offset;
    ref.data_link_type = packet.data_link_type;
    ref.captured_length = packet.captured_length;
    ref.original_length = packet.original_length;
    ref.ts_sec = packet.ts_sec;
    ref.ts_usec = packet.ts_usec;
    return ref;
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_EXPECT(packet.has_value());
    return *packet;
}

RawPcapPacket require_raw_fixture_packet(const std::filesystem::path& relative_path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(fixture_path(relative_path)));
    const auto packet = reader.read_next();
    PFL_EXPECT(packet.has_value());
    PFL_EXPECT(!reader.read_next().has_value());
    return *packet;
}

std::optional<PacketDetails> decode_fixture_packet_details_best_effort(const RawPcapPacket& packet) {
    PacketDetailsService details_service {};
    return details_service.decode_best_effort(packet.bytes, make_packet_ref(packet));
}

std::vector<session_detail::PacketSummaryLayer> build_summary_layers(
    const PacketDetails& details,
    const PacketRef& packet,
    const std::string& protocol_details_text = {}
) {
    session_detail::PacketSummaryOptions options {};
    options.source_capture_accessible = true;
    options.protocol_details_text = protocol_details_text;
    return session_detail::build_packet_summary_layers(details, packet, options);
}

const session_detail::PacketSummaryLayer* find_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    const auto it = std::find_if(layers.begin(), layers.end(), [&](const session_detail::PacketSummaryLayer& layer) {
        return layer.id == id;
    });
    return it == layers.end() ? nullptr : &(*it);
}

const session_detail::PacketSummaryField* find_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto it = std::find_if(layer.fields.begin(), layer.fields.end(), [&](const session_detail::PacketSummaryField& field) {
        return field.label == label;
    });
    return it == layer.fields.end() ? nullptr : &(*it);
}

const session_detail::PacketSummaryLayer* find_child(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& id,
    const std::size_t occurrence = 0U
) {
    std::size_t seen = 0U;
    for (const auto& child : layer.children) {
        if (child.id != id) {
            continue;
        }
        if (seen == occurrence) {
            return &child;
        }
        ++seen;
    }
    return nullptr;
}

}  // namespace

void run_ipv4_options_pcap_fixture_tests() {
    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/01_ipv4_udp_no_options_control.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->ipv4.options_bytes.empty());

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        PFL_EXPECT(find_child(*ipv4_layer, "ipv4_options") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/02_ipv4_router_alert_igmpv2_report.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_igmp);
        PFL_EXPECT(!details->has_udp);

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        const auto* igmp_layer = find_layer(layers, "igmp");
        PFL_EXPECT(ipv4_layer != nullptr);
        PFL_EXPECT(igmp_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(ipv4_options->title == "IPv4 Options (4 bytes)");
        const auto* router_alert = find_child(*ipv4_options, "ipv4_option_router_alert");
        PFL_EXPECT(router_alert != nullptr);
        const auto* meaning_field = find_field(*router_alert, "Meaning");
        PFL_EXPECT(meaning_field != nullptr);
        PFL_EXPECT(meaning_field->value == "Router shall examine packet");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/03_ipv4_router_alert_udp_payload.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 12345U);
        PFL_EXPECT(details->udp.dst_port == 54321U);

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        const auto* udp_layer = find_layer(layers, "udp");
        PFL_EXPECT(ipv4_layer != nullptr);
        PFL_EXPECT(udp_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_router_alert") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/04_ipv4_nop_eol_padding_tcp_syn.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.flags == 0x02U);

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        const auto* tcp_layer = find_layer(layers, "tcp");
        PFL_EXPECT(ipv4_layer != nullptr);
        PFL_EXPECT(tcp_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_nop", 0U) != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_nop", 1U) != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_eol", 0U) != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/05_ipv4_record_route_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_udp);

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        const auto* rr = find_child(*ipv4_options, "ipv4_option_rr");
        PFL_EXPECT(rr != nullptr);
        PFL_EXPECT(find_field(*rr, "Pointer") != nullptr);
        PFL_EXPECT(find_field(*rr, "Route Address 1") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/06_ipv4_timestamp_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        const auto* timestamp = find_child(*ipv4_options, "ipv4_option_timestamp");
        PFL_EXPECT(timestamp != nullptr);
        PFL_EXPECT(find_field(*timestamp, "Pointer") != nullptr);
        PFL_EXPECT(find_field(*timestamp, "Overflow") != nullptr);
        PFL_EXPECT(find_field(*timestamp, "Flag") != nullptr);
        PFL_EXPECT(find_field(*timestamp, "Raw") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/07_ipv4_loose_source_route_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_lsrr") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/08_ipv4_strict_source_route_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_ssrr") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/09_ipv4_unknown_valid_option_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        const auto* unknown = find_child(*ipv4_options, "ipv4_option_unknown");
        PFL_EXPECT(unknown != nullptr);
        PFL_EXPECT(find_field(*unknown, "Type") != nullptr);
        PFL_EXPECT(find_field(*unknown, "Raw") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/10_ipv4_multiple_options_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_udp);

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_nop", 0U) != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_router_alert", 0U) != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_rr", 0U) != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_eol", 0U) != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/11_ipv4_max_header_options_tcp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->ipv4.header_length_bytes == 60U);

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        const auto* tcp_layer = find_layer(layers, "tcp");
        PFL_EXPECT(ipv4_layer != nullptr);
        PFL_EXPECT(tcp_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(ipv4_options->title == "IPv4 Options (40 bytes)");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/12_ipv4_first_fragment_with_options_udp.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(packet.is_ip_fragmented);

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        PFL_EXPECT(find_field(*ipv4_layer, "Fragmentation") != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_router_alert") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/13_ipv4_noninitial_fragment_with_options.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(!details->has_tcp);

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_router_alert") != nullptr);
    }

    {
        const auto raw_packet = require_raw_fixture_packet("parsing/ip_options/14_ipv4_option_length_zero_malformed.pcap");
        const auto details = decode_fixture_packet_details_best_effort(raw_packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);

        const auto layers = build_summary_layers(*details, make_packet_ref(raw_packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        const auto* malformed = find_child(*ipv4_options, "ipv4_option_malformed");
        PFL_EXPECT(malformed != nullptr);
        PFL_EXPECT(malformed->title == "IPv4 option length is invalid");
    }

    {
        const auto raw_packet = require_raw_fixture_packet("parsing/ip_options/15_ipv4_option_length_one_malformed.pcap");
        const auto details = decode_fixture_packet_details_best_effort(raw_packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);

        const auto layers = build_summary_layers(*details, make_packet_ref(raw_packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        const auto* malformed = find_child(*ipv4_options, "ipv4_option_malformed");
        PFL_EXPECT(malformed != nullptr);
        PFL_EXPECT(malformed->title == "IPv4 option length is invalid");
    }

    {
        const auto raw_packet = require_raw_fixture_packet("parsing/ip_options/16_ipv4_option_length_past_ihl_malformed.pcap");
        const auto details = decode_fixture_packet_details_best_effort(raw_packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);

        const auto layers = build_summary_layers(*details, make_packet_ref(raw_packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        const auto* malformed = find_child(*ipv4_options, "ipv4_option_malformed");
        PFL_EXPECT(malformed != nullptr);
        PFL_EXPECT(malformed->title == "IPv4 option length exceeds header");
    }

    {
        const auto raw_packet = require_raw_fixture_packet("parsing/ip_options/17_ipv4_options_missing_length_byte_malformed.pcap");
        const auto details = decode_fixture_packet_details_best_effort(raw_packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_udp);

        const auto layers = build_summary_layers(*details, make_packet_ref(raw_packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        const auto* truncated = find_child(*ipv4_options, "ipv4_option_malformed", 0U);
        const auto* malformed = find_child(*ipv4_options, "ipv4_option_malformed", 1U);
        PFL_EXPECT(truncated != nullptr);
        PFL_EXPECT(truncated->title == "IPv4 options truncated");
        PFL_EXPECT(malformed != nullptr);
        PFL_EXPECT(malformed->title == "IPv4 option length field missing");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ip_options/18_ipv4_eol_then_nonzero_padding.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());

        const auto layers = build_summary_layers(*details, packet, session.read_packet_protocol_details_text(packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_eol") != nullptr);
        const auto* malformed = find_child(*ipv4_options, "ipv4_option_malformed");
        PFL_EXPECT(malformed != nullptr);
        PFL_EXPECT(malformed->title == "Non-zero padding after EOL");
    }

    {
        const auto raw_packet = require_raw_fixture_packet("parsing/ip_options/19_ipv4_snaplen_truncated_inside_options.pcap");
        const auto details = decode_fixture_packet_details_best_effort(raw_packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.header_truncated);
        PFL_EXPECT(details->ipv4.options_truncated);
        PFL_EXPECT(!details->has_udp);

        const auto layers = build_summary_layers(*details, make_packet_ref(raw_packet));
        const auto* warnings = find_layer(layers, "warnings");
        PFL_EXPECT(warnings != nullptr);
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(ipv4_options->warning);
        const auto* malformed = find_child(*ipv4_options, "ipv4_option_malformed", 0U);
        PFL_EXPECT(malformed != nullptr);
        PFL_EXPECT(malformed->title == "IPv4 options truncated");
    }

    {
        const auto raw_packet = require_raw_fixture_packet("parsing/ip_options/20_ipv4_snaplen_truncated_before_next_header.pcap");
        const auto details = decode_fixture_packet_details_best_effort(raw_packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->ipv4.header_truncated);
        PFL_EXPECT(!details->has_udp);

        const auto layers = build_summary_layers(*details, make_packet_ref(raw_packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        const auto* ipv4_options = find_child(*ipv4_layer, "ipv4_options");
        PFL_EXPECT(ipv4_options != nullptr);
        PFL_EXPECT(find_child(*ipv4_options, "ipv4_option_router_alert") != nullptr);
    }

    {
        const auto raw_packet = require_raw_fixture_packet("parsing/ip_options/21_ipv4_ihl_exceeds_packet_length.pcap");
        const auto details = decode_fixture_packet_details_best_effort(raw_packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.header_truncated);
        PFL_EXPECT(!details->has_udp);

        const auto layers = build_summary_layers(*details, make_packet_ref(raw_packet));
        PFL_EXPECT(find_layer(layers, "ipv4") != nullptr);
        PFL_EXPECT(find_layer(layers, "warnings") != nullptr);
    }

    {
        const auto raw_packet = require_raw_fixture_packet("parsing/ip_options/22_ipv4_invalid_ihl_too_small.pcap");
        const auto details = decode_fixture_packet_details_best_effort(raw_packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.invalid_header_length);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(!details->has_tcp);

        const auto layers = build_summary_layers(*details, make_packet_ref(raw_packet));
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        PFL_EXPECT(ipv4_layer->warning);
        PFL_EXPECT(find_child(*ipv4_layer, "ipv4_options") == nullptr);
    }
}

}  // namespace pfl::tests
