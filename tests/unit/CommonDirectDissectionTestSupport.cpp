#include "CommonDirectDissectionTestSupport.h"

#include <algorithm>
#include <utility>
#include <variant>

#include "core/decode/PacketDecodeSupport.h"
#include "core/decode/PacketDecoder.h"

namespace pfl::tests::common_direct_test {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

std::vector<std::vector<std::uint8_t>>& declared_root_slice_storage() {
    static std::vector<std::vector<std::uint8_t>> storage {};
    return storage;
}

std::string format_builder_path(const ProtocolPathBuilder& builder) {
    PFL_EXPECT(!builder.overflowed());
    return format_protocol_path(builder.to_path());
}

bool protocol_uses_ports(const ProtocolId protocol) {
    return protocol == ProtocolId::tcp ||
           protocol == ProtocolId::udp ||
           protocol == ProtocolId::sctp;
}

}  // namespace

RawPcapPacket make_raw_packet(
    const std::vector<std::uint8_t>& captured_bytes,
    const std::uint32_t original_length,
    const std::uint32_t data_link_type,
    const std::uint64_t packet_index
) {
    return RawPcapPacket {
        .packet_index = packet_index,
        .ts_sec = 1U,
        .ts_usec = 1U,
        .captured_length = static_cast<std::uint32_t>(captured_bytes.size()),
        .original_length = original_length == 0U ? static_cast<std::uint32_t>(captured_bytes.size()) : original_length,
        .data_offset = 64U,
        .data_link_type = data_link_type,
        .bytes = captured_bytes,
    };
}

RawPcapPacket require_raw_fixture_packet(const std::filesystem::path& relative_path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(fixture_path(relative_path)));
    const auto packet = reader.read_next();
    PFL_REQUIRE(packet.has_value());
    PFL_EXPECT(!reader.read_next().has_value());
    return *packet;
}

std::vector<RawPcapPacket> require_raw_fixture_packets(const std::filesystem::path& relative_path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(fixture_path(relative_path)));

    std::vector<RawPcapPacket> packets {};
    while (const auto packet = reader.read_next()) {
        packets.push_back(*packet);
    }

    PFL_EXPECT(!packets.empty());
    return packets;
}

PacketSlice make_root_slice(const RawPcapPacket& packet) {
    return make_root_packet_slice(
        ByteSourceId::captured_frame(static_cast<std::uint32_t>(packet.packet_index)),
        packet.bytes,
        packet.captured_length,
        packet.original_length
    );
}

PacketSlice make_declared_root_slice(const std::vector<std::uint8_t>& bytes, const std::size_t declared_length) {
    auto& storage = declared_root_slice_storage();
    storage.push_back(bytes);
    const auto& stable_bytes = storage.back();
    return make_root_packet_slice(
        ByteSourceId::captured_frame(),
        stable_bytes,
        stable_bytes.size(),
        declared_length
    );
}

PacketSlice require_child_slice(
    const PacketSlice& parent,
    const std::size_t payload_offset,
    const std::size_t declared_payload_length
) {
    const auto child = make_child_slice(parent, payload_offset, declared_payload_length);
    PFL_REQUIRE(child.has_slice());
    return *child.slice;
}

ByteRange require_range(const std::size_t begin, const std::size_t end) {
    const auto range = ByteRange::from_begin_end(begin, end);
    PFL_REQUIRE(range.has_value());
    return *range;
}

std::string format_shadow_path(const ImportDissectionFacts& facts) {
    return format_builder_path(facts.physical_path);
}

ProtocolPath shadow_path(const ImportDissectionFacts& facts) {
    PFL_EXPECT(!facts.physical_path.overflowed());
    return facts.physical_path.to_path();
}

LegacyDirectFacts decode_legacy_direct(const RawPcapPacket& packet) {
    PacketDecoder decoder {};
    const auto decoded = decoder.decode(packet);

    LegacyDirectFacts facts {};
    if (!decoded.has_value()) {
        return facts;
    }

    facts.recognized_flow = true;
    facts.path = decoded.protocol_path_builder.to_path();

    if (decoded.ipv4.has_value()) {
        facts.family = DissectionAddressFamily::ipv4;
        facts.protocol = decoded.ipv4->flow_key.protocol;
        facts.has_addresses = true;
        facts.src_addr_v4 = decoded.ipv4->flow_key.src_addr;
        facts.dst_addr_v4 = decoded.ipv4->flow_key.dst_addr;
        facts.is_ip_fragmented = decoded.ipv4->packet_ref.is_ip_fragmented;
        facts.has_ports = !facts.is_ip_fragmented && protocol_uses_ports(facts.protocol);
        facts.src_port = decoded.ipv4->flow_key.src_port;
        facts.dst_port = decoded.ipv4->flow_key.dst_port;
        facts.has_payload_length = !facts.is_ip_fragmented || decoded.ipv4->packet_ref.payload_length != 0U;
        facts.captured_payload_length = decoded.ipv4->packet_ref.payload_length;
        facts.has_tcp_flags = facts.protocol == ProtocolId::tcp && !facts.is_ip_fragmented;
        facts.tcp_flags = decoded.ipv4->packet_ref.tcp_flags;
    } else if (decoded.ipv6.has_value()) {
        facts.family = DissectionAddressFamily::ipv6;
        facts.protocol = decoded.ipv6->flow_key.protocol;
        facts.has_addresses = true;
        facts.src_addr_v6 = decoded.ipv6->flow_key.src_addr;
        facts.dst_addr_v6 = decoded.ipv6->flow_key.dst_addr;
        facts.is_ip_fragmented = decoded.ipv6->packet_ref.is_ip_fragmented;
        facts.has_ports = !facts.is_ip_fragmented && protocol_uses_ports(facts.protocol);
        facts.src_port = decoded.ipv6->flow_key.src_port;
        facts.dst_port = decoded.ipv6->flow_key.dst_port;
        facts.has_payload_length = !facts.is_ip_fragmented || decoded.ipv6->packet_ref.payload_length != 0U;
        facts.captured_payload_length = decoded.ipv6->packet_ref.payload_length;
        facts.has_tcp_flags = facts.protocol == ProtocolId::tcp && !facts.is_ip_fragmented;
        facts.tcp_flags = decoded.ipv6->packet_ref.tcp_flags;
    }

    return facts;
}

ImportDissectionFacts run_shadow(const RawPcapPacket& packet, const DissectionRegistry& registry) {
    ImportDissectionCollector collector {};
    const DissectionEngine engine {};
    const auto result = engine.run(
        registry,
        make_link_type_selector(packet.data_link_type),
        make_root_slice(packet),
        collector.consumer()
    );
    collector.finish(result);
    return collector.facts();
}

std::vector<DissectionStep> collect_shadow_steps(const RawPcapPacket& packet, const DissectionRegistry& registry) {
    struct StepRecorder {
        std::vector<DissectionStep> steps {};
    };

    auto record_step = [](void* context, const DissectionStep& step) {
        auto* recorder = static_cast<StepRecorder*>(context);
        recorder->steps.push_back(step);
    };

    StepRecorder recorder {};
    const DissectionEngine engine {};
    static_cast<void>(engine.run(
        registry,
        make_link_type_selector(packet.data_link_type),
        make_root_slice(packet),
        DissectionConsumer {
            .on_step = record_step,
            .context = &recorder,
        }
    ));
    return recorder.steps;
}

std::vector<DissectionLayerKind> collect_step_kinds(const std::vector<DissectionStep>& steps) {
    std::vector<DissectionLayerKind> kinds {};
    kinds.reserve(steps.size());
    for (const auto& step : steps) {
        kinds.push_back(step.layer);
    }
    return kinds;
}

const PppoeFacts* find_pppoe_facts(const std::vector<DissectionStep>& steps) {
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::pppoe) {
            continue;
        }

        const auto* facts = std::get_if<PppoeFacts>(&step.facts);
        if (facts != nullptr) {
            return facts;
        }
    }

    return nullptr;
}

const PbbFacts* find_pbb_facts(const std::vector<DissectionStep>& steps) {
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::pbb) {
            continue;
        }

        const auto* facts = std::get_if<PbbFacts>(&step.facts);
        if (facts != nullptr) {
            return facts;
        }
    }

    return nullptr;
}

const MacsecFacts* find_macsec_facts(const std::vector<DissectionStep>& steps) {
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::macsec) {
            continue;
        }

        const auto* facts = std::get_if<MacsecFacts>(&step.facts);
        if (facts != nullptr) {
            return facts;
        }
    }

    return nullptr;
}

void expect_shadow_matches_legacy_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_path,
    const StopReason expected_stop_reason
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow_path(shadow) == legacy.path);
    PFL_EXPECT(format_shadow_path(shadow) == expected_path);
    PFL_EXPECT(format_protocol_path(legacy.path) == expected_path);
    PFL_EXPECT(shadow.terminal_protocol == legacy.protocol);
    PFL_EXPECT(shadow.family == legacy.family);
    PFL_EXPECT(shadow.has_flow_addresses == legacy.has_addresses);
    if (legacy.family == DissectionAddressFamily::ipv4) {
        PFL_EXPECT(shadow.src_addr_v4 == legacy.src_addr_v4);
        PFL_EXPECT(shadow.dst_addr_v4 == legacy.dst_addr_v4);
        PFL_EXPECT(shadow.has_ipv4_fragmentation);
        PFL_EXPECT(shadow.ipv4_fragmentation.is_fragmented == legacy.is_ip_fragmented);
    } else if (legacy.family == DissectionAddressFamily::ipv6) {
        PFL_EXPECT(shadow.src_addr_v6 == legacy.src_addr_v6);
        PFL_EXPECT(shadow.dst_addr_v6 == legacy.dst_addr_v6);
        PFL_EXPECT(shadow.has_ipv6_fragmentation);
        PFL_EXPECT(shadow.ipv6_fragmentation.has_fragment_header == legacy.is_ip_fragmented);
    }
    PFL_EXPECT(shadow.has_ports == legacy.has_ports);
    PFL_EXPECT(shadow.src_port == legacy.src_port);
    PFL_EXPECT(shadow.dst_port == legacy.dst_port);
    PFL_EXPECT(shadow.has_transport_payload_length == legacy.has_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == legacy.captured_payload_length);
    PFL_EXPECT(shadow.has_tcp_flags == legacy.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == legacy.tcp_flags);
}

void expect_shadow_matches_legacy_portless_terminal_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_path,
    const StopReason expected_stop_reason
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow_path(shadow) == legacy.path);
    PFL_EXPECT(format_shadow_path(shadow) == expected_path);
    PFL_EXPECT(format_protocol_path(legacy.path) == expected_path);
    PFL_EXPECT(shadow.terminal_protocol == legacy.protocol);
    PFL_EXPECT(shadow.family == legacy.family);
    PFL_EXPECT(shadow.has_flow_addresses == legacy.has_addresses);
    if (legacy.family == DissectionAddressFamily::ipv4) {
        PFL_EXPECT(shadow.src_addr_v4 == legacy.src_addr_v4);
        PFL_EXPECT(shadow.dst_addr_v4 == legacy.dst_addr_v4);
        PFL_EXPECT(shadow.has_ipv4_fragmentation);
        PFL_EXPECT(shadow.ipv4_fragmentation.is_fragmented == legacy.is_ip_fragmented);
    } else if (legacy.family == DissectionAddressFamily::ipv6) {
        PFL_EXPECT(shadow.src_addr_v6 == legacy.src_addr_v6);
        PFL_EXPECT(shadow.dst_addr_v6 == legacy.dst_addr_v6);
        PFL_EXPECT(shadow.has_ipv6_fragmentation);
        PFL_EXPECT(shadow.ipv6_fragmentation.has_fragment_header == legacy.is_ip_fragmented);
    }
    PFL_EXPECT(legacy.src_port == 0U);
    PFL_EXPECT(legacy.dst_port == 0U);
    PFL_EXPECT(!shadow.has_ports);
    PFL_EXPECT(shadow.src_port == 0U);
    PFL_EXPECT(shadow.dst_port == 0U);
    PFL_EXPECT(!shadow.has_transport_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == 0U);
    PFL_EXPECT(!shadow.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == 0U);
}

void expect_shadow_matches_legacy_recognized_non_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_shadow_path,
    const std::string& expected_legacy_path,
    const StopReason expected_stop_reason
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(legacy.protocol == ProtocolId::arp);
    PFL_EXPECT(format_protocol_path(legacy.path) == expected_legacy_path);

    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_non_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow.terminal_protocol == ProtocolId::arp);
    PFL_EXPECT(shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(shadow.has_arp_addresses);
    PFL_EXPECT(format_shadow_path(shadow) == expected_shadow_path);
    PFL_EXPECT(!shadow.has_ports);
    PFL_EXPECT(shadow.src_port == 0U);
    PFL_EXPECT(shadow.dst_port == 0U);
    PFL_EXPECT(!shadow.has_transport_payload_length);
    PFL_EXPECT(!shadow.has_tcp_flags);
}

void record_step_kind(void* context, const DissectionStep& step) {
    auto* recorder = static_cast<StepKindRecorder*>(context);
    recorder->kinds.push_back(step.layer);
}

std::vector<std::uint8_t> add_ipv4_options(
    const std::vector<std::uint8_t>& ethernet_packet,
    const std::vector<std::uint8_t>& options
) {
    PFL_REQUIRE((options.size() % 4U) == 0U);
    auto bytes = ethernet_packet;
    constexpr std::size_t ip_offset = 14U;
    const auto old_header_length = static_cast<std::size_t>((bytes[ip_offset] & 0x0FU) * 4U);
    const auto transport_offset = ip_offset + old_header_length;
    bytes.insert(
        bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset),
        options.begin(),
        options.end()
    );

    bytes[ip_offset] = static_cast<std::uint8_t>((bytes[ip_offset] & 0xF0U) | ((old_header_length + options.size()) / 4U));
    const auto total_length = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[ip_offset + 2U]) << 8U) |
        static_cast<std::uint16_t>(bytes[ip_offset + 3U])
    );
    const auto new_total_length = static_cast<std::uint16_t>(total_length + options.size());
    bytes[ip_offset + 2U] = static_cast<std::uint8_t>((new_total_length >> 8U) & 0xFFU);
    bytes[ip_offset + 3U] = static_cast<std::uint8_t>(new_total_length & 0xFFU);
    return bytes;
}

void set_ipv4_total_length(std::vector<std::uint8_t>& packet, const std::uint16_t total_length) {
    constexpr std::size_t ip_offset = 14U;
    packet[ip_offset + 2U] = static_cast<std::uint8_t>((total_length >> 8U) & 0xFFU);
    packet[ip_offset + 3U] = static_cast<std::uint8_t>(total_length & 0xFFU);
}

void set_udp_length(std::vector<std::uint8_t>& packet, const std::uint16_t datagram_length) {
    constexpr std::size_t udp_offset = 14U + 20U;
    packet[udp_offset + 4U] = static_cast<std::uint8_t>((datagram_length >> 8U) & 0xFFU);
    packet[udp_offset + 5U] = static_cast<std::uint8_t>(datagram_length & 0xFFU);
}

std::vector<std::uint8_t> make_ethernet_ieee8023_frame(const std::uint16_t payload_length) {
    std::vector<std::uint8_t> bytes {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        static_cast<std::uint8_t>((payload_length >> 8U) & 0xFFU),
        static_cast<std::uint8_t>(payload_length & 0xFFU),
    };
    for (std::uint16_t index = 0U; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(index & 0xFFU));
    }
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_frame_with_payload(
    const std::uint16_t ether_type,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    };
    append_be16(bytes, ether_type);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_macsec_bytes(
    const std::uint8_t tci_an,
    const std::uint8_t short_length,
    const std::uint32_t packet_number,
    const std::vector<std::uint8_t>& protected_payload,
    const bool has_sci,
    const std::uint64_t sci,
    const bool include_full_icv,
    const std::vector<std::uint8_t>& icv_override
) {
    std::vector<std::uint8_t> bytes {
        tci_an,
        short_length,
    };
    append_be32(bytes, packet_number);
    if (has_sci) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            bytes.push_back(static_cast<std::uint8_t>((sci >> shift) & 0xFFU));
        }
    }
    bytes.insert(bytes.end(), protected_payload.begin(), protected_payload.end());
    if (include_full_icv) {
        if (icv_override.empty()) {
            for (std::uint8_t index = 0U; index < 16U; ++index) {
                bytes.push_back(static_cast<std::uint8_t>(0xA0U + index));
            }
        } else {
            bytes.insert(bytes.end(), icv_override.begin(), icv_override.end());
        }
    }
    return bytes;
}

void append_mpls_label(
    std::vector<std::uint8_t>& bytes,
    const std::uint32_t label,
    const bool bottom_of_stack,
    const std::uint8_t traffic_class,
    const std::uint8_t ttl
) {
    const auto entry = (label << 12U) |
        (static_cast<std::uint32_t>(traffic_class & 0x7U) << 9U) |
        (static_cast<std::uint32_t>(bottom_of_stack ? 1U : 0U) << 8U) |
        static_cast<std::uint32_t>(ttl);
    append_be32(bytes, entry);
}

std::vector<std::uint8_t> make_mpls_payload_with_labels(
    const std::initializer_list<std::uint32_t> labels,
    const std::vector<std::uint8_t>& payload,
    const std::uint8_t traffic_class,
    const std::uint8_t ttl
) {
    PFL_REQUIRE(labels.size() > 0U);
    std::vector<std::uint8_t> bytes {};
    std::size_t index = 0U;
    for (const auto label : labels) {
        ++index;
        append_mpls_label(bytes, label, index == labels.size(), traffic_class, ttl);
    }
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_ipv4_header_only_packet(const std::uint8_t protocol) {
    std::vector<std::uint8_t> bytes {
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
        0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02,
        0x08, 0x00,
        0x45, 0x00,
    };
    append_be16(bytes, 20U);
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    bytes.push_back(64U);
    bytes.push_back(protocol);
    append_be16(bytes, 0U);
    append_be32(bytes, ipv4(10, 0, 0, 1));
    append_be32(bytes, ipv4(10, 0, 0, 2));
    return bytes;
}

std::vector<std::uint8_t> make_sctp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint32_t verification_tag,
    const std::uint32_t checksum,
    const std::uint16_t payload_length
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be32(bytes, verification_tag);
    append_be32(bytes, checksum);
    for (std::uint16_t index = 0U; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(0x30U + (index % 10U)));
    }
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_ipv4_sctp_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint32_t verification_tag,
    const std::uint32_t checksum,
    const std::uint16_t payload_length
) {
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolSctp,
        0U,
        make_sctp_segment(src_port, dst_port, verification_tag, checksum, payload_length)
    );
}

std::vector<std::uint8_t> make_gre_header(
    const std::uint16_t protocol_type,
    const std::vector<std::uint8_t>& payload,
    const bool has_checksum,
    const bool has_key,
    const bool has_sequence,
    const std::uint16_t extra_flags,
    const std::uint16_t checksum,
    const std::uint16_t reserved1,
    const std::uint32_t key,
    const std::uint32_t sequence_number
) {
    std::uint16_t flags_and_version = extra_flags;
    if (has_checksum) {
        flags_and_version = static_cast<std::uint16_t>(flags_and_version | detail::kGreFlagChecksum);
    }
    if (has_key) {
        flags_and_version = static_cast<std::uint16_t>(flags_and_version | detail::kGreFlagKey);
    }
    if (has_sequence) {
        flags_and_version = static_cast<std::uint16_t>(flags_and_version | detail::kGreFlagSequence);
    }

    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, flags_and_version);
    append_be16(bytes, protocol_type);
    if (has_checksum) {
        append_be16(bytes, checksum);
        append_be16(bytes, reserved1);
    }
    if (has_key) {
        append_be32(bytes, key);
    }
    if (has_sequence) {
        append_be32(bytes, sequence_number);
    }
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_ipv4_gre_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::vector<std::uint8_t>& gre_payload,
    const std::uint16_t flags_fragment,
    const std::uint8_t ttl
) {
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolGre,
        flags_fragment,
        gre_payload,
        ttl
    );
}

std::vector<std::uint8_t> make_ethernet_ipv6_gre_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    const std::vector<std::uint8_t>& gre_payload
) {
    return make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolGre,
        gre_payload
    );
}

std::vector<std::uint8_t> make_ah_header(
    const std::uint8_t next_header,
    const std::uint32_t spi,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& icv,
    const std::uint16_t reserved,
    const std::optional<std::uint8_t>& payload_length_field_override
) {
    PFL_REQUIRE((icv.size() % 4U) == 0U);
    const auto computed_header_length = 12U + icv.size();
    const auto payload_length_field = payload_length_field_override.value_or(
        static_cast<std::uint8_t>((computed_header_length / 4U) - 2U)
    );

    std::vector<std::uint8_t> bytes {};
    bytes.push_back(next_header);
    bytes.push_back(payload_length_field);
    append_be16(bytes, reserved);
    append_be32(bytes, spi);
    append_be32(bytes, sequence_number);
    bytes.insert(bytes.end(), icv.begin(), icv.end());
    return bytes;
}

std::vector<std::uint8_t> make_esp_header(
    const std::uint32_t spi,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& opaque_payload
) {
    std::vector<std::uint8_t> bytes {};
    append_be32(bytes, spi);
    append_be32(bytes, sequence_number);
    bytes.insert(bytes.end(), opaque_payload.begin(), opaque_payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_ipv4_ah_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& inner_payload,
    const std::uint32_t spi,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& icv,
    const std::uint16_t flags_fragment
) {
    auto payload = make_ah_header(next_header, spi, sequence_number, icv);
    payload.insert(payload.end(), inner_payload.begin(), inner_payload.end());
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolAh,
        flags_fragment,
        payload
    );
}

std::vector<std::uint8_t> make_ethernet_ipv6_ah_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& inner_payload,
    const std::uint32_t spi,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& icv
) {
    auto payload = make_ah_header(next_header, spi, sequence_number, icv);
    payload.insert(payload.end(), inner_payload.begin(), inner_payload.end());
    return make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolAh,
        payload
    );
}

std::vector<std::uint8_t> make_ethernet_ipv4_esp_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint32_t spi,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& opaque_payload,
    const std::uint16_t flags_fragment
) {
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolEsp,
        flags_fragment,
        make_esp_header(spi, sequence_number, opaque_payload)
    );
}

std::vector<std::uint8_t> make_ethernet_ipv6_esp_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    const std::uint32_t spi,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& opaque_payload
) {
    return make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolEsp,
        make_esp_header(spi, sequence_number, opaque_payload)
    );
}

std::vector<std::uint8_t> make_ipv4_payload_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint8_t protocol,
    const std::vector<std::uint8_t>& payload,
    const std::uint16_t flags_fragment,
    const std::uint8_t ttl
) {
    return strip_ethernet_header(make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        protocol,
        flags_fragment,
        payload,
        ttl
    ));
}

std::vector<std::uint8_t> make_ipv6_payload_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        0x60U, 0x00U, 0x00U, 0x00U,
    };
    append_be16(bytes, static_cast<std::uint16_t>(payload.size()));
    bytes.push_back(next_header);
    bytes.push_back(64U);
    bytes.insert(bytes.end(), src_addr.begin(), src_addr.end());
    bytes.insert(bytes.end(), dst_addr.begin(), dst_addr.end());
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_igmp_message(
    const std::uint8_t type,
    const std::uint8_t code,
    const std::uint16_t checksum,
    const std::uint32_t group_or_control,
    const std::vector<std::uint8_t>& body
) {
    std::vector<std::uint8_t> bytes {};
    bytes.push_back(type);
    bytes.push_back(code);
    append_be16(bytes, checksum);
    append_be32(bytes, group_or_control);
    bytes.insert(bytes.end(), body.begin(), body.end());
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_ipv4_igmp_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint8_t type,
    const std::uint8_t code,
    const std::uint16_t checksum,
    const std::uint32_t group_or_control,
    const std::vector<std::uint8_t>& body
) {
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolIgmp,
        0U,
        make_igmp_message(type, code, checksum, group_or_control, body)
    );
}

std::vector<std::uint8_t> make_ipv6_tcp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint16_t payload_length,
    const std::uint8_t flags
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be32(bytes, 0x01020304U);
    append_be32(bytes, 0x05060708U);
    bytes.push_back(0x50U);
    bytes.push_back(flags);
    append_be16(bytes, 0x4000U);
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    for (std::uint16_t index = 0U; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(0x41U + (index % 26U)));
    }
    return bytes;
}

std::vector<std::uint8_t> make_ipv4_tcp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint16_t payload_length,
    const std::uint8_t flags
) {
    return make_ipv6_tcp_segment(src_port, dst_port, payload_length, flags);
}

std::vector<std::uint8_t> make_ipv4_udp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint16_t payload_length
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be16(bytes, static_cast<std::uint16_t>(8U + payload_length));
    append_be16(bytes, 0U);
    for (std::uint16_t index = 0U; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(0x61U + (index % 26U)));
    }
    return bytes;
}

std::vector<std::uint8_t> make_ipv6_routing_extension(
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        next_header,
        0U,
        0U,
        0U,
        0U,
        0U,
        0U,
        0U,
    };
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_ipv6_destination_options_extension(
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
) {
    return make_ipv6_routing_extension(next_header, payload);
}

}  // namespace pfl::tests::common_direct_test
