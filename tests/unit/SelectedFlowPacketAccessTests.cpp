#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "app/session/SelectedFlowPacketAccess.h"
#include "app/session/SessionFlowHelpers.h"
#include "app/session/SessionQuicPresentation.h"
#include "core/index/Serialization.h"

namespace pfl::tests {

namespace {

PacketRef make_packet_ref(
    const std::uint64_t packet_index,
    const std::uint64_t timestamp_us,
    const std::uint32_t original_length,
    const std::uint64_t byte_offset
) {
    return PacketRef {
        .packet_index = packet_index,
        .ts_sec = static_cast<std::uint32_t>(timestamp_us / 1000000ULL),
        .ts_usec = static_cast<std::uint32_t>(timestamp_us % 1000000ULL),
        .byte_offset = byte_offset,
        .data_link_type = kLinkTypeEthernet,
        .captured_length = original_length,
        .original_length = original_length,
    };
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

void append_quic_varint(std::vector<std::uint8_t>& bytes, const std::uint64_t value) {
    if (value < 64U) {
        bytes.push_back(static_cast<std::uint8_t>(value));
        return;
    }

    PFL_REQUIRE(value < 16384U);
    bytes.push_back(static_cast<std::uint8_t>(0x40U | ((value >> 8U) & 0x3FU)));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::vector<std::uint8_t> concat_bytes(
    const std::vector<std::uint8_t>& first,
    const std::vector<std::uint8_t>& second
) {
    std::vector<std::uint8_t> combined {};
    combined.reserve(first.size() + second.size());
    combined.insert(combined.end(), first.begin(), first.end());
    combined.insert(combined.end(), second.begin(), second.end());
    return combined;
}

std::vector<std::uint8_t> make_plaintext_quic_initial_payload(const std::vector<std::uint8_t>& frame_bytes) {
    std::vector<std::uint8_t> payload {
        0xC0U,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x08U,
        0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
        0x08U,
        0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U,
        0x00U,
    };

    append_quic_varint(payload, frame_bytes.size() + 1U);
    payload.push_back(0x00U);
    payload.insert(payload.end(), frame_bytes.begin(), frame_bytes.end());
    return payload;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes(
    const std::uint64_t crypto_offset,
    const std::vector<std::uint8_t>& crypto_bytes
) {
    std::vector<std::uint8_t> frame {0x06U};
    append_quic_varint(frame, crypto_offset);
    append_quic_varint(frame, crypto_bytes.size());
    frame.insert(frame.end(), crypto_bytes.begin(), crypto_bytes.end());
    return frame;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes(const std::vector<std::uint8_t>& crypto_bytes) {
    return make_quic_crypto_frame_bytes(0U, crypto_bytes);
}

std::vector<std::uint8_t> make_quic_ack_frame_bytes() {
    return {0x02U, 0x00U, 0x00U, 0x00U, 0x00U};
}

std::vector<std::uint8_t> make_tls_client_hello_handshake_bytes() {
    const std::vector<std::uint8_t> server_name {'s', 't', 'a', 'g', 'e', '1', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'};

    std::vector<std::uint8_t> sni_extension_data {};
    append_be16(sni_extension_data, static_cast<std::uint16_t>(server_name.size() + 3U));
    sni_extension_data.push_back(0x00U);
    append_be16(sni_extension_data, static_cast<std::uint16_t>(server_name.size()));
    sni_extension_data.insert(sni_extension_data.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> supported_versions_extension_data {0x02U, 0x03U, 0x04U};

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x0000U);
    append_be16(extensions, static_cast<std::uint16_t>(sni_extension_data.size()));
    extensions.insert(extensions.end(), sni_extension_data.begin(), sni_extension_data.end());
    append_be16(extensions, 0x002BU);
    append_be16(extensions, static_cast<std::uint16_t>(supported_versions_extension_data.size()));
    extensions.insert(extensions.end(), supported_versions_extension_data.begin(), supported_versions_extension_data.end());

    std::vector<std::uint8_t> body {};
    body.push_back(0x03U);
    body.push_back(0x03U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(static_cast<std::uint8_t>(0x20U + index));
    }
    body.push_back(0x00U);
    append_be16(body, 0x0002U);
    append_be16(body, 0x1301U);
    body.push_back(0x01U);
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake {0x01U};
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

std::vector<std::uint8_t> make_tls_server_hello_handshake_bytes() {
    std::vector<std::uint8_t> body {};
    append_be16(body, 0x0303U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(static_cast<std::uint8_t>(0xA0U + index));
    }
    body.push_back(0x00U);
    append_be16(body, 0x1301U);
    body.push_back(0x00U);

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x002BU);
    append_be16(extensions, 0x0002U);
    extensions.push_back(0x03U);
    extensions.push_back(0x04U);

    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake {0x02U};
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

FlowKeyV4 reverse_flow_key(const FlowKeyV4& key) {
    return FlowKeyV4 {
        .src_addr = key.dst_addr,
        .dst_addr = key.src_addr,
        .src_port = key.dst_port,
        .dst_port = key.src_port,
        .protocol = key.protocol,
        .protocol_path_id = key.protocol_path_id,
    };
}

CaptureState build_selected_flow_packet_access_state() {
    CaptureState state {};
    const auto path_id = state.protocol_path_registry.intern(ProtocolPath {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    });
    PFL_REQUIRE(path_id != kInvalidProtocolPathId);

    const FlowKeyV4 flow_key {
        .src_addr = ipv4(192, 0, 2, 10),
        .dst_addr = ipv4(198, 51, 100, 20),
        .src_port = 41000U,
        .dst_port = 443U,
        .protocol = ProtocolId::tcp,
        .protocol_path_id = path_id,
    };
    auto& connection = state.ipv4_connections.get_or_create(make_connection_key(flow_key));
    connection.key = make_connection_key(flow_key);

    const std::vector<PacketRef> packets {
        make_packet_ref(10U, 1'000'000U, 100U, 1000U),
        make_packet_ref(20U, 1'100'000U, 90U, 2000U),
        make_packet_ref(30U, 1'200'000U, 120U, 3000U),
        make_packet_ref(40U, 1'300'000U, 80U, 4000U),
    };

    connection.add_packet(flow_key, packets[0]);
    connection.add_packet(reverse_flow_key(flow_key), packets[1]);
    connection.add_packet(flow_key, packets[2]);
    connection.add_packet(reverse_flow_key(flow_key), packets[3]);

    for (const auto& packet : packets) {
        observe_capture_packet_statistics(state.packet_statistics, packet, true);
    }

    return state;
}

detail::CaptureIndexStableHeader make_v16_test_header(
    std::string source_capture_path_utf8 = "selected-flow-provider-test.pcap"
) {
    return detail::CaptureIndexStableHeader {
        .magic = kStableCaptureIndexMagic,
        .container_format_version = kCaptureIndexStableContainerFormatVersion,
        .header_flags = 0U,
        .header_size = 0U,
        .index_revision = kCaptureIndexStableIndexRevision,
        .writer_application_version = "0.3.0-test",
        .source_format = CaptureSourceFormat::classic_pcap,
        .source_file_size = 4096U,
        .source_last_write_time = 0,
        .source_content_fingerprint = 0x12345678ULL,
        .source_capture_path_utf8 = std::move(source_capture_path_utf8),
    };
}

detail::CaptureIndexV16FastStatisticsTier make_v16_fast_tier(const CaptureState& state) {
    const auto connections = session_detail::list_connections(state);
    const auto general_statistics = session_detail::build_capture_general_statistics(connections);
    return detail::CaptureIndexV16FastStatisticsTier {
        .capture_statistics_snapshot = session_detail::make_capture_statistics_snapshot(
            state.packet_statistics,
            general_statistics,
            CaptureStatisticsScope::complete),
        .protocol_path_registry = state.protocol_path_registry,
        .protocol_path_display_statistics =
            session_detail::build_protocol_path_display_statistics(state, connections),
    };
}

CaptureIndexV16MetadataTier write_and_read_v16_metadata(
    const CaptureState& state,
    const std::filesystem::path& index_path,
    std::string source_capture_path_utf8 = "selected-flow-provider-test.pcap"
) {
    const auto fast_tier = make_v16_fast_tier(state);
    const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
    PFL_REQUIRE(static_cast<bool>(plan_result));

    std::ofstream stream(index_path, std::ios::binary | std::ios::trunc);
    PFL_REQUIRE(stream.is_open());
    PFL_REQUIRE(detail::write_v16_fast_statistics_tier(
        stream,
        make_v16_test_header(std::move(source_capture_path_utf8)),
        fast_tier
    ));
    PFL_REQUIRE(detail::write_v16_metadata_tier_sections(stream, plan_result.plan));
    PFL_REQUIRE(detail::write_v16_packetref_detail_sections(stream, plan_result.plan.packetref_detail_sections));
    PFL_REQUIRE(detail::write_v16_unrecognized_reason_sections(stream, plan_result.plan.unrecognized_reason_sections));
    PFL_REQUIRE(detail::write_v16_packet_locator_sections(
        stream,
        plan_result.plan.packet_locator_sections,
        plan_result.plan.packet_locator_entries
    ));
    stream.close();

    std::ifstream read_stream(index_path, std::ios::binary);
    PFL_REQUIRE(read_stream.is_open());
    CaptureIndexV16MetadataTier metadata {};
    PFL_REQUIRE(static_cast<bool>(detail::read_v16_metadata_tier(read_stream, metadata)));
    return metadata;
}

void expect_packet_sequence(
    const std::vector<PacketRef>& actual,
    const std::vector<PacketRef>& expected
) {
    PFL_REQUIRE(actual.size() == expected.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        PFL_EXPECT(actual[index] == expected[index]);
    }
}

class CountingSelectedFlowPacketAccessSource final : public session_detail::SelectedFlowPacketAccessSource {
public:
    CountingSelectedFlowPacketAccessSource(
        std::vector<PacketRef> packets_a,
        std::vector<PacketRef> packets_b
    )
        : packets_a_(std::move(packets_a)),
          packets_b_(std::move(packets_b)) {}

    [[nodiscard]] session_detail::SelectedFlowDirectionalPacketCountResult directional_packet_count(
        const Direction direction
    ) const override {
        return session_detail::SelectedFlowDirectionalPacketCountResult {
            .packet_count = direction == Direction::a_to_b
                ? static_cast<std::uint64_t>(packets_a_.size())
                : static_cast<std::uint64_t>(packets_b_.size()),
        };
    }

    [[nodiscard]] session_detail::SelectedFlowDirectionalPacketReadResult read_direction(
        const Direction direction,
        const std::uint64_t local_offset,
        const std::uint64_t limit
    ) const override {
        ++read_call_count_;
        total_requested_packets_ += limit;

        const auto& packets = direction == Direction::a_to_b ? packets_a_ : packets_b_;
        if (local_offset > packets.size()) {
            return session_detail::SelectedFlowDirectionalPacketReadResult {
                .status = session_detail::SelectedFlowPacketAccessStatus::invalid_local_offset,
            };
        }

        const auto available = static_cast<std::uint64_t>(packets.size()) - local_offset;
        const auto begin = packets.begin() + static_cast<std::ptrdiff_t>(local_offset);
        const auto end = begin + static_cast<std::ptrdiff_t>(std::min(limit, available));
        return session_detail::SelectedFlowDirectionalPacketReadResult {
            .packet_refs = std::vector<PacketRef>(begin, end),
        };
    }

    [[nodiscard]] std::size_t read_call_count() const noexcept {
        return read_call_count_;
    }

    [[nodiscard]] std::uint64_t total_requested_packets() const noexcept {
        return total_requested_packets_;
    }

private:
    std::vector<PacketRef> packets_a_ {};
    std::vector<PacketRef> packets_b_ {};
    mutable std::size_t read_call_count_ {0};
    mutable std::uint64_t total_requested_packets_ {0};
};

struct SyntheticDirectionalSequence {
    std::uint64_t packet_count {0};
    std::uint64_t first_packet_index {0};
    std::uint64_t packet_index_stride {1};
};

struct SyntheticDirectionalReadCall {
    Direction direction {Direction::a_to_b};
    std::uint64_t local_offset {0};
    std::uint64_t limit {0};
};

class SyntheticCountingSelectedFlowPacketAccessSource final : public session_detail::SelectedFlowPacketAccessSource {
public:
    SyntheticCountingSelectedFlowPacketAccessSource(
        SyntheticDirectionalSequence sequence_a,
        SyntheticDirectionalSequence sequence_b
    )
        : sequence_a_(sequence_a),
          sequence_b_(sequence_b) {}

    [[nodiscard]] session_detail::SelectedFlowDirectionalPacketCountResult directional_packet_count(
        const Direction direction
    ) const override {
        return session_detail::SelectedFlowDirectionalPacketCountResult {
            .packet_count = sequence(direction).packet_count,
        };
    }

    [[nodiscard]] session_detail::SelectedFlowDirectionalPacketReadResult read_direction(
        const Direction direction,
        const std::uint64_t local_offset,
        const std::uint64_t limit
    ) const override {
        read_calls_.push_back(SyntheticDirectionalReadCall {
            .direction = direction,
            .local_offset = local_offset,
            .limit = limit,
        });
        total_requested_packets_ += limit;

        const auto& spec = sequence(direction);
        if (local_offset > spec.packet_count) {
            return session_detail::SelectedFlowDirectionalPacketReadResult {
                .status = session_detail::SelectedFlowPacketAccessStatus::invalid_local_offset,
            };
        }

        const auto available = spec.packet_count - local_offset;
        const auto count_to_read = std::min(limit, available);
        std::vector<PacketRef> packets {};
        packets.reserve(static_cast<std::size_t>(count_to_read));
        for (std::uint64_t index = 0U; index < count_to_read; ++index) {
            const auto sequence_offset = local_offset + index;
            const auto packet_index =
                spec.first_packet_index + (sequence_offset * spec.packet_index_stride);
            packets.push_back(make_packet_ref(
                packet_index,
                1'000'000U + packet_index,
                64U,
                packet_index * 128U
            ));
        }

        return session_detail::SelectedFlowDirectionalPacketReadResult {
            .packet_refs = std::move(packets),
        };
    }

    [[nodiscard]] std::size_t read_call_count() const noexcept {
        return read_calls_.size();
    }

    [[nodiscard]] std::uint64_t total_requested_packets() const noexcept {
        return total_requested_packets_;
    }

    [[nodiscard]] const std::vector<SyntheticDirectionalReadCall>& read_calls() const noexcept {
        return read_calls_;
    }

private:
    [[nodiscard]] const SyntheticDirectionalSequence& sequence(const Direction direction) const noexcept {
        return direction == Direction::a_to_b ? sequence_a_ : sequence_b_;
    }

    SyntheticDirectionalSequence sequence_a_ {};
    SyntheticDirectionalSequence sequence_b_ {};
    mutable std::vector<SyntheticDirectionalReadCall> read_calls_ {};
    mutable std::uint64_t total_requested_packets_ {0};
};

[[nodiscard]] bool has_small_offset_prefix_walk(
    const SyntheticCountingSelectedFlowPacketAccessSource& source,
    const std::uint64_t offset_ceiling
) {
    return std::any_of(
        source.read_calls().begin(),
        source.read_calls().end(),
        [offset_ceiling](const SyntheticDirectionalReadCall& call) {
            return call.local_offset > 0U && call.local_offset < offset_ceiling;
        }
    );
}

std::filesystem::path write_quic_directional_context_capture() {
    const auto server_hello_bytes = make_tls_server_hello_handshake_bytes();
    const auto split_offset = server_hello_bytes.size() / 2U;
    const std::vector<std::uint8_t> server_hello_prefix(
        server_hello_bytes.begin(),
        server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset));
    const std::vector<std::uint8_t> server_hello_suffix(
        server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset),
        server_hello_bytes.end());

    return write_temp_pcap(
        "pfl_selected_flow_quic_provider_directional_context.pcap",
        make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
            {
                100U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 41, 3, 1),
                    ipv4(10, 41, 3, 2),
                    54020,
                    443,
                    make_plaintext_quic_initial_payload(
                        make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())))
            },
            {
                200U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 41, 3, 2),
                    ipv4(10, 41, 3, 1),
                    443,
                    54020,
                    make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(server_hello_prefix)))
            },
            {
                300U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 41, 3, 2),
                    ipv4(10, 41, 3, 1),
                    443,
                    54020,
                    make_plaintext_quic_initial_payload(concat_bytes(
                        make_quic_crypto_frame_bytes(static_cast<std::uint64_t>(split_offset), server_hello_suffix),
                        make_quic_ack_frame_bytes())))
            },
        })
    );
}

std::filesystem::path write_quic_bounded_access_capture(const std::size_t packet_count) {
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {};
    packets.reserve(packet_count);
    for (std::uint32_t packet_index = 0U; packet_index < packet_count; ++packet_index) {
        packets.push_back({
            1000U + packet_index,
            make_ethernet_ipv4_udp_packet_with_bytes_payload(
                ipv4(10, 42, 1, 1),
                ipv4(10, 42, 1, 2),
                54060,
                443,
                make_plaintext_quic_initial_payload(make_quic_ack_frame_bytes()))
        });
    }

    return write_temp_pcap(
        "pfl_selected_flow_quic_provider_bounded_access.pcap",
        make_classic_pcap(packets)
    );
}

std::filesystem::path write_interleaved_quic_ownership_capture() {
    return write_temp_pcap(
        "pfl_selected_flow_quic_provider_ownership_interleaved.pcap",
        make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
            {
                100U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 43, 1, 1),
                    ipv4(10, 43, 1, 2),
                    54070,
                    443,
                    make_plaintext_quic_initial_payload(
                        make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())))
            },
            {
                200U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 43, 2, 1),
                    ipv4(10, 43, 2, 2),
                    54071,
                    443,
                    make_plaintext_quic_initial_payload(
                        make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())))
            },
            {
                300U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 43, 1, 2),
                    ipv4(10, 43, 1, 1),
                    443,
                    54070,
                    make_plaintext_quic_initial_payload(make_quic_ack_frame_bytes()))
            },
            {
                400U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 43, 2, 2),
                    ipv4(10, 43, 2, 1),
                    443,
                    54071,
                    make_plaintext_quic_initial_payload(make_quic_ack_frame_bytes()))
            },
        })
    );
}

std::span<const std::uint8_t> optional_bytes_span(const std::optional<std::vector<std::uint8_t>>& bytes) {
    return bytes.has_value()
        ? std::span<const std::uint8_t>(bytes->data(), bytes->size())
        : std::span<const std::uint8_t> {};
}

void expect_equal_quic_presentation(
    const session_detail::QuicPresentationResult& actual,
    const session_detail::QuicPresentationResult& expected
) {
    PFL_EXPECT(actual.shell_type == expected.shell_type);
    PFL_EXPECT(actual.shell.header_form == expected.shell.header_form);
    PFL_EXPECT(actual.shell.dcid == expected.shell.dcid);
    PFL_EXPECT(actual.shell.scid == expected.shell.scid);
    PFL_EXPECT(actual.selected_packet_indices == expected.selected_packet_indices);
    PFL_EXPECT(actual.additional_shell_types == expected.additional_shell_types);
    PFL_EXPECT(actual.sni == expected.sni);
    PFL_EXPECT(actual.crypto_packet_indices == expected.crypto_packet_indices);
    PFL_EXPECT(actual.used_bounded_crypto_assembly == expected.used_bounded_crypto_assembly);
    PFL_EXPECT(actual.selected_initial_plaintext_payload == expected.selected_initial_plaintext_payload);
    PFL_EXPECT(actual.selected_initial_plaintext_packet_index == expected.selected_initial_plaintext_packet_index);
    PFL_EXPECT(actual.packets.size() == expected.packets.size());
    for (std::size_t index = 0U; index < expected.packets.size(); ++index) {
        PFL_EXPECT(actual.packets[index].shell_type == expected.packets[index].shell_type);
        PFL_EXPECT(actual.packets[index].shell.header_form == expected.packets[index].shell.header_form);
        PFL_EXPECT(actual.packets[index].frames.size() == expected.packets[index].frames.size());
        PFL_EXPECT(actual.packets[index].tls_handshakes.size() == expected.packets[index].tls_handshakes.size());
        PFL_EXPECT(actual.packets[index].has_authenticated_initial_plaintext == expected.packets[index].has_authenticated_initial_plaintext);
        PFL_EXPECT(actual.packets[index].sni == expected.packets[index].sni);
    }

    PFL_EXPECT(actual.tls_handshake.has_value() == expected.tls_handshake.has_value());
    if (actual.tls_handshake.has_value() && expected.tls_handshake.has_value()) {
        PFL_EXPECT(actual.tls_handshake->handshake_type == expected.tls_handshake->handshake_type);
        PFL_EXPECT(actual.tls_handshake->handshake_type_text == expected.tls_handshake->handshake_type_text);
        PFL_EXPECT(actual.tls_handshake->handshake_length == expected.tls_handshake->handshake_length);
        PFL_EXPECT(actual.tls_handshake->details_text == expected.tls_handshake->details_text);
    }
}

}  // namespace

void run_selected_flow_packet_access_tests() {
    {
        ScopedTestContext context {"resident_provider_preserves_directional_and_merged_semantics"};

        const auto packet_a1 = make_packet_ref(10U, 1'000'000U, 80U, 1000U);
        const auto packet_a2 = make_packet_ref(30U, 1'200'000U, 82U, 3000U);
        const auto packet_b1 = make_packet_ref(20U, 1'100'000U, 81U, 2000U);
        const std::vector<PacketRef> packets_a {packet_a1, packet_a2};
        const std::vector<PacketRef> packets_b {packet_b1};
        const session_detail::ResidentSelectedFlowPacketAccessSource source(
            std::span<const PacketRef>(packets_a.data(), packets_a.size()),
            2U,
            std::span<const PacketRef>(packets_b.data(), packets_b.size()),
            1U
        );

        const auto count_a = source.directional_packet_count(Direction::a_to_b);
        const auto count_b = source.directional_packet_count(Direction::b_to_a);
        PFL_REQUIRE(static_cast<bool>(count_a));
        PFL_REQUIRE(static_cast<bool>(count_b));
        PFL_EXPECT(count_a.packet_count == 2U);
        PFL_EXPECT(count_b.packet_count == 1U);

        const auto read_a = source.read_direction(Direction::a_to_b, 1U, 5U);
        const auto read_b = source.read_direction(Direction::b_to_a, 0U, 1U);
        PFL_REQUIRE(static_cast<bool>(read_a));
        PFL_REQUIRE(static_cast<bool>(read_b));
        expect_packet_sequence(read_a.packet_refs, {packet_a2});
        expect_packet_sequence(read_b.packet_refs, {packet_b1});

        const auto merged = session_detail::read_selected_flow_merged_range(source, 1U, 2U);
        PFL_REQUIRE(static_cast<bool>(merged));
        PFL_EXPECT(merged.total_packet_count == 3U);
        PFL_REQUIRE(merged.packets.size() == 2U);
        PFL_EXPECT(merged.packets[0].packet == packet_b1);
        PFL_EXPECT(merged.packets[0].direction == Direction::b_to_a);
        PFL_EXPECT(merged.packets[0].flow_local_packet_number == 2U);
        PFL_EXPECT(merged.packets[1].packet == packet_a2);
        PFL_EXPECT(merged.packets[1].direction == Direction::a_to_b);
        PFL_EXPECT(merged.packets[1].flow_local_packet_number == 3U);

        const auto packet_lookup = session_detail::selected_flow_packet_at(source, 2U);
        PFL_REQUIRE(static_cast<bool>(packet_lookup));
        PFL_REQUIRE(packet_lookup.packet.has_value());
        PFL_EXPECT(packet_lookup.packet->packet == packet_b1);
        PFL_EXPECT(packet_lookup.packet->direction == Direction::b_to_a);
        PFL_EXPECT(packet_lookup.packet->flow_local_packet_number == 2U);

        const auto context_lookup = session_detail::selected_flow_packet_context_for_packet_index(source, 30U);
        PFL_REQUIRE(static_cast<bool>(context_lookup));
        PFL_REQUIRE(context_lookup.packet.has_value());
        PFL_EXPECT(context_lookup.packet->packet == packet_a2);
        PFL_EXPECT(context_lookup.packet->direction == Direction::a_to_b);
        PFL_EXPECT(context_lookup.packet->flow_local_packet_number == 3U);
    }

    {
        ScopedTestContext context {"merged_reader_remains_bounded_for_small_window_requests"};

        std::vector<PacketRef> packets_a {};
        std::vector<PacketRef> packets_b {};
        packets_a.reserve(100U);
        packets_b.reserve(100U);
        for (std::uint64_t index = 0U; index < 100U; ++index) {
            packets_a.push_back(make_packet_ref(index * 2U, 1'000'000U + index, 64U, index * 128U));
            packets_b.push_back(make_packet_ref((index * 2U) + 1U, 1'000'500U + index, 64U, (index * 128U) + 64U));
        }

        CountingSelectedFlowPacketAccessSource source(std::move(packets_a), std::move(packets_b));
        const auto merged = session_detail::read_selected_flow_merged_range(source, 10U, 3U);
        PFL_REQUIRE(static_cast<bool>(merged));
        PFL_EXPECT(merged.total_packet_count == 200U);
        PFL_REQUIRE(merged.packets.size() == 3U);
        PFL_EXPECT(merged.packets[0].packet.packet_index == 10U);
        PFL_EXPECT(merged.packets[1].packet.packet_index == 11U);
        PFL_EXPECT(merged.packets[2].packet.packet_index == 12U);
        PFL_EXPECT(source.read_call_count() > 0U);
        PFL_EXPECT(source.total_requested_packets() < 512U);
    }

    {
        ScopedTestContext context {"late_selected_flow_packet_lookup_uses_bounded_directional_reads"};

        SyntheticCountingSelectedFlowPacketAccessSource source(
            SyntheticDirectionalSequence {
                .packet_count = 500'000U,
                .first_packet_index = 0U,
                .packet_index_stride = 2U,
            },
            SyntheticDirectionalSequence {
                .packet_count = 500'000U,
                .first_packet_index = 1U,
                .packet_index_stride = 2U,
            }
        );

        const auto lookup = session_detail::selected_flow_packet_at(source, 900'001U);
        PFL_REQUIRE(static_cast<bool>(lookup));
        PFL_REQUIRE(lookup.packet.has_value());
        PFL_EXPECT(lookup.packet->packet.packet_index == 900'000U);
        PFL_EXPECT(lookup.packet->direction == Direction::a_to_b);
        PFL_EXPECT(lookup.packet->flow_local_packet_number == 900'001U);
        PFL_EXPECT(source.read_call_count() <= 160U);
        PFL_EXPECT(source.total_requested_packets() <= 1024U);
        PFL_EXPECT(!has_small_offset_prefix_walk(source, 1000U));
    }

    {
        ScopedTestContext context {"deep_merged_page_lookup_uses_bounded_directional_reads"};

        SyntheticCountingSelectedFlowPacketAccessSource source(
            SyntheticDirectionalSequence {
                .packet_count = 500'000U,
                .first_packet_index = 0U,
                .packet_index_stride = 2U,
            },
            SyntheticDirectionalSequence {
                .packet_count = 500'000U,
                .first_packet_index = 1U,
                .packet_index_stride = 2U,
            }
        );

        const auto merged = session_detail::read_selected_flow_merged_range(source, 900'000U, 30U);
        PFL_REQUIRE(static_cast<bool>(merged));
        PFL_EXPECT(merged.total_packet_count == 1'000'000U);
        PFL_REQUIRE(merged.packets.size() == 30U);
        for (std::size_t index = 0U; index < merged.packets.size(); ++index) {
            const auto expected_packet_index = 900'000U + static_cast<std::uint64_t>(index);
            PFL_EXPECT(merged.packets[index].packet.packet_index == expected_packet_index);
            PFL_EXPECT(merged.packets[index].direction ==
                (expected_packet_index % 2U == 0U ? Direction::a_to_b : Direction::b_to_a));
            PFL_EXPECT(merged.packets[index].flow_local_packet_number == expected_packet_index + 1U);
        }
        PFL_EXPECT(source.read_call_count() <= 160U);
        PFL_EXPECT(source.total_requested_packets() <= 1024U);
        PFL_EXPECT(!has_small_offset_prefix_walk(source, 1000U));
    }

    {
        ScopedTestContext context {"exact_packet_index_lookup_uses_directional_binary_search"};

        SyntheticCountingSelectedFlowPacketAccessSource source_a(
            SyntheticDirectionalSequence {
                .packet_count = 500'000U,
                .first_packet_index = 0U,
                .packet_index_stride = 2U,
            },
            SyntheticDirectionalSequence {
                .packet_count = 500'000U,
                .first_packet_index = 1U,
                .packet_index_stride = 2U,
            }
        );

        const auto lookup_a = session_detail::selected_flow_packet_context_for_packet_index(source_a, 900'000U);
        PFL_REQUIRE(static_cast<bool>(lookup_a));
        PFL_REQUIRE(lookup_a.packet.has_value());
        PFL_EXPECT(lookup_a.packet->packet.packet_index == 900'000U);
        PFL_EXPECT(lookup_a.packet->direction == Direction::a_to_b);
        PFL_EXPECT(lookup_a.packet->flow_local_packet_number == 900'001U);
        PFL_EXPECT(source_a.read_call_count() <= 160U);
        PFL_EXPECT(source_a.total_requested_packets() <= 512U);
        PFL_EXPECT(!has_small_offset_prefix_walk(source_a, 1000U));

        SyntheticCountingSelectedFlowPacketAccessSource source_b(
            SyntheticDirectionalSequence {
                .packet_count = 500'000U,
                .first_packet_index = 0U,
                .packet_index_stride = 2U,
            },
            SyntheticDirectionalSequence {
                .packet_count = 500'000U,
                .first_packet_index = 1U,
                .packet_index_stride = 2U,
            }
        );

        const auto lookup_b = session_detail::selected_flow_packet_context_for_packet_index(source_b, 900'001U);
        PFL_REQUIRE(static_cast<bool>(lookup_b));
        PFL_REQUIRE(lookup_b.packet.has_value());
        PFL_EXPECT(lookup_b.packet->packet.packet_index == 900'001U);
        PFL_EXPECT(lookup_b.packet->direction == Direction::b_to_a);
        PFL_EXPECT(lookup_b.packet->flow_local_packet_number == 900'002U);
        PFL_EXPECT(source_b.read_call_count() <= 160U);
        PFL_EXPECT(source_b.total_requested_packets() <= 512U);
        PFL_EXPECT(!has_small_offset_prefix_walk(source_b, 1000U));
    }

    {
        ScopedTestContext context {"exact_packet_index_lookup_not_found_stays_bounded"};

        SyntheticCountingSelectedFlowPacketAccessSource source(
            SyntheticDirectionalSequence {
                .packet_count = 100'000U,
                .first_packet_index = 10U,
                .packet_index_stride = 10U,
            },
            SyntheticDirectionalSequence {
                .packet_count = 100'000U,
                .first_packet_index = 15U,
                .packet_index_stride = 10U,
            }
        );

        const auto between = session_detail::selected_flow_packet_context_for_packet_index(source, 12U);
        PFL_REQUIRE(static_cast<bool>(between));
        PFL_EXPECT(!between.packet.has_value());

        const auto before_first = session_detail::selected_flow_packet_context_for_packet_index(source, 1U);
        PFL_REQUIRE(static_cast<bool>(before_first));
        PFL_EXPECT(!before_first.packet.has_value());

        const auto after_last = session_detail::selected_flow_packet_context_for_packet_index(source, 2'000'000U);
        PFL_REQUIRE(static_cast<bool>(after_last));
        PFL_EXPECT(!after_last.packet.has_value());

        PFL_EXPECT(source.read_call_count() <= 240U);
        PFL_EXPECT(source.total_requested_packets() <= 768U);
    }

    {
        ScopedTestContext context {"merged_reader_handles_directional_edge_cases"};

        {
            SyntheticCountingSelectedFlowPacketAccessSource source(
                SyntheticDirectionalSequence {
                    .packet_count = 1000U,
                    .first_packet_index = 0U,
                    .packet_index_stride = 1U,
                },
                SyntheticDirectionalSequence {}
            );
            const auto merged = session_detail::read_selected_flow_merged_range(source, 990U, 5U);
            PFL_REQUIRE(static_cast<bool>(merged));
            PFL_REQUIRE(merged.packets.size() == 5U);
            PFL_EXPECT(merged.packets.front().packet.packet_index == 990U);
            PFL_EXPECT(merged.packets.front().direction == Direction::a_to_b);
            PFL_EXPECT(merged.packets.front().flow_local_packet_number == 991U);
            PFL_EXPECT(source.read_call_count() <= 80U);
        }

        {
            SyntheticCountingSelectedFlowPacketAccessSource source(
                SyntheticDirectionalSequence {},
                SyntheticDirectionalSequence {
                    .packet_count = 1000U,
                    .first_packet_index = 0U,
                    .packet_index_stride = 1U,
                }
            );
            const auto merged = session_detail::read_selected_flow_merged_range(source, 990U, 5U);
            PFL_REQUIRE(static_cast<bool>(merged));
            PFL_REQUIRE(merged.packets.size() == 5U);
            PFL_EXPECT(merged.packets.front().packet.packet_index == 990U);
            PFL_EXPECT(merged.packets.front().direction == Direction::b_to_a);
            PFL_EXPECT(merged.packets.front().flow_local_packet_number == 991U);
            PFL_EXPECT(source.read_call_count() <= 80U);
        }

        {
            SyntheticCountingSelectedFlowPacketAccessSource source(
                SyntheticDirectionalSequence {
                    .packet_count = 3U,
                    .first_packet_index = 0U,
                    .packet_index_stride = 1U,
                },
                SyntheticDirectionalSequence {
                    .packet_count = 10'000U,
                    .first_packet_index = 1000U,
                    .packet_index_stride = 1U,
                }
            );
            const auto merged = session_detail::read_selected_flow_merged_range(source, 2U, 3U);
            PFL_REQUIRE(static_cast<bool>(merged));
            PFL_REQUIRE(merged.packets.size() == 3U);
            PFL_EXPECT(merged.packets[0].packet.packet_index == 2U);
            PFL_EXPECT(merged.packets[1].packet.packet_index == 1000U);
            PFL_EXPECT(merged.packets[2].packet.packet_index == 1001U);
            PFL_EXPECT(source.read_call_count() <= 80U);
        }

        {
            SyntheticCountingSelectedFlowPacketAccessSource source(
                SyntheticDirectionalSequence {
                    .packet_count = 10'000U,
                    .first_packet_index = 1000U,
                    .packet_index_stride = 1U,
                },
                SyntheticDirectionalSequence {
                    .packet_count = 3U,
                    .first_packet_index = 0U,
                    .packet_index_stride = 1U,
                }
            );
            const auto merged = session_detail::read_selected_flow_merged_range(source, 2U, 3U);
            PFL_REQUIRE(static_cast<bool>(merged));
            PFL_REQUIRE(merged.packets.size() == 3U);
            PFL_EXPECT(merged.packets[0].packet.packet_index == 2U);
            PFL_EXPECT(merged.packets[0].direction == Direction::b_to_a);
            PFL_EXPECT(merged.packets[1].packet.packet_index == 1000U);
            PFL_EXPECT(merged.packets[2].packet.packet_index == 1001U);
            PFL_EXPECT(source.read_call_count() <= 80U);
        }
    }

    {
        ScopedTestContext context {"duplicate_packet_index_across_directions_is_malformed"};

        SyntheticCountingSelectedFlowPacketAccessSource exact_source(
            SyntheticDirectionalSequence {
                .packet_count = 10U,
                .first_packet_index = 0U,
                .packet_index_stride = 2U,
            },
            SyntheticDirectionalSequence {
                .packet_count = 10U,
                .first_packet_index = 4U,
                .packet_index_stride = 2U,
            }
        );
        const auto exact_lookup =
            session_detail::selected_flow_packet_context_for_packet_index(exact_source, 4U);
        PFL_EXPECT(!static_cast<bool>(exact_lookup));
        PFL_EXPECT(exact_lookup.status == session_detail::SelectedFlowPacketAccessStatus::malformed_packetref);

        SyntheticCountingSelectedFlowPacketAccessSource merged_source(
            SyntheticDirectionalSequence {
                .packet_count = 10U,
                .first_packet_index = 0U,
                .packet_index_stride = 2U,
            },
            SyntheticDirectionalSequence {
                .packet_count = 10U,
                .first_packet_index = 4U,
                .packet_index_stride = 2U,
            }
        );
        const auto merged = session_detail::read_selected_flow_merged_range(merged_source, 2U, 2U);
        PFL_EXPECT(!static_cast<bool>(merged));
        PFL_EXPECT(merged.status == session_detail::SelectedFlowPacketAccessStatus::malformed_packetref);
    }

    {
        ScopedTestContext context {"v16_provider_matches_resident_provider"};

        const auto state = build_selected_flow_packet_access_state();
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_selected_flow_packet_access_v16.idx";
        const auto metadata = write_and_read_v16_metadata(state, index_path);

        const auto ipv4_connections = state.ipv4_connections.list();
        PFL_REQUIRE(ipv4_connections.size() == 1U);
        PFL_REQUIRE(!metadata.ipv4_connections.empty());

        const auto canonical_ordinal = metadata.ipv4_connections.front().canonical_connection_ordinal;
        const session_detail::ResidentSelectedFlowPacketAccessSource resident_source(*ipv4_connections.front());
        const session_detail::CaptureIndexV16SelectedFlowPacketAccessSource v16_source(
            index_path,
            metadata,
            canonical_ordinal
        );

        const auto resident_a = resident_source.read_direction(Direction::a_to_b, 0U, 10U);
        const auto resident_b = resident_source.read_direction(Direction::b_to_a, 0U, 10U);
        const auto v16_a = v16_source.read_direction(Direction::a_to_b, 0U, 10U);
        const auto v16_b = v16_source.read_direction(Direction::b_to_a, 0U, 10U);
        PFL_REQUIRE(static_cast<bool>(resident_a));
        PFL_REQUIRE(static_cast<bool>(resident_b));
        PFL_REQUIRE(static_cast<bool>(v16_a));
        PFL_REQUIRE(static_cast<bool>(v16_b));
        expect_packet_sequence(v16_a.packet_refs, resident_a.packet_refs);
        expect_packet_sequence(v16_b.packet_refs, resident_b.packet_refs);

        const auto resident_merged = session_detail::read_selected_flow_merged_range(resident_source, 0U, 10U);
        const auto v16_merged = session_detail::read_selected_flow_merged_range(v16_source, 0U, 10U);
        PFL_REQUIRE(static_cast<bool>(resident_merged));
        PFL_REQUIRE(static_cast<bool>(v16_merged));
        PFL_EXPECT(v16_merged.total_packet_count == resident_merged.total_packet_count);
        PFL_REQUIRE(v16_merged.packets.size() == resident_merged.packets.size());
        for (std::size_t index = 0; index < resident_merged.packets.size(); ++index) {
            PFL_EXPECT(v16_merged.packets[index].packet == resident_merged.packets[index].packet);
            PFL_EXPECT(v16_merged.packets[index].direction == resident_merged.packets[index].direction);
            PFL_EXPECT(
                v16_merged.packets[index].flow_local_packet_number ==
                resident_merged.packets[index].flow_local_packet_number);
        }
    }

    {
        ScopedTestContext context {"capture_session_v16_selected_flow_exact_packet_context_does_not_require_source_capture"};

        const auto state = build_selected_flow_packet_access_state();
        const auto index_path =
            std::filesystem::temp_directory_path() / "pfl_selected_flow_packet_access_v16_no_source.idx";
        const auto missing_source_path =
            std::filesystem::temp_directory_path() / "pfl_selected_flow_packet_access_missing_source.pcap";
        std::filesystem::remove(missing_source_path);
        static_cast<void>(write_and_read_v16_metadata(state, index_path, missing_source_path.generic_string()));

        CaptureSession session {};
        PFL_REQUIRE(session.load_v16_index_for_testing(index_path));
        PFL_EXPECT(session.opened_from_index());
        PFL_EXPECT(!session.has_source_capture());
        PFL_EXPECT(!session.source_capture_accessible());
        PFL_EXPECT(!session.find_packet(30U).has_value());

        const auto packet_context = session.selected_flow_packet_context_for_packet_index(0U, 30U);
        PFL_REQUIRE(packet_context.has_value());
        PFL_EXPECT(packet_context->packet.packet_index == 30U);
        PFL_EXPECT(packet_context->flow_packet_index == 3U);
        PFL_EXPECT(packet_context->direction == Direction::a_to_b);
        PFL_EXPECT(!session.selected_flow_packet_context_for_packet_index(0U, 999U).has_value());
    }

    {
        ScopedTestContext context {"quic_selected_flow_presentation_matches_v16_provider"};

        const auto capture_path = write_quic_directional_context_capture();
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(capture_path, CaptureImportOptions {}));

        const auto ipv4_connections = session.state().ipv4_connections.list();
        PFL_REQUIRE(ipv4_connections.size() == 1U);

        const auto index_path = std::filesystem::temp_directory_path() / "pfl_selected_flow_quic_provider_v16.idx";
        const auto metadata = write_and_read_v16_metadata(session.state(), index_path);
        PFL_REQUIRE(!metadata.ipv4_connections.empty());

        const auto canonical_ordinal = metadata.ipv4_connections.front().canonical_connection_ordinal;
        const session_detail::ResidentSelectedFlowPacketAccessSource resident_source(*ipv4_connections.front());
        const session_detail::CaptureIndexV16SelectedFlowPacketAccessSource v16_source(
            index_path,
            metadata,
            canonical_ordinal
        );

        const auto resident_cid =
            session_detail::find_quic_client_initial_connection_id_for_packet_source(session, resident_source, 0U);
        const auto v16_cid =
            session_detail::find_quic_client_initial_connection_id_for_packet_source(session, v16_source, 0U);
        PFL_REQUIRE(resident_cid.has_value());
        PFL_REQUIRE(v16_cid.has_value());
        PFL_EXPECT(*resident_cid == *v16_cid);

        const auto resident_client = session_detail::build_quic_presentation_for_selected_direction(
            session,
            ipv4_connections.front()->flow_a.key,
            resident_source,
            Direction::a_to_b,
            std::vector<std::uint64_t> {0U},
            optional_bytes_span(resident_cid),
            0U
        );
        const auto v16_client = session_detail::build_quic_presentation_for_selected_direction(
            session,
            ipv4_connections.front()->flow_a.key,
            v16_source,
            Direction::a_to_b,
            std::vector<std::uint64_t> {0U},
            optional_bytes_span(v16_cid),
            0U
        );
        PFL_REQUIRE(resident_client.has_value());
        PFL_REQUIRE(v16_client.has_value());
        expect_equal_quic_presentation(*v16_client, *resident_client);
        PFL_REQUIRE(v16_client->tls_handshake.has_value());
        PFL_EXPECT(v16_client->tls_handshake->handshake_type_text == "ClientHello");
        PFL_EXPECT(v16_client->sni == std::optional<std::string> {"stage1.example"});

        const auto resident_server = session_detail::build_quic_presentation_for_selected_direction(
            session,
            ipv4_connections.front()->flow_b.key,
            resident_source,
            Direction::b_to_a,
            std::vector<std::uint64_t> {1U, 2U},
            optional_bytes_span(resident_cid),
            0U
        );
        const auto v16_server = session_detail::build_quic_presentation_for_selected_direction(
            session,
            ipv4_connections.front()->flow_b.key,
            v16_source,
            Direction::b_to_a,
            std::vector<std::uint64_t> {1U, 2U},
            optional_bytes_span(v16_cid),
            0U
        );
        PFL_REQUIRE(resident_server.has_value());
        PFL_REQUIRE(v16_server.has_value());
        expect_equal_quic_presentation(*v16_server, *resident_server);
        PFL_REQUIRE(v16_server->tls_handshake.has_value());
        PFL_EXPECT(v16_server->tls_handshake->handshake_type_text == "ServerHello");
        PFL_EXPECT(!v16_server->sni.has_value());
        PFL_EXPECT(v16_server->used_bounded_crypto_assembly);
    }

    {
        ScopedTestContext context {"quic_selected_flow_presentation_reads_stay_bounded"};

        constexpr std::size_t kPacketCount = 200U;
        const auto capture_path = write_quic_bounded_access_capture(kPacketCount);
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(capture_path, CaptureImportOptions {}));

        const auto ipv4_connections = session.state().ipv4_connections.list();
        PFL_REQUIRE(ipv4_connections.size() == 1U);

        CountingSelectedFlowPacketAccessSource source(
            ipv4_connections.front()->flow_a.packets,
            {}
        );
        const auto presentation = session_detail::build_quic_presentation_for_selected_direction(
            session,
            ipv4_connections.front()->flow_a.key,
            source,
            Direction::a_to_b,
            std::vector<std::uint64_t> {30U},
            {},
            0U
        );
        PFL_REQUIRE(presentation.has_value());
        PFL_EXPECT(source.read_call_count() > 0U);
        PFL_EXPECT(source.total_requested_packets() < kPacketCount);
        PFL_EXPECT(!presentation->packets.empty());
    }

    {
        ScopedTestContext context {"quic_selected_flow_presentation_stays_within_requested_flow"};

        const auto capture_path = write_interleaved_quic_ownership_capture();
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(capture_path, CaptureImportOptions {}));

        const auto ipv4_connections = session.state().ipv4_connections.list();
        PFL_REQUIRE(ipv4_connections.size() == 2U);

        const auto* target_connection = ipv4_connections[0];
        const auto* other_connection = ipv4_connections[1];
        CountingSelectedFlowPacketAccessSource source(
            target_connection->flow_a.packets,
            target_connection->flow_b.packets
        );

        const auto own_presentation = session_detail::build_quic_presentation_for_selected_direction(
            session,
            target_connection->flow_a.key,
            source,
            Direction::a_to_b,
            std::vector<std::uint64_t> {target_connection->flow_a.packets.front().packet_index},
            {},
            0U
        );
        PFL_REQUIRE(own_presentation.has_value());

        const auto foreign_presentation = session_detail::build_quic_presentation_for_selected_direction(
            session,
            target_connection->flow_a.key,
            source,
            Direction::a_to_b,
            std::vector<std::uint64_t> {other_connection->flow_a.packets.front().packet_index},
            {},
            0U
        );
        PFL_EXPECT(!foreign_presentation.has_value());
        PFL_EXPECT(source.total_requested_packets() <=
            static_cast<std::uint64_t>(target_connection->flow_a.packets.size() + target_connection->flow_b.packets.size()));
    }
}

}  // namespace pfl::tests
