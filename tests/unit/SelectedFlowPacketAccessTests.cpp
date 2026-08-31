#include <algorithm>
#include <filesystem>
#include <fstream>
#include <utility>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/SelectedFlowPacketAccess.h"
#include "app/session/SessionFlowHelpers.h"
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

detail::CaptureIndexStableHeader make_v16_test_header() {
    return detail::CaptureIndexStableHeader {
        .magic = kStableCaptureIndexMagic,
        .container_format_version = kCaptureIndexStableContainerFormatVersion,
        .header_flags = 0U,
        .header_size = 0U,
        .index_revision = kCaptureIndexStableV16Revision,
        .writer_application_version = "0.3.0-test",
        .source_format = CaptureSourceFormat::classic_pcap,
        .source_file_size = 4096U,
        .source_last_write_time = 0,
        .source_content_fingerprint = 0x12345678ULL,
        .source_capture_path_utf8 = "selected-flow-provider-test.pcap",
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
    const std::filesystem::path& index_path
) {
    const auto fast_tier = make_v16_fast_tier(state);
    const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
    PFL_REQUIRE(static_cast<bool>(plan_result));

    std::ofstream stream(index_path, std::ios::binary | std::ios::trunc);
    PFL_REQUIRE(stream.is_open());
    PFL_REQUIRE(detail::write_v16_fast_statistics_tier(stream, make_v16_test_header(), fast_tier));
    PFL_REQUIRE(detail::write_v16_metadata_tier_sections(stream, plan_result.plan.metadata));
    PFL_REQUIRE(detail::write_v16_packetref_detail_sections(stream, plan_result.plan.packetref_detail_sections));
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
        PFL_EXPECT(source.total_requested_packets() < merged.total_packet_count);
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
}

}  // namespace pfl::tests
