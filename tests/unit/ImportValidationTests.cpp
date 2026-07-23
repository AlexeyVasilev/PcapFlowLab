#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "tools/import_validation/ImportValidation.h"

namespace pfl::tests {

namespace {

std::filesystem::path write_empty_classic_pcap(const std::string& file_name) {
    return write_temp_pcap(
        file_name,
        make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {})
    );
}

std::filesystem::path write_single_tcp_classic_pcap(const std::string& file_name) {
    return write_temp_pcap(
        file_name,
        make_classic_pcap({
            {
                100U,
                make_ethernet_ipv4_tcp_packet(
                    ipv4(10, 1, 0, 1),
                    ipv4(10, 1, 0, 2),
                    40000U,
                    443U
                ),
            },
        })
    );
}

std::filesystem::path write_single_unrecognized_classic_pcap(const std::string& file_name) {
    return write_temp_pcap(
        file_name,
        make_classic_pcap({
            {
                100U,
                std::vector<std::uint8_t> {0x00U, 0x11U, 0x22U, 0x33U},
            },
        })
    );
}

std::filesystem::path write_single_tcp_pcapng(const std::string& file_name) {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(
        ipv4(10, 2, 0, 1),
        ipv4(10, 2, 0, 2),
        50000U,
        8443U
    );

    return write_temp_pcap(
        file_name,
        make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0U, 1U, 100U, tcp_packet),
        })
    );
}

std::filesystem::path write_staged_prefix_classic_pcap(const std::string& file_name) {
    constexpr std::size_t kMinCapturedLengthForStagedImportBytes = 16U * 1024U;

    std::vector<std::uint8_t> long_hop_by_hop_header {
        17U,
        19U,
    };
    long_hop_by_hop_header.resize(160U, 0x00U);

    auto ipv6_payload = long_hop_by_hop_header;
    const auto udp_segment = make_ipv6_udp_segment(
        53000U,
        443U,
        static_cast<std::uint16_t>(kMinCapturedLengthForStagedImportBytes + 256U)
    );
    ipv6_payload.insert(ipv6_payload.end(), udp_segment.begin(), udp_segment.end());

    const auto large_ipv6_packet = make_ethernet_ipv6_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
        0U,
        ipv6_payload
    );

    return write_temp_pcap(
        file_name,
        make_classic_pcap_with_captured_lengths({
            ClassicPcapCapturedRecord {
                .ts_usec = 100U,
                .captured_bytes = large_ipv6_packet,
                .original_length = static_cast<std::uint32_t>(large_ipv6_packet.size() + 512U),
            },
        })
    );
}

void expect_compare_success_with_exact_parity(
    const std::filesystem::path& capture_path,
    const std::string& context_label
) {
    const ScopedTestContext context {context_label};
    const auto result = compare_import_validation(capture_path);
    PFL_REQUIRE(result.success);
    PFL_EXPECT(result.parity);
    PFL_EXPECT(result.mismatch_count == 0U);
    PFL_EXPECT(result.mismatches.empty());
}

ImportValidationPacketObservation make_ipv4_tcp_observation(
    const std::uint64_t packet_index,
    const std::uint32_t payload_length,
    const ProtocolPath& path,
    const ImportValidationPacketClassification classification = ImportValidationPacketClassification::recognized_flow
) {
    ImportValidationPacketObservation observation {};
    observation.packet_index = packet_index;
    observation.file_offset = packet_index * 100U;
    observation.captured_length = 128U;
    observation.original_length = 128U;
    observation.link_type = kLinkTypeEthernet;
    observation.classification = classification;
    observation.family = dissection::DissectionAddressFamily::ipv4;
    observation.protocol = ProtocolId::tcp;
    observation.has_addresses = true;
    observation.src_addr_v4 = ipv4(10, 0, 0, 1);
    observation.dst_addr_v4 = ipv4(10, 0, 0, 2);
    observation.has_ports = true;
    observation.src_port = 40000U;
    observation.dst_port = 443U;
    observation.has_transport_payload_length = true;
    observation.captured_transport_payload_length = payload_length;
    observation.has_tcp_flags = true;
    observation.tcp_flags = 0x18U;
    observation.physical_path = path;
    observation.final_status = dissection::ParseStatus::complete;
    observation.stop_reason = dissection::StopReason::terminal_protocol;
    return observation;
}

ImportValidationFlowSnapshotV4 make_flow_snapshot(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const ProtocolPath& path
) {
    return ImportValidationFlowSnapshotV4 {
        .key = FlowKeyV4 {
            .src_addr = src_addr,
            .dst_addr = dst_addr,
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = ProtocolId::udp,
        },
        .protocol_path = path,
        .packet_count = 1U,
        .total_bytes = 64U,
    };
}

}  // namespace

void run_import_validation_tests() {
    {
        const ScopedTestContext context {"canonical_states_identical"};
        ImportValidationCanonicalState legacy {};
        legacy.summary.packet_count = 1U;
        legacy.summary.flow_count = 1U;
        legacy.summary.total_bytes = 64U;

        auto unified = legacy;
        const auto result = compare_canonical_states(legacy, unified);
        PFL_REQUIRE(result.success);
        PFL_EXPECT(result.parity);
        PFL_EXPECT(result.mismatch_count == 0U);
        PFL_EXPECT(result.mismatches.empty());
    }

    {
        const ScopedTestContext context {"canonical_states_mismatch_reporting_bounded"};
        ImportValidationCanonicalState legacy {};
        legacy.summary.packet_count = 1U;
        legacy.summary.flow_count = 2U;
        legacy.summary.total_bytes = 3U;

        ImportValidationCanonicalState unified {};
        unified.summary.packet_count = 10U;
        unified.summary.flow_count = 20U;
        unified.summary.total_bytes = 30U;

        const ImportValidationOptions options {
            .max_packets = std::nullopt,
            .include_hints = true,
            .max_reported_mismatches = 1U,
        };
        const auto result = compare_canonical_states(legacy, unified, options);
        PFL_REQUIRE(result.success);
        PFL_EXPECT(!result.parity);
        PFL_EXPECT(result.mismatch_count == 3U);
        PFL_REQUIRE(result.mismatches.size() == 1U);
        PFL_EXPECT(result.mismatches[0].category == ImportValidationMismatchCategory::summary);
        PFL_EXPECT(result.mismatches[0].entity == "summary");
        PFL_EXPECT(result.mismatches[0].field == "packet_count");
        PFL_EXPECT(result.mismatches[0].legacy_value == "1");
        PFL_EXPECT(result.mismatches[0].unified_value == "10");
    }

    {
        const ScopedTestContext context {"packet_payload_mismatches_group_by_signature"};
        const ProtocolPath path {
            LayerKey::ethernet_ii(),
            LayerKey::ipv4(),
            LayerKey::tcp(),
        };
        const std::vector<ImportValidationPacketObservation> legacy {
            make_ipv4_tcp_observation(3876U, 73U, path),
            make_ipv4_tcp_observation(6221U, 1011U, path),
            make_ipv4_tcp_observation(16975U, 304U, path),
        };
        const std::vector<ImportValidationPacketObservation> unified {
            make_ipv4_tcp_observation(3876U, 37U, path),
            make_ipv4_tcp_observation(6221U, 975U, path),
            make_ipv4_tcp_observation(16975U, 268U, path),
        };

        const auto result = compare_packet_observations(legacy, unified);
        PFL_EXPECT(result.mismatch_count == 3U);
        PFL_REQUIRE(result.groups.size() == 1U);
        PFL_EXPECT(result.groups[0].category == ImportValidationPacketMismatchCategory::payload_length);
        PFL_EXPECT(result.groups[0].occurrence_count == 3U);
        PFL_EXPECT(result.groups[0].packet_indices.size() == 3U);
        PFL_EXPECT(result.groups[0].packet_indices[0] == 3876U);
        PFL_EXPECT(result.groups[0].packet_indices[1] == 6221U);
        PFL_EXPECT(result.groups[0].packet_indices[2] == 16975U);
        PFL_REQUIRE(result.groups[0].numeric_delta.has_value());
        PFL_EXPECT(*result.groups[0].numeric_delta == 36);
        PFL_EXPECT(result.first_divergence.any_packet_index == std::optional<std::uint64_t> {3876U});
        PFL_EXPECT(result.first_divergence.payload_length_packet_index == std::optional<std::uint64_t> {3876U});
    }

    {
        const ScopedTestContext context {"packet_index_filter_returns_exact_single_packet"};
        const ProtocolPath path {
            LayerKey::ethernet_ii(),
            LayerKey::ipv4(),
            LayerKey::tcp(),
        };
        const std::vector<ImportValidationPacketObservation> legacy {
            make_ipv4_tcp_observation(0U, 10U, path),
            make_ipv4_tcp_observation(1U, 20U, path, ImportValidationPacketClassification::unrecognized),
        };
        auto second_unified = make_ipv4_tcp_observation(1U, 20U, path);
        second_unified.classification = ImportValidationPacketClassification::recognized_flow;
        const std::vector<ImportValidationPacketObservation> unified {
            make_ipv4_tcp_observation(0U, 10U, path),
            second_unified,
        };
        const ImportValidationOptions options {
            .max_packets = std::nullopt,
            .packet_index = 1U,
            .include_hints = true,
            .max_reported_mismatches = 32U,
        };

        const auto result = compare_packet_observations(legacy, unified, options);
        PFL_EXPECT(result.mismatch_count == 1U);
        PFL_REQUIRE(result.groups.size() == 1U);
        PFL_EXPECT(result.groups[0].category == ImportValidationPacketMismatchCategory::classification);
        PFL_REQUIRE(result.groups[0].packet_indices.size() == 1U);
        PFL_EXPECT(result.groups[0].packet_indices[0] == 1U);
        PFL_EXPECT(result.first_divergence.classification_packet_index == std::optional<std::uint64_t> {1U});
    }

    {
        const ScopedTestContext context {"registry_comparison_reports_added_path_and_id_drift"};
        const ProtocolPath path_a {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::udp()};
        const ProtocolPath path_b {LayerKey::ethernet_ii(), LayerKey::vlan(7U), LayerKey::ipv4(), LayerKey::udp()};
        const ProtocolPath path_c {LayerKey::ethernet_ii(), LayerKey::ipv6(), LayerKey::udp()};
        const ProtocolPath path_x {LayerKey::ethernet_ii(), LayerKey::pppoe(), LayerKey::ppp(), LayerKey::ipv4(), LayerKey::udp()};

        const auto comparison = compare_structural_protocol_path_registries(
            std::vector<ProtocolPath> {path_a, path_b, path_c},
            std::vector<ProtocolPath> {path_x, path_a, path_b, path_c});

        PFL_EXPECT(comparison.shared_structural_path_count == 3U);
        PFL_EXPECT(comparison.id_drift_count == 3U);
        PFL_EXPECT(comparison.only_in_legacy.empty());
        PFL_REQUIRE(comparison.only_in_unified.size() == 1U);
        PFL_EXPECT(comparison.only_in_unified[0] == path_x);
    }

    {
        const ScopedTestContext context {"canonical_compare_matches_flows_by_structural_path"};
        const ProtocolPath path_a {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::udp()};
        const ProtocolPath path_b {LayerKey::ethernet_ii(), LayerKey::vlan(7U), LayerKey::ipv4(), LayerKey::udp()};
        const ProtocolPath path_x {LayerKey::ethernet_ii(), LayerKey::pppoe(), LayerKey::ppp(), LayerKey::ipv4(), LayerKey::udp()};

        ImportValidationCanonicalState legacy {};
        legacy.summary.packet_count = 1U;
        legacy.summary.flow_count = 2U;
        legacy.summary.total_bytes = 128U;
        legacy.protocol_registry_paths = {path_a, path_b};
        legacy.ipv4_flows = {
            make_flow_snapshot(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1000U, 2000U, path_a),
            make_flow_snapshot(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 3000U, 4000U, path_b),
        };

        ImportValidationCanonicalState unified = legacy;
        unified.protocol_registry_paths = {path_x, path_a, path_b};
        std::sort(
            unified.ipv4_flows.begin(),
            unified.ipv4_flows.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.key < rhs.key;
            });

        const auto result = compare_canonical_states(legacy, unified);
        PFL_REQUIRE(result.success);
        PFL_EXPECT(!result.parity);
        PFL_EXPECT(result.registry_comparison.only_in_unified.size() == 1U);
        for (const auto& mismatch : result.mismatches) {
            PFL_EXPECT(mismatch.category != ImportValidationMismatchCategory::flow);
        }
    }

    {
        const ScopedTestContext context {"missing_input_returns_failure"};
        const auto result = run_legacy_import_validation(
            std::filesystem::temp_directory_path() / "pfl_missing_capture_for_validation.pcap"
        );
        PFL_EXPECT(!result.success);
        PFL_EXPECT(!result.error_text.empty());
    }

    expect_compare_success_with_exact_parity(
        write_empty_classic_pcap("pfl_import_validation_empty.pcap"),
        "empty_classic_pcap"
    );

    {
        const ScopedTestContext context {"single_recognized_flow_classic_pcap"};
        const auto capture_path = write_single_tcp_classic_pcap("pfl_import_validation_single_tcp.pcap");
        const auto legacy = run_legacy_import_validation(capture_path);
        const auto unified = run_unified_import_validation(capture_path);
        PFL_REQUIRE(legacy.success);
        PFL_REQUIRE(unified.success);
        PFL_EXPECT(legacy.metrics.packet_count == 1U);
        PFL_EXPECT(unified.metrics.packet_count == 1U);
        PFL_EXPECT(legacy.metrics.flow_count == 1U);
        PFL_EXPECT(unified.metrics.flow_count == 1U);
        PFL_EXPECT(legacy.metrics.unrecognized_count == 0U);
        PFL_EXPECT(unified.metrics.unrecognized_count == 0U);
        PFL_REQUIRE(legacy.packet_observations.size() == 1U);
        PFL_REQUIRE(unified.packet_observations.size() == 1U);

        const auto compare = compare_import_validation(capture_path);
        PFL_REQUIRE(compare.success);
        PFL_EXPECT(compare.parity);

        const ImportValidationOptions diagnose_options {
            .max_packets = std::nullopt,
            .packet_index = 0U,
            .include_hints = true,
            .max_reported_mismatches = 32U,
        };
        const auto diagnose = diagnose_import_validation(capture_path, diagnose_options);
        PFL_REQUIRE(diagnose.success);
        PFL_EXPECT(diagnose.session_compare.parity);
        PFL_EXPECT(diagnose.packet_compare.mismatch_count == 0U);
        PFL_REQUIRE(diagnose.legacy_packet.has_value());
        PFL_REQUIRE(diagnose.unified_packet.has_value());
        PFL_EXPECT(diagnose.legacy_packet->packet_index == 0U);
        PFL_EXPECT(diagnose.unified_packet->packet_index == 0U);
    }

    {
        const ScopedTestContext context {"single_unrecognized_packet_classic_pcap"};
        const auto compare = compare_import_validation(
            write_single_unrecognized_classic_pcap("pfl_import_validation_unrecognized.pcap")
        );
        PFL_REQUIRE(compare.success);
        PFL_EXPECT(compare.parity);
        PFL_EXPECT(compare.legacy_metrics.unrecognized_count == 1U);
        PFL_EXPECT(compare.unified_metrics.unrecognized_count == 1U);
        PFL_EXPECT(compare.legacy_metrics.flow_count == 0U);
        PFL_EXPECT(compare.unified_metrics.flow_count == 0U);
    }

    expect_compare_success_with_exact_parity(
        write_staged_prefix_classic_pcap("pfl_import_validation_staged_prefix_ipv6_udp.pcap"),
        "staged_prefix_classic_pcap"
    );

    expect_compare_success_with_exact_parity(
        write_single_tcp_pcapng("pfl_import_validation_single_tcp.pcapng"),
        "single_tcp_pcapng"
    );
}

}  // namespace pfl::tests
