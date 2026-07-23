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

        const auto compare = compare_import_validation(capture_path);
        PFL_REQUIRE(compare.success);
        PFL_EXPECT(compare.parity);
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
