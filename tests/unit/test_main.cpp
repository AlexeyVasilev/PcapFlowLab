#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <string_view>
#include <vector>

#include "TestSupport.h"

namespace pfl::tests {

namespace {

std::vector<RecordedTestFailure>& failure_storage() {
    static std::vector<RecordedTestFailure> failures {};
    return failures;
}

}  // namespace

void run_flow_key_tests();
void run_dissection_foundation_tests();
void run_common_direct_dissection_tests();
void run_protocol_path_tests();
void run_connection_tests();
void run_ingestor_tests();
void run_import_tests();
void run_analysis_settings_tests();
void run_flow_analysis_tests();
void run_packet_access_tests();
void run_packet_details_tests();
void run_packet_payload_tests();
void run_packet_protocol_details_tests();
void run_arp_pcap_fixture_tests();
void run_igmp_pcap_fixture_tests();
void run_ipv4_options_pcap_fixture_tests();
void run_packet_metadata_tests();
void run_flow_hints_tests();
void run_flow_hints_raw_fixtures_tests();
void run_flow_hints_real_fixtures_tests();
void run_query_tests();
void run_stream_query_tests();
void run_protocol_summary_tests();
void run_top_summary_tests();
void run_vlan_tests();
void run_export_tests();
void run_pcapng_tests();
void run_index_tests();
void run_index_format_tests();
void run_chunked_import_tests();
void run_protocol_coverage_tests();
void run_malformed_packet_handling_tests();
void run_linux_cooked_tests();
void run_linux_cooked_pcap_fixture_tests();
void run_fragmentation_tests();
void run_reassembly_architecture_tests();
void run_reassembly_v1_tests();
void run_perf_open_logger_tests();
void run_quic_initial_parser_tests();
void run_protocol_recognition_stats_tests();
void run_unrecognized_packet_tests();
void run_mpls_pcap_fixture_tests();
void run_pppoe_pcap_fixture_tests();
void run_vlan_pcap_fixture_tests();
void run_llc_snap_pcap_fixture_tests();
void run_mpls_pseudowire_pcap_fixture_tests();
void run_pbb_pcap_fixture_tests();
void run_macsec_pcap_fixture_tests();
void run_vxlan_pcap_fixture_tests();
void run_geneve_pcap_fixture_tests();
void run_gtpu_pcap_fixture_tests();
void run_gre_pcap_fixture_tests();
void run_esp_pcap_fixture_tests();
void run_ah_pcap_fixture_tests();
void run_eoip_pcap_fixture_tests();
void run_ip_encapsulation_pcap_fixture_tests();
void run_sctp_pcap_fixture_tests();

void expect(bool condition, const char* expression, const char* file, int line) {
    if (condition) {
        return;
    }

    std::ostringstream builder {};
    builder << file << ':' << line << " expectation failed: " << expression;
    record_failure_message(builder.str());
}

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) {
        return;
    }

    std::ostringstream builder {};
    builder << file << ':' << line << " requirement failed: " << expression;
    throw TestFailure(builder.str());
}

void record_failure_message(std::string message) {
    failure_storage().push_back(RecordedTestFailure {
        .message = std::move(message),
    });
}

const std::vector<RecordedTestFailure>& recorded_failures() {
    return failure_storage();
}

bool has_recorded_failures() {
    return !failure_storage().empty();
}

void clear_recorded_failures() {
    failure_storage().clear();
}

}  // namespace pfl::tests

int main() {
    pfl::tests::clear_recorded_failures();

    struct TestSuiteEntry {
        std::string_view name;
        std::function<void()> run;
    };

    const std::vector<TestSuiteEntry> suites {
        {"flow_key", pfl::tests::run_flow_key_tests},
        {"dissection_foundation", pfl::tests::run_dissection_foundation_tests},
        {"common_direct_dissection", pfl::tests::run_common_direct_dissection_tests},
        {"protocol_path", pfl::tests::run_protocol_path_tests},
        {"connection", pfl::tests::run_connection_tests},
        {"ingestor", pfl::tests::run_ingestor_tests},
        {"import", pfl::tests::run_import_tests},
        {"analysis_settings", pfl::tests::run_analysis_settings_tests},
        {"flow_analysis", pfl::tests::run_flow_analysis_tests},
        {"packet_access", pfl::tests::run_packet_access_tests},
        {"packet_details", pfl::tests::run_packet_details_tests},
        {"packet_payload", pfl::tests::run_packet_payload_tests},
        {"packet_protocol_details", pfl::tests::run_packet_protocol_details_tests},
        {"arp_pcap_fixtures", pfl::tests::run_arp_pcap_fixture_tests},
        {"igmp_pcap_fixtures", pfl::tests::run_igmp_pcap_fixture_tests},
        {"ipv4_options_pcap_fixtures", pfl::tests::run_ipv4_options_pcap_fixture_tests},
        {"packet_metadata", pfl::tests::run_packet_metadata_tests},
        {"flow_hints", pfl::tests::run_flow_hints_tests},
        {"flow_hints_raw_fixtures", pfl::tests::run_flow_hints_raw_fixtures_tests},
        {"flow_hints_real_fixtures", pfl::tests::run_flow_hints_real_fixtures_tests},
        {"query", pfl::tests::run_query_tests},
        {"stream_query", pfl::tests::run_stream_query_tests},
        {"protocol_summary", pfl::tests::run_protocol_summary_tests},
        {"top_summary", pfl::tests::run_top_summary_tests},
        {"vlan", pfl::tests::run_vlan_tests},
        {"export", pfl::tests::run_export_tests},
        {"pcapng", pfl::tests::run_pcapng_tests},
        {"index", pfl::tests::run_index_tests},
        {"index_format", pfl::tests::run_index_format_tests},
        {"chunked_import", pfl::tests::run_chunked_import_tests},
        {"protocol_coverage", pfl::tests::run_protocol_coverage_tests},
        {"malformed_packet_handling", pfl::tests::run_malformed_packet_handling_tests},
        {"linux_cooked", pfl::tests::run_linux_cooked_tests},
        {"linux_cooked_pcap_fixtures", pfl::tests::run_linux_cooked_pcap_fixture_tests},
        {"fragmentation", pfl::tests::run_fragmentation_tests},
        {"reassembly_architecture", pfl::tests::run_reassembly_architecture_tests},
        {"reassembly_v1", pfl::tests::run_reassembly_v1_tests},
        {"perf_open_logger", pfl::tests::run_perf_open_logger_tests},
        {"quic_initial_parser", pfl::tests::run_quic_initial_parser_tests},
        {"protocol_recognition_stats", pfl::tests::run_protocol_recognition_stats_tests},
        {"unrecognized_packet", pfl::tests::run_unrecognized_packet_tests},
        {"mpls_pcap_fixtures", pfl::tests::run_mpls_pcap_fixture_tests},
        {"pppoe_pcap_fixtures", pfl::tests::run_pppoe_pcap_fixture_tests},
        {"vlan_pcap_fixtures", pfl::tests::run_vlan_pcap_fixture_tests},
        {"llc_snap_pcap_fixtures", pfl::tests::run_llc_snap_pcap_fixture_tests},
        {"mpls_pseudowire_pcap_fixtures", pfl::tests::run_mpls_pseudowire_pcap_fixture_tests},
        {"pbb_pcap_fixtures", pfl::tests::run_pbb_pcap_fixture_tests},
        {"macsec_pcap_fixtures", pfl::tests::run_macsec_pcap_fixture_tests},
        {"vxlan_pcap_fixtures", pfl::tests::run_vxlan_pcap_fixture_tests},
        {"geneve_pcap_fixtures", pfl::tests::run_geneve_pcap_fixture_tests},
        {"gtpu_pcap_fixtures", pfl::tests::run_gtpu_pcap_fixture_tests},
        {"gre_pcap_fixtures", pfl::tests::run_gre_pcap_fixture_tests},
        {"esp_pcap_fixtures", pfl::tests::run_esp_pcap_fixture_tests},
        {"ah_pcap_fixtures", pfl::tests::run_ah_pcap_fixture_tests},
        {"eoip_pcap_fixtures", pfl::tests::run_eoip_pcap_fixture_tests},
        {"ip_encapsulation_pcap_fixtures", pfl::tests::run_ip_encapsulation_pcap_fixture_tests},
        {"sctp_pcap_fixtures", pfl::tests::run_sctp_pcap_fixture_tests},
    };

    for (const auto& suite : suites) {
        try {
            suite.run();
        } catch (const pfl::tests::TestFailure& failure) {
            pfl::tests::record_failure_message(failure.what());
        } catch (const std::exception& exception) {
            pfl::tests::record_failure_message(
                std::string {"suite "} + std::string {suite.name} + " threw unexpected exception: " + exception.what()
            );
        } catch (...) {
            pfl::tests::record_failure_message(
                std::string {"suite "} + std::string {suite.name} + " threw unknown exception"
            );
        }
    }

    if (pfl::tests::has_recorded_failures()) {
        std::cerr << "FAILED: " << pfl::tests::recorded_failures().size() << " expectation(s)\n";
        for (const auto& failure : pfl::tests::recorded_failures()) {
            std::cerr << failure.message << '\n';
        }
        return 1;
    }

    std::cout << "All tests passed.\n";
    return 0;
}
