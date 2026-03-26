#include <exception>
#include <iostream>
#include <sstream>

#include "TestSupport.h"

namespace pfl::tests {

void run_flow_key_tests();
void run_connection_tests();
void run_ingestor_tests();
void run_import_tests();
void run_import_mode_tests();
void run_packet_access_tests();
void run_packet_details_tests();
void run_packet_payload_tests();
void run_packet_metadata_tests();
void run_flow_hints_tests();
void run_flow_hints_raw_fixtures_tests();
void run_flow_hints_real_fixtures_tests();
void run_query_tests();
void run_protocol_summary_tests();
void run_top_summary_tests();
void run_vlan_tests();
void run_export_tests();
void run_pcapng_tests();
void run_index_tests();
void run_chunked_import_tests();
void run_protocol_coverage_tests();

void expect(bool condition, const char* expression, const char* file, int line) {
    if (condition) {
        return;
    }

    std::ostringstream builder;
    builder << file << ':' << line << " expectation failed: " << expression;
    throw TestFailure(builder.str());
}

}  // namespace pfl::tests

int main() {
    try {
        pfl::tests::run_flow_key_tests();
        pfl::tests::run_connection_tests();
        pfl::tests::run_ingestor_tests();
        pfl::tests::run_import_tests();
        pfl::tests::run_import_mode_tests();
        pfl::tests::run_packet_access_tests();
        pfl::tests::run_packet_details_tests();
        pfl::tests::run_packet_payload_tests();
        pfl::tests::run_packet_metadata_tests();
        pfl::tests::run_flow_hints_tests();
        pfl::tests::run_flow_hints_raw_fixtures_tests();
        pfl::tests::run_flow_hints_real_fixtures_tests();
        pfl::tests::run_query_tests();
        pfl::tests::run_protocol_summary_tests();
        pfl::tests::run_top_summary_tests();
        pfl::tests::run_vlan_tests();
        pfl::tests::run_export_tests();
        pfl::tests::run_pcapng_tests();
        pfl::tests::run_index_tests();
        pfl::tests::run_chunked_import_tests();
        pfl::tests::run_protocol_coverage_tests();
    } catch (const pfl::tests::TestFailure& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    } catch (const std::exception& exception) {
        std::cerr << "unexpected test failure: " << exception.what() << '\n';
        return 1;
    }

    std::cout << "All tests passed.\n";
    return 0;
}





