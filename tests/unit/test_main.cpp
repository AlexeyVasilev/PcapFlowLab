#include <exception>
#include <iostream>
#include <sstream>

#include "TestSupport.h"

namespace pfl::tests {

void run_flow_key_tests();
void run_connection_tests();
void run_ingestor_tests();
void run_import_tests();
void run_packet_access_tests();

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
        pfl::tests::run_packet_access_tests();
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
