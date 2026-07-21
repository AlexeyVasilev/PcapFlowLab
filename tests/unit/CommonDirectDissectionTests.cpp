#include "CommonDirectDissectionTestSupport.h"

namespace pfl::tests {

void run_common_direct_dissection_tests() {
    common_direct_test::run_common_direct_core_dissection_tests();
    common_direct_test::run_common_direct_link_dissection_tests();
    common_direct_test::run_common_direct_network_dissection_tests();
    common_direct_test::run_common_direct_encapsulation_dissection_tests();
    common_direct_test::run_common_direct_transport_dissection_tests();
}

}  // namespace pfl::tests
