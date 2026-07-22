#include "CommonDirectDissectionTestSupport.h"

namespace pfl::tests {

void run_common_direct_dissection_tests() {
    common_direct_test::run_common_direct_core_dissection_tests();
    common_direct_test::run_common_direct_link_dissection_tests();
    common_direct_test::run_common_direct_network_dissection_tests();
    common_direct_test::run_common_direct_encapsulation_dissection_tests();
    common_direct_test::run_common_direct_eoip_dissection_tests();
    common_direct_test::run_common_direct_mpls_pseudowire_dissection_tests();
    common_direct_test::run_common_direct_transport_dissection_tests();
    common_direct_test::run_common_direct_vxlan_dissection_tests();
    common_direct_test::run_common_direct_geneve_dissection_tests();
    common_direct_test::run_common_direct_gtpu_dissection_tests();
}

}  // namespace pfl::tests
