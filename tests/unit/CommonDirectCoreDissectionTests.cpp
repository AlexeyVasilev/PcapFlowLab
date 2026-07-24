#include "CommonDirectDissectionTestSupport.h"

namespace pfl::tests::common_direct_test {

void run_common_direct_core_dissection_tests() {
    run_common_direct_registry_engine_tests();
    run_common_direct_collector_tests();
    run_common_direct_path_policy_tests();
    run_common_direct_bounds_traversal_tests();
}

}  // namespace pfl::tests::common_direct_test
