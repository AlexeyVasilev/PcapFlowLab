#pragma once

namespace pfl {

struct AnalysisSettings {
    bool http_use_path_as_service_hint {false};
    bool use_possible_tls_quic {false};
    bool ignore_vlan_and_mpls_layers_when_grouping_flows {false};
};

}  // namespace pfl

