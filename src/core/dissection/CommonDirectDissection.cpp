#include "core/dissection/CommonDirectDissection.h"

#include <array>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModules.h"

namespace pfl::dissection {

void ImportDissectionCollector::consume(const DissectionStep& step) noexcept {
    ++facts_.step_count;
    facts_.final_status = step.status;

    if (!facts_.path_overflowed && !facts_.physical_path.push(step.layer_key)) {
        facts_.path_overflowed = true;
    }

    if (step.terminal_flow.has_value()) {
        const auto& flow = *step.terminal_flow;
        if (flow.family != DissectionAddressFamily::unknown) {
            facts_.family = flow.family;
        }
        if (flow.protocol != ProtocolId::unknown) {
            facts_.terminal_protocol = flow.protocol;
        }
        if (flow.has_addresses) {
            facts_.has_flow_addresses = true;
            facts_.src_addr_v4 = flow.src_addr_v4;
            facts_.dst_addr_v4 = flow.dst_addr_v4;
        }
        if (flow.has_ports) {
            facts_.src_port = flow.src_port;
            facts_.dst_port = flow.dst_port;
            facts_.has_ports = true;
        }
    }

    if (step.arp_addresses.has_value()) {
        facts_.has_arp_addresses = true;
        facts_.arp_addresses = *step.arp_addresses;
    }

    if (step.transport_payload.has_value()) {
        facts_.has_transport_payload_length = true;
        facts_.captured_transport_payload_length = step.transport_payload->captured_payload_length;
    }

    if (step.tcp_control.has_value()) {
        facts_.has_tcp_flags = true;
        facts_.tcp_flags = step.tcp_control->flags;
    }

    if (step.ipv4_fragmentation.has_value()) {
        facts_.has_ipv4_fragmentation = true;
        facts_.ipv4_fragmentation = *step.ipv4_fragmentation;
    }

    if (step.layer_key.kind == ProtocolLayerKind::arp && step.status == ParseStatus::complete) {
        if (facts_.has_arp_addresses &&
            (facts_.arp_addresses.has_sender_ipv4 || facts_.arp_addresses.has_target_ipv4)) {
            facts_.family = DissectionAddressFamily::ipv4;
        }
        facts_.terminal_protocol = ProtocolId::arp;
    }
}

void ImportDissectionCollector::finish(const DissectionEngineResult& result) noexcept {
    facts_.stop_reason = result.stop_reason;
    facts_.traversed_depth = result.traversed_depth;
    facts_.step_count = result.step_count;

    if (facts_.terminal_protocol == ProtocolId::arp && result.stop_reason == StopReason::terminal_protocol) {
        facts_.outcome = ImportDissectionOutcome::recognized_non_flow;
        return;
    }

    if (facts_.terminal_protocol != ProtocolId::unknown &&
        facts_.family != DissectionAddressFamily::unknown &&
        facts_.has_flow_addresses &&
        (result.stop_reason == StopReason::terminal_protocol || result.stop_reason == StopReason::needs_reassembly)) {
        facts_.outcome = ImportDissectionOutcome::recognized_flow;
        return;
    }

    facts_.outcome = ImportDissectionOutcome::unrecognized;
}

void ImportDissectionCollector::consume_step(void* context, const DissectionStep& step) noexcept {
    auto* collector = static_cast<ImportDissectionCollector*>(context);
    collector->consume(step);
}

DissectionRegistryBuildResult make_common_direct_registry() {
    const std::array registrations {
        DissectorRegistration {
            .selector = make_link_type_selector(kLinkTypeEthernet),
            .dissector = dissect_ethernet,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ether_type,
                .value = detail::kEtherTypeIpv4,
            },
            .dissector = dissect_ipv4,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ether_type,
                .value = detail::kEtherTypeArp,
            },
            .dissector = dissect_arp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ether_type,
                .value = detail::kEtherTypeVlan,
            },
            .dissector = dissect_vlan,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ether_type,
                .value = detail::kEtherTypeQinq,
            },
            .dissector = dissect_vlan,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ether_type,
                .value = detail::kEtherTypeLegacyVlan,
            },
            .dissector = dissect_vlan,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ip_protocol,
                .value = detail::kIpProtocolTcp,
            },
            .dissector = dissect_tcp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ip_protocol,
                .value = detail::kIpProtocolUdp,
            },
            .dissector = dissect_udp,
        },
    };

    return DissectionRegistry::build(registrations);
}

}  // namespace pfl::dissection
