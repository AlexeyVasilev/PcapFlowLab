#include "core/dissection/CommonDirectDissection.h"

#include <array>
#include <type_traits>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModules.h"

namespace pfl::dissection {

namespace {

ProtocolId protocol_id_from_ip_protocol(const std::uint8_t protocol) noexcept {
    if (protocol == detail::kIpProtocolIcmp) {
        return ProtocolId::icmp;
    }
    if (protocol == detail::kIpProtocolIgmp) {
        return ProtocolId::igmp;
    }
    if (protocol == detail::kIpProtocolTcp) {
        return ProtocolId::tcp;
    }
    if (protocol == detail::kIpProtocolUdp) {
        return ProtocolId::udp;
    }
    if (protocol == detail::kIpProtocolSctp) {
        return ProtocolId::sctp;
    }

    return ProtocolId::unknown;
}

ProtocolId protocol_id_from_ipv6_next_header(const std::uint8_t next_header) noexcept {
    if (next_header == detail::kIpProtocolTcp) {
        return ProtocolId::tcp;
    }
    if (next_header == detail::kIpProtocolUdp) {
        return ProtocolId::udp;
    }
    if (next_header == detail::kIpProtocolSctp) {
        return ProtocolId::sctp;
    }
    if (next_header == detail::kIpProtocolIcmpV6) {
        return ProtocolId::icmpv6;
    }

    return ProtocolId::unknown;
}

std::uint32_t captured_payload_length_from_bounds(const LayerBounds& bounds) noexcept {
    if (!bounds.payload.has_value()) {
        return 0U;
    }

    return static_cast<std::uint32_t>(bounds.payload->captured.length());
}

}  // namespace

void ImportDissectionCollector::consume(const DissectionStep& step) noexcept {
    ++facts_.step_count;
    facts_.final_status = step.status;

    if (step.descendant_path_commit_policy.has_value()) {
        active_descendant_path_commit_policy_ = step.descendant_path_commit_policy;
    }

    if (step.defer_last_deferrable_path_contribution &&
        step.path_commit_policy != PathCommitPolicy::immediate) {
        for (std::size_t index = pending_path_size_; index > 0U; --index) {
            auto& pending = pending_path_[index - 1U];
            if (!pending.deferrable_by_child) {
                continue;
            }

            pending.commit_policy = step.path_commit_policy;
            pending.deferrable_by_child = false;
            break;
        }
    }

    if (step.path_contribution.has_value()) {
        if (pending_path_size_ >= pending_path_.size()) {
            facts_.path_overflowed = true;
        } else {
            auto effective_policy = step.path_commit_policy;
            if (effective_policy == PathCommitPolicy::immediate &&
                active_descendant_path_commit_policy_.has_value()) {
                effective_policy = *active_descendant_path_commit_policy_;
            }
            pending_path_[pending_path_size_++] = PendingPathContribution {
                .layer = *step.path_contribution,
                .commit_policy = effective_policy,
                .deferrable_by_child = step.path_contribution_deferrable_by_child,
                .terminal_disposition = step.terminal_disposition,
            };
        }
    }

    if (step.terminal_disposition != TerminalDisposition::none) {
        terminal_disposition_ = step.terminal_disposition;
    }

    std::visit(
        [this, &step](const auto& layer_facts) {
            using Facts = std::decay_t<decltype(layer_facts)>;
            if constexpr (std::is_same_v<Facts, std::monostate> ||
                          std::is_same_v<Facts, EthernetFacts> ||
                          std::is_same_v<Facts, VlanFacts> ||
                          std::is_same_v<Facts, LlcSnapFacts> ||
                          std::is_same_v<Facts, LinuxCookedFacts> ||
                          std::is_same_v<Facts, PppoeFacts> ||
                          std::is_same_v<Facts, PppFacts>) {
                return;
            } else if constexpr (std::is_same_v<Facts, ArpFacts>) {
                facts_.has_arp_addresses = true;
                facts_.arp_addresses = layer_facts;
                if (layer_facts.has_sender_ipv4 || layer_facts.has_target_ipv4) {
                    facts_.family = DissectionAddressFamily::ipv4;
                }
                facts_.terminal_protocol = ProtocolId::arp;
            } else if constexpr (std::is_same_v<Facts, Ipv4Facts>) {
                facts_.family = DissectionAddressFamily::ipv4;
                facts_.has_flow_addresses = true;
                facts_.src_addr_v4 = layer_facts.src_addr_v4;
                facts_.dst_addr_v4 = layer_facts.dst_addr_v4;
                facts_.has_ipv4_fragmentation = true;
                facts_.ipv4_fragmentation = ImportIpv4Fragmentation {
                    .is_fragmented = layer_facts.is_fragmented,
                    .more_fragments = layer_facts.more_fragments,
                    .fragment_offset_units = layer_facts.fragment_offset_units,
                };

                if (facts_.terminal_protocol == ProtocolId::unknown) {
                    facts_.terminal_protocol = protocol_id_from_ip_protocol(layer_facts.protocol);
                }
            } else if constexpr (std::is_same_v<Facts, Ipv6Facts>) {
                facts_.family = DissectionAddressFamily::ipv6;
                facts_.has_flow_addresses = true;
                facts_.src_addr_v6 = layer_facts.src_addr_v6;
                facts_.dst_addr_v6 = layer_facts.dst_addr_v6;
                facts_.has_ipv6_fragmentation = true;
                facts_.ipv6_fragmentation = ImportIpv6Fragmentation {
                    .has_fragment_header = layer_facts.has_fragment_header,
                    .more_fragments = layer_facts.more_fragments,
                    .fragment_offset_units = layer_facts.fragment_offset_units,
                    .is_atomic_fragment = layer_facts.is_atomic_fragment,
                };

                if (facts_.terminal_protocol == ProtocolId::unknown) {
                    facts_.terminal_protocol = protocol_id_from_ipv6_next_header(layer_facts.next_header);
                }
            } else if constexpr (std::is_same_v<Facts, Ipv6ExtensionFacts>) {
                if (facts_.terminal_protocol == ProtocolId::unknown) {
                    facts_.terminal_protocol = protocol_id_from_ipv6_next_header(layer_facts.next_header);
                }
            } else if constexpr (std::is_same_v<Facts, Ipv6FragmentFacts>) {
                facts_.has_ipv6_fragmentation = true;
                facts_.ipv6_fragmentation = ImportIpv6Fragmentation {
                    .has_fragment_header = true,
                    .more_fragments = layer_facts.more_fragments,
                    .fragment_offset_units = layer_facts.fragment_offset_units,
                    .is_atomic_fragment = layer_facts.is_atomic_fragment,
                };

                if (facts_.terminal_protocol == ProtocolId::unknown) {
                    facts_.terminal_protocol = protocol_id_from_ipv6_next_header(layer_facts.next_header);
                }
            } else if constexpr (std::is_same_v<Facts, GreFacts>) {
                return;
            } else if constexpr (std::is_same_v<Facts, MplsFacts>) {
                return;
            } else if constexpr (std::is_same_v<Facts, AhFacts>) {
                return;
            } else if constexpr (std::is_same_v<Facts, EspFacts>) {
                facts_.terminal_protocol = ProtocolId::esp;
                facts_.has_transport_payload_length = step.bounds.payload.has_value();
                facts_.captured_transport_payload_length = captured_payload_length_from_bounds(step.bounds);
            } else if constexpr (std::is_same_v<Facts, IcmpFacts>) {
                facts_.terminal_protocol = ProtocolId::icmp;
            } else if constexpr (std::is_same_v<Facts, Icmpv6Facts>) {
                facts_.terminal_protocol = ProtocolId::icmpv6;
            } else if constexpr (std::is_same_v<Facts, IgmpFacts>) {
                facts_.terminal_protocol = ProtocolId::igmp;
                if (layer_facts.has_effective_destination_v4) {
                    igmp_effective_destination_v4_ = layer_facts.effective_destination_v4;
                }
            } else if constexpr (std::is_same_v<Facts, TcpFacts>) {
                facts_.terminal_protocol = ProtocolId::tcp;
                facts_.has_ports = true;
                facts_.src_port = layer_facts.src_port;
                facts_.dst_port = layer_facts.dst_port;
                facts_.has_tcp_flags = true;
                facts_.tcp_flags = layer_facts.flags;
                facts_.has_transport_payload_length = step.bounds.payload.has_value();
                facts_.captured_transport_payload_length = captured_payload_length_from_bounds(step.bounds);
            } else if constexpr (std::is_same_v<Facts, UdpFacts>) {
                facts_.terminal_protocol = ProtocolId::udp;
                facts_.has_ports = true;
                facts_.src_port = layer_facts.src_port;
                facts_.dst_port = layer_facts.dst_port;
                facts_.has_transport_payload_length = step.bounds.payload.has_value();
                facts_.captured_transport_payload_length = captured_payload_length_from_bounds(step.bounds);
            } else if constexpr (std::is_same_v<Facts, SctpFacts>) {
                facts_.terminal_protocol = ProtocolId::sctp;
                facts_.has_ports = true;
                facts_.src_port = layer_facts.src_port;
                facts_.dst_port = layer_facts.dst_port;
                facts_.has_transport_payload_length = step.bounds.payload.has_value();
                facts_.captured_transport_payload_length = captured_payload_length_from_bounds(step.bounds);
            }
        },
        step.facts
    );
}

void ImportDissectionCollector::finish(const DissectionEngineResult& result) noexcept {
    facts_.stop_reason = result.stop_reason;
    facts_.traversed_depth = result.traversed_depth;
    facts_.step_count = result.step_count;

    if (facts_.terminal_protocol == ProtocolId::igmp &&
        facts_.family == DissectionAddressFamily::ipv4 &&
        facts_.has_flow_addresses &&
        igmp_effective_destination_v4_.has_value()) {
        facts_.dst_addr_v4 = *igmp_effective_destination_v4_;
    }

    const auto recognized_non_flow =
        terminal_disposition_ == TerminalDisposition::recognized_non_flow &&
        result.stop_reason == StopReason::terminal_protocol;
    const auto recognized_flow =
        facts_.terminal_protocol != ProtocolId::unknown &&
        facts_.family != DissectionAddressFamily::unknown &&
        facts_.has_flow_addresses &&
        (result.stop_reason == StopReason::terminal_protocol || result.stop_reason == StopReason::needs_reassembly) &&
        (terminal_disposition_ == TerminalDisposition::flow_candidate || result.stop_reason == StopReason::needs_reassembly);
    facts_.physical_path.clear();
    for (std::size_t index = 0U; index < pending_path_size_; ++index) {
        const auto& pending = pending_path_[index];
        switch (pending.commit_policy) {
        case PathCommitPolicy::immediate:
            break;
        case PathCommitPolicy::recognized_flow:
            if (!recognized_flow) {
                continue;
            }
            break;
        case PathCommitPolicy::recognized_flow_or_recognized_non_flow:
            if (recognized_flow) {
                break;
            }
            if (!recognized_non_flow || pending.terminal_disposition != TerminalDisposition::none) {
                continue;
            }
            break;
        }
        if (!facts_.path_overflowed && !facts_.physical_path.push(pending.layer)) {
            facts_.path_overflowed = true;
        }
    }

    if (recognized_non_flow) {
        facts_.outcome = ImportDissectionOutcome::recognized_non_flow;
        return;
    }

    if (recognized_flow) {
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
            .selector = make_link_type_selector(kLinkTypeLinuxSll),
            .dissector = dissect_linux_sll,
        },
        DissectorRegistration {
            .selector = make_link_type_selector(kLinkTypeLinuxSll2),
            .dissector = dissect_linux_sll2,
        },
        DissectorRegistration {
            .selector = make_link_type_selector(kLinkTypeEthernet),
            .dissector = dissect_ethernet,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::linux_cooked_protocol,
                .value = detail::kEtherTypeIpv4,
            },
            .dissector = dissect_ipv4,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::linux_cooked_protocol,
                .value = detail::kEtherTypeIpv6,
            },
            .dissector = dissect_ipv6,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::linux_cooked_protocol,
                .value = detail::kEtherTypeArp,
            },
            .dissector = dissect_linux_cooked_arp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ieee8023_payload,
                .value = kIeee8023PayloadSelectorValue,
            },
            .dissector = dissect_llc_snap,
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
                .value = detail::kEtherTypeIpv6,
            },
            .dissector = dissect_ipv6,
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
                .value = detail::kEtherTypePppoeDiscovery,
            },
            .dissector = dissect_pppoe_discovery,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ether_type,
                .value = detail::kEtherTypePppoeSession,
            },
            .dissector = dissect_pppoe_session,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::llc_snap_pid,
                .value = detail::kEtherTypeIpv4,
            },
            .dissector = dissect_ipv4,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::llc_snap_pid,
                .value = detail::kEtherTypeIpv6,
            },
            .dissector = dissect_ipv6,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::llc_snap_pid,
                .value = detail::kEtherTypeArp,
            },
            .dissector = dissect_arp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ppp_frame,
                .value = kPppFrameContinueSelectorValue,
            },
            .dissector = dissect_ppp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ppp_protocol,
                .value = detail::kPppProtocolIpv4,
            },
            .dissector = dissect_ipv4,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ppp_protocol,
                .value = detail::kPppProtocolIpv6,
            },
            .dissector = dissect_ipv6,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ppp_protocol,
                .value = 0xC021U,
            },
            .dissector = dissect_ppp_control,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ppp_protocol,
                .value = 0x8021U,
            },
            .dissector = dissect_ppp_control,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ppp_protocol,
                .value = 0x8057U,
            },
            .dissector = dissect_ppp_control,
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
                .domain = SelectorDomain::ether_type,
                .value = detail::kEtherTypeMplsUnicast,
            },
            .dissector = dissect_mpls_label,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ip_protocol,
                .value = detail::kIpProtocolIcmp,
            },
            .dissector = dissect_icmp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ip_protocol,
                .value = detail::kIpProtocolIgmp,
            },
            .dissector = dissect_igmp,
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
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ip_protocol,
                .value = detail::kIpProtocolSctp,
            },
            .dissector = dissect_sctp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ip_protocol,
                .value = detail::kIpProtocolGre,
            },
            .dissector = dissect_gre,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ip_protocol,
                .value = detail::kIpProtocolEsp,
            },
            .dissector = dissect_esp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ip_protocol,
                .value = detail::kIpProtocolAh,
            },
            .dissector = dissect_ipv4_ah,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ip_protocol,
                .value = detail::kIpProtocolIpv4Encapsulation,
            },
            .dissector = dissect_ipv4,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ip_protocol,
                .value = detail::kIpProtocolIpv6Encapsulation,
            },
            .dissector = dissect_ipv6,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolHopByHop,
            },
            .dissector = dissect_ipv6_hop_by_hop,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolRouting,
            },
            .dissector = dissect_ipv6_routing,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolFragment,
            },
            .dissector = dissect_ipv6_fragment,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolDestinationOptions,
            },
            .dissector = dissect_ipv6_destination_options,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolIcmpV6,
            },
            .dissector = dissect_icmpv6,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolTcp,
            },
            .dissector = dissect_tcp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolUdp,
            },
            .dissector = dissect_udp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolSctp,
            },
            .dissector = dissect_sctp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolGre,
            },
            .dissector = dissect_gre,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolEsp,
            },
            .dissector = dissect_esp,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolAh,
            },
            .dissector = dissect_ipv6_ah,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolIpv4Encapsulation,
            },
            .dissector = dissect_ipv4,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ipv6_next_header,
                .value = detail::kIpProtocolIpv6Encapsulation,
            },
            .dissector = dissect_ipv6,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::gre_protocol_type,
                .value = detail::kEtherTypeIpv4,
            },
            .dissector = dissect_ipv4,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::gre_protocol_type,
                .value = detail::kEtherTypeIpv6,
            },
            .dissector = dissect_ipv6,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::gre_protocol_type,
                .value = detail::kGreProtocolTypeTransparentEthernetBridging,
            },
            .dissector = dissect_ethernet,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::gre_protocol_type,
                .value = detail::kEtherTypeMplsUnicast,
            },
            .dissector = dissect_mpls_label,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::mpls_stack,
                .value = kMplsStackContinueSelectorValue,
            },
            .dissector = dissect_mpls_label,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::mpls_payload,
                .value = detail::kEtherTypeIpv4,
            },
            .dissector = dissect_ipv4,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::mpls_payload,
                .value = detail::kEtherTypeIpv6,
            },
            .dissector = dissect_ipv6,
        },
    };

    return DissectionRegistry::build(registrations);
}

}  // namespace pfl::dissection
