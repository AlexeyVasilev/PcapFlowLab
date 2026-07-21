Synthetic Geneve parsing fixtures for production-behavior regression tests.

This directory documents the current production `PacketDecoder` Geneve contract.
It is fixture-first documentation for the supported production path only. It does
not describe any shadow dissection implementation.

## Strict production Geneve contract

Current production flow extraction recognizes Geneve only when all of the
following are true:

- outer transport is UDP with destination port `6081`;
- the bounded UDP payload contains at least the fixed 8-byte Geneve base header;
- Geneve version is `0`;
- Geneve option length is interpreted in 4-byte units and the full option area
  fits inside the bounded UDP payload;
- Geneve Protocol Type is Ethernet `0x6558`;
- the inner Ethernet continuation resolves to supported inner IPv4 or IPv6
  transport.

Current production behavior also implies:

- source-only port `6081` is not enough;
- `src=6081,dst=6081` is still accepted, because production gates on
  destination port only;
- VNI is parsed as a 24-bit big-endian field;
- VNI participates in protocol-path-aware flow identity;
- Geneve options, OAM, Critical, and other flag/control bits do not currently
  participate in flow identity;
- individual Geneve options are not parsed;
- unsupported Protocol Type values do not continue into inner Ethernet decoding;
- nested overlay-like inner UDP traffic is not recursively decoded as another
  overlay;
- outer IPv4 or IPv6 fragmentation prevents Geneve inner-flow extraction and
  falls back to the outer IP fragmentation shell;
- selected-packet Summary / Protocol details may still show lenient
  warning-oriented Geneve metadata on UDP/6081 packets even when strict flow
  extraction rejects the payload.

## Shared constants

- outer source MAC: `02:00:00:00:50:01`
- outer destination MAC: `02:00:00:00:50:02`
- primary outer IPv4 pair: `203.0.113.50 -> 203.0.113.51`
- alternate outer IPv4 pair: `203.0.113.60 -> 203.0.113.61`
- outer IPv6 pair: `2001:db8:50:1::1 -> 2001:db8:50:1::2`
- default Geneve destination port: `6081`
- wrong-port negative control: `6091`
- default supported Protocol Type: Ethernet `0x6558`
- default VNI: `100`

## Fixture inventory

- `01_geneve_inner_ipv4_tcp.pcap`
  Valid outer IPv4 / UDP / Geneve / Ethernet / inner IPv4 / TCP.
- `02_geneve_inner_ipv4_udp.pcap`
  Valid outer IPv4 / UDP / Geneve / Ethernet / inner IPv4 / UDP.
- `03_geneve_inner_ipv6_tcp.pcap`
  Valid outer IPv4 / UDP / Geneve / Ethernet / inner IPv6 / TCP.
- `04_geneve_inner_ipv6_udp.pcap`
  Valid outer IPv4 / UDP / Geneve / Ethernet / inner IPv6 / UDP.
- `05_geneve_truncated_base_header.pcap`
  UDP/6081 Geneve-like payload truncated before the fixed 8-byte base header.
- `06_geneve_invalid_version.pcap`
  Version `1` packet; strict flow extraction rejects it, details may still show
  best-effort inner continuation.
- `07_geneve_options_length_truncated.pcap`
  Option-length field declares more option bytes than are bounded/captured.
- `08_geneve_truncated_inner_ethernet.pcap`
  Valid Geneve base header but truncated inner Ethernet header.
- `09_geneve_truncated_inner_ipv4.pcap`
  Valid Geneve + inner Ethernet, but truncated inner IPv4 header.
- `10_geneve_unsupported_protocol_type.pcap`
  Protocol Type `0x0800` instead of Ethernet `0x6558`.
- `11_geneve_inner_ipv4_tcp_bidirectional.pcap`
  Two packets that must collapse into one bidirectional inner TCP flow.
- `12_geneve_same_outer_tuple_different_inner_flows.pcap`
  Same outer UDP tuple, different inner TCP tuples.
- `13_geneve_inner_vlan_ipv4_tcp.pcap`
  Supported inner `802.1Q VLAN -> IPv4 -> TCP` continuation.
- `14_geneve_outer_ipv6_inner_ipv4_tcp.pcap`
  Outer IPv6 carrier with supported inner IPv4 / TCP continuation.
- `15_geneve_wrong_udp_port_valid_geneve_payload.pcap`
  Valid-looking Geneve bytes on non-6081 UDP destination port.
- `16_geneve_vni_boundary_values.pcap`
  VNI boundary coverage for `0` and `16777215`.
- `17_geneve_with_options_inner_ipv4_tcp.pcap`
  Valid non-zero option length with bounded option skipping.
- `18_geneve_udp_port_direction_matrix.pcap`
  Destination-port gating matrix: valid `dst=6081`, source-only `6081`
  negative control, and `src=6081,dst=6081` positive control.
- `19_geneve_same_inner_tuple_different_vni.pcap`
  Same inner tuple, different VNIs; must split by protocol-path identity.
- `20_geneve_outer_tagged_contexts.pcap`
  Outer single-VLAN, outer QinQ, and outer legacy `0x9100` VLAN contexts.
- `21_geneve_identity_outer_carrier_variation_same_flow.pcap`
  Same VNI plus same inner tuple across different outer carrier metadata;
  production should still merge them into one flow.
- `22_geneve_identity_outer_and_inner_vlan_splits.pcap`
  Same inner tuple split by outer VLAN path contribution and inner VLAN path
  contribution.
- `23_geneve_outer_ipv4_fragmentation.pcap`
  Outer IPv4 fragmentation shell; Geneve inner flow must not be extracted.
- `24_geneve_outer_ipv6_fragmentation.pcap`
  Outer IPv6 fragment-header shell; Geneve inner flow must not be extracted.
- `25_geneve_option_and_flag_tolerance_matrix.pcap`
  Accepted OAM/Critical/control-bit/trailing-reserved variation plus bounded
  options; these remain presentation metadata, not identity.
- `26_geneve_inner_supported_and_visible_matrix.pcap`
  Supported inner continuation matrix:
  `inner VLAN`, `inner IEEE 802.3 LLC/SNAP -> IPv4`, and
  `inner IEEE 802.3 LLC/SNAP -> IPv6`.
- `27_geneve_unsupported_and_nested_matrix.pcap`
  ARP comparison case, unknown-inner-EtherType fallback case, and nested
  Geneve/VXLAN-like inner UDP traffic that must remain plain inner UDP and not
  recurse.
- `28_geneve_udp_declared_bounds_matrix.pcap`
  UDP/IP declared-bounds matrix for exact-header-only and bounded-payload cases.
- `29_geneve_capture_truncation_matrix.pcap`
  Capture-truncation matrix covering truncated Geneve header, truncated options,
  truncated inner Ethernet, and truncated inner IPv4.
- `30_geneve_vni_byte_order_distinct_values.pcap`
  Distinct VNI byte-order coverage with `0x010203` and `0x030201`.
- `31_geneve_linux_cooked_contexts.pcap`
  Linux SLL outer context carrying supported Geneve / inner IPv4 / UDP.
- `32_geneve_linux_cooked_v2_contexts.pcap`
  Linux SLL2 outer context carrying supported Geneve / inner IPv6 / TCP.
- `33_geneve_inner_unsupported_ethernet_payloads.pcap`
  Valid Geneve / inner Ethernet matrix for inner ARP, PPPoE Session, MPLS
  unicast, PBB, MACsec, and an asymmetric unknown EtherType.
- `34_geneve_nested_gtpu_no_recursion.pcap`
  Valid Geneve / inner Ethernet / inner IPv4 / UDP / GTP-U-like payload that
  must terminate at the inner UDP carrier and not recurse into GTP-U.

## Current expectations

- Valid supported Geneve packets produce normal inner IPv4/IPv6 TCP/UDP flows.
- Protocol paths include the physical carrier plus `Geneve(vni=...)`.
- Same inner tuple plus different VNI splits into different flows.
- Same inner tuple plus same VNI plus different outer carrier metadata still
  merges into one flow, because outer carrier endpoints are not part of v1 flow
  identity.
- Unsupported or malformed Geneve cases stay conservative and do not fabricate
  inner flows.
- Wrong-port packets remain ordinary outer UDP.
- Fragmented outer IPv4/IPv6 packets do not enter Geneve, remain recognized
  fragmentation-shell flows, keep `unrecognized_packet_count() == 0` for
  fixtures `23` and `24`, and recover no VNI or inner endpoint identity.
- Linux cooked carriers preserve `LinuxSll` or `LinuxSll2` in the protocol path.

## Unsupported inner-Ethernet matrix

When the outer Geneve header is otherwise valid and the inner Ethernet
EtherType is one of the following:

- ARP `0x0806`
- PPPoE Session `0x8864`
- MPLS unicast `0x8847`
- PBB `0x88e7`
- MACsec `0x88e5`
- unknown asymmetric EtherType `0x1234`

current production flow extraction does not persist `Geneve(vni=...)` into the
final flow identity for any of these packets.

The exact current production outcome is:

| Inner EtherType | Flow result | Geneve/VNI path committed | Inner Ethernet committed | Deeper best-effort details |
| --- | --- | --- | --- | --- |
| ARP `0x0806` | ordinary outer UDP fallback flow | no | no | Geneve + inner Ethernet header only |
| PPPoE Session `0x8864` | ordinary outer UDP fallback flow | no | no | inner IPv4/UDP can still appear in selected-packet details |
| MPLS unicast `0x8847` | ordinary outer UDP fallback flow | no | no | inner IPv4/UDP can still appear in selected-packet details |
| PBB `0x88e7` | ordinary outer UDP fallback flow | no | no | inner IPv4/UDP can still appear in selected-packet details |
| MACsec `0x88e5` | ordinary outer UDP fallback flow | no | no | Geneve + inner Ethernet header only |
| unknown `0x1234` | ordinary outer UDP fallback flow | no | no | Geneve + inner Ethernet header only |

Additional contract details for this matrix:

- no case fabricates inner endpoints or ports into flow identity;
- `ProtocolPathRegistry` grows only by the single outer fallback path
  `EthernetII -> IPv4 -> UDP`;
- selected-packet details keep the outer Geneve layer visible, but do not
  surface nested PPPoE/MPLS/PBB/MACsec path layers inside Geneve.

## Nested overlay non-recursion

Current committed fixtures explicitly pin the non-recursive Geneve behavior for:

- Geneve -> inner IPv4/UDP -> Geneve-like UDP/6081
- Geneve -> inner IPv4/UDP -> VXLAN-like UDP/4789
- Geneve -> inner IPv4/UDP -> GTP-U-like UDP/2152

The exact current production rule is:

- the accepted first Geneve layer remains present in the path;
- the final flow is the inner UDP carrier flow;
- no second Geneve/VXLAN/GTP-U path layer is added;
- no second VNI or GTP-U TEID identity is recovered.

For these packets the final path remains:

- `EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> UDP`

## Fixture 28 exact declared-bounds contract

`28_geneve_udp_declared_bounds_matrix.pcap` is fixed to the following current
production behavior:

- session summary packet count: `3`
- unrecognized packet count: `1`
- flow rows: `3`

Per packet:

| Packet index | Outer IPv4 Total Length | UDP Length | Captured Length | Geneve header reachable | Geneve details available | Flow result | Unrecognized result | Physical path |
| --- | ---: | ---: | ---: | --- | --- | --- | --- | --- |
| `0` | `92` | `16` | `106` | yes, exact 8-byte header only | yes | ordinary outer UDP fallback flow | no | `EthernetII -> IPv4 -> UDP` |
| `1` | `40` | `20` | `54` | yes, but declared options overrun bounded UDP payload | yes | ordinary outer UDP fallback flow | no | `EthernetII -> IPv4 -> UDP` |
| `2` | `36` | `72` | `106` | no usable Geneve reachability after top-level UDP declared-bounds failure | no | no flow | yes | none committed |
| `3` | `92` | `72` | `106` | yes | yes | recognized inner TCP flow | no | `EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> TCP` |

Packet `2` is the important negative control:

- outer IPv4 details are still available;
- Geneve details are absent;
- the packet lands in the unrecognized list;
- no Geneve/VNI path is committed.

## Generator note

These fixtures were generated deterministically during branch development, but
no local generator is kept in the tree after this fixture pass.
