Synthetic VXLAN regression fixtures that define the exact current production `PacketDecoder` contract.

This directory is production-fixture coverage only. It does not imply that shadow VXLAN dissection exists.

## Production contract summary

Current production VXLAN behavior is:

- entry is UDP destination port `4789` only;
- UDP destination `8472`, source-only `4789`, and other ports remain ordinary UDP;
- strict flow extraction requires a full 8-byte VXLAN header with:
  - flags byte exactly `0x08`;
  - reserved bytes 1..3 equal to `0x00`;
  - trailing reserved byte equal to `0x00`;
- VNI is parsed as big-endian 24-bit bytes 4..6;
- VNI participates in `ProtocolPath` identity;
- successful strict continuation uses:
  - outer link / VLAN context;
  - outer IPv4 or IPv6;
  - outer UDP;
  - `VXLAN(vni=...)`;
  - inner Ethernet continuation;
- strict inner-flow extraction continues only when inner traversal bottoms out in IPv4 or IPv6 plus TCP/UDP/SCTP;
- fragmented outer IPv4 and fragmented outer IPv6 do not produce VXLAN inner flows;
- selected-packet details are intentionally more lenient than flow extraction and may still show bounded VXLAN metadata or partial inner warnings on UDP/4789 packets.

## Regeneration policy

- Existing committed fixtures are the source of truth.
- Do not regenerate existing binaries unless a structural defect is proven.
- Temporary deterministic generators may be created under `tmp/`, run locally, and then removed.

## Fixture classification

Existing fixtures `01` through `16` are reusable.

- `01` to `04`, `10` to `16`: complete and reusable.
- `05` to `09`: reusable and now covered by stronger assertions.

New fixtures `17` through `30` were added to close migration-critical gaps for:

- UDP port entry rules;
- outer carrier reachability;
- outer fragmentation;
- UDP declared-bound behavior;
- supported versus visible-only inner continuations;
- unsupported inner continuations;
- nested-overlay negatives;
- caplen/origlen truncation;
- byte-order-proof VNI identity.

## Per-fixture contract

### 01_vxlan_inner_ipv4_tcp.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53000 -> 4789`, UDP length `84`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Decoded VNI: `100`.
- Inner: EthernetII -> IPv4 -> TCP, `10.40.0.10:49440 -> 10.40.0.20:443`.
- Bounds: captured length = original length = `118`.
- Outcome: one recognized inner TCP flow, `ProtocolId::tcp`.
- Path: `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP`.
- Purpose: baseline successful inner IPv4/TCP continuation.

### 02_vxlan_inner_ipv4_udp.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53001 -> 4789`, UDP length `72`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Decoded VNI: `100`.
- Inner: EthernetII -> IPv4 -> UDP, `10.40.0.10:53540 -> 10.40.0.20:443`.
- Bounds: captured length = original length = `106`.
- Outcome: one recognized inner UDP flow, `ProtocolId::udp`.
- Path: `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP`.
- Purpose: baseline successful inner IPv4/UDP continuation.

### 03_vxlan_inner_ipv6_tcp.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53002 -> 4789`, UDP length `104`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Decoded VNI: `100`.
- Inner: EthernetII -> IPv6 -> TCP, `2001:db8:40::10:49440 -> 2001:db8:40::20:443`.
- Bounds: captured length = original length = `138`.
- Outcome: one recognized inner TCP flow, `ProtocolId::tcp`.
- Path: `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> TCP`.
- Purpose: baseline successful inner IPv6/TCP continuation.

### 04_vxlan_inner_ipv6_udp.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53003 -> 4789`, UDP length `92`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Decoded VNI: `100`.
- Inner: EthernetII -> IPv6 -> UDP, `2001:db8:40::10:53540 -> 2001:db8:40::20:443`.
- Bounds: captured length = original length = `126`.
- Outcome: one recognized inner UDP flow, `ProtocolId::udp`.
- Path: `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> UDP`.
- Purpose: baseline successful inner IPv6/UDP continuation.

### 05_vxlan_truncated_header.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53004 -> 4789`, UDP length `14`.
- VXLAN bytes available: `6 / 8`.
- Inner: none.
- Bounds: captured length = original length = `48`.
- Outcome: no inner flow; warning-oriented packet details only.
- Path: no committed VXLAN inner path.
- Purpose: fixed-header truncation below 8 bytes.

### 06_vxlan_invalid_flags_or_reserved_bits.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53005 -> 4789`, UDP length `72`.
- VXLAN header bytes: `00 00 00 00 00 00 64 00`.
- Decoded VNI: `100`.
- Inner: bounded inner Ethernet / IPv4 / UDP may remain visible in packet details.
- Bounds: captured length = original length = `106`.
- Outcome: no inner flow; invalid VXLAN warning in details.
- Path: no committed VXLAN inner path.
- Purpose: I-flag-clear negative control.

### 07_vxlan_truncated_inner_ethernet.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53006 -> 4789`, UDP length `25`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Decoded VNI: `100`.
- Inner: fewer than 14 bytes of inner Ethernet.
- Bounds: captured length = original length = `59`.
- Outcome: no inner flow; truncated inner Ethernet warning.
- Path: no committed VXLAN inner path.
- Purpose: bounded inner Ethernet truncation.

### 08_vxlan_truncated_inner_ipv4.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53007 -> 4789`, UDP length `40`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Decoded VNI: `100`.
- Inner: complete Ethernet header, truncated IPv4 child.
- Bounds: captured length = original length = `74`.
- Outcome: no inner flow; bounded inner IPv4 warning.
- Path: no committed VXLAN inner path.
- Purpose: bounded inner IPv4 truncation.

### 09_vxlan_unsupported_inner_ethertype.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53008 -> 4789`, UDP length `55`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Decoded VNI: `100`.
- Inner: EthernetII with unsupported EtherType `0x88b5`.
- Bounds: captured length = original length = `89`.
- Outcome: no inner flow.
- Path: no committed VXLAN inner path.
- Purpose: known inner-EtherType unsupported branch.

### 10_vxlan_same_inner_tuple_different_vni.pcap

- Outer: two EthernetII / IPv4 / UDP / VXLAN packets, UDP `53009 -> 4789` and `53010 -> 4789`.
- VXLAN headers:
  - packet 0: `08 00 00 00 00 00 64 00`, VNI `100`;
  - packet 1: `08 00 00 00 00 00 c8 00`, VNI `200`.
- Inner: same EthernetII -> IPv4 -> TCP tuple `10.40.0.10:49440 -> 10.40.0.20:443`.
- Outcome: two distinct recognized TCP flows.
- Path:
  - `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP`
  - `EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4 -> TCP`
- Purpose: prove VNI splits otherwise-identical inner tuples.

### 11_vxlan_inner_ipv4_tcp_bidirectional.pcap

- Outer: two EthernetII / IPv4 / UDP / VXLAN packets on UDP `53011 -> 4789` and `53012 -> 4789`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Inner: bidirectional IPv4/TCP tuple between `10.40.0.10:49440` and `10.40.0.20:443`.
- Outcome: one recognized TCP flow with two packets.
- Path: `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP`.
- Purpose: prove bidirectional grouping still happens on the inner tuple.

### 12_vxlan_same_outer_tuple_different_inner_flows.pcap

- Outer: same EthernetII / IPv4 / UDP carrier tuple `203.0.113.40:53013 -> 203.0.113.41:4789`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Inner: two different IPv4/TCP flows:
  - `10.40.0.10:10001 -> 10.40.0.20:443`
  - `10.40.0.10:10002 -> 10.40.0.20:443`
- Outcome: two recognized TCP flows.
- Path: identical physical path except for the terminal inner ports.
- Purpose: outer carrier tuple does not define the final flow.

### 13_vxlan_inner_vlan_ipv4_tcp.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53014 -> 4789`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Inner: EthernetII -> VLAN `140` -> IPv4 -> TCP, `10.40.0.10:49440 -> 10.40.0.20:443`.
- Outcome: one recognized TCP flow.
- Path: `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=140) -> IPv4 -> TCP`.
- Purpose: supported inner single-VLAN continuation.

### 14_vxlan_outer_ipv6_inner_ipv4_tcp.pcap

- Outer: EthernetII, IPv6 `2001:db8:40:1::1 -> 2001:db8:40:1::2`, UDP `53015 -> 4789`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Inner: EthernetII -> IPv4 -> TCP, `10.40.0.10:49440 -> 10.40.0.20:443`.
- Outcome: one recognized TCP flow.
- Path: `EthernetII -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP`.
- Purpose: outer IPv6 carriage reaches VXLAN and inner IPv4.

### 15_vxlan_wrong_udp_port_valid_vxlan_payload.pcap

- Outer: EthernetII, IPv4 `203.0.113.40 -> 203.0.113.41`, UDP `53016 -> 4799`.
- Payload bytes begin with an otherwise-valid VXLAN header for VNI `100`.
- Inner: EthernetII -> IPv4 -> TCP bytes are present but must not be used.
- Outcome: no VXLAN recognition; no inner flow.
- Path: ordinary outer UDP only if grouped.
- Purpose: wrong-destination-port negative control.

### 16_vxlan_vni_boundary_values.pcap

- Outer: two EthernetII / IPv4 / UDP / VXLAN packets on UDP `53017 -> 4789` and `53018 -> 4789`.
- VXLAN headers:
  - packet 0: VNI bytes `00 00 00`, decoded VNI `0`;
  - packet 1: VNI bytes `ff ff ff`, decoded VNI `16777215`.
- Inner:
  - packet 0: IPv4/TCP `10.40.0.10:49440 -> 10.40.0.20:443`;
  - packet 1: IPv4/TCP `10.40.0.11:10001 -> 10.40.0.21:443`.
- Outcome: both packets remain valid recognized flows.
- Purpose: prove VNI boundary values are accepted and preserved.

### 17_vxlan_udp_port_and_header_matrix.pcap

- Fixture type: six-packet entry-rule matrix.
- Common outer envelope: EthernetII / IPv4 `203.0.113.40 -> 203.0.113.41`.
- Packet contracts:
  - packet 0: UDP `53170 -> 4789`, header `08 00 00 00 00 00 64 00`, valid inner IPv4/TCP, recognized inner TCP flow, path `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP`.
  - packet 1: UDP `53171 -> 8472`, same VXLAN-looking bytes, remains plain outer UDP flow, path `EthernetII -> IPv4 -> UDP`.
  - packet 2: UDP `4789 -> 4799`, source-only VXLAN port, remains plain outer UDP flow, path `EthernetII -> IPv4 -> UDP`.
  - packet 3: UDP `53172 -> 4789`, header `00 00 00 00 00 00 64 00`, details show invalid VXLAN, flow falls back to outer UDP.
  - packet 4: UDP `53173 -> 4789`, header flags `0x88`, details show invalid VXLAN, flow falls back to outer UDP.
  - packet 5: UDP `53174 -> 4789`, valid-looking flags with non-zero reserved bytes, details warn, flow falls back to outer UDP.
- Purpose: exact entry-port and header-validation gate.

### 18_vxlan_outer_tagged_contexts.pcap

- Fixture type: three-packet outer-carrier reachability matrix.
- Packet contracts:
  - packet 0: EthernetII -> VLAN `201` -> IPv4, UDP `53180 -> 4789`, inner IPv4/UDP `10.50.0.10:55010 -> 10.50.0.20:8080`, path `EthernetII -> VLAN(vid=201) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP`.
  - packet 1: EthernetII -> VLAN `401` -> VLAN `402` -> IPv6, UDP `53181 -> 4789`, inner IPv6/TCP `2001:db8:40::10:55011 -> 2001:db8:40::20:8443`, path `EthernetII -> VLAN(vid=401) -> VLAN(vid=402) -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> TCP`.
  - packet 2: EthernetII -> legacy VLAN-like `0x9100` / VLAN `501` -> IPv4, UDP `53182 -> 4789`, inner IPv4/TCP `10.50.0.11:55012 -> 10.50.0.21:9443`, path `EthernetII -> VLAN(vid=501) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP`.
- Purpose: supported outer VLAN/QinQ/0x9100 reachability.

### 19_vxlan_outer_ipv6_inner_ipv6_udp.pcap

- Outer: EthernetII -> IPv6 `2001:db8:40:1::1 -> 2001:db8:40:1::2`, UDP `53190 -> 4789`, UDP length `82`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Inner: EthernetII -> IPv6 -> UDP, `2001:db8:40::10:55020 -> 2001:db8:40::20:53`.
- Outcome: one recognized UDP flow.
- Path: `EthernetII -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> UDP`.
- Purpose: supported outer IPv6 + inner IPv6 path.

### 20_vxlan_linux_sll_ipv4_inner_ipv4_udp.pcap

- Outer: Linux cooked v1 (`linktype 113`) -> IPv4 `203.0.113.60 -> 203.0.113.61`, UDP `53200 -> 4789`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Inner: EthernetII -> IPv4 -> UDP, `10.60.0.10:55030 -> 10.60.0.20:1234`.
- Outcome: one recognized UDP flow.
- Path: `LinuxSll -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP`.
- Purpose: Linux cooked outer reachability.

### 21_vxlan_linux_sll2_ipv6_inner_ipv6_udp.pcap

- Outer: Linux cooked v2 (`linktype 276`) -> IPv6 `2001:db8:40:1::1 -> 2001:db8:40:1::2`, UDP `53210 -> 4789`.
- VXLAN header bytes: `08 00 00 00 00 00 64 00`.
- Inner: EthernetII -> IPv6 -> UDP, `2001:db8:40::10:55031 -> 2001:db8:40::20:5353`.
- Outcome: one recognized UDP flow.
- Path: `LinuxSll2 -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> UDP`.
- Purpose: Linux SLL2 outer reachability.

### 22_vxlan_identity_outer_carrier_variation_same_flow.pcap

- Fixture type: four packets with one inner tuple and constant VNI `100`.
- Outer carriers vary by source/destination outer IPv4 and UDP source port:
  - `203.0.113.70 -> 203.0.113.71`, UDP `53220 -> 4789`
  - `203.0.113.72 -> 203.0.113.73`, UDP `53220 -> 4789`
  - `203.0.113.70 -> 203.0.113.71`, UDP `53221 -> 4789`
  - `203.0.113.72 -> 203.0.113.73`, UDP `53222 -> 4789`
- Inner: same IPv4/TCP tuple `10.70.0.10:56000 -> 10.70.0.20:443`.
- Outcome: one recognized TCP flow with four packets and one protocol-path id.
- Purpose: outer carrier endpoints and outer UDP source port do not participate in current VXLAN flow identity.

### 23_vxlan_identity_outer_and_inner_vlan_splits.pcap

- Fixture type: four packets with four distinct physical paths.
- Packet contracts:
  - packet 0: outer VLAN `141`, inner plain IPv4/TCP `10.71.0.10:56010 -> 10.71.0.20:443`.
  - packet 1: outer VLAN `142`, same inner tuple as packet 0.
  - packet 2: no outer VLAN, inner VLAN `200`, inner IPv4/TCP `10.71.0.10:56011 -> 10.71.0.20:443`.
  - packet 3: no outer VLAN, inner VLAN `201`, same inner tuple as packet 2.
- Outcome: four one-packet recognized TCP flows.
- Paths:
  - `EthernetII -> VLAN(vid=141) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP`
  - `EthernetII -> VLAN(vid=142) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP`
  - `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=200) -> IPv4 -> TCP`
  - `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=201) -> IPv4 -> TCP`
- Purpose: both outer and inner VLAN metadata affect `ProtocolPath` identity.

### 24_vxlan_outer_ipv4_fragmentation.pcap

- Fixture type: four-packet outer IPv4 fragmentation matrix.
- Packet contracts:
  - packet 0: first fragment, MF set, offset `0`, bytes still contain UDP/VXLAN-looking data.
  - packet 1: non-first fragment, MF set, offset `2`.
  - packet 2: final non-first fragment, offset `4`.
  - packet 3: capture-truncated fragment.
- Outcome:
  - packets 0..2 group into one fragmented outer UDP flow shell only;
  - truncated fragment stays unrecognized;
  - no VXLAN inner flow is recovered.
- Path: grouped flow path is `EthernetII -> IPv4`.
- Purpose: fragmented outer IPv4 does not enter VXLAN strict decoding.

### 25_vxlan_outer_ipv6_fragmentation.pcap

- Fixture type: four-packet outer IPv6 fragmentation matrix.
- Packet contracts:
  - packet 0: fragment header with offset `0`;
  - packet 1: non-zero fragment offset;
  - packet 2: final fragment;
  - packet 3: truncated outer IPv6/fragment case.
- Outcome:
  - packets 0..2 group into one fragmented outer UDP flow shell only;
  - truncated packet stays unrecognized;
  - no VXLAN inner flow is recovered.
- Path: grouped flow path is `EthernetII -> IPv6`.
- Purpose: fragmented outer IPv6 does not enter VXLAN strict decoding.

### 26_vxlan_udp_declared_bounds_matrix.pcap

- Fixture type: four-packet UDP/enclosing-bound matrix.
- Packet contracts:
  - packet 0: UDP `53260 -> 4789`, declared UDP length `81`, full VXLAN header plus bounded inner IPv4/TCP are visible, producing the inner flow `10.74.0.10:56040 -> 10.74.0.20:443`.
  - packet 1: UDP `53261 -> 4789`, declared UDP length `16`, exactly full VXLAN header and no inner frame, outer UDP fallback flow.
  - packet 2: UDP `53262 -> 4789`, UDP length is shorter than captured trailing bytes, but the declared UDP window still contains a complete inner IPv4/TCP flow `10.74.0.11:56041 -> 10.74.0.21:443`; bytes beyond the declared UDP end are ignored.
  - packet 3: UDP `53263 -> 4789`, another full bounded inner IPv4/TCP packet matching packet 0, so it merges into the same inner TCP flow despite a different outer UDP source port.
- Outcome: three recognized flows and zero unrecognized packets:
  - one merged inner TCP flow with packets 0 and 3;
  - one outer UDP fallback flow for packet 1;
  - one inner TCP flow for packet 2.
- Purpose: bytes beyond effective UDP or outer-IP declared bounds must not be used for VNI or inner recovery.

### 27_vxlan_inner_supported_and_visible_matrix.pcap

- Fixture type: three-packet inner-continuation profile matrix.
- Packet contracts:
  - packet 0: inner ARP behind valid VXLAN, visible in packet details but not a strict inner VXLAN flow, outer UDP fallback flow `203.0.113.92:53270 -> 203.0.113.93:4789`.
  - packet 1: inner EthernetII -> QinQ `551/552` -> IPv6 -> TCP `2001:db8:40::10:56050 -> 2001:db8:40::20:443`, recognized inner TCP flow.
  - packet 2: inner IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP `10.75.0.11:56051 -> 10.75.0.21:69`, recognized inner UDP flow.
- Paths:
  - fallback: `EthernetII -> IPv4 -> UDP`
  - QinQ flow: `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=551) -> VLAN(vid=552) -> IPv6 -> TCP`
  - LLC/SNAP flow: `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP`
- Purpose: distinguish supported inner continuation from visible-only recognized-non-flow continuation.

### 28_vxlan_unsupported_and_nested_matrix.pcap

- Fixture type: eight-packet unsupported/nested-overlay matrix.
- Outer carrier: EthernetII / IPv4 `203.0.113.94 -> 203.0.113.95`, UDP destination `4789`, VNI `100`.
- Packets 0..4: unsupported inner continuations that all fall back to ordinary outer UDP flows:
  - inner PPPoE-like payload;
  - inner MPLS-like payload;
  - inner PBB-like payload;
  - unknown inner EtherType;
  - other unsupported bounded case.
- Packets 5..7: inner IPv4/UDP payloads whose destination ports look like overlays:
  - packet 5: inner UDP destination `4789`;
  - packet 6: inner UDP destination `6081`;
  - packet 7: inner UDP destination `2152`.
- Outcome:
  - packets 0..4: plain outer UDP flows only;
  - packets 5..7: recognized inner UDP flows, but no recursive VXLAN/Geneve/GTP-U decapsulation.
- Paths for packets 5..7: `EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP`.
- Purpose: no nested overlay recursion in current production VXLAN continuation.

### 29_vxlan_capture_truncation_matrix.pcap

- Fixture type: four-packet caplen/origlen truncation matrix.
- Common outer carrier: EthernetII / IPv4 `203.0.113.96 -> 203.0.113.97`.
- Packet contracts:
  - packet 0: capture ends before UDP header, no UDP, no VXLAN, unrecognized.
  - packet 1: UDP `53291 -> 4789`, origlen longer than caplen, only `4 / 8` VXLAN bytes captured, outer UDP fallback flow with VXLAN header-truncated details.
  - packet 2: UDP `53292 -> 4789`, full VXLAN header but truncated inner Ethernet header, outer UDP fallback flow.
  - packet 3: UDP `53293 -> 4789`, full VXLAN header and inner Ethernet header, truncated inner IPv4 child, outer UDP fallback flow with `vxlan.inner_packet.ipv4.header_truncated`.
- Outcome: three outer UDP flows plus one unrecognized packet.
- Purpose: genuine capture truncation at outer UDP, VXLAN, inner Ethernet, and inner IPv4 boundaries.

### 30_vxlan_vni_byte_order_distinct_values.pcap

- Outer: two EthernetII / IPv4 / UDP / VXLAN packets:
  - packet 0: UDP `53300 -> 4789`, VNI bytes `01 02 03`, decoded VNI `66051`;
  - packet 1: UDP `53301 -> 4789`, VNI bytes `03 02 01`, decoded VNI `197121`.
- Inner: same IPv4/TCP tuple `10.78.0.10:56080 -> 10.78.0.20:443`.
- Outcome: two distinct recognized TCP flows.
- Paths:
  - `EthernetII -> IPv4 -> UDP -> VXLAN(vni=66051) -> EthernetII -> IPv4 -> TCP`
  - `EthernetII -> IPv4 -> UDP -> VXLAN(vni=197121) -> EthernetII -> IPv4 -> TCP`
- Purpose: explicit big-endian 24-bit VNI byte-order proof.

## Expected file list

- `01_vxlan_inner_ipv4_tcp.pcap`
- `02_vxlan_inner_ipv4_udp.pcap`
- `03_vxlan_inner_ipv6_tcp.pcap`
- `04_vxlan_inner_ipv6_udp.pcap`
- `05_vxlan_truncated_header.pcap`
- `06_vxlan_invalid_flags_or_reserved_bits.pcap`
- `07_vxlan_truncated_inner_ethernet.pcap`
- `08_vxlan_truncated_inner_ipv4.pcap`
- `09_vxlan_unsupported_inner_ethertype.pcap`
- `10_vxlan_same_inner_tuple_different_vni.pcap`
- `11_vxlan_inner_ipv4_tcp_bidirectional.pcap`
- `12_vxlan_same_outer_tuple_different_inner_flows.pcap`
- `13_vxlan_inner_vlan_ipv4_tcp.pcap`
- `14_vxlan_outer_ipv6_inner_ipv4_tcp.pcap`
- `15_vxlan_wrong_udp_port_valid_vxlan_payload.pcap`
- `16_vxlan_vni_boundary_values.pcap`
- `17_vxlan_udp_port_and_header_matrix.pcap`
- `18_vxlan_outer_tagged_contexts.pcap`
- `19_vxlan_outer_ipv6_inner_ipv6_udp.pcap`
- `20_vxlan_linux_sll_ipv4_inner_ipv4_udp.pcap`
- `21_vxlan_linux_sll2_ipv6_inner_ipv6_udp.pcap`
- `22_vxlan_identity_outer_carrier_variation_same_flow.pcap`
- `23_vxlan_identity_outer_and_inner_vlan_splits.pcap`
- `24_vxlan_outer_ipv4_fragmentation.pcap`
- `25_vxlan_outer_ipv6_fragmentation.pcap`
- `26_vxlan_udp_declared_bounds_matrix.pcap`
- `27_vxlan_inner_supported_and_visible_matrix.pcap`
- `28_vxlan_unsupported_and_nested_matrix.pcap`
- `29_vxlan_capture_truncation_matrix.pcap`
- `30_vxlan_vni_byte_order_distinct_values.pcap`
