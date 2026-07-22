Synthetic production-contract fixtures for current GTP-U behavior.

This directory defines the exact production `PacketDecoder` contract for GTP-U on
branch `feature/unified-packet-dissection`.

This is not a 3GPP feature matrix. The source of truth is current production
decoding plus production fixture tests.

## Exact production rules captured here

- GTP-U candidacy is considered only on UDP destination port `2152`.
- UDP source-port-only `2152` is not enough.
- `src=2152,dst=2152` is accepted because destination-port gating matches.
- Non-`2152` UDP stays ordinary outer UDP even if the payload bytes look like GTP-U.
- Current production path order for UDP overlays is destination-port based:
  - VXLAN `4789`
  - Geneve `6081`
  - GTP-U `2152`
  - otherwise ordinary UDP
- Production GTP-U flow continuation currently supports only direct inner IPv4 or
  direct inner IPv6 payloads.
- Inner Ethernet is not supported for GTP-U.
- Nested overlay-looking inner UDP does not recurse into VXLAN, Geneve, or GTP-U
  again; it terminates as inner UDP.
- GTP-U base-header acceptance currently requires:
  - fixed 8-byte header available inside effective UDP bounds;
  - version `1`;
  - PT bit set;
  - message type `0xff` T-PDU;
  - declared GTP length fully bounded inside the effective UDP payload.
- The 16-bit GTP length field is interpreted as the number of bytes after the
  first 8 bytes of the GTP-U base header.
- TEID is big-endian and participates in protocol-path-aware flow identity.
- The reserved flag bit is currently tolerated and does not affect identity.
- If any of `E`, `S`, or `PN` is set, production expects the full common
  4-byte optional block:
  - sequence number, 2 bytes, big-endian;
  - N-PDU number, 1 byte;
  - next-extension-header type, 1 byte.
- If `E=1`, production bounded-skips an extension-header chain:
  - extension length unit is `length_byte * 4`;
  - total extension header length must be at least 2 bytes;
  - the last byte of each extension block is treated as the next-extension-header type;
  - traversal stops when the next-extension-header type becomes `0x00`;
  - malformed or truncated chains prevent inner-flow continuation.
- GTP-U control/non-T-PDU messages currently do not create inner flows.
- For many malformed or unsupported UDP/2152 cases, production still keeps the
  packet as an ordinary outer UDP flow while selected-packet details can show
  lenient GTP-U warnings.
- Outer IPv4/IPv6 fragmentation blocks GTP-U continuation and leaves only the
  outer fragmentation-shell flow path:
  - `EthernetII -> IPv4`
  - `EthernetII -> IPv6`
- Carrier contexts currently exercised here:
  - Ethernet II + IPv4/IPv6
  - outer VLAN
  - outer QinQ
  - outer legacy VLAN TPID `0x9100`
  - Linux cooked SLL
  - Linux cooked SLL2

## Shared constants

- Outer source MAC: `02:00:00:00:60:01`
- Outer destination MAC: `02:00:00:00:60:02`
- Outer source IPv4: `203.0.113.60`
- Outer destination IPv4: `203.0.113.61`
- Outer source IPv6: `2001:db8:60:1::1`
- Outer destination IPv6: `2001:db8:60:1::2`
- Default T-PDU TEID: `0x01020304`
- Default inner IPv4 source/destination: `10.60.0.10 -> 10.60.0.20`
- Default inner IPv6 source/destination:
  `2001:db8:60::10 -> 2001:db8:60::20`

## Fixture contract

### 01_gtpu_inner_ipv4_tcp.pcap

- Outer: EthernetII / IPv4 / UDP `55000 -> 2152`
- GTP-U: flags `0x30`, version `1`, PT set, T-PDU, TEID `0x01020304`
- Inner: IPv4 / TCP `10.60.0.10:49660 -> 10.60.0.20:443`
- Outcome: one recognized inner TCP flow
- Physical path:
  `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP`
- Purpose: basic positive IPv4/TCP continuation

### 02_gtpu_inner_ipv4_udp.pcap

- Outer: EthernetII / IPv4 / UDP `55001 -> 2152`
- GTP-U: flags `0x30`, T-PDU, TEID `0x01020304`
- Inner: IPv4 / UDP `10.60.0.10:53760 -> 10.60.0.20:443`
- Outcome: one recognized inner UDP flow
- Physical path:
  `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> UDP`
- Purpose: basic positive IPv4/UDP continuation

### 03_gtpu_inner_ipv6_tcp.pcap

- Outer: EthernetII / IPv4 / UDP `55002 -> 2152`
- GTP-U: flags `0x30`, T-PDU, TEID `0x01020304`
- Inner: IPv6 / TCP
- Outcome: one recognized inner IPv6/TCP flow
- Physical path:
  `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv6 -> TCP`
- Purpose: direct inner IPv6/TCP continuation

### 04_gtpu_inner_ipv6_udp.pcap

- Outer: EthernetII / IPv4 / UDP `55003 -> 2152`
- GTP-U: flags `0x30`, T-PDU, TEID `0x01020304`
- Inner: IPv6 / UDP
- Outcome: one recognized inner IPv6/UDP flow
- Physical path:
  `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv6 -> UDP`
- Purpose: direct inner IPv6/UDP continuation

### 05_gtpu_truncated_base_header.pcap

- Outer: EthernetII / IPv4 / UDP `55004 -> 2152`
- GTP-U: fewer than 8 visible bytes
- Outcome: no inner flow; ordinary outer UDP flow remains
- Physical path: `EthernetII -> IPv4 -> UDP`
- Packet-details behavior: lenient GTP-U layer with truncated-header warning
- Purpose: base-header capture truncation

### 06_gtpu_invalid_version.pcap

- Outer: EthernetII / IPv4 / UDP `55005 -> 2152`
- GTP-U: version `2`, PT set, T-PDU, TEID `0x01020304`
- Outcome: no inner flow; ordinary outer UDP flow remains
- Physical path: `EthernetII -> IPv4 -> UDP`
- Packet-details behavior: GTP-U warning for unsupported version
- Purpose: exact version gate

### 07_gtpu_unsupported_message_type.pcap

- Outer: EthernetII / IPv4 / UDP `55006 -> 2152`
- GTP-U: version `1`, PT set, message type `0x01` Echo Request
- Outcome: no inner flow; ordinary outer UDP flow remains
- Physical path: `EthernetII -> IPv4 -> UDP`
- Packet-details behavior: GTP-U warning for unsupported message type
- Purpose: non-T-PDU control-message fallback

### 08_gtpu_truncated_inner_ipv4.pcap

- Outer: EthernetII / IPv4 / UDP `55007 -> 2152`
- GTP-U: valid base header, TEID `0x01020304`
- Inner: IPv4-looking payload truncated inside GTP bounds
- Outcome: no inner flow; ordinary outer UDP flow remains
- Physical path: `EthernetII -> IPv4 -> UDP`
- Packet-details behavior: visible inner IPv4 warning
- Purpose: bounded inner IPv4 truncation

### 09_gtpu_truncated_inner_ipv6.pcap

- Outer: EthernetII / IPv4 / UDP `55008 -> 2152`
- GTP-U: valid base header, TEID `0x01020304`
- Inner: IPv6-looking payload truncated inside GTP bounds
- Outcome: no inner flow; ordinary outer UDP flow remains
- Physical path: `EthernetII -> IPv4 -> UDP`
- Packet-details behavior: visible inner IPv6 warning
- Purpose: bounded inner IPv6 truncation

### 10_gtpu_unknown_inner_payload.pcap

- Outer: EthernetII / IPv4 / UDP `55009 -> 2152`
- GTP-U: valid base header, TEID `0x01020304`
- Inner: first nibble is neither IPv4 nor IPv6
- Outcome: no inner flow; ordinary outer UDP flow remains
- Physical path: `EthernetII -> IPv4 -> UDP`
- Packet-details behavior: GTP-U warning for unknown inner payload
- Purpose: exact direct-inner-IP profile boundary

### 11_gtpu_inner_ipv4_tcp_bidirectional.pcap

- Outer: two EthernetII / IPv4 / UDP / GTP-U packets
- GTP-U: same TEID `0x01020304`
- Inner: reverse-direction IPv4/TCP packets for the same tuple
- Outcome: one bidirectional TCP flow, two packets
- Physical path:
  `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP`
- Purpose: bidirectional inner flow grouping

### 12_gtpu_same_outer_tuple_different_inner_flows.pcap

- Outer: same outer UDP tuple on both packets
- GTP-U: same TEID `0x01020304`
- Inner: two different IPv4/TCP source ports
- Outcome: two distinct inner TCP flows
- Physical path:
  `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP`
- Purpose: inner tuple dominates over outer UDP tuple

### 13_gtpu_outer_ipv6_inner_ipv4_tcp.pcap

- Outer: EthernetII / IPv6 / UDP `55013 -> 2152`
- GTP-U: T-PDU, TEID `0x01020304`
- Inner: IPv4 / TCP
- Outcome: one recognized inner IPv4/TCP flow
- Physical path:
  `EthernetII -> IPv6 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP`
- Purpose: outer IPv6 carrier reachability

### 14_gtpu_wrong_udp_port_valid_gtpu_payload.pcap

- Outer: EthernetII / IPv4 / UDP `55014 -> 2162`
- Payload: bytes otherwise resembling valid GTP-U
- Outcome: ordinary outer UDP flow only
- Physical path: `EthernetII -> IPv4 -> UDP`
- Packet-details behavior: no GTP-U layer at all
- Purpose: strict UDP destination-port gate

### 15_gtpu_teid_boundary_values.pcap

- Outer: EthernetII / IPv4 / UDP `55015 -> 2152`, `55016 -> 2152`
- GTP-U TEIDs:
  - `0x00000000`
  - `0xffffffff`
- Inner: distinct IPv4/TCP tuples
- Outcome: both recognized; both TEID boundary values accepted
- Physical paths:
  - `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x00000000) -> IPv4 -> TCP`
  - `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0xffffffff) -> IPv4 -> TCP`
- Purpose: TEID byte-order and boundary acceptance

### 16_gtpu_with_sequence_inner_ipv4_tcp.pcap

- Outer: EthernetII / IPv4 / UDP `55017 -> 2152`
- GTP-U: `S=1`, sequence `0x1234`
- Outcome: recognized inner TCP flow
- Physical path:
  `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP`
- Packet-details behavior: sequence number visible
- Purpose: optional-block `S` handling

### 17_gtpu_with_npdu_inner_ipv4_tcp.pcap

- Outer: EthernetII / IPv4 / UDP `55018 -> 2152`
- GTP-U: `PN=1`, N-PDU `0x5a`
- Outcome: recognized inner TCP flow
- Physical path:
  `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP`
- Packet-details behavior: N-PDU number visible
- Purpose: optional-block `PN` handling

### 18_gtpu_with_extension_header_inner_ipv4_tcp.pcap

- Outer: EthernetII / IPv4 / UDP `55019 -> 2152`
- GTP-U: `E=1`, optional next-extension-header type `0x85`
- Extension chain: one minimal 4-byte block `01 de ad 00`
- Outcome: recognized inner TCP flow
- Physical path:
  `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP`
- Packet-details behavior: extension type and skipped-byte count visible
- Purpose: bounded extension-chain skip

### 19_gtpu_truncated_optional_header.pcap

- Outer: EthernetII / IPv4 / UDP `55020 -> 2152`
- GTP-U: one of `E/S/PN` implies optional block, but the 4-byte block is incomplete
- Outcome: no inner flow; ordinary outer UDP flow remains
- Physical path: `EthernetII -> IPv4 -> UDP`
- Packet-details behavior: optional-header truncated warning
- Purpose: optional-block truncation

### 20_gtpu_truncated_extension_header.pcap

- Outer: EthernetII / IPv4 / UDP `55021 -> 2152`
- GTP-U: optional block present; extension chain incomplete
- Outcome: no inner flow; ordinary outer UDP flow remains
- Physical path: `EthernetII -> IPv4 -> UDP`
- Packet-details behavior: extension-chain truncated warning
- Purpose: bounded extension truncation

### 21_gtpu_same_inner_tuple_different_teid.pcap

- Outer: two EthernetII / IPv4 / UDP / GTP-U packets
- Inner: same IPv4/TCP tuple on both packets
- TEIDs:
  - `0x01020304`
  - `0x11223344`
- Outcome: two distinct recognized flows
- Physical paths:
  - `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP`
  - `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x11223344) -> IPv4 -> TCP`
- Purpose: TEID identity split

### 22_gtpu_udp_port_direction_matrix.pcap

- Packet 1:
  - outer UDP `2152 -> 55024`
  - valid-looking GTP-U bytes
  - outcome: ordinary outer UDP flow only
- Packet 2:
  - outer UDP `2152 -> 2152`
  - valid T-PDU
  - outcome: recognized inner TCP flow
- Purpose: exact destination-port direction rule

### 23_gtpu_control_message_matrix.pcap

- Outer: six EthernetII / IPv4 / UDP `55030..55035 -> 2152`
- Message types:
  - `0x01`
  - `0x02`
  - `0x1a`
  - `0xfe`
  - `0x1f`
  - `0x7a`
- Outcome: all remain ordinary outer UDP flows
- Physical path: `EthernetII -> IPv4 -> UDP`
- Packet-details behavior: lenient GTP-U metadata plus unsupported-message warning
- Purpose: current control/non-T-PDU dispatch boundary

### 24_gtpu_flag_matrix_inner_ipv4_tcp.pcap

- Packet 1: PT clear
  - outcome: ordinary outer UDP flow only
- Packet 2: reserved bit set
  - outcome: accepted inner TCP flow
- Packet 3: `S+PN`
  - sequence `0x1235`, N-PDU `0x5b`
  - outcome: accepted inner TCP flow
- Packet 4: `S+E`
  - sequence `0x1236`, next extension `0x85`
  - outcome: accepted inner TCP flow
- Packet 5: `PN+E`
  - N-PDU `0x5c`, next extension `0x85`
  - outcome: accepted inner TCP flow
- Packet 6: `S+PN+E`
  - sequence `0x1237`, N-PDU `0x5d`, next extension `0x85`
  - outcome: accepted inner TCP flow
- Identity result:
  - PT-clear packet does not join the GTP-U flow
  - reserved/E/S/PN differences do not split the accepted GTP-U flow
- Purpose: exact PT/reserved/E/S/PN semantics and non-identity of optional metadata

### 25_gtpu_outer_tagged_contexts.pcap

- Packet 1: outer VLAN `201`
- Packet 2: outer QinQ `551 / 552`
- Packet 3: outer legacy TPID `0x9100`, VLAN `701`
- All three:
  - outer IPv4 / UDP `-> 2152`
  - same TEID `0x01020304`
  - same inner IPv4/TCP tuple
- Outcome: three distinct recognized flows
- Purpose: outer carrier metadata remains identity-bearing in the physical path

### 26_gtpu_outer_ipv6_inner_ipv6_udp.pcap

- Outer: EthernetII / IPv6 / UDP `55053 -> 2152`
- GTP-U: T-PDU, TEID `0x01020324`
- Inner: IPv6 / UDP
- Outcome: one recognized inner IPv6/UDP flow
- Physical path:
  `EthernetII -> IPv6 -> UDP -> GTP-U(teid=0x01020324) -> IPv6 -> UDP`
- Purpose: outer IPv6 plus inner IPv6 reachability

### 27_gtpu_linux_sll_inner_ipv4_udp.pcap

- Outer: Linux cooked SLL / IPv4 / UDP `55054 -> 2152`
- GTP-U: TEID `0x01020354`
- Inner: IPv4 / UDP
- Outcome: one recognized inner IPv4/UDP flow
- Physical path:
  `LinuxSll -> IPv4 -> UDP -> GTP-U(teid=0x01020354) -> IPv4 -> UDP`
- Purpose: Linux SLL carrier reachability

### 28_gtpu_linux_sll2_inner_ipv6_tcp.pcap

- Outer: Linux cooked SLL2 / IPv6 / UDP `55055 -> 2152`
- GTP-U: TEID `0x01020364`
- Inner: IPv6 / TCP
- Outcome: one recognized inner IPv6/TCP flow
- Physical path:
  `LinuxSll2 -> IPv6 -> UDP -> GTP-U(teid=0x01020364) -> IPv6 -> TCP`
- Purpose: Linux SLL2 carrier reachability

### 29_gtpu_nested_overlay_udp_terminal.pcap

- Outer: three EthernetII / IPv4 / UDP / GTP-U packets
- Inner: IPv4 / UDP with destination ports:
  - `2152`
  - `4789`
  - `6081`
- Outcome: three recognized inner UDP flows; no recursive nested-overlay decode
- Physical paths:
  - `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020374) -> IPv4 -> UDP`
  - `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020375) -> IPv4 -> UDP`
  - `EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020376) -> IPv4 -> UDP`
- Purpose: nested overlay termination at inner UDP

### 30_gtpu_outer_ipv4_fragmentation.pcap

- Outer: two IPv4 fragments carrying bytes that would start a GTP-U/UDP packet
- Outcome:
  - one outer IPv4 fragmentation-shell flow
  - `unrecognized_packet_count() == 0`
- Physical path: `EthernetII -> IPv4`
- Packet-details behavior: outer IPv4 visible; no UDP or GTP-U fabricated
- Purpose: outer IPv4 fragmentation blocks GTP-U continuation

### 31_gtpu_outer_ipv6_fragmentation.pcap

- Outer: two IPv6 fragment-header packets carrying bytes that would start a GTP-U/UDP packet
- Outcome:
  - one outer IPv6 fragmentation-shell flow
  - `unrecognized_packet_count() == 0`
- Physical path: `EthernetII -> IPv6`
- Packet-details behavior: outer IPv6 visible; no UDP or GTP-U fabricated
- Purpose: outer IPv6 fragmentation blocks GTP-U continuation

## Notes for migration

- This directory defines the production contract that shadow GTP-U migration must match.
- Shadow GTP-U dissection is not implemented in this pass.
- No temporary fixture generator is committed with this directory.
