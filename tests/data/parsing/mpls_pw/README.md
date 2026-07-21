Deterministic production MPLS Ethernet pseudowire fixture contract.

This directory documents and exercises the exact current production behavior in
`PacketDecodeSupport.h`, `PacketDecoder.cpp`, `CaptureImportProcessor.cpp`, and
`PacketDetailsService.cpp`.

This is not an RFC-target document. Production code is the source of truth.

Shadow MPLS pseudowire support now exists in the shadow dissection engine, but
this README remains the production contract source of truth.

## Scope

These fixtures cover:
- MPLS label-stack parsing to bottom of stack;
- post-BoS production branch selection;
- Ethernet pseudowire continuation with and without a 4-byte control word;
- inner Ethernet continuation into IPv4 / IPv6 / ARP / VLAN / QinQ / LLC-SNAP;
- production-supported outer entry contexts before MPLS;
- malformed, truncated, ambiguous, and unsupported pseudowire payloads;
- exact persistent `ProtocolPath` behavior for recognized flows.

These fixtures do not claim:
- production cutover or full shadow/production equivalence beyond the committed subset;
- generic RFC 4448 / RFC 4385 compliance beyond what production currently does;
- generic inner EtherType continuation behind pseudowire;
- control-word length or fragmentation semantics beyond current production checks.

## Production entry contexts

Current production MPLS parsing is reachable through:
- direct Ethernet II `0x8847` / `0x8848`;
- outer single VLAN `0x8100` before MPLS;
- outer QinQ `0x88a8` + `0x8100` before MPLS;
- outer legacy VLAN-like `0x9100` before MPLS;
- GRE protocol type `0x8847` through the GRE-specific path.

This fixture directory focuses on the direct Ethernet/VLAN entry shapes. GRE/MPLS
entry is covered separately in the GRE fixture set and reuses the same
post-BoS MPLS helper behavior.

## Exact post-BoS classification order

After the production parser reaches the BoS label, it makes decisions in this
order:

1. If no bytes remain, status is `missing_inner_payload`.
2. If the first nibble is `4`, production classifies the payload as direct
   inner IPv4 immediately.
3. If the first nibble is `6`, production classifies the payload as direct
   inner IPv6 immediately.
4. If bytes start with `00 00` and fewer than 4 bytes remain, production treats
   the payload as a truncated pseudowire control word.
5. If bytes start with `00 00` and a full 4-byte control word is present,
   production tries Ethernet continuation starting after the 4-byte control
   word.
6. If the control-word branch above cannot produce a full inner Ethernet header
   but 4 control-word bytes were present, production reports inner Ethernet
   truncation, not a direct-IP fallback.
7. If no control word was accepted, production tries plain inner Ethernet
   continuation directly at BoS.
8. If no full inner Ethernet header is visible, production reports inner
   Ethernet truncation.
9. Otherwise production reports `unknown_payload`.

Important consequences:
- direct-IP nibble checks win before pseudowire fallback;
- control-word recognition is currently only "first 16 bits are exactly
  `0x0000`";
- non-zero control-word flags are not accepted as a control word;
- no separate persistent `ProtocolPath` layer is created for the control word;
- `MPLS PW` is added to the path only when inner Ethernet continuation is
  actually recovered.

## Identity rules proven by these fixtures/tests

Current production flow identity for recognized MPLS pseudowire traffic uses:
- ordered MPLS labels;
- presence of the `MPLS PW` path layer when inner Ethernet is recovered;
- inner continuation path layers such as inner Ethernet, VLAN/QinQ, LLC/SNAP,
  IPv4/IPv6, and transport.

Current production identity does not use:
- MPLS traffic class;
- MPLS TTL;
- pseudowire control-word flags;
- pseudowire control-word sequence;
- human-readable label names.

## Unsupported inner continuation classes

Current production has two distinct unsupported inner classes after pseudowire
 Ethernet recovery:

- known-but-not-terminal inner continuations become `unknown_payload`
  Representative fixture:
  - `21_mpls_pw_inner_pppoe_session_no_cw.pcap`
  - inner Ethernet EtherType is PPPoE Session (`0x8864`)
  - production preserves inner Ethernet but does not continue into PPPoE here.

- unsupported Ethernet II inner EtherTypes become
  `unknown_inner_ether_type`
  Representative fixture:
  - `22_mpls_pw_inner_mpls_no_cw.pcap`
  - production branch is the same class currently used for inner MPLS and is
    also representative of other unsupported Ethernet-II inner types such as
    PBB or MACsec.

## Shared constants

- Outer PE B MAC: `02:00:00:00:50:02`
- Outer PE A MAC: `02:00:00:00:50:01`
- Inner CE B MAC: `02:00:00:00:51:02`
- Inner CE A MAC: `02:00:00:00:51:01`
- Host A IPv4: `192.0.2.50`
- Host B IPv4: `198.51.100.50`
- Host A IPv6: `2001:db8:50::10`
- Host B IPv6: `2001:db8:50::20`
- Default transport label: `24050`
- Default service label: `16050`

All successful fixtures in this directory currently have zero captured transport
payload bytes after the terminal TCP/UDP/ARP header.

## Fixture contract

### 01_mpls_pw_eth_ipv4_tcp_no_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: starts with inner Ethernet destination
  `02:00:...`; no direct-IP nibble hit; plain inner Ethernet pseudowire branch
- Control word: absent
- Inner protocol: Ethernet II / IPv4 / TCP
- Bounds: complete
- Production outcome: one recognized flow, `ProtocolId::tcp`
- Addresses/ports: `192.0.2.50:49180 -> 198.51.100.50:443`
- Physical `ProtocolPath`:
  `EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> TCP`
- Identity purpose: baseline no-control-word MPLS PW TCP path

### 02_mpls_pw_eth_ipv4_udp_no_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: plain inner Ethernet pseudowire branch
- Control word: absent
- Inner protocol: Ethernet II / IPv4 / UDP
- Bounds: complete
- Production outcome: one recognized flow, `ProtocolId::udp`
- Addresses/ports: `192.0.2.50:53560 -> 198.51.100.50:443`
- Physical `ProtocolPath`:
  `EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> UDP`
- Identity purpose: baseline no-control-word MPLS PW UDP path

### 03_mpls_pw_eth_ipv6_tcp_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: `00 00` control-word branch, then inner
  Ethernet
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: Ethernet II / IPv6 / TCP
- Bounds: complete
- Production outcome: one recognized flow, `ProtocolId::tcp`
- Physical `ProtocolPath`:
  `EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv6 -> TCP`
- Identity purpose: control-word-present IPv6/TCP success path

### 04_mpls_pw_eth_ipv6_udp_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: `00 00` control-word branch, then inner
  Ethernet
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: Ethernet II / IPv6 / UDP
- Bounds: complete
- Production outcome: one recognized flow, `ProtocolId::udp`
- Physical `ProtocolPath`:
  `EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv6 -> UDP`
- Identity purpose: control-word-present IPv6/UDP success path

### 05_mpls_pw_eth_arp_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: `00 00` control-word branch, then inner
  Ethernet
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: Ethernet II / ARP
- Bounds: complete
- Production outcome: one recognized flow, `ProtocolId::arp`
- Physical `ProtocolPath`:
  `EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> ARP`
- Identity purpose: ARP recognized behind pseudowire

### 06_mpls_pw_eth_vlan_ipv4_tcp_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: control-word branch
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: Ethernet II / VLAN(vid=100) / IPv4 / TCP
- Bounds: complete
- Production outcome: one recognized TCP flow
- Physical `ProtocolPath`:
  `EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> VLAN(vid=100) -> IPv4 -> TCP`
- Identity purpose: inner VLAN contributes to persistent path

### 07_mpls_pw_eth_qinq_ipv4_udp_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: control-word branch
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: Ethernet II / VLAN(vid=100) / VLAN(vid=200) / IPv4 / UDP
- Bounds: complete
- Production outcome: one recognized UDP flow
- Physical `ProtocolPath`:
  `EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> VLAN(vid=100) -> VLAN(vid=200) -> IPv4 -> UDP`
- Identity purpose: repeated inner VLAN ordering is persistent

### 08_mpls_pw_eth_llc_snap_ipv4_udp_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: control-word branch
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: IEEE 802.3 / LLC / SNAP / IPv4 / UDP
- Bounds: bounded by declared 802.3 length
- Production outcome: one recognized UDP flow
- Physical `ProtocolPath`:
  `EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP`
- Identity purpose: inner 802.3/LLC-SNAP continuation remains path-bearing

### 09_mpls_pw_unknown_inner_ethertype_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: control-word branch
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: Ethernet II / unknown EtherType
- Bounds: complete
- Production outcome: no flow, `Unknown MPLS pseudowire inner EtherType`
- Physical path: MPLS + recovered inner Ethernet envelope only; no flow path id
- Identity purpose: unsupported Ethernet-II inner EtherType branch

### 10_mpls_pw_truncated_label_stack.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: incomplete first label
- BoS payload bytes/classification: none; label parse stops first
- Control word: N/A
- Bounds: captured truncation before one full label
- Production outcome: no flow, `MPLS label header truncated`
- Identity purpose: label-header truncation before any label key exists

### 11_mpls_pw_truncated_control_word.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: starts `00 00`, fewer than 4 bytes remain
- Control word: truncated after 2 bytes, flags visible as `0x0000`
- Inner protocol: none recovered
- Bounds: capture truncation
- Production outcome: no flow, `MPLS pseudowire control word truncated`
- Identity purpose: proves `00 00` is enough to enter the control-word branch

### 12_mpls_pw_truncated_inner_ethernet.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: full `00 00` control word accepted
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: partial inner Ethernet header only
- Bounds: fewer than 14 bytes after the control word
- Production outcome: no flow, `Inner Ethernet header truncated`
- Identity purpose: proves accepted control word suppresses direct fallback

### 13_mpls_pw_truncated_inner_ipv4.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: control-word branch, then inner Ethernet
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: Ethernet II / partial IPv4
- Bounds: inner IPv4 header capture-truncated
- Production outcome: no flow, conservative IPv4 truncation reporting
- Identity purpose: bounded inner IPv4 truncation after successful pseudowire
  recovery

### 14_mpls_pw_control_word_with_sequence.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: control-word branch
- Control word: flags `0x0000`, sequence `0x1234`
- Inner protocol: Ethernet II / IPv4 / UDP
- Bounds: complete
- Production outcome: one recognized UDP flow
- Physical `ProtocolPath`:
  `EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> UDP`
- Identity purpose: sequence is presentation-only, not path-bearing

### 15_mpls_pw_ambiguous_no_cw_inner_ethernet.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: first nibble is `0x0`, not `4` or `6`;
  not a control word because bytes do not start `00 00`; plain inner Ethernet
  continuation succeeds
- Control word: absent
- Inner protocol: Ethernet II / IPv4 / UDP
- Bounds: complete
- Production outcome: one recognized UDP flow
- Identity purpose: proves ordinary no-control-word pseudowire branch when the
  destination MAC starts with `0x02`

### 16_mpls_pw_outer_vlan_inner_qinq_ipv4_udp_cw.pcap

- Outer encapsulation: Ethernet II / outer VLAN(vid=300) / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: control-word branch
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: Ethernet II / VLAN(vid=100) / VLAN(vid=200) / IPv4 / UDP
- Bounds: complete
- Production outcome: one recognized UDP flow
- Physical `ProtocolPath`:
  `EthernetII -> VLAN(vid=300) -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> VLAN(vid=100) -> VLAN(vid=200) -> IPv4 -> UDP`
- Identity purpose: outer VLAN and inner QinQ both persist in path

### 17_mpls_pw_outer_qinq_inner_ipv4_udp_cw.pcap

- Outer encapsulation: Ethernet II / VLAN(vid=310) / VLAN(vid=311) / MPLS
  `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: control-word branch
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: Ethernet II / IPv4 / UDP
- Bounds: complete
- Production outcome: one recognized UDP flow
- Physical `ProtocolPath`:
  `EthernetII -> VLAN(vid=310) -> VLAN(vid=311) -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> UDP`
- Identity purpose: outer QinQ reachability before pseudowire

### 18_mpls_pw_outer_legacy_vlan_ipv4_tcp_cw.pcap

- Outer encapsulation: Ethernet II / legacy VLAN-like TPID `0x9100` / MPLS
  `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: control-word branch
- Control word: flags `0x0000`, sequence `0`
- Inner protocol: Ethernet II / IPv4 / TCP
- Bounds: complete
- Production outcome: one recognized TCP flow
- Physical `ProtocolPath`:
  `EthernetII -> VLAN(vid=320) -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> TCP`
- Identity purpose: legacy outer VLAN entry is preserved only as `VLAN(vid=...)`
  in path identity

### 19_mpls_pw_ambiguous_no_cw_mac_starts_with_4.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: first byte is `0x40`, so production picks
  direct IPv4 before considering pseudowire fallback
- Control word: absent
- Inner bytes on wire: actually start like an Ethernet frame, but that branch is
  never reached
- Bounds: complete bytes, structurally invalid for a real IPv4 packet
- Production outcome: no flow, no persistent path id, no pseudowire recovery
- Identity purpose: proves direct-IPv4 heuristic wins over Ethernet pseudowire

### 20_mpls_pw_ambiguous_no_cw_mac_starts_with_6.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: first byte is `0x60`, so production picks
  direct IPv6 before considering pseudowire fallback
- Control word: absent
- Inner bytes on wire: actually start like an Ethernet frame, but that branch is
  never reached
- Bounds: complete bytes, structurally invalid for a real IPv6 packet
- Production outcome: no flow, no persistent path id, no pseudowire recovery
- Identity purpose: proves direct-IPv6 heuristic wins over Ethernet pseudowire

### 21_mpls_pw_inner_pppoe_session_no_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: plain inner Ethernet pseudowire branch
- Control word: absent
- Inner protocol: Ethernet II / PPPoE Session (`0x8864`)
- Bounds: complete inner Ethernet and PPPoE-like bytes
- Production outcome: no flow, `Unknown MPLS payload`
- Identity purpose: known inner EtherType that is preserved but not continued in
  this pseudowire path

### 22_mpls_pw_inner_mpls_no_cw.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: plain inner Ethernet pseudowire branch
- Control word: absent
- Inner protocol: Ethernet II / inner MPLS EtherType `0x8847`
- Bounds: complete inner Ethernet
- Production outcome: no flow, `Unknown MPLS pseudowire inner EtherType`
- Identity purpose: representative unsupported Ethernet-II inner EtherType
  branch, also representative of current PBB/MACsec-style inner EtherType
  rejection

### 23_mpls_pw_nonzero_cw_flags_not_recognized.pcap

- Outer encapsulation: Ethernet II / MPLS `0x8847`
- Ordered labels: `24050`, `16050 (BoS)`
- BoS payload bytes/classification: begins `00 01`, so it does not satisfy the
  current control-word recognizer; production then tries plain inner Ethernet
  at BoS and reports truncation
- Control word: intentionally not recognized because flags are non-zero
- Inner protocol: none recovered
- Bounds: fewer than 14 bytes after BoS
- Production outcome: no flow, `Inner Ethernet header truncated`
- Identity purpose: proves non-zero control-word flags are not accepted as a
  pseudowire control word

## Local generation

The committed repository intentionally does not keep a local generator for this
directory. If fixtures need regeneration later, create a temporary local helper,
review the resulting bytes, and delete that helper before commit.
