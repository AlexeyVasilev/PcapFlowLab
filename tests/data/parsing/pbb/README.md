Synthetic IEEE 802.1ah PBB / MAC-in-MAC fixtures for the current production decoder.

These fixtures define the production migration contract for a future shadow PBB pass.

Current production subset covered here:
- outer Ethernet II entry with EtherType `0x88e7`;
- outer VLAN entry before PBB through the shared VLAN parser for `0x8100`, `0x88a8`, and `0x9100`;
- fixed 4-byte PBB I-TAG parsing;
- PBB identity keyed only by 24-bit I-SID;
- inner customer Ethernet continuation into:
  - IPv4;
  - IPv6;
  - ARP;
  - inner VLAN / QinQ;
  - inner IEEE 802.3 LLC/SNAP when it resolves to IPv4;
- conservative no-flow handling for:
  - unknown inner EtherType;
  - known-but-unsupported nested continuations such as inner PPPoE session;
  - truncated I-TAG;
  - complete I-TAG with no inner Ethernet bytes;
  - truncated inner Ethernet;
  - truncated inner IPv4;
  - truncated inner IPv6;
  - truncated inner ARP;
  - extra captured tail beyond the bounded inner network/transport lengths;
  - caplen-truncated inner IPv4 after a complete I-TAG.

Not covered or intentionally unsupported here:
- PBB-TE;
- OAM / CFM;
- bridge-learning or control-plane behavior;
- nested PBB continuation;
- inner PPPoE continuation through PBB;
- inner MPLS continuation through PBB;
- MACsec through PBB.

Key production semantics locked by these fixtures:
- exact entry EtherType is `0x88e7`;
- I-TAG size is exactly 4 bytes;
- I-TAG fields are parsed as:
  - PCP: top 3 bits;
  - DEI: next 1 bit;
  - NCA: next 1 bit;
  - reserved: next 3 bits;
  - I-SID: low 24 bits;
- ProtocolPath contribution is exactly one `PBB(isid=0x......)` layer;
- PBB flow identity uses I-SID only;
- PCP / DEI / NCA / reserved bits do not split flows;
- inner Ethernet II appears in physical ProtocolPath for inner Ethernet II continuations;
- inner IEEE 802.3 / LLC-SNAP appears as `IEEE 802.3 -> LLC/SNAP` rather than `EthernetII`.

Shared fixture constants reused unless a case says otherwise:
- outer backbone source MAC: `02:00:00:00:60:01`
- outer backbone destination MAC: `02:00:00:00:60:02`
- inner customer source MAC: `02:00:00:00:61:01`
- inner customer destination MAC: `02:00:00:00:61:02`
- IPv4 source: `192.0.2.60`
- IPv4 destination: `198.51.100.60`
- IPv6 source: `2001:db8:60::10`
- IPv6 destination: `2001:db8:60::20`
- TCP source port: `49190`
- TCP destination port: `443`
- UDP source port: `53570`
- UDP destination port: `443`
- default I-SID: `0x123456`

No committed fixture generator is kept for this directory. PCAPs are committed deterministic binaries.

## Fixture Contract

### 01_pbb_ipv4_tcp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: PCP `0`, DEI `0`, NCA `0`, reserved `0`, I-SID `0x123456`.
- Inner structure: Ethernet II -> IPv4 -> TCP.
- Production outcome: recognized flow.
- ProtocolId: `TCP`.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> TCP`.
- Purpose: baseline direct inner IPv4/TCP continuation.

### 02_pbb_ipv4_udp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> IPv4 -> UDP.
- Production outcome: recognized flow.
- ProtocolId: `UDP`.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP`.
- Purpose: baseline direct inner IPv4/UDP continuation.

### 03_pbb_ipv6_tcp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> IPv6 -> TCP.
- Production outcome: recognized flow.
- ProtocolId: `TCP`.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> TCP`.
- Purpose: baseline direct inner IPv6/TCP continuation.

### 04_pbb_ipv6_udp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> IPv6 -> UDP.
- Production outcome: recognized flow.
- ProtocolId: `UDP`.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> UDP`.
- Purpose: baseline direct inner IPv6/UDP continuation.

### 05_pbb_arp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> ARP.
- Production outcome: recognized non-flow surfaced through the normal flow list.
- ProtocolId: `ARP`.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x123456) -> EthernetII`.
- Purpose: locks current ARP-behind-PBB behavior without fabricating transport ports.

### 06_pbb_inner_vlan_ipv4_tcp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> VLAN `610` -> IPv4 -> TCP.
- Production outcome: recognized flow.
- ProtocolId: `TCP`.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=610) -> IPv4 -> TCP`.
- Purpose: inner customer single-tag VLAN continuation.

### 07_pbb_inner_qinq_ipv4_udp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> outer inner VLAN `620` -> inner VLAN `610` -> IPv4 -> UDP.
- Production outcome: recognized flow.
- ProtocolId: `UDP`.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=620) -> VLAN(vid=610) -> IPv4 -> UDP`.
- Purpose: inner customer QinQ continuation.

### 08_pbb_inner_llc_snap_ipv4_udp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: inner IEEE 802.3 length frame -> LLC/SNAP -> IPv4 -> UDP.
- Production outcome: recognized flow.
- ProtocolId: `UDP`.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x123456) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP`.
- Purpose: locks shared inner LLC/SNAP continuation through PBB.

### 09_pbb_outer_btag_ipv4_udp.pcap
- Outer encapsulation: Ethernet II -> provider B-TAG VLAN `600` -> PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> IPv4 -> UDP.
- Production outcome: recognized flow.
- ProtocolId: `UDP`.
- Physical ProtocolPath: `EthernetII -> VLAN(vid=600) -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP`.
- Purpose: provider VLAN before PBB remains visible in path and selected-packet presentation.

### 10_pbb_outer_btag_inner_vlan_ipv4_tcp.pcap
- Outer encapsulation: Ethernet II -> provider B-TAG VLAN `600` -> PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> VLAN `610` -> IPv4 -> TCP.
- Production outcome: recognized flow.
- ProtocolId: `TCP`.
- Physical ProtocolPath: `EthernetII -> VLAN(vid=600) -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=610) -> IPv4 -> TCP`.
- Purpose: outer provider VLAN plus inner customer VLAN composition.

### 11_pbb_unknown_inner_ethertype.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> unknown EtherType.
- Production outcome: unrecognized packet.
- Reason text: `Unknown PBB inner EtherType`.
- Path behavior: no persisted flow ProtocolPath.
- Purpose: unknown inner EtherType must not fabricate IPv4/IPv6/ARP continuation.

### 12_pbb_truncated_itag.pcap
- Outer encapsulation: Ethernet II -> EtherType `0x88e7`.
- Boundary shape: only 2 of 4 I-TAG bytes captured.
- Production outcome: unrecognized packet.
- Reason text: `PBB I-TAG truncated`.
- Selected-packet behavior: partial first-byte metadata can still be shown.
- Purpose: fixed-header truncation contract.

### 13_pbb_truncated_inner_ethernet.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: complete default I-TAG.
- Boundary shape: fewer than 14 bytes remain for the inner Ethernet header.
- Production outcome: unrecognized packet.
- Reason text: `Inner Ethernet header truncated`.
- Purpose: complete I-TAG with truncated inner Ethernet continuation.

### 14_pbb_truncated_inner_ipv4.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: complete default I-TAG.
- Inner structure: complete inner Ethernet II with EtherType IPv4, but fixed IPv4 header is truncated.
- Production outcome: unrecognized packet.
- Reason text: `IPv4 header truncated`.
- Purpose: complete inner Ethernet plus truncated inner protocol.

### 15_pbb_metadata_nondefault_itag.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: PCP `5`, DEI `1`, NCA `1`, reserved `0`, I-SID `0x654321`.
- Inner structure: Ethernet II -> IPv4 -> UDP.
- Production outcome: recognized flow.
- ProtocolId: `UDP`.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x654321) -> EthernetII -> IPv4 -> UDP`.
- Purpose: non-default I-TAG metadata presentation and non-default I-SID identity.

### 16_pbb_same_isid_same_inner_tuple_metadata_variation.pcap
- Packets: 2.
- Outer encapsulation: Ethernet II directly into PBB for both packets.
- Packet 1 I-TAG: PCP `0`, DEI `0`, NCA `0`, reserved `0`, I-SID `0x123456`.
- Packet 2 I-TAG: PCP `7`, DEI `1`, NCA `1`, reserved `5`, I-SID `0x123456`.
- Inner structure for both packets: identical Ethernet II -> IPv4 -> UDP tuple.
- Production outcome: one recognized flow with two packets.
- Physical ProtocolPath for both packets: `EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP`.
- Identity purpose: proves PCP / DEI / NCA / reserved bits do not split the flow when I-SID is unchanged.

### 17_pbb_different_isid_same_inner_tuple.pcap
- Packets: 2.
- Outer encapsulation: Ethernet II directly into PBB for both packets.
- Packet 1 I-SID: `0x123456`.
- Packet 2 I-SID: `0x123457`.
- Inner structure for both packets: identical Ethernet II -> IPv4 -> UDP tuple.
- Production outcome: two recognized flows.
- Physical ProtocolPaths:
  - `EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP`
  - `EthernetII -> PBB(isid=0x123457) -> EthernetII -> IPv4 -> UDP`
- Identity purpose: proves I-SID participates in production flow/path identity.

### 18_pbb_zero_isid_ipv4_udp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: default metadata, I-SID `0x000000`.
- Inner structure: Ethernet II -> IPv4 -> UDP.
- Production outcome: recognized flow.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x000000) -> EthernetII -> IPv4 -> UDP`.
- Purpose: lower I-SID boundary coverage.

### 19_pbb_max_isid_ipv4_udp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: default metadata, I-SID `0xffffff`.
- Inner structure: Ethernet II -> IPv4 -> UDP.
- Production outcome: recognized flow.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0xffffff) -> EthernetII -> IPv4 -> UDP`.
- Purpose: upper 24-bit I-SID boundary coverage.

### 20_pbb_outer_qinq_ipv6_udp.pcap
- Outer encapsulation: Ethernet II -> outer provider tag `0x88a8` VLAN `701` -> inner provider/customer tag `0x8100` VLAN `702` -> PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> IPv6 -> UDP.
- Production outcome: recognized flow.
- Physical ProtocolPath: `EthernetII -> VLAN(vid=701) -> VLAN(vid=702) -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> UDP`.
- Purpose: proves production can enter PBB after outer QinQ and preserve both outer VLAN layers.

### 21_pbb_outer_legacy_vlan_ipv4_udp.pcap
- Outer encapsulation: Ethernet II -> legacy VLAN TPID `0x9100` with VID `703` -> PBB.
- PBB header: default metadata, I-SID `0x123456`.
- Inner structure: Ethernet II -> IPv4 -> UDP.
- Production outcome: recognized flow.
- Physical ProtocolPath: `EthernetII -> VLAN(vid=703) -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP`.
- Purpose: locks current shared support for alternate outer VLAN TPID `0x9100` before PBB.

### 22_pbb_capture_truncated_inner_ipv4_caplen_lt_origlen.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: complete default I-TAG.
- Boundary shape: capture ends 8 bytes into the inner IPv4 header; original frame length is larger than captured length.
- Production outcome: unrecognized packet.
- Reason text: `IPv4 header truncated`.
- Selected-packet behavior: inner Ethernet and partial IPv4 details remain visible; no transport tuple is fabricated.
- Purpose: capture-truncation contract after a complete PBB header and complete inner Ethernet header.

### 23_pbb_complete_itag_no_inner_ethernet.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: complete default I-TAG.
- Boundary shape: zero bytes remain after the fixed 4-byte I-TAG.
- Production outcome: unrecognized packet.
- Reason text: `Inner Ethernet header truncated`.
- Selected-packet behavior: PBB details remain visible and an empty/truncated inner Ethernet shell is still surfaced conservatively.
- Purpose: distinguishes complete PBB-header parsing from missing inner Ethernet bytes.

### 24_pbb_truncated_inner_ipv6.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: complete default I-TAG.
- Inner structure: complete inner Ethernet II with EtherType IPv6, but only 20 of 40 fixed IPv6 header bytes are captured.
- Production outcome: unrecognized packet.
- Reason text: `IPv6 header truncated`.
- Selected-packet behavior: conservative details stop at the inner Ethernet layer; no inner IPv6/UDP tuple is fabricated.
- Purpose: inner IPv6 fixed-header truncation contract after a complete I-TAG and complete inner Ethernet header.

### 25_pbb_truncated_inner_arp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: complete default I-TAG.
- Inner structure: complete inner Ethernet II with EtherType ARP, fixed 8-byte ARP header present, address section truncated.
- Selected-packet behavior: conservative ARP details are exposed with a truncated address section warning.
- Import accounting note: current fixture tests intentionally do not over-constrain whether this packet is surfaced through the unrecognized list or through the normal ARP flow-style accounting path.
- Purpose: conservative ARP-address-section truncation behind PBB.

### 26_pbb_inner_pppoe_session_unsupported.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: complete default I-TAG.
- Inner structure: complete inner Ethernet II with EtherType PPPoE Session and a minimal PPPoE session payload.
- Production outcome: unrecognized packet.
- Reason text: `Unsupported or malformed packet`.
- Path behavior: no persisted flow ProtocolPath even though the inner EtherType is known.
- Purpose: known nested continuation that current production does not continue through PBB.

### 27_pbb_extra_captured_tail_ipv4_udp.pcap
- Outer encapsulation: Ethernet II directly into PBB.
- PBB header: complete default I-TAG.
- Inner structure: Ethernet II -> IPv4 -> UDP with UDP payload `pbb-tail-ok`.
- Boundary shape: conspicuous captured tail bytes `de ad be ef a5 5a` follow the declared inner IPv4/UDP lengths.
- Production outcome: recognized flow.
- ProtocolId: `UDP`.
- Physical ProtocolPath: `EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP`.
- Payload-accounting purpose: transport payload length and payload dump stay bounded to the declared inner IPv4/UDP lengths and exclude the unrelated captured tail.
