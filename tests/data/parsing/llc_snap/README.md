Synthetic LLC/SNAP parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- IEEE 802.3 length-based Ethernet framing followed by LLC;
- SNAP encapsulation with both Ethernet OUI `00:00:00` and non-zero OUI variants;
- inner IPv4 / IPv6 / ARP payload recovery through LLC/SNAP;
- VLAN and QinQ before LLC/SNAP as candidate shim-composition cases;
- unknown SNAP PID handling;
- non-SNAP LLC fallback handling;
- malformed or truncated LLC/SNAP envelopes;
- IEEE 802.3 length-boundary mismatch cases.

Current audited production behavior is intentionally narrow:
- Ethernet II is selected for values `>= 0x0600`; IEEE 802.3 length framing is selected for values `< 0x0600`;
- after outer VLAN / QinQ / legacy `0x9100` tags, the same post-tag `< 0x0600` test decides whether the inner payload is treated as IEEE 802.3;
- IEEE 802.3 child parsing is bounded by `min(declared_length, captured_payload_length)`;
- if the declared IEEE 802.3 payload is longer than the captured bytes, production keeps the parse bounded by capture and exposes the mismatch as truncation/warning state;
- if the captured frame contains bytes beyond the declared IEEE 802.3 payload, production does not use those extra bytes to complete LLC, SNAP, or inner IPv4 / IPv6 / ARP parsing;
- extra captured bytes beyond the declared IEEE 802.3 payload are treated conservatively as trailer/padding in selected-packet presentation when applicable;
- LLC/SNAP continuation is recognized only for canonical SNAP LLC:
  - DSAP `0xaa`
  - SSAP `0xaa`
  - Control `0x03`
- production does not implement any broader two-byte LLC control interpretation in this path;
- non-SNAP LLC remains a conservative no-flow case: LLC details are exposed, but no inner IPv4 / IPv6 / ARP continuation and no ProtocolPath contribution is created;
- SNAP continuation is supported for known PID values regardless of OUI when the bounded payload validates:
  - IPv4 `0x0800`
  - IPv6 `0x86dd`
  - ARP `0x0806`
- for supported PID values, production collapses LLC+SNAP into a single ProtocolPath contribution: `LLC/SNAP`;
- unsupported or unknown SNAP payloads do not contribute `LLC/SNAP` to ProtocolPath because no flow is recognized;
- VLAN and QinQ before LLC/SNAP are supported for the same bounded continuation path;
- malformed LLC/SNAP headers remain best-effort with specific truncation warnings.

## Local generation

This directory intentionally does not keep a committed generator.

When regeneration is needed, use a temporary local helper script from the
repository root, review the produced `.pcap` files, then delete the helper
before finishing the fixture pass.

Notes:
- the fixture contract is the committed `.pcap` files plus the production fixture tests;
- generation should write classic little-endian Ethernet `.pcap` files with deterministic MAC/IP/port values;
- malformed and declared-boundary cases should be assembled from explicit bytes rather than protocol-library defaults.

## Shared constants

- Host A MAC: `02:00:00:00:40:01`
- Host B MAC: `02:00:00:00:40:02`
- Host A IPv4: `192.0.2.40`
- Host B IPv4: `198.51.100.40`
- Host A IPv6: `2001:db8:40::10`
- Host B IPv6: `2001:db8:40::20`
- TCP source port: `49170`
- TCP destination port: `443`
- UDP source port: `53550`
- UDP destination port: `443`
- SNAP Ethernet OUI: `00:00:00`

## IEEE 802.3 / LLC / SNAP basics

- Ethernet II uses EtherType values `>= 0x0600`.
- IEEE 802.3 uses a length field `< 0x0600`.
- LLC/SNAP frames in this fixture set use:
  - DSAP `0xaa`
  - SSAP `0xaa`
  - Control `0x03`
  - OUI `00:00:00` by default, plus selected non-zero OUI coverage
  - PID / protocol id matching an Ethernet-style payload identifier when noted

## Current production contract

Current committed production contract covered by this directory:
- plain LLC/SNAP inner IPv4 / IPv6 / ARP recovery is supported for known SNAP PID values when the bounded payload validates, including non-zero OUI cases because production dispatch keys off PID only after canonical DSAP/SSAP/Control;
- VLAN/QinQ before LLC/SNAP are supported for the same bounded continuation path;
- supported ProtocolPath shapes are:
  - `IEEE 802.3 -> LLC/SNAP -> IPv4 -> TCP`
  - `IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP`
  - `IEEE 802.3 -> LLC/SNAP -> IPv6 -> TCP`
  - `IEEE 802.3 -> LLC/SNAP -> IPv6 -> UDP`
  - `IEEE 802.3 -> LLC/SNAP` for ARP
  - `EthernetII -> VLAN(vid=...) -> LLC/SNAP -> ...` when the LLC/SNAP envelope sits behind VLAN / QinQ
- unknown SNAP PID and non-SNAP LLC stay conservative and must not fabricate IPv4 / IPv6 / ARP or produce a flow-bearing ProtocolPath;
- malformed/truncated and length-mismatch cases stay bounded by the declared IEEE 802.3 payload and are expected to surface truncation or unsupported no-flow behavior rather than use captured tail bytes to complete the envelope;
- truncated inner IPv4 after a valid LLC/SNAP header can still surface partial IPv4 details while remaining no-flow.

This pass materializes the previously identified LLC/SNAP fixture gaps for:
- DSAP-only truncation;
- DSAP+SSAP truncation;
- canonical DSAP/SSAP with non-SNAP Control;
- declared-short IEEE 802.3 payload with captured tail bytes;
- exact declared payload plus visible padding;
- truncated inner IPv6 after a valid SNAP header;
- truncated inner ARP after a valid SNAP header;
- legacy `0x9100` VLAN before LLC/SNAP.

---

### 01_llc_snap_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / OUI `00:00:00` / PID IPv4 / IPv4 / TCP / Raw
- Expected production outcome: recognized flow
- Expected ProtocolId: TCP
- Expected ProtocolPath: `IEEE 802.3 -> LLC/SNAP -> IPv4 -> TCP`
- Current behavior: recovers inner IPv4/TCP through LLC/SNAP and forms a normal IPv4/TCP flow.

### 02_llc_snap_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / PID IPv4 / IPv4 / UDP / Raw
- Expected production outcome: recognized flow
- Expected ProtocolId: UDP
- Expected ProtocolPath: `IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP`
- Current behavior: recovers inner IPv4/UDP and forms a normal IPv4/UDP flow.

### 03_llc_snap_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / PID IPv6 / IPv6 / TCP / Raw
- Expected production outcome: recognized flow
- Expected ProtocolId: TCP
- Expected ProtocolPath: `IEEE 802.3 -> LLC/SNAP -> IPv6 -> TCP`
- Current behavior: recovers inner IPv6/TCP and forms a normal IPv6/TCP flow.

### 04_llc_snap_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / PID IPv6 / IPv6 / UDP / Raw
- Expected production outcome: recognized flow
- Expected ProtocolId: UDP
- Expected ProtocolPath: `IEEE 802.3 -> LLC/SNAP -> IPv6 -> UDP`
- Current behavior: recovers inner IPv6/UDP and forms a normal IPv6/UDP flow.

### 05_llc_snap_arp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / PID ARP / ARP
- Expected production outcome: recognized flow
- Expected ProtocolId: ARP
- Expected ProtocolPath: `IEEE 802.3 -> LLC/SNAP`
- Current behavior: ARP is recognized behind LLC/SNAP.

### 06_vlan_llc_snap_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN `0x8100` / 802.3-length payload / LLC SNAP / IPv4 / TCP
- VLAN ID: `100`
- Expected production outcome: recognized flow
- Expected ProtocolId: TCP
- Expected ProtocolPath: `EthernetII -> VLAN(vid=100) -> LLC/SNAP -> IPv4 -> TCP`
- Current behavior: outer VLAN envelope remains visible and inner IPv4/TCP is recovered through LLC/SNAP.
- Generator note: written manually with a VLAN TPID followed by an inner 802.3 length field to keep the wire image deterministic.

### 07_qinq_llc_snap_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / QinQ `0x88A8` / VLAN `0x8100` / 802.3-length payload / LLC SNAP / IPv4 / UDP
- Outer VLAN ID: `200`
- Inner VLAN ID: `300`
- Expected production outcome: recognized flow
- Expected ProtocolId: UDP
- Expected ProtocolPath: `EthernetII -> VLAN(vid=200) -> VLAN(vid=300) -> LLC/SNAP -> IPv4 -> UDP`
- Current behavior: outer QinQ/VLAN envelope remains visible and inner IPv4/UDP is recovered through LLC/SNAP.

### 08_llc_snap_unknown_pid.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / OUI `00:00:00` / unknown PID / Raw
- Expected production outcome: no flow
- Expected classification: unsupported / unknown SNAP PID
- Expected ProtocolPath contribution: none
- Current behavior: remains no-flow with reason `Unknown SNAP PID`; selected-packet Summary shows IEEE 802.3, LLC, SNAP, the unknown PID, and bounded Data preview.

### 09_llc_snap_nonzero_oui_ipv4_pid.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / non-zero OUI / PID `0x0800` / IPv4-like bytes
- Non-zero OUI: `00:00:f8`
- Expected production outcome: recognized flow
- Expected ProtocolId: UDP
- Expected ProtocolPath: `IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP`
- Current behavior: forms a normal IPv4/UDP flow when the bounded payload validates; selected-packet Summary preserves the actual non-zero OUI while continuing into IPv4 and UDP.

### 10_llc_non_snap_ipx_like.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / non-SNAP LLC / Raw
- Expected production outcome: no flow
- Expected classification: unsupported / non-SNAP LLC
- Expected ProtocolPath contribution: none
- Current behavior: remains no-flow with reason `Non-SNAP LLC frame`; selected-packet Summary shows LLC fields plus bounded Data preview.

### 11_llc_snap_truncated_llc_header.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length says LLC follows, but LLC header is incomplete
- Expected production outcome: no flow
- Expected classification: captured-truncated LLC header
- Expected ProtocolPath contribution: none
- Current behavior: remains no-flow with reason `LLC header truncated`; selected-packet Summary shows IEEE 802.3 plus LLC truncation warning.

### 12_llc_snap_truncated_snap_header.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP marker present, but SNAP OUI/PID is incomplete
- Expected production outcome: no flow
- Expected classification: captured-truncated SNAP header
- Expected ProtocolPath contribution: none
- Current behavior: remains no-flow with reason `SNAP header truncated`; selected-packet Summary shows LLC, partial SNAP presence, and SNAP truncation warning.

### 13_llc_snap_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / PID IPv4 / partial IPv4 header
- Expected production outcome: no flow
- Expected classification: bounded inner IPv4 truncation after a valid LLC/SNAP envelope
- Expected ProtocolPath contribution: none because no flow is recognized
- Current behavior: remains no-flow with reason `IPv4 header truncated`; selected-packet Summary reuses the shared partial IPv4 presentation after LLC/SNAP.

### 14_llc_snap_length_short_payload.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length field larger than captured LLC/SNAP payload
- Declared IEEE 802.3 payload length: `53`
- Captured IEEE 802.3 payload bytes: `46`
- Expected production outcome: recognized IPv4/UDP flow from the bounded captured subset
- Expected ProtocolPath: `IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP`
- Expected captured transport payload length: `10` bytes
- Expected padding/trailer semantics: no extra captured trailer exists; production remains bounded by capture, not by the larger declared length
- Current behavior: inner IPv4/UDP is still recovered when enough header bytes are available, but LLC / IPv4 / UDP layers expose truncation warnings and the packet remains bounded by captured bytes.

### 15_llc_snap_length_extra_payload.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length field smaller than captured frame payload
- Declared IEEE 802.3 payload length: `28`
- Captured IEEE 802.3 payload bytes: `58`
- Expected production outcome: no flow
- Expected classification: bounded parse stops at the declared IEEE 802.3 payload; extra captured bytes are trailer, not additional SNAP / IPv4 / UDP bytes
- Expected ProtocolPath contribution: none
- Expected trailer length: `30` bytes
- Current behavior: trailing bytes beyond the declared IEEE 802.3 length are ignored for inner parsing and shown conservatively as a Trailer layer (`30 bytes` in this fixture) with bounded raw preview; the packet remains no-flow with reason `UDP header truncated`, while IEEE 802.3 and partial IPv4 layers show length-boundary warnings.

### 16_llc_truncated_dsap_only.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / one captured LLC byte
- Declared IEEE 802.3 payload length: `1`
- Captured LLC bytes: `AA`
- Expected production outcome: no flow
- Expected classification: captured-truncated LLC header
- Expected ProtocolPath contribution: none
- Purpose: prove a one-byte DSAP-only capture remains a pure LLC truncation case and does not fabricate SSAP, Control, SNAP, or a flow-bearing path.

### 17_llc_truncated_dsap_ssap.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / two captured LLC bytes
- Declared IEEE 802.3 payload length: `2`
- Captured LLC bytes: `AA AA`
- Expected production outcome: no flow
- Expected classification: captured-truncated LLC header
- Expected ProtocolPath contribution: none
- Purpose: distinguish DSAP+SSAP truncation from DSAP-only truncation while still proving that production does not fabricate the missing Control or SNAP continuation.

### 18_llc_non_snap_control.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC `AA AA 00` / captured tail that would resemble SNAP + IPv4 if misparsed
- Declared IEEE 802.3 payload length: complete captured payload
- Expected production outcome: no flow
- Expected classification: unsupported / non-SNAP LLC
- Expected ProtocolPath contribution: none
- Purpose: prove that canonical DSAP/SSAP with Control other than `0x03` remains a non-SNAP LLC stop and does not continue into OUI/PID or inner IPv4.

### 19_llc_snap_declared_short_with_captured_tail.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length `7` / canonical LLC+partial SNAP inside declared payload / full PID + IPv4 bytes only in the captured tail beyond the declared boundary
- Declared IEEE 802.3 payload length: `7`
- Captured IEEE 802.3 payload bytes: greater than `7`
- Expected production outcome: no flow
- Expected classification: SNAP header truncated
- Expected ProtocolPath contribution: none
- Declared-versus-captured detail: production must stop at the declared boundary, leaving the full PID and IPv4 bytes in the trailer rather than using them to complete the SNAP header.
- Purpose: lock in the declared-boundary rule for future shadow parity.

### 20_llc_snap_padding_after_declared_payload.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / IPv4 / UDP / declared payload end / captured padding
- IPv4 source: `192.0.2.50`
- IPv4 destination: `198.51.100.50`
- UDP source port: `54050`
- UDP destination port: `4500`
- UDP payload: ASCII `gap20-udp`
- Captured padding bytes outside the declared payload: `DE AD BE EF A5 5A`
- Expected production outcome: recognized flow
- Expected ProtocolId: UDP
- Expected ProtocolPath: `IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP`
- Expected captured transport payload length: `9` bytes
- Padding detail: the `DE AD BE EF A5 5A` bytes are trailer only and must not affect IPv4 or UDP payload bounds.
- Purpose: prove exact declared-length success plus visible padding exclusion.

### 21_llc_snap_truncated_inner_ipv6.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / canonical LLC SNAP / supported IPv6 PID / truncated IPv6 bytes
- Declared IEEE 802.3 payload length: complete captured payload
- Expected production outcome: no flow
- Expected classification: `IPv6 header truncated`
- Expected ProtocolPath contribution: none
- Purpose: preserve successful LLC/SNAP recognition through the continuation boundary while proving that truncated inner IPv6 does not fabricate endpoints or ports.

### 22_llc_snap_truncated_inner_arp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / canonical LLC SNAP / supported ARP PID / truncated ARP bytes
- Declared IEEE 802.3 payload length: complete captured payload
- Expected production outcome: no flow
- Expected classification: `ARP header truncated`
- Expected ProtocolPath contribution: none
- Purpose: prove that a supported ARP PID with an incomplete ARP body remains a conservative no-flow truncation case.

### 23_vlan_9100_llc_snap_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN TPID `0x9100` / VID `413` / 802.3-length payload / canonical LLC SNAP / IPv4 / UDP
- IPv4 source: `192.0.2.53`
- IPv4 destination: `198.51.100.53`
- UDP source port: `54053`
- UDP destination port: `4530`
- UDP payload: ASCII `v9100-udp`
- Expected production outcome: recognized flow
- Expected ProtocolId: UDP
- Expected ProtocolPath: `EthernetII -> VLAN(vid=413) -> LLC/SNAP -> IPv4 -> UDP`
- Purpose: verify that production applies the IEEE 802.3 length rule after legacy VLAN TPID `0x9100`, not only after `0x8100` / `0x88A8`.

## Expected generated file list

- `01_llc_snap_ipv4_tcp.pcap`
- `02_llc_snap_ipv4_udp.pcap`
- `03_llc_snap_ipv6_tcp.pcap`
- `04_llc_snap_ipv6_udp.pcap`
- `05_llc_snap_arp.pcap`
- `06_vlan_llc_snap_ipv4_tcp.pcap`
- `07_qinq_llc_snap_ipv4_udp.pcap`
- `08_llc_snap_unknown_pid.pcap`
- `09_llc_snap_nonzero_oui_ipv4_pid.pcap`
- `10_llc_non_snap_ipx_like.pcap`
- `11_llc_snap_truncated_llc_header.pcap`
- `12_llc_snap_truncated_snap_header.pcap`
- `13_llc_snap_truncated_inner_ipv4.pcap`
- `14_llc_snap_length_short_payload.pcap`
- `15_llc_snap_length_extra_payload.pcap`
- `16_llc_truncated_dsap_only.pcap`
- `17_llc_truncated_dsap_ssap.pcap`
- `18_llc_non_snap_control.pcap`
- `19_llc_snap_declared_short_with_captured_tail.pcap`
- `20_llc_snap_padding_after_declared_payload.pcap`
- `21_llc_snap_truncated_inner_ipv6.pcap`
- `22_llc_snap_truncated_inner_arp.pcap`
- `23_vlan_9100_llc_snap_ipv4_udp.pcap`
