Synthetic IEEE 802.1ah PBB / MAC-in-MAC parsing fixtures for future regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- basic outer backbone Ethernet plus PBB I-TAG framing;
- inner customer Ethernet continuation into IPv4 / IPv6 / ARP;
- optional outer provider B-TAG before the I-TAG;
- optional inner customer VLAN / QinQ / LLC-SNAP composition;
- unknown inner EtherType fallback;
- malformed or truncated I-TAG / inner Ethernet / inner IPv4 cases;
- non-default I-TAG metadata presentation candidates.

Parser implementation is intentionally **not** part of this pass.
These fixtures are being prepared first so later parser work can target stable deterministic captures.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python3 tests/data/parsing/pbb/generate_pbb_pcaps.py --output-dir tests/data/parsing/pbb
```

To overwrite previously generated fixtures:

```bash
python3 tests/data/parsing/pbb/generate_pbb_pcaps.py --output-dir tests/data/parsing/pbb --force
```

Notes:
- The generator only writes local classic little-endian Ethernet `.pcap` files.
- It does not send packets and does not require root/admin privileges.
- Review generated captures locally in Wireshark before committing them.
- Scapy is used only for stable inner IPv4 / IPv6 / TCP / UDP / ARP payload bytes.
- PBB I-TAG, outer/inner Ethernet framing, VLAN/QinQ, LLC/SNAP, and malformed/truncated cases are assembled from explicit bytes for deterministic wire layout.

## Shared constants

- Backbone A MAC: `02:00:00:00:60:01`
- Backbone B MAC: `02:00:00:00:60:02`
- Customer A MAC: `02:00:00:00:61:01`
- Customer B MAC: `02:00:00:00:61:02`
- Host A IPv4: `192.0.2.60`
- Host B IPv4: `198.51.100.60`
- Host A IPv6: `2001:db8:60::10`
- Host B IPv6: `2001:db8:60::20`
- TCP source port: `49190`
- TCP destination port: `443`
- UDP source port: `53570`
- UDP destination port: `443`
- Default I-SID: `0x123456`
- Outer B-VLAN ID: `600`
- Inner C-VLAN ID: `610`
- Inner S-VLAN ID: `620`

## PBB / MAC-in-MAC notes

- Outer EtherType for the I-TAG envelope is `0x88e7`.
- This fixture set models a narrow MAC-in-MAC chain:
  - outer backbone Ethernet;
  - optional outer provider B-TAG;
  - PBB I-TAG;
  - inner customer Ethernet;
  - optional inner VLAN / QinQ / LLC-SNAP;
  - inner IPv4 / IPv6 / ARP / unknown / malformed payload.
- The 4-byte I-TAG is emitted from explicit bytes using:
  - PCP: 3 bits
  - DEI: 1 bit
  - UCA: 1 bit
  - reserved: 3 bits
  - I-SID: 24 bits
- No PBB-TE, OAM/CFM, control-plane, service semantics, or bridge-learning behavior is implied here.

## Current support assumptions

Current repository docs do not claim shared PBB / MAC-in-MAC parser support yet.

Conservative expectation for the current codebase before parser work lands:
- these fixtures may remain no-flow / unrecognized;
- outer Ethernet may still be visible in selected-packet details;
- richer I-TAG / inner Ethernet / inner IPv4 continuation is future parser work;
- malformed and truncated cases must remain no-crash robustness fixtures.

Future parser work should aim to reuse existing shared continuation paths where appropriate:
- inner VLAN / QinQ;
- inner LLC/SNAP;
- partial inner IPv4 presentation for truncated cases.

---

### 01_pbb_ipv4_tcp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / IPv4 / TCP / Raw
- Future expected behavior: parse the I-TAG, recover inner Ethernet, and form a normal IPv4/TCP flow.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

### 02_pbb_ipv4_udp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / IPv4 / UDP / Raw
- Future expected behavior: normal IPv4/UDP flow through MAC-in-MAC.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

### 03_pbb_ipv6_tcp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / IPv6 / TCP / Raw
- Future expected behavior: normal IPv6/TCP flow through MAC-in-MAC.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

### 04_pbb_ipv6_udp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / IPv6 / UDP / Raw
- Future expected behavior: normal IPv6/UDP flow through MAC-in-MAC.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

### 05_pbb_arp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / ARP
- Future expected behavior: ARP recognized behind PBB without fabricating a transport flow.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

### 06_pbb_inner_vlan_ipv4_tcp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / inner VLAN / IPv4 / TCP
- Future expected behavior: PBB continuation plus reuse of existing inner VLAN support.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

### 07_pbb_inner_qinq_ipv4_udp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / inner QinQ / inner VLAN / IPv4 / UDP
- Future expected behavior: PBB continuation plus reuse of stacked customer VLAN support.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

### 08_pbb_inner_llc_snap_ipv4_udp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet 802.3 length / LLC / SNAP / IPv4 / UDP
- Future expected behavior: PBB continuation plus reuse of the existing LLC/SNAP path.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

### 09_pbb_outer_btag_ipv4_udp.pcap

- Packets: 1
- Layer chain: outer Ethernet / outer provider VLAN B-TAG / PBB I-TAG / inner Ethernet / IPv4 / UDP
- Future expected behavior: provider VLAN before PBB I-TAG remains visible and does not block inner IPv4/UDP continuation.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

### 10_pbb_outer_btag_inner_vlan_ipv4_tcp.pcap

- Packets: 1
- Layer chain: outer Ethernet / outer provider VLAN B-TAG / PBB I-TAG / inner Ethernet / inner VLAN / IPv4 / TCP
- Future expected behavior: outer provider VLAN plus inner customer VLAN composition through PBB.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

### 11_pbb_unknown_inner_ethertype.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / unknown EtherType / Raw
- Future expected behavior: conservative fallback only; parser must not fabricate IPv4 / IPv6 / ARP.
- Current conservative behavior candidate: no-flow / unrecognized.

### 12_pbb_truncated_itag.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB EtherType `0x88e7` / incomplete I-TAG
- Future expected behavior: malformed/truncated I-TAG robustness only; no crash.
- Current conservative behavior candidate: no-flow / unrecognized.

### 13_pbb_truncated_inner_ethernet.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / partial inner Ethernet header
- Future expected behavior: no crash; later parser work may show partial inner Ethernet details.
- Current conservative behavior candidate: no-flow / unrecognized.

### 14_pbb_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / IPv4 EtherType / partial IPv4 header
- Future expected behavior: no-flow with shared partial IPv4 presentation reused after the PBB shim.
- Current conservative behavior candidate: no-flow / unrecognized until both PBB continuation and partial-inner presentation are wired together.

### 15_pbb_metadata_nondefault_itag.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG with non-default PCP / DEI / UCA / I-SID / inner Ethernet / IPv4 / UDP
- Future expected behavior: presentation of I-TAG metadata fields such as PCP, DEI, UCA, and I-SID.
- Current conservative behavior candidate: likely no-flow until PBB continuation is implemented.

## Expected generated file list

- `01_pbb_ipv4_tcp.pcap`
- `02_pbb_ipv4_udp.pcap`
- `03_pbb_ipv6_tcp.pcap`
- `04_pbb_ipv6_udp.pcap`
- `05_pbb_arp.pcap`
- `06_pbb_inner_vlan_ipv4_tcp.pcap`
- `07_pbb_inner_qinq_ipv4_udp.pcap`
- `08_pbb_inner_llc_snap_ipv4_udp.pcap`
- `09_pbb_outer_btag_ipv4_udp.pcap`
- `10_pbb_outer_btag_inner_vlan_ipv4_tcp.pcap`
- `11_pbb_unknown_inner_ethertype.pcap`
- `12_pbb_truncated_itag.pcap`
- `13_pbb_truncated_inner_ethernet.pcap`
- `14_pbb_truncated_inner_ipv4.pcap`
- `15_pbb_metadata_nondefault_itag.pcap`
