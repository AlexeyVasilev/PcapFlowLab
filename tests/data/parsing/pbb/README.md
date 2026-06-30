Synthetic IEEE 802.1ah PBB / MAC-in-MAC parsing fixtures for future regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- basic outer backbone Ethernet plus PBB I-TAG framing;
- inner customer Ethernet continuation into IPv4 / IPv6 / ARP;
- optional outer provider B-TAG before the I-TAG;
- optional inner customer VLAN / QinQ / LLC-SNAP composition;
- unknown inner EtherType fallback;
- malformed or truncated I-TAG / inner Ethernet / inner IPv4 cases;
- non-default I-TAG metadata presentation candidates.

Current repository behavior now supports a bounded first pass of shared PBB / MAC-in-MAC parsing:
- outer EtherType `0x88e7` I-TAG detection;
- 4-byte I-TAG metadata presentation (PCP / DEI / UCA / I-SID);
- inner customer Ethernet continuation into IPv4 / IPv6 / ARP;
- reuse of inner VLAN / QinQ / LLC/SNAP continuation;
- conservative no-flow handling for unknown inner EtherType and malformed/truncated cases.

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

Current shared support covers:
- normal inner IPv4 / IPv6 TCP/UDP flow extraction behind PBB;
- ARP recognition behind PBB without fabricating a transport flow;
- outer B-TAG preservation before the I-TAG;
- inner VLAN / QinQ / LLC/SNAP continuation after the I-TAG;
- conservative partial presentation for truncated inner IPv4 headers.

Still intentionally conservative:
- unknown inner EtherType remains no-flow with bounded Data preview;
- truncated I-TAG and truncated inner Ethernet remain no-flow;
- no PBB-TE, OAM/CFM, bridge-learning, or service semantics are implied.

---

### 01_pbb_ipv4_tcp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / IPv4 / TCP / Raw
- Current expected behavior: normal IPv4/TCP flow through MAC-in-MAC.

### 02_pbb_ipv4_udp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / IPv4 / UDP / Raw
- Current expected behavior: normal IPv4/UDP flow through MAC-in-MAC.

### 03_pbb_ipv6_tcp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / IPv6 / TCP / Raw
- Current expected behavior: normal IPv6/TCP flow through MAC-in-MAC.

### 04_pbb_ipv6_udp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / IPv6 / UDP / Raw
- Current expected behavior: normal IPv6/UDP flow through MAC-in-MAC.

### 05_pbb_arp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / ARP
- Current expected behavior: ARP recognized behind PBB without fabricating a transport flow.

### 06_pbb_inner_vlan_ipv4_tcp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / inner VLAN / IPv4 / TCP
- Current expected behavior: PBB continuation plus reuse of existing inner VLAN support.

### 07_pbb_inner_qinq_ipv4_udp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / inner QinQ / inner VLAN / IPv4 / UDP
- Current expected behavior: PBB continuation plus reuse of stacked customer VLAN support.

### 08_pbb_inner_llc_snap_ipv4_udp.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet 802.3 length / LLC / SNAP / IPv4 / UDP
- Current expected behavior: PBB continuation plus reuse of the existing LLC/SNAP path.

### 09_pbb_outer_btag_ipv4_udp.pcap

- Packets: 1
- Layer chain: outer Ethernet / outer provider VLAN B-TAG / PBB I-TAG / inner Ethernet / IPv4 / UDP
- Current expected behavior: provider VLAN before PBB I-TAG remains visible and does not block inner IPv4/UDP continuation.

### 10_pbb_outer_btag_inner_vlan_ipv4_tcp.pcap

- Packets: 1
- Layer chain: outer Ethernet / outer provider VLAN B-TAG / PBB I-TAG / inner Ethernet / inner VLAN / IPv4 / TCP
- Current expected behavior: outer provider VLAN plus inner customer VLAN composition through PBB.

### 11_pbb_unknown_inner_ethertype.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / unknown EtherType / Raw
- Current expected behavior: conservative fallback only; parser must not fabricate IPv4 / IPv6 / ARP.

### 12_pbb_truncated_itag.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB EtherType `0x88e7` / incomplete I-TAG
- Current expected behavior: malformed/truncated I-TAG robustness only; no crash.

### 13_pbb_truncated_inner_ethernet.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / partial inner Ethernet header
- Current expected behavior: no crash with conservative partial inner Ethernet presentation.

### 14_pbb_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG / inner Ethernet / IPv4 EtherType / partial IPv4 header
- Current expected behavior: no-flow with shared partial IPv4 presentation reused after the PBB shim.

### 15_pbb_metadata_nondefault_itag.pcap

- Packets: 1
- Layer chain: outer Ethernet / PBB I-TAG with non-default PCP / DEI / UCA / I-SID / inner Ethernet / IPv4 / UDP
- Current expected behavior: normal IPv4/UDP flow plus visible non-default I-TAG metadata fields such as PCP, DEI, UCA, and I-SID.

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
