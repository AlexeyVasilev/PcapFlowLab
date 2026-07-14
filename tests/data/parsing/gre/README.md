Synthetic GRE parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- GRE version 0 carrying inner IPv4 / IPv6 transport traffic;
- outer IPv4 and outer IPv6 GRE carriage;
- optional GRE checksum, key, and sequence fields;
- Transparent Ethernet Bridging (`0x6558`) with inner Ethernet continuation;
- outer VLAN / QinQ before GRE;
- MPLS carried directly inside GRE;
- unsupported or opaque GRE protocol types;
- GRE version 1 / PPTP-like unsupported coverage;
- malformed or truncated GRE headers, optional fields, and inner payloads;
- GRE key namespace coverage where identical inner tuples with different GRE keys should split.

The local helper script that generates these pcaps is intentionally **not** committed.

## Local generation

Run from the repository root with a local Python 3 interpreter:

```bash
python3 tmp/generate_gre_pcaps.py tests/data/parsing/gre --force
```

Notes:
- The script is a local helper only and should **not** be committed.
- It writes classic little-endian Ethernet `.pcap` files with deterministic MAC/IP/port values.
- GRE headers and malformed/truncated cases are assembled from explicit bytes for stable results across environments.
- Snaplen-truncated coverage is written manually so included length and original wire length can differ.

## GRE basics

- IP protocol number for GRE: `47`
- GRE version 0 base header:
  - flags / version: 16 bits
  - protocol type: 16 bits
- Optional fields may follow the base header in this order:
  - checksum + reserved1: 4 bytes when checksum-present bit is set
  - key: 4 bytes when key-present bit is set
  - sequence number: 4 bytes when sequence-present bit is set
- Protocol types used by this fixture set:
  - `0x0800` IPv4
  - `0x86DD` IPv6
  - `0x6558` Transparent Ethernet Bridging
  - `0x8847` MPLS unicast
- GRE version 1 / PPTP-like framing is intentionally staged as unsupported/deferred coverage in this pass.

## Shared constants

- Outer client MAC: `02:00:00:00:30:01`
- Outer server/router MAC: `02:00:00:00:30:02`
- Inner client MAC: `02:00:00:00:31:01`
- Inner server MAC: `02:00:00:00:31:02`
- Outer IPv4 client: `192.0.2.30`
- Outer IPv4 server: `198.51.100.30`
- Inner IPv4 client: `10.30.0.10`
- Inner IPv4 server: `10.30.0.20`
- Outer IPv6 client: `2001:db8:30::1`
- Outer IPv6 server: `2001:db8:30::2`
- Inner IPv6 client: `2001:db8:31::10`
- Inner IPv6 server: `2001:db8:31::20`
- TCP client port: `49152`
- TCP server port: `443`
- UDP client port: `53530`
- UDP server port: `443`
- Outer VLAN ID: `330`
- Outer QinQ service VLAN ID: `331`
- Inner VLAN ID for TEB coverage: `130`

## Current implementation status

Implemented in the current GRE pass:
- direct GRE version 0 inner IPv4/IPv6 plus TCP/UDP flow extraction;
- GRE Transparent Ethernet Bridging (`0x6558`) inner Ethernet continuation, including inner VLAN preservation when the inner Ethernet continuation resolves it;
- outer IPv4 and outer IPv6 GRE carriage;
- optional GRE checksum/key/sequence field skipping for bounded inner decode;
- outer VLAN/QinQ preservation before GRE when the existing outer-layer parser resolves those layers.

Still staged for later work:
- GRE MPLS payload continuation;
- GRE sequence/checksum Packet Details presentation;
- GRE version 1 / PPTP-like handling beyond conservative unsupported behavior.

Active regression coverage now expects successful flow extraction for fixtures `01`-`14`, `21`, and `22`, excluding only the still-staged GRE/MPLS and unsupported/truncation cases.
GRE key-aware protocol-path identity is now supported when the GRE key flag is present and the full 32-bit key is available:
- same inner tuple + different GRE keys split into distinct flows;
- same inner tuple + same GRE key remains one flow;
- checksum and sequence metadata do not participate in flow identity.

### 01_gre_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE / IPv4 / TCP
- Expected future behavior: normal TCP flow; path `EthernetII -> IPv4 -> GRE -> IPv4 -> TCP`.

### 02_gre_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE / IPv4 / UDP
- Expected future behavior: normal UDP flow; path `EthernetII -> IPv4 -> GRE -> IPv4 -> UDP`.

### 03_gre_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE / IPv6 / TCP
- Expected future behavior: normal IPv6 TCP flow; path `EthernetII -> IPv4 -> GRE -> IPv6 -> TCP`.

### 04_gre_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE / IPv6 / UDP
- Expected future behavior: normal IPv6 UDP flow.

### 05_ipv6_outer_gre_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv6 / GRE / IPv4 / TCP
- Expected future behavior: normal IPv4 TCP flow with outer IPv6 preserved in the path.

### 06_ipv6_outer_gre_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv6 / GRE / IPv6 / UDP
- Expected future behavior: normal IPv6 UDP flow with outer IPv6 GRE carriage.

### 07_gre_key_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE(key) / IPv4 / UDP
- GRE key: `0x11111111`
- Current behavior: inner IPv4/UDP decodes normally and the protocol path becomes `EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP`.

### 08_gre_sequence_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE(sequence) / IPv4 / TCP
- GRE sequence: `0x01020304`
- Expected future behavior: sequence visible in Packet Details; sequence not part of flow identity.

### 09_gre_checksum_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE(checksum) / IPv4 / UDP
- Expected future behavior: checksum field visible in Packet Details; inner IPv4/UDP decoded.

### 10_gre_checksum_key_sequence_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE(checksum,key,sequence) / IPv4 / UDP
- Current behavior: optional fields are skipped in order and the protocol path becomes `EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP`.

### 11_gre_teb_ethernet_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE(TEB) / inner Ethernet / IPv4 / TCP
- Current behavior: supported; path `EthernetII -> IPv4 -> GRE -> EthernetII -> IPv4 -> TCP`.

### 12_gre_teb_ethernet_vlan_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE(TEB) / inner Ethernet / VLAN / IPv4 / UDP
- Current behavior: supported; inner VLAN is preserved after GRE TEB with path `EthernetII -> IPv4 -> GRE -> EthernetII -> VLAN(vid=130) -> IPv4 -> UDP`.

### 13_outer_vlan_gre_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer VLAN / IPv4 / GRE / IPv4 / UDP
- Expected future behavior: outer VLAN is preserved before outer IPv4/GRE.

### 14_outer_qinq_gre_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / outer QinQ / outer VLAN / IPv4 / GRE / IPv4 / TCP
- Expected future behavior: both outer VLAN tags are preserved.

### 15_gre_mpls_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE(MPLS) / MPLS / IPv4 / UDP
- Expected future behavior: staged fixture target for GRE/MPLS continuation; path should become `EthernetII -> IPv4 -> GRE -> MPLS -> IPv4 -> UDP` once GRE/MPLS support exists.

### 16_gre_unknown_protocol_type.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE(unknown protocol type) / Raw
- Expected future behavior: GRE recognized, payload opaque, no fabricated TCP/UDP flow, no crash.

### 17_gre_version1_pptp_like_unsupported.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE version 1 / Raw
- Expected future behavior: recognized as GRE-family traffic but unsupported/deferred; no unsafe inner decode.

### 18_gre_truncated_base_header.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / partial GRE
- Expected future behavior: conservative truncated GRE handling; no crash.

### 19_gre_truncated_key_field.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE(key flag set) / partial key bytes
- Expected future behavior: conservative truncated optional-field handling; no crash.

### 20_gre_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / GRE / partial inner IPv4
- Expected future behavior: GRE layer visible; inner IPv4 partial/truncated handling remains conservative.

### 21_gre_same_inner_tuple_different_keys.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / GRE(key) / IPv4 / UDP
- GRE keys:
  - packet 1: `0x11111111`
  - packet 2: `0x22222222`
- Current behavior: two distinct flows because GRE key participates in protocol-path identity.

### 22_gre_same_inner_tuple_same_key_two_packets.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / GRE(key) / IPv4 / UDP
- GRE key on both packets: `0x11111111`
- Current behavior: one flow with packet count `2` because both packets share the same keyed GRE protocol path.
- Expected future behavior: one normal flow with two packets.

## Expected generated file list

- `01_gre_ipv4_tcp.pcap`
- `02_gre_ipv4_udp.pcap`
- `03_gre_ipv6_tcp.pcap`
- `04_gre_ipv6_udp.pcap`
- `05_ipv6_outer_gre_ipv4_tcp.pcap`
- `06_ipv6_outer_gre_ipv6_udp.pcap`
- `07_gre_key_ipv4_udp.pcap`
- `08_gre_sequence_ipv4_tcp.pcap`
- `09_gre_checksum_ipv4_udp.pcap`
- `10_gre_checksum_key_sequence_ipv4_udp.pcap`
- `11_gre_teb_ethernet_ipv4_tcp.pcap`
- `12_gre_teb_ethernet_vlan_ipv4_udp.pcap`
- `13_outer_vlan_gre_ipv4_udp.pcap`
- `14_outer_qinq_gre_ipv4_tcp.pcap`
- `15_gre_mpls_ipv4_udp.pcap`
- `16_gre_unknown_protocol_type.pcap`
- `17_gre_version1_pptp_like_unsupported.pcap`
- `18_gre_truncated_base_header.pcap`
- `19_gre_truncated_key_field.pcap`
- `20_gre_truncated_inner_ipv4.pcap`
- `21_gre_same_inner_tuple_different_keys.pcap`
- `22_gre_same_inner_tuple_same_key_two_packets.pcap`
