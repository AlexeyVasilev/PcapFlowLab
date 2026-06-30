Synthetic MPLS Ethernet pseudowire parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- Ethernet-over-MPLS pseudowire payloads after an MPLS label stack;
- optional 4-byte pseudowire control word before the inner Ethernet frame;
- inner Ethernet continuation into IPv4 / IPv6 / ARP;
- inner VLAN / QinQ composition;
- inner IEEE 802.3 length + LLC/SNAP composition;
- unknown inner Ethernet EtherType fallback;
- malformed or truncated MPLS label, control-word, inner-Ethernet, and inner-IPv4 cases;
- control-word metadata coverage such as a non-zero sequence field;
- ambiguity coverage for no-control-word inner Ethernet payloads.

Parser implementation is intentionally **not** part of this pass.
This fixture set prepares deterministic wire images first so later parser work and tests can target them safely.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python3 tests/data/parsing/mpls_pw/generate_mpls_pw_pcaps.py --output-dir tests/data/parsing/mpls_pw --force
```

Notes:
- The generator only writes local classic little-endian `.pcap` files.
- It does not send packets and does not require root/admin privileges.
- Review generated captures locally in Wireshark before committing them.
- Scapy is used only for stable inner IPv4 / IPv6 / TCP / UDP / ARP payload bytes.
- MPLS labels, pseudowire control words, inner Ethernet framing, LLC/SNAP, and malformed/truncated cases are assembled from explicit bytes for exact deterministic behavior.

## Shared constants

- Outer PE A MAC: `02:00:00:00:50:01`
- Outer PE B MAC: `02:00:00:00:50:02`
- Inner CE A MAC: `02:00:00:00:51:01`
- Inner CE B MAC: `02:00:00:00:51:02`
- Host A IPv4: `192.0.2.50`
- Host B IPv4: `198.51.100.50`
- Host A IPv6: `2001:db8:50::10`
- Host B IPv6: `2001:db8:50::20`
- TCP source port: `49180`
- TCP destination port: `443`
- UDP source port: `53560`
- UDP destination port: `443`
- Service label: `16050`
- Transport label: `24050`
- Default MPLS TTL: `64`

## MPLS pseudowire basics

- Outer EtherType is MPLS unicast: `0x8847`
- The outer MPLS stack uses a deterministic two-label baseline in most fixtures:
  - transport label `24050`
  - service label `16050`
- Each MPLS label entry is 4 bytes:
  - Label: 20 bits
  - TC: 3 bits
  - BoS: 1 bit
  - TTL: 8 bits
- After the BoS label, this fixture set models an Ethernet pseudowire payload, not direct IP.
- Some fixtures include a 4-byte pseudowire control word before the inner Ethernet frame:
  - first 16 bits reserved/flags
  - next 16 bits sequence
- This pass does **not** claim any current committed MPLS pseudowire parser support.

## Current support assumptions

Current committed MPLS support in PcapFlowLab is focused on direct MPLS-to-IPv4/IPv6 continuation after the BoS label.

Conservative assumptions for this fixture set:
- MPLS pseudowire inner Ethernet continuation is not implemented yet;
- these captures are expected to stay no-flow or conservative until later parser work lands;
- malformed/truncated fixtures should remain safe and inspectable;
- future parser work should reuse already-added VLAN, LLC/SNAP, PPPoE, partial IPv4, and unrecognized-packet presentation paths where applicable.

## Future supported behavior targets

Future parser work will likely want to support:
- inner Ethernet continuation after MPLS pseudowire;
- optional pseudowire control-word recognition;
- inner VLAN/QinQ continuation;
- inner LLC/SNAP continuation;
- conservative fallback for unknown inner EtherType;
- partial inner Ethernet / partial inner IPv4 presentation where safe.

## Fixture list

### 01_mpls_pw_eth_ipv4_tcp_no_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / inner Ethernet / IPv4 / TCP / Raw
- Future expected behavior: recover inner Ethernet and form a normal IPv4/TCP flow.

### 02_mpls_pw_eth_ipv4_udp_no_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / inner Ethernet / IPv4 / UDP / Raw
- Future expected behavior: recover inner Ethernet and form a normal IPv4/UDP flow.

### 03_mpls_pw_eth_ipv6_tcp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / pseudowire control word / inner Ethernet / IPv6 / TCP / Raw
- Future expected behavior: parse the control word and recover an inner IPv6/TCP flow.

### 04_mpls_pw_eth_ipv6_udp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / pseudowire control word / inner Ethernet / IPv6 / UDP / Raw
- Future expected behavior: parse the control word and recover an inner IPv6/UDP flow.

### 05_mpls_pw_eth_arp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / pseudowire control word / inner Ethernet / ARP
- Future expected behavior: ARP recognized behind the MPLS pseudowire.

### 06_mpls_pw_eth_vlan_ipv4_tcp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / inner Ethernet / VLAN / IPv4 / TCP
- Future expected behavior: inner VLAN does not block IPv4/TCP continuation.

### 07_mpls_pw_eth_qinq_ipv4_udp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / inner Ethernet / QinQ / VLAN / IPv4 / UDP
- Future expected behavior: stacked inner VLAN tags do not block IPv4/UDP continuation.

### 08_mpls_pw_eth_llc_snap_ipv4_udp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / inner Ethernet 802.3 length / LLC / SNAP / IPv4 / UDP
- Future expected behavior: inner LLC/SNAP continuation reuses the existing shared LLC/SNAP support.

### 09_mpls_pw_unknown_inner_ethertype_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / inner Ethernet / unknown EtherType / Raw
- Conservative current behavior candidate: must not fabricate IPv4 / IPv6 / ARP.

### 10_mpls_pw_truncated_label_stack.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS EtherType / incomplete MPLS label entry
- Conservative current behavior candidate: malformed/truncated MPLS robustness only; no crash.

### 11_mpls_pw_truncated_control_word.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / incomplete pseudowire control word
- Conservative current behavior candidate: malformed/truncated control-word robustness only; no crash.

### 12_mpls_pw_truncated_inner_ethernet.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / partial inner Ethernet header
- Conservative current behavior candidate: no crash; future parser may show partial inner Ethernet.

### 13_mpls_pw_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / inner Ethernet / IPv4 EtherType / partial IPv4 header
- Future expected behavior: safe no-flow handling that reuses the shared partial IPv4 presentation.

### 14_mpls_pw_control_word_with_sequence.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word with non-zero sequence / inner Ethernet / IPv4 / UDP
- Future expected behavior: control-word metadata presentation candidate with non-zero sequence preserved.

### 15_mpls_pw_ambiguous_no_cw_inner_ethernet.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / inner Ethernet / IPv4 / UDP
- Purpose: the inner Ethernet destination MAC begins with `0x02`, so future parser work must not confuse the pseudowire payload with direct MPLS IPv4/IPv6 nibble-based continuation.
- Future expected behavior: parser chooses inner Ethernet pseudowire continuation, not direct IPv4/IPv6 guessing.

## Expected generated file list

- `01_mpls_pw_eth_ipv4_tcp_no_cw.pcap`
- `02_mpls_pw_eth_ipv4_udp_no_cw.pcap`
- `03_mpls_pw_eth_ipv6_tcp_cw.pcap`
- `04_mpls_pw_eth_ipv6_udp_cw.pcap`
- `05_mpls_pw_eth_arp_cw.pcap`
- `06_mpls_pw_eth_vlan_ipv4_tcp_cw.pcap`
- `07_mpls_pw_eth_qinq_ipv4_udp_cw.pcap`
- `08_mpls_pw_eth_llc_snap_ipv4_udp_cw.pcap`
- `09_mpls_pw_unknown_inner_ethertype_cw.pcap`
- `10_mpls_pw_truncated_label_stack.pcap`
- `11_mpls_pw_truncated_control_word.pcap`
- `12_mpls_pw_truncated_inner_ethernet.pcap`
- `13_mpls_pw_truncated_inner_ipv4.pcap`
- `14_mpls_pw_control_word_with_sequence.pcap`
- `15_mpls_pw_ambiguous_no_cw_inner_ethernet.pcap`
