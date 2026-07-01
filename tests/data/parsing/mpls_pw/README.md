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

These fixtures are now exercised by shared MPLS pseudowire regression tests.
Current committed behavior covers bounded MPLS Ethernet pseudowire continuation into:
- inner Ethernet II and inner IEEE 802.3;
- optional 4-byte pseudowire control word presentation;
- inner VLAN / QinQ;
- inner LLC / SNAP;
- inner ARP / IPv4 / IPv6 continuation when the bounded inner payload is valid.

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
- Current committed behavior supports basic MPLS Ethernet pseudowire parsing and presentation.

## Current support assumptions

Current committed MPLS support in PcapFlowLab covers:
- direct MPLS-to-IPv4/IPv6 continuation after the BoS label;
- Ethernet pseudowire continuation after the BoS label;
- optional 4-byte pseudowire control word recognition when the bounded bytes match the pseudowire shape;
- inner Ethernet continuation through VLAN / QinQ / LLC-SNAP into ARP / IPv4 / IPv6 when supported by existing shared parsers;
- conservative no-flow handling for malformed/truncated pseudowire payloads and unknown inner EtherTypes.

## Current conservative limits

The current implementation is intentionally bounded and conservative:
- it does not attempt generic MPLS pseudowire continuation for arbitrary unknown inner protocols;
- unknown inner Ethernet EtherTypes remain no-flow with bounded Data presentation;
- malformed or truncated label/control-word/inner-Ethernet/inner-IPv4 cases remain no-flow;
- deeper protocol-specific `Protocol` tab rendering is still driven by existing shared analyzers rather than a new MPLS-specific protocol-text system.

## Fixture list

### 01_mpls_pw_eth_ipv4_tcp_no_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / inner Ethernet / IPv4 / TCP / Raw
- Current expected behavior: recover inner Ethernet and form a normal IPv4/TCP flow.

### 02_mpls_pw_eth_ipv4_udp_no_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / inner Ethernet / IPv4 / UDP / Raw
- Current expected behavior: recover inner Ethernet and form a normal IPv4/UDP flow.

### 03_mpls_pw_eth_ipv6_tcp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / pseudowire control word / inner Ethernet / IPv6 / TCP / Raw
- Current expected behavior: parse the control word and recover an inner IPv6/TCP flow.

### 04_mpls_pw_eth_ipv6_udp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / pseudowire control word / inner Ethernet / IPv6 / UDP / Raw
- Current expected behavior: parse the control word and recover an inner IPv6/UDP flow.

### 05_mpls_pw_eth_arp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / pseudowire control word / inner Ethernet / ARP
- Current expected behavior: ARP recognized behind the MPLS pseudowire.

### 06_mpls_pw_eth_vlan_ipv4_tcp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / inner Ethernet / VLAN / IPv4 / TCP
- Current expected behavior: inner VLAN does not block IPv4/TCP continuation.

### 07_mpls_pw_eth_qinq_ipv4_udp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / inner Ethernet / QinQ / VLAN / IPv4 / UDP
- Current expected behavior: stacked inner VLAN tags do not block IPv4/UDP continuation.

### 08_mpls_pw_eth_llc_snap_ipv4_udp_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / inner Ethernet 802.3 length / LLC / SNAP / IPv4 / UDP
- Current expected behavior: inner LLC/SNAP continuation reuses the existing shared LLC/SNAP support.

### 09_mpls_pw_unknown_inner_ethertype_cw.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / inner Ethernet / unknown EtherType / Raw
- Current expected behavior: no normal flow is formed; parser preserves inner Ethernet and bounded unknown-payload presentation without fabricating IPv4 / IPv6 / ARP.

### 10_mpls_pw_truncated_label_stack.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS EtherType / incomplete MPLS label entry
- Current expected behavior: malformed/truncated MPLS robustness only; no crash.

### 11_mpls_pw_truncated_control_word.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / incomplete pseudowire control word
- Current expected behavior: malformed/truncated control-word robustness only; no crash.

### 12_mpls_pw_truncated_inner_ethernet.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / partial inner Ethernet header
- Current expected behavior: no crash; partial inner Ethernet details remain visible conservatively.

### 13_mpls_pw_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word / inner Ethernet / IPv4 EtherType / partial IPv4 header
- Current expected behavior: safe no-flow handling that reuses the shared partial IPv4 presentation.

### 14_mpls_pw_control_word_with_sequence.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / control word with non-zero sequence / inner Ethernet / IPv4 / UDP
- Current expected behavior: control-word metadata presentation preserves the non-zero sequence value.

### 15_mpls_pw_ambiguous_no_cw_inner_ethernet.pcap

- Packets: 1
- Layer chain: Outer Ethernet / MPLS label stack / inner Ethernet / IPv4 / UDP
- Purpose: the inner Ethernet destination MAC begins with `0x02`, so the parser must not confuse the pseudowire payload with direct MPLS IPv4/IPv6 nibble-based continuation.
- Current expected behavior: parser chooses inner Ethernet pseudowire continuation, not direct IPv4/IPv6 guessing.

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
