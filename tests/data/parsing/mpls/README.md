Synthetic MPLS parsing fixtures for future regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- MPLS unicast (`0x8847`) and multicast (`0x8848`) Ethernet encapsulation;
- single-label and multi-label MPLS stacks;
- inner IPv4 and IPv6 payload discovery after MPLS;
- explicit-null, router-alert, repeated-label, and unusual-label cases;
- VLAN and QinQ before MPLS;
- unknown, absent, malformed, and snaplen-truncated MPLS payloads;
- future flow-grouping decisions when inner 5-tuples match but labels differ.

The local helper script that generates these pcaps is intentionally **not** committed.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python3 tmp/generate_mpls_pcaps.py tests/data/parsing/mpls
```

Notes:
- The script is a local helper only and should **not** be committed.
- Review the generated `.pcap` files locally before committing them.
- The generator writes classic little-endian `.pcap` files with deterministic MAC/IP/port values.
- Snaplen-truncated cases are written manually so included length and original wire length differ.

## MPLS basics

- MPLS unicast EtherType: `0x8847`
- MPLS multicast EtherType: `0x8848`
- Each MPLS label stack entry is 4 bytes:
  - Label: 20 bits
  - Traffic Class / TC: 3 bits
  - Bottom of Stack / BoS: 1 bit
  - TTL: 8 bits
- MPLS stack parsing should continue until an entry with `BoS=1` is found.
- After the BoS label, the future parser should infer the inner payload from the first nibble:
  - `4` -> IPv4
  - `6` -> IPv6
  - anything else -> unknown / unsupported inner payload

## Shared constants

- Client MAC: `02:00:00:00:10:01`
- Provider / router MAC: `02:00:00:00:10:02`
- Client IPv4: `192.0.2.10`
- Server IPv4: `198.51.100.20`
- Client IPv6: `2001:db8:1::10`
- Server IPv6: `2001:db8:2::20`
- Client TCP port: `49152`
- Server TCP port: `443`
- Client UDP port: `53530`
- Server UDP port: `443`

## Expected current behavior before dedicated MPLS parsing

For most fixtures in this directory, the current code base is expected to stop at Ethernet and fail to reach inner IPv4/IPv6 transport headers through MPLS. In practice that means:
- normal flow creation will often be absent;
- many packets will likely appear in the unrecognized packet list;
- selected-packet inspection may show Frame/Ethernet and raw bytes only;
- malformed or truncated MPLS should not crash the app.

## Expected future behavior after MPLS parser implementation

Once MPLS parsing is implemented, the parser should:
- recognize MPLS unicast and multicast EtherTypes;
- parse label stacks until `BoS=1`;
- expose MPLS label metadata in Summary / Protocol presentation;
- continue into inner IPv4 or IPv6 when the payload is complete enough;
- create normal flows when an inner IP + transport flow key can be extracted;
- keep malformed or unsupported-inner MPLS packets in unrecognized handling with clear reasons.

---

### 01_mpls_ipv4_tcp_single_label.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / IPv4 / TCP SYN
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 100, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 / TCP
- Expected current behavior: likely unrecognized because MPLS is not parsed yet.
- Expected future behavior: normal TCP flow is created; Summary includes Ethernet -> MPLS -> IPv4 -> TCP; MPLS shows label, TC, BoS, TTL.

### 02_mpls_ipv4_udp_single_label.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / IPv4 / UDP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 101, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 / UDP
- Expected current behavior: likely unrecognized.
- Expected future behavior: normal UDP flow is created; Summary includes Ethernet -> MPLS -> IPv4 -> UDP.

### 03_mpls_ipv6_tcp_single_label.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / IPv6 / TCP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 102, TC 0, BoS 1, TTL 64
- Inner payload: IPv6 / TCP
- Expected current behavior: likely unrecognized.
- Expected future behavior: normal IPv6 TCP flow is created; Summary includes Ethernet -> MPLS -> IPv6 -> TCP.

### 04_mpls_ipv6_udp_single_label.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / IPv6 / UDP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 103, TC 0, BoS 1, TTL 64
- Inner payload: IPv6 / UDP
- Expected current behavior: likely unrecognized.
- Expected future behavior: normal IPv6 UDP flow is created; Summary includes Ethernet -> MPLS -> IPv6 -> UDP.

### 05_mpls_ipv4_tcp_two_labels.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / MPLS / IPv4 / TCP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 16000, TC 0, BoS 0, TTL 64
  - label 16001, TC 0, BoS 1, TTL 63
- Inner payload: IPv4 / TCP
- Expected current behavior: likely unrecognized.
- Expected future behavior: parser preserves both labels and reaches inner IPv4/TCP.

### 06_mpls_ipv4_udp_three_labels.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / MPLS / MPLS / IPv4 / UDP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 100, TC 0, BoS 0, TTL 64
  - label 200, TC 3, BoS 0, TTL 63
  - label 300, TC 5, BoS 1, TTL 62
- Inner payload: IPv4 / UDP
- Expected current behavior: likely unrecognized.
- Expected future behavior: all labels are preserved in order; parser reaches inner IPv4/UDP.

### 07_mpls_ipv6_tcp_two_labels.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / MPLS / IPv6 / TCP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 24000, TC 1, BoS 0, TTL 64
  - label 24001, TC 0, BoS 1, TTL 63
- Inner payload: IPv6 / TCP
- Expected current behavior: likely unrecognized.
- Expected future behavior: parser reaches inner IPv6/TCP.

### 08_mpls_multicast_ethertype_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / IPv4 / UDP
- MPLS EtherType: `0x8848`
- MPLS labels:
  - label 400, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 / UDP
- Expected current behavior: likely unrecognized.
- Expected future behavior: MPLS multicast EtherType is recognized and parser reaches inner IPv4/UDP.

### 09_mpls_ipv4_explicit_null_label.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / IPv4 / TCP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 0, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 / TCP
- Expected current behavior: likely unrecognized.
- Expected future behavior: label 0 may be shown as IPv4 Explicit NULL; inner IPv4/TCP is still parsed.

### 10_mpls_ipv6_explicit_null_label.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / IPv6 / TCP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 2, TC 0, BoS 1, TTL 64
- Inner payload: IPv6 / TCP
- Expected current behavior: likely unrecognized.
- Expected future behavior: label 2 may be shown as IPv6 Explicit NULL; inner IPv6/TCP is still parsed.

### 11_mpls_router_alert_label.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / MPLS / IPv4 / UDP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 1, TC 0, BoS 0, TTL 64
  - label 401, TC 0, BoS 1, TTL 63
- Inner payload: IPv4 / UDP
- Expected current behavior: likely unrecognized.
- Expected future behavior: label 1 is preserved and optionally named Router Alert; parser continues through the stack until BoS.

### 12_mpls_implicit_null_label_unusual.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / IPv4 / TCP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 3, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 / TCP
- Expected current behavior: likely unrecognized.
- Expected future behavior: parser preserves unusual label 3 without crashing; fixture remains documented as wire-unusual robustness coverage.

### 13_vlan_mpls_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / MPLS / IPv4 / TCP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 500, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 / TCP
- Expected current behavior: likely unrecognized.
- Expected future behavior: Summary includes Ethernet -> VLAN -> MPLS -> IPv4 -> TCP and flow key extraction reaches TCP.

### 14_qinq_mpls_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / VLAN / MPLS / IPv4 / UDP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 501, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 / UDP
- Expected current behavior: likely unrecognized.
- Expected future behavior: repeated VLAN tags before MPLS are preserved; if QinQ support still lags MPLS support, treat this as future/edge coverage.

### 15_mpls_unknown_inner_payload.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / Raw
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 600, TC 0, BoS 1, TTL 64
- Inner payload: unknown (first nibble is neither 4 nor 6)
- Expected current behavior: likely unrecognized.
- Expected future behavior: MPLS can be displayed, but no normal flow key is produced; packet may remain unrecognized with a reason such as `Unknown MPLS payload`.

### 16_mpls_no_inner_payload.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 601, TC 0, BoS 1, TTL 64
- Inner payload: absent
- Expected current behavior: likely unrecognized.
- Expected future behavior: MPLS can be displayed; parser reports missing inner payload and does not crash.

### 17_mpls_truncated_label_header.pcap

- Packets: 1
- Layer chain: Ethernet / partial MPLS
- MPLS EtherType: `0x8847`
- MPLS labels: truncated before one full 4-byte entry
- Inner payload: truncated
- Expected current behavior: unrecognized packet with conservative details only.
- Expected future behavior: reason/warning such as `MPLS label header truncated`; no crash.

### 18_mpls_stack_no_bos_before_payload_end.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / MPLS
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 700, TC 0, BoS 0, TTL 64
  - label 701, TC 0, BoS 0, TTL 63
- Inner payload: absent before BoS
- Expected current behavior: unrecognized.
- Expected future behavior: parser does not guess inner IP; warning/reason such as `MPLS bottom-of-stack not found`.

### 19_mpls_second_label_truncated.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / partial MPLS
- MPLS EtherType: `0x8847`
- MPLS labels:
  - first label 800, TC 0, BoS 0, TTL 64
  - second label truncated before full 4 bytes
- Inner payload: truncated before BoS
- Expected current behavior: unrecognized.
- Expected future behavior: first label is preserved; parser reports truncated next MPLS label and does not crash.

### 20_mpls_snaplen_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / partial IPv4
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 900, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 header snaplen-truncated
- Expected current behavior: likely unrecognized.
- Expected future behavior: capture-truncated state is preserved; MPLS is displayed; IPv4 may be partial or warning-only depending parser policy.

### 21_mpls_snaplen_truncated_inner_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / IPv4 / partial TCP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - label 901, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 complete, TCP header snaplen-truncated
- Expected current behavior: likely unrecognized.
- Expected future behavior: MPLS and IPv4 are displayed; packet may remain unrecognized if transport flow key cannot be extracted; Summary/Raw remain available.

### 22_mpls_two_packets_same_ipv4_tcp_flow.pcap

- Packets: 2
- Layer chain: Ethernet / MPLS / IPv4 / TCP
- MPLS EtherType: `0x8847`
- MPLS labels on both packets:
  - label 1000, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 / TCP, same 5-tuple on both packets
- Expected current behavior: likely unrecognized.
- Expected future behavior: one normal flow with two packets; MPLS should not change packet grouping when labels and inner 5-tuple are the same.

### 23_mpls_same_inner_flow_different_labels.pcap

- Packets: 2
- Layer chain: Ethernet / MPLS / IPv4 / TCP
- MPLS EtherType: `0x8847`
- MPLS labels:
  - packet 1: label 1100, TC 0, BoS 1, TTL 64
  - packet 2: label 1200, TC 0, BoS 1, TTL 64
- Inner payload: IPv4 / TCP, same inner 5-tuple on both packets
- Expected current behavior: likely unrecognized.
- Expected future behavior: preferred current design assumption is grouping by inner 5-tuple only, not by MPLS label; if label-aware grouping is chosen later, update this documentation and future tests accordingly.

## Expected generated file list

- `01_mpls_ipv4_tcp_single_label.pcap`
- `02_mpls_ipv4_udp_single_label.pcap`
- `03_mpls_ipv6_tcp_single_label.pcap`
- `04_mpls_ipv6_udp_single_label.pcap`
- `05_mpls_ipv4_tcp_two_labels.pcap`
- `06_mpls_ipv4_udp_three_labels.pcap`
- `07_mpls_ipv6_tcp_two_labels.pcap`
- `08_mpls_multicast_ethertype_ipv4_udp.pcap`
- `09_mpls_ipv4_explicit_null_label.pcap`
- `10_mpls_ipv6_explicit_null_label.pcap`
- `11_mpls_router_alert_label.pcap`
- `12_mpls_implicit_null_label_unusual.pcap`
- `13_vlan_mpls_ipv4_tcp.pcap`
- `14_qinq_mpls_ipv4_udp.pcap`
- `15_mpls_unknown_inner_payload.pcap`
- `16_mpls_no_inner_payload.pcap`
- `17_mpls_truncated_label_header.pcap`
- `18_mpls_stack_no_bos_before_payload_end.pcap`
- `19_mpls_second_label_truncated.pcap`
- `20_mpls_snaplen_truncated_inner_ipv4.pcap`
- `21_mpls_snaplen_truncated_inner_tcp.pcap`
- `22_mpls_two_packets_same_ipv4_tcp_flow.pcap`
- `23_mpls_same_inner_flow_different_labels.pcap`
