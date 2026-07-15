Synthetic IP encapsulation parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- outer IPv4 protocol `4` carrying inner IPv4;
- outer IPv4 protocol `41` carrying inner IPv6;
- outer IPv6 next-header `4` carrying inner IPv4;
- outer IPv6 next-header `41` carrying inner IPv6;
- outer VLAN / QinQ before the outer IP header;
- repeated nested inner IP layers;
- same-inner-tuple grouping tradeoffs across different outer tunnel endpoints;
- conservative handling for truncated or too-short inner payloads.

The local helper scripts that generate these pcaps are intentionally **not** committed as project artifacts. They are local stdlib-only helpers under `tmp/`.

## Local generation

Preferred local helper:

```bash
python3 tmp/generate_ip_encapsulation_pcaps.py tests/data/parsing/ip_encapsulation --force
```

PowerShell fallback used in environments without a Python launcher:

```powershell
powershell -ExecutionPolicy Bypass -File tmp/generate_ip_encapsulation_pcaps.ps1 tests/data/parsing/ip_encapsulation
```

Notes:
- the helpers are local-only and should not be treated as production tooling;
- they write classic little-endian Ethernet `.pcap` files with deterministic MAC/IP/port values;
- truncation fixtures are written manually so captured length and original wire length can differ when useful;
- fixture integrity and import/accounting tests now exist for this directory;
- parser expectations remain deferred until the parser implementation iterations;
- plain IP encapsulation parsing is still not implemented by this test-only pass.

## Protocol basics

- IPv4 protocol `4`: IPv4-in-IP
- IPv4 protocol `41`: IPv6 encapsulation over IPv4
- IPv6 next-header `4`: inner IPv4 over IPv6
- IPv6 next-header `41`: inner IPv6 over IPv6

Expected future parser behavior:
- outer IP header remains part of the protocol path;
- the innermost recognized IPv4/IPv6 + TCP/UDP/SCTP tuple should drive flow extraction;
- inner ICMP / ICMPv6 should follow existing control-protocol handling;
- outer VLAN/QinQ should remain preserved before the outer IP layer;
- no tunnel namespace identifier is added in v1 for basic IP-in-IP encapsulation;
- same inner tuple through different outer tunnel endpoints may merge in v1 because outer tunnel endpoints are not intended to participate in protocol-path identity.

Expected future paths include:
- `EthernetII -> IPv4 -> IPv4 -> TCP`
- `EthernetII -> IPv4 -> IPv6 -> UDP`
- `EthernetII -> IPv6 -> IPv4 -> TCP`
- `EthernetII -> IPv6 -> IPv6 -> UDP`
- repeated nested IP layers such as `EthernetII -> IPv4 -> IPv4 -> IPv4 -> UDP`

## Shared constants

- Outer client MAC: `02:00:00:00:60:01`
- Outer server MAC: `02:00:00:00:60:02`
- Outer IPv4 client A: `192.0.2.60`
- Outer IPv4 server A: `198.51.100.60`
- Outer IPv4 client B: `192.0.2.61`
- Outer IPv4 server B: `198.51.100.61`
- Inner IPv4 client: `10.60.0.10`
- Inner IPv4 server: `10.60.0.20`
- Outer IPv6 client A: `2001:db8:60::1`
- Outer IPv6 server A: `2001:db8:60::2`
- Outer IPv6 client B: `2001:db8:60::11`
- Outer IPv6 server B: `2001:db8:60::12`
- Inner IPv6 client: `2001:db8:61::10`
- Inner IPv6 server: `2001:db8:61::20`
- TCP client port: `49160`
- TCP server port: `443`
- UDP client port: `53600`
- UDP server port: `443`
- Outer VLAN ID: `660`
- Outer QinQ VLAN IDs: `661`, `662`

## Fixture descriptions

### 01_ipv4_in_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4(proto=4) / inner IPv4 / TCP
- Expected future path: `EthernetII -> IPv4 -> IPv4 -> TCP`

### 02_ipv4_in_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4(proto=4) / inner IPv4 / UDP
- Expected future path: `EthernetII -> IPv4 -> IPv4 -> UDP`

### 03_ipv6_in_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4(proto=41) / inner IPv6 / TCP
- Expected future path: `EthernetII -> IPv4 -> IPv6 -> TCP`

### 04_ipv6_in_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4(proto=41) / inner IPv6 / UDP
- Expected future path: `EthernetII -> IPv4 -> IPv6 -> UDP`

### 05_ipv4_in_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv6(next-header=4) / inner IPv4 / TCP
- Expected future path: `EthernetII -> IPv6 -> IPv4 -> TCP`

### 06_ipv4_in_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv6(next-header=4) / inner IPv4 / UDP
- Expected future path: `EthernetII -> IPv6 -> IPv4 -> UDP`

### 07_ipv6_in_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv6(next-header=41) / inner IPv6 / TCP
- Expected future path: `EthernetII -> IPv6 -> IPv6 -> TCP`

### 08_ipv6_in_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv6(next-header=41) / inner IPv6 / UDP
- Expected future path: `EthernetII -> IPv6 -> IPv6 -> UDP`

### 09_outer_vlan_ipv4_in_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN(660) / outer IPv4(proto=4) / inner IPv4 / UDP
- Expected future path: `EthernetII -> VLAN(vid=660) -> IPv4 -> IPv4 -> UDP`

### 10_outer_qinq_ipv6_in_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN(661) / VLAN(662) / outer IPv4(proto=41) / inner IPv6 / TCP
- Expected future path: `EthernetII -> VLAN(vid=661) -> VLAN(vid=662) -> IPv4 -> IPv6 -> TCP`

### 11_outer_vlan_ipv4_in_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN(660) / outer IPv6(next-header=4) / inner IPv4 / UDP
- Expected future path: `EthernetII -> VLAN(vid=660) -> IPv6 -> IPv4 -> UDP`

### 12_nested_ipv4_in_ipv4_in_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4(proto=4) / middle IPv4(proto=4) / inner IPv4 / UDP
- Expected future path: `EthernetII -> IPv4 -> IPv4 -> IPv4 -> UDP`
- Purpose: repeated inner IPv4 layers should remain positional in the protocol path.

### 13_same_inner_tuple_different_outer_ipv4_tunnels.pcap

- Packets: 2
- Same inner IPv4/UDP tuple appears through two different outer IPv4 tunnel endpoint pairs.
- Accepted v1 tradeoff: these may later merge into one flow because outer tunnel endpoints are not intended to participate in protocol-path identity.

### 14_same_inner_tuple_same_outer_ipv4_two_packets.pcap

- Packets: 2
- Same outer IPv4 endpoints and same inner IPv4/UDP tuple.
- Expected future behavior: one flow with two packets.

### 15_ipv4_in_ipv4_inner_icmp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4(proto=4) / inner IPv4 / ICMP echo request
- Expected future path: `EthernetII -> IPv4 -> IPv4`
- Terminal ICMP layer may remain outside path presentation if project policy continues to exclude terminal control badges.

### 16_ipv6_in_ipv4_inner_icmpv6.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4(proto=41) / inner IPv6 / ICMPv6 echo request
- Expected future path: `EthernetII -> IPv4 -> IPv6`
- Terminal ICMPv6 layer may remain outside path presentation if project policy continues to exclude terminal control badges.

### 17_truncated_inner_ipv4_header.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4(proto=4) / partial inner IPv4
- Expected future behavior: conservative handling only; no crash and no fabricated inner TCP/UDP flow.

### 18_truncated_inner_ipv6_header.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4(proto=41) / partial inner IPv6
- Expected future behavior: conservative handling only; no crash.

### 19_outer_ipv4_proto4_payload_too_short.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4(proto=4) / tiny non-header payload
- Expected future behavior: no crash and no fabricated inner flow.

### 20_ipv6_next41_payload_too_short.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv6(next-header=41) / tiny non-header payload
- Expected future behavior: no crash and no fabricated inner flow.

## Expected generated file list

- `01_ipv4_in_ipv4_tcp.pcap`
- `02_ipv4_in_ipv4_udp.pcap`
- `03_ipv6_in_ipv4_tcp.pcap`
- `04_ipv6_in_ipv4_udp.pcap`
- `05_ipv4_in_ipv6_tcp.pcap`
- `06_ipv4_in_ipv6_udp.pcap`
- `07_ipv6_in_ipv6_tcp.pcap`
- `08_ipv6_in_ipv6_udp.pcap`
- `09_outer_vlan_ipv4_in_ipv4_udp.pcap`
- `10_outer_qinq_ipv6_in_ipv4_tcp.pcap`
- `11_outer_vlan_ipv4_in_ipv6_udp.pcap`
- `12_nested_ipv4_in_ipv4_in_ipv4_udp.pcap`
- `13_same_inner_tuple_different_outer_ipv4_tunnels.pcap`
- `14_same_inner_tuple_same_outer_ipv4_two_packets.pcap`
- `15_ipv4_in_ipv4_inner_icmp.pcap`
- `16_ipv6_in_ipv4_inner_icmpv6.pcap`
- `17_truncated_inner_ipv4_header.pcap`
- `18_truncated_inner_ipv6_header.pcap`
- `19_outer_ipv4_proto4_payload_too_short.pcap`
- `20_ipv6_next41_payload_too_short.pcap`
