Synthetic EoIP parsing fixtures for regression tests.

This directory contains tiny deterministic `.pcap` fixtures for a future MikroTik EoIP pass.
In this pass, the committed fixtures and active tests establish wire-layout and import/accounting
contracts only. Production EoIP parsing, inner-flow extraction, Packet Details, and protocol-path
expectations are intentionally deferred.

## Purpose

These fixtures cover:
- GRE version 1 EoIP wire shape over outer IPv4 protocol `47`;
- the EoIP-specific four-byte payload-length / tunnel-ID word that follows the GRE base header;
- inner Ethernet continuation with inner IPv4, IPv6, VLAN, and QinQ payloads;
- outer VLAN and outer MPLS preservation before the outer IPv4/GRE carriage;
- deterministic identity edge cases for future tunnel-ID-aware protocol-path flow identity;
- malformed and truncated EoIP robustness cases that must stay conservative.

## Local generation

Run from the repository root with a local Python 3 interpreter:

```bash
python3 tmp/generate_eoip_pcaps.py tests/data/parsing/eoip --force
```

Notes:
- `tmp/generate_eoip_pcaps.py` is a local helper only and is not intended as committed production tooling.
- The script writes classic little-endian Ethernet `.pcap` files with deterministic timestamps, IPv4 IDs, and checksums.
- The script self-validates every generated fixture and fails loudly if a malformed case no longer matches its contract.

## EoIP basics

MikroTik EoIP over IPv4 uses:
- outer IPv4 protocol `47` (`GRE`);
- GRE version `1`;
- GRE K bit set;
- GRE Protocol Type `0x6400`;
- a four-byte word immediately after the GRE base header:
  - first 16 bits: encapsulated Ethernet payload length;
  - second 16 bits: EoIP tunnel ID;
- raw inner Ethernet frame immediately after that word.

The complete normal EoIP header is eight bytes:

```text
20 01 64 00 <payload-length:2> <tunnel-id:2>
```

This fixture set intentionally does **not** encode:
- PPTP Call ID semantics;
- PPTP acknowledgement number;
- GRE checksum or routing fields;
- a second GRE key after the payload-length / tunnel-ID word.

## Future identity policy

Future protocol-path-aware identity for EoIP should normalize the 16-bit tunnel ID into the
existing GRE key slot:

```text
GRE(key=0x00001900)
```

for tunnel ID `6400` (`0x1900`).

Important rules:
- the 16-bit EoIP tunnel ID should participate in future flow identity;
- the 16-bit EoIP payload-length field must **not** participate in identity;
- the raw combined 32-bit on-wire word must **not** be interned as a GRE key, because its upper
  16 bits are packet-dependent payload length;
- same tunnel ID plus same inner tuple should remain one future flow even when inner Ethernet frame
  lengths differ;
- same inner tuple plus different tunnel IDs should split in the future.

No separate `EoIP` protocol-path layer is introduced by these fixtures. The future normalized
identity is expected to reuse the existing GRE key representation.

## Shared deterministic constants

- Outer client MAC: `02:00:00:00:80:01`
- Outer server MAC: `02:00:00:00:80:02`
- Inner client MAC: `02:00:00:00:81:01`
- Inner server MAC: `02:00:00:00:81:02`
- Outer IPv4 client A: `192.0.2.80`
- Outer IPv4 server A: `198.51.100.80`
- Outer IPv4 client B: `192.0.2.81`
- Outer IPv4 server B: `198.51.100.81`
- Inner IPv4 client: `10.80.0.10`
- Inner IPv4 server: `10.80.0.20`
- Inner IPv6 client: `2001:db8:81::10`
- Inner IPv6 server: `2001:db8:81::20`
- TCP client port: `49180`
- TCP server port: `443`
- UDP client port: `53800`
- UDP server port: `443`
- Normal outer VLAN ID: `806`
- Normal inner VLAN ID: `1806`
- Inner QinQ VLAN IDs: `1807`, `1808`
- Primary tunnel ID: `6400`
- Secondary tunnel ID: `6401`
- High tunnel ID: `65535`

Real-capture-inspired deterministic fixture constants for fixture `07`:
- outer VLAN ID: `406`
- MPLS labels:
  - `56474`, bottom-of-stack `false`
  - `477436`, bottom-of-stack `true`
- outer IPv4 client/server: `172.10.0.66 -> 172.10.0.2`
- inner VLAN ID: `3918`
- inner IPv4 client/server: `172.16.72.2 -> 172.19.0.242`
- UDP ports: `12366 -> 12406`

## Current status

In this pass:
- all fixtures are committed and actively validated;
- import/accounting tests are active and green by design;
- parser-independent byte-layout tests are active and green by design;
- production parser expectations are **not** active yet;
- production Packet Details / Summary expectations are **not** active yet.

## Fixture descriptions

### 01_ipv4_eoip_inner_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / GRE version 1 / EoIP / inner Ethernet / inner IPv4 / UDP
- Tunnel ID: `6400`
- Purpose: baseline valid EoIP carriage for inner IPv4 / UDP.

### 02_ipv4_eoip_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / EoIP / inner Ethernet / inner IPv4 / TCP
- Tunnel ID: `6400`
- Purpose: baseline valid EoIP carriage for inner IPv4 / TCP.

### 03_ipv4_eoip_inner_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / EoIP / inner Ethernet / inner IPv6 / UDP
- Tunnel ID: `6400`
- Purpose: baseline valid EoIP carriage for inner IPv6 / UDP.

### 04_ipv4_eoip_inner_vlan_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / EoIP / inner Ethernet / inner VLAN / inner IPv4 / UDP
- Tunnel ID: `6400`
- Purpose: baseline valid inner VLAN continuation behind EoIP.

### 05_ipv4_eoip_inner_qinq_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / EoIP / inner Ethernet / inner QinQ / inner IPv6 / TCP
- Tunnel ID: `6400`
- Purpose: exact inner QinQ continuation contract.

### 06_outer_vlan_ipv4_eoip_inner_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer VLAN / outer IPv4 / EoIP / inner Ethernet / inner IPv4 / UDP
- Tunnel ID: `6400`
- Purpose: preserve outer VLAN before outer IPv4 / GRE.

### 07_outer_vlan_mpls2_ipv4_eoip_inner_vlan_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN 406 / MPLS 56474 / MPLS 477436 / outer IPv4 / EoIP / inner Ethernet / inner VLAN 3918 / inner IPv4 / UDP
- Tunnel ID: `6400`
- Purpose: deterministic equivalent of the observed real capture shape with outer VLAN + MPLS + EoIP.

### 08_same_inner_tuple_different_tunnel_ids.pcap

- Packets: 2
- Same outer IPv4 endpoints and same inner IPv4 / UDP tuple.
- Tunnel IDs: `6400`, `6401`
- Purpose: future identity split baseline for same inner tuple / different tunnel ID.

### 09_same_tunnel_id_different_inner_payload_lengths.pcap

- Packets: 2
- Same tunnel ID: `6400`
- Same inner IPv4 / UDP tuple
- Different inner UDP payload sizes, so the EoIP payload-length field differs between packets
- Purpose: critical future normalization baseline proving payload length must not split identity.

### 10_same_tunnel_id_two_packets.pcap

- Packets: 2
- Same tunnel ID: `6400`
- Same inner tuple and same payload length
- Purpose: future one-flow / two-packet baseline inside one tunnel.

### 11_max_tunnel_id.pcap

- Packets: 1
- Tunnel ID: `65535`
- Purpose: boundary-value tunnel ID encoding coverage.

### 12_truncated_eoip_key_word.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / GRE base header / partial payload-length+tunnel-ID word
- Purpose: truncated EoIP-specific word robustness.

### 13_eoip_payload_length_exceeds_available.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / full EoIP header / too-short bounded inner bytes
- Purpose: declared payload length larger than available inner Ethernet bytes.

### 14_eoip_payload_length_smaller_than_inner_frame.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / full EoIP header / declared bounded frame shorter than following bytes
- Purpose: future parser must stay bounded by declared EoIP payload length.

### 15_eoip_missing_key_bit.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / GRE version 1 with K bit clear / protocol type `0x6400`
- Purpose: negative control proving EoIP must require the GRE K bit.

### 16_gre_v1_unsupported_protocol_type.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / GRE version 1 / protocol type `0x1234`
- Purpose: GRE version-1 unsupported-protocol negative control.

### 17_eoip_truncated_inner_ethernet.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / valid EoIP header / fewer than 14 bytes of inner Ethernet
- Purpose: truncated inner Ethernet robustness.

### 18_eoip_truncated_inner_vlan.pcap

- Packets: 1
- Layer chain: Ethernet / outer IPv4 / valid EoIP header / inner Ethernet addresses + VLAN EtherType + truncated VLAN bytes
- Purpose: truncated inner VLAN robustness.

## Expected generated file list

- `01_ipv4_eoip_inner_ipv4_udp.pcap`
- `02_ipv4_eoip_inner_ipv4_tcp.pcap`
- `03_ipv4_eoip_inner_ipv6_udp.pcap`
- `04_ipv4_eoip_inner_vlan_ipv4_udp.pcap`
- `05_ipv4_eoip_inner_qinq_ipv6_tcp.pcap`
- `06_outer_vlan_ipv4_eoip_inner_ipv4_udp.pcap`
- `07_outer_vlan_mpls2_ipv4_eoip_inner_vlan_ipv4_udp.pcap`
- `08_same_inner_tuple_different_tunnel_ids.pcap`
- `09_same_tunnel_id_different_inner_payload_lengths.pcap`
- `10_same_tunnel_id_two_packets.pcap`
- `11_max_tunnel_id.pcap`
- `12_truncated_eoip_key_word.pcap`
- `13_eoip_payload_length_exceeds_available.pcap`
- `14_eoip_payload_length_smaller_than_inner_frame.pcap`
- `15_eoip_missing_key_bit.pcap`
- `16_gre_v1_unsupported_protocol_type.pcap`
- `17_eoip_truncated_inner_ethernet.pcap`
- `18_eoip_truncated_inner_vlan.pcap`
