Synthetic VXLAN parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- outer IPv4 / UDP / VXLAN carrying inner Ethernet plus IPv4 / IPv6 transport traffic;
- malformed or truncated VXLAN headers;
- malformed or truncated inner Ethernet / IPv4 payload after VXLAN;
- unsupported inner Ethernet payloads behind a valid VXLAN header;
- the known branch limitation where identical inner 5-tuples from different VNIs may still merge.
- future bidirectional inner-flow grouping cases that should collapse into one inner TCP flow;
- same-outer-tuple cases that should eventually split by the inner tuple instead of the outer UDP carrier tuple;
- recursive continuation from VXLAN into an inner VLAN-tagged Ethernet payload;
- outer IPv6 VXLAN carriage and UDP port-gating negative controls.

These fixtures are for the `feature/overlay-inner-flow-tuples` branch.

Current branch intent:
- supported tunnel/overlay parsing should eventually recover an effective inner IPv4/IPv6 plus TCP/UDP tuple;
- VXLAN VNI is presentation metadata for now, not part of flow identity;
- malformed VXLAN cases should remain conservative and should not fabricate inner flow tuples.

Current implemented status:
- valid UDP/4789 VXLAN carrying inner Ethernet plus IPv4/IPv6 plus TCP/UDP now uses the inner tuple for flow grouping;
- valid inner Ethernet plus VLAN plus IPv4 plus TCP continuation is also expected to work through the existing inner Ethernet/VLAN path;
- selected-packet Summary / Protocol details now expose VXLAN metadata, including flags, VNI flag state, and VNI, and Summary continues with sequential inner Ethernet plus VLAN/IP/TCP/UDP layers whose inner titles include addresses/ports where applicable;
- VNI is still not part of flow identity, so identical inner tuples from different VNIs may still merge.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python tests/data/parsing/vxlan/generate_vxlan_pcaps.py --output-dir tests/data/parsing/vxlan
```

To overwrite previously generated fixtures:

```bash
python tests/data/parsing/vxlan/generate_vxlan_pcaps.py --output-dir tests/data/parsing/vxlan --force
```

Notes:
- The generator is committed, but generated `.pcap` files are not created in this edit step.
- Review generated `.pcap` files locally before committing them.
- The script writes classic little-endian Ethernet `.pcap` files with deterministic MAC/IP/port values.
- VXLAN headers are assembled from explicit bytes to keep the fixed-header cases stable across Scapy versions.

## Shared constants

- Outer source MAC: `02:00:00:00:40:01`
- Outer destination MAC: `02:00:00:00:40:02`
- Outer source IPv4: `203.0.113.40`
- Outer destination IPv4: `203.0.113.41`
- Outer source IPv6: `2001:db8:40:1::1`
- Outer destination IPv6: `2001:db8:40:1::2`
- Outer UDP source port: `53000`
- VXLAN UDP destination port: `4789`
- Negative-control non-VXLAN UDP destination port: `4799`
- Inner source MAC: `02:00:00:00:41:01`
- Inner destination MAC: `02:00:00:00:41:02`
- Inner IPv4 source: `10.40.0.10`
- Inner IPv4 destination: `10.40.0.20`
- Alternate inner IPv4 source: `10.40.0.11`
- Alternate inner IPv4 destination: `10.40.0.21`
- Inner IPv6 source: `2001:db8:40::10`
- Inner IPv6 destination: `2001:db8:40::20`
- Inner TCP source port: `49440`
- Inner TCP destination port: `443`
- Inner UDP source port: `53540`
- Inner UDP destination port: `443`
- Alternate inner TCP source ports: `10001`, `10002`
- Inner VLAN ID for recursive shim case: `140`
- Default VNI: `100`
- Alternate VNI for collision case: `200`

## Future support assumptions for this branch

Planned VXLAN behavior for later implementation steps:
- valid VXLAN over UDP/4789 with a valid inner Ethernet plus inner IPv4/IPv6 plus TCP/UDP tuple should eventually create a normal flow keyed by the inner tuple;
- selected-packet Summary / Protocol details should preserve outer IPv4 / UDP plus VXLAN layer metadata, including VNI;
- malformed or truncated VXLAN / inner payload cases should remain conservative and should not fabricate normal inner flows;
- identical inner tuples from different VNIs are a known limitation in this branch because VNI is not yet part of flow identity.

---

### 01_vxlan_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.40:53000 -> 203.0.113.41:4789`
- VNI: `100`
- Inner tuple: `10.40.0.10:49440 -> 10.40.0.20:443`
- Expected future behavior: candidate normal inner IPv4/TCP flow using the inner tuple as the effective flow endpoints.

### 02_vxlan_inner_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / inner IPv4 / UDP / Raw
- Outer tuple: `203.0.113.40:53001 -> 203.0.113.41:4789`
- VNI: `100`
- Inner tuple: `10.40.0.10:53540 -> 10.40.0.20:443`
- Expected future behavior: candidate normal inner IPv4/UDP flow using the inner tuple as the effective flow endpoints.

### 03_vxlan_inner_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / inner IPv6 / TCP / Raw
- Outer tuple: `203.0.113.40:53002 -> 203.0.113.41:4789`
- VNI: `100`
- Inner tuple: `2001:db8:40::10:49440 -> 2001:db8:40::20:443`
- Expected future behavior: candidate normal inner IPv6/TCP flow using the inner tuple as the effective flow endpoints.

### 04_vxlan_inner_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / inner IPv6 / UDP / Raw
- Outer tuple: `203.0.113.40:53003 -> 203.0.113.41:4789`
- VNI: `100`
- Inner tuple: `2001:db8:40::10:53540 -> 2001:db8:40::20:443`
- Expected future behavior: candidate normal inner IPv6/UDP flow using the inner tuple as the effective flow endpoints.

### 05_vxlan_truncated_header.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / partial VXLAN
- Outer tuple: `203.0.113.40:53004 -> 203.0.113.41:4789`
- VXLAN payload length: less than the fixed 8-byte VXLAN header
- Expected future behavior: no inner tuple extraction; conservative outer/fallback or unrecognized handling only.

### 06_vxlan_invalid_flags_or_reserved_bits.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / malformed VXLAN / inner Ethernet / inner IPv4 / UDP
- Outer tuple: `203.0.113.40:53005 -> 203.0.113.41:4789`
- VNI field present but VXLAN flags intentionally invalid for a basic valid frame
- Expected future behavior: do not accept the packet as a valid VXLAN inner-tuple carrier.

### 07_vxlan_truncated_inner_ethernet.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / partial inner Ethernet
- Outer tuple: `203.0.113.40:53006 -> 203.0.113.41:4789`
- VNI: `100`
- Expected future behavior: VXLAN header may be recognized, but no inner flow tuple should be extracted because the inner Ethernet header is incomplete.

### 08_vxlan_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / partial inner IPv4
- Outer tuple: `203.0.113.40:53007 -> 203.0.113.41:4789`
- VNI: `100`
- Inner Ethernet EtherType: `0x0800`
- Expected future behavior: no normal flow tuple should be created; later packet-details work may show partial inner IPv4 fields conservatively.

### 09_vxlan_unsupported_inner_ethertype.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / unsupported inner EtherType / Raw
- Outer tuple: `203.0.113.40:53008 -> 203.0.113.41:4789`
- VNI: `100`
- Inner Ethernet EtherType: synthetic unsupported value `0x88b5`
- Expected future behavior: VXLAN may be recognized, but no inner IPv4/IPv6 TCP/UDP tuple should be extracted.

### 10_vxlan_same_inner_tuple_different_vni.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuples:
  - packet 1: `203.0.113.40:53009 -> 203.0.113.41:4789`
  - packet 2: `203.0.113.40:53010 -> 203.0.113.41:4789`
- VNIs:
  - packet 1: `100`
- packet 2: `200`
- Inner tuple for both packets: `10.40.0.10:49440 -> 10.40.0.20:443`
- Expected future behavior: known limitation case; current branch may merge both packets into one flow because VNI is not part of flow identity yet.

### 11_vxlan_inner_ipv4_tcp_bidirectional.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuples:
  - packet 1: `203.0.113.40:53011 -> 203.0.113.41:4789`
  - packet 2: `203.0.113.40:53012 -> 203.0.113.41:4789`
- VNI for both packets: `100`
- Inner tuples:
  - packet 1: `10.40.0.10:49440 -> 10.40.0.20:443`
  - packet 2: `10.40.0.20:443 -> 10.40.0.10:49440`
- Expected future behavior: both packets should belong to one bidirectional inner IPv4/TCP flow after VXLAN support is implemented.

### 12_vxlan_same_outer_tuple_different_inner_flows.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuple for both packets: `203.0.113.40:53013 -> 203.0.113.41:4789`
- VNI for both packets: `100`
- Inner tuples:
  - packet 1: `10.40.0.10:10001 -> 10.40.0.20:443`
  - packet 2: `10.40.0.10:10002 -> 10.40.0.20:443`
- Expected future behavior: after VXLAN support, these should become two distinct inner IPv4/TCP flows based on the inner tuple.
- Expected current pre-parser behavior: this case is intended to document why future tests should initially fail if traffic still collapses into one outer UDP/4789 flow.

### 13_vxlan_inner_vlan_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / 802.1Q VLAN / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.40:53014 -> 203.0.113.41:4789`
- VNI: `100`
- Inner VLAN ID: `140`
- Inner tuple: `10.40.0.10:49440 -> 10.40.0.20:443`
- Expected future behavior: VXLAN parsing should recognize VXLAN and continue through the existing inner Ethernet/VLAN/IP/TCP path to recover the inner tuple.

### 14_vxlan_outer_ipv6_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv6 / UDP / VXLAN / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuple: `2001:db8:40:1::1:53015 -> 2001:db8:40:1::2:4789`
- VNI: `100`
- Inner tuple: `10.40.0.10:49440 -> 10.40.0.20:443`
- Expected future behavior: outer IPv6 carriage should not prevent VXLAN recognition or inner IPv4/TCP tuple extraction.

### 15_vxlan_wrong_udp_port_valid_vxlan_payload.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP(non-4789) / bytes that otherwise resemble VXLAN / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.40:53016 -> 203.0.113.41:4799`
- Embedded VNI bytes: `100`
- Inner tuple if decapsulated hypothetically: `10.40.0.10:49440 -> 10.40.0.20:443`
- Expected future behavior: negative control for UDP port gating; do not treat this as VXLAN in the basic parser and do not extract an inner VXLAN tuple.

### 16_vxlan_vni_boundary_values.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuples:
  - packet 1: `203.0.113.40:53017 -> 203.0.113.41:4789`
  - packet 2: `203.0.113.40:53018 -> 203.0.113.41:4789`
- VNIs:
  - packet 1: `0`
  - packet 2: `16777215`
- Inner tuples:
  - packet 1: `10.40.0.10:49440 -> 10.40.0.20:443`
  - packet 2: `10.40.0.11:10001 -> 10.40.0.21:443`
- Expected future behavior: VXLAN metadata extraction should preserve and display VNI boundary values. VNI still remains outside flow identity in this branch.

## Expected generated file list

- `01_vxlan_inner_ipv4_tcp.pcap`
- `02_vxlan_inner_ipv4_udp.pcap`
- `03_vxlan_inner_ipv6_tcp.pcap`
- `04_vxlan_inner_ipv6_udp.pcap`
- `05_vxlan_truncated_header.pcap`
- `06_vxlan_invalid_flags_or_reserved_bits.pcap`
- `07_vxlan_truncated_inner_ethernet.pcap`
- `08_vxlan_truncated_inner_ipv4.pcap`
- `09_vxlan_unsupported_inner_ethertype.pcap`
- `10_vxlan_same_inner_tuple_different_vni.pcap`
- `11_vxlan_inner_ipv4_tcp_bidirectional.pcap`
- `12_vxlan_same_outer_tuple_different_inner_flows.pcap`
- `13_vxlan_inner_vlan_ipv4_tcp.pcap`
- `14_vxlan_outer_ipv6_inner_ipv4_tcp.pcap`
- `15_vxlan_wrong_udp_port_valid_vxlan_payload.pcap`
- `16_vxlan_vni_boundary_values.pcap`
