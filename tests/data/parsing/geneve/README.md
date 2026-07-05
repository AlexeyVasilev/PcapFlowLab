Synthetic Geneve parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- outer IPv4 / UDP / Geneve carrying inner Ethernet plus IPv4 / IPv6 transport traffic;
- malformed or truncated Geneve base headers;
- malformed Geneve version or option-length handling;
- malformed or truncated inner Ethernet / IPv4 payload after Geneve;
- unsupported Geneve protocol types;
- the known branch limitation where identical inner 5-tuples from different VNIs may still merge;
- future bidirectional inner-flow grouping cases that should collapse into one inner TCP flow;
- same-outer-tuple cases that should eventually split by the inner tuple instead of the outer UDP carrier tuple;
- recursive continuation from Geneve into an inner VLAN-tagged Ethernet payload;
- outer IPv6 Geneve carriage, UDP port-gating negative controls, and a valid non-zero option-length Geneve case.

These fixtures are for the `feature/overlay-inner-flow-tuples` branch.

Current branch intent:
- supported tunnel/overlay parsing should eventually recover an effective inner IPv4/IPv6 plus TCP/UDP tuple;
- Geneve VNI is presentation metadata for now, not part of flow identity;
- malformed Geneve cases should remain conservative and should not fabricate inner flow tuples.

Current implemented status:
- Geneve fixture generator, README, generated `.pcap` files, and flow fixture tests are committed;
- valid UDP/6081 Geneve carrying Ethernet plus inner IPv4/IPv6 plus TCP/UDP now supports inner flow-tuple extraction;
- Geneve option length is handled in 4-byte units and bounded options are skipped safely for tuple extraction;
- Geneve VNI is parsed as metadata, but it is not part of flow identity in this branch yet;
- selected-packet Geneve Summary / Protocol details remain a follow-up step.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python tests/data/parsing/geneve/generate_geneve_pcaps.py --output-dir tests/data/parsing/geneve
```

To overwrite previously generated fixtures:

```bash
python tests/data/parsing/geneve/generate_geneve_pcaps.py --output-dir tests/data/parsing/geneve --force
```

Notes:
- The generator is committed, but generated `.pcap` files are not created in this edit step.
- Review generated `.pcap` files locally before committing them.
- The script writes classic little-endian Ethernet `.pcap` files with deterministic MAC/IP/port/VNI values.
- Geneve headers are assembled from explicit bytes to keep the fixed-header and option-layout cases stable across Scapy versions.

## Shared constants

- Outer source MAC: `02:00:00:00:50:01`
- Outer destination MAC: `02:00:00:00:50:02`
- Outer source IPv4: `203.0.113.50`
- Outer destination IPv4: `203.0.113.51`
- Outer source IPv6: `2001:db8:50:1::1`
- Outer destination IPv6: `2001:db8:50:1::2`
- Outer UDP source port base: `54000`
- Geneve UDP destination port: `6081`
- Negative-control non-Geneve UDP destination port: `6091`
- Inner source MAC: `02:00:00:00:51:01`
- Inner destination MAC: `02:00:00:00:51:02`
- Inner IPv4 source: `10.50.0.10`
- Inner IPv4 destination: `10.50.0.20`
- Alternate inner IPv4 source: `10.50.0.11`
- Alternate inner IPv4 destination: `10.50.0.21`
- Inner IPv6 source: `2001:db8:50::10`
- Inner IPv6 destination: `2001:db8:50::20`
- Inner TCP source port: `49550`
- Inner TCP destination port: `443`
- Inner UDP source port: `53650`
- Inner UDP destination port: `443`
- Alternate inner TCP source ports: `10011`, `10012`
- Inner VLAN ID for recursive shim case: `150`
- Geneve Ethernet protocol type: `0x6558`
- Default VNI: `100`
- Alternate VNI for collision case: `200`

## Current branch behavior and remaining follow-up

Current Geneve behavior in this branch:
- valid Geneve over UDP/6081 with a valid inner Ethernet plus inner IPv4/IPv6 plus TCP/UDP tuple creates a normal flow keyed by the inner tuple;
- bounded Geneve options are skipped safely using the option length field in 4-byte units;
- malformed or truncated Geneve / inner payload cases remain conservative and do not fabricate normal inner flows;
- identical inner tuples from different VNIs are a known limitation in this branch because VNI is not yet part of flow identity;
- selected-packet Summary / Protocol details for Geneve metadata remain future work.

---

### 01_geneve_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Geneve / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.50:54000 -> 203.0.113.51:6081`
- Geneve VNI: `100`
- Option length: `0`
- Inner tuple: `10.50.0.10:49550 -> 10.50.0.20:443`
- Expected current behavior: one normal inner IPv4/TCP flow using the inner tuple as the effective flow endpoints.

### 02_geneve_inner_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Geneve / inner Ethernet / inner IPv4 / UDP / Raw
- Outer tuple: `203.0.113.50:54001 -> 203.0.113.51:6081`
- Geneve VNI: `100`
- Option length: `0`
- Inner tuple: `10.50.0.10:53650 -> 10.50.0.20:443`
- Expected current behavior: one normal inner IPv4/UDP flow using the inner tuple as the effective flow endpoints.

### 03_geneve_inner_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Geneve / inner Ethernet / inner IPv6 / TCP / Raw
- Outer tuple: `203.0.113.50:54002 -> 203.0.113.51:6081`
- Geneve VNI: `100`
- Option length: `0`
- Inner tuple: `2001:db8:50::10:49550 -> 2001:db8:50::20:443`
- Expected current behavior: one normal inner IPv6/TCP flow using the inner tuple as the effective flow endpoints.

### 04_geneve_inner_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Geneve / inner Ethernet / inner IPv6 / UDP / Raw
- Outer tuple: `203.0.113.50:54003 -> 203.0.113.51:6081`
- Geneve VNI: `100`
- Option length: `0`
- Inner tuple: `2001:db8:50::10:53650 -> 2001:db8:50::20:443`
- Expected current behavior: one normal inner IPv6/UDP flow using the inner tuple as the effective flow endpoints.

### 05_geneve_truncated_base_header.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / partial Geneve
- Outer tuple: `203.0.113.50:54004 -> 203.0.113.51:6081`
- Geneve payload length: less than the fixed 8-byte base header
- Expected future behavior: no inner tuple extraction; conservative outer/fallback or unrecognized handling only.

### 06_geneve_invalid_version.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / malformed Geneve / inner Ethernet / inner IPv4 / TCP
- Outer tuple: `203.0.113.50:54005 -> 203.0.113.51:6081`
- Geneve version: `1`
- Geneve VNI: `100`
- Expected future behavior: do not accept the packet as a valid Geneve inner-tuple carrier.

### 07_geneve_options_length_truncated.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / partial Geneve options
- Outer tuple: `203.0.113.50:54006 -> 203.0.113.51:6081`
- Geneve VNI: `100`
- Option length: declares `8` bytes of options, but only `4` bytes are present
- Expected future behavior: no inner tuple extraction.

### 08_geneve_truncated_inner_ethernet.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Geneve / partial inner Ethernet
- Outer tuple: `203.0.113.50:54007 -> 203.0.113.51:6081`
- Geneve VNI: `100`
- Option length: `0`
- Expected current behavior: no inner flow tuple is extracted because the inner Ethernet header is incomplete.

### 09_geneve_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Geneve / inner Ethernet / partial inner IPv4
- Outer tuple: `203.0.113.50:54008 -> 203.0.113.51:6081`
- Geneve VNI: `100`
- Inner Ethernet EtherType: `0x0800`
- Expected current behavior: no normal flow tuple is created; later packet-details work may show partial inner IPv4 fields conservatively.

### 10_geneve_unsupported_protocol_type.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Geneve / non-Ethernet protocol type / Raw
- Outer tuple: `203.0.113.50:54009 -> 203.0.113.51:6081`
- Geneve VNI: `100`
- Protocol type: `0x0800` (IPv4 directly, intentionally outside the initial Ethernet-payload Geneve scope)
- Expected current behavior: no inner Ethernet/IP tuple extraction in the first Geneve pass.

### 11_geneve_inner_ipv4_tcp_bidirectional.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / Geneve / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuples:
  - packet 1: `203.0.113.50:54010 -> 203.0.113.51:6081`
  - packet 2: `203.0.113.50:54011 -> 203.0.113.51:6081`
- Geneve VNI for both packets: `100`
- Inner tuples:
  - packet 1: `10.50.0.10:49550 -> 10.50.0.20:443`
  - packet 2: `10.50.0.20:443 -> 10.50.0.10:49550`
- Expected current behavior: both packets belong to one bidirectional inner IPv4/TCP flow.

### 12_geneve_same_outer_tuple_different_inner_flows.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / Geneve / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuple for both packets: `203.0.113.50:54012 -> 203.0.113.51:6081`
- Geneve VNI for both packets: `100`
- Inner tuples:
  - packet 1: `10.50.0.10:10011 -> 10.50.0.20:443`
  - packet 2: `10.50.0.10:10012 -> 10.50.0.20:443`
- Expected current behavior: these become two distinct inner IPv4/TCP flows based on the inner tuple.

### 13_geneve_inner_vlan_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Geneve / inner Ethernet / 802.1Q VLAN / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.50:54013 -> 203.0.113.51:6081`
- Geneve VNI: `100`
- Inner VLAN ID: `150`
- Inner tuple: `10.50.0.10:49550 -> 10.50.0.20:443`
- Expected current behavior: Geneve parsing recognizes Geneve and continues through the existing inner Ethernet/VLAN/IP/TCP path to recover the inner tuple.

### 14_geneve_outer_ipv6_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv6 / UDP / Geneve / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuple: `2001:db8:50:1::1:54014 -> 2001:db8:50:1::2:6081`
- Geneve VNI: `100`
- Inner tuple: `10.50.0.10:49550 -> 10.50.0.20:443`
- Expected current behavior: outer IPv6 carriage does not prevent Geneve recognition or inner IPv4/TCP tuple extraction.

### 15_geneve_wrong_udp_port_valid_geneve_payload.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP(non-6081) / bytes that otherwise resemble Geneve / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.50:54015 -> 203.0.113.51:6091`
- Embedded VNI bytes: `100`
- Inner tuple if decapsulated hypothetically: `10.50.0.10:49550 -> 10.50.0.20:443`
- Expected current behavior: negative control for UDP port gating; do not treat this as Geneve in the basic parser and do not extract an inner Geneve tuple.

### 16_geneve_vni_boundary_values.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / Geneve / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuples:
  - packet 1: `203.0.113.50:54016 -> 203.0.113.51:6081`
  - packet 2: `203.0.113.50:54017 -> 203.0.113.51:6081`
- Geneve VNIs:
  - packet 1: `0`
  - packet 2: `16777215`
- Inner tuples:
  - packet 1: `10.50.0.10:49550 -> 10.50.0.20:443`
  - packet 2: `10.50.0.11:10011 -> 10.50.0.21:443`
- Expected current behavior: valid Geneve packets produce inner flows for both VNI boundary values. VNI still remains outside flow identity in this branch.

### 17_geneve_with_options_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Geneve / options / inner Ethernet / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.50:54018 -> 203.0.113.51:6081`
- Geneve VNI: `100`
- Option length: `8` bytes
- Option shape: one deterministic 8-byte option block with a 4-byte Geneve option header and 4 bytes of option data
- Inner tuple: `10.50.0.10:49550 -> 10.50.0.20:443`
- Expected current behavior: parser skips bounded options safely and extracts the inner tuple.

## Expected generated file list

- `01_geneve_inner_ipv4_tcp.pcap`
- `02_geneve_inner_ipv4_udp.pcap`
- `03_geneve_inner_ipv6_tcp.pcap`
- `04_geneve_inner_ipv6_udp.pcap`
- `05_geneve_truncated_base_header.pcap`
- `06_geneve_invalid_version.pcap`
- `07_geneve_options_length_truncated.pcap`
- `08_geneve_truncated_inner_ethernet.pcap`
- `09_geneve_truncated_inner_ipv4.pcap`
- `10_geneve_unsupported_protocol_type.pcap`
- `11_geneve_inner_ipv4_tcp_bidirectional.pcap`
- `12_geneve_same_outer_tuple_different_inner_flows.pcap`
- `13_geneve_inner_vlan_ipv4_tcp.pcap`
- `14_geneve_outer_ipv6_inner_ipv4_tcp.pcap`
- `15_geneve_wrong_udp_port_valid_geneve_payload.pcap`
- `16_geneve_vni_boundary_values.pcap`
- `17_geneve_with_options_inner_ipv4_tcp.pcap`
