Synthetic VLAN parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- single-tag 802.1Q VLAN carrying normal IPv4 / IPv6 transport traffic;
- VLAN-tagged ARP handling;
- stacked VLAN / QinQ encapsulation;
- legacy `0x9100` VLAN-like tagging;
- unknown inner EtherTypes behind VLAN;
- malformed or truncated VLAN frames;
- snaplen-truncated inner payload after a VLAN shim.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python tests/data/parsing/vlan/generate_vlan_pcaps.py --output-dir tests/data/parsing/vlan
```

To overwrite previously generated fixtures:

```bash
python tests/data/parsing/vlan/generate_vlan_pcaps.py --output-dir tests/data/parsing/vlan --force
```

Notes:
- The generator is committed because this VLAN fixture set is still being introduced incrementally.
- Review generated `.pcap` files locally before committing them.
- The script writes classic little-endian Ethernet `.pcap` files with deterministic MAC/IP/port values.
- Stacked `0x88A8`, legacy `0x9100`, and malformed/truncated VLAN cases are written from explicit bytes to stay stable across Scapy versions.

## Shared constants

- Client MAC: `02:00:00:00:20:01`
- Server MAC: `02:00:00:00:20:02`
- Client IPv4: `192.0.2.10`
- Server IPv4: `198.51.100.20`
- ARP target IPv4: `192.0.2.1`
- Client IPv6: `2001:db8:10::10`
- Server IPv6: `2001:db8:20::20`
- Client TCP port: `49152`
- Server TCP port: `443`
- Client UDP port: `53530`
- Server UDP port: `443`

## Current support assumptions

Current repository docs already claim base `802.1Q VLAN` support in shared selected-packet Summary.

Current audited parser behavior:
- single-tag `0x8100` VLAN carrying IPv4 / IPv6 / ARP is supported for normal flow extraction and selected-packet Summary;
- stacked VLAN / QinQ is supported for outer `0x88A8` plus inner VLAN tags;
- legacy `0x9100` tagging is recognized as a supported VLAN-like TPID;
- maximum VLAN tag depth is currently `4`, so triple-tag captures are supported within the bounded limit;
- malformed and snaplen-truncated VLAN cases remain conservative/unrecognized but should preserve Ethernet/VLAN envelope details where they can be decoded safely.

---

### 01_vlan_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / IPv4 / TCP
- VLAN TPID: `0x8100`
- Expected current behavior: candidate normal TCP flow; VLAN should not block IPv4/TCP flow extraction.

### 02_vlan_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / IPv4 / UDP
- VLAN TPID: `0x8100`
- Expected current behavior: candidate normal UDP flow through a single VLAN tag.

### 03_vlan_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / IPv6 / TCP
- VLAN TPID: `0x8100`
- Expected current behavior: candidate normal IPv6/TCP flow through a single VLAN tag.

### 04_vlan_arp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / ARP
- VLAN TPID: `0x8100`
- Expected current behavior: candidate ARP parsing/presentation should still work behind one VLAN tag.

### 05_qinq_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / VLAN / IPv4 / UDP
- Outer TPID: `0x88A8`
- Inner TPID: `0x8100`
- Expected current behavior: normal IPv4/UDP flow through current two-tag QinQ support.

### 06_qinq_arp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / VLAN / ARP
- Outer TPID: `0x88A8`
- Inner TPID: `0x8100`
- Expected current behavior: ARP parsing/presentation should still work through current two-tag QinQ support.

### 07_legacy_9100_vlan_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN-like tag / IPv4 / UDP
- Tag TPID: `0x9100`
- Expected current behavior: normal IPv4/UDP flow through legacy/non-standard VLAN-like encapsulation.

### 08_triple_vlan_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / VLAN / VLAN / IPv4 / TCP
- VLAN TPIDs: `0x8100`, `0x8100`, `0x8100`
- Expected current behavior: normal IPv4/TCP flow through three VLAN tags within the bounded depth limit.

### 09_vlan_unknown_inner_ethertype.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / unknown inner EtherType
- VLAN TPID: `0x8100`
- Expected behavior: conservative fallback only; no crash; selected packet details should still preserve Ethernet/VLAN envelope information.

### 10_vlan_truncated_tag.pcap

- Packets: 1
- Layer chain: Ethernet / partial VLAN
- VLAN TPID indicated: `0x8100`
- Expected behavior: malformed/truncated handling only; no crash; selected packet details should still preserve Ethernet plus VLAN-specific truncation information.

### 11_vlan_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / partial IPv4
- VLAN TPID: `0x8100`
- Expected behavior: capture truncation remains visible; parser stays safe after VLAN and may produce partial or unrecognized behavior depending on current implementation. Richer partial IPv4 presentation is future IPv4 parser work.

## Expected generated file list

- `01_vlan_ipv4_tcp.pcap`
- `02_vlan_ipv4_udp.pcap`
- `03_vlan_ipv6_tcp.pcap`
- `04_vlan_arp.pcap`
- `05_qinq_ipv4_udp.pcap`
- `06_qinq_arp.pcap`
- `07_legacy_9100_vlan_ipv4_udp.pcap`
- `08_triple_vlan_ipv4_tcp.pcap`
- `09_vlan_unknown_inner_ethertype.pcap`
- `10_vlan_truncated_tag.pcap`
- `11_vlan_truncated_inner_ipv4.pcap`
