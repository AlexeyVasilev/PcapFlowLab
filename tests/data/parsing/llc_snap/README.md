Synthetic LLC/SNAP parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- IEEE 802.3 length-based Ethernet framing followed by LLC;
- SNAP encapsulation with both Ethernet OUI `00:00:00` and non-zero OUI variants;
- inner IPv4 / IPv6 / ARP payload recovery through LLC/SNAP;
- VLAN and QinQ before LLC/SNAP as candidate shim-composition cases;
- unknown SNAP PID handling;
- non-SNAP LLC fallback handling;
- malformed or truncated LLC/SNAP envelopes;
- IEEE 802.3 length-boundary mismatch cases.

Current committed support in this branch is intentionally narrow:
- IEEE 802.3 length-based Ethernet framing is distinguished from Ethernet II;
- LLC/SNAP is recognized only for DSAP `0xaa`, SSAP `0xaa`, Control `0x03`;
- SNAP continuation is supported for known PID values regardless of OUI when the bounded payload validates:
  - IPv4 `0x0800`
  - IPv6 `0x86dd`
  - ARP `0x0806`
- VLAN and QinQ before LLC/SNAP are supported for the same bounded continuation path;
- unknown SNAP PID and non-SNAP LLC remain conservative no-flow cases with bounded Data/raw preview in selected-packet Summary;
- malformed LLC/SNAP headers remain best-effort with specific truncation warnings;
- IEEE 802.3 length bounds are respected for inner parsing, and trailing bytes beyond the declared 802.3 length are ignored.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python tests/data/parsing/llc_snap/generate_llc_snap_pcaps.py --output-dir tests/data/parsing/llc_snap
```

To overwrite previously generated fixtures:

```bash
python tests/data/parsing/llc_snap/generate_llc_snap_pcaps.py --output-dir tests/data/parsing/llc_snap --force
```

Notes:
- The generator is committed because this LLC/SNAP fixture set is still being introduced incrementally.
- Review generated `.pcap` files locally before committing them.
- The script writes classic little-endian Ethernet `.pcap` files with deterministic MAC/IP/port values.
- Scapy is used for stable inner IPv4 / IPv6 / TCP / UDP / ARP payloads.
- Ethernet 802.3 length framing, LLC, SNAP, malformed envelopes, and length-mismatch cases are written from explicit bytes so behavior stays stable across Scapy versions.

## Shared constants

- Host A MAC: `02:00:00:00:40:01`
- Host B MAC: `02:00:00:00:40:02`
- Host A IPv4: `192.0.2.40`
- Host B IPv4: `198.51.100.40`
- Host A IPv6: `2001:db8:40::10`
- Host B IPv6: `2001:db8:40::20`
- TCP source port: `49170`
- TCP destination port: `443`
- UDP source port: `53550`
- UDP destination port: `443`
- SNAP Ethernet OUI: `00:00:00`

## IEEE 802.3 / LLC / SNAP basics

- Ethernet II uses EtherType values `>= 0x0600`.
- IEEE 802.3 uses a length field `< 0x0600`.
- LLC/SNAP frames in this fixture set use:
  - DSAP `0xaa`
  - SSAP `0xaa`
  - Control `0x03`
  - OUI `00:00:00` by default, plus selected non-zero OUI coverage
  - PID / protocol id matching an Ethernet-style payload identifier when noted

## Current support assumptions

Current committed assumptions:
- plain LLC/SNAP inner IPv4 / IPv6 / ARP recovery is supported for known SNAP PID values even when the SNAP OUI is non-zero, as long as the bounded payload validates;
- VLAN/QinQ before LLC/SNAP are supported for the same bounded continuation path;
- unknown SNAP PID and non-SNAP LLC stay conservative and must not fabricate IPv4 / IPv6 / ARP;
- malformed/truncated and length-mismatch cases remain no-flow robustness fixtures;
- truncated inner IPv4 after LLC/SNAP can show partial IPv4 details while still remaining no-flow.

---

### 01_llc_snap_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / OUI `00:00:00` / PID IPv4 / IPv4 / TCP / Raw
- Current behavior: recovers inner IPv4/TCP through LLC/SNAP and forms a normal IPv4/TCP flow.

### 02_llc_snap_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / PID IPv4 / IPv4 / UDP / Raw
- Current behavior: recovers inner IPv4/UDP and forms a normal IPv4/UDP flow.

### 03_llc_snap_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / PID IPv6 / IPv6 / TCP / Raw
- Current behavior: recovers inner IPv6/TCP and forms a normal IPv6/TCP flow.

### 04_llc_snap_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / PID IPv6 / IPv6 / UDP / Raw
- Current behavior: recovers inner IPv6/UDP and forms a normal IPv6/UDP flow.

### 05_llc_snap_arp.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / PID ARP / ARP
- Current behavior: ARP is recognized behind LLC/SNAP.

### 06_vlan_llc_snap_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN `0x8100` / 802.3-length payload / LLC SNAP / IPv4 / TCP
- Current behavior: outer VLAN envelope remains visible and inner IPv4/TCP is recovered through LLC/SNAP.
- Generator note: written manually with a VLAN TPID followed by an inner 802.3 length field to keep the wire image deterministic.

### 07_qinq_llc_snap_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / QinQ `0x88A8` / VLAN `0x8100` / 802.3-length payload / LLC SNAP / IPv4 / UDP
- Current behavior: outer QinQ/VLAN envelope remains visible and inner IPv4/UDP is recovered through LLC/SNAP.

### 08_llc_snap_unknown_pid.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / OUI `00:00:00` / unknown PID / Raw
- Current behavior: remains no-flow with reason `Unknown SNAP PID`; selected-packet Summary shows IEEE 802.3, LLC, SNAP, the unknown PID, and bounded Data preview.

### 09_llc_snap_nonzero_oui_ipv4_pid.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / non-zero OUI / PID `0x0800` / IPv4-like bytes
- Current behavior: forms a normal IPv4/UDP flow when the bounded payload validates; selected-packet Summary preserves the actual non-zero OUI while continuing into IPv4 and UDP.

### 10_llc_non_snap_ipx_like.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / non-SNAP LLC / Raw
- Current behavior: remains no-flow with reason `Non-SNAP LLC frame`; selected-packet Summary shows LLC fields plus bounded Data preview.

### 11_llc_snap_truncated_llc_header.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length says LLC follows, but LLC header is incomplete
- Current behavior: remains no-flow with reason `LLC header truncated`; selected-packet Summary shows IEEE 802.3 plus LLC truncation warning.

### 12_llc_snap_truncated_snap_header.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP marker present, but SNAP OUI/PID is incomplete
- Current behavior: remains no-flow with reason `SNAP header truncated`; selected-packet Summary shows LLC, partial SNAP presence, and SNAP truncation warning.

### 13_llc_snap_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length / LLC SNAP / PID IPv4 / partial IPv4 header
- Current behavior: remains no-flow with reason `IPv4 header truncated`; selected-packet Summary reuses the shared partial IPv4 presentation after LLC/SNAP.

### 14_llc_snap_length_short_payload.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length field larger than captured LLC/SNAP payload
- Current behavior: inner IPv4/UDP is still recovered when enough header bytes are available, but LLC / IPv4 / UDP layers expose truncation warnings and the packet remains bounded by captured bytes.

### 15_llc_snap_length_extra_payload.pcap

- Packets: 1
- Layer chain: Ethernet 802.3 length field smaller than captured frame payload
- Current behavior: trailing bytes beyond the declared IEEE 802.3 length are ignored for inner parsing; the packet remains no-flow with reason `UDP header truncated`, while LLC and partial IPv4 layers show length-boundary warnings.

## Expected generated file list

- `01_llc_snap_ipv4_tcp.pcap`
- `02_llc_snap_ipv4_udp.pcap`
- `03_llc_snap_ipv6_tcp.pcap`
- `04_llc_snap_ipv6_udp.pcap`
- `05_llc_snap_arp.pcap`
- `06_vlan_llc_snap_ipv4_tcp.pcap`
- `07_qinq_llc_snap_ipv4_udp.pcap`
- `08_llc_snap_unknown_pid.pcap`
- `09_llc_snap_nonzero_oui_ipv4_pid.pcap`
- `10_llc_non_snap_ipx_like.pcap`
- `11_llc_snap_truncated_llc_header.pcap`
- `12_llc_snap_truncated_snap_header.pcap`
- `13_llc_snap_truncated_inner_ipv4.pcap`
- `14_llc_snap_length_short_payload.pcap`
- `15_llc_snap_length_extra_payload.pcap`
