Synthetic PPPoE / PPP parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- basic PPPoE Session frames carrying IPv4 / IPv6 transport traffic;
- PPPoE Session control protocols such as LCP, IPCP, and IPv6CP;
- PPPoE Discovery packets such as PADI / PADO / PADR / PADS / PADT;
- VLAN and QinQ shims before PPPoE;
- unknown PPP protocol payloads inside PPPoE Session frames;
- malformed or truncated PPPoE / PPP envelopes;
- inconsistent PPPoE length-field cases.

Parser implementation is intentionally **not** part of this pass. These fixtures
exist so we can review bytes first, then add focused regression tests and parser
support in later small steps.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python tests/data/parsing/pppoe/generate_pppoe_pcaps.py --output-dir tests/data/parsing/pppoe
```

To overwrite previously generated fixtures:

```bash
python tests/data/parsing/pppoe/generate_pppoe_pcaps.py --output-dir tests/data/parsing/pppoe --force
```

Notes:
- The generator is committed because this PPPoE fixture set is still being introduced incrementally.
- Review generated `.pcap` files locally before committing them.
- The script writes classic little-endian Ethernet `.pcap` files with deterministic MAC/IP/port values.
- IPv4 / IPv6 / TCP / UDP payloads come from Scapy, while PPPoE / PPP / discovery / malformed envelopes are assembled from explicit bytes to stay stable across Scapy versions.

## Shared constants

- Client MAC: `02:00:00:00:30:01`
- Access concentrator / server MAC: `02:00:00:00:30:02`
- Client IPv4: `192.0.2.30`
- Server IPv4: `198.51.100.30`
- Client IPv6: `2001:db8:30::10`
- Server IPv6: `2001:db8:30::20`
- PPPoE session id: `0x1234`
- Client TCP port: `49160`
- Server TCP port: `443`
- Client UDP port: `53540`
- Server UDP port: `443`

## Protocol values used

- PPPoE Discovery EtherType: `0x8863`
- PPPoE Session EtherType: `0x8864`
- PPP IPv4: `0x0021`
- PPP IPv6: `0x0057`
- PPP LCP: `0xc021`
- PPP IPCP: `0x8021`
- PPP IPv6CP: `0x8057`

PPPoE codes used:
- PADI: `0x09`
- PADO: `0x07`
- PADR: `0x19`
- PADS: `0x65`
- PADT: `0xa7`
- Session data: `0x00`

## Current support assumptions

This pass does **not** claim current committed PPPoE parser support.

Conservative assumptions until parser work is added:
- PPPoE Session frames carrying IPv4 / IPv6 are future expected supported behavior;
- PPP LCP / IPCP / IPv6CP session frames are control-payload candidates that should remain safe and inspectable, but not become normal IP flows;
- PPPoE Discovery packets are no-flow candidates and should remain safe to inspect;
- VLAN and QinQ before PPPoE are future shim-composition candidates;
- malformed/truncated/length-mismatch cases are no-crash robustness fixtures first.

---

### 01_pppoe_session_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session / PPP IPv4 / IPv4 / TCP / Raw
- Expected future behavior: normal IPv4/TCP flow through PPPoE Session.

### 02_pppoe_session_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session / PPP IPv4 / IPv4 / UDP / Raw
- Expected future behavior: normal IPv4/UDP flow through PPPoE Session.

### 03_pppoe_session_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session / PPP IPv6 / IPv6 / TCP / Raw
- Expected future behavior: normal IPv6/TCP flow through PPPoE Session.

### 04_pppoe_session_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session / PPP IPv6 / IPv6 / UDP / Raw
- Expected future behavior: normal IPv6/UDP flow through PPPoE Session.

### 05_pppoe_session_lcp_config_request.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session / PPP LCP / Configure-Request
- Current conservative behavior candidate: safe PPP control-payload inspection only; should not become an IP flow.

### 06_pppoe_session_ipcp_config_request.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session / PPP IPCP / Configure-Request
- Current conservative behavior candidate: safe IPv4 control-payload inspection only; not a normal IP data flow.

### 07_pppoe_session_ipv6cp_config_request.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session / PPP IPv6CP / Configure-Request
- Current conservative behavior candidate: safe IPv6 control-payload inspection only; not a normal IP data flow.

### 08_pppoe_discovery_padi.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Discovery PADI / tags
- Current conservative behavior candidate: discovery recognition only; no PPP payload; should not become an IP flow.

### 09_pppoe_discovery_pado.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Discovery PADO / tags
- Tags include: `Service-Name`, `AC-Name`, `AC-Cookie`
- Current conservative behavior candidate: safe discovery inspection only.

### 10_pppoe_discovery_padr.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Discovery PADR / tags
- Current conservative behavior candidate: safe discovery request inspection only.

### 11_pppoe_discovery_pads.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Discovery PADS / tags
- Session id: `0x1234`
- Current conservative behavior candidate: safe discovery session-confirmation inspection only.

### 12_pppoe_discovery_padt.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Discovery PADT
- Session id: `0x1234`
- Current conservative behavior candidate: safe termination-packet inspection only.

### 13_vlan_pppoe_session_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN `0x8100` / PPPoE Session / PPP IPv4 / IPv4 / TCP
- Expected future behavior: VLAN should not block PPPoE Session or inner IPv4/TCP parsing.

### 14_qinq_pppoe_session_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / outer `0x88A8` / inner `0x8100` / PPPoE Session / PPP IPv4 / IPv4 / UDP
- Expected future behavior: QinQ should not block PPPoE Session or inner IPv4/UDP parsing.

### 15_pppoe_session_unknown_ppp_protocol.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session / unknown PPP protocol / Raw
- Current conservative behavior candidate: safe fallback only; should not fabricate IPv4/IPv6 payload parsing.

### 16_pppoe_truncated_header.pcap

- Packets: 1
- Layer chain: Ethernet indicates PPPoE Session EtherType, but PPPoE header is incomplete
- Current malformed/truncated behavior candidate: no-crash robustness only.

### 17_pppoe_truncated_ppp_protocol.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session header present, but PPP protocol field is incomplete
- Current malformed/truncated behavior candidate: safe partial PPPoE handling only.

### 18_pppoe_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session / PPP IPv4 / partial IPv4 header
- Current malformed/truncated behavior candidate: safe handling after PPPoE shim; richer partial IPv4 rendering is future IPv4 work.

### 19_pppoe_bad_length_short_payload.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session with length field larger than captured payload
- Current malformed/truncated behavior candidate: parser should stay conservative and safe.

### 20_pppoe_bad_length_extra_payload.pcap

- Packets: 1
- Layer chain: Ethernet / PPPoE Session with length field smaller than captured payload
- Current malformed/consistency behavior candidate: parser should respect PPPoE length and stay conservative about trailing bytes.

## Expected generated file list

- `01_pppoe_session_ipv4_tcp.pcap`
- `02_pppoe_session_ipv4_udp.pcap`
- `03_pppoe_session_ipv6_tcp.pcap`
- `04_pppoe_session_ipv6_udp.pcap`
- `05_pppoe_session_lcp_config_request.pcap`
- `06_pppoe_session_ipcp_config_request.pcap`
- `07_pppoe_session_ipv6cp_config_request.pcap`
- `08_pppoe_discovery_padi.pcap`
- `09_pppoe_discovery_pado.pcap`
- `10_pppoe_discovery_padr.pcap`
- `11_pppoe_discovery_pads.pcap`
- `12_pppoe_discovery_padt.pcap`
- `13_vlan_pppoe_session_ipv4_tcp.pcap`
- `14_qinq_pppoe_session_ipv4_udp.pcap`
- `15_pppoe_session_unknown_ppp_protocol.pcap`
- `16_pppoe_truncated_header.pcap`
- `17_pppoe_truncated_ppp_protocol.pcap`
- `18_pppoe_truncated_inner_ipv4.pcap`
- `19_pppoe_bad_length_short_payload.pcap`
- `20_pppoe_bad_length_extra_payload.pcap`
