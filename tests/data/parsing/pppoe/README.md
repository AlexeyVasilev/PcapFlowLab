Synthetic PPPoE / PPP parsing fixtures for regression tests.

This directory defines the migration contract for the current production
`PacketDecoder` and related production-selected-packet paths.

It does not define any shadow dissection behavior.

## Exact production contract

Confirmed from production code and existing tests:

- PPPoE Discovery EtherType `0x8863` is recognized only as a diagnostic no-flow packet.
- PPPoE Discovery does not contribute a production `ProtocolPath`.
- PPPoE Session continuation only exists for:
  - version `1`
  - type `1`
  - code `0x00`
- PPP framing is read as a fixed 2-byte big-endian PPP Protocol field.
- PPP Protocol Field Compression and ACFC are not supported.
- Supported PPP Session payload protocols are:
  - `0x0021` -> bounded IPv4 continuation -> normal IPv4/TCP or IPv4/UDP flow when the inner tuple is fully available
  - `0x0057` -> bounded IPv6 continuation -> normal IPv6/TCP or IPv6/UDP flow when the inner tuple is fully available
- PPP control protocols remain no-flow packets:
  - `0xc021` -> LCP
  - `0x8021` -> IPCP
  - `0x8057` -> IPv6CP
- Unknown PPP protocols remain no-flow packets with explicit reason text.
- Bounded PPPoE payload semantics use `min(declared PPPoE payload length, captured PPPoE payload bytes)`.
- Bytes beyond the declared PPPoE payload must not be used to complete PPP, IP, or transport parsing.
- Session ID `0x0000` is accepted by current production support.
- Session ID does not participate in current production `ProtocolPath` or flow identity.
- Current production PPPoE/PPP path contribution is:
  - `PPPoE -> PPP`
  - with no session-id/code/version/type identifier in the path layer key
- Supported link entry shims before PPPoE are:
  - direct Ethernet II
  - single `0x8100` VLAN
  - QinQ-style `0x88A8` outer + `0x8100` inner VLAN
  - legacy single `0x9100` VLAN-like tag
- No non-Ethernet PPPoE entry path is currently covered by production.

## Local generation

There is no committed PPPoE fixture generator in the repository.

When new PPPoE fixtures are required:

- use a temporary local generator under `tmp/`;
- generate only the missing deterministic `.pcap` files;
- delete the temporary generator before finishing.

The committed `.pcap` files in this directory are the source of truth.

## Shared constants

- Client MAC: `02:00:00:00:30:01`
- Access concentrator / server MAC: `02:00:00:00:30:02`
- Client IPv4: `192.0.2.30`
- Server IPv4: `198.51.100.30`
- Client IPv6: `2001:db8:30::10`
- Server IPv6: `2001:db8:30::20`
- Default PPPoE session id: `0x1234`
- Client TCP port: `49160`
- Server TCP port: `443`
- Client UDP port: `53540`
- Server UDP port: `443`

## Fixture inventory

### Supported Session data flows

- `01_pppoe_session_ipv4_tcp.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=51) -> PPP 0x0021 -> IPv4 -> TCP`
  - Outcome: one recognized IPv4/TCP flow
  - ProtocolId: `tcp`
  - ProtocolPath: `EthernetII -> PPPoE -> PPP -> IPv4 -> TCP`

- `02_pppoe_session_ipv4_udp.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=39) -> PPP 0x0021 -> IPv4 -> UDP`
  - Outcome: one recognized IPv4/UDP flow
  - ProtocolId: `udp`
  - ProtocolPath: `EthernetII -> PPPoE -> PPP -> IPv4 -> UDP`

- `03_pppoe_session_ipv6_tcp.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=71) -> PPP 0x0057 -> IPv6 -> TCP`
  - Outcome: one recognized IPv6/TCP flow
  - ProtocolId: `tcp`
  - ProtocolPath: `EthernetII -> PPPoE -> PPP -> IPv6 -> TCP`

- `04_pppoe_session_ipv6_udp.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=59) -> PPP 0x0057 -> IPv6 -> UDP`
  - Outcome: one recognized IPv6/UDP flow
  - ProtocolId: `udp`
  - ProtocolPath: `EthernetII -> PPPoE -> PPP -> IPv6 -> UDP`

- `13_vlan_pppoe_session_ipv4_tcp.pcap`
  - Wire: `EthernetII -> VLAN(tpid=0x8100,vid=130) -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=51) -> PPP 0x0021 -> IPv4 -> TCP`
  - Outcome: one recognized IPv4/TCP flow through single VLAN
  - ProtocolPath: `EthernetII -> VLAN(vid=130) -> PPPoE -> PPP -> IPv4 -> TCP`

- `14_qinq_pppoe_session_ipv4_udp.pcap`
  - Wire: `EthernetII -> VLAN(tpid=0x88A8,vid=230) -> VLAN(tpid=0x8100,vid=231) -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=39) -> PPP 0x0021 -> IPv4 -> UDP`
  - Outcome: one recognized IPv4/UDP flow through QinQ
  - ProtocolPath: `EthernetII -> VLAN(vid=230) -> VLAN(vid=231) -> PPPoE -> PPP -> IPv4 -> UDP`

- `21_pppoe_session_same_tuple_same_session_id.pcap`
  - Wire: two identical `EthernetII -> PPPoE Session(session=0x3333,decl=39) -> PPP 0x0021 -> IPv4 -> UDP` packets
  - Outcome: one recognized UDP flow with two packets
  - Identity purpose: proves same tuple + same Session ID stays in one flow
  - ProtocolPath: `EthernetII -> PPPoE -> PPP -> IPv4 -> UDP`

- `22_pppoe_session_same_tuple_different_session_id.pcap`
  - Wire: two packets with the same inner IPv4/UDP tuple, Session IDs `0x3333` and `0x4444`
  - Outcome: one recognized UDP flow with two packets
  - Identity purpose: proves Session ID does not split production flow identity
  - ProtocolPath: `EthernetII -> PPPoE -> PPP -> IPv4 -> UDP`

- `23_pppoe_session_zero_session_id_ipv4_udp.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x0000,decl=39) -> PPP 0x0021 -> IPv4 -> UDP`
  - Outcome: one recognized IPv4/UDP flow
  - Identity purpose: proves Session ID zero is accepted
  - ProtocolPath: `EthernetII -> PPPoE -> PPP -> IPv4 -> UDP`

- `24_qinq_pppoe_session_ipv6_tcp.pcap`
  - Wire: `EthernetII -> VLAN(tpid=0x88A8,vid=232) -> VLAN(tpid=0x8100,vid=233) -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=71) -> PPP 0x0057 -> IPv6 -> TCP`
  - Outcome: one recognized IPv6/TCP flow through QinQ
  - ProtocolPath: `EthernetII -> VLAN(vid=232) -> VLAN(vid=233) -> PPPoE -> PPP -> IPv6 -> TCP`

- `25_legacy_9100_vlan_pppoe_session_ipv4_udp.pcap`
  - Wire: `EthernetII -> VLAN(tpid=0x9100,vid=330) -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=39) -> PPP 0x0021 -> IPv4 -> UDP`
  - Outcome: one recognized IPv4/UDP flow through legacy `0x9100`
  - ProtocolPath: `EthernetII -> VLAN(vid=330) -> PPPoE -> PPP -> IPv4 -> UDP`

### Discovery and PPP control no-flow fixtures

- `05_pppoe_session_lcp_config_request.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=16) -> PPP 0xc021`
  - Outcome: no flow, reason `PPP LCP control packet`
  - ProtocolPath: none

- `06_pppoe_session_ipcp_config_request.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=12) -> PPP 0x8021`
  - Outcome: no flow, reason `PPP IPCP control packet`
  - ProtocolPath: none

- `07_pppoe_session_ipv6cp_config_request.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=16) -> PPP 0x8057`
  - Outcome: no flow, reason `PPP IPv6CP control packet`
  - ProtocolPath: none

- `08_pppoe_discovery_padi.pcap`
  - Wire: `EthernetII -> PPPoE Discovery(v=1,type=1,code=0x09,session=0x0000,decl=13)`
  - Outcome: no flow, reason `PPPoE Discovery PADI`
  - ProtocolPath: none

- `09_pppoe_discovery_pado.pcap`
  - Wire: `EthernetII -> PPPoE Discovery(v=1,type=1,code=0x07,session=0x0000,decl=30)`
  - Outcome: no flow, reason `PPPoE Discovery PADO`
  - ProtocolPath: none

- `10_pppoe_discovery_padr.pcap`
  - Wire: `EthernetII -> PPPoE Discovery(v=1,type=1,code=0x19,session=0x0000,decl=29)`
  - Outcome: no flow, reason `PPPoE Discovery PADR`
  - ProtocolPath: none

- `11_pppoe_discovery_pads.pcap`
  - Wire: `EthernetII -> PPPoE Discovery(v=1,type=1,code=0x65,session=0x1234,decl=22)`
  - Outcome: no flow, reason `PPPoE Discovery PADS`
  - ProtocolPath: none

- `12_pppoe_discovery_padt.pcap`
  - Wire: `EthernetII -> PPPoE Discovery(v=1,type=1,code=0xa7,session=0x1234,decl=0)`
  - Outcome: no flow, reason `PPPoE Discovery PADT`
  - ProtocolPath: none

- `15_pppoe_session_unknown_ppp_protocol.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=8) -> PPP 0x1235`
  - Outcome: no flow, reason `Unknown PPP protocol`
  - ProtocolPath: none

### Declared-boundary, truncation, and unsupported-variant fixtures

- `16_pppoe_truncated_header.pcap`
  - Wire: Ethernet advertises PPPoE Session EtherType but fewer than 6 PPPoE header bytes are captured
  - Outcome: no flow, reason `PPPoE Session header truncated`
  - Classification: structural truncation
  - ProtocolPath: none

- `17_pppoe_truncated_ppp_protocol.pcap`
  - Wire: complete PPPoE Session header with declared payload `2`, but only one PPP Protocol byte is captured
  - Outcome: no flow, reason `PPP protocol field truncated`
  - Classification: structural truncation / declared payload exceeds capture
  - ProtocolPath: none

- `18_pppoe_truncated_inner_ipv4.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=12) -> PPP 0x0021 -> partial IPv4 header`
  - Outcome: no flow, reason `Unsupported or malformed packet`
  - Classification: supported PPP protocol with truncated inner IPv4
  - ProtocolPath: none

- `19_pppoe_bad_length_short_payload.pcap`
  - Wire: valid `PPPoE Session -> PPP 0x0021 -> IPv4 -> UDP`, but declared PPPoE payload `51` exceeds captured PPPoE payload `39`
  - Outcome: one recognized IPv4/UDP flow with PPPoE length warning
  - Boundary purpose: proves bounded continuation uses captured bytes only
  - ProtocolPath: `EthernetII -> PPPoE -> PPP -> IPv4 -> UDP`

- `20_pppoe_bad_length_extra_payload.pcap`
  - Wire: valid `PPPoE Session -> PPP 0x0021 -> IPv4 -> UDP`, but declared PPPoE payload `33` is shorter than captured PPPoE payload `43`
  - Outcome: one recognized IPv4/UDP flow with trailing-bytes-ignored warning
  - Boundary purpose: proves bytes after the declared PPPoE payload do not extend inner parsing
  - ProtocolPath: `EthernetII -> PPPoE -> PPP -> IPv4 -> UDP`

- `26_pppoe_session_declared_too_short_for_ppp_protocol_with_valid_trailer.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=1)` followed by captured bytes that look like `PPP 0x0021 -> IPv4 -> UDP`
  - Outcome: no flow, reason `PPP protocol field truncated`
  - Boundary purpose: proves production does not read PPP bytes beyond the declared PPPoE boundary
  - ProtocolPath: none

- `27_pppoe_session_capture_truncated_ipv4_udp_caplen_lt_origlen.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=39) -> PPP 0x0021 -> partial IPv4/UDP packet`
  - Capture semantics: PCAP `caplen < orig_len`
  - Outcome: no flow, reason `Unsupported or malformed packet`
  - Boundary purpose: genuine capture truncation fixture
  - ProtocolPath: none

- `28_pppoe_session_unsupported_version_with_ipv4_trailer.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=2,type=1,code=0x00,session=0x1234,decl=39) -> PPP 0x0021 -> IPv4 -> UDP`
  - Outcome: no flow, reason `Unsupported or malformed packet`
  - Variant purpose: unsupported PPPoE version
  - ProtocolPath: none

- `29_pppoe_session_unsupported_type_with_ipv4_trailer.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=2,code=0x00,session=0x1234,decl=39) -> PPP 0x0021 -> IPv4 -> UDP`
  - Outcome: no flow, reason `Unsupported or malformed packet`
  - Variant purpose: unsupported PPPoE type
  - ProtocolPath: none

- `30_pppoe_session_unsupported_code_with_ipv4_trailer.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x01,session=0x1234,decl=39) -> PPP 0x0021 -> IPv4 -> UDP`
  - Outcome: no flow, reason `Unsupported or malformed packet`
  - Variant purpose: unsupported PPPoE Session code
  - ProtocolPath: none

- `31_pppoe_session_zero_length_payload.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=0)` with no PPP payload bytes
  - Outcome: no flow, reason `PPP protocol field truncated`
  - Boundary purpose: zero declared payload
  - ProtocolPath: none

- `32_pppoe_session_truncated_inner_ipv6.pcap`
  - Wire: `EthernetII -> PPPoE Session(v=1,type=1,code=0x00,session=0x1234,decl=14) -> PPP 0x0057 -> 12 captured IPv6 header bytes`
  - Outcome: no flow, reason `Unsupported or malformed packet`
  - Classification: supported PPP protocol with truncated inner IPv6
  - ProtocolPath: none

- `33_pppoe_same_session_id_supported_and_unsupported_code.pcap`
  - Wire: two packets with Session ID `0x5555`
    - packet 1: supported `code=0x00`, `PPP 0x0021 -> IPv4 -> UDP`
    - packet 2: unsupported `code=0x01`, same inner-looking PPP/IPv4/UDP bytes
  - Outcome: one recognized IPv4/UDP flow plus one unrecognized packet
  - Identity purpose: proves unsupported code does not create an additional PPPoE flow/path
  - ProtocolPath: recognized packet uses `EthernetII -> PPPoE -> PPP -> IPv4 -> UDP`; unsupported packet contributes no path
