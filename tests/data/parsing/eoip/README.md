Synthetic EoIP parsing fixtures for production-contract regression tests.

This directory defines the exact current production contract for MikroTik-style EoIP handling in `PacketDecoder` and packet-details code. These fixtures are intentionally source-of-truth tests for both production-regression checks and the shadow-engine parity suite.

## Scope

The committed fixtures define:
- how production distinguishes strict EoIP from ordinary GRE;
- which outer entry contexts can reach EoIP classification;
- the exact on-wire EoIP word layout and byte order;
- how tunnel ID is normalized into physical `ProtocolPath`;
- which inner Ethernet continuations are supported;
- which GRE/EoIP-looking cases remain ordinary GRE or no-flow;
- how malformed and truncated packets stay conservative.

No local generator is intentionally kept in the repository. Temporary fixture-generation helpers may be used during development, but they must be deleted afterward.

## Production classification contract

Production reaches EoIP only through the outer IPv4 `protocol=47` path.

Strict EoIP classification requires all of the following:
- outer IPv4 transport protocol `47`;
- complete 4-byte GRE base header;
- GRE version `1`;
- GRE key bit set;
- GRE checksum bit clear;
- GRE sequence bit clear;
- GRE Protocol Type `0x6400`.

If all of those hold, production treats the next 4 bytes as the EoIP-specific word:
- bytes `0..1`: frame length, big-endian;
- bytes `2..3`: tunnel ID, little-endian.

Important consequences:
- outer IPv6 `next_header=47` does not classify `0x6400` as EoIP in production;
- GRE v0 direct IPv4, GRE TEB, and GRE with a key that merely looks like an EoIP word remain ordinary GRE;
- GRE version `1` plus `0x6400` plus checksum set does not classify as EoIP;
- GRE v0 plus `0x6400` does not classify as EoIP;
- missing-key-bit `0x6400` remains non-EoIP GRE and is reported conservatively.

## Header layout and byte order

The strict EoIP wire shape used by production is:

```text
GRE flags/version: 0x2001
GRE protocol:      0x6400
EoIP word:
  frame length:    16-bit big-endian
  tunnel id:       16-bit little-endian
inner frame:       raw inner Ethernet frame
```

Examples:
- tunnel ID `6400` (`0x1900`) is written as bytes `00 19`;
- tunnel ID `6401` (`0x1901`) is written as bytes `01 19`;
- tunnel ID `65535` (`0xffff`) is written as bytes `ff ff`.

Production packet details intentionally keep two values separate:
- `Raw GRE Key`
  this is the literal 32-bit word seen in the EoIP slot;
- `Identity Key`
  this is the normalized 16-bit logical tunnel ID widened into the existing GRE-key identity slot.

For example, fixture `09` proves that:
- raw key `0x002e0019` and raw key `0x00360019` are different packet-level words;
- both normalize to the same identity key `0x00001900`.

## Physical path and identity

Production does not introduce a separate `EoIP(...)` path layer.

Successful EoIP flows use the existing GRE key slot in physical `ProtocolPath`, for example:

```text
EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP
```

Identity rules established by fixtures:
- tunnel ID participates in persistent path identity;
- EoIP frame length does not participate in identity;
- the stored `GRE(key=...)` value is the decoded little-endian 16-bit Tunnel ID widened into the existing 32-bit GRE-key slot, not the raw 32-bit EoIP word;
- outer IPv4 source/destination addresses do not become final flow endpoints;
- outer VLAN / MPLS layers do remain part of the physical path, so they can still split flows;
- same inner tuple plus same tunnel ID aggregates even if outer IPv4 endpoints change;
- same inner tuple plus different tunnel IDs splits;
- same tunnel ID plus different payload lengths aggregates;
- same tunnel ID plus the same inner frame but different accepted EoIP `frame_length` values still aggregates;
- same tunnel ID plus different outer VLAN path metadata splits.

## Entry contexts

Current production-supported reachability established by fixtures:
- Ethernet II -> IPv4 -> EoIP;
- outer single VLAN -> IPv4 -> EoIP;
- outer VLAN + MPLS -> IPv4 -> EoIP.

Current production non-EoIP reachability established by fixtures:
- Ethernet II -> IPv6 -> GRE version 1 + key + `0x6400` remains ordinary GRE and no-flow.
- outer IPv4 fragmented `protocol 47` packets do not continue into EoIP at all, even when the captured bytes contain a complete valid-looking EoIP header and inner Ethernet/IP/transport payload;
- first fragments (`MF=1`, offset `0`) remain no-flow and commit no physical path;
- non-first fragments remain no-flow and commit no physical path;
- caplen-truncated fragmented outer-IPv4 `protocol 47` packets still stop at the outer IPv4 layer and do not read beyond captured bytes.

This directory still does not claim current production EoIP support for:
- outer IPv6 EoIP classification;
- Linux cooked roots;
- plain-IP-contained EoIP;
- recursive nested EoIP continuation;
- PBB or MPLS-pseudowire flow continuation through EoIP.

## Inner Ethernet continuation profile

Current production-supported inner continuations established by fixtures:
- inner Ethernet II -> IPv4 -> TCP;
- inner Ethernet II -> IPv4 -> UDP;
- inner Ethernet II -> IPv6 -> UDP;
- inner VLAN -> IPv4 -> UDP;
- inner QinQ -> IPv6 -> TCP;
- inner IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP.

Current production-rejected or no-flow continuations established by fixtures:
- inner Ethernet too short for a full header;
- inner VLAN header truncated;
- declared EoIP frame length beyond bounded available bytes;
- bounded frame shorter than the full inner Ethernet header;
- outer IPv6 `0x6400` packets, even when the following bytes look exactly like a valid EoIP word;
- inner PPPoE Session (`0x8864`) behind valid EoIP:
  no production flow, no committed physical path, but best-effort packet details can still surface the outer inner Ethernet plus recovered inner IPv4 / UDP facts;
- inner MPLS unicast (`0x8847`) behind valid EoIP:
  no production flow, no committed physical path, but best-effort packet details can still surface the outer inner Ethernet, MPLS label stack, and recovered inner IPv4 / UDP facts;
- inner PBB (`0x88e7`) behind valid EoIP:
  no production flow, no committed physical path, but best-effort packet details can still surface the outer inner Ethernet plus recovered inner IPv4 / UDP facts;
- inner MACsec (`0x88e5`) behind valid EoIP:
  no production flow, no committed physical path, and no recovered inner IP/transport flow tuple;
- inner unknown EtherType behind valid EoIP:
  no production flow, no committed physical path, and no recovered inner IP/transport flow tuple;
- nested EoIP carried through inner IPv4 `protocol 47`:
  no production flow, no committed physical path, and no recursive nested GRE/EoIP continuation even when the nested bytes are a valid-looking strict EoIP shape.

## Bounds and truncation contract

The malformed/truncated fixtures prove that production:
- requires enough bytes for the 4-byte GRE base header before EoIP classification is possible;
- requires the full 4-byte EoIP word before tunnel ID can be reported;
- never reads an inner Ethernet frame beyond the EoIP-declared bounded length;
- reports truncated inner Ethernet and truncated inner VLAN conservatively;
- does not fabricate inner IPv4 addresses, ports, or flow tuples when bounds are insufficient.
- fragmented outer IPv4 `protocol 47` packets are classified before any GRE/EoIP continuation attempt, so complete valid-looking EoIP bytes inside first or later fragments do not create a flow, a Tunnel ID identity, or a committed `ProtocolPath`;
- caplen-truncated fragmented outer IPv4 packets still expose only bounded outer-IPv4 details and do not consume GRE/EoIP bytes beyond capture length.

## Fixture inventory

### Reusable successful-flow fixtures

`01_ipv4_eoip_inner_ipv4_udp.pcap`
- Outer: Ethernet II / IPv4 / GRE v1 + K / `0x6400`
- Inner: Ethernet II / IPv4 / UDP
- Outcome: recognized flow
- ProtocolId: UDP
- Path: `EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP`
- Purpose: baseline strict EoIP success.

`02_ipv4_eoip_inner_ipv4_tcp.pcap`
- Outer: Ethernet II / IPv4 / strict EoIP
- Inner: Ethernet II / IPv4 / TCP
- Outcome: recognized flow
- ProtocolId: TCP
- Path: `EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> TCP`
- Purpose: direct inner IPv4/TCP continuation.

`03_ipv4_eoip_inner_ipv6_udp.pcap`
- Outer: Ethernet II / IPv4 / strict EoIP
- Inner: Ethernet II / IPv6 / UDP
- Outcome: recognized flow
- ProtocolId: UDP
- Path: `EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv6 -> UDP`
- Purpose: direct inner IPv6/UDP continuation.

`04_ipv4_eoip_inner_vlan_ipv4_udp.pcap`
- Outer: Ethernet II / IPv4 / strict EoIP
- Inner: Ethernet II / VLAN 1806 / IPv4 / UDP
- Outcome: recognized flow
- ProtocolId: UDP
- Path: `EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> VLAN(vid=1806) -> IPv4 -> UDP`
- Purpose: inner VLAN continuation.

`05_ipv4_eoip_inner_qinq_ipv6_tcp.pcap`
- Outer: Ethernet II / IPv4 / strict EoIP
- Inner: Ethernet II / QinQ 1807 / 1808 / IPv6 / TCP
- Outcome: recognized flow
- ProtocolId: TCP
- Path: `EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> VLAN(vid=1807) -> VLAN(vid=1808) -> IPv6 -> TCP`
- Purpose: inner QinQ continuation.

`06_outer_vlan_ipv4_eoip_inner_ipv4_udp.pcap`
- Outer: Ethernet II / VLAN 806 / IPv4 / strict EoIP
- Inner: Ethernet II / IPv4 / UDP
- Outcome: recognized flow
- ProtocolId: UDP
- Path: `EthernetII -> VLAN(vid=806) -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP`
- Purpose: outer VLAN metadata remains in physical path.

`07_outer_vlan_mpls2_ipv4_eoip_inner_vlan_ipv4_udp.pcap`
- Outer: Ethernet II / VLAN 406 / MPLS 56474 / MPLS 477436 / IPv4 / strict EoIP
- Inner: Ethernet II / VLAN 3918 / IPv4 / UDP
- Outcome: recognized flow
- ProtocolId: UDP
- Path: `EthernetII -> VLAN(vid=406) -> MPLS(label=56474) -> MPLS(label=477436) -> IPv4 -> GRE(key=0x00000019) -> EthernetII -> VLAN(vid=3918) -> IPv4 -> UDP`
- Purpose: real-shape-inspired outer VLAN + MPLS carriage and tunnel-ID byte-order proof for tunnel ID `25`.

`08_same_inner_tuple_different_tunnel_ids.pcap`
- Packets: 2
- Inner tuple: identical
- Tunnel IDs: `6400`, `6401`
- Outcome: 2 recognized flows
- Purpose: tunnel ID splits identity.

`09_same_tunnel_id_different_inner_payload_lengths.pcap`
- Packets: 2
- Inner tuple: identical
- Tunnel ID: identical
- Raw GRE/EoIP words: different
- Outcome: 1 recognized flow
- Purpose: raw frame-length word does not split identity.

`10_same_tunnel_id_two_packets.pcap`
- Packets: 2
- Inner tuple: identical
- Tunnel ID: identical
- Outcome: 1 recognized flow
- Purpose: ordinary same-tunnel aggregation baseline.

`11_max_tunnel_id.pcap`
- Tunnel ID: `65535`
- Outcome: recognized flow
- Path: `EthernetII -> IPv4 -> GRE(key=0x0000ffff) -> EthernetII -> IPv4 -> UDP`
- Purpose: high tunnel-ID boundary.

`19_ipv4_eoip_inner_llc_snap_ipv4_udp.pcap`
- Outer: Ethernet II / IPv4 / strict EoIP
- Inner: IEEE 802.3 / LLC/SNAP / IPv4 / UDP
- Outcome: recognized flow
- ProtocolId: UDP
- Path: `EthernetII -> IPv4 -> GRE(key=0x00001900) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP`
- Purpose: proves EoIP uses the existing inner Ethernet continuation profile strongly enough to continue through inner LLC/SNAP.

`26_same_tunnel_same_inner_tuple_different_outer_ipv4_endpoints.pcap`
- Packets: 2
- Outer IPv4 endpoints: different
- Inner tuple: identical
- Tunnel ID: identical
- Outcome: 1 recognized flow
- Path: `EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP`
- Purpose: proves outer IPv4 endpoints do not participate in final EoIP flow identity.

`27_same_tunnel_same_inner_tuple_different_outer_vlan_metadata.pcap`
- Packets: 2
- One packet: direct outer IPv4
- One packet: outer VLAN 806 -> IPv4
- Inner tuple: identical
- Tunnel ID: identical
- Outcome: 2 recognized flows
- Paths:
  - `EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP`
  - `EthernetII -> VLAN(vid=806) -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP`
- Purpose: proves outer physical path metadata still splits EoIP flows.

### Reusable conservative no-flow fixtures

`12_truncated_eoip_key_word.pcap`
- Outcome: unrecognized packet
- Purpose: GRE base header is present, but the outer IPv4-declared GRE payload is only 6 bytes, so a full 8-byte EoIP header does not fit inside the enclosing declared boundary.

`13_eoip_payload_length_exceeds_available.pcap`
- Outcome: unrecognized packet
- Purpose: declared inner frame length exceeds bounded available bytes.

`14_eoip_payload_length_smaller_than_inner_frame.pcap`
- Outcome: unrecognized packet
- Purpose: parser must stay bounded by the declared EoIP frame length even when more captured bytes follow; the bounded inner-Ethernet child becomes capture-truncated relative to the 14-byte Ethernet header.

`15_eoip_missing_key_bit.pcap`
- Outcome: unrecognized packet
- Classification: ordinary GRE, not EoIP
- Purpose: proves strict EoIP requires the GRE key bit.

`16_gre_v1_unsupported_protocol_type.pcap`
- Outcome: unrecognized packet
- Classification: ordinary GRE, not EoIP
- Purpose: GRE v1 unsupported-protocol negative control.

`17_eoip_truncated_inner_ethernet.pcap`
- Outcome: unrecognized packet
- Classification: EoIP recognized, inner Ethernet truncated
- Purpose: no fabricated inner Ethernet tuple; the bounded inner-Ethernet child exposes fewer than 14 visible bytes, so shadow reports an inner-Ethernet truncation rather than continuing to inner IP.

`18_eoip_truncated_inner_vlan.pcap`
- Outcome: unrecognized packet
- Classification: EoIP recognized, inner VLAN structurally incomplete inside the bounded EoIP child
- Purpose: partial VLAN presentation without inner flow fabrication; after the bounded inner Ethernet header only 2 declared bytes remain for the VLAN child, so the VLAN header is structurally incomplete inside the EoIP frame boundary.

### New GRE/EoIP ambiguity fixtures

`20_ipv6_gre_v1_k_6400_inner_ipv4_udp_not_eoip.pcap`
- Outer: Ethernet II / IPv6 / GRE version 1 + K / `0x6400`
- Following 4 bytes: valid-looking EoIP word `0x002e0019`
- Outcome: unrecognized packet
- Classification: ordinary GRE, not EoIP
- Purpose: production outer IPv6 path does not enable EoIP classification.

`21_ipv4_gre_v0_inner_ipv4_udp_not_eoip.pcap`
- Outer: Ethernet II / IPv4 / GRE v0 / Protocol Type IPv4
- Outcome: recognized flow
- Path: `EthernetII -> IPv4 -> GRE -> IPv4 -> UDP`
- Purpose: ordinary GRE v0 direct-inner-IPv4 baseline.

`22_ipv4_gre_v0_teb_inner_ipv4_udp_not_eoip.pcap`
- Outer: Ethernet II / IPv4 / GRE v0 / Protocol Type TEB
- Outcome: recognized flow
- Path: `EthernetII -> IPv4 -> GRE -> EthernetII -> IPv4 -> UDP`
- Purpose: ordinary GRE TEB must remain GRE, not EoIP.

`23_ipv4_gre_v0_key_looks_like_eoip_word_inner_ipv4_udp.pcap`
- Outer: Ethernet II / IPv4 / GRE v0 with key
- GRE key: `0x002e0019`
- Outcome: recognized flow
- Path: `EthernetII -> IPv4 -> GRE(key=0x002e0019) -> IPv4 -> UDP`
- Purpose: ordinary GRE key values that look like EoIP words must remain plain GRE keys.

`24_ipv4_gre_v0_6400_wrong_version_key.pcap`
- Outer: Ethernet II / IPv4 / GRE v0 with key / Protocol Type `0x6400`
- Outcome: unrecognized packet
- Classification: ordinary GRE, not EoIP
- Purpose: `0x6400` alone is not enough; GRE version must also match.

`25_ipv4_gre_v1_checksum_key_6400_not_eoip.pcap`
- Outer: Ethernet II / IPv4 / GRE version 1 with checksum + key / Protocol Type `0x6400`
- Raw GRE key slot bytes: `0x002e0019`
- Outcome: unrecognized packet
- Classification: ordinary GRE, not EoIP
- Purpose: checksum-present `0x6400` packets do not satisfy the strict EoIP signature.

### Fragmentation and unsupported-continuation fixtures

`28_ipv4_eoip_first_fragment_mf_complete_inner.pcap`
- Packets: 1
- Outer IPv4 fragmentation fields: `MF=1`, fragment offset `0`
- EoIP header fields:
  - frame length: `46`
  - raw tunnel-id bytes: `00 19`
  - decoded tunnel ID: `6400`
- Inner EtherType/protocol: Ethernet II / IPv4 / UDP bytes are fully present
- Production outcome: unrecognized packet
- Flow count: `0`
- Physical ProtocolPath: none committed
- Identity purpose: proves first-fragment outer IPv4 `protocol 47` does not create EoIP Tunnel ID identity even when a full valid-looking EoIP payload is captured
- Bounds purpose: proves production stops at outer IPv4 fragmentation before any GRE/EoIP continuation.

`29_ipv4_eoip_nonfirst_fragment_valid_looking_bytes_captrunc.pcap`
- Packets: 2
- Packet 1 outer IPv4 fragmentation fields: `MF=1`, fragment offset `1`
- Packet 2 outer IPv4 fragmentation fields: `MF=0`, fragment offset `2`, `caplen < orig_len`
- EoIP header fields in both packets:
  - raw GRE flags/version: `0x2001`
  - protocol type: `0x6400`
  - frame length word present in captured bytes
  - raw tunnel-id bytes: `00 19`
  - decoded tunnel ID: `6400`
- Inner EtherType/protocol: valid-looking Ethernet II / IPv4 / UDP bytes
- Production outcome: both packets stay unrecognized
- Flow count: `0`
- Physical ProtocolPath: none committed
- Identity purpose: proves later fragments do not fabricate Tunnel ID identity
- Bounds purpose: proves non-first fragments and caplen-truncated non-first fragments still stop at outer IPv4 and do not read beyond captured bytes.

`30_ipv4_eoip_inner_unsupported_ethernet_payloads.pcap`
- Packets: 5
- Outer IPv4 fragmentation fields: none; all packets are unfragmented strict outer IPv4 EoIP
- Per-packet EoIP header fields:
  - tunnel-id bytes: `00 19`
  - decoded tunnel ID: `6400`
  - frame lengths: `59`, `57`, `72`, `74`, `18`
- Packet 1 inner EtherType/protocol: PPPoE Session `0x8864`
  - Production outcome: unrecognized packet
  - Flow count: `0`
  - Physical ProtocolPath: none committed
  - Details note: best-effort inner packet details can still surface inner IPv4 / UDP after PPPoE/PPP, but PPPoE does not continue into production flow extraction through EoIP.
- Packet 2 inner EtherType/protocol: MPLS unicast `0x8847`
  - Production outcome: unrecognized packet
  - Flow count: `0`
  - Physical ProtocolPath: none committed
  - Details note: best-effort packet details can still surface MPLS plus inner IPv4 / UDP, but MPLS behind EoIP does not continue into production flow extraction.
- Packet 3 inner EtherType/protocol: PBB `0x88e7`
  - Production outcome: unrecognized packet
  - Flow count: `0`
  - Physical ProtocolPath: none committed
  - Details note: best-effort packet details can still surface recovered inner IPv4 / UDP facts, but the PBB layer is not committed into an EoIP production path and no flow is formed.
- Packet 4 inner EtherType/protocol: MACsec `0x88e5`
  - Production outcome: unrecognized packet
  - Flow count: `0`
  - Physical ProtocolPath: none committed
  - Details note: best-effort packet details stop at inner Ethernet / MACsec-facing envelope with no recovered inner IP/transport flow tuple.
- Packet 5 inner EtherType/protocol: unknown `0x1234`
  - Production outcome: unrecognized packet
  - Flow count: `0`
  - Physical ProtocolPath: none committed
  - Details note: best-effort packet details stop at inner Ethernet only.
- Identity purpose: proves unsupported inner Ethernet payloads do not accidentally reuse root Ethernet reachability and do not grow `ProtocolPathRegistry`
- Bounds purpose: proves strict EoIP classification can coexist with conservative no-flow inner continuation.

`31_ipv4_eoip_nested_eoip_not_continued.pcap`
- Packets: 1
- Outer IPv4 fragmentation fields: none
- EoIP header fields:
  - frame length: `88`
  - raw tunnel-id bytes: `00 19`
  - decoded tunnel ID: `6400`
- Inner EtherType/protocol: Ethernet II / inner IPv4 `protocol 47` with valid-looking nested GRE/EoIP bytes
- Production outcome: unrecognized packet
- Flow count: `0`
- Physical ProtocolPath: none committed
- Identity purpose: proves production stops before recursive nested EoIP continuation and does not fabricate a nested Tunnel ID/path
- Bounds purpose: proves valid-looking nested GRE/EoIP bytes inside inner IPv4 do not bypass the current transport-only inner-IP continuation gate.

`32_same_tunnel_same_inner_frame_different_frame_length.pcap`
- Packets: 2
- Outer IPv4 fragmentation fields: none
- Packet 1 EoIP header fields:
  - frame length: `46`
  - raw EoIP/GRE word: `0x002e0019`
  - raw tunnel-id bytes: `00 19`
  - decoded tunnel ID: `6400`
- Packet 2 EoIP header fields:
  - frame length: `50`
  - raw EoIP/GRE word: `0x00320019`
  - raw tunnel-id bytes: `00 19`
  - decoded tunnel ID: `6400`
- Inner EtherType/protocol: identical Ethernet II / IPv4 / UDP frame in both packets
- Production outcome: one recognized UDP flow containing both packets
- Flow count: `1`
- Physical ProtocolPath: `EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP`
- Identity purpose: proves accepted EoIP frame-length variation alone does not split identity when the Tunnel ID and bounded inner frame are otherwise the same
- Bounds purpose: packet 2 carries extra bounded bytes after the inner IPv4 packet, but transport payload accounting still follows the inner IPv4/UDP lengths rather than the larger EoIP frame length.

## Expected file list

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
- `19_ipv4_eoip_inner_llc_snap_ipv4_udp.pcap`
- `20_ipv6_gre_v1_k_6400_inner_ipv4_udp_not_eoip.pcap`
- `21_ipv4_gre_v0_inner_ipv4_udp_not_eoip.pcap`
- `22_ipv4_gre_v0_teb_inner_ipv4_udp_not_eoip.pcap`
- `23_ipv4_gre_v0_key_looks_like_eoip_word_inner_ipv4_udp.pcap`
- `24_ipv4_gre_v0_6400_wrong_version_key.pcap`
- `25_ipv4_gre_v1_checksum_key_6400_not_eoip.pcap`
- `26_same_tunnel_same_inner_tuple_different_outer_ipv4_endpoints.pcap`
- `27_same_tunnel_same_inner_tuple_different_outer_vlan_metadata.pcap`
- `28_ipv4_eoip_first_fragment_mf_complete_inner.pcap`
- `29_ipv4_eoip_nonfirst_fragment_valid_looking_bytes_captrunc.pcap`
- `30_ipv4_eoip_inner_unsupported_ethernet_payloads.pcap`
- `31_ipv4_eoip_nested_eoip_not_continued.pcap`
- `32_same_tunnel_same_inner_frame_different_frame_length.pcap`
