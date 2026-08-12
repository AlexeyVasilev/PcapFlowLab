# ICMPv4 Fixture Contracts

This directory contains deterministic classic PCAP fixtures for the fixture-first ICMPv4 inspection pass.

Scope of this directory:
- ICMPv4 only.
- No ICMPv6 fixtures in this pass.
- Outer Ethernet and IPv4 framing stay valid unless a fixture intentionally tests ICMP truncation.
- Generated fixture `.pcap` files are committed; the temporary local generator used to create them is intentionally not tracked.

## Current production behavior

Current shared production support already covers:
- flow recognition as protocol `ICMP`;
- portless flow identity keyed by the outer effective IPv4 endpoints;
- Packet Details text with basic `Type`, `Code`, `Source`, and `Destination`;
- layered Packet Summary driven by the bounded `IcmpInspectionParser -> IcmpMessage` path after IPv4;
- Packet Bytes `ICMP Message` protocol-unit view for recognized ICMP packets.

Current production behavior intentionally does not cover:
- checksum validation reporting;
- quoted-inner-datagram recursive decoding;
- Echo request/reply correlation;
- Stream/reassembly presentation;
- ICMPv6 parity.

Current flow identity contract remains unchanged:
- Echo Identifier is not part of the flow key;
- Type/Code are not part of the flow key;
- quoted/original datagrams inside ICMP errors do not affect flow identity;
- persistent protocol-path identity still stops at `IPv4` for top-level ICMP flows.

## Current ICMP Summary contract

Current shared pipeline is:

`IPv4 payload (protocol 1)` -> bounded `IcmpInspectionParser` -> `IcmpMessage` -> structured Packet Summary + `ICMP Message` byte view.

Current Summary exposes the common fixed header:
- `Type`
- `Code`
- `Checksum`

and useful type-specific fields where available:
- Echo Request / Echo Reply:
  - `Identifier`
  - `Sequence Number`
  - `Payload Length`
- Destination Unreachable:
  - useful `Code` interpretation
  - `Next-Hop MTU` for Fragmentation Needed
  - `Quoted Data Length`
- Redirect:
  - useful `Code` interpretation
  - `Gateway Address`
- Time Exceeded:
  - useful `Code` interpretation
  - `Quoted Data Length`
- Parameter Problem:
  - useful `Code` interpretation
  - `Pointer`

Unknown `Type` / `Code` values must remain visible numerically.
Malformed and truncated packets must remain bounded.
Deep recursive parsing of the quoted/original datagram remains explicitly out of scope.

## Current ICMP Bytes contract

For a normal top-level IPv4 ICMP packet, Packet Bytes views remain conceptually:
- `Captured Packet` when needed by generic fallback logic;
- existing link-layer view such as `Ethernet II Frame`;
- `IPv4 Packet`;
- `ICMP Message`.

`ICMP Message` means the complete ICMP PDU:
- common ICMP header;
- type-specific metadata;
- payload or quoted/original datagram bytes.

It should start at the true ICMP offset and extend to the bounded end of the IPv4 payload.

## Quoted original datagram contract

Error-message fixtures intentionally carry realistic quoted bytes, usually:
- original IPv4 header;
- enough original transport bytes to show that the quoted packet was UDP or TCP.

The guaranteed contract is:
- quoted/original data is bounded;
- quoted/original data length is known.

These fixtures do not promise future recursive decoding of:
- quoted IPv4;
- quoted TCP/UDP;
- quoted application payload.

## Checksum policy

Normal fixtures in this directory use valid ICMP checksums.
An intentionally invalid ICMP checksum fixture is deferred in this pass because there is not yet a shared ICMP checksum-validation presentation contract to preserve.

## ICMPv6 boundary

ICMPv6 is intentionally deferred to a separate follow-up.
It is not treated as a trivial renumbering of ICMPv4 because useful ICMPv6 support includes IPv6-specific control traffic such as Neighbor Discovery and Router Discovery.

## Scenario Matrix

| Fixture | Type | Code | Purpose | Type-specific fields present on wire | Quoted data | Malformed/truncated | Summary expectation |
|---|---:|---:|---|---|---|---|---|
| `01_icmp_echo_request.pcap` | 8 | 0 | Echo Request baseline | Identifier, Sequence Number, payload | no | no | common header + echo fields + payload length |
| `02_icmp_echo_reply.pcap` | 0 | 0 | Echo Reply baseline | Identifier, Sequence Number, payload | no | no | common header + echo fields + payload length |
| `03_icmp_dest_unreachable_network.pcap` | 3 | 0 | Destination Unreachable, Network Unreachable | reserved rest-of-header | yes | no | common header + code text + quoted data length |
| `04_icmp_dest_unreachable_host.pcap` | 3 | 1 | Destination Unreachable, Host Unreachable | reserved rest-of-header | yes | no | common header + code text + quoted data length |
| `05_icmp_dest_unreachable_port.pcap` | 3 | 3 | Destination Unreachable, Port Unreachable | reserved rest-of-header | yes | no | common header + code text + quoted data length |
| `06_icmp_dest_unreachable_frag_needed_mtu_1400.pcap` | 3 | 4 | Fragmentation Needed baseline | Next-Hop MTU = `1400` | yes | no | common header + Next-Hop MTU + quoted data length |
| `07_icmp_time_exceeded_ttl.pcap` | 11 | 0 | TTL exceeded in transit | reserved rest-of-header | yes | no | common header + code text + quoted data length |
| `08_icmp_time_exceeded_reassembly.pcap` | 11 | 1 | Fragment reassembly timeout | reserved rest-of-header | yes | no | common header + code text + quoted data length |
| `09_icmp_redirect_host_gateway.pcap` | 5 | 1 | Redirect with gateway address | Gateway Address = `192.0.2.254` | yes | no | common header + gateway address + code text + quoted data length |
| `10_icmp_parameter_problem_pointer_5.pcap` | 12 | 0 | Parameter Problem with pointer | Pointer = `5` | yes | no | common header + pointer + code text + quoted data length |
| `11_icmp_unknown_type_99.pcap` | 99 | 1 | Unknown numeric Type remains visible | none beyond common header | no | no | common header with numeric type/code |
| `12_icmp_echo_request_unknown_code_7.pcap` | 8 | 7 | Known Type with uncommon Code | Identifier, Sequence Number, payload | no | no | common header + numeric uncommon code + echo fields |
| `13_icmp_truncated_common_header_3_bytes.pcap` | 8 | 0 | Fewer than 4 common-header bytes captured | incomplete common header | no | truncated common header | bounded truncation diagnostics only |
| `14_icmp_truncated_echo_body.pcap` | 8 | 0 | Common header present but echo body incomplete | partial Identifier only | no | truncated echo body | common header + bounded echo truncation diagnostics |
| `15_icmp_truncated_error_quote.pcap` | 3 | 3 | Error header present but quoted payload incomplete | reserved rest-of-header | partial | truncated quoted/original data | common header + quoted data length + bounded truncation diagnostics |
| `16_icmp_same_endpoints_different_identifiers.pcap` | 8 | 0 | Flow-identity regression: different Echo IDs, same endpoints | varying Identifier / Sequence | no | no | grouped under existing endpoint-only ICMP flow semantics |
