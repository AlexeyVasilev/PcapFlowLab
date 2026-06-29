# Protocol Support

## Purpose

This document is the authoritative repository-level reference for current protocol support in Pcap Flow Lab.

It describes what "support" means for each protocol across:

- open/import-time flow recognition;
- flow grouping;
- service-hint generation;
- selected-packet layered Summary;
- selected-packet Protocol details;
- selected-packet Payload bytes;
- selected-flow Stream items;
- current tests and parsing fixtures.

Qt UI remains the reference UI, and Tauri UI consumes the same shared backend/session behavior where that behavior is already frontend-neutral.

## Support Categories

The support matrix below uses the following categories.

- `Flow recognition`
  - The product can recognize enough about the packet or flow to classify it meaningfully.
- `Flow key extraction`
  - The protocol participates directly in conversation / flow grouping.
- `Service hint`
  - The protocol can produce user-facing hint text for flow lists.
- `Packet Summary layer`
  - The protocol appears as a dedicated layer in selected-packet layered Summary.
- `Protocol details`
  - Selected-packet `Protocol` can show protocol-specific structured or text details.
- `Payload bytes`
  - Selected-packet `Payload` can show protocol-relevant bytes for the selected packet.
- `Stream items`
  - Selected-flow `Stream` can produce protocol-aware timeline items instead of only generic transport payload rows.
- `Tests / fixtures`
  - The repository contains unit tests and/or parsing fixtures that exercise the current behavior.

## Status Labels

- `Supported`
  - Implemented, exercised by current code paths, and verified by tests or fixtures.
- `Partial`
  - Meaningful support exists, but important parts still fall back to generic behavior or remain intentionally limited.
- `Detection-only`
  - The product can recognize the protocol or hint it, but deeper packet/details/stream presentation is not implemented.
- `Planned`
  - The document or code structure implies future support, but the protocol is not materially implemented yet.
- `Not supported`
  - No current support in that category was found.
- `Needs audit`
  - Static inspection found hints of support, but the exact runtime behavior was not clear enough to claim more.
- `N/A`
  - The category does not meaningfully apply to that row.

## Current Architectural Split

Protocol support is intentionally split across three layers of work.

### Open / import-time work

Open-time processing is intentionally shallow:

- packet metadata is decoded;
- flow keys are built;
- counters are aggregated;
- cheap protocol and service hints may be computed;
- expensive selected-flow work is deferred.

This keeps capture open responsive and avoids reading or parsing more payload than necessary up front.

### Selected-packet work

Selected-packet inspection is on-demand:

- packet bytes are read lazily from the source capture when available;
- layered Summary is built from decoded packet details;
- `Raw`, `Payload`, and `Protocol` tabs are populated only for the selected packet.

For malformed or truncated packets, selected-packet inspection is best-effort:

- the inspector may still show Frame / link / network facts that were decoded safely;
- deeper transport or application layers may be absent when parsing stops conservatively;
- raw packet bytes can still be shown when the source capture is attached and readable.

If the original source capture is unavailable, index-backed metadata may still be shown, but byte-backed details remain unavailable.

### Selected-flow work

Selected-flow work is also on-demand:

- selected-flow packet rows are loaded in bounded batches;
- selected-flow Stream is bounded and ephemeral;
- selected-flow Analysis is loaded only for the selected flow;
- deferred hint enrichment can refresh the selected flow after selection.

## Fast vs Deep Import Behavior

Current Fast vs Deep behavior is narrower than the names may suggest.

- `Fast` import computes packet metadata, flow grouping, counters, and cheap protocol/service hints during open.
- `Deep` import currently reuses the same base decode and aggregation path as Fast import.
- `Deep` still exists as the product's dedicated integration point for future more expensive analyzers, but static inspection does not support claiming broad extra per-protocol parsing during open today.
- Some expensive or bounded enrichments remain deferred even when a capture is already open.
- QUIC-related service-hint enrichment is the clearest example:
  - open-time QUIC detection is intentionally cheap;
  - selected-flow actions can later trigger bounded QUIC analysis and refresh the service hint for that flow.
- `possible_tls` and `possible_quic` hints are settings-gated fallback hints rather than confirmed protocol parsing.

This behavior is shared by Qt UI and Tauri UI because both consume the same backend/session import path.

## Support Matrix: Frame, Link, Network, Transport

| Protocol | Recognition | Flow key / grouping | Service hint | Packet Summary layer | Protocol details | Payload tab | Stream items | Tests / fixtures | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PCAP / Frame metadata | Supported | N/A | N/A | Supported | Not supported | Not supported | N/A | Supported | Frame layer shows packet index in file, selected-flow packet index when available, timestamp, captured length, original length, and truncation warnings. |
| Ethernet | Supported | N/A | Not supported | Supported | Not supported | Not supported | N/A | Supported | Ethernet II and IEEE 802.3 length-based framing both appear in layered Summary with source/destination MAC addresses plus either EtherType or declared payload length. |
| IEEE 802.3 LLC/SNAP (Ethernet OUI `00:00:00`) | Partial | Partial | Not supported | Supported | Not supported | Not supported | N/A | Supported | Shared decode distinguishes IEEE 802.3 length framing from Ethernet II, recognizes LLC/SNAP only for DSAP `0xaa`, SSAP `0xaa`, Control `0x03`, and continues through Ethernet OUI `00:00:00` only for PID IPv4, IPv6, and ARP. Direct and VLAN/QinQ-wrapped cases are supported. Unknown PID, non-zero OUI, and non-SNAP LLC remain conservative with specific no-flow reason text and bounded Data/raw preview. Malformed LLC/SNAP headers and IEEE 802.3 length-boundary mismatches are handled best-effort, and trailing bytes beyond the declared 802.3 length are ignored for inner parsing. |
| 802.1Q VLAN | Supported | N/A | Not supported | Supported | Not supported | Not supported | N/A | Supported | Single-tag `0x8100`, `0x88A8` QinQ-style outer tags, and legacy `0x9100` VLAN-like tags are supported in shared decode and layered Summary. VLAN stack depth is bounded to 4 tags. Unknown or truncated inner VLAN payloads remain conservative and can stay in the unrecognized-packet list while still preserving partial Ethernet/VLAN envelope details. |
| MPLS | Partial | Partial | Not supported | Supported | Not supported | Partial | Partial | Supported | Ethernet MPLS unicast/multicast and VLAN-before-MPLS are recognized. Each label becomes its own Summary layer with label / TC / BoS / TTL. Inner IPv4/IPv6 is inferred from the first nibble after the BoS label, and normal TCP/UDP flows group by the inner 5-tuple only. Unknown or malformed MPLS payloads remain in the unrecognized-packet list with conservative reason text. |
| PPPoE Session + PPP IPv4/IPv6 + PPP control basics + basic PPPoE Discovery | Partial | Partial | Not supported | Supported | Partial | Partial | Partial | Supported | Current PPPoE support covers PPPoE Session (`0x8864`) data frames with `code = 0x00`, bounding inner parsing to `min(declared PPPoE payload length, captured PPPoE payload bytes)`, and continuing through PPP IPv4 (`0x0021`) and PPP IPv6 (`0x0057`) into normal IPv4/IPv6/TCP/UDP parsing when enough bounded inner header bytes are available. Selected-packet layered Summary preserves PPPoE Session and PPP protocol layers, basic PPP control presentation for LCP/IPCP/IPv6CP Configure-style packets, and basic PPPoE Discovery (`0x8863`) header/tag presentation for PADI/PADO/PADR/PADS/PADT. Discovery and PPP control packets remain no-flow. Unknown PPP protocols remain conservative, while PPPoE length-mismatch packets may still form normal flows if their bounded inner tuple is available. |
| ARP | Supported | Supported | Supported | Supported | Supported | Supported | Supported | Supported | Strongest non-IP shared parsing path today. Supports Ethernet/IPv4 ARP well, variable `hlen` / `plen`, truncated warnings, and one-packet-per-item stream rows. Request/reply packets are not grouped into a higher-level conversation item. |
| IPv4 | Supported | Supported | Not supported | Supported | Not supported | Not supported | N/A | Supported | IPv4 facts appear in layered Summary, including conservative selected-packet header fields such as IHL, DS field, identification, flags, fragment offset, TTL, protocol, checksum, and addresses. When IPv4 options are present, Summary can append a nested `IPv4 Options (N bytes)` child with wire-order option entries for EOL, NOP, RR, Timestamp, LSRR, SSRR, Router Alert, and unknown valid options, plus malformed/truncation warnings when parsing must stop conservatively. There is no standalone IPv4 `Protocol` tab renderer today. |
| IPv6 | Supported | Supported | Not supported | Supported | Not supported | Not supported | N/A | Supported | IPv6 facts appear in layered Summary, including conservative selected-packet header fields such as traffic class, flow label, payload length, next header, hop limit, and addresses. There is no standalone IPv6 `Protocol` tab renderer today. |
| IGMP | Supported | Supported | Supported | Supported | Supported | Not supported | Not supported | Supported | First-pass IPv4 IGMP support groups by source plus effective multicast-group key, keeps ports internally at zero but empty in UI, supports IGMPv1/v2 base-header parsing, safe unknown-type handling, and partial IGMPv3 membership-report presentation. Malformed or truncated IGMP packets can remain in the unrecognized-packet list with explicit reason text. |
| ICMP | Supported | Supported | Not supported | Supported | Supported | Not supported | Not supported | Supported | Selected-packet `Protocol` can show basic ICMP text, and layered Summary now appends a dedicated ICMP layer after IPv4. |
| ICMPv6 | Supported | Supported | Not supported | Supported | Supported | Not supported | Not supported | Supported | Selected-packet `Protocol` can show basic ICMPv6 text, and layered Summary now appends a dedicated ICMPv6 layer after IPv6. |
| TCP | Supported | Supported | Not supported | Supported | Partial | Supported | Supported | Supported | Layered Summary exposes TCP ports, raw sequence / acknowledgment numbers, header length, flags, window, checksum, urgent pointer, payload length, and a nested `TCP Options (N bytes)` subtree when options are present. The first shared on-demand parser handles EOL, NOP, MSS, Window Scale, SACK Permitted, SACK, Timestamps, unknown valid options, and conservative malformed/truncation warnings. Generic selected-packet `Protocol` text is not emitted for plain TCP packets, but higher-level analyzers can consume TCP payload. Stream falls back to generic `TCP Payload` rows when no HTTP/TLS specialization applies. |
| UDP | Supported | Supported | Not supported | Supported | Partial | Supported | Supported | Supported | Layered Summary exposes UDP ports, length, checksum, and payload length. Generic selected-packet `Protocol` text is not emitted for plain UDP packets, but higher-level analyzers can consume UDP payload. Stream falls back to generic `UDP Payload` rows when no specialization applies. |

## Support Matrix: Higher-Level Protocols And Hints

These rows generally ride on top of TCP or UDP flows. They do not create separate flow-key semantics of their own.

| Protocol / hint | Recognition | Flow key / grouping | Service hint | Packet Summary layer | Protocol details | Payload tab | Stream items | Tests / fixtures | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TLS | Supported | Not supported | Supported | Supported | Supported | Partial | Supported | Supported | Flow hint detection can extract TLS version and SNI where available. Selected-packet layered Summary now appends a final TLS layer using the existing protocol-details path. Selected-packet `Payload` remains transport-payload-oriented rather than a full TLS tree. Selected-flow Stream supports TLS record / handshake labeling such as `TLS ClientHello`, `TLS ServerHello`, and `TLS AppData`. |
| QUIC | Supported | Not supported | Partial | Supported | Supported | Partial | Supported | Supported | Open-time QUIC detection is intentionally cheap. Service hint may remain empty at open time and refresh later through bounded selected-flow analysis. Selected-packet layered Summary now appends a final QUIC layer using the existing protocol-details path, including QUIC+TLS presentation where available. Stream supports QUIC Initial item labeling such as `QUIC Initial: CRYPTO` and `QUIC Initial: ACK`. No claim is made here about full general QUIC reassembly. |
| DNS | Supported | Not supported | Supported | Supported | Supported | Partial | Partial | Supported | Open-time hinting supports DNS with QNAME-based service hints. Selected-packet layered Summary now appends a final DNS layer using the existing protocol-details path. Selected-packet `Payload` is generic UDP/TCP payload bytes. Stream code contains DNS-specific label hooks, but current tests still primarily cover generic UDP fallback rows, so stream support should be treated as partial. |
| mDNS | Detection-only | Not supported | Not supported | Not supported | Not supported | Partial | Partial | Supported | Detection depends on UDP/5353 and multicast destination checks. Current behavior stops at hinting plus generic UDP surfaces. |
| HTTP | Supported | Not supported | Supported | Supported | Supported | Partial | Supported | Supported | Open-time hinting can use `Host`, and optionally request path fallback when the relevant setting is enabled. Selected-packet layered Summary now appends a final HTTP layer using the existing protocol-details path. Stream can build request/response-oriented items such as `HTTP GET /...` from bounded reconstruction. |
| DHCP | Detection-only | Not supported | Not supported | Not supported | Not supported | Partial | Partial | Supported | Current support is open-time detection from BOOTP/DHCP shape checks. Selected-packet / Stream surfaces fall back to generic UDP behavior. |
| STUN | Detection-only | Not supported | Not supported | Not supported | Not supported | Partial | Partial | Supported | Current support is hint-only. No dedicated selected-packet or stream presentation was found. |
| BitTorrent | Detection-only | Not supported | Not supported | Not supported | Not supported | Partial | Partial | Supported | Current support is handshake / hint recognition only. No dedicated packet-details or stream presentation was found. |
| SSH | Detection-only | Not supported | Not supported | Not supported | Not supported | Partial | Partial | Supported | Current support is banner-based hint recognition only. |
| SMTP | Detection-only | Not supported | Not supported | Not supported | Not supported | Partial | Partial | Supported | Current support is cheap text / port-based hint recognition only. |
| POP3 | Detection-only | Not supported | Not supported | Not supported | Not supported | Partial | Partial | Supported | Current support is cheap text / port-based hint recognition only. |
| IMAP | Detection-only | Not supported | Not supported | Not supported | Not supported | Partial | Partial | Supported | Current support is cheap text / port-based hint recognition only. |
| `possible_tls` | Detection-only | Not supported | Not supported | Not supported | Not supported | Not supported | Not supported | Supported | Settings-gated fallback hint for TCP/443-like traffic when confirmed TLS detection did not fire. This is intentionally not a claim of real TLS parsing. |
| `possible_quic` | Detection-only | Not supported | Not supported | Not supported | Not supported | Not supported | Not supported | Supported | Settings-gated fallback hint for UDP/443-like traffic when confirmed QUIC detection did not fire. This is intentionally not a claim of real QUIC parsing. |

## Known Limitations By Area

### Layered Summary

The shared layered Summary model is intentionally conservative today.

- It is strongest for:
  - frame metadata;
  - Ethernet;
  - VLAN;
  - MPLS label stacks;
  - ARP;
  - IGMP;
  - IPv4;
  - IPv6;
  - TCP;
  - UDP.
- IPv4 Summary now includes a first structured nested IPv4 options subtree under the IPv4 layer when options are present, including EOL/NOP handling, safe parsing for RR/Timestamp/LSRR/SSRR/Router Alert, unknown-option raw preservation, and conservative malformed/truncation warnings for selected-packet inspection only.
- TCP Summary now includes a first structured nested TCP options subtree under the TCP layer, but this remains selected-packet/on-demand only and does not affect open/import behavior.
- It still does not expose full dedicated Summary subtrees for:
  - mDNS;
  - DHCP;
  - STUN;
  - BitTorrent;
  - SMTP / POP3 / IMAP / SSH.
- For TLS, QUIC, DNS, HTTP, ICMP, and ICMPv6, layered Summary now appends a conservative final protocol layer using the existing selected-packet protocol-details path instead of introducing a separate deep Summary parser.

### Protocol details

Selected-packet `Protocol` currently has three main modes:

- specialized analyzers for:
  - TLS;
  - QUIC;
  - DNS;
  - HTTP;
- shared basic protocol text for:
  - ARP;
  - IGMP;
  - ICMP;
  - ICMPv6;
- explicit "unavailable" or "no protocol-specific details" fallbacks for other packets.

IPv4, IPv6, Ethernet, and VLAN currently contribute strongly to layered Summary rather than to standalone `Protocol` text.

### Payload bytes

Selected-packet `Payload` is not a generic "deep application payload" system.

- For TCP and UDP packets it shows extracted transport payload bytes.
- For ARP packets it shows bounded ARP bytes through the packet-details payload path.
- For fragmented IP packets, payload extraction is intentionally conservative and may be empty.
- For protocols such as ICMP and ICMPv6, a protocol-specific payload tab was not found.

### Service hints

Service hints are intentionally heuristic and bounded.

- HTTP can use `Host`, and optionally request path fallback.
- TLS can expose SNI where parsing succeeds.
- QUIC service hints may require deferred selected-flow analysis.
- ARP can produce descriptive request/reply/probe/gratuitous text.
- Many other hint-only protocols do not currently produce service text.

### Unrecognized packets

Packets that cannot be assigned to a normal flow are collected separately during direct source-capture open.

- they do not participate in normal flow grouping;
- they remain selectable for packet-details inspection;
- stream reconstruction does not apply to them;
- they are not currently persisted into saved index files, so reopening an index can lose the unrecognized-packet list.

### Stream items

Selected-flow Stream currently supports only a subset of protocol-aware timelines.

- The Stream tab exists only for selected flows.
- Stream generation is bounded and on-demand.
- Stream support is implemented only for flow families backed by:
  - TCP;
  - UDP;
  - ARP.
- Specialized stream presentation is strongest for:
  - HTTP;
  - TLS;
  - QUIC;
  - ARP.
- Generic fallback rows remain common for plain TCP and UDP payloads.
- ARP stream behavior is intentionally simple:
  - one ARP packet becomes one stream item;
  - request/reply packets are not grouped together;
  - ARP payload/protocol text reuse shared packet-details logic.

## Current Test And Fixture Coverage

### Parsing fixture directories

Current parsing fixture directories under `tests/data/parsing/` include:

- `arp`
  - ARP request/reply, gratuitous ARP, probe, VLAN-tagged ARP, Ethernet padding, malformed/truncated cases, snaplen-truncated capture, and uncommon opcode / address-size variants.
- `igmp`
  - IGMPv1/v2 reports and queries, same-group/source grouping cases, Router Alert / IPv4 IHL handling, safe unknown-type handling, partial IGMPv3 membership reports, bad checksum, and truncated / snaplen-truncated IGMP fixtures.
- `dns`
  - basic DNS request/response coverage.
- `http`
  - request/response and multi-message / partial-response coverage.
- `mpls`
  - single-label and multi-label stacks, MPLS multicast EtherType, special labels, VLAN/QinQ before MPLS, unknown inner payloads, and snaplen-truncated inner IPv4/TCP cases.
- `pppoe`
  - deterministic PPPoE Session, PPP control, PPPoE Discovery, VLAN/QinQ-before-PPPoE, unknown PPP protocol, and malformed/truncated/length-mismatch fixtures. The current parser supports normal PPPoE Session IPv4/IPv6 data continuation with bounded PPPoE payload semantics, basic PPP control header/option presentation for no-flow LCP/IPCP/IPv6CP packets, and basic PPPoE Discovery header/tag presentation for no-flow Discovery packets. Unknown PPP protocols remain conservative, while length-mismatch fixtures can still produce normal flows when enough bounded inner header bytes are available.
- `llc_snap`
  - deterministic IEEE 802.3 length / LLC / SNAP fixtures, including direct IPv4/IPv6/ARP continuation, VLAN/QinQ-before-LLC/SNAP composition, unknown PID/non-SNAP fallback, and malformed/truncated/length-boundary cases. Current shared support is intentionally narrow: Ethernet OUI `00:00:00` plus PID IPv4/IPv6/ARP continues into normal decode, while unknown OUI/PID and non-SNAP LLC remain conservative with bounded payload preview, malformed headers surface explicit truncation warnings, and declared 802.3 length bounds limit inner parsing.
- `quic`
  - QUIC Initial, constricted captures, IPv6 variants, and analysis-oriented fixtures.
- `tcp`
  - generic TCP payload and checksum-oriented fixtures.
- `tls`
  - TLS 1.2 / 1.3, constricted captures, and IPv6 variants.
- `udp`
  - generic UDP payload, truncation, and checksum-oriented fixtures.
- `vlan`
  - single-tag 802.1Q, current two-tag QinQ, VLAN-tagged ARP, unknown inner EtherType, and malformed/truncated VLAN fixtures.

### Unit-test areas worth checking when protocol support changes

Current protocol behavior is primarily exercised in:

- `tests/unit/FlowHintsTests.cpp`
- `tests/unit/AnalysisSettingsTests.cpp`
- `tests/unit/PacketDetailsTests.cpp`
- `tests/unit/PacketPayloadTests.cpp`
- `tests/unit/PacketProtocolDetailsTests.cpp`
- `tests/unit/StreamQueryTests.cpp`
- `tests/unit/ArpPcapFixtureTests.cpp`
- `tests/unit/VlanPcapFixtureTests.cpp`
- `tests/unit/FragmentationTests.cpp`
- `tests/unit/MalformedPacketHandlingTests.cpp`

## How To Update This Document

Whenever protocol support changes, update this document alongside the code change.

At minimum, re-check:

- protocol enums and hint enums in `src/core/domain/**`;
- decoder / packet-details / payload services in `src/core/**`;
- selected-flow stream and formatting code in `src/app/session/**`;
- frontend-neutral DTO exposure in `src/app/frontend/**`;
- selected-packet and selected-flow rendering expectations in Qt UI and Tauri UI docs;
- unit tests and parsing fixtures under `tests/unit/**` and `tests/data/parsing/**`.

Update all of the following together when practical:

- this document;
- unit tests;
- parsing fixtures or fixture generators;
- any affected presentation-contract / DTO mapping docs.

If support is heuristic, bounded, or selected-flow-only, say so explicitly here rather than broadening the wording.
