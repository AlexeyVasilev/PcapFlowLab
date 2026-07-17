# Protocol Support

## Purpose

This document is the authoritative repository-level reference for current protocol support in Pcap Flow Lab.

Related design docs:

- `docs/protocols/overlay_inner_flow_tuple_branch.md`
- `docs/protocols/protocol_path_flow_identity.md`

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
| IEEE 802.3 LLC/SNAP | Partial | Partial | Not supported | Supported | Not supported | Not supported | N/A | Supported | Shared decode distinguishes IEEE 802.3 length framing from Ethernet II, recognizes LLC/SNAP only for DSAP `0xaa`, SSAP `0xaa`, Control `0x03`, and continues through known SNAP PID values for IPv4, IPv6, and ARP when the bounded payload validates, including non-zero OUI cases. Direct and VLAN/QinQ-wrapped cases are supported. Unknown PID and non-SNAP LLC remain conservative with specific no-flow reason text and bounded Data/raw preview. Malformed LLC/SNAP headers and IEEE 802.3 length-boundary mismatches are handled best-effort, and trailing bytes beyond the declared 802.3 length are ignored for inner parsing. |
| 802.1Q VLAN | Supported | N/A | Not supported | Supported | Not supported | Not supported | N/A | Supported | Single-tag `0x8100`, `0x88A8` QinQ-style outer tags, and legacy `0x9100` VLAN-like tags are supported in shared decode and layered Summary. VLAN stack depth is bounded to 4 tags. Unknown or truncated inner VLAN payloads remain conservative and can stay in the unrecognized-packet list while still preserving partial Ethernet/VLAN envelope details. |
| MACsec / IEEE 802.1AE | Partial | Not supported | Not supported | Supported | Partial | Not supported | N/A | Supported | Shared decode recognizes EtherType `0x88e5` directly after Ethernet or outer VLAN/QinQ, parses basic SecTAG metadata (Version/ES/SC/SCB/E/C/AN, Short Length, Packet Number, optional SCI), and keeps protected payload opaque. Selected-packet layered Summary can show `MACsec SecTAG`, bounded `MACsec Protected Payload`, and `MACsec ICV` when enough bytes are present; for complete `E=0` / `C=0` secured-data cases, the first two secured-data bytes may also be surfaced as `Plain EtherType` metadata while the remaining bytes stay opaque. Selected-packet `Protocol` can show best-effort MACsec text for no-flow packets. No decryption, no ICV validation, no MKA/SAK or control-plane support, and no flow recovery from protected payload are implemented, so all current MACsec fixtures remain no-flow packets with specific truncation/decryption reason text. |
| IEEE 802.1ah PBB / MAC-in-MAC | Partial | Partial | Not supported | Supported | Not supported | Not supported | N/A | Supported | Shared decode recognizes EtherType `0x88e7`, parses the 4-byte I-TAG (Priority/Drop Eligible/NCA/Reserved 1/Reserved 2/I-SID), and continues into inner customer Ethernet. Inner IPv4/IPv6 TCP/UDP can form normal flows, ARP can be recognized behind PBB, and inner VLAN/QinQ/LLC-SNAP composition is supported. Outer B-TAG before PBB is preserved in layered Summary. Unknown inner EtherType and malformed/truncated I-TAG or inner headers remain conservative no-flow packets with explicit reason text and bounded Data/partial-header presentation; truncated I-TAG packets can still expose partial first-byte bit fields and basic PBB protocol-detail text for manual inspection. No PBB-TE, OAM/CFM, control-plane, or bridge-learning semantics are implemented. |
| MPLS | Partial | Partial | Not supported | Supported | Not supported | Partial | Partial | Supported | Ethernet MPLS unicast/multicast and VLAN-before-MPLS are recognized. Each label becomes its own Summary layer with label / TC / BoS / TTL. After the BoS label, shared decode now supports direct IPv4/IPv6 continuation plus basic Ethernet pseudowire continuation with optional 4-byte control word, including inner Ethernet, inner VLAN/QinQ, inner IEEE 802.3 LLC/SNAP, and inner ARP/IPv4/IPv6 continuation when the bounded inner payload is valid. Unknown or malformed MPLS payloads remain in the unrecognized-packet list with conservative reason text such as truncated control word, truncated inner Ethernet, unknown inner EtherType, or truncated inner IPv4. |
| PPPoE Session + PPP IPv4/IPv6 + PPP control basics + basic PPPoE Discovery | Partial | Partial | Not supported | Supported | Partial | Partial | Partial | Supported | Current PPPoE support covers PPPoE Session (`0x8864`) data frames with `code = 0x00`, bounding inner parsing to `min(declared PPPoE payload length, captured PPPoE payload bytes)`, and continuing through PPP IPv4 (`0x0021`) and PPP IPv6 (`0x0057`) into normal IPv4/IPv6/TCP/UDP parsing when enough bounded inner header bytes are available. Selected-packet layered Summary preserves PPPoE Session and PPP protocol layers, basic PPP control presentation for LCP/IPCP/IPv6CP Configure-style packets, and basic PPPoE Discovery (`0x8863`) header/tag presentation for PADI/PADO/PADR/PADS/PADT. Discovery and PPP control packets remain no-flow. Unknown PPP protocols remain conservative, while PPPoE length-mismatch packets may still form normal flows if their bounded inner tuple is available. |
| VXLAN / Geneve / GTP-U UDP overlays | Partial | Partial | Not supported | Partial | Partial | Partial | Partial | Supported | Current overlay-inner-tuple support recognizes VXLAN over UDP/4789, Geneve over UDP/6081, and GTPv1-U T-PDU over UDP/2152 during open/import. VXLAN and Geneve require a valid bounded overlay header that leads to inner Ethernet plus inner IPv4/IPv6 plus TCP/UDP/SCTP, including existing inner VLAN continuation where valid. GTP-U supports the basic direct-inner-IP user-plane path, where the inner payload starts directly with IPv4 or IPv6 plus TCP/UDP/SCTP. The effective flow tuple becomes the inner transport tuple. Protocol-path-aware flow identity now also includes tunnel namespace metadata such as VXLAN VNI, Geneve VNI, and GTP-U TEID, so same-inner-tuple traffic from distinct overlay namespaces splits into distinct flows. VXLAN, Geneve, and GTP-U selected-packet Summary / Protocol details are implemented. VXLAN and Geneve show sequential inner Ethernet/VLAN/IP/transport layers for valid overlays; GTP-U shows a dedicated GTP-U layer followed by sequential direct inner IPv4/IPv6 and TCP/UDP/SCTP layers when safely available for both outer IPv4 and outer IPv6 UDP carriers. Known GTP-U message types and known next-extension-header types may be displayed by name in selected-packet details, while extension headers remain shallow skip-only metadata rather than deep-parsed structures. Overlay-carried SCTP selected-packet details reuse the bounded SCTP common-header, first-chunk, and known-PPID presentation used by direct SCTP packets, but SCTP PPID naming remains presentation metadata only. Malformed/truncated overlay-like UDP payloads on their standard ports use lenient warning-oriented selected-packet presentation only and do not change flow grouping. For Geneve, strict flow extraction still requires version `0`, 4-byte-unit option bounds that fit the captured payload, and Ethernet Protocol Type (`0x6558`); selected-packet details may still show best-effort inner continuation for unsupported-version Geneve when those other bounds remain valid, while unsupported protocol types are reported distinctly and do not continue into inner Ethernet decoding. For GTP-U, strict flow extraction requires version `1`, PT set, message type T-PDU `0xff`, bounded optional fields when E/S/PN are set, and a bounded extension-header chain when `E=1`; selected-packet details may still show lenient malformed/truncated/unsupported metadata on UDP/2152 without changing flow keys. Outer tunnel source/destination endpoints are still intentionally excluded from v1 flow identity, so packets with the same overlay namespace id and same inner tuple can still merge across different outer carriers. |
| GRE v0 direct inner IPv4/IPv6, TEB inner Ethernet, and MPLS unicast | Partial | Partial | Not supported | Supported | Supported | Not supported | Not supported | Supported | Current GRE support recognizes IPv4 protocol `47` and IPv6 next-header `47` for conservative GRE version `0` bounded decode. Direct inner IPv4 and IPv6 payload types (`0x0800`, `0x86DD`) can continue into normal TCP/UDP/SCTP flow extraction. GRE Transparent Ethernet Bridging (`0x6558`) can also continue into the existing inner Ethernet path, including supported inner VLAN continuation before inner IPv4/IPv6 plus TCP/UDP/SCTP. GRE MPLS unicast (`0x8847`) reuses the existing MPLS stack classifier, so plain MPLS that bottoms out into IPv4/IPv6 can continue into normal TCP/UDP/SCTP flow extraction, and any already-safe MPLS pseudowire continuation follows the same bounded helper behavior. Optional checksum/key/sequence fields are safely skipped only when fully present. Selected-packet Summary / Protocol Details now show a GRE layer plus bounded inner continuation for direct inner IP, TEB inner Ethernet, GRE/MPLS, and any fully present optional checksum/key/sequence metadata. GRE key now participates in protocol-path-aware flow identity when the key flag is set and the full 32-bit key is available, so same-inner-tuple traffic with different GRE keys splits into distinct flows while checksum and sequence metadata do not affect identity. GRE version `1` / PPTP-like framing remains out of scope for this pass. |
| ESP (opaque IPsec payload) | Partial | Partial | Not supported | Supported | Supported | Not supported | Not supported | Supported | Current ESP support recognizes direct IPv4 protocol `50` and IPv6 next-header `50` when at least the fixed 8-byte ESP lead-in is available. Flow identity uses the outer IP family plus outer addresses, zero ports, protocol `ESP`, and a protocol path that includes `ESP(spi=...)`, so same-endpoint different-SPI traffic splits while same-SPI packets group together. Selected-packet Summary / Protocol details expose SPI, Sequence Number, opaque payload length, and conservative truncation warnings. NAT-T UDP/4500, trailer/padding/authentication parsing, decryption, and inner-payload decode remain out of scope. |
| Plain IPv4/IPv6 encapsulation (`proto 4` / `41`) | Partial | Partial | Not supported | Supported | Supported | Not supported | Not supported | Supported | Current support covers the four direct family combinations `IPv4->IPv4`, `IPv4->IPv6`, `IPv6->IPv4`, and `IPv6->IPv6` with bounded inner TCP/UDP continuation, one representative nested `IPv4 -> IPv4 -> IPv4 -> UDP` case, and inner ICMP / ICMPv6 zero-port flow handling for the documented outer-IPv4 fixtures. Selected-packet Summary / Protocol details show ordered outer and inner network/transport layers for the implemented direct cases and bounded truncated-inner presentation for malformed fixtures. Outer tunnel endpoints intentionally do not participate in v1 identity, so identical inner tuples through different plain-IP outer endpoints may still merge. |
| AH (direct and bounded tunnel mode) | Partial | Partial | Not supported | Supported | Supported | Not supported | Not supported | Supported | Current AH support recognizes direct IPv4/IPv6 AH when the fixed header and declared bounds are valid, supports direct TCP/UDP continuation plus the documented IPv6 Hop-by-Hop before AH case, and includes AH SPI in protocol-path-aware identity. The implemented tunnel-mode fixtures can continue into bounded inner IPv4/IPv6 plus TCP/UDP flow extraction. Selected-packet Summary / Protocol details expose AH metadata, partial/truncated warnings, and bounded inner continuation when safely available. Sequence Number remains details-only metadata, while ICV verification, nested AH chains, and broader next-header families remain deferred. |
| MikroTik EoIP over GRE | Partial | Partial | Not supported | Supported | Supported | Not supported | Not supported | Supported | Current support recognizes the strict MikroTik EoIP shape over outer IPv4 GRE version `1` with K bit set and Protocol Type `0x6400`, parses big-endian frame length plus little-endian Tunnel ID, and normalizes Tunnel ID into the existing `GRE(key=...)` protocol-path identity slot. Bounded inner Ethernet continuation supports documented inner IPv4/IPv6/TCP/UDP plus inner VLAN/QinQ composition, while malformed or non-EoIP GRE v1 lookalikes remain conservative. EoIP frame length does not participate in identity, outer IPv6 carriage is still deferred, and no separate `EoIP` protocol-path layer is introduced. |
| ARP | Supported | Supported | Supported | Supported | Supported | Supported | Supported | Supported | Strongest non-IP shared parsing path today. Supports Ethernet/IPv4 ARP well, variable `hlen` / `plen`, truncated warnings, and one-packet-per-item stream rows. Request/reply packets are not grouped into a higher-level conversation item. |
| IPv4 | Supported | Supported | Not supported | Supported | Not supported | Not supported | N/A | Supported | IPv4 facts appear in layered Summary, including conservative selected-packet header fields such as IHL, DS field, identification, flags, fragment offset, TTL, protocol, checksum, and addresses. When IPv4 options are present, Summary can append a nested `IPv4 Options (N bytes)` child with wire-order option entries for EOL, NOP, RR, Timestamp, LSRR, SSRR, Router Alert, and unknown valid options, plus malformed/truncation warnings when parsing must stop conservatively. There is no standalone IPv4 `Protocol` tab renderer today. |
| IPv6 | Supported | Supported | Not supported | Supported | Not supported | Not supported | N/A | Supported | IPv6 facts appear in layered Summary, including conservative selected-packet header fields such as traffic class, flow label, payload length, next header, hop limit, and addresses. There is no standalone IPv6 `Protocol` tab renderer today. |
| IGMP | Supported | Supported | Supported | Supported | Supported | Not supported | Not supported | Supported | First-pass IPv4 IGMP support groups by source plus effective multicast-group key, keeps ports internally at zero but empty in UI, supports IGMPv1/v2 base-header parsing, safe unknown-type handling, and partial IGMPv3 membership-report presentation. Malformed or truncated IGMP packets can remain in the unrecognized-packet list with explicit reason text. |
| ICMP | Supported | Supported | Not supported | Supported | Supported | Not supported | Not supported | Supported | Selected-packet `Protocol` can show basic ICMP text, and layered Summary now appends a dedicated ICMP layer after IPv4. |
| ICMPv6 | Supported | Supported | Not supported | Supported | Supported | Not supported | Not supported | Supported | Selected-packet `Protocol` can show basic ICMPv6 text, and layered Summary now appends a dedicated ICMPv6 layer after IPv6. |
| TCP | Supported | Supported | Not supported | Supported | Partial | Supported | Supported | Supported | Layered Summary exposes TCP ports, raw sequence / acknowledgment numbers, header length, flags, window, checksum, urgent pointer, payload length, and a nested `TCP Options (N bytes)` subtree when options are present. The first shared on-demand parser handles EOL, NOP, MSS, Window Scale, SACK Permitted, SACK, Timestamps, unknown valid options, and conservative malformed/truncation warnings. Generic selected-packet `Protocol` text is not emitted for plain TCP packets, but higher-level analyzers can consume TCP payload. Stream falls back to generic `TCP Payload` rows when no HTTP/TLS specialization applies. |
| UDP | Supported | Supported | Not supported | Supported | Partial | Supported | Supported | Supported | Layered Summary exposes UDP ports, length, checksum, and payload length. Generic selected-packet `Protocol` text is not emitted for plain UDP packets, but higher-level analyzers can consume UDP payload. Stream falls back to generic `UDP Payload` rows when no specialization applies. |
| SCTP | Supported | Supported | Not supported | Supported | Supported | Not supported | Not supported | Supported | IPv4 protocol `132` and IPv6 next-header `132` now form normal SCTP flows keyed by source/destination IP plus SCTP source/destination ports. Selected-packet Summary / Protocol details show the SCTP common header, bounded first-chunk metadata, DATA PPID, and known PPID pseudo-layers for documented PPIDs. VLAN, MPLS direct-inner-IP, and supported VXLAN/Geneve/GTP-U inner-SCTP regression cases reuse the existing shim/overlay tuple paths. SCTP stream/reassembly is intentionally not implemented, SCTP checksum validation is not implemented, PPID recognition is presentation metadata only, and deep ASN.1 / SIGTRAN / Diameter parsing remains out of scope. |

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
- they are now persisted into saved index files, so reopening a current-format index preserves the unrecognized-packet list.

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

## Current Non-Goals For This Branch

The current protocol-support pass intentionally does not claim support for:

- QUIC false-positive cleanup beyond the bounded shim changes already implemented;
- L2TP, NAT-T ESP over UDP/4500, GRE shapes outside the documented GRE v0 direct-inner-IP / TEB / MPLS subset, or GTP-U shapes outside the documented GTPv1-U T-PDU subset;
- MACsec decryption, ICV validation, MKA/SAK handling, or inner flow recovery;
- PBB-TE, OAM/CFM, PBB control-plane behavior, or bridge-learning semantics;
- PPPoE session-negotiation or control-plane semantics beyond conservative Discovery / PPP-control presentation;
- MPLS LDP, BGP-labeled services, OAM, or MPLS-TP control-plane semantics.

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
- `mpls_pw`
  - deterministic MPLS Ethernet pseudowire fixtures, including inner Ethernet IPv4/IPv6/ARP candidates, pseudowire control-word cases, inner VLAN/QinQ and LLC/SNAP composition, and malformed/truncated pseudowire cases. Current committed behavior supports bounded pseudowire inner Ethernet continuation with optional control-word presentation and normal inner ARP/IPv4/IPv6 continuation when the bounded inner payload is valid, while malformed or unsupported pseudowire payloads remain conservative no-flow packets.
- `pppoe`
  - deterministic PPPoE Session, PPP control, PPPoE Discovery, VLAN/QinQ-before-PPPoE, unknown PPP protocol, and malformed/truncated/length-mismatch fixtures. The current parser supports normal PPPoE Session IPv4/IPv6 data continuation with bounded PPPoE payload semantics, basic PPP control header/option presentation for no-flow LCP/IPCP/IPv6CP packets, and basic PPPoE Discovery header/tag presentation for no-flow Discovery packets. Unknown PPP protocols remain conservative, while length-mismatch fixtures can still produce normal flows when enough bounded inner header bytes are available.
- `pbb`
  - deterministic IEEE 802.1ah PBB / MAC-in-MAC fixtures, including basic inner IPv4/IPv6/ARP continuation, outer B-TAG composition, inner VLAN/QinQ/LLC-SNAP composition, unknown inner EtherType, non-default I-TAG metadata, and malformed/truncated I-TAG / inner-header cases. Current committed behavior supports bounded I-TAG parsing plus inner customer Ethernet continuation into IPv4/IPv6/ARP and shared inner VLAN/QinQ/LLC-SNAP handling, while unknown or malformed inner payloads remain conservative no-flow packets.
- `macsec`
  - deterministic IEEE 802.1AE MACsec fixtures, including basic SecTAG metadata, optional SCI, outer VLAN/QinQ-before-MACsec composition, TCI flag coverage, zero Packet Number, and malformed/truncated SecTAG / SCI / ICV-boundary cases. Current committed behavior recognizes MACsec and presents conservative SecTAG/SCI/protected-payload/ICV details for selected packets, while keeping protected payload opaque and all fixtures as no-flow packets with specific reason text.
- `llc_snap`
  - deterministic IEEE 802.3 length / LLC / SNAP fixtures, including direct IPv4/IPv6/ARP continuation, VLAN/QinQ-before-LLC/SNAP composition, unknown PID/non-SNAP fallback, and malformed/truncated/length-boundary cases. Current shared support is intentionally narrow: known SNAP PID values for IPv4/IPv6/ARP continue into normal decode when the bounded payload validates, including non-zero OUI cases, while unknown PID and non-SNAP LLC remain conservative with bounded payload preview, malformed headers surface explicit truncation warnings, and declared 802.3 length bounds limit inner parsing.
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
- `vxlan`
  - deterministic VXLAN fixtures including inner IPv4/IPv6 TCP/UDP continuation, VNI boundary values, inner VLAN composition, malformed/truncated headers, wrong-port negatives, and selected-packet VXLAN presentation coverage.
- `geneve`
  - deterministic Geneve fixtures including inner IPv4/IPv6 TCP/UDP continuation, bounded option skipping, VNI boundary values, inner VLAN composition, malformed/truncated headers, wrong-port negatives, unsupported-protocol cases, and selected-packet Geneve presentation coverage.
- `gtpu`
  - deterministic GTP-U fixtures including direct inner IPv4/IPv6 TCP/UDP continuation, TEID boundary values, optional S/PN/E field coverage, bounded extension-header skip, malformed/truncated headers, wrong-port negatives, and selected-packet GTP-U presentation coverage.
- `ah`
  - deterministic AH fixtures including direct IPv4/IPv6 TCP/UDP continuation, IPv6 Hop-by-Hop before AH, bounded tunnel-mode inner IPv4/IPv6 TCP/UDP continuation, SPI-aware identity coverage, and malformed/truncated AH presentation coverage.
- `esp`
  - deterministic ESP fixtures including direct IPv4/IPv6 SPI + sequence recognition, same-endpoint different-SPI split behavior, same-SPI grouping, outer VLAN/QinQ composition, opaque-payload handling, truncated base-header negatives, SPI boundary values, and staged NAT-T UDP/4500 follow-up cases.
- `ip_encapsulation`
  - deterministic plain IPv4/IPv6 encapsulation fixtures including all four direct family combinations, one representative nested IPv4 case, outer VLAN/QinQ composition, accepted same-inner-tuple merge tradeoff coverage, inner ICMP/ICMPv6 zero-port cases, and conservative malformed/truncated inner-header handling.
- `eoip`
  - deterministic MikroTik EoIP fixtures including strict GRE v1 + K-bit + Protocol Type `0x6400` recognition, big-endian frame length plus little-endian Tunnel ID decoding, normalized GRE-key identity reuse, inner Ethernet/VLAN/QinQ continuation, and malformed/truncated bounds coverage.
- `sctp`
  - deterministic SCTP fixtures including direct IPv4/IPv6 common-header flow extraction, known and unknown DATA PPID presentation, INIT/SACK first-chunk coverage, truncated common-header / DATA-metadata cases, bidirectional grouping, VLAN/MPLS regression coverage, supported VXLAN/Geneve/GTP-U inner-SCTP regression coverage, and non-SCTP false-positive prevention.

### Unit-test areas worth checking when protocol support changes

Current protocol behavior is primarily exercised in:

- `tests/unit/FlowHintsTests.cpp`
- `tests/unit/AnalysisSettingsTests.cpp`
- `tests/unit/PacketDetailsTests.cpp`
- `tests/unit/PacketPayloadTests.cpp`
- `tests/unit/PacketProtocolDetailsTests.cpp`
- `tests/unit/StreamQueryTests.cpp`
- `tests/unit/ArpPcapFixtureTests.cpp`
- `tests/unit/IgmpPcapFixtureTests.cpp`
- `tests/unit/VlanPcapFixtureTests.cpp`
- `tests/unit/PppoePcapFixtureTests.cpp`
- `tests/unit/LlcSnapPcapFixtureTests.cpp`
- `tests/unit/MplsPseudowirePcapFixtureTests.cpp`
- `tests/unit/PbbPcapFixtureTests.cpp`
- `tests/unit/MacsecPcapFixtureTests.cpp`
- `tests/unit/SctpPcapFixtureTests.cpp`
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
