# UI Presentation Contract

## Purpose

This document defines the intended user-facing presentation contract for Pcap Flow Lab across:

- the current Qt UI;
- the experimental Tauri UI;
- future CLI commands that expose session and inspection data;
- possible future frontend-neutral DTO cleanup.

Qt is currently the reference implementation because it exposes the broadest surface area today, but the contract described here is not intended to be Qt-specific. The goal is to converge on shared presentation semantics and shared backend-facing data expectations even if different frontends render them differently.

This document is intentionally presentation-oriented. It describes:

- what the product should display;
- what state transitions matter to users;
- what kinds of backend/session data frontends should request;
- what should later become shared frontend-neutral DTO shape.

Current protocol-detection and protocol-presentation coverage is documented separately in [protocol_support.md](../protocols/protocol_support.md).

## Scope And Non-Goals

### In scope

- Defining the shared concepts visible in the application shell.
- Defining the expected fields shown in the flows list, selected-flow packets list, packet inspector, selected-flow stream view, statistics view, and analysis workspace.
- Describing expected loading, empty, unavailable, and error states.
- Highlighting which fields should ideally come from structured backend/session DTOs versus which can remain frontend formatting.
- Recording initial ownership decisions for core, session, frontend-neutral DTOs, frontend controllers, rendering, and CLI surfaces.

### Out of scope

- Immediate implementation changes in Qt, Tauri, session, or DTO layers.
- Pixel-perfect layout, visual styling, spacing, or theming.
- Moving deep analysis into capture-open processing.
- Changing reassembly, stream, persistence, export, or source-attachment policy.
- Defining final CLI UX or command syntax.
- Freezing final C++ types.

## Architecture Alignment Constraints

This contract must remain aligned with the current backend/session architecture:

- fast open remains packet-oriented;
- deep stream/reassembly work is not moved into capture-open processing;
- stream remains selected-flow-only, bounded, and ephemeral;
- raw packet bytes are read lazily when byte-backed inspection is needed;
- index-only / source-unavailable behavior remains explicit;
- no session-wide stream reconstruction for all flows at open time;
- no unbounded packet or payload preview loading.

## Flow Grouping Setting Contract

The shared settings surface now includes two import-time grouping options:

- `Ignore VLAN and MPLS layers when grouping flows`
- `Ignore GTP-U TEIDs when grouping inner flows`

Presentation semantics:

- the setting affects raw-capture flow grouping only;
- it does not rewrite the currently open session in place;
- changing it while a capture or index is already open requires reopening that source to apply the new grouping;
- when the active raw-imported session was actually opened with the mode enabled, Qt and Tauri should both show a persistent informational banner that VLAN and MPLS layers are being ignored for grouping and that flows from different VLANs or MPLS paths may merge;
- when the active raw-imported session was actually opened with the GTP-U expert mode enabled, Qt and Tauri should both show a persistent informational banner that GTP-U TEIDs are being ignored for inner-flow grouping and that flows from different GTP-U tunnels may merge;
- when the active session was loaded from an index and the current setting is enabled, Qt and Tauri should both show the explicit limitation warning that stored index grouping is preserved and the current VLAN-and-MPLS grouping setting is not reapplied.
- when the active session was loaded from an index and the current GTP-U expert mode is enabled, Qt and Tauri should both show the explicit limitation warning that stored index grouping is preserved and the current GTP-U TEID grouping setting is not reapplied.

Packet-versus-flow presentation boundary:

- Packet Details and Bytes still show the observed VLAN and MPLS headers for the selected packet;
- flow-list Path presentation and Protocol Path Statistics follow the normalized flow identity, so VLAN and MPLS label-stack layers may be absent there when the mode was active at import time.
- Packet Details and Bytes still show the observed per-packet GTP-U TEID for the selected packet;
- flow-list Path presentation and Protocol Path Statistics follow the normalized flow identity, so `GTP-U(teid=...)` may appear there as plain `GTP-U` when the expert mode was active at import time.

## Terminology And Identifier Semantics

The contract should use consistent identifier vocabulary across Qt, Tauri, and future CLI surfaces.

### Stable identifiers

- `flow_index`
  - stable backend/session flow identifier;
  - follows backend/session indexing semantics;
  - should not be confused with visible row position after filtering or sorting.
- `packet_index`
  - stable global packet index in the capture/file/session;
  - should not be confused with row number within the selected-flow packet list.
- `stream_item_index`
  - stable index within the selected-flow stream result for the current selected flow and current stream query shape;
  - should not be treated as a global packet identifier.

### Display numbers

- `flow_display_number` or `flow_display_id`
  - optional user-facing display number for flows;
  - may be 1-based when the UI presents flows that way;
  - should be derived from `flow_index` or current presentation policy, not treated as the stable backend identifier.
- `flow_packet_row` or `flow_packet_number`
  - row number within the selected-flow packet list;
  - not the same as `packet_index`;
  - may be 1-based for human readability.
- user-facing packet numbers shown in details/summary should be 1-based as well, even when the underlying stable `packet_index` remains 0-based internally.
- `stream_item_display_number`
  - optional user-facing row number in the stream table;
  - not required to be the same thing as `stream_item_index`.

### Selection semantics

- `selected_flow`
  - should reference a stable flow identifier where possible;
  - should not be stored only as a visible filtered/sorted row.
- `selected_packet`
  - should reference `packet_index` where possible;
  - should not be stored only as a visible packet-table row.
- `selected_stream_item`
  - should reference the stable stream item identifier used by the current selected-flow stream result where possible;
  - should not be stored only as a visible stream-table row.

### Practical implication

Frontends may still track visible row indexes locally for table widgets, but the shared contract should be defined in terms of stable identifiers and explicit display-number fields rather than row-position assumptions.

## Ownership Model

This section defines which layer should own which kind of logic.

### Core / domain / core services

Core should own:

- packet facts;
- capture facts;
- decoded metadata;
- flow aggregation;
- packet references;
- protocol hints;
- bounded reassembly primitives;
- protocol parsing and packet inspection facts.

Core should not own:

- UI wording;
- tab labels;
- row highlighting rules;
- pixel layout;
- frontend-specific filtering widgets;
- view-local selection orchestration.

### App / session

Session should own:

- opening captures and indexes;
- application-facing read queries;
- selected-flow packet queries;
- selected-flow stream queries;
- source availability state;
- expected source path where relevant;
- lazy byte-backed inspection;
- bounded and on-demand behavior;
- action availability facts that depend on session/source state.

Session should not become a visual presentation layer.

### App / frontend-neutral DTO layer

Frontend-neutral DTOs should own:

- stable structured fields needed by Qt, Tauri, and future CLI;
- shared unavailable/truncated/source-state metadata;
- shared bounded-preview metadata;
- optional display-ready text when it represents shared product semantics rather than styling.

Examples of acceptable display-ready shared semantics:

- protocol details text;
- bounded raw preview text;
- bounded payload preview text;
- generated Wireshark display filter string.

Examples that should remain frontend-only:

- colors;
- chip/badge styling;
- exact button text for most local actions;
- exact column widths;
- hover/tool-tip timing.

### Frontend controller / model layer

Frontend controller/model logic should own:

- local selection state;
- visible sorting and filtering state;
- pagination/load-more UI state;
- tab activation;
- reset orchestration based on shared rules;
- local table-row mapping;
- clipboard interaction.

### Frontend rendering layer

Frontend rendering should own:

- colors;
- row highlighting;
- column widths;
- compact vs comfortable density;
- truncation and elision;
- exact visual layout;
- local responsive behavior.

### CLI

CLI should:

- prefer structured output first;
- optionally expose display-ready text fields when they are part of the shared DTO contract;
- avoid inventing a separate semantic model for flows, packets, details, or stream items.

## Initial Decisions

These are the initial stabilization decisions for future follow-up work.

- Core should not become a UI presentation layer.
- Frontend-neutral DTOs should expose structured facts first.
- Frontend-neutral DTOs may include display-ready text only when it represents shared product semantics, such as:
  - protocol details text;
  - bounded hex preview text;
  - bounded payload preview text;
  - generated Wireshark filter string.
- Visual styling remains frontend-only.
- Filtering and sorting can remain frontend-side for now, but should operate over documented DTO fields.
- Selection and reset semantics are part of the shared presentation contract.
- Packet Details byte inspection must remain bounded, selected-view-only, and must carry unavailable / partial / truncated state explicitly.
- Stream remains selected-flow-only, on-demand, bounded, ephemeral, and not persisted.
- Analysis remains reference behavior for now, not a frozen shared DTO contract.

## Global Application Shell

All frontends should share the same high-level user concepts.

### Shared shell concepts

- Active session path:
  - current opened input path;
  - whether the active session came from a capture or an index.
- Open mode:
  - currently `Fast` or `Deep`.
- Open state:
  - idle;
  - opening;
  - opened;
  - error.
- Source availability:
  - source capture attached and byte-backed inspection available;
  - index-only / source missing;
  - expected source path when known.
- Partial-open state:
  - when a capture was opened only partially and some operations are restricted.
- Current selection state:
  - selected flow;
  - selected packet;
  - selected stream item, when stream-item details are active.
- Frontend status text:
  - informational status;
  - non-fatal warnings;
  - actionable errors.

### Shared shell state behavior

- Opening a new capture or index must clear stale flow, packet, stream, analysis, and details state.
- Open failure must not leave stale selected flow, selected packet, stream data, or packet details visible.
- Source-unavailable mode must remain usable for metadata-only views while clearly marking raw-byte-dependent views as unavailable.
- Frontends may present these states differently, but the meaning should stay aligned.

## Flows View

The main flows view is the primary session-browsing surface. Qt currently uses structured flow fields and frontend filtering/sorting over that data. That behavior should be the reference.

### Expected flow list fields

Each flow row should expose at least the following user-facing fields:

- selection checkbox / selected-for-batch-action state;
- flow index;
- address family;
- protocol;
- protocol hint;
- service;
- endpoint A;
- endpoint B;
- fragmentation indicator;
- packet count;
- byte count.

### Current Qt presentation notes

- Flow index is displayed as a 1-based row identifier tied to the session flow index.
- Address family is shown as `IPv4` or `IPv6`.
- The visible flow table now uses compact `Endpoint A` / `Endpoint B` columns rather than separate address/port columns.
- `Endpoint A` is the source endpoint of the first observed packet assigned to the flow, and `Endpoint B` is its destination endpoint.
- Visible `A->B` / `B->A` direction text follows that same first-observed orientation and is not a lower-address or client/server inference rule.
- Endpoint formatting rules are:
  - IPv4 with port: `address : port`;
  - IPv4 without port: `address`;
  - IPv6 with port: `[address] : port`;
  - IPv6 without port: `address`;
  - missing/zero/invalid port: address only.
- Endpoint address/port are treated as key identifiers and should remain fully visible through adequate column width and horizontal scrolling rather than endpoint overlap as the normal display path.
- Detected Protocol is presentation-formatted from `protocol_hint`:
  - `possible_tls` -> `Possible TLS`;
  - `possible_quic` -> `Possible QUIC`;
  - other values are rendered in a user-facing uppercase/title form.
- Fragmentation is currently shown via a `Frag` column and a highlighted state when fragmented packets are present.
- Qt keeps both structured address/port fields and combined endpoint text available for matching/filtering.

### Filtering and search expectations

Frontend filtering is expected to be case-insensitive and work over already-available flow data. Current Qt behavior matches against:

- family;
- protocol;
- protocol hint;
- service hint;
- address A;
- address B;
- combined endpoint A / endpoint B text when available;
- port A;
- port B;
- fragmentation indicator / fragmentation count text.

The contract does not require filtering to be implemented in the backend. Frontends may filter already-loaded flow DTOs as long as semantics stay consistent.

### Sorting expectations

Current Qt behavior supports sorting by visible columns. Shared contract expectations:

- sort should operate on the same logical fields that are shown in the flow list;
- sort state is frontend state, not session state;
- sort should not change backend/session meaning.

### Selected flow behavior

- Selecting a flow makes it the active selected flow for:
  - selected-flow packet list;
  - selected-flow stream view;
  - selected-flow Wireshark filter generation;
  - selected-flow analysis.
- Changing selected flow must clear:
  - selected packet;
  - selected stream item;
  - packet details inspector;
  - selected-flow packet pagination state;
  - selected-flow stream state;
  - selected-flow analysis state until refreshed for the new flow.

### Wireshark display filter behavior

For the currently selected flow, frontends may display and copy a generated Wireshark display filter string.

Shared expectations:

- generated from structured selected-flow data;
- conservative and display-oriented;
- copy action should be available when a filter exists;
- missing or unsupported filter data should result in `no filter available`, not a fabricated filter.

Whether the final filter text is fully assembled in the backend or assembled in the frontend from structured fields remains a follow-up decision.

### Empty, loading, and error states

Flows view should clearly distinguish:

- no capture or index opened;
- flow list loading / applying session;
- no flows available;
- filter has no matches;
- general flow-list error state if one exists.

### Unrecognized packets list

Frontends may show a separate selectable list for packets that could not be assigned to a normal flow.

Shared expectations:

- this list is distinct from the normal flow table rather than fabricated as a pseudo-flow;
- rows are paginated like the selected-flow packet list;
- selecting the unrecognized-packet list clears the active selected flow;
- packet details inspection remains available;
- stream reconstruction is unavailable for this selection mode;
- the list is capture-backed only and is not guaranteed to persist through saved index round-trips.
- malformed MPLS packets follow this same unrecognized path: frontends may still show Ethernet/VLAN/MPLS and partial inner-IP Summary details, but a normal flow is created only when a complete inner IPv4/IPv6 transport flow key can be extracted.

### Backend vs frontend formatting

Backend/frontend-neutral DTOs should ideally provide structured fields:

- flow index;
- family;
- protocol;
- protocol hint;
- service;
- address A / port A;
- address B / port B;
- fragmentation flags/count;
- packet count;
- byte count.

Frontend formatting can remain responsible for:

- column labels;
- tooltip text;
- sort indicator display;
- filter box text;
- local truncation/elision rules.

## Selected-Flow Packets View

The selected-flow packets view is a bounded list tied to the currently selected flow.

### Expected packet list fields

Each selected-flow packet row should expose:

- row number within the selected flow;
- packet index in the capture/file;
- direction;
- timestamp / time;
- captured length;
- original length;
- transport payload length;
- TCP flags when available.

Current Qt also exposes marker-related presentation data:

- IP fragmentation indicator;
- suspected TCP retransmission marker when present.

These markers are part of current Qt presentation and should be treated as valid contract fields when available.

### Pagination / load-more behavior

Current Qt behavior is bounded and incremental.

Shared expectations:

- selected-flow packet lists are not required to load all packets immediately;
- UI should be able to show:
  - loading packet list;
  - showing first N of total;
  - all packets loaded;
  - load more available.
- load-more is tied to the selected flow only.
- frontends may present the lower selected-flow `Packets` / `Stream` controls as one compact toolbar-style row as long as packet/stream switching, packet-count status, and `Load More` remain visible and consistent.

### Selected packet behavior

- Selecting a packet makes it the active packet for the packet details inspector.
- Only one selected packet is active at a time.
- Selected packet should be cleared when:
  - selected flow changes;
  - packet page/list resets;
  - open fails;
  - a new capture/index is opened.

### Reset behavior when selected flow changes

When the selected flow changes:

- the selected-flow packet list is rebuilt for the new flow;
- loaded packet rows reset to the initial bounded view;
- selected packet is cleared;
- stale packet details must disappear.

### Empty, loading, error, and unavailable states

Packet list should distinguish:

- no capture/index opened;
- no flow selected;
- loading packet list;
- no packets available for the selected flow;
- partial packet list loaded;
- source-unavailable state when metadata is still present but byte-backed inspection is restricted;
- packet-list error state if one exists.

## Packet Details Inspector

Qt currently models the right-hand inspector as a tabbed details surface. That should be the reference shape for shared presentation semantics.

### Expected sections / tabs

- Summary
- Bytes

Current Packet Details direction note:

- `Summary / Bytes` is now the shared packet-details tab shape for Qt and the experimental Tauri UI;
- the removed `Raw` tab is represented by packet-byte inspection, whose fallback root view is now labeled `Captured Packet`;
- rich decoded Packet Details may be unavailable while packet metadata Summary and `Bytes` fallback presentation remain available from the same shared adapter contract;
- Qt and Tauri should therefore treat Summary availability and `Bytes` availability as related but independent states;
- the `Bytes` selector is now protocol-unit-oriented by default, so entries such as `Ethernet II Frame`, `IEEE 802.3 Frame`, `PPP Packet`, `IPv4 Packet`, `TCP Segment`, `UDP Datagram`, `ARP Packet`, and existing QUIC packet/frame views represent complete bounded protocol data units rather than payload-only slices;
- the same stable protocol-layer identity may also retain an optional payload-only range for a later `Whole Unit | Payload Only` UI toggle, but the current Qt and Tauri UIs always request/display the complete unit range;
- complete nested carrier units now use protocol-oriented selectors such as `802.1Q Encapsulation`, `GRE Packet`, `EoIP Packet`, `Geneve Packet`, `GTP-U Message`, `AH Packet`, and `ESP Packet`, while any retained payload-only range stays internal optional metadata on the same descriptor;
- Stream Item Details now use `Summary / Item Data`, where `Item Data` is selected-row-only and is backed by one bounded selected-item materialization.
- Stream Item Details Summary is intended to be a frontend-neutral mapping from retained structured stream-item semantics; labels and retained protocol text may still exist elsewhere, but they are not semantic authorities for Summary.

Qt also supports stream-item details in the same right-hand panel. That is noted separately below as a cross-cutting selection question.

### Summary

Summary should show compact packet metadata and packet-level interpretation, including where available:

- packet index;
- timestamp;
- captured length;
- original length;
- payload length;
- direction;
- TCP flags;
- link-layer summary;
- network-layer summary;
- transport-layer summary;
- endpoint addresses and ports;
- warning text when present.

Qt currently uses formatted summary text rather than a purely structured field grid. Shared contract should preserve the information content even if different frontends choose a different compact layout.

Current direction note:

- packet details Summary now has a first shared structured decoded-layer list for selected-packet/on-demand rendering;
- Qt Summary text inside the structured inspector is selectable/copyable via read-only text controls; this is presentation-only and does not change packet/session semantics;
- the current narrow layer model covers already-decoded facts such as Frame, Ethernet, VLAN, MPLS, ARP, IGMP, IPv4, IPv6, TCP, and UDP;
- the Frame layer should show packet index in file and, when selected-flow context is available, packet index within the selected flow;
- the Ethernet layer should expose source/destination MAC addresses and decoded EtherType text;
- MPLS should appear as one Summary layer per label between Ethernet/VLAN and the resolved inner IPv4/IPv6 layer, using the stable shared layer id `mpls` so repeated occurrences naturally map to `mpls#0`, `mpls#1`, and so on for expansion-state tracking;
- the IPv4 and IPv6 layers should expose conservative decoded header fields from selected-packet/on-demand parsing rather than open-time import work;
- when IPv4 options are present, the IPv4 layer should expose a nested `ipv4_options` child with overall length/raw bytes plus per-option child nodes in wire order; the first supported set includes EOL, NOP, RR, Timestamp, LSRR, SSRR, Router Alert, and unknown valid options, while malformed/truncated entries surface warning children and stop parsing conservatively;
- the TCP and UDP layers should expose conservative transport header fields from selected-packet/on-demand parsing, including header checksums;
- the TCP layer should expose raw sequence/acknowledgment numbers, header length, window, urgent pointer, and a nested `tcp_options` child when options are present;
- the `tcp_options` child should keep raw option bytes visible and may contain nested child nodes such as MSS, Window Scale, SACK Permitted, SACK, Timestamps, unknown options, and malformed/warning nodes;
- Packet Details Summary may append one ephemeral top-level `data` layer immediately after the effective terminal TCP or UDP layer when the selected packet contains captured transport payload bytes that are genuinely unclaimed by any supported child protocol;
- the effective terminal transport is tunnel-neutral and comes from one shared selected-packet model populated by existing top-level and supported nested dissection paths;
- the effective terminal transport may be the ordinary top-level TCP/UDP layer or a supported nested terminal inner TCP/UDP layer already exposed by selected-packet decoding; when multiple supported layers exist, the deepest supported terminal transport wins;
- tunnel-carrier UDP does not independently emit generic `data` when a supported child tunnel owns those bytes, and unsupported tunnel bodies remain deferred rather than being reparsed inside the Summary layer builder;
- an inner TCP ACK-only packet with zero terminal application payload must not emit `data`;
- TLS ownership for selected-packet Summary must validate the bounded record header, must not treat zero-length Handshake / Alert / ChangeCipherSpec headers as TLS-owned, and should suppress `data` for zero-length ApplicationData only when the selected-packet path already has confirmed TLS context;
- this `data` layer is selected-packet Summary only, stays packet-local, uses a bounded 32-byte preview, keeps full bytes in the Packet Details `Bytes` tab through the recognized outer packet-unit view or the fallback `Captured Packet` view plus protocol-level payload views, and does not affect ProtocolPath, flow identity, index format, import recognition, or Stream Summary behavior; generic Stream Data and unsupported L2/L3 or tunnel payload Data remain deferred;
- selected-packet QUIC preparation may also retain one bounded decrypted Initial plaintext artifact for future byte-level inspection, but that artifact stays packet-local, is not copied into Stream rows, and is not used as the semantic source of truth for current Summary layers;
- recognized encrypted or opaque protocol payload remains owned by that protocol and must not fall back to generic `data`;
- when structured layers are present, default expansion should open `Warnings` when present plus the final non-warning protocol layer, and frontends should remember user expansion state per protocol-chain signature for the current UI session;
- Qt, Tauri, and future CLI surfaces should continue converging on this shared layer list instead of relying mainly on frontend-local text reconstruction;
- Packet Details no longer expose a visible Protocol tab, and selected-stream rows no longer retain formatted `protocol_text`; explicit formatter/debug APIs may remain where they are intentionally used outside Stream row retention.
- Packet Details Summary now treats packet-local DNS and HTTP fields as authoritative structured input and must not rebuild those Summary fields by reparsing formatted protocol text.
- DHCP/BOOTP remains deferred in this stage because the current packet model still lacks one shared structured message view for Packet Details Summary.

### Bytes

Bytes should show one selected bounded byte view at a time.

Expected semantics:

- `Captured Packet` is the fallback replacement for the removed `Raw` packet preview and appears only when no complete safe outer protocol unit covers the captured packet bytes;
- when rich decoded Packet Details are unavailable but captured packet bytes are still readable, `Captured Packet` may remain fully available and must not be hidden solely because Summary is partial;
- for ordinary recognized packets, the selector starts with the actual recognized outer protocol unit, such as `Ethernet II Frame`, `IEEE 802.3 Frame`, `PPPoE Packet`, `PPP Packet`, `IPv4 Packet`, `TCP Segment`, `UDP Datagram`, `ARP Packet`, `ICMP Message`, `ICMPv6 Message`, `IGMP Message`, and existing QUIC packet/frame views;
- complete unit means protocol header plus bounded protocol payload;
- stable identity belongs to the protocol layer, not to the currently displayed range mode;
- the generic captured-packet root is suppressed whenever one recognized outer protocol-unit descriptor uses captured packet bytes, starts at offset `0`, and safely covers the full available captured packet range;
- the current UI always materializes `whole_unit`;
- a future UI pass may add `Whole Unit | Payload Only` without changing descriptor identities;
- when no recognized outer unit safely covers the full available captured range, `Captured Packet` remains visible as the root fallback and exposes only captured packet bytes rather than PCAP/PCAPNG container metadata;
- when an IPv6 payload-only range exists in the current backend contract, it starts at the authoritative upper-layer payload offset after any decoded IPv6 extension-header chain rather than immediately after the fixed 40-byte base header;
- packet-local DNS byte views now expose `DNS Message` as a semantic child of `UDP Datagram` when the current DNS analyzer already owns the transport payload authoritatively;
- packet-local DNS over TCP remains packet-local only: when the current parser recognizes one complete length-prefixed DNS message already present in the selected TCP payload, the `DNS Message` range excludes the 2-byte TCP DNS length prefix;
- whole-unit packet-backed carrier descriptors include their own protocol header, including `IEEE 802.3 Frame`, `LLC PDU`, `SNAP PDU`, `PBB Packet`, `PPPoE Packet`, `PPP Packet`, `VXLAN Packet`, `GRE Packet`, `EoIP Packet`, `Geneve Packet`, `GTP-U Message`, `AH Packet`, and `ESP Packet`;
- `IEEE 802.3 Frame` is selected from authoritative decode metadata rather than inferred in the UI layer; its whole-unit range begins at destination MAC, includes the 2-byte Length field, includes exactly the declared MAC client data extent, and excludes trailing MAC padding beyond the declared length; its payload-only range begins at LLC DSAP when present;
- LLC/SNAP hierarchy is explicit when the decode path classifies the link layer as 802.3: `IEEE 802.3 Frame -> LLC PDU -> SNAP PDU -> carried child`, while non-SNAP LLC remains `IEEE 802.3 Frame -> LLC PDU`; when declared 802.3 coverage is incomplete because trailing captured bytes fall outside the authoritative whole-unit range, the fallback root may remain as `Captured Packet -> IEEE 802.3 Frame -> ...`;
- PPPoE Session packet bytes now layer as `PPPoE Packet -> PPP Packet -> carried child` when the decode layer has an authoritative PPP Protocol field and bounded PPP information field; `PPP Packet` includes the PPP Protocol field in whole-unit mode and its payload-only range begins after the parsed Protocol field;
- PPPoE Discovery packets remain `PPPoE Packet` only and do not manufacture a false `PPP Packet` child;
- `802.1Q Encapsulation` whole-unit materialization begins at the VLAN TPID, includes TPID, TCI, the encapsulated EtherType/length field, and the complete bounded carried payload; its optional payload-only mode begins at the authoritative carried-protocol boundary;
- when a separate payload-only range remains meaningful, it stays an explicitly separate descriptor rather than being mislabeled as a whole packet;
- record-layer TLS over TCP now layers as `TCP Segment -> TLS Record -> TLS Handshake Message` when the current bounded TLS parser confirms ownership;
- packet-local byte views keep their normal label and do not carry a `Reassembled` suffix;
- byte views backed by bounded reconstructed owners keep one stable descriptor identity and surface `Reassembled` through structured assembly metadata and the display label;
- record-layer TLS over TCP may therefore appear either as packet-local `TCP Segment -> TLS Record -> TLS Handshake Message` or, when multiple contributing TCP segments are required, as `TLS Handshake Record (Reassembled)` with a reassembled handshake child;
- QUIC never invents a `TLS Record` layer: TLS over QUIC exposes only `TLS Handshake Message`;
- when one TLS handshake maps unambiguously to one CRYPTO data range, QUIC may layer as `CRYPTO Frame Data -> TLS Handshake Message`;
- when one TLS handshake spans multiple CRYPTO contributions, QUIC uses one bounded reconstructed `QUIC CRYPTO Stream (Reassembled)` owner attached to the selected Initial context and attaches the TLS handshake there rather than to one arbitrary frame; when one selected Initial packet owns the required contiguous prefix it may remain under the decrypted Initial plaintext, otherwise it may hang from the owning Initial packet context;
- when Summary classifies the effective terminal TCP or UDP application payload as unclaimed `Data`, Packet Details Bytes exposes exactly one `Data` descriptor as a semantic child of that same effective terminal transport;
- `Data` materializes the complete available packet-local unclaimed application payload from captured packet bytes, while Summary keeps its separate bounded preview;
- nested ownership remains terminal-transport-first: inner TCP or UDP `Data` suppresses any outer tunnel-carrier `Data`, and recognized DNS, TLS, QUIC, HTTP, or other supported child ownership suppresses `Data` entirely;
- `Data` does not expose a second payload-only mode because the whole unit is already the value itself, and zero-length payloads do not produce a `Data` descriptor;
- `Data` keeps one stable `data` identity per selected packet rather than deriving identity from a display label or preview text;
- the selector uses backend-provided stable ids and backend-provided descriptor order;
- only one selected view is materialized/formatted at a time;
- frontends preserve the exact previously selected stable id when the newly selected packet still exposes that same id;
- when the preserved id is unavailable, frontends fall back to the historical captured-packet stable id when that fallback descriptor is visible, then to the first available descriptor;
- frontends do not reconstruct hierarchy, ranges, or identities from offsets or display labels;
- formatted hex/ascii text remains bounded and deterministic;
- source-unavailable state remains explicit in index-only / no-source mode;
- no stale bytes remain visible after packet/open/selection changes.

Backend note for the current migration stage:

- selected-packet byte inspection now has a separate backend descriptor layer that is independent from Summary and Protocol presentation;
- the current pass now supports four owner kinds:
  - captured packet bytes loaded on demand through `CaptureSession::read_packet_data(...)`;
  - one selected-packet QUIC Initial plaintext owner when authenticated Initial decryption succeeds on the existing bounded QUIC path;
  - one bounded QUIC CRYPTO-prefix owner when existing QUIC/TLS handshake semantics already authorize a logical TLS handshake range that spans CRYPTO contributions;
  - one bounded reconstructed TLS-record owner when existing selected-packet TLS analysis already reconstructs a contributing TCP TLS record;
- descriptors carry stable non-localized protocol-layer identities, explicit parent relationships, one primary complete-unit range, and an optional payload-only range only where that second range is already authoritative; they do not retain per-view byte buffers or preformatted text;
- materialization and hex formatting happen on demand for one selected view at a time;
- the current pass covers protocol-unit defaults for the fallback `Captured Packet` root plus Ethernet II, IEEE 802.3, stacked VLAN encapsulations, LLC, SNAP, MPLS label-stack-and-payload units, PBB, PPPoE, PPP, ARP, IPv4, IPv6, TCP, UDP, SCTP, ICMP, ICMPv6, IGMP, VXLAN, inner Ethernet II, inner IEEE 802.3, and inner IPv4/IPv6/TCP/UDP/SCTP where production packet details already expose authoritative bounds;
- current PPP Packet support is limited to the already-authoritative PPPoE decode path with a 2-byte PPP Protocol field; Protocol Field Compression is not guessed in the presentation layer;
- Linux cooked SLL v1 and SLL2 packet-byte units now use authoritative cooked-header whole-unit and payload ranges for selected-packet byte materialization;
- semantic child layers may intentionally overlap their parent transport or carrier range when the child unit is independently authoritative, including `UDP Datagram -> DNS Message`, `TCP Segment -> TLS Record`, `TLS Record -> TLS Handshake Message`, and `CRYPTO Frame Data -> TLS Handshake Message`;
- overlapping parent and child ranges are expected because nested encapsulations intentionally retain both the carrier unit and the decoded child unit;
- duplicate suppression applies only to semantically equivalent descriptors; plain IP-in-IP does not manufacture an extra tunnel-payload view when only the nested IP payloads are authoritative;
- packet-backed nested carrier descriptors now use complete-unit selectors with optional payload-only materialization on the same stable id, rather than exposing misleading primary payload-only selectors; the remaining explicit value-oriented payload child views are `ESP Protected Payload`, `QUIC Initial Protected Payload`, and derived value views such as `CRYPTO Frame Data`;
- `ESP Packet` remains opaque and owns one child `ESP Protected Payload`; the child excludes SPI and Sequence Number and remains the explicit value-oriented protected-range selector;
- selected-packet TLS byte views reuse the same bounded selected-packet TLS analysis already used by Summary rather than running a second independent full-flow reconstruction pass;
- selected TCP packet policy is contribution-based: a selected packet shows only TLS records and handshake messages to which that packet contributes, and split TLS records use a bounded reconstructed owner instead of fabricating a fake contiguous captured range inside one packet;
- packet-local TLS records keep packet-backed ownership and normal labels, while split TLS records and their handshake children surface `Reassembled` plus contributing TCP-segment count from structured reconstruction metadata rather than from inferred lengths;
- complete packet-local TLS records use captured packet bytes directly, while split or bounded reconstructed TLS records and their handshake children use one reconstructed owner plus child ranges into that owner rather than per-record or per-handshake byte copies;
- encrypted or opaque TLS records such as `ApplicationData` remain TLS records even when no plaintext handshake child exists;
- when current metadata confirms TLS ownership but only a bounded partial TCP fragment is available, the descriptor remains the narrowest honest TLS unit, such as `TLS Record Fragment`, with complete/partial/truncated state derived from structured TLS lengths;
- DNS and TLS byte views remain packet-details-only in this stage; stream-item byte owners and stream-item application-unit byte selectors remain deferred;
- selected-packet QUIC byte inspection now also exposes:
  - captured QUIC envelope ranges as children of the captured `UDP Datagram`;
  - captured QUIC Initial protected-payload ranges only when the packet-number length and packet end are authoritative;
  - one derived `QUIC Initial Decrypted Payload` owner with child `QUIC Frame` and `CRYPTO Frame Data` ranges when authenticated Initial decryption succeeds;
- selected-packet byte inspection now also exposes one packet-backed `Data` descriptor when `prepare_selected_packet_summary(...)` has already classified the effective terminal application payload as complete, authoritative, and unclaimed by a supported child protocol;
- that `Data` descriptor reuses the same `PacketDataPresentation` ownership decision and the same effective transport payload provenance already used by Summary, keeps a stable `data` identity, and never falls back to the 32-byte Summary preview as its byte owner;
- QUIC envelope offsets retained by the byte-presentation layer are rebased exactly once from UDP-payload-relative provenance to captured-frame-relative byte offsets;
- the captured `QUIC Initial Protected Payload` contract starts immediately after the unprotected packet-number field and currently includes the AEAD authentication tag because that is the authoritative encrypted-payload extent already exposed by the selected-packet QUIC code path;
- derived QUIC frame offsets are relative to the decrypted Initial plaintext owner, while `CRYPTO` stream offsets remain logical QUIC metadata and are not reused as plaintext byte offsets;
- `CRYPTO Frame Data` views exclude the frame type and encoded offset/length varints and expose only the CRYPTO frame value bytes;
- QUIC TLS handshake views inherit their range from the same structured QUIC/TLS handshake model already used by Packet Summary; when one handshake spans multiple CRYPTO contributions, one bounded `QUIC CRYPTO Stream` descriptor becomes the handshake parent, may be attached either under the decrypted Initial plaintext or under the owning Initial packet context, and carries reassembled assembly metadata such as contributing CRYPTO-frame count;
- QUIC does not synthesize a TLS record header or record owner, and failed Initial decryption must not fabricate QUIC frame, `CRYPTO Frame Data`, `QUIC CRYPTO Stream`, or TLS handshake byte ownership;
- coalesced QUIC UDP datagrams retain one descriptor identity per envelope; derived Initial plaintext belongs only to its owning envelope and is never attached to neighboring `0-RTT`, `Handshake`, or `Protected payload` envelopes;
- failed Initial decryption may still retain the captured QUIC packet view and, when header-protection removal established an authoritative boundary, the captured protected-payload view, but it must not fabricate derived plaintext, QUIC frame, `CRYPTO Frame Data`, `QUIC CRYPTO Stream`, or TLS byte ownership;
- the retained QUIC Initial plaintext owner reuses the existing selected-packet QUIC plaintext artifact and is not copied into a second complete buffer solely for byte presentation;
- captured and derived owners are intentionally transparent to the UI once the selector has chosen a stable id;
- application protocols still deferred from Packet Details Bytes in this stage include packet-local HTTP message units and DHCP/BOOTP message units, because current packet presentation does not yet expose a single shared authoritative application-unit byte range for those protocols.
- Stream Item Details tabs remain unchanged in this pass; stream-item byte owners, packet-spanning HTTP message byte units, and long-lived QUIC derived owners remain deferred.

### Packet details state model

Frontends should distinguish:

- no packet selected;
- loading packet details;
- details loaded;
- byte-backed sections unavailable because source capture is missing;
- no payload available;
- truncated preview;
- details error.

### Stream-item details note

Qt currently reuses the details panel for stream-item inspection as well. That suggests a likely future shared concept:

- the right-hand details inspector is selection-driven;
- it may inspect either a packet or a stream item;
- only one selection context is active at a time.

That is a useful reference point, but stream-item details should remain an explicit follow-up item rather than an assumed finalized contract.

## Selected-Flow Stream View

The selected-flow stream view is a bounded, on-demand reconstruction for the currently selected flow only.

### Core behavior

Current Qt behavior establishes the intended contract:

- stream is selected-flow-only;
- stream is on-demand;
- stream is bounded;
- stream is ephemeral;
- stream is not persisted as part of open-time session state;
- stream must not be computed during capture open;
- stream must not be computed globally for all flows.

Current session/controller behavior already follows this model by reconstructing stream items only for a selected flow and only within bounded packet/item budgets.

### Expected stream item fields

Based on current Qt stream presentation, each stream item should expose:

- stream item index;
- direction;
- label / type / protocol-facing description;
- byte length;
- contributing packet count;
- source packet reference summary;
- constricted / quality indicator when present.
- selected-item-only Item Data through the details surface:
  - exact selected-item bytes when authoritative;
  - explicit unavailable / synthetic / stale state otherwise;
  - no protocol-level byte selector hierarchy.

Summary-specific contract notes:

- Stream Item Summary is the primary structured inspection surface for selected stream items.
- Summary must be produced from retained stream-item model fields, not by reparsing Stream labels, Protocol text, or formatted byte strings.
- Stream labels themselves should also be constructed from retained structured stream-item semantics rather than by parsing formatted protocol text.
- HTTP stream rows may keep display labels such as `HTTP Request` or `HTTP Gap`, but Summary semantics come from retained HTTP request/response/partial/gap metadata.
- TLS stream rows may keep display labels such as `TLS ClientHello`, but Summary semantics come from retained TLS semantic kind, parser context, and retained structured TLS record models.
- QUIC stream rows may keep display labels such as `QUIC Initial: CRYPTO`, but Summary semantics come from retained QUIC packet/frame/TLS-handshake presentation models.
- Generic and synthetic rows must expose explicit structured kind/state for payload, partial, or gap behavior rather than relying on label wording.
- `Item Data` remains the byte-ownership surface, and its availability, ownership, packet-local versus reassembled status, and source/provenance selection must come from retained structured stream-item semantics rather than from formatted protocol text.
- `StreamItemRow::protocol_text` is no longer retained. Flow-list `FlowRow::protocol_text` remains a separate live user-facing field outside the selected-stream-item semantic contract, and the Flows Protocol column remains unchanged.

Qt currently renders source-packet references in a compact user-facing form such as:

- `packet #6`
- `packets #6,#7`
- fallback count-based text when packet-local numbering is unavailable.

### Bounded window / load-more behavior

Current Qt behavior includes:

- initial bounded packet window;
- initial bounded stream item count;
- load-more action for stream view;
- message indicating when the stream was built only from the first N packets;
- message indicating when more packets can be scanned to extend the stream view.

Shared expectations:

- stream reconstruction quality/boundedness should be surfaced clearly;
- stream view may show item-count and packet-window state separately;
- `load more` extends bounded reconstruction for the selected flow only.

### Empty, loading, unavailable, and error states

Stream view should distinguish:

- no capture/index opened;
- no flow selected;
- loading stream view;
- stream loaded;
- no stream items available for the selected flow;
- stream unavailable because source capture is not attached;
- bounded/partial stream result;
- stream error state if one exists.

### Selection behavior

- Selecting a stream item makes it the active stream-item selection.
- Changing selected flow must clear stream-item selection and stream contents.
- Stream data must be cleared on new open, open failure, and filtered-away flow selection changes.

## Statistics / Overview View

Qt currently exposes a broader statistics surface than the current Tauri UI. The shared contract should at least preserve what Qt already shows and separate `basic overview` from `extended statistics`.

### Basic overview metrics

Current Qt summary bar shows:

- packet count;
- flow count;
- original bytes;
- captured bytes.

These are the minimum shared overview fields.

### Protocol and family summary

Current Qt protocol statistics show:

- transport-family breakdown:
  - TCP;
  - UDP;
  - Other;
- for each transport group:
  - flow count;
  - packet count;
  - captured bytes;
  - original bytes;
- IP family breakdown:
  - IPv4;
  - IPv6;
- for each IP family:
  - flow count;
  - packet count;
  - captured bytes;
  - original bytes.

### Protocol-hint summary

Qt now exposes the detected-protocol-hints table as an optional collapsible
Statistics section rather than an always-visible panel. The table itself keeps
the same row semantics:

- group:
  - Confirmed;
  - Possible;
  - Unknown;
- protocol / hint title;
- flow count;
- packet count;
- captured bytes;
- original bytes.

This section now also has a dedicated backend/frontend-neutral request path for
section-scoped loading. Qt and Tauri both request these rows lazily on first
eligible section expansion rather than carrying them through the eager
overview DTO.

For the current shared contract, canonical Statistics display formatting is
owned by shared C++ presentation helpers rather than frontend-local QML or
JavaScript:

- overview `captured bytes` / `original bytes` expose both raw numeric values
  and compact display text;
- Protocol Summary transport/family rows expose both raw byte counts and
  compact display text;
- detected-protocol-hints rows expose both raw counts/bytes and canonical
  `count (percent)` / `size (percent)` text;
- raw numeric fields remain available for sorting, charts, and future
  consumers.

### QUIC and TLS summary

Qt now exposes `QUIC and TLS` as one optional collapsible Statistics section
containing two side-by-side cards. The card contents remain protocol-specific:

- QUIC:
  - total flows;
  - with SNI;
  - without SNI;
  - version counts such as v1, draft-29, v2, unknown;
- TLS:
  - total flows;
  - with SNI;
  - without SNI;
  - TLS 1.2 count;
  - TLS 1.3 count;
  - unknown-version count.

The shared backend now also exposes a dedicated typed `QUIC and TLS` section
request that returns the two recognition models together while keeping them
semantically independent. One side may be empty without invalidating the
other. Qt and Tauri now load this section lazily instead of duplicating the
values in the eager overview DTO.

### Top talkers

Qt now exposes `Top Endpoints and Ports` as one optional collapsible
Statistics section containing the existing two top-talker panels:

- Top Endpoints
- Top Ports

Each panel shows:

- endpoint or port label;
- packet count;
- byte count.

These panels also support drill-down actions from statistics into flow filtering/navigation.

The shared backend now also exposes a dedicated typed request for `Top
Endpoints and Ports`. It reuses the existing bounded top-summary aggregation,
keeps the current limit/order semantics, and may reuse a per-capture cache for
the requested limit. Qt and Tauri now load these rows lazily instead of
duplicating them in the eager overview DTO.

### Flows by Packet Count

The shared backend now defines a presentation-neutral histogram for `Flows by
Packet Count`.

Semantic contract:

- the authoritative source is the finalized listed-flow packet count restored
  by capture import and index load;
- packet count is per flow across both directions;
- calculation is `O(number of listed flows)` with fixed-size bucket storage;
- one lazy per-capture calculation accumulates both:
  - flow count per packet-count bucket
  - original-byte totals per packet-count bucket;
- the model carries:
  - `total_flow_count`
  - `total_original_byte_count`
  - `maximum_bucket_flow_count`
  - `maximum_bucket_original_byte_count`
  - ordered semantic buckets;
- each bucket carries a stable bucket id plus inclusive lower/upper bounds and
  both:
  - the number of flows in that range
  - the summed original bytes for flows in that range;
- display labels are derived later by the frontend-neutral adapter rather than
  being the semantic source of truth.

Exact ordered buckets:

- `1`
- `2`
- `3-5`
- `6-10`
- `11-25`
- `26-50`
- `51-100`
- `101-250`
- `251-500`
- `501-1000`
- `1001-5000`
- `5001+`

Normal listed flows do not use a zero-packet bucket. If a listed zero-packet
flow is encountered, it is excluded from the normal bucket totals and counted
separately through explicit diagnostic counters for both flow count and
original bytes so the main histogram remains production-safe and semantically
honest.

Presentation contract:

- the bucket dimension remains packet count per flow;
- both Qt and Tauri expose two frontend-local display modes over the same
  cached histogram result:
  - `Flows`
  - `Original bytes`;
- `Flows` uses flow-count normalization and exact flow counts;
- `Original bytes` uses original-byte normalization and formatted original-byte
  totals;
- mode switching is presentation-only:
  - no second backend request
  - no second flow walk
  - no cache invalidation
  - no recalculation;
- default mode for each new capture is `Flows`.

### Packet Size Distribution

The shared backend now also defines a separate capture-wide `Packet Size
Distribution` model.

Semantic contract:

- the metric uses captured packet length:
  - `RawPcapPacket::captured_length` during capture import
  - persisted `PacketRef::captured_length` during index load;
- it counts every packet record successfully accepted by the current import
  pipeline, including:
  - recognized flow packets
  - unrecognized packets
  - decode-malformed packets
  - packets that never obtain a flow key;
- it does not count:
  - unreadable truncated tail bytes
  - incomplete packet records
  - PCAPNG metadata blocks
  - block padding
  - other non-packet records;
- accumulation happens during capture import and is retained with capture
  state;
- index load reconstructs the same result from persisted `PacketRef` metadata
  without reading packet bytes or reopening the source capture;
- section expansion is presentation-lazy only:
  - it requests a finalized retained DTO
  - it does not rescan packets or flows;
- the current PCAPNG unsupported-interface limitation remains explicit:
  - EPBs skipped before a `RawPcapPacket` is surfaced are not represented.

The semantic model carries:

- `total_packet_count`
- `maximum_bucket_packet_count`
- `maximum_captured_packet_length`
- 13 ordered fixed buckets with stable ids and inclusive bounds.

Exact ordered buckets:

- `0-63`
- `64-127`
- `128-255`
- `256-511`
- `512-1023`
- `1024-1399`
- `1400-1550`
- `1551-2499`
- `2500-5000`
- `5001-9000`
- `9001-16000`
- `16001-25000`
- `25001+`

Presentation contract:

- Qt and Tauri expose it as an optional collapsible Statistics section placed:
  - after `Protocol Summary`
  - after the conditional `Unrecognized Packets` block
  - before `Flows by Packet Count`;
- the section header summary is `<total_packet_count> packets`;
- the expanded body shows:
  - a short explanation that the metric covers imported captured packet lengths,
    including unrecognized packets
  - a maximum captured packet size line
  - all 13 rows with shared stable bucket ids, shared labels, normalized bars,
    and exact packet counts;
- the maximum value is the maximum captured packet length, not original length
  or decoded frame size.

### Section-scoped loading direction

Qt now keeps only the overview cards plus the transport/family Protocol Summary
always visible. These sections are optional, independently collapsible, and
loaded through typed per-capture requests:

- Packet Size Distribution
- Flows by Packet Count
- Protocol Path Tree
- Detected Protocol Hints
- QUIC and TLS
- Top Endpoints and Ports

Request contract for the Qt Statistics tab:

- a section request may start only when a capture is loaded, the Statistics tab
  is active, the section is expanded, and the section is still
  `not_requested` for the current capture;
- first expansion loads once for the current capture;
- collapse/reopen and Statistics-tab leave/return reuse the already prepared
  result;
- opening or closing a capture resets optional-section expansion, visible
  section state, and section request state to `not_requested`.

`Protocol Path` remains a separate independently mode-cached lazy request path.
Qt keeps the current mode selector plus `Show flows`, `Expand all`, and
`Collapse all` controls inside that collapsible section. Switching modes while
the section is collapsed defers the request until the section is expanded
again; switching modes while expanded reuses an existing mode cache or loads
that mode once.

### Statistics state expectations

Statistics view should distinguish:

- no capture/index opened;
- statistics available;
- empty/no-data state where applicable.

### Currently not fully defined for shared contract

The following are visible in Qt but may still need a later contract pass for exact shared DTO shape:

- statistics mode selection details;
- top-talkers drill-down semantics for future CLI;
- whether all extended statistics should be available in minimal frontends or only in richer UIs.

## Analysis View

Qt currently implements a selected-flow analysis workspace rather than only a placeholder.

### Triggering behavior

Current Qt behavior:

- analysis is selected-flow-driven;
- manually entering the Analysis tab with a selected flow uses the current selected-flow context;
- entering the Analysis tab with a selected flow triggers refresh;
- analysis is not computed during capture open;
- analysis refresh is tied to selected-flow context and active analysis tab.

### Expected analysis characteristics

- on-demand;
- selected-flow-only;
- not global across all flows;
- not part of open-time processing.

### Current visible analysis content

Qt currently exposes a broad analysis surface including:

- analysis flow list in the left pane;
- selected-flow analysis details in the right pane;
- duration / timeline metrics;
- endpoint summary;
- total packets / total bytes / captured bytes;
- packets-per-second and bytes-per-second metrics;
- direction split metrics;
- average / min / max packet size metrics;
- inter-arrival metrics;
- protocol hint / service / protocol-version text;
- TCP control counts when applicable;
- burst and idle-gap metrics;
- rate graph availability / status / window text;
- histogram data:
  - inter-arrival;
  - packet size;
- sequence preview rows;
- analysis-sequence export action.

### Contract note

This document records Qt as the current reference for analysis presentation, but analysis is the least mature shared contract area for non-Qt frontends. It should be treated as reference behavior plus follow-up questions, not as an immediate DTO freeze.

## Export / Actions

Visible UI actions influence the shared presentation contract because they shape what state and metadata must be available to frontends.

### Open / session actions

- Open capture in Fast mode
- Open capture in Deep mode
- Open index
- Save index
- Attach / locate source capture when the original source is missing

### Flow actions

- Copy selected-flow Wireshark filter
- Send selected flow to Analysis
- Export current flow
- Export selected flows
- Export unselected flows
- Smart Export

### Selected-flow browsing actions

- Load more packets
- Load more stream items

### Analysis actions

- Open selected flow in Analysis
- Export flow analysis sequence CSV

### Descriptive contract note

The contract does not require every frontend to expose every action immediately. It does require that:

- actions depend on clearly defined session / selection / source-availability state;
- unavailable actions should be explainable through shared state semantics;
- export and attach-source workflows should use the same backend-facing meaning across frontends.

## Field Ownership And Stabilization Table

| Area | Contract item | Preferred owner | Status | Initial decision | Follow-up |
|---|---|---|---|---|---|
| Shell | open state | app/session + frontend-neutral DTO | stable | shared state semantics, frontend-specific rendering | decide final DTO naming |
| Shell | source availability | app/session + frontend-neutral DTO | stable | explicit source-attached / unavailable / expected-path state | unify wording later |
| Flows | flow list fields | frontend-neutral DTO | stable | structured facts first | align Qt/Tauri/CLI naming |
| Flows | flow filtering | frontend controller/model | frontend-only | keep frontend-side for now | standardize matching fields only |
| Flows | flow sorting | frontend controller/model | frontend-only | keep frontend-side for now | standardize sortable fields only |
| Flows | Wireshark display filter | frontend-neutral DTO or frontend assembly from DTO fields | candidate | allow shared display string if semantics are shared | decide backend-vs-frontend ownership |
| Packets | selected-flow packet rows | frontend-neutral DTO | stable | structured row DTO is a good target | align row-number semantics |
| Packets | packet pagination / load-more | app/session + frontend controller/model | stable | bounded selected-flow-only behavior is shared | refine common status metadata |
| Inspector | packet details summary | frontend-neutral DTO | candidate | move toward structured summary fields | avoid overfreezing final text layout |
| Inspector | raw preview | frontend-neutral DTO | candidate | bounded preview plus truncated/unavailable metadata | decide text-only vs structured preview shape |
| Inspector | payload preview | frontend-neutral DTO | candidate | bounded preview plus no-payload/truncated/unavailable metadata | align payload label semantics |
| Inspector | protocol details text | frontend-neutral DTO | stable | shared product text is acceptable here | keep deep analysis out of scope |
| Stream | stream item rows | frontend-neutral DTO | candidate | align with current Qt-visible stream fields | refine source-packet-reference structure |
| Stream | stream load-more / boundedness | app/session + frontend-neutral DTO | stable | bounded selected-flow-only semantics are shared | expose packet-window metadata consistently |
| Stream | stream item details | frontend-neutral DTO | active | `Summary / Item Data` backed by one selected-item materialization only; formatted protocol text is not retained per row | keep byte ownership in backend; avoid per-row eager text |
| Statistics | counters | app/session + frontend-neutral DTO | stable | structured counters first | keep frontend formatting local |
| Statistics | grouping / labels | frontend rendering or optional shared display semantics | needs decision | do not force into core | revisit after CLI requirements are clearer |
| Analysis | analysis workspace | app/session + frontend-specific presentation | deferred | treat Qt as reference behavior | revisit after flows/packets/details/stream stabilize |
| Actions | export / action availability | app/session | stable | session should own factual availability | standardize reason/unavailable metadata later |

## DTO Stabilization Plan

This is a staged plan for future code follow-ups. It is descriptive only and does not imply immediate implementation work.

### Stage 1: Clarify Flow DTO and Packet Row DTO fields

Why it matters:

- flows and packet rows are already the most shared surfaces across Qt, Tauri, and future CLI;
- these are the least controversial DTOs to stabilize first.

What should change later:

- document and implement explicit structured flow fields;
- document and implement explicit structured packet-row fields;
- align identifier semantics and row-number semantics.

What should not change:

- no change to core packet-processing behavior;
- no move of filtering/sorting into core;
- no change to open-time processing.

### Stage 2: Introduce or refine PacketInspector DTO

Why it matters:

- packet details are currently one of the most Qt-shaped presentation areas;
- Tauri and CLI will both benefit from a shared shape.

What should change later:

- add structured summary fields;
- add bounded raw preview metadata;
- add bounded payload preview metadata;
- carry explicit truncated / unavailable / no-payload state.

What should not change:

- no unbounded byte loading;
- no new deep protocol analysis implied;
- no conversion of core into a UI formatting layer.

### Stage 3: Refine Stream DTO

Why it matters:

- stream is already selected-flow-only and bounded in backend/session behavior;
- the remaining divergence is mostly presentation shape.

What should change later:

- align stream item fields with current Qt-visible semantics;
- add source packet references;
- add bounded packet-window metadata;
- add constricted / quality flags where relevant.

What should not change:

- stream must stay selected-flow-only;
- stream must stay on-demand;
- stream must stay bounded and ephemeral.

### Stage 4: Refine SourceAvailabilityState and common unavailable/error semantics

Why it matters:

- source-unavailable behavior affects packet details, stream, export, and source-attachment flows;
- today the semantics are shared, but the wording is scattered.

What should change later:

- define one common source-availability shape;
- define shared unavailable-state metadata used by Qt, Tauri, and CLI.

What should not change:

- no hiding of index-only mode;
- no fake raw/payload/stream data when source bytes are unavailable.

### Stage 5: Align Tauri UI with the shared DTO contract

Why it matters:

- Tauri is already close enough to benefit from a shared contract;
- this reduces Qt/Tauri drift.

What should change later:

- align Tauri field names and presentation semantics with stabilized DTOs;
- remove local shape drift where possible.

What should not change:

- no broad rewrite;
- no forced Qt pixel parity.

### Stage 6: Design CLI commands using the same DTO contract

Why it matters:

- CLI should not invent a third semantic model;
- CLI is a good test of which fields are truly shared versus view-specific.

What should change later:

- design CLI commands around shared DTOs for flows, packets, details, and stream;
- decide where CLI should emit structured fields, display text, or both.

What should not change:

- no requirement that CLI mimic Qt layout;
- no dependence on frontend-only visual concepts.

### Stage 7: Revisit Statistics and Analysis DTOs

Why it matters:

- statistics and analysis are the richest and least-stabilized surfaces;
- they should be revisited after the lower-risk DTOs are settled.

What should change later:

- decide which statistics are core shared contract versus optional rich-UI sections;
- decide what part of analysis becomes shared DTO shape.

What should not change:

- do not freeze the entire Qt analysis workspace too early;
- do not move analysis work into open-time processing.

## Backend / Session DTO Implications

This section is intentionally forward-looking. These are candidate frontend-neutral DTO improvements suggested by the contract. They are not part of this documentation-only change.

### Flow DTO candidates

- explicit address family field;
- explicit protocol field;
- explicit protocol-hint field;
- explicit service field;
- explicit address A / port A / address B / port B fields;
- explicit fragmentation indicator / fragmented-packet-count fields;
- packet count and byte count as structured numeric values;
- optional derived Wireshark-filter fields or enough structured data to generate them consistently.

### Packet list DTO candidates

- explicit row number within selected flow;
- packet index;
- direction display value or direction enum;
- formatted timestamp text and/or structured timestamp;
- captured length;
- original length;
- payload length;
- TCP flags text;
- fragmentation / retransmission marker fields.

### Packet details DTO candidates

- structured summary fields for packet metadata;
- bounded raw preview text plus metadata:
  - truncated;
  - unavailable;
  - source-required;
- bounded payload preview text plus metadata:
  - truncated;
  - unavailable;
  - no payload;
- protocol details text;
- payload tab title / protocol-specific payload label when already known.

### Stream DTO candidates

- stream item index;
- direction;
- item label / type;
- byte count;
- contributing packet count;
- source packet references;
- constricted / quality indicator;
- packet-window and load-more metadata aligned with Qt presentation.

### Shared shell / state DTO candidates

- explicit open state / open source kind;
- source-availability and expected-source-path state;
- common unavailable/error/source-state semantics;
- explicit selected-flow / selected-packet / selected-stream-item identifiers for frontend coordination.

## Do Not Standardize Yet

The following areas should remain deliberately flexible for now:

- exact visual layout;
- colors and badges;
- exact wording of most UI status text;
- full Analysis DTO shape;
- full Export workflow parity;
- stream-item-to-packet navigation behavior;
- whether all statistics sections are required in CLI;
- exact compact-vs-comfortable density decisions;
- exact tab/panel arrangement outside the shared semantic contract.

## Open Questions

### Identifiers and display numbering

- Should every frontend expose both stable identifiers and user-facing display numbers explicitly?
- Should `flow_display_number` always be `flow_index + 1`, or remain a presentation choice?
- Should stream rows expose both `stream_item_index` and `stream_item_display_number`?

### DTO vs frontend formatting

- How much display formatting should live in frontend-neutral DTOs versus UI code?
- Should packet summary remain formatted text, become fully structured, or support both?
- Should statistics grouping labels such as `Confirmed`, `Possible`, and `Unknown` be shared semantics or frontend-local wording?

### CLI output format

- Should future CLI output expose structured fields, display-ready text, or both?
- Which fields are required for machine-readable JSON versus human-readable text output?

### Wireshark filter generation

- Should the backend provide the final display filter string, or only structured endpoint/protocol fields?
- If the final filter string is shared, where should protocol/family-specific formatting rules live?

### Packet inspector structure

- Should the packet inspector contract stabilize around structured summary fields plus bounded preview text?
- Which fields belong in shared packet-summary structure versus protocol details text?

### Stream item details and navigation

- Should stream-item selection drive the same inspector contract as packet selection in all frontends?
- Should stream items always point back to source packets in a standardized way?
- How much stream-item detail is worth standardizing before packet-inspector DTOs settle?

### Statistics scope

- Which parts of Qt's extended statistics are required for the future CLI versus optional?
- Should top-talkers drill-down semantics be part of the shared contract or remain UI-specific?

### Analysis maturity

- Which parts of Qt's analysis workspace should be considered stable shared contract now?
- Which parts should remain reference-only until flows/packets/details/stream DTOs stabilize?

### Source-unavailable behavior

- How should index-only mode and detached-source mode be normalized across all frontends?
- Which unavailable messages should remain frontend wording and which should become shared semantic states?

