# UI Presentation Contract

## Purpose

This document defines the intended user-facing presentation contract for Pcap Flow Lab across:

- the current Qt UI;
- the experimental Tauri UI spike;
- future CLI commands that expose session and inspection data;
- possible future frontend-neutral DTO cleanup.

Qt is currently the reference implementation because it exposes the broadest surface area today, but the contract described here is not intended to be Qt-specific. The goal is to converge on shared presentation semantics and shared backend-facing data expectations even if different frontends render them differently.

This document is intentionally presentation-oriented. It describes what the product should display, what state transitions matter to users, and what kinds of backend/session data frontends should request.

## Scope And Non-Goals

### In scope

- Defining the shared concepts visible in the application shell.
- Defining the expected fields shown in the flows list, selected-flow packets list, packet inspector, selected-flow stream view, statistics view, and analysis workspace.
- Describing expected loading, empty, unavailable, and error states.
- Highlighting which fields should ideally come from structured backend/session DTOs versus which can remain frontend formatting.

### Out of scope

- Immediate implementation changes in Qt, Tauri, session, or DTO layers.
- Pixel-perfect layout, visual styling, spacing, or theming.
- Moving deep analysis into capture-open processing.
- Changing reassembly, stream, persistence, export, or source-attachment policy.
- Defining final CLI UX or command syntax.

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
- address A;
- port A;
- address B;
- port B;
- fragmentation indicator;
- packet count;
- byte count.

### Current Qt presentation notes

- Flow index is displayed as a 1-based row identifier tied to the session flow index.
- Address family is shown as `IPv4` or `IPv6`.
- Protocol hint is presentation-formatted:
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
- missing/unsupported filter data should result in “no filter available”, not a fabricated filter.

Whether the final filter text is fully assembled in the backend or assembled in the frontend from structured fields remains a follow-up decision.

### Empty, loading, and error states

Flows view should clearly distinguish:

- no capture or index opened;
- flow list loading / applying session;
- no flows available;
- filter has no matches;
- general flow-list error state if one exists.

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
- Raw
- Payload
  - protocol-specific payload labels may be used when already available, for example `UDP Payload`
- Protocol

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

### Raw

Raw should show a bounded raw packet byte preview.

Expected semantics:

- bounded preview only;
- hex/ascii-oriented presentation;
- no unbounded byte loading;
- source-unavailable state in index-only / no-source mode;
- no stale bytes after flow/packet/open changes.

If the backend returns formatted preview text, frontends may render that faithfully rather than reformat it aggressively.

### Payload

Payload should show a bounded transport payload preview.

Expected semantics:

- preview can be empty when the packet has no transport payload;
- preview can be truncated;
- preview can be unavailable when source bytes are unavailable;
- no unbounded payload loading;
- protocol-specific payload tab label may be used when existing inspection paths already provide it.

### Protocol

Protocol should show the currently available protocol details text/summary for the selected packet.

Expected semantics:

- current protocol-specific details text only;
- no implication that new deep protocol analysis must be added;
- clear “no protocol details” / unavailable state when appropriate.

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
- “load more” extends bounded reconstruction for the selected flow only.

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

Qt currently exposes a broader statistics surface than the current Tauri spike. The shared contract should at least preserve what Qt already shows and separate “basic overview” from “extended statistics”.

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

Qt currently shows a detected-protocol-hints table with:

- group:
  - Confirmed;
  - Possible;
  - Unknown;
- protocol/hint title;
- flow count;
- packet count;
- captured bytes;
- original bytes.

### QUIC and TLS summary

Qt also exposes protocol-specific summary sections for:

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

### Top talkers

Qt currently exposes top-talker panels:

- Top Endpoints
- Top Ports

Each panel shows:

- endpoint or port label;
- packet count;
- byte count.

These panels also support drill-down actions from statistics into flow filtering/navigation.

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
- `Send flow to Analysis` moves the selected flow into the Analysis tab;
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
- duration/timeline metrics;
- endpoint summary;
- total packets / total bytes / captured bytes;
- packets-per-second and bytes-per-second metrics;
- direction split metrics;
- average/min/max packet size metrics;
- inter-arrival metrics;
- protocol hint / service / protocol-version text;
- TCP control counts when applicable;
- burst and idle-gap metrics;
- rate graph availability/status/window text;
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

- actions depend on clearly defined session/selection/source-availability state;
- unavailable actions should be explainable through shared state semantics;
- export and attach-source workflows should use the same backend-facing meaning across frontends.

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
- item label/type;
- byte count;
- contributing packet count;
- source packet references;
- constricted/quality indicator;
- packet-window and load-more metadata aligned with Qt presentation.

### Shared shell / state DTO candidates

- explicit open state / open source kind;
- source-availability and expected-source-path state;
- common unavailable/error/source-state semantics;
- explicit selected-flow / selected-packet / selected-stream-item identifiers for frontend coordination.

## Open Questions

- Exact shared column order and naming:
  - should all frontends preserve Qt column names exactly, or only field semantics?
- CLI shape:
  - should future CLI output expose structured fields, display-ready text, or both?
- Formatting boundary:
  - how much display formatting should live in frontend-neutral DTOs versus UI code?
- Wireshark filter generation:
  - should the backend provide the final display filter string, or only structured endpoint/protocol fields?
- Packet details formatting:
  - should Summary become a fully structured field grid across all frontends, or remain formatted text plus structured metadata?
- Stream-item details:
  - should stream-item selection drive the same inspector contract as packet selection in all frontends?
- Stream-to-packet navigation:
  - should stream items always point back to source packets in a standardized way?
- Statistics scope:
  - which parts of Qt’s extended statistics are required for the future CLI versus optional?
- Source-unavailable behavior:
  - how should index-only mode and detached-source mode be normalized across all frontends?
- Analysis contract:
  - which parts of Qt’s analysis workspace should be considered stable shared contract now, and which remain exploratory/reference-only?

