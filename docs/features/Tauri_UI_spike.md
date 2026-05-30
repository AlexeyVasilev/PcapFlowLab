# RFC: Tauri UI Spike

## Status
Draft

## Motivation

Pcap Flow Lab already has a layered architecture with a C++ core, application/session layer, and an optional Qt Quick desktop UI. The goal of this spike is to evaluate whether a modern webview-based desktop frontend can be added without changing the packet-processing core.

## Goals

- Evaluate Tauri as an experimental desktop frontend
- Keep the existing C++ core and session logic
- Define a small frontend-facing API boundary
- Validate a minimal user workflow:
  - open capture
  - show summary
  - show flow list
  - select a flow
  - show packet list
  - optionally show a simple stream list

## Non-goals

- No full UI migration
- No Smart Export UI in this spike
- No full packet details / protocol panes
- No packaging/release work for the Tauri build
- No core parser redesign
- No replacement of the existing Qt UI

## Current architectural fit

The current project already supports:
- packet-oriented fast open
- selected-flow-only deeper inspection
- ephemeral, bounded stream analysis
- a separate application/session layer above the core

This makes the project suitable for a frontend experiment that requests data on demand instead of owning capture-processing logic in the UI.

## Proposed approach

### Backend
Add a thin frontend adapter layer over the current session API.

Initial commands:
- open_capture(path)
- get_summary()
- get_flows()
- select_flow(flow_id)
- get_selected_flow_packets()
- get_selected_flow_stream()

### Frontend
Build a minimal Tauri UI with:
- file picker
- summary panel
- flow list
- packet list
- optional stream list

### IPC model
Use Tauri v2 commands for request/response operations.
Use events only where async status notifications become useful.

## Risks

- Current Qt-facing controller/model layer may not map directly to a frontend-neutral API
- Selected-flow operations may need explicit async/loading state handling
- Packaging will become more complex if this grows beyond a spike

## Success criteria

The spike is successful if it can:
1. open a capture
2. show summary
3. show flows
4. select a flow
5. show packet list
6. do all of the above without changing core packet-processing logic

## Exit criteria

Stop the spike if:
- too much logic is trapped inside Qt-specific controller/model code
- the required backend boundary becomes too invasive
- packaging/runtime complexity outweighs UI benefits

## Implementation addendum

Current boundary observations:

- `CaptureSession` already exposes most of the useful read-side operations for a frontend: open, summary, flow list, flow packets, and bounded stream items.
- `MainController` is not just a transport layer. It currently mixes session calls with Qt progress state, selected-flow state, source-capture handling, packet/stream pagination, and Q_PROPERTY-driven derived state.
- `FlowListModel`, `PacketListModel`, `StreamListModel`, and `PacketDetailsViewModel` are QML-facing presentation adapters and should stay Qt-specific.

Recommended frontend-facing API for the first spike:

- `open_capture(path, open_mode)`
- `get_overview()`
- `get_flows()`
- `select_flow(flow_index)`
- `get_selected_flow_packets(offset, limit)`

Optional later API:

- `get_selected_flow_stream(packet_window, item_limit)`

Recommended implementation strategy:

- add a very small frontend-neutral adapter over `CaptureSession`
- let that adapter own selected-flow state and DTO shaping
- do not expose Qt models or `MainController` directly to Tauri

Current implementation status:

- a first backend-facing adapter layer now exists for:
  - `open_capture(path, open_mode)`
  - `get_overview()`
  - `get_flows()`
  - `select_flow(flow_index)`
  - `get_selected_flow_packets(offset, limit)`
- a minimal Tauri scaffold now exists under `experimental/tauri-ui-spike/`
- the first wired commands are:
  - `open_capture`
  - `get_overview`
  - `get_flows`
  - `select_flow`
  - `get_selected_flow_packets`
- the current Tauri frontend now covers overview + flows + selected-flow packets + a basic selected-flow stream tab
- stream remains intentionally limited to a bounded, selected-flow-only slice in the current spike

UI direction note:

- the existing Qt UI remains the primary product UI for now
- the Tauri path is still an experimental parallel frontend spike

Current frontend-shell status:

- the Tauri shell now has explicit open states: idle, opening, opened, and error
- the shell uses a compact top session bar plus frontend-only main tabs: Flows, Statistics, and Analysis
- the long vertically stacked page has been replaced with a viewport-oriented desktop layout
- the current shell has had a compact density pass to move it closer to a desktop analyzer and away from a card-heavy web layout
- the open workflow clears stale overview/flow/packet state before each new open attempt
- the flow table now supports a frontend-only case-insensitive filter over the loaded flow DTOs
- the flow table now also supports frontend-only sorting over the already loaded flow DTOs
- the flow table now shows a user-facing 1-based flow number while keeping stable backend `flow_index` internally
- the current flow table now also surfaces address family and fragmentation state from the shared flow DTO
- flow selection is stable and visually highlighted in the flow table
- the selected flow now exposes a conservative Wireshark display filter string from the shared flow DTO plus best-effort clipboard copy
- selected-flow packets now page through the existing `offset` / `limit` backend API
- the packet table now surfaces compact markers for IP fragmentation and suspected TCP retransmission using existing packet-row DTO fields
- a small grouped frontend-neutral source-availability state now backs Tauri shell warnings plus packet-details / stream unavailable fallbacks
- a basic selected-flow Stream tab can now query bounded stream items on demand for the active flow only
- the Stream tab now keeps shared structured source-packet references and constricted notes in its DTO path while rendering a compact selectable stream list
- stream rows are now selectable in the Tauri Stream tab and drive a basic Selected Stream Item Details view in the right-hand inspector area
- selected packets can now be inspected through a small packet-details panel backed by the frontend-neutral adapter
- selected packet inspection is now organized as compact Summary / Raw / Payload / Protocol tabs inside the Tauri details panel
- the packet-details panel now consumes shared packet-inspector DTO fields for the panel title, protocol-specific payload tab title, and explicit no-payload metadata
- packet selection resets on open, flow change, packet-page change, and open failure to avoid stale detail state
- the Flows tab keeps flows on top and shows packets plus selected-packet details side by side in the lower area
- the lower-left Flows workspace now has Packets and Stream tabs; Stream remains lazy, bounded, and selected-flow-only
- the Statistics tab now shows basic overview cards plus compact transport, IP family, protocol-hint, QUIC, TLS, top-endpoint, and top-port summary sections from the frontend-neutral overview DTO
- statistics rows for protocol hints, top endpoints, and top ports can now drill down into the existing Flows tab filter
- the Analysis tab now includes its own compact Analysis Flows list on the left plus a first compact selected-flow analysis slice on the right
- the current shell keeps a typed path as a manual fallback while Browse / attach-source workflows remain deferred for a later pass
- the current shell now supports a native Open File dialog as the primary desktop open workflow
- the typed path remains available as a compact manual fallback

Current packet-details limitations:

- the Tauri packet-details panel is intentionally basic and does not aim for full Qt packet-details parity yet
- raw and payload previews are bounded to small preview windows
- byte-backed details can be unavailable in index-only sessions or when the original source capture cannot be read
- source-availability facts are now grouped in the frontend-neutral adapter for Tauri, but Qt still uses existing controller/view-model placeholders
- the Raw tab only exposes a bounded preview through the existing session inspection path; it is not a full raw-byte viewer

Current stream limitations:

- the Tauri Stream tab is intentionally basic and does not try to reproduce the full Qt stream presentation
- selecting a stream item does not yet navigate to packet details or source packets
- stream items are loaded on demand for the selected flow only
- stream reconstruction stays bounded by packet-window and item budgets instead of attempting unbounded reconstruction

Current analysis limitations:

- the current Tauri Analysis tab is selected-flow-only and loads on demand; it does not compute analysis during capture open
- the first Tauri Analysis slice only covers compact flow summary, totals, direction split, timing/size metrics, and basic TCP control counts
- charts, histograms, sequence preview, export, and the richer Qt analysis workspace remain deferred

Current statistics limitations:

- statistics drill-down actions and Qt-style percentage formatting remain deferred
- the Tauri Statistics tab still does not implement the richer Qt top-talker drill-down behavior
- statistics drill-down currently reuses the frontend flow filter only; it does not yet implement dedicated endpoint/port drill-down actions or packet navigation

Current flow-filter / Wireshark-filter limitations:

- the flow filter is frontend-only and only searches across fields already present in the loaded flow DTOs
- when a filter hides the selected flow, the Tauri shell clears the visible flow/packet/details selection instead of trying to preserve hidden selection state
- the Wireshark display filter is generated conservatively from current DTO fields and does not aim for full Qt parity yet

Recommended first spike scope:

1. open capture
2. show summary/overview
3. show flow list
4. select a flow
5. show selected-flow packet list

Stream should be a follow-up slice after the packet-list adapter is stable, because the current stream path still depends on controller-owned packet-window and cache orchestration.

Current open-workflow notes:

- native file picking now uses Tauri's dialog path with filters for `*.pcap`, `*.pcapng`, `*.idx`, and `*.pflidx`
- the same backend open path is still used after file selection, so capture/index detection behavior does not change
