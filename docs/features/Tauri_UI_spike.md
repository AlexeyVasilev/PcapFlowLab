# RFC: Tauri UI Spike

## Status
Draft, but now substantially beyond the original bring-up slice.

## Motivation

Pcap Flow Lab already has a layered architecture with a C++ core, application/session layer, and a Qt desktop UI. The Tauri spike evaluates whether a modern webview-based desktop frontend can sit on top of the same backend/session layer without changing packet-processing behavior.

## Goals

- Evaluate Tauri as an experimental desktop frontend.
- Keep the existing C++ core and session logic.
- Define and exercise a frontend-neutral adapter boundary.
- Validate a realistic selected-flow analyzer workflow across flows, packets, stream, statistics, and first-slice analysis.

## Non-goals

- No full UI migration.
- No replacement of the Qt UI.
- No core parser redesign.
- No packaging/release hardening as part of the spike itself.
- No promise of full Qt parity in one pass.

## Current architectural fit

The current project already supports:

- packet-oriented fast open
- selected-flow-only deeper inspection
- grouped source-availability facts
- ephemeral, bounded stream analysis
- selected-flow analysis results from the session layer
- a separate application/session layer above the core

This makes the project suitable for a frontend experiment that requests richer data on demand instead of moving capture-processing logic into the UI.

## Backend / adapter direction

The spike now relies on a small frontend-neutral adapter over `CaptureSession`.

Current adapter-backed operations include:

- `open_capture(path, open_mode)`
- `save_index(path)`
- `export_current_flow(path)`
- `export_selected_flows(path, flow_indices)`
- `get_overview()`
- `get_flows()`
- `select_flow(flow_index)`
- `get_selected_flow_packets(offset, limit)`
- `get_selected_flow_packet_details(packet_index)`
- `get_selected_flow_stream(packet_window, item_limit)`
- `get_selected_flow_analysis()`

The existing Qt UI remains the reference implementation for richer presentation semantics, but the Tauri path now exercises a meaningful shared DTO surface for:

- flows
- packet rows
- packet details
- source availability
- stream items
- overview/statistics
- first-slice selected-flow analysis

## Current Tauri shell status

The current Tauri spike now supports:

- compact Qt-like `File / Flow / View` menu shell
- native Open File dialog as the primary open workflow
- typed-path manual fallback
- `File -> Save Index` through the existing session/index path
- `Flow -> Export Current Flow` through the existing flow-export/session path
- source capture locate/attach workflow for index-backed or source-missing sessions
- open mode handling
- grouped source-availability warning behavior in the shell
- compact desktop-style layout with internal panel scrolling
- frontend-only top-level tabs: `Flows`, `Statistics`, `Analysis`
- explicit shell open states: `idle`, `opening`, `opened`, `error`

## Current Flows capability

The `Flows` tab now supports:

- frontend-only case-insensitive filtering over already loaded flow DTOs
- frontend-only sorting over already loaded flow DTOs
- separate checked-flow selection state for batch-oriented workflows
- user-facing 1-based flow numbering while keeping stable backend `flow_index`
- address family and fragmentation state from shared flow DTOs
- conservative shared Wireshark display filter text plus copy
- selected-flow packet pagination over the existing backend `offset / limit` API
- compact packet markers for IP fragmentation and suspected TCP retransmission
- packet details tabs:
  - `Summary`
  - `Raw`
  - `Payload`
  - `Protocol`
- byte-backed packet details can recover after a valid source-capture attach
- a compact checked-flow status bar shown only when one or more flows are checked
- the menu shell currently wires:
  - `File -> Open Capture (Fast)`
  - `File -> Open Capture (Deep)`
  - `File -> Open Index`
  - `File -> Save Index`
  - `File -> Exit`
  - `Flow -> Export Current Flow`
  - `Flow -> Export Selected Flows`
  - `View -> About`

## Current Stream capability

The `Stream` tab now supports:

- selected-flow-only stream loading
- lazy/on-demand loading
- bounded packet-window and item budgets
- `Load More`
- selectable stream rows
- basic selected stream-item details
- shared structured source-packet references and constricted notes in the DTO path
- stream reconstruction can recover after a valid source-capture attach

## Current Statistics capability

The `Statistics` tab now supports:

- overview cards
- transport summary
- IP family summary
- detected protocol hints
- QUIC recognition
- TLS recognition
- top endpoints
- top ports
- drill-down into the existing `Flows` filter from:
  - protocol hints
  - top endpoints
  - top ports

## Current Analysis capability

The `Analysis` tab now supports a first selected-flow-only, on-demand analysis workspace:

- left-side Analysis Flows list built from already loaded flow DTOs
- right-side selected-flow analysis details
- flow summary
- protocol panel
- traffic totals
- direction split
- derived metrics
- timing and size
- burst / idle summary
- TCP controls when available
- packet size histogram
- inter-arrival histogram
- sequence preview
- selected-flow sequence CSV export
- `Open in Flows`

Analysis remains:

- selected-flow-only
- on-demand
- not computed during capture open
- not computed globally for all flows
- sequence CSV export is also selected-flow-only and reuses the existing analysis/session path

`Flow -> Export Current Flow`:

- is selected-flow-only
- reuses the existing session export path
- writes `.pcap`
- requires the original source capture to be readable
- coexists with frontend-local checked-flow selection; `Export Unselected Flows` and `Smart Export` remain deferred

`Flow -> Export Selected Flows`:

- uses the checked-flow set, not the active selected flow
- reuses the existing session batch export path
- writes `.pcap`
- requires the original source capture to be readable
- keeps checked-flow state intact after success, cancel, or failure

The source-attach workflow:

- reuses existing session validation
- keeps the current session open on attach failure
- updates grouped source-availability state in place
- makes byte-backed packet details and stream available on the next explicit reload when the chosen source capture is valid

## Current limitations and remaining Qt gaps

The Tauri spike is still not full Qt parity. The main remaining gaps are:

- export workflows
- batch checked-flow export workflows beyond `Flow -> Export Current Flow` and `Flow -> Export Selected Flows`
- save/open index workflow polish
- settings/preferences
- packet inspector still intentionally simpler than Qt even though it now has `Summary / Raw / Payload / Protocol`
- stream-to-packet navigation is still missing
- statistics still miss Qt-style percentage formatting and deeper drill-down/navigation behavior
- Analysis still misses:
  - rate graph
  - richer charts
  - fuller Qt analysis workspace parity
- large-capture performance work, virtualization, and more advanced pagination strategies are still unaddressed

## Current deferred items

- Export workflows beyond `Flow -> Export Current Flow`, `Flow -> Export Selected Flows`, `File -> Save Index`, and selected-flow Analysis sequence CSV export
- `Export Unselected Flows` and `Smart Export` still remain deferred even though Tauri now tracks checked-flow selection in the Flows table
- Save/open index workflow polish
- Settings/preferences
- Stream-to-packet navigation
- Qt-style percentage formatting in Statistics
- richer Statistics drill-down/navigation
- Analysis rate graph
- fuller Analysis parity
- large-capture performance and virtualization pass

## Recommended next priorities

1. Export workflows beyond `Flow -> Export Current Flow`, `Flow -> Export Selected Flows`, `Save Index`, and selected-flow Analysis sequence CSV
2. Save/open index workflow polish
3. Settings/preferences
4. Performance pass for large captures, including virtualization/pagination where needed
5. Analysis export and rate graph after core Tauri workflows stabilize
6. CLI design after the frontend-neutral DTO surface settles

## Notes

- The existing Qt UI remains the primary product UI.
- The Tauri path is still an experimental parallel frontend spike.
- The current spike has moved well beyond the original bring-up, but should still be treated as an incremental evaluation path rather than a committed UI migration.
