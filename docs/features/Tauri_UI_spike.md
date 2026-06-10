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
- No claim that the current Tauri shell is already CSP-hardened or detached from the global Tauri bridge.

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
- `export_smart_flows(path, flow_indices, options)`
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
- Qt-like top session shell with:
  - `Open Capture...`
  - Fast/Deep mode selector
  - right-side active-session display
- native Open File dialog as the primary open workflow
- real shared-backend open progress and cancel via `OpenContext`
- `File -> Save Index` through the existing session/index path
- `Flow -> Export Current Flow` through the existing flow-export/session path
- `Flow -> Export Selected Flows` through the existing batch flow-export/session path
- `Flow -> Export Unselected Flows` through the existing batch flow-export/session path
- `Flow -> Smart Export...` through the existing smart-export/session path
- `View -> Settings` for the currently shared safe runtime settings slice
- source capture locate/attach workflow for index-backed or source-missing sessions
- open mode handling
- grouped source-availability warning behavior in the shell
- partial/truncated capture warning banner when a capture opens partially
- dev-only memory diagnostics gated by `PFL_TAURI_MEMORY_LOG=1`
- active-tab-only heavy rendering for `Flows`, `Statistics`, and `Analysis`
- frontend-only virtualization/windowing for the main Flows table and Analysis flow list
- full loaded flow DTO arrays are still held in JS; virtualization currently reduces DOM/render pressure only
- the previous visible 500-row cap / `Show more` behavior has been removed for these two large flow lists
- selected-flow packet loading now gives immediate loading feedback, stays bounded to the current batch with append-only `Load More`, and keeps Stream / Analysis lazy
- selected-flow packet and stream loading for very large flows remains a known optimization area
- compact desktop-style layout with internal panel scrolling
- frontend-only top-level tabs: `Flows`, `Analysis`, `Statistics`
- Qt-aligned top-level tab order and runtime-only adjustable splitters for the Flows and Analysis workspaces
- explicit shell open states: `idle`, `opening`, `opened`, `error`

## Current Flows capability

The `Flows` tab now supports:

- frontend-only case-insensitive filtering over already loaded flow DTOs
- frontend-only sorting over already loaded flow DTOs
- separate checked-flow selection state for batch-oriented workflows
- user-facing 1-based flow numbering while keeping stable backend `flow_index`
- address family and fragmentation state from shared flow DTOs
- conservative shared Wireshark display filter text plus copy
- selected-flow packet loading over the existing backend `offset / limit` API with bounded append-only `Load More`
- the initial selected-flow packet batch is intentionally small and bounded for responsiveness
- packet list columns now align more closely with Qt:
  - `#`
  - `Direction`
  - `Time`
  - `Captured`
  - `Payload`
  - `Flags`
  - `Marker`
- direction chips and TCP flag highlighting in the packet list
- Qt-like packet marker display for existing shared packet semantics such as `Suspected retransmission`
- packet details tabs:
  - `Summary`
  - `Raw`
  - `Payload`
  - `Protocol`
- the `Summary` tab now follows Qt more closely with a compact text-style packet summary block instead of metadata cards
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
  - `Flow -> Export Unselected Flows`
  - `Flow -> Smart Export...`
  - `View -> About`
  - `View -> Settings`

## Current Stream capability

The `Stream` tab now supports:

- selected-flow-only stream loading
- lazy/on-demand loading
- bounded packet-window and item budgets
- `Load More`
- Qt-like directional stream item cards
- left/right alignment by direction
- selectable stream items
- basic selected stream-item details
- shared structured source-packet references and constricted notes in the DTO path
- stream reconstruction can recover after a valid source-capture attach
- selected-flow stream latency on very large flows remains a known optimization area

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
- not reloaded on ordinary flow clicks unless the `Analysis` tab is active
- sequence CSV export is also selected-flow-only and reuses the existing analysis/session path

Open workflow:

- the primary shell action is `Open Capture...`
- the active session area now mirrors Qt more closely:
  - `Active session: No active session`
  - `Active session: PCAP: <path>`
  - `Active session: Index: <path>`
- capture/index open now surfaces real shared-backend progress instead of a Tauri-only placeholder
- cancel during open reuses the existing shared session/open cancellation path

`View -> Settings`:

- is now enabled in Tauri
- is intentionally runtime-only
- currently exposes the safe existing settings already present in the shared app/session path:
  - `HTTP path as service hint when Host is missing`
  - `Use possible TLS/QUIC`
  - `Show Wireshark filter for selected flow`
  - `Validate IPv4/TCP/UDP checksums for selected packet`
- applies the Wireshark-filter visibility toggle immediately after `OK`
- applies packet checksum validation only to selected packet details when readable source bytes are available

`Flow -> Export Current Flow`:

- is selected-flow-only
- reuses the existing session export path
- writes `.pcap`
- requires the original source capture to be readable
- coexists with frontend-local checked-flow selection and the now-wired selected / unselected / smart batch export workflows

`Flow -> Export Selected Flows`:

- uses the checked-flow set, not the active selected flow
- reuses the existing session batch export path
- writes `.pcap`
- requires the original source capture to be readable
- keeps checked-flow state intact after success, cancel, or failure

`Flow -> Export Unselected Flows`:

- uses the inverse of the checked-flow set over the full loaded flow list
- is not limited to the currently visible filtered rows
- reuses the existing session batch export path
- writes `.pcap`
- requires the original source capture to be readable
- keeps checked-flow state intact after success, cancel, or failure

`Flow -> Smart Export...`:

- reuses the existing smart-export session path and product semantics
- supports current / selected / unselected / all flow scopes
- supports:
  - all packets
  - first N packets
  - first M original bytes
  - include last packet
  - include every K-th packet after the base prefix
- supports:
  - single output file
  - separate file per flow
- writes `.pcap` for single-file mode
- writes one PCAP per flow plus `flows_manifest.csv` for separate-file-per-flow mode
- requires the original source capture to be readable
- currently keeps the existing session, selected flow, checked-flow state, packets, stream, statistics, and analysis intact after success, cancel, or failure
- currently does not mirror Qt's per-flow smart-export progress/cancel UI; it reuses the same session path without the richer Qt progress surface

The source-attach workflow:

- reuses existing session validation
- keeps the current session open on attach failure
- updates grouped source-availability state in place
- makes byte-backed packet details and stream available on the next explicit reload when the chosen source capture is valid

The dev-only memory diagnostics workflow:

- is opt-in through `PFL_TAURI_MEMORY_LOG=1`
- appends `tauri_memory_log.csv`
- logs repeated-open / load / render phases together with frontend row counts
- logs virtual window start/end values and whether Flows / Analysis list virtualization is active
- logs selected-flow packet/stream/analysis request timing phases when diagnostics are enabled
- is intended for manual leak/retention investigation only
- does not change product behavior when disabled

Current Tauri shell hardening constraints:

- `src-tauri/tauri.conf.json` still keeps `withGlobalTauri: true` because the current plain HTML/JS spike depends on the injected global bridge.
- `src-tauri/tauri.conf.json` still keeps `security.csp: null` for the current experimental shell; tightening CSP safely is still a separate hardening pass because the current plain HTML/JS shell depends on the injected global bridge and runtime-verified DOM/style behavior.

## Current limitations and remaining Qt gaps

The Tauri spike is still not full Qt parity. The main remaining gaps are:

- save/open index workflow polish
- the Tauri shell no longer exposes the previous visible typed-path action in the primary toolbar
- settings remain runtime-only; there is still no shared non-Qt persistence path for Tauri
- packet inspector still intentionally simpler than Qt even though it now has `Summary / Raw / Payload / Protocol`
- packet details display polish remains incomplete compared with Qt
- packet details should eventually converge on a shared structured decoded-layer DTO rather than frontend-local text/layout reconstruction
- stream-to-packet navigation is still missing
- statistics still miss Qt-style percentage formatting and deeper drill-down/navigation behavior
- Analysis still misses:
  - rate graph
  - richer charts
  - fuller Qt analysis workspace parity
- selected-flow packet and stream latency on very large flows remains a known issue
- shared backend packet-byte read behavior for very large flows remains a known optimization area
- packet virtualization, stream virtualization, and backend paging/filtering/sorting for very large captures are still deferred
- memory diagnostics exist, but they are investigative only; they are not a substitute for a future large-capture performance / virtualization pass
- frontend virtualization is now the first mitigation layer, but backend paging/filtering/sorting is still deferred for very large captures

## Current deferred items

- Save/open index workflow polish
- settings persistence and any broader Settings/preferences parity
- Stream-to-packet navigation
- Qt-style percentage formatting in Statistics
- richer Statistics drill-down/navigation
- Analysis rate graph
- fuller Analysis parity
- selected-flow packet/stream latency work for very large flows
- shared packet-byte read optimization in the backend/session path
- deeper large-capture memory and DTO-size optimization if needed

## Next priorities after merge

1. Tauri/UI parity polish versus Qt, especially compact layout and presentation details
2. Selected-flow packet and stream latency investigation for very large flows
3. Packet details display polish
4. Shared backend packet-byte read optimization in the session/core path
5. Deeper memory optimization only if needed after virtualization, such as narrower DTO slices or backend paging/filter/sort
6. Save/open index workflow polish and runtime settings persistence after the core large-flow path is healthier

## Notes

- The existing Qt UI remains the primary product UI.
- The Tauri path is still an experimental parallel frontend spike.
- The current spike now covers most primary desktop workflows, but should still be treated as an incremental evaluation path rather than a committed UI migration.
