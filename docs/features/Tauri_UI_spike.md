# Tauri UI Spike

## Status

Implemented experimental frontend design / evolution document.

The Tauri work began as a frontend spike and evolved into a meaningful
alternative desktop frontend over the shared C++ backend/session layer.

Qt remains the reference desktop UI.
Tauri remains experimental.

Current shared UI semantics are defined canonically in:

- [../ui/presentation_contract.md](../ui/presentation_contract.md)
- [../ui/frontend_dto_mapping.md](../ui/frontend_dto_mapping.md)
- [../ui/tauri_qt_parity_audit.md](../ui/tauri_qt_parity_audit.md)
- [../protocols/protocol_support.md](../protocols/protocol_support.md)

This document is retained primarily for Tauri-specific evolution history,
architecture decisions, experimental frontend constraints, and implementation
context. It is not the canonical current Qt/Tauri presentation contract.

## Motivation

Pcap Flow Lab already has a layered architecture with a C++ core, application/session layer, and a Qt desktop UI. The experimental Tauri UI validates that a modern webview-based desktop frontend can sit on top of the same backend/session layer without changing packet-processing behavior.

Current shared protocol-detection and inspection coverage is documented in
[protocol_support.md](../protocols/protocol_support.md).

## Goals

- Evaluate Tauri as an experimental desktop frontend.
- Keep the existing C++ core and session logic.
- Define and exercise a frontend-neutral adapter boundary.
- Validate a realistic selected-flow desktop workflow across flows, packets,
  stream, statistics, and analysis.

## Non-goals

- No full UI migration.
- No replacement of the Qt UI.
- No core parser redesign.
- No packaging/release hardening as part of this experimental UI path.
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

The Tauri UI relies on the shared `FrontendSessionAdapter` /
`FrontendSessionAdapterBridge` boundary over `CaptureSession`.

The adapter surface has grown substantially beyond the original bring-up slice.
Rather than treating a short method list here as exhaustive, the important
current capability groups are:

- capture/index opening and source-availability state
- source attach and index save
- settings exchange/update
- flow queries and flow export workflows
- Smart Export workflows
- Packet Details and packet-byte materialization/export
- Stream and Stream Item Details / Item Data
- Statistics and Protocol Path DTOs
- selected-flow Analysis and sequence export
- supported-protocol catalog exposure

Qt remains the richer reference desktop UI in several presentation/workflow
areas, but the Tauri path now exercises a meaningful shared DTO/presentation
surface instead of a narrow first-slice adapter.

## Current experimental status

The current Tauri UI supports the major desktop workflow areas below while
remaining an experimental frontend:

- compact Qt-like `File / Flow / View / Help` menu shell
- `Help -> About` dialog aligned more closely with the Qt About content, but labeled for `Tauri`
- Qt-like top session shell with:
  - `Open Capture...`
  - Fast/Deep mode selector
  - right-side active-session display
  - separate `Source PCAP` line for index-backed sessions
- native Open File dialog as the primary open workflow
- real shared-backend open progress and cancel via `OpenContext`
- `File -> Save Index` through the existing session/index path
- `Flow -> Export Current Flow` through the existing flow-export/session path
- `Flow -> Export Selected Flows` through the existing batch flow-export/session path
- `Flow -> Export Unselected Flows` through the existing batch flow-export/session path
- `Flow -> Export All Flows Info to CSV...` through the shared flow-manifest CSV/session path
- `Flow -> Smart Export...` through the existing smart-export/session path
- `View -> Settings` for the current shared runtime-safe settings slice
- source capture locate/attach workflow for index-backed or source-missing sessions
- open mode handling
- grouped source-availability warning behavior in the shell
- partial/truncated capture warning banner when a capture opens partially
- dev-only memory diagnostics gated by `PFL_TAURI_MEMORY_LOG=1`
- active-tab-only heavy rendering for `Flows`, `Statistics`, and `Analysis`
- frontend-only virtualization/windowing for the main Flows table and Analysis flow list
- full loaded flow DTO arrays are still held in JS; virtualization currently reduces DOM/render pressure only
- the previous visible 500-row cap / `Show more` behavior has been removed for these two large flow lists
- selected-flow packet loading now gives immediate loading feedback, stays bounded to the current batch with append-only `Load More`, keeps Stream / Analysis lazy, and shows a simpler `Showing N of Total packets` count label
- selected-flow packet and stream loading for very large flows remains a known optimization area
- Fast-mode lazy QUIC service hints now refresh back into the selected flow row after flow selection, matching Qt's on-demand selected-flow hint enrichment without global QUIC scanning
- compact desktop-style layout with internal panel scrolling
- generated cross-platform Tauri icon assets from a canonical local source icon, including Linux PNG bundle icons
- frontend-only top-level tabs: `Flows`, `Analysis`, `Statistics`
- Qt-aligned top-level tab order and runtime-only adjustable splitters for the Flows and Analysis workspaces
- explicit shell open states: `idle`, `opening`, `opened`, `error`

For detailed current UI semantics, refer to the canonical presentation and
mapping docs rather than treating the lists below as the authority for shared
product behavior.

## Implemented areas

This document keeps a compact Tauri-oriented inventory of major implemented
areas. It is intentionally not a complete current user manual.

### Flows

The `Flows` tab now supports:

- frontend-only case-insensitive filtering over already loaded flow DTOs
- frontend-only sorting over already loaded flow DTOs
- separate checked-flow selection state for batch-oriented workflows
- user-facing 1-based flow numbering while keeping stable backend `flow_index`
- address family and fragmentation state from shared flow DTOs
- compact visible `Endpoint A` / `Endpoint B` columns in the flow table instead of separate address/port columns
- endpoint formatting aligned with Qt:
  - IPv4 with port: `address : port`
  - IPv4 without port: `address`
  - IPv6 with port: `[address] : port`
  - IPv6 without port: `address`
  - missing/zero/invalid port: address only
- endpoint address/port are treated as key identifiers and should stay visible in the table rather than relying on tooltip-only display
- conservative shared Wireshark display filter text plus copy
- selected-flow packet loading over the existing backend `offset / limit` API with bounded append-only `Load More`
- the initial selected-flow packet batch is intentionally small and bounded for responsiveness
- the lower selected-flow `Packets` / `Stream` controls, packet-count status, and `Load More` action now sit in one compact toolbar-style row
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
  - `Bytes`
- selected Stream Item Details tabs:
  - `Summary`
  - `Item Data`
- the `Summary` tab now follows Qt more closely with a compact text-style packet summary block instead of metadata cards
- the top-shell `Open Capture...` action now uses a lighter desktop-style treatment closer to the Qt shell instead of a heavy filled primary button
- the `Bytes` tab now shows one selected packet-byte view on demand rather than a preview-only display
- Packet Details and Stream Item Details mode selectors now use compact tab styling instead of button styling
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
  - `Flow -> Export All Flows Info to CSV...`
  - `Flow -> Smart Export...`
  - `Help -> About`
  - `View -> Settings`

### Stream

The `Stream` tab now supports:

- selected-flow-only stream loading
- lazy/on-demand loading
- bounded packet-window and item budgets
- `Load More`
- Qt-like directional stream item cards
- left/right alignment by direction
- selectable stream items
- shared ARP stream items for selected ARP flows, one packet per item
- Qt-like selected stream-item details with:
  - compact header/title block
  - `Summary / Item Data` tabs
  - bounded item-data preview when authoritative bytes are available
- shared structured source-packet references and constricted notes in the DTO path
- stream reconstruction can recover after a valid source-capture attach
- selected-flow stream latency on very large flows remains a known optimization area

### Statistics

The `Statistics` tab now supports:

- overview cards
- transport summary
- IP family summary
- optional `Unrecognized Packets` summary block sourced from retained session/index metadata and hidden when the count is zero
- optional `Packet Size Distribution` section sourced from retained import/index metadata
- detected protocol hints
- QUIC recognition
- TLS recognition
- top endpoints
- top ports
- drill-down into the existing `Flows` filter from:
  - protocol hints
  - top endpoints
  - top ports

Backend/API note:

- Tauri now matches the Qt Statistics section contract:
  - overview cards plus `Transport` / `Family` summaries remain always visible
  - six optional sections start collapsed for each capture
  - first eligible expansion issues the dedicated request once per capture
  - collapse/reopen and Statistics-tab return reuse the cached result
  - capture replacement clears expansion and per-section cached results
- `Packet Size Distribution` is separate from the selected-flow Analysis packet-size histogram:
  - it uses captured packet length
  - it includes recognized, unrecognized, and decode-malformed imported packets
  - it excludes unreadable truncated tail bytes
  - import performs the accumulation and index load reconstructs it from persisted `PacketRef::captured_length`
  - opening the section transports only the finalized DTO and renders it
  - unsupported-interface PCAPNG EPBs skipped before packet surfacing are not represented
- `Flows by Packet Count` keeps its existing packet-count buckets but now offers
  frontend-local `Flows` / `Original bytes` display modes over the same cached
  histogram payload
- changing that histogram mode is presentation-only and does not trigger a
  second backend request or a second flow walk
- the shared backend now also provides dedicated typed requests for:
  - Packet Size Distribution
  - Flows by Packet Count
  - Detected Protocol Hints
  - QUIC and TLS
  - Top Endpoints and Ports
- overview byte cards and Protocol Summary byte columns now reuse shared C++
  compact formatting
- `Detected Protocol Hints` now reuses shared C++ count/byte-plus-percentage
  formatting instead of JavaScript-side calculations
- Tauri overview no longer duplicates these optional-section payloads
- Protocol Path remains on its separate lazy request/cache path

### Analysis

The `Analysis` tab supports a selected-flow-only, on-demand analysis workspace:

- left-side Analysis Flows list built from already loaded flow DTOs
- Analysis Flows `Packets` and `Bytes` columns now match Qt-style plain integer formatting in that table
- right-side selected-flow analysis details ordered closer to Qt
- overview with Qt-like richer `Protocol: transport (hint)` display when a meaningful hint exists
- protocol panel with QUIC/TLS-specific rows and TCP control counts folded into that panel when applicable
- derived metrics and burst / idle summary in a shared row on wide layouts
- Qt-like rate graph with `Data/s` / `Packets/s` and `A->B` / `B->A` / `Both` toggles, rendered from shared selected-flow analysis samples
- directional
- packet size histogram
- inter-arrival histogram
- sequence preview
- selected-flow sequence CSV export
- `Open in Flows`
- right-side Analysis presentation is now closer to Qt in typography, spacing, and compact label/value layout
- Burst / Idle Summary now uses a one-column Qt-like layout, and Directional is rendered more compactly
- the rate graph data comes from shared selected-flow analysis data, not Tauri-side sample generation

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
- index-backed sessions now also show `Source PCAP: <path>` separately, or a compact unavailable/not-attached state when the source capture is not currently readable
- the visible Tauri app title no longer says `Spike`
- capture/index open now surfaces real shared-backend progress instead of a Tauri-only placeholder
- cancel during open reuses the existing shared session/open cancellation path
- redundant `Opened capture:` / `Opened index:` success lines are intentionally omitted because the active-session area already carries that information

### Settings

`View -> Settings`:

- is enabled in Tauri
- uses staged dialog state like Qt
- `OK` commits and `Cancel` discards draft state
- is intentionally runtime-only
- is organized into:
  - `View & Inspection`
  - `Capture Processing`
- currently exposes the safe existing settings already present in the shared app/session path, including the runtime-only presentation toggles:
  - `Use possible TLS/QUIC`
  - `Show Wireshark filter for selected flow`
  - `Show Protocol Path column in the flow table`
  - `Show fragmented packet count column in the flow table` (default off)
  - `Validate IPv4/TCP/UDP checksums for selected packet`
  - `HTTP path as service hint when Host is missing`
  - `Ignore VLAN and MPLS layers when grouping flows`
  - `Ignore GTP-U TEIDs when grouping inner flows`
- applies the Wireshark-filter visibility toggle immediately after `OK`
- applies packet checksum validation only to selected packet details when readable source bytes are available
- capture-processing grouping settings apply on the next raw import/reopen
- committed runtime settings do not reinterpret an already opened index

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
- supports:
  - current flow
  - selected flows
  - unselected flows
  - all flows
  - matching current filter
  - not matching current filter
  - unrecognized packets
- supports:
  - all packets
  - first N packets
  - first M original bytes
  - include last packet
  - include every K-th packet after the base prefix
- supports:
  - single output file
  - separate file per flow
- `Unrecognized packets` is exported as one packet-set target and does not allow separate-file-per-flow mode
- writes `.pcap` for single-file mode
- writes one PCAP per flow plus `flows_manifest.csv` for separate-file-per-flow mode
- requires the original source capture to be readable
- currently keeps the existing session, selected flow, checked-flow state, packets, stream, statistics, and analysis intact after success, cancel, or failure
- Qt single-file Smart Export now has async/progress/cancel in the desktop UI, but Tauri Smart Export still reuses one-shot invoke/session paths without detailed packet-level progress or cancellation
- Tauri currently shows only busy/status-level Smart Export feedback, and this limitation applies to both flow-based Smart Export and `Unrecognized packets`

`Flow -> Export All Flows Info to CSV...`:

- reuses the shared backend flow-manifest CSV writer rather than duplicating CSV logic in JS/Rust
- opens a native Save dialog with `flows_manifest.csv` as the default file name
- exports all current session flows, including `protocol_path`, even when the shell skips eager flow-row loading for very large sessions
- intentionally omits Smart Export specific columns such as `file_name` and `exported_*`

Follow-up: add async Smart Export progress/cancel support to the Tauri spike, likely using the same start/poll/cancel pattern already used for capture opening. This should cover both flow-based Smart Export and Unrecognized packets Smart Export.

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

### Experimental/frontend constraints

Current Tauri shell hardening constraints:

- `src-tauri/tauri.conf.json` still keeps `withGlobalTauri: true` because the current plain HTML/JS shell depends on the injected global bridge.
- `src-tauri/tauri.conf.json` still keeps `security.csp: null` for the current experimental shell; tightening CSP safely is still a separate hardening pass because the current plain HTML/JS shell depends on the injected global bridge and runtime-verified DOM/style behavior.

## Remaining experimental limitations worth preserving

The Tauri UI is now functionally close to Qt for primary workflows, but it is still not full Qt parity. The main remaining gaps are:

- save/open index workflow polish
- the Tauri shell no longer exposes the previous visible typed-path action in the primary toolbar
- settings remain runtime-only; there is still no shared non-Qt persistence path for Tauri
- the shared runtime settings slice now includes both `Ignore VLAN and MPLS layers when grouping flows` and `Ignore GTP-U TEIDs when grouping inner flows`, and the Tauri shell mirrors the same reopen-required status plus the same raw-import and index-loaded informational grouping banners as Qt
- packet inspector still intentionally simpler than Qt even though it now has
  `Summary / Bytes`
- packet details display polish remains incomplete compared with Qt
- packet details should eventually converge on a shared structured decoded-layer DTO rather than frontend-local text/layout reconstruction
- stream-to-packet navigation is still missing
- stream item details are now much closer to Qt, but some protocol-specific
  formatting/helper paths still remain Qt-only
- statistics still miss some deeper drill-down/navigation behavior compared with Qt
- Analysis still misses:
  - richer charts
  - fuller Qt analysis workspace parity
- selected-flow packet and stream latency on very large flows remains a known issue
- shared backend packet-byte read behavior for very large flows remains a known optimization area
- very large sessions now keep the async open progress/cancel path, overview, and statistics available, but the shell skips eager full `get_flows()` loading above `250,000` flows to avoid hanging on multi-million-flow captures or very large indexes
- packet virtualization, stream virtualization, and backend paging/filtering/sorting for very large captures are still deferred
- memory diagnostics exist, but they are investigative only; they are not a substitute for a future large-capture performance / virtualization pass
- frontend virtualization is now the first mitigation layer, but backend
  paging/filtering/sorting is still deferred for very large captures

## Historical/deferred follow-up themes

- Save/open index workflow polish
- settings persistence and any broader Settings/preferences parity
- Stream-to-packet navigation
- richer Statistics drill-down/navigation
- fuller Analysis parity
- analysis rate-graph presentation polish versus Qt
- selected-flow packet/stream latency work for very large flows
- shared packet-byte read optimization in the backend/session path
- deeper large-capture memory and DTO-size optimization if needed

## Example later priorities from this evolution stage

1. Tauri/UI parity polish versus Qt, especially compact layout and presentation details
2. Selected-flow packet and stream latency investigation for very large flows
3. Packet details display polish
4. Shared backend packet-byte read optimization in the session/core path
5. Deeper memory optimization only if needed after virtualization, such as narrower DTO slices or backend paging/filter/sort
6. Save/open index workflow polish and runtime settings persistence after the core large-flow path is healthier

## Notes

- The existing Qt UI remains the primary product UI.
- The Tauri UI remains experimental, even though it now covers most primary desktop workflows.
- The Tauri path should still be treated as an incremental evaluation frontend rather than a committed UI migration.
- The canonical Tauri icon source is `experimental/tauri-ui-spike/app-icon.png`; regenerate `experimental/tauri-ui-spike/src-tauri/icons/` with `cargo tauri icon app-icon.png`.
