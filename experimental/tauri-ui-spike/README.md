# Tauri UI Spike

This directory contains the experimental Tauri frontend for Pcap Flow Lab.

## Current scope

Implemented slice:

- compact Qt-like `File / Flow / View` menu shell
- native Open File dialog as the primary open workflow
- typed path as a compact manual fallback
- `File -> Save Index` through the existing session/index path
- `Flow -> Export Current Flow` through the existing session flow-export path
- `Flow -> Export Selected Flows` through the existing session batch flow-export path
- `Flow -> Export Unselected Flows` through the existing session batch flow-export path
- `Flow -> Smart Export...` through the existing session smart-export path
- locate/attach source capture for index-backed or source-missing sessions
- dev-only memory diagnostics gated by `PFL_TAURI_MEMORY_LOG=1`
- active-tab-only heavy rendering for `Flows`, `Statistics`, and `Analysis`
- frontend-only virtualization/windowing for the main Flows table and Analysis flow list
- full loaded flow DTO arrays are still held in JS; virtualization currently reduces DOM/render pressure only
- the previous visible 500-row cap / `Show more` behavior has been removed for these two large flow lists
- open mode handling
- grouped source-availability warning behavior
- frontend-only top-level tabs for `Flows`, `Statistics`, and `Analysis`
- compact desktop-style viewport layout with internal panel scrolling
- frontend-neutral `Flows` workflow:
  - filtering
  - sorting
  - separate checked-flow selection state for batch-oriented workflows
  - Wireshark filter display and copy
  - selected-flow packets
  - packet markers for fragmentation and suspected retransmission
  - packet details tabs: `Summary / Raw / Payload / Protocol`
- selected-flow `Stream` workflow:
  - selected-flow-only
  - lazy/on-demand
  - bounded
  - `Load More`
  - selectable stream items
  - basic selected stream-item details
- richer `Statistics` workflow:
  - overview cards
  - transport summary
  - IP family summary
  - detected protocol hints
  - QUIC/TLS recognition
  - top endpoints / top ports
  - drill-down into the existing `Flows` filter
- first selected-flow `Analysis` workflow:
  - left-side Analysis Flows list built from already loaded flow DTOs
  - selected-flow-only, on-demand analysis details on the right
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

## Current behavior

- The spike now uses a native Open File dialog as the primary open workflow.
- The shell now includes a compact Qt-like menu bar with `File`, `Flow`, and `View`.
- The typed capture/index path remains available as a compact manual fallback.
- `File -> Open Capture (Fast/Deep)` and `File -> Open Index` reuse the existing open path with native dialogs.
- `File -> Save Index` reuses the existing session/index save path and a native Save dialog with `.idx` default suffix.
- `Flow -> Export Current Flow` reuses the existing session flow-export path and a native Save dialog with `.pcap` default suffix.
- `Flow -> Export Selected Flows` reuses the existing session batch flow-export path, the checked-flow set, and the same native `.pcap` Save dialog behavior.
- `Flow -> Export Unselected Flows` reuses the existing session batch flow-export path, the inverse of checked-flow selection over the full loaded flow list, and the same native `.pcap` Save dialog behavior.
- `Flow -> Smart Export...` reuses the existing smart-export session path and a compact Tauri dialog that mirrors the existing flow-scope, base-selection, and output-mode semantics.
- `Flow -> Export Current Flow` is selected-flow-only and requires the original source capture to be readable.
- `Flow -> Export Selected Flows` uses checked-flow selection rather than the active selected flow and also requires the original source capture to be readable.
- `Flow -> Export Unselected Flows` uses the unchecked remainder of the loaded flow list and also requires the original source capture to be readable.
- `Flow -> Smart Export...` also requires the original source capture to be readable and currently supports:
  - current / selected / unselected / all scopes
  - single-file `.pcap` export
  - separate-file-per-flow export to a chosen folder
  - the existing Smart Export retention rules
- The current shell keeps open mode handling and grouped source-availability warnings in the compact top session area.
- When byte-backed inspection is unavailable, the shell can locate and attach the original source capture through a native picker.
- Attach-source reuses existing session validation and keeps the current session open if the chosen capture does not match.
- The shell uses a compact top session bar instead of a long vertically stacked page.
- Normal desktop usage should stay inside the viewport; tables and details panels scroll internally.
- The Flows tab supports case-insensitive frontend filtering over already loaded flow rows.
- The Flows table supports frontend-local sorting over already loaded flow DTOs.
- The Flows table also keeps a separate checked-flow selection state for future batch workflows without changing the active selected flow.
- The flow table shows a user-facing 1-based flow number while keeping stable `flow_index` internally.
- The flow table surfaces address family and fragmentation state from the shared flow DTO.
- When one or more flow checkboxes are active, the Flows workspace shows a compact bottom status bar with the checked-flow count.
- Opening a new path clears stale overview, flows, packets, stream, analysis, and prior errors before the next backend call.
- Open controls are disabled while an open is in flight.
- Backend open failures are surfaced in the shell instead of leaving partial stale data on screen.
- Clicking a flow row loads that flow's packets and resets packet paging to the first page.
- The lower-left Flows workspace has `Packets` and `Stream` tabs.
- If the current filter hides the selected flow, the shell clears visible flow/packet/stream/details state to avoid stale UI.
- Clicking a packet row loads packet details and bounded Raw/Payload previews when byte-backed inspection is available.
- The selected-packet inspector consumes shared packet-details DTO fields for the panel title, protocol-specific payload tab title, and explicit no-payload state.
- The Stream tab keeps stream reconstruction bounded to the selected flow plus the current packet/item budgets.
- Stream rows are selectable and drive a basic Selected Stream Item Details view.
- Selecting a stream item does not yet navigate to packet details or source packets.
- The Statistics tab renders compact overview/statistics sections from the frontend-neutral overview DTO.
- Statistics drill-down currently works by switching to `Flows` and reusing the existing frontend filter.
- The Analysis tab has its own compact flow list on the left and selected-flow analysis details on the right.
- Analysis stays selected-flow-only and does not run during capture open.
- Selecting a flow in Analysis reuses the shared selected-flow state and can be followed with `Open in Flows`.
- Analysis histograms use existing selected-flow analysis data only and expose frontend-only direction toggles: `All / A->B / B->A`.
- Sequence CSV export is available only from selected-flow Analysis and uses a native Save dialog.
- When `PFL_TAURI_MEMORY_LOG=1` is present, the shell appends `tauri_memory_log.csv` with repeated-open / load / render phase snapshots for manual retention investigation.
- The memory log now also records the active top-level tab, active lower-left tab, virtual window start/end values, and whether Flows or the Analysis list are currently virtualized.

## Structure

- `src-tauri/`:
  Rust Tauri backend plus a thin Rust-to-C++ bridge layer
- `web/`:
  plain HTML/CSS/JavaScript frontend for the spike

## Bootstrap notes

- `src-tauri/icons/icon.ico` is provided for Tauri's Windows resource step.
- `src-tauri/capabilities/default.json` defines the minimal default desktop capability.
- On Windows, use the default Rust MSVC toolchain for the spike.

## Deferred items

- Tauri now supports six narrow save/export workflows:
  - `File -> Save Index`
  - `Flow -> Export Current Flow`
  - `Flow -> Export Selected Flows`
  - `Flow -> Export Unselected Flows`
  - `Flow -> Smart Export...`
  - selected-flow Analysis sequence CSV export
- Checked-flow selection exists in the Flows table and now powers `Flow -> Export Selected Flows`.
- `Flow -> Export Unselected Flows` now exports the inverse of checked-flow selection.
- Other export workflows are still absent in Tauri.
- Qt's richer per-flow smart-export progress/cancel UI is still not mirrored in Tauri.
- Attach-source is now available as a compact locate/attach workflow, but broader index workflow parity is still incomplete.
- Save/open index workflow details are still thinner than Qt and need a smaller parity polish pass.
- `View -> Settings` now exposes the existing shared/runtime settings already present in Qt/app code:
  - `HTTP: use request path as service hint when Host is missing`
  - `Use possible TLS/QUIC`
- `View -> Settings` also now exposes the existing display setting:
  - `Show Wireshark filter for selected flow`
- `View -> Settings` now also exposes:
  - `Validate IPv4/TCP/UDP checksums for selected packet`
- Checksum validation is runtime-only and applies only when selected packet details are loaded with readable source bytes.
- Settings persistence and any remaining Qt-only settings are still deferred.
- The Stream tab is still experimental and exposes only a bounded selected-flow slice with basic stream-item details; stream-to-packet navigation is still missing.
- Statistics remain partial compared to Qt:
  - Qt-style percentage formatting is still deferred.
  - Drill-down does not yet navigate directly to a specific flow row, packet row, or packet details.
- The current Tauri Analysis tab intentionally covers only a first compact slice of the existing selected-flow session analysis:
  - flow summary
  - protocol panel
  - totals
  - direction split
  - derived metrics
  - timing/size metrics
  - burst/idle summary
  - basic TCP control counts
  - compact histogram sections
  - compact sequence preview
- The following Analysis areas remain deferred:
  - rate graph
  - richer charts
  - fuller Qt analysis workspace parity
- Selected packet inspection is still basic compared with Qt even though it now has `Summary / Raw / Payload / Protocol` tabs.
- In index-only mode or when the original source capture is unavailable, byte-backed packet details plus Raw/Payload previews can be unavailable even though packet metadata is still shown.
- After a valid source attach, byte-backed packet details and stream become available on the next explicit reload; the shell does not trigger global stream or analysis recomputation.
- Source availability is now grouped in the frontend-neutral adapter for open/session shell state plus packet-details / stream unavailable fallbacks, but Qt still uses its existing controller-owned placeholder logic.
- Raw and Payload tabs intentionally show bounded previews only; they do not implement full raw-byte or payload viewers.
- The Wireshark display filter is generated only from already loaded flow DTO fields, so it stays intentionally conservative and may not match full Qt parity.
- Clipboard copy is best-effort; if the browser clipboard API is unavailable or fails, the shell only shows a small non-fatal message.
- Large-capture performance work, virtualization, and more advanced pagination strategies have not been addressed yet.
- The dev-only memory log is investigative only; it does not replace a future large-capture performance / virtualization pass.
- Frontend virtualization is now the first mitigation layer; backend paging/filtering/sorting for very large captures is still deferred.

## Recommended next priorities

1. Export workflows beyond `Flow -> Export Current Flow`, `Flow -> Export Selected Flows`, `Flow -> Export Unselected Flows`, `Flow -> Smart Export...`, `Save Index`, and selected-flow Analysis sequence CSV export
2. Save/open index workflow polish
3. Broader Settings/preferences parity and persistence
4. Performance pass for large captures, including virtualization/pagination where needed
5. Analysis export and rate graph after core Tauri workflows stabilize
6. CLI design after the frontend-neutral DTO surface settles

## Notes

- This is an experimental parallel UI path.
- The Qt desktop UI remains the main product UI for now.
- The Tauri backend talks to the existing C++ code through `FrontendSessionAdapter`.
