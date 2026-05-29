# Tauri UI Spike

This directory contains the first experimental Tauri frontend for Pcap Flow Lab.

## Current scope

Implemented slice:

- open capture
- load overview
- load flow list
- select a flow
- load the selected-flow packet list
- load a basic selected-flow stream view on demand
- select a packet from the current packet page
- inspect basic selected-packet details
- inspect selected packets through compact Summary / Raw / Payload / Protocol tabs
- frontend-only tabs for Flows, Statistics, and Analysis
- viewport-oriented analyzer layout with internal panel scrolling
- compact desktop-style density pass for the Flows workspace
- frontend flow filter/search on the loaded flow list
- generated Wireshark display filter text for the selected flow
- open workflow state handling: idle, opening, opened, error
- flow-row selection highlighting
- selected-flow packet pagination with Previous/Next controls
- selected-flow Stream tab with on-demand bounded loading and Load More
- compact flow-family / fragmentation surfacing in the Tauri flow table
- compact packet-row markers for IP fragmentation and suspected TCP retransmission

Not implemented yet:

- full packet details parity
- analysis
- Smart Export
- settings
- production packaging
- browse/file-picker workflow

## Current behavior

- The spike keeps the typed capture/index path workflow.
- The shell now uses a compact top session bar instead of a long vertically stacked page.
- Normal desktop usage should stay inside the viewport; tables and details panels scroll internally.
- The current Tauri shell is intentionally denser than a typical web layout: smaller controls, tighter tabs, denser tables, and more compact packet-details presentation.
- The Flows tab now supports case-insensitive frontend filtering over already loaded flow rows.
- The flow table now shows a user-facing 1-based flow number while keeping stable `flow_index` internally for selection and backend calls.
- The flow table now surfaces address family and fragmentation state from the current shared flow DTO.
- Flow filtering shows a visible result count and does not trigger backend filtering calls.
- Opening a new path clears stale overview, flows, packets, and prior errors before the next backend call.
- Open controls are disabled while an open is in flight.
- Backend open failures are surfaced in the shell instead of leaving partial stale data on screen.
- Clicking a flow row loads that flow's packets and resets packet paging to the first page.
- The lower-left Flows workspace now has Packets and Stream tabs; Stream is loaded lazily for the selected flow only.
- If the current filter hides the selected flow, the Tauri shell clears the visible flow/packet/details selection to avoid stale UI state.
- Clicking a packet row loads packet details and a bounded payload preview when byte-backed inspection is available.
- The selected-packet inspector is now tabbed: Summary, Raw, Payload, and Protocol.
- The lower Flows workspace now gives more width to the packet inspector than to the packet list so Raw and Protocol inspection stay readable at normal desktop sizes.
- Summary keeps compact packet metadata visible without large cards.
- Raw and Payload previews are intentionally bounded to small previews instead of full packet dumps.
- Raw and Payload previews use monospace, preformatted blocks with internal horizontal scrolling when lines are long.
- Raw and Payload previews can be unavailable in index-only sessions or when the source capture cannot be read.
- The packets panel shows loading, empty, and error states and reports the current visible range.
- The Stream tab shows loading, empty, unavailable, and error states and keeps stream reconstruction bounded to the selected flow plus the current packet/item budgets.
- Packet details are reset on new open attempts, open failures, flow changes, and packet page changes.
- The Flows tab now keeps the main workflow in one analyzer view: flows above, packets and packet details below.
- The selected flow also shows a conservative Wireshark display filter string with a Copy button that uses the browser clipboard API when available.
- The current Tauri shell now consumes the shared Wireshark display filter field from the frontend-neutral flow DTO instead of rebuilding the filter only in JavaScript.
- Protocol hints now use the shared display-oriented hint text from the frontend-neutral flow DTO when available.
- The Statistics tab currently contains only the basic overview cards/data.
- The Analysis tab is a placeholder only and does not implement analysis behavior yet.

## Structure

- `src-tauri/`:
  Rust Tauri backend plus a thin Rust-to-C++ bridge layer
- `web/`:
  plain HTML/CSS/JavaScript frontend for the spike

## Bootstrap notes

- `src-tauri/icons/icon.ico` is provided for Tauri's Windows resource step.
- `src-tauri/capabilities/default.json` defines the minimal default desktop capability.
- on Windows, use the default Rust MSVC toolchain for the spike

## Deferred items

- Browse is intentionally deferred for now. A file dialog is possible in Tauri, but wiring it cleanly would expand the current capability and shell surface beyond this small navigation-focused pass.
- Stream, Analysis, Packet Details, Export, and settings workflows are still outside the spike's current scope.
- The Stream tab is still experimental and exposes only a small subset of the current Qt stream presentation fields.
- The Analysis tab is shell-only for now; it intentionally does not call backend analysis APIs in this iteration.
- Selected packet inspection is still basic. It does not aim for full Qt packet-details parity yet.
- In index-only mode or when the original source capture is unavailable, byte-backed packet details plus Raw/Payload previews can be unavailable even though packet metadata is still shown.
- Raw and Payload tabs intentionally show bounded previews only; they do not implement full raw-byte or payload viewers.
- The Wireshark display filter is generated only from already loaded flow DTO fields, so it stays intentionally conservative and may not match full Qt parity.
- Packet rows now surface compact marker text for fragmented packets and suspected TCP retransmissions, but the overall packet table still remains intentionally compact.
- Clipboard copy is best-effort; if the browser clipboard API is unavailable or fails, the shell only shows a small non-fatal message.

## Notes

- This is an experimental parallel UI path.
- The Qt desktop UI remains the main product UI for now.
- The Tauri backend talks to the existing C++ code through `FrontendSessionAdapter`.
