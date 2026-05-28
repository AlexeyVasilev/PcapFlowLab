# Tauri UI Spike

This directory contains the first experimental Tauri frontend for Pcap Flow Lab.

## Current scope

Implemented slice:

- open capture
- load overview
- load flow list
- select a flow
- load the selected-flow packet list
- select a packet from the current packet page
- inspect basic selected-packet details
- frontend-only tabs for Flows, Statistics, and Analysis
- viewport-oriented analyzer layout with internal panel scrolling
- compact desktop-style density pass for the Flows workspace
- frontend flow filter/search on the loaded flow list
- generated Wireshark display filter text for the selected flow
- open workflow state handling: idle, opening, opened, error
- flow-row selection highlighting
- selected-flow packet pagination with Previous/Next controls

Not implemented yet:

- stream view
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
- Flow filtering shows a visible result count and does not trigger backend filtering calls.
- Opening a new path clears stale overview, flows, packets, and prior errors before the next backend call.
- Open controls are disabled while an open is in flight.
- Backend open failures are surfaced in the shell instead of leaving partial stale data on screen.
- Clicking a flow row loads that flow's packets and resets packet paging to the first page.
- If the current filter hides the selected flow, the Tauri shell clears the visible flow/packet/details selection to avoid stale UI state.
- Clicking a packet row loads packet details and a bounded payload preview when byte-backed inspection is available.
- The packets panel shows loading, empty, and error states and reports the current visible range.
- Packet details are reset on new open attempts, open failures, flow changes, and packet page changes.
- The Flows tab now keeps the main workflow in one analyzer view: flows above, packets and packet details below.
- The selected flow also shows a conservative Wireshark display filter string with a Copy button that uses the browser clipboard API when available.
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
- The Analysis tab is shell-only for now; it intentionally does not call backend analysis APIs in this iteration.
- Selected packet inspection is still basic. It does not aim for full Qt packet-details parity yet.
- In index-only mode or when the original source capture is unavailable, byte-backed packet details and payload preview can be unavailable even though packet metadata is still shown.
- The Wireshark display filter is generated only from already loaded flow DTO fields, so it stays intentionally conservative and may not match full Qt parity.
- Clipboard copy is best-effort; if the browser clipboard API is unavailable or fails, the shell only shows a small non-fatal message.

## Notes

- This is an experimental parallel UI path.
- The Qt desktop UI remains the main product UI for now.
- The Tauri backend talks to the existing C++ code through `FrontendSessionAdapter`.
