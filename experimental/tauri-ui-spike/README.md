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
- Opening a new path clears stale overview, flows, packets, and prior errors before the next backend call.
- Open controls are disabled while an open is in flight.
- Backend open failures are surfaced in the shell instead of leaving partial stale data on screen.
- Clicking a flow row loads that flow's packets and resets packet paging to the first page.
- Clicking a packet row loads packet details and a bounded payload preview when byte-backed inspection is available.
- The packets panel shows loading, empty, and error states and reports the current visible range.
- Packet details are reset on new open attempts, open failures, flow changes, and packet page changes.

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
- Selected packet inspection is still basic. It does not aim for full Qt packet-details parity yet.
- In index-only mode or when the original source capture is unavailable, byte-backed packet details and payload preview can be unavailable even though packet metadata is still shown.

## Notes

- This is an experimental parallel UI path.
- The Qt desktop UI remains the main product UI for now.
- The Tauri backend talks to the existing C++ code through `FrontendSessionAdapter`.
