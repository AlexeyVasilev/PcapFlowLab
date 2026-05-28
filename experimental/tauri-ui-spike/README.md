# Tauri UI Spike

This directory contains the first experimental Tauri frontend for Pcap Flow Lab.

## Current scope

Implemented slice:

- open capture
- load overview
- load flow list
- select a flow
- load the selected-flow packet list
- open workflow state handling: idle, opening, opened, error
- flow-row selection highlighting
- selected-flow packet pagination with Previous/Next controls

Not implemented yet:

- stream view
- packet details
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
- The packets panel shows loading, empty, and error states and reports the current visible range.

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

## Notes

- This is an experimental parallel UI path.
- The Qt desktop UI remains the main product UI for now.
- The Tauri backend talks to the existing C++ code through `FrontendSessionAdapter`.
