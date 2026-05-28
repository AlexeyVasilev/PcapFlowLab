# Tauri UI Spike

This directory contains the first experimental Tauri frontend for Pcap Flow Lab.

## Current scope

Implemented slice:

- open capture
- load overview
- load flow list
- select a flow
- load the selected-flow packet list

Not implemented yet:

- stream view
- packet details
- analysis
- Smart Export
- settings
- production packaging

## Structure

- `src-tauri/`:
  Rust Tauri backend plus a thin Rust-to-C++ bridge layer
- `web/`:
  plain HTML/CSS/JavaScript frontend for the spike

## Bootstrap notes

- `src-tauri/icons/icon.ico` is provided for Tauri's Windows resource step.
- `src-tauri/capabilities/default.json` defines the minimal default desktop capability.
- on Windows, this spike is currently aligned with the existing MinGW-based C++ toolchain via `src-tauri/.cargo/config.toml`

## Notes

- This is an experimental parallel UI path.
- The Qt desktop UI remains the main product UI for now.
- The Tauri backend talks to the existing C++ code through `FrontendSessionAdapter`.
