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

Recommended first spike scope:

1. open capture
2. show summary/overview
3. show flow list
4. select a flow
5. show selected-flow packet list

Stream should be a follow-up slice after the packet-list adapter is stable, because the current stream path still depends on controller-owned packet-window and cache orchestration.
