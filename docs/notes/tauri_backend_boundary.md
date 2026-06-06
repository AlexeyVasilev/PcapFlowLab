# Tauri Backend Boundary Note

## Scope

This note maps the current Qt-facing UI boundary to the existing application/session layer and identifies the smallest practical frontend-neutral API surface for a Tauri spike.

It does not propose core packet-processing changes.

Current status:

- the first adapter layer now exists as `FrontendSessionAdapter`
- the first implemented slice is:
  - open capture
  - get overview
  - get flows
  - select flow
  - get selected-flow packets
- a minimal Tauri scaffold now exists under `experimental/tauri-ui-spike/`
- backend state in the spike is held as one active adapter/session instance in the Tauri backend layer

## Files inspected most heavily

- `src/ui/app/MainController.h`
- `src/ui/app/MainController.cpp`
- `src/ui/app/FlowListModel.h`
- `src/ui/app/FlowListModel.cpp`
- `src/ui/app/PacketListModel.h`
- `src/ui/app/PacketListModel.cpp`
- `src/ui/app/StreamListModel.h`
- `src/ui/app/StreamListModel.cpp`
- `src/ui/app/PacketDetailsViewModel.h`
- `src/app/session/CaptureSession.h`
- `src/app/session/CaptureSession.cpp`
- `src/app/session/FlowRows.h`

## Current boundary observations

### `CaptureSession` already owns the useful backend operations

The session layer already provides most of the raw workflow surface needed by a frontend:

- open capture or index
- attach source capture
- read summary and protocol/top summaries
- list flows
- list flow packets
- count flow packets
- list bounded flow stream items
- read packet details and protocol text
- compute selected-flow analysis

The output types in `FlowRows.h` are already close to frontend DTOs:

- `FlowRow`
- `PacketRow`
- `StreamItemRow`

They are still C++ domain rows, but they are much closer to a frontend-neutral surface than the Qt models are.

### `MainController` is a mixed adapter + Qt state machine

`MainController` is not only a thin wrapper over `CaptureSession`.

It currently combines:

- file-open and save/export command handling
- async open/export progress state
- selected-flow / selected-packet / selected-stream-item state
- source-capture availability handling
- packet-list lazy loading state
- stream-list bounded loading state
- selected-flow analysis state
- UI-facing formatted text and availability flags
- glue code that fills Qt models and emits Qt signals

For the target workflows, the important controller-owned logic is:

- `openPath(...)` and `applyLoadedState(...)`
- `setSelectedFlowIndex(...)`
- `refreshSelectedFlowPackets(...)`
- `refreshSelectedStreamItems(...)`

That logic is reusable conceptually, but it is currently entangled with Qt model updates and Q_PROPERTY state.

### Qt models are presentation adapters, not backend contracts

The models are clearly QML-facing:

- `FlowListModel` owns checked state, text filtering, sorting, and QAbstractListModel roles
- `PacketListModel` converts `PacketRow` into QML roles and tracks one UI-specific marker aggregate
- `StreamListModel` converts `StreamItemRow` into QML roles and formats source packet text like `packet #6,#7`
- `PacketDetailsViewModel` is a pure text-presentation object built for tabbed QML details panes

These should not become the Tauri backend contract.

## Current mismatch with a frontend-neutral API

The main Qt-specific dependencies that do not transfer cleanly are:

### Q_PROPERTY and signal-driven derived state

`MainController` exposes a large amount of derived UI state through:

- Q_PROPERTY
- Q_INVOKABLE
- Qt signals

Examples:

- `canLoadMorePackets`
- `streamLoading`
- `selectedFlowWiresharkFilter`
- `analysisAvailable`
- `statusText`

This state is useful, but the Qt mechanism is not. A Tauri-facing layer should return explicit DTOs instead of mirroring Q_PROPERTY.

### Role-based models

The current flow/packet/stream lists are shaped as:

- QAbstractListModel
- numeric roles
- QML-facing role names

A Tauri-facing API should instead return plain serializable arrays of DTOs.

### Controller-owned formatting

Some data shaping currently lives in the controller or Qt model layer:

- formatted protocol-hint display text
- flow filtering and sorting rules in `FlowListModel`
- stream source-packet text formatting in `StreamListModel`
- selected-flow packet payload shaping via `apply_original_transport_payload_lengths(...)`
- selected-stream detail text composition in `MainController`

This means the future adapter should separate:

- raw DTO data returned to the frontend
- optional helper formatting kept in the frontend

### Controller-owned selected-flow caches and budgets

The stream path is not a simple stateless read.

`MainController::refreshSelectedStreamItems(...)` coordinates:

- packet-window budgets
- selected-flow packet cache preparation
- TCP payload suppression preparation
- packet-number lookup for user-visible stream packet numbering
- "load more" state

That logic is still backend-valid, but it should move into a small non-Qt adapter before exposing stream to Tauri.

## Proposed minimal frontend-facing API

For the first spike, the smallest safe API is:

### `open_capture(path, open_mode, analysis_settings)`

Purpose:

- open a capture or index and create the active backend session

Existing code it would call:

- `CaptureSession::open_input(...)`
- or `CaptureSession::open_capture(...)` / `load_index(...)` through the existing open-mode path

Near-usable now:

- yes, but currently orchestrated by `MainController::openPath(...)`

Adapter work needed:

- small adapter method to own one active `CaptureSession`
- return a compact result DTO with success/error/source-availability state

### `get_overview()`

Purpose:

- return capture summary and high-level protocol stats after open

Existing code it would call:

- `CaptureSession::summary()`
- `CaptureSession::protocol_summary()`
- `CaptureSession::quic_recognition_stats()`
- `CaptureSession::tls_recognition_stats()`
- optionally `CaptureSession::top_summary(...)`

Near-usable now:

- yes

Adapter work needed:

- aggregate DTO instead of many separate Qt properties

### `get_flows()`

Purpose:

- return the flow list in capture order

Existing code it would call:

- `CaptureSession::list_flows()`

Near-usable now:

- yes

Adapter work needed:

- minimal DTO serialization only

Recommendation for first spike:

- keep filter/sort in the frontend instead of copying `FlowListModel` behavior immediately

### `select_flow(flow_index)`

Purpose:

- store the active flow in the adapter and reset selected-flow ephemeral state

Existing code it would conceptually mirror:

- `MainController::setSelectedFlowIndex(...)`

Near-usable now:

- not as a single backend method; this is currently controller state logic

Adapter work needed:

- small adapter-side selected-flow state
- clear selected-flow packet cache and stream-related ephemeral state

### `get_selected_flow_packets(offset, limit)`

Purpose:

- return packet rows for the selected flow

Existing code it would call:

- `CaptureSession::flow_packet_count(...)`
- `CaptureSession::list_flow_packets(flow_index, offset, limit)`
- `CaptureSession::prepare_selected_flow_packet_cache(...)`
- `CaptureSession::suspected_tcp_retransmission_packet_indices(...)`

Near-usable now:

- mostly yes, but some shaping currently happens in `MainController::refreshSelectedFlowPackets(...)`

Adapter work needed:

- apply the same original transport payload-length shaping
- add packet-level retransmission marker shaping
- return rows plus `total_count`

### Optional later: `get_selected_flow_stream(packet_window, item_limit)`

Purpose:

- return bounded stream items for the selected flow

Existing code it would call:

- `CaptureSession::prepare_selected_flow_packet_cache(...)`
- `CaptureSession::list_flow_stream_items_for_packet_prefix(...)`
- `CaptureSession::flow_packet_count(...)`

Near-usable now:

- only partially

Adapter work needed:

- move the current controller-side packet-window budget logic into a frontend-neutral class
- keep source-capture availability checks and packet-number mapping outside Qt

Recommendation:

- do not include stream in the first Tauri slice unless the packet-list slice is already clean

## Recommended adapter shape

Do not have Tauri call `MainController`.

Do not have Tauri talk directly to raw `CaptureSession` either.

The best next step is a very small adapter layer, for example:

- `FrontendSessionAdapter`
- or `TauriSessionAdapter`

Responsibilities:

- own one active `CaptureSession`
- hold selected-flow state
- expose serializable DTO-friendly methods
- move only the non-Qt selected-flow orchestration that Tauri actually needs

It should not:

- depend on QAbstractListModel
- expose Q_PROPERTY
- own QML text formatting
- absorb export or full details-pane logic in the first spike

## Recommended first implementation slice

The first safe vertical slice is:

1. `open_capture(...)`
2. `get_overview()`
3. `get_flows()`
4. `select_flow(flow_index)`
5. `get_selected_flow_packets(offset, limit)`

Why this slice first:

- it exercises the real capture/session boundary
- it avoids the Qt role-model layer
- it proves selected-flow-only on-demand reads
- it avoids the more stateful bounded stream path initially

Stream should be the second slice, after the packet-list adapter is stable.

## What should remain Qt-specific for now

Keep these in the Qt UI for the spike:

- QML models and role names
- file dialogs
- controller-owned browse helpers
- status banner phrasing
- analysis tab/property fan-out
- packet-details tab text composition
- Smart Export UI/workflow
- current stream-list incremental UI behavior

The spike should prove the backend boundary, not replace the Qt desktop UI.
