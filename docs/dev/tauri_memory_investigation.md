# Tauri Memory Investigation

## Scope

This note captures a static ownership and retention audit for the experimental Tauri UI spike, plus the dev-only diagnostics hooks added to make repeated-open memory behavior measurable without changing product behavior.

The goal is narrow:

- audit obvious lifetime boundaries across C++, bridge/FFI, Rust, and web state;
- add opt-in logging for repeated open / reload phases;
- harden frontend cleanup before the next open;
- reduce unnecessary heavy DOM rendering for very large captures;
- replace the temporary fixed-row cap with lightweight frontend virtualization for the two largest flow lists;
- document the remaining high-risk retention areas without over-claiming a confirmed leak.

## Opt-in diagnostics

Enable diagnostics by starting the Tauri spike with:

```powershell
$env:PFL_TAURI_MEMORY_LOG = '1'
```

When enabled, the Tauri app appends a CSV log to:

- `tauri_memory_log.csv`

The log is written relative to the Tauri process current working directory.

Current columns:

- `timestamp_unix_ms`
- `phase`
- `open_path`
- `open_path_short`
- `open_state`
- `active_tab`
- `flow_view_tab`
- `flow_count`
- `visible_flow_count`
- `total_analysis_flow_count`
- `checked_flow_count`
- `packet_count`
- `stream_item_count`
- `analysis_sequence_row_count`
- `packet_size_histogram_row_count`
- `inter_arrival_histogram_row_count`
- rendered DOM row counts for flows / packets / stream / analysis list / sequence preview / key statistics tables
- `flow_virtual_window_start`
- `flow_virtual_window_end`
- `analysis_flow_virtual_window_start`
- `analysis_flow_virtual_window_end`
- `flow_virtualization_active`
- `analysis_flow_virtualization_active`
- `packet_request_offset`
- `packet_request_limit`
- `packet_request_row_count`
- `packet_request_total_count`
- `overview_loaded`
- `packet_details_loaded`
- `analysis_loaded`
- `selected_flow_index`
- `selected_packet_index`
- `process_working_set_bytes`

Logged phases currently include:

- `app_started`
- `before_open_cleanup`
- `after_open_cleanup`
- `before_open_capture`
- `after_open_capture`
- `after_get_overview`
- `after_get_flows`
- `after_render_flows`
- `flow_select_started`
- `packets_request_started`
- `packets_request_finished`
- `packets_render_finished`
- `stream_request_started`
- `stream_request_finished`
- `analysis_request_started`
- `analysis_request_finished`
- `after_statistics_loaded`
- `after_analysis_loaded`
- `after_stream_loaded`
- `before_next_open`
- `after_next_open`

## Static audit findings

### 1. `CaptureSession` / `FrontendSessionAdapter` lifetime

- The Tauri process holds a single `CppFrontendSessionAdapter` inside `AdapterState`, wrapped by `Mutex`.
- That adapter owns one `FrontendSessionAdapter`, which in turn owns one `CaptureSession`.
- The session object is intentionally process-global for the Tauri app lifetime and is reused across commands.
- Opening a new capture does not create a new Tauri-side adapter object; it replaces session-owned capture data through the existing open path.

This is not a leak by itself. It does mean memory shrink after reopen depends on the session replacing old capture-owned structures correctly and on allocator/WebView behavior.

### 2. Bridge / FFI allocation ownership

The current Rust <-> C++ path is JSON-string based:

- C++ bridge methods serialize DTOs into one heap `char*`.
- Rust `parse_json_owned<T>(json_ptr)` copies the contents into a Rust `String`.
- Rust always frees the original C string with `pfl_frontend_string_free(json_ptr)`.

Important consequence:

- there is no obvious nested cross-FFI ownership tree for DTO arrays/strings;
- the top-level owned FFI allocation appears to be released correctly after every command response.

No clear small FFI leak was identified in the current JSON bridge path, so no FFI ownership fix was made in this pass.

### 3. Rust DTO conversion and command return path

- Rust command handlers deserialize the returned JSON into owned Rust DTOs and then return those DTOs to Tauri.
- We did not find a second persistent Rust-side cache of the large flow/statistics/analysis DTO payloads.
- The main risk in Rust is therefore not a repeated response leak but lack of observability around repeated command cycles.

This pass adds only the dev-only CSV logger to that layer.

### 4. JS state retention

The largest frontend-held payloads are:

- `state.flows`
- `state.packets`
- `state.streamItems`
- `state.overview`
- `state.analysis`
- `state.packetDetails`

Before this pass, the app already had logical cleanup helpers such as:

- `clearFlows()`
- `clearPackets()`
- `clearStream()`
- `clearAnalysis()`
- `resetForNewOpen()`

The remaining risk was that large rendered DOM tables and text containers could stay populated until the next render, while the new open was already starting.

This pass hardens cleanup by explicitly clearing the main rendered table bodies and analysis/details text containers before the next open.

It also adds a first large-capture mitigation in the web shell:

- only the active heavy top-level tab is rebuilt;
- only the active lower-left `Packets` or `Stream` pane is rebuilt inside `Flows`;
- the Flows table and Analysis flow list now use lightweight scroll-window virtualization instead of rendering every row at once.
- the earlier visible `Show more` cap path is no longer the primary large-list UX.
- selected-flow packet loading now updates the loading state immediately, stays bounded to the current page, and ignores stale async responses after a newer flow selection.

### 5. Render-path / event-handler retention

Current render behavior is based on:

- one-time event listener registration during app startup;
- re-rendering via `innerHTML` replacement for tables and compact panels.

The good news:

- event listeners are not reattached on every render for the same controls;
- the render path does not appear to accumulate duplicate per-row listeners in a classic leak pattern.

The remaining risk:

- large table DOMs and large HTML strings can still temporarily retain memory until the WebView and JS engine reclaim them;
- repeated open cycles may therefore show high-water behavior even without a true logic leak.

### 6. Repeated-open cleanup risk

Repeated opens were the highest-risk workflow for retention, because the app could hold:

- old flow arrays
- old analysis arrays
- old sequence preview rows
- old statistics tables
- old DOM table rows

This pass makes that workflow more observable and more deterministic by:

- logging `before_next_open`
- logging `before_open_cleanup` and `after_open_cleanup`
- clearing rendered containers before the next open
- logging post-open / post-load phases so retained state can be compared across cycles

## Memory risk areas still worth watching

These are the most likely sources of elevated memory usage even if no strict ownership leak exists:

1. Full frontend-retained `state.flows` for large captures.
2. Large rendered flow windows can still pressure WebView memory even though they are now bounded.
3. Analysis payload retention:
   - sequence preview rows
   - packet-size histogram rows
   - inter-arrival histogram rows
4. Statistics tables and top-talker rows held at the same time as full flow DTOs.
5. WebView allocator / JS GC lag after repeated table teardown and rebuild.

## Fixes made in this pass

Concrete fixes made:

- explicit DOM/container cleanup before new open in the Tauri web shell
- active-tab-only heavy rendering for `Flows`, `Statistics`, and `Analysis`
- active lower-pane-only rendering for `Packets` vs `Stream`
- lightweight frontend virtualization for the main Flows table and the Analysis flow list

Concrete leak fixes not made:

- no FFI ownership bug was clearly identified in the current JSON bridge path
- no `CaptureSession` core lifetime change was made
- no virtualization / pagination redesign was attempted

## Manual measurement protocol

Recommended repeated-open measurement protocol:

1. Start Tauri with `PFL_TAURI_MEMORY_LOG=1`.
2. Open one large capture or index.
3. Visit:
   - `Flows`
   - `Statistics`
   - `Analysis`
   - `Stream`
4. Open a second large capture.
5. Repeat that cycle at least 3 times.
6. Inspect `tauri_memory_log.csv` for:
   - whether `flow_count` returns to expected new-capture counts
   - whether `rendered_flow_dom_row_count` stays bounded by the current virtual window
   - whether `rendered_analysis_flow_dom_row_count` stays bounded by the current virtual window
   - whether `flow_virtual_window_start/end` advance as you scroll
   - whether `analysis_flow_virtual_window_start/end` advance as you scroll
   - whether `flow_select_started -> packets_request_started -> packets_request_finished -> packets_render_finished` stays tight for large-flow selection
   - whether `packet_request_offset/limit/row_count/total_count` match the expected bounded first page
   - whether rendered DOM row counts drop to near-zero at `after_open_cleanup`
   - whether large analysis/statistics row counts persist unexpectedly across `before_next_open` -> `after_open_cleanup`
   - whether `process_working_set_bytes` climbs monotonically or stabilizes

Because working set is allocator- and WebView-dependent, also cross-check with external OS tools:

- Windows Task Manager
- Process Explorer

The external check matters because working set may stay elevated briefly even when JS arrays and DOM nodes are no longer logically referenced.

## Deferred optimization candidates

If repeated-open memory still looks unhealthy after this diagnostics pass, the next candidates should be:

1. Backend paging/filtering/sorting for very large captures.
2. More aggressive statistics/analysis lazy rendering.
3. Smaller overview / analysis DTO slices for very large captures.
4. Optional analysis/sequence truncation in the Tauri spike.
5. A deeper session-level audit only if the CSV and OS measurements indicate retained memory after successful cleanup.
