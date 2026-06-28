# Large-Capture Performance Guidelines

This document captures practical rules from the selected-flow and large-capture optimization work. Use it when reviewing or extending hot paths in Qt, Tauri, or shared backend/session code.

## Core Principle

Large-capture UI actions must be bounded by the visible or requested window, not by:

- total capture packet count
- total flow packet count
- full TCP direction packet count
- full flow list size
- full DTO or details payload size

If the UI asks for a first page, first batch, selected row, or selected item, the backend path should stay proportional to that request.

## Anti-Patterns

- Rebuilding the full flow list for selected-flow actions.
  Example: repeated `list_connections(state_)` or `list_flows()` materialization when only one selected flow is needed.

- Full-flow materialization on UI selection.
  Example: Tauri `select_flow` building full flow rows even though the response only needs selected state.

- Full-flow or full-direction collection before applying budget.
  Example: stream first-load collecting or sorting all direction packets before applying a small packet budget.

- Hidden full-flow scans inside helper functions.
  Example: a bounded outer path calling a helper that internally scans all QUIC packets.

- Per-packet file open/read/close in hot paths.
  Example: repeated `CaptureFilePacketReader` or `FileByteSource` creation for visible packet rows.

- Byte reads during list DTO construction.
  Example: Tauri stream list DTO eagerly building payload or protocol text for every stream item.

- Eager details generation.
  Example: building protocol, payload, or source details for all rows or items instead of lazy-loading the selected item only.

- Expensive parser branches without cheap precheck.
  Example: running HTTP reconstruction on TLS or binary flows only to return no HTTP prefix.

- Reconstructing source mappings in a second pass.
  Example: rebuilding reassembled-byte-to-packet mapping by reading selected-flow payloads again after reassembly already knew contributors.

- Per-byte mapping where interval mapping is enough.
  Example: stream chunk or source mapping using one mapping entry per byte instead of packet intervals or byte ranges.

- Treating diagnostics as production logic.
  Temporary diagnostics should isolate bottlenecks, then be removed or replaced by intentional production telemetry.

## Successful Patterns

- Metadata-first enrichment.
  Prefer packet and flow metadata for list rows. Read bytes only for ambiguous or selected cases.

- Runtime-only caches with explicit invalidation.
  Examples:
  - selected-flow full-packet cache
  - selected-flow TCP prefix context
  - cached listed connection view

- Cheap single-flow lookup.
  Use a direct or cached flow lookup when only one flow is needed.

- Bounded prefix or window APIs.
  Stream, packet-row, and fallback helpers should accept bounded packet refs or spans.

- Bounded reassembly.
  Reassemble only the requested bounded prefix for first-load UI.

- Bounded QUIC discovery.
  QUIC Initial and CID discovery for first-load should not scan the full flow.

- Cheap protocol precheck or gating.
  Use service hints and bounded-prefix sniffing to avoid expensive TLS or HTTP branches when they are unlikely to succeed.

- Interval-based source mapping.
  Reassembly should carry packet byte counts or intervals so TLS and HTTP presentation can map source packets cheaply.

- Lazy details.
  Keep list DTOs lightweight. Load heavy payload, protocol, and details fields for the selected packet or item only.

- Stage-based diagnostics.
  When profiling a hot path, split timing into backend or session, cache, parser or reassembly, DTO, JSON or IPC, and frontend stages where possible.

## Review Checklist

- Does this UI action scale with the visible limit or requested window instead of full capture or flow size?
- Does this path call `list_flows()`, `flow_packets()`, `collect_packets()`, or direction collection in response to a small UI request?
- Does any helper called from a bounded path escape into full-flow scanning?
- Does list or summary DTO construction read packet bytes?
- Are heavy details generated eagerly for all rows or items?
- Are source packet numbers or ranges computed without extra packet byte reads?
- Are caches invalidated on open, reset, load-index, and source-attachment changes as needed?
- Does Tauri avoid sending heavy fields over JSON until they are visible?
- Is the path safe for 30M+ packets and hundreds of thousands of flows?
- Are diagnostics temporary, removable, and separate from production behavior?

## Qt And Tauri Notes

- Qt and Tauri share the backend optimizations.
- Tauri has extra risk from DTO size, JSON serialization, IPC transfer, and frontend state churn.
- Tauri list responses should stay small and lazy-load heavy details.
- Avoid returning full snapshots for selection-only actions.

## Future Work

- Selected packet details can still be heavy on some large flows.
- Selected stream item details can still be heavy for some items.
- Those paths should be optimized later as separate focused passes.
