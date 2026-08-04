# Stream Architecture

## Purpose

Stream is a payload-oriented view for the currently selected flow.

- It exists to present protocol-aware or payload-aware Stream items for one flow at a time.
- It is derived from already imported packet and flow metadata plus lazy raw-packet reads from the source capture.
- It is not persisted in indexes, checkpoints, or `CaptureState`.
- It is not part of capture open, import, summary construction, or index build.

In practical terms, Stream is a selected-flow analysis surface, not a stored stream model.

## Core principles

- Selected-flow only: Stream work starts only after a flow is selected.
- On-demand only: no Stream materialization runs during fast open or index load.
- Ephemeral: results may be discarded and rebuilt whenever selection or view state changes.
- Bounded: every reassembly-backed operation is constrained by explicit `max_packets` and `max_bytes` limits.
- Heuristic: current behavior is packet-order best-effort analysis, not TCP-correct reconstruction.

These constraints are intentional. They keep Stream useful for interactive analysis without moving expensive transport reconstruction into the global ingestion path.

## Stream item model

Each Stream row is represented as a `StreamItemRow`.

- `stream_item_index`: 1-based item order within the current materialized Stream result.
- `direction_text`: `A→B` or `B→A`, based on canonical flow direction.
- `label`: user-facing classification such as `TLS ClientHello`, `HTTP 200 OK`, `TCP Payload`, or `UDP Payload`, derived from retained structured stream-item semantics rather than by parsing formatted protocol text.
- `byte_count`: byte size of the item payload represented by the row.
- `packet_count`: number of packets contributing bytes to the item.
- `packet_indices`: contributing packet indices in capture order.
- `payload_hex_text`: optional formatted payload preview for item-level details.

The model is intentionally narrow. A Stream item is a presentation artifact for the selected flow, not a protocol object with lifecycle outside the current view.

Formatted protocol-oriented text is no longer retained in `StreamItemRow`.

- Stream labels, Summary, and Item Data ownership come from structured retained semantics.
- Explicit formatter/debug APIs may still exist where they are intentionally consumed outside Stream row retention.
- `payload_hex_text` remains temporarily for a separate cleanup pass.
- `FlowRow::protocol_text` remains live and unchanged for the flow list and related behavior.

## Stream materialization

Stream now uses one bounded on-demand materialization pipeline.

- The same protocol-aware builder is used for the initial selected-flow result and every later `Load more` refresh.
- Initial and extended views differ only by bounds, primarily the packet window and item budget supplied to the builder.
- The packet window always remains a bounded prefix of the selected flow's packets: `[0, packet_window_count)`.
- The logical-item budget is cumulative across protocol-aware reconstruction, not a late UI-only slice after building every TLS or HTTP item in that packet window.
- A small flow may fit completely inside the initial bounds and therefore appear fully materialized immediately.
- A larger flow yields a partial result from the same builder, not from a fallback-only path.

Selected-flow Stream materialization is owned by `CaptureSession`.

- `CaptureSession` keeps one ephemeral selected-flow Stream context for the currently materialized bounded prefix.
- The context is selected-flow-only, capture-lifetime-only, and non-persistent.
- Qt and `FrontendSessionAdapter` / Tauri reuse the same session-owned materialization; they do not carry independent Stream cursors or tokens.
- The context records the materialized packet-window count, the cumulative item limit used for that build, the materialized rows, and internal ordering/stability metadata.
- Repeated compatible requests reuse the current context result.
- Smaller compatible projections reuse the retained materialized prefix without rewinding protocol-aware state.
- Packet-window or item-budget growth currently uses a fresh bounded rebuild from packet zero.
- This conservative growth behavior avoids carrying forward a continuation frontier whose committed boundary is not represented exactly in the visible cumulative result.

For selected-flow UI queries, the effective budget includes one extra logical item of lookahead.

- If the visible limit is `N`, bounded Stream reconstruction materializes at most `N + 1` logical items for that query shape.
- The extra item is used only to answer whether `can_load_more` should remain true for the current packet window.
- Visible ordering and visible prefix content must match the corresponding prefix of the larger bounded rebuild.

Internally the materialized result is split into:

- a committed stable prefix;
- a provisional suffix that begins at the earliest unstable ordering position.

Window-incomplete rows remain provisional because a larger packet window may replace them with a completed structured item. Genuine gap rows, malformed terminal rows, and capture-constricted terminal rows remain stable.

### Load more

`Load more` remains a cumulative bounded query, not a frontend append protocol.

- The controller increases the selected flow's packet and item budgets.
- `CaptureSession` reevaluates that larger cumulative Stream shape.
- Packet-window or item-budget growth currently rebuilds the bounded prefix from scratch.
- Repeated identical requests and smaller compatible projections may still reuse the retained materialized result.
- The result remains selected-flow only, ephemeral, and non-persistent.
- No frontend cursor token or persisted continuation checkpoint is introduced.

## Reassembly usage

Stream uses reassembly only as a local helper for selected-flow analysis.

- Directional only: one request handles one flow direction at a time.
- Packet-order concatenation only: payload bytes are appended in observed packet order.
- Exact duplicate TCP payload segments may be suppressed for the selected flow when they were already marked by the selected-flow retransmission detector.
- The same bounded reassembly-assisted path is used whether Stream is still partial or already expanded by `Load more`.
- No overlap trimming: overlapping sequence-space handling is not implemented.
- No out-of-order repair: reordered packets are not reassembled into transport-correct byte order.
- Partial results are allowed: budget exhaustion and incomplete trailing data are normal outputs, not exceptional states.

Reassembly quality flags are diagnostic. They describe approximation, suppression, or incompleteness, but they do not make the result TCP-correct.

## Protocol-specific behavior

### TLS

TLS Stream parsing is record-oriented and may use bounded directional reassembly.

- Multiple TLS records inside one TCP payload are split into separate Stream items.
- A TLS record spanning multiple TCP packets may become one logical item if the bounded reassembly buffer contains the full record.
- TLS Stream reconstruction now runs through an explicit resumable scanner state in the session layer.
- Selected-flow Stream context retains the materialized bounded result plus stability metadata for compatible projection reuse.
- Bounds growth currently prefers a fresh bounded rebuild over retained continuation.
- Packet-window growth may replace an earlier window-incomplete TLS projection with one completed row when newly authorized packets finish the record.
- A window-incomplete TLS row is a projection of pending scanner state at the current packet-window boundary.
- HTTP remains rebuild-based.
- Handshake records are labeled by known handshake type when identifiable.
- `ClientHello`, `ServerHello`, and `Certificate` items can expose a richer Protocol text block when the bounded Stream bytes contain enough complete handshake data.
- Incomplete trailing TLS data falls back conservatively to partial TLS labels.

Typical labels include:

- `TLS ClientHello`
- `TLS ServerHello`
- `TLS Certificate`
- `TLS AppData`
- `TLS Payload (partial)`
- `TLS Record Fragment (partial)`

### HTTP

HTTP Stream parsing is header-oriented and may use bounded directional reassembly.

- Complete request and response header blocks are recognized in byte order.
- A request or response spanning multiple TCP packets may become one logical item if enough bytes are present in the bounded reassembly buffer.
- HTTP remains rebuild-based for now and does not yet use a retained continuation scanner.
- Message labels are derived from request line or response status when available.
- HTTP body reconstruction is intentionally incomplete as a general model.
- Stream currently recognizes enough body framing to continue across some complete messages, but it is not a general HTTP body-reconstruction subsystem.

Typical labels include:

- `HTTP GET /`
- `HTTP 200 OK`
- `HTTP Payload (partial)`

### Generic TCP fallback

When TCP payload is not recognized as a supported protocol-aware Stream item, the fallback remains packet-payload oriented.

- Label: `TCP Payload`
- One packet typically maps to one generic fallback item.
- This remains true even if a richer transport-correct interpretation would be possible in a future design.

### UDP fallback

Generic UDP behavior remains packet-payload oriented.

- Label: `UDP Payload`
- No UDP reassembly model is applied for Stream.

### DNS

DNS is currently packet-level only in Stream.

- In deep protocol-detail paths it may become `DNS Query` or `DNS Response`.
- Outside that path it remains generic UDP payload.
- There is no DNS transaction-level or multi-packet Stream model.

### QUIC

QUIC now has a first narrow selected-flow labeling step, but not a full Stream reconstruction model.

- QUIC packets may be labeled as `QUIC Initial`, `QUIC Handshake`, `QUIC Retry`, `QUIC Version Negotiation`, or `QUIC Protected Payload` when packet bytes support reliable header typing.
- Where plaintext frame bytes are directly parseable, the same bounded selected-flow path may refine a packet-sized item to `QUIC ACK` or `QUIC CRYPTO`.
- When the current packet-sized QUIC CRYPTO bytes directly expose a parseable TLS `ClientHello` or `ServerHello`, the item Protocol text may append the same narrow TLS handshake fields used by the TLS detail path.
- If bytes are incomplete or uncertain, QUIC traffic still falls back to `UDP Payload`.
- No QUIC decryption or session-wide reconstruction is introduced by this step.

## Partial and fallback behavior

Conservative fallback is preferred over producing a falsely complete Stream item.

Current partial and fallback labels include:

- `TLS Payload (partial)`
- `TLS Record Fragment (partial)`
- `HTTP Payload (partial)`
- `TCP Payload`
- `UDP Payload`

These labels usually mean one of the following:

- the bounded reassembly buffer does not contain enough bytes for a complete protocol unit
- trailing bytes do not match the expected next protocol structure
- transport quality is insufficient for a more specific interpretation
- the payload is outside currently supported protocol-aware Stream logic

## Known limitations

- No TCP-correct reconstruction.
- No general retransmission handling beyond exact duplicate TCP payload suppression.
- Out-of-order repair is not implemented.
- Overlap trimming is not implemented.
- QUIC Stream labeling is not implemented.
- Stream output may differ from Wireshark on captures with retransmissions, overlaps, reordering, or missing bytes.
- Long flows may be truncated by explicit packet or byte budgets.

## Future direction

Near-term Stream evolution is expected to stay incremental.

- broader retransmission suppression and handling in Stream construction
- more unified Stream build logic across initial build and continuation
- QUIC-aware Stream labeling
- richer TLS item labeling and protocol details

## Relationship to other docs

This document is the focused reference for the Stream subsystem.

- See `docs/architecture.md` for overall system boundaries and persistence policy.
- See `docs/reassembly-rfc.md` for the narrower contract and non-goals of bounded reassembly.
- See `docs/stream-baseline-test-plan.md` for current regression expectations and fixture-backed Stream behavior.
