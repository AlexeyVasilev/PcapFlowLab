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
- `label`: user-facing classification such as `TLS ClientHello`, `HTTP 200 OK`, `TCP Payload`, or `UDP Payload`.
- `byte_count`: byte size of the item payload represented by the row.
- `packet_count`: number of packets contributing bytes to the item.
- `packet_indices`: contributing packet indices in capture order.
- `payload_hex_text`: optional formatted payload preview for item-level details.
- `protocol_text`: optional protocol-oriented details text for item-level details.

The model is intentionally narrow. A Stream item is a presentation artifact for the selected flow, not a protocol object with lifecycle outside the current view.

## Stream materialization modes

Current Stream materialization has three practical modes.

### Full build within budget

If the selected flow is small enough, Stream items are materialized in one pass and the full current result fits within the initial item and packet budgets.

- This is the common path for small captures and small flows.
- No additional continuation step is needed.

### Packet-prefix build

For heavier flows, initial Stream construction uses a bounded packet window and a bounded item target.

- The first Stream result is intentionally partial.
- The goal is fast interactive startup for the selected flow rather than full immediate reconstruction.
- The initial result should still preserve stable item ordering within the scanned packet prefix.

### Load more

When the initial packet window or item budget is insufficient, the UI exposes explicit continuation.

- Additional Stream items are materialized only when the user asks for more.
- This extends the selected flow's current ephemeral Stream result.
- It does not retroactively change capture-wide state.
- It does not imply a persistent Stream cache.

## Reassembly usage

Stream uses reassembly only as a local helper for selected-flow analysis.

- Directional only: one request handles one flow direction at a time.
- Packet-order concatenation only: payload bytes are appended in observed packet order.
- No retransmission repair: duplicate payload is not currently removed from Stream reconstruction.
- No overlap trimming: overlapping sequence-space handling is not implemented.
- No out-of-order repair: reordered packets are not reassembled into transport-correct byte order.
- Partial results are allowed: budget exhaustion and incomplete trailing data are normal outputs, not exceptional states.

Reassembly quality flags are diagnostic. They describe approximation or incompleteness, but they do not make the result TCP-correct.

## Protocol-specific behavior

### TLS

TLS Stream parsing is record-oriented and may use bounded directional reassembly.

- Multiple TLS records inside one TCP payload are split into separate Stream items.
- A TLS record spanning multiple TCP packets may become one logical item if the bounded reassembly buffer contains the full record.
- Handshake records are labeled by known handshake type when identifiable.
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

QUIC does not currently have a dedicated Stream model.

- QUIC traffic stays on the generic UDP Stream path.
- Flow-level QUIC recognition does not imply QUIC-specific Stream labeling.

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
- Retransmissions are not handled by Stream reconstruction yet.
- Out-of-order repair is not implemented.
- Overlap trimming is not implemented.
- QUIC Stream labeling is not implemented.
- Stream output may differ from Wireshark on captures with retransmissions, overlaps, reordering, or missing bytes.
- Long flows may be truncated by explicit packet or byte budgets.

## Future direction

Near-term Stream evolution is expected to stay incremental.

- retransmission detection and optional suppression in Stream construction
- more unified Stream build logic across initial build and continuation
- QUIC-aware Stream labeling
- richer TLS item labeling and protocol details

## Relationship to other docs

This document is the focused reference for the Stream subsystem.

- See `docs/architecture.md` for overall system boundaries and persistence policy.
- See `docs/reassembly-rfc.md` for the narrower contract and non-goals of bounded reassembly.
- See `docs/stream-baseline-test-plan.md` for current regression expectations and fixture-backed Stream behavior.