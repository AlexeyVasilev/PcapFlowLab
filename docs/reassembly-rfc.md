# Reassembly RFC

## Status

Current implementation exists and is intentionally narrow.

- `core/reassembly` provides bounded directional TCP payload concatenation.
- The current product uses it only for selected-flow, on-demand Stream analysis.
- It is not full TCP-correct reconstruction.
- It does not run during the fast path, summary computation, or index construction.

## Current scope

Reassembly is currently used to improve Stream item construction for a selected TCP flow direction.

- Input is a flow index, a direction (`A->B` or `B->A`), and explicit budgets.
- Output is a temporary buffer plus contributing packet indices and quality flags.
- Use is per-flow and per-request only.
- No session-wide or persistent stream cache is part of the current design.

## Bounded reassembly contract

Reassembly must always be bounded.

- Every request is limited by `max_packets` and `max_bytes`.
- Those limits apply equally to interactive Stream analysis.
- Reassembly is never allowed to become unbounded in memory use or latency.

## Architectural boundaries

Reassembly stays outside the fast path.

- Fast open remains packet-oriented.
- Open-time ingestion does not perform stream reconstruction.
- Index creation and checkpoint writing do not store reassembled buffers or stream artifacts.
- Stream analysis is an on-demand layer over already imported packet and flow metadata.

## Current uses in Stream

### TLS

TLS Stream parsing uses directional reassembly when available.

- Multiple TLS records inside one TCP payload are split into separate stream items.
- A TLS record spanning multiple TCP packets can appear as one logical stream item when the bounded reassembly buffer contains the full record.
- Incomplete trailing TLS data falls back conservatively to `TLS Record Fragment` or `TLS Payload`.

### HTTP

HTTP Stream parsing also uses directional reassembly, but only for header blocks.

- Complete HTTP request and response header blocks are recognized in byte order.
- A header block spanning multiple TCP packets can appear as one logical stream item when enough bytes are present in the bounded reassembly buffer.
- HTTP body parsing, content-length handling, and chunked decoding are intentionally out of scope.
- Incomplete or trailing non-header data falls back conservatively to `HTTP Payload`.

## Accuracy and diagnostic semantics

Current reassembly is heuristic.

- Payload bytes are concatenated in packet order.
- This is not a transport-correct TCP byte stream.
- Retransmissions, overlaps, and out-of-order repair are not implemented.
- Stream consumers must treat the result as best-effort data.

Quality flags are diagnostic only.

- Current flags cover packet-order-only reconstruction, packet or byte budget truncation, non-payload packets, possible transport gaps, and possible retransmissions.
- These signals describe approximation or limits in reconstruction.
- They must not be treated as ground truth about the network.

## Persistence policy

The project stores analysis results, not reconstructed streams.

Persisted:

- normal capture summary and flow state
- index/checkpoint metadata
- small final analysis results and flags, when explicitly added by a feature

Not persisted:

- reassembled byte buffers
- stream items shown in the UI
- packet contribution lists used only for Stream details
- temporary payload previews or other large derived artifacts

## Stream cache policy

Current Stream analysis remains ephemeral.

- Stream-view data is rebuilt for the selected flow on demand.
- Any cache is scoped only to the currently selected flow.
- It may be discarded at any time.
- It is a UI/performance optimization only, not part of system state.

## Non-goals of the current implementation

- no full TCP-correct reconstruction
- no retransmission modeling
- no overlap trimming
- no out-of-order repair
- no bidirectional message stitching
- no HTTP body reconstruction
- no chunked transfer decoding
- no QUIC stream reassembly yet
- no persistent stream artifacts
- no global execution across all flows during open

## Near-term limitations

- Long streams may be truncated by budget.
- Stream output may differ from Wireshark on captures with missing bytes, retransmissions, or reordering.
- Conservative fallback is preferred over a falsely complete item.
