# Stream Architecture

## Purpose

Stream is the bounded selected-flow semantic view.

- It materializes protocol-aware or conservative fallback items for one selected flow at a time.
- It is derived from imported flow metadata plus lazy reads from the source capture when source bytes are available.
- It is not persisted in indexes, checkpoints, or `CaptureState`.
- It is not part of capture open, import, summary construction, or index build.

In practice, Stream is an on-demand selected-flow analysis surface rather than a stored cross-session model.

## Core principles

- Selected-flow only: Stream work starts only after a flow is selected.
- On-demand only: no Stream materialization runs during fast open or index load.
- Ephemeral: results may be discarded and rebuilt whenever selection, bounds, or compatible session state changes.
- Bounded: every reconstruction-backed operation is constrained by explicit packet, item, and byte budgets.
- Conservative: current behavior is best-effort selected-flow analysis, not transport-correct session reconstruction.

These constraints are intentional. They keep Stream useful for interactive inspection without moving expensive transport analysis into global ingestion.

## Stream item model

Each visible Stream row is represented as a `StreamItemRow`.

- `stream_item_index`: 1-based item order within the current materialized Stream result.
- `direction_text`: `A→B` or `B→A`, based on canonical flow direction.
- `label`: user-facing classification such as `TLS ClientHello`, `HTTP 200 OK`, `DNS Query`, `QUIC Initial: CRYPTO`, `TCP Payload`, or `UDP Payload`.
- `byte_count`: byte size represented by the item.
- `packet_count`: number of packets contributing authoritative bytes to the item.
- `packet_indices`: contributing packet indices in capture order.

The model is intentionally narrow. A Stream item is a selected-flow presentation unit, not a fully retained protocol object.

Important ownership and presentation rules:

- `StreamItemRow` does not retain preformatted payload hex text.
- Stream labels, Summary semantics, and Item Data ownership come from retained structured item semantics and provenance.
- Explicit formatter or debug helpers may still exist elsewhere when intentionally consumed by other surfaces.
- Item Data hex formatting is produced on demand from authoritative owned bytes when that ownership exists.
- `FlowRow::protocol_text` remains a separate live field for flow-list behavior and is not the authority for Stream semantics.

## Materialization pipeline

Stream uses one bounded on-demand materialization pipeline owned by `CaptureSession`.

- The same protocol-aware builder is used for the initial selected-flow result and every later `Load more` refresh.
- Initial and extended views differ only by cumulative bounds, primarily packet window and item budget.
- The packet window is always a bounded prefix of the selected flow's packets: `[0, packet_window_count)`.
- The logical-item budget is cumulative inside protocol-aware reconstruction rather than a late frontend-only slice.
- Small flows may fit completely inside the initial bounds and appear fully materialized immediately.
- Larger flows yield partial results from the same builder.

`CaptureSession` owns one ephemeral selected-flow Stream context for the currently materialized bounded prefix.

- The context is selected-flow-only, capture-lifetime-only, and non-persistent.
- Qt and `FrontendSessionAdapter` / Tauri reuse this session-owned materialization; they do not carry independent Stream cursors or continuation tokens.
- The context records the materialized packet-window count, cumulative item limit, rows, ordering metadata, and row stability metadata.
- Compatible repeated requests may reuse the retained materialized result.
- Smaller compatible projections may reuse the retained prefix safely.
- Packet-window or item-budget growth currently rebuilds the larger bounded prefix from packet zero.

This is intentionally conservative: the system reuses compatible materialized results where that is safe, but it does not promise append-only continuation from a retained scanner frontier.

For selected-flow UI queries, the effective item budget includes one extra logical item of lookahead.

- If the visible limit is `N`, bounded Stream reconstruction materializes at most `N + 1` logical items for that query shape.
- The extra item is used only to determine whether `can_load_more` should remain true for the current packet window.
- Visible ordering and visible prefix content must match the corresponding prefix of the larger bounded rebuild.

Internally the materialized result is split into:

- a committed stable prefix;
- a provisional suffix beginning at the earliest unstable ordering position.

Window-incomplete rows remain provisional because a larger packet window may replace them with a completed structured item. Genuine gap rows, malformed terminal rows, and capture-constrained terminal rows remain stable.

### Load more

`Load more` is a cumulative bounded query, not a frontend append protocol.

- The controller increases selected-flow packet and item budgets.
- `CaptureSession` reevaluates that larger cumulative Stream shape.
- Larger cumulative bounds currently trigger a safe bounded rebuild from packet zero.
- Compatible repeated requests and smaller compatible projections may still reuse the retained materialized result.
- No frontend cursor token or persisted continuation checkpoint is introduced.

## Caching and source-byte requirements

Current Stream analysis depends on source-capture bytes.

- If the session lacks accessible source capture bytes, byte-backed Stream reconstruction is unavailable.
- Selected-flow Stream work may prepare ephemeral selected-flow packet caches and full-packet caches as performance helpers.
- Those caches are selected-flow-scoped, runtime-only, and discardable.
- They are not persisted and do not imply all-flow background reconstruction.

The current architecture therefore has caching, but only in a narrow selected-flow sense:

- packet-byte caches may avoid rereading packet bytes for compatible selected-flow work;
- retained Stream context may avoid recomputing an already materialized compatible bounded prefix;
- larger cumulative bounds still rebuild the larger bounded prefix safely.

## Reassembly usage

Stream uses bounded directional TCP reassembly only as a local selected-flow helper.

- Directional only: one request handles one flow direction at a time.
- Packet-order concatenation only: payload bytes are appended in observed packet order.
- Exact duplicate TCP payload contributions may be suppressed when selected-flow suppression context marks them reliably.
- Duplicate-prefix trimming may also suppress already-accounted leading bytes where selected-flow TCP contribution metadata proves the trim is authoritative.
- The same bounded reassembly-assisted path is used whether Stream is partial or expanded by `Load more`.
- No transport-correct overlap repair is implemented.
- No out-of-order repair is implemented.
- Partial results are normal when budgets, gaps, fragmentation boundaries, or missing bytes intervene.

Reassembly quality flags are diagnostic. They describe approximation, suppression, or incompleteness; they do not make the result TCP-correct.

## Protocol-specific behavior

### TLS

TLS Stream parsing is record-oriented and may use bounded directional reassembly.

- Multiple TLS records inside one TCP payload are split into separate Stream items.
- A TLS record spanning multiple TCP packets may become one logical item if the bounded reassembly buffer contains the full record.
- Packet-window growth may replace an earlier window-incomplete TLS projection with a completed row when newly authorized packets finish the record.
- Handshake records are labeled by known handshake type when identifiable.
- Alert records surface alert-specific details when reliably parsed.
- Incomplete trailing TLS data falls back conservatively to partial labels.

Typical labels include:

- `TLS ClientHello`
- `TLS ServerHello`
- `TLS Certificate`
- `TLS CertificateRequest`
- `TLS ServerHelloDone`
- `TLS CertificateVerify`
- `TLS NewSessionTicket`
- `TLS ChangeCipherSpec`
- `TLS Alert`
- `TLS AppData`
- `TLS Payload (partial)`
- `TLS Record Fragment (partial)`
- `TLS Gap`

### HTTP

HTTP Stream parsing is bounded request/response-oriented and may use directional reassembly.

- Complete request and response messages are recognized in byte order when bounded available bytes make message boundaries authoritative.
- A request or response spanning multiple TCP packets may become one logical item if enough bytes are present in the bounded reassembly buffer.
- Message labels are derived from request line or response status when available.
- The current implementation traverses `Content-Length` and supported chunked framing far enough to continue across complete messages and retain honest message ownership.
- This is still not a general HTTP body-decoding or application-level reconstruction subsystem.
- Incomplete trailing or post-gap data falls back conservatively to partial payload rows or explicit gap rows.

Typical labels include:

- `HTTP GET /...`
- `HTTP 200 OK`
- `HTTP Payload (partial)`
- `HTTP Gap`
- `HTTP Payload`

### Generic TCP fallback

When TCP payload is not recognized as a supported protocol-aware Stream item, the fallback remains packet-payload oriented.

- Label: `TCP Payload`
- One packet typically maps to one generic fallback item.
- This remains true even if a richer transport-correct interpretation might be possible in some future design.

### UDP fallback

Generic UDP behavior remains packet-payload oriented.

- Label: `UDP Payload`
- No generic UDP reassembly model is applied for Stream.

### DNS and mDNS

DNS and mDNS currently have packet-local structured Stream rows where the packet bytes support reliable classification.

- Supported labels include `DNS Query`, `DNS Response`, `mDNS Query`, and `mDNS Response`.
- This is still not a transaction-pairing or multi-packet DNS stream model.
- Unsupported or uncertain UDP payloads still fall back conservatively to `UDP Payload`.

### QUIC

QUIC Stream semantics are implemented in a bounded shell-aware, packet-local model rather than a full session reconstruction model.

- QUIC packets may surface shell-oriented rows such as `QUIC Version Negotiation`, `QUIC Retry`, `Handshake`, `Protected payload`, `0-RTT`, or coarse `QUIC Initial`.
- Where reliable Initial plaintext semantics are available, the same bounded selected-flow path may refine rows to labels such as `QUIC Initial: ACK` or `QUIC Initial: CRYPTO`.
- Standalone `PADDING` and `PING` do not become Stream items.
- One UDP packet may yield multiple QUIC semantic units when those units are reliably distinguished.
- Bounded QUIC details may append TLS-over-CRYPTO handshake semantics when those derived bytes are authoritative.
- This does not introduce full QUIC session reconstruction, generic QUIC stream reassembly, decryption-backed session modeling, or HTTP/3 analysis.

## Partial and fallback behavior

Conservative fallback is preferred over a falsely complete Stream item.

Current partial and fallback labels include:

- `TLS Payload (partial)`
- `TLS Record Fragment (partial)`
- `TLS Gap`
- `HTTP Payload (partial)`
- `HTTP Gap`
- `TCP Payload`
- `UDP Payload`

These labels usually mean one of the following:

- the bounded available bytes do not contain enough data for a complete protocol unit
- earlier transport bytes are missing or the bounded helper stopped at a gap boundary
- transport quality is insufficient for a more specific interpretation
- the payload is outside currently supported protocol-aware Stream logic

## Current limits

- No full TCP-correct reconstruction.
- No general overlap repair.
- No out-of-order repair.
- No full DNS transaction model.
- No full QUIC session reconstruction or HTTP/3 parsing.
- Stream output may differ from Wireshark on captures with retransmissions, overlaps, reordering, or missing bytes.
- Long flows may be truncated by explicit packet or byte budgets.

## Relationship to other docs

This document is the focused reference for the Stream subsystem.

- See `docs/architecture.md` for overall system boundaries and persistence policy.
- See `docs/reassembly-rfc.md` for the narrower contract and non-goals of bounded reassembly.
- See `docs/selected-flow-contract.md` for the selected-flow packet/stream/details contract.
