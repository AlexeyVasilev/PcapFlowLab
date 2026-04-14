# Architecture

Pcap Flow Lab is a flow-first packet-capture analyzer. The persistent model is packet and flow metadata; richer Stream analysis is derived on demand for the currently selected flow and is not part of the saved state.

## Main components

- `core/io`: classic PCAP and current PCAPNG readers, random-access packet reads, and classic PCAP export.
- `core/decode`: packet-oriented link and network decoding for ingestion.
- `core/domain`: connection keys, packet references, runtime flows, summaries, and related lightweight types.
- `core/services`: capture import, flow aggregation, packet inspection, exports, protocol analyzers, and developer-only perf logging.
- `core/index`: sectioned binary index and checkpoint formats with exact-version loading.
- `core/reassembly`: bounded directional reassembly helpers used only for on-demand analysis.
- `app/session`: application-facing entry point for opening captures/indexes and for flow, packet, and stream queries.
- `ui`: Qt Quick desktop UI over the session layer.

## Runtime paths

### Fast path

The fast path is the default way to open a capture.

- Parses PCAP / PCAPNG packets and decodes packet metadata.
- Aggregates packets into bidirectional connections and per-direction flows.
- Populates summaries, flow rows, packet rows, cheap hints, fragmentation flags, and packet references.
- Optional weak fallback hints may classify otherwise unresolved TCP/UDP port 443 flows as `Possible TLS` / `Possible QUIC`; these remain presentation-level buckets distinct from confirmed TLS/QUIC detection.
- Does not run directional reassembly.
- Does not perform deep protocol reconstruction during open.
- Keeps work packet-oriented and predictable.
- If import fails after a strictly valid prefix has already been accepted, the session may still open partially with a warning; corrupted trailing data is discarded rather than recovered.

### Index path

Saved analysis indexes can be opened directly instead of re-importing the capture.

- The index stores capture summary, connections, flows, packet references, source metadata, and checkpointable analysis state.
- The binary format is explicitly sectioned and loaded with an exact-version policy.
- Raw packet bytes are not stored in the index.
- An index can be opened without the original capture; this is an explicit index-only mode.
- Raw packet features become available again only after the matching source capture is attached and validated.

### On-demand analysis

On-demand analysis is separate from the fast path and from index loading.

- Triggered only for the currently selected flow.
- Requires source capture access because packet bytes are still read lazily from the original capture.
- Builds ephemeral derived artifacts only for the active flow.
- Current user-facing use is the Stream tab.
- The selected-flow packet list may also carry ephemeral `Suspected retransmission` markers for exact duplicate payload-bearing TCP packets in the active flow only; these markers are not persisted and do not change open-time summaries or counts.
- Selected-flow Stream construction can suppress retransmitted packet contribution in the current bounded model; this remains presentation-oriented and does not imply transport-complete recovery.
- Analysis tab now also includes a bounded metadata-only Sequence Preview block for the selected flow.
- Analysis can also export the full selected-flow packet sequence to CSV as a metadata-only artifact without payload bytes.
- Analysis tab now also includes a bounded metadata-only Timeline block for the selected flow.
- Analysis tab now also includes a bounded metadata-only Packet Size Histogram block for the selected flow.
- Analysis tab now also includes a bounded metadata-only Inter-arrival Histogram block for the selected flow.
- Analysis tab now also includes a bounded metadata-only Derived Metrics block for the selected flow.
- Analysis tab now also includes a bounded metadata-only Directional Ratio block for the selected flow.
- Analysis tab now also includes a bounded metadata-only Flow Rate graph block for the selected flow (window-aggregated Data/s and Packets/s from packet timestamps, lengths, and direction only).
- Analysis tab block order is periodically reorganized for readability, with summary/interpretation blocks ahead of evidence/detail blocks; this does not change analysis logic.
- Never runs globally across all flows during open.

## Flow aggregation and packet model

- Connections use a canonical symmetric key for bidirectional grouping.
- Each runtime connection keeps separate `flow_a` and `flow_b` packet lists.
- `PacketRef` stores packet index, file offset, timestamp, captured/original lengths, transport payload length, TCP flags, link type, and fragmentation metadata.
- Packet bytes are loaded lazily when details, payload, protocol text, export, or stream analysis needs them.
- Selected-flow packet lists now use bounded initial materialization in the UI. Small flows that fit within the initial packet budget are materialized fully, while larger flows append additional rows only through explicit Load more continuation.
- Selected-flow packet rows may be annotated on demand with exact-duplicate TCP retransmission suspicion using direction + seq + ack + payload length + payload bytes. This remains flow-local, conservative, and presentation-oriented.
- Selected-flow Stream items now follow the same pattern: small flows that fit within the initial Stream budget are materialized fully, and heavier flows append additional items only through explicit Load more continuation.

## Stream items and directional reassembly

The Stream tab is a derived payload-oriented view, not a stored stream model.

- Stream items are built on demand for the selected flow only.
- Results are ephemeral and replaced when flow selection changes.
- No stream items are stored in `CaptureState`, indexes, or checkpoints.

Current Stream behavior:

- UDP stream items remain packet-payload based.
- Generic non-TLS / non-HTTP TCP fallback remains packet-payload based.
- TLS stream parsing uses bounded directional reassembly.
  - Multiple TLS records inside one TCP payload are split into separate stream items.
  - A TLS record spanning multiple TCP packets can appear as one logical stream item when the bounded reassembly buffer contains the full record.
  - Incomplete trailing TLS data falls back conservatively to `TLS Record Fragment` or `TLS Payload`.
- HTTP stream parsing uses bounded directional reassembly for requests and responses, including bodies assembled across multiple TCP segments when enough bytes are available.
  - Complete HTTP requests and responses can appear as one logical stream item even when assembled from many TCP packets.
  - `Content-Length` and chunked-body traversal are used to preserve bounded multi-segment continuity where parseability remains clear.
  - Incomplete or ambiguous data falls back conservatively rather than implying transport-complete recovery.
- QUIC selected-flow inspection provides meaningful bounded packet-aware parsing.
  - Practical frame-level details such as `CRYPTO`, `ACK`, and `PADDING` can be exposed in packet and Stream presentation when confidently isolated.
  - Parseable CRYPTO contents can surface handshake-aware TLS details such as `ClientHello` and `ServerHello` in bounded selected-flow contexts.
  - This remains conservative selected-flow inspection, not full QUIC reconstruction or decryption-backed analysis.

## Reassembly principles

Current reassembly is intentionally narrow.

- Directional: one flow direction (`A->B` or `B->A`) per request.
- Bounded: every request is limited by `max_packets` and `max_bytes`.
- Heuristic: packet-order payload concatenation, not transport-correct TCP reconstruction.
- Ephemeral: buffers and packet-contribution maps are built only for the current request.
- Local: used for selected-flow on-demand analysis, not for global open-time processing.

Reassembly results may be incomplete.

- Quality flags can report packet-order-only reconstruction, budget truncation, non-payload packets, possible transport gaps, and possible retransmissions.
- Those flags are diagnostic only; they are not ground truth about network correctness.

## Persistence boundaries

Persisted data:

- capture summary
- flows and connections
- packet references and packet-level metadata
- source capture metadata used for index attach validation
- checkpoint progress/state needed for chunked import resume

Not persisted:

- stream items
- partial-open session state and failure context
- corrupted trailing capture data beyond a strict partial-open prefix
- reassembled byte buffers
- per-flow temporary stream caches
- packet contribution maps used only for Stream presentation

## Developer-only instrumentation

Open-time performance logging is developer-only and off by default.

- Creating `perf-open.enabled` in the current working directory or next to the executable enables CSV logging.
- The log is written to `perf_open_log.csv`.
- It records application-level timing for `capture_fast`, `capture_deep`, and `index_load` opens.
- It does not change normal product behavior when disabled.

## UI list surfaces

Current large-list surfaces prefer virtualization-friendly QML views and comparatively lightweight delegates over pagination.

- Flow table uses `ListView` with fixed-height delegates and lazy vertical creation.
- Packet list uses `ListView` with fixed-height delegates and lazy vertical creation.
- Stream view uses `ListView`; it is also virtualized, although each delegate is visually heavier than a packet row.
- Explicit vertical scrollbars are enabled on these surfaces for usability.

Current scalability risks are still worth watching:

- Flow and packet rows use wide delegate trees with several formatted labels per visible row.
- The current flow table is vertically virtualized, but horizontal overflow is still handled by clipping rather than a dedicated horizontal-scrolling table model.
- Pagination is intentionally deferred until stronger evidence shows that current virtualization is insufficient.

## Known limitations

- No full TCP-correct stream reconstruction.
- TCP retransmission effects are only partially handled in Stream construction; retransmitted packets are suppressed in the current bounded selected-flow model, but full retransmission-aware recovery does not exist.
- HTTP Stream reconstruction is bounded and selected-flow-only; requests and responses, including bodies, can be assembled across multiple TCP segments, but recovery remains heuristic and not transport-complete.
- QUIC selected-flow inspection is meaningful but bounded; frame-level and handshake-aware details can be exposed, but full QUIC reconstruction and decryption remain out of scope.
- Bounded reassembly may truncate long streams.
- Stream view is ephemeral and may differ from Wireshark on captures with retransmissions, reordering, or missing bytes.
- Index and checkpoint loading use an exact-version policy; backward compatibility across format revisions is not guaranteed yet.







