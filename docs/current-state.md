# Current State

Pcap Flow Lab 0.3.0 is a flow-first packet-capture analyzer built around a
canonical bidirectional flow inventory, on-demand packet inspection, and
bounded selected-flow analysis.

## Inputs and session types

The current desktop and CLI product can open:

- raw `PCAP` captures;
- raw `PCAPNG` captures;
- saved Pcap Flow Lab analysis indexes (`.idx`).

Raw capture open/import builds the current canonical flow inventory from packet
metadata and bounded decode facts. Saved indexes reopen previously materialized
analysis state without reimporting the original capture.

Indexes are exact-version artifacts. The current stable index baseline is
revision `15`, with header inspection kept independent from full payload
compatibility. When the saved index revision or required section schemas are
not supported, the product requires rebuilding the index from the source
capture.

An index can open without the original source capture. In that index-only mode,
metadata-backed workflows remain available, but byte-backed inspection,
selected-flow reconstruction, and packet-writing export still depend on a valid
attached source capture.

## Flow model and grouping

The core interactive model is a canonical grouped bidirectional flow.

- Endpoints are grouped symmetrically for identity.
- User-facing `Endpoint A` / `Endpoint B` orientation comes from the first
  observed packet in the grouped flow.
- `A->B` and `B->A` therefore mean first-observed orientation, not inferred
  client/server roles.

Flow identity is protocol-path-aware. The grouped endpoint tuple is combined
with interned protocol-path identity so that namespace-bearing layers such as
overlay/tunnel identifiers can split otherwise identical endpoint tuples into
distinct canonical flows.

Raw capture import also supports two optional expert normalization modes:

- ignore VLAN/MPLS layers when grouping flows;
- ignore GTP-U TEIDs when grouping inner flows.

These settings affect canonical flow identity only at raw-import time. They do
not rewrite packet facts, Packet Details surfaces, or already-saved index
grouping.

## Import and open behavior

The normal open path is intentionally packet-oriented and predictable.

- Import computes packet metadata, packet references, grouped flow inventory,
  cheap protocol/service hints, and whole-capture counters.
- Production import now uses the unified registry-driven dissection path.
- The open path does not run global stream reconstruction or transport-complete
  reassembly.
- Whole-capture packet-size accounting is accumulated during import.
- Malformed, truncated, and unsupported packets are handled conservatively.

When the importer can accept a valid prefix of the input before later failure,
the session may still open partially with a warning rather than pretending that
trailing corrupted data was recovered successfully.

## Packet inspection

Selected-packet inspection is on demand.

`Packet Details` currently exposes:

- `Summary`
- `Bytes`

`Summary` is the structured packet-inspection surface. `Bytes` exposes
packet-owned and derived byte views for the selected packet when source bytes
are available.

Packet inspection is best-effort and conservative. Pcap Flow Lab can still
surface useful Frame / link / network / transport facts for malformed or
truncated packets, but it does not fabricate deeper protocol structure when
safe parseability stops.

## Selected-flow workflow

Flow inspection is split into `Packets`, `Stream`, and `Analysis` workflows.

### Packets

The selected-flow packet list is loaded incrementally and remains tied to the
current canonical flow orientation.

Packet metadata can remain visible from index-backed state, while byte-backed
packet inspection still depends on source capture availability.

### Stream

The Stream workflow is selected-flow only, bounded, and ephemeral.

- Stream rows are built on demand for the active flow.
- Results are not stored in the saved index.
- Current behavior is intentionally bounded rather than transport-complete.

`Stream Item Details` currently exposes:

- `Summary`
- `Item Data`

`Summary` is the structured stream-item inspection surface. `Item Data`
materializes authoritative item-owned bytes only when current ownership or
retained provenance exists.

Current protocol-aware Stream support is strongest for TLS and HTTP over TCP,
with bounded QUIC-related item inspection where parseable context exists.
Generic TCP/UDP cases still fall back to payload-oriented rows when no richer
specialization applies.

## Protocol-aware inspection

The current product exposes useful structured protocol inspection without
claiming universal deep parsing.

At a high level, current production behavior includes:

- structured packet `Summary` and byte-view inspection for recognized packets;
- bounded selected-flow TLS inspection;
- bounded selected-flow HTTP request/response reconstruction;
- structured DNS and mDNS inspection;
- bounded QUIC packet and selected-flow inspection with conservative limits.

Detailed protocol capability belongs in
`docs/protocols/protocol_support.md`, not in this overview.

## Analysis workspace

The Analysis workspace is selected-flow only.

It is metadata-driven and bounded. Current production behavior includes flow
overview, directional metrics, timeline/rate-style analysis, sequence preview,
and selected-flow histograms derived from packet metadata for the active flow.

Analysis does not imply global precomputation during open, and it does not
claim full transport-correct reconstruction.

## Statistics workspace

Statistics is whole-capture / whole-index oriented.

The current product exposes whole-session overview data plus structured
whole-capture statistics such as transport/family summaries, packet-size
distribution, flow-count histograms, protocol-path trees, detected-protocol
hints, QUIC/TLS summary views, and top endpoint/port summaries.

Optional heavier Statistics sections are loaded lazily and reuse cached results
for the current session.

## Export workflows

Pcap Flow Lab currently supports practical export workflows at both desktop and
CLI surfaces.

At a high level, current export behavior includes:

- saving reusable analysis indexes;
- packet/byte export from selected packet or selected stream-item byte-backed
  surfaces when authoritative bytes are available;
- flow export / Smart Export workflows that write packet data for selected
  canonical flows;
- export of unrecognized packets in the current Smart Export flow.

Byte-backed export still depends on readable source capture bytes.

## Application surfaces

Qt is the primary/reference desktop UI for Pcap Flow Lab 0.3.0.

The repository also contains:

- an experimental Tauri desktop frontend that shares the same backend/session
  architecture where behavior is already frontend-neutral;
- a public CLI with five top-level commands:
  - `summary`
  - `flows`
  - `export-flows`
  - `flow-info`
  - `packet-info`

These surfaces are different applications over the same core packet/import,
session, index, and presentation architecture.

## Current limitations

Important current limitations remain:

- selected-flow reconstruction is bounded and heuristic, not full TCP-correct
  reassembly;
- Stream artifacts and reassembly buffers are not persisted in indexes;
- raw packet bytes are not stored in indexes;
- index-only sessions remain useful for metadata, but byte-backed inspection
  and packet-writing export require the original source capture;
- QUIC inspection is useful but bounded, and is not a full QUIC session or
  HTTP/3 analyzer;
- protocol support is intentionally uneven across protocols and should be read
  from the dedicated protocol-support reference rather than inferred from the
  existence of one packet or stream surface.
