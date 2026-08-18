# Flow Aggregate Metadata RFC

Status: runtime foundation and stable v15 index persistence are implemented;
PacketRef compaction remains proposed.

This document defines the compact aggregate metadata foundation proposed for
future indexed flow filtering and related metadata queries.

Related RFCs:

- [Advanced Flow Filter RFC](advanced-flow-filter-rfc.md)
- [Index v15 Container RFC](index-v15-container-rfc.md)

## Goal

The goal is to support future flow filtering and index-backed metadata queries
without requiring repeated scans over all persisted `PacketRef` entries for
ordinary filter evaluation.

The intended direction is:

- keep aggregate ownership on canonical `ConnectionV4` / `ConnectionV6`
- avoid a separate global metadata lookup table if practical
- persist only compact authoritative aggregates
- derive higher-level or ratio-based predicates in O(1)

## Current State

### Verified current per-packet persistent state

Current `PacketRef` fields are:

- `packet_index`
- `byte_offset`
- `data_link_type`
- `captured_length`
- `original_length`
- `ts_sec`
- `ts_usec`
- `payload_length`
- `tcp_flags`
- `is_ip_fragmented`

Current stable v15 serialized `PacketRef` layout writes:

- `u64 packet_index`
- `u32 ts_sec`
- `u32 ts_usec`
- `u64 byte_offset`
- `u32 data_link_type`
- `u32 captured_length`
- `u32 original_length`
- `u32 payload_length`
- `u8 tcp_flags`
- `u8 is_ip_fragmented`

Current serialized size is therefore 42 bytes per packet ref.

Current in-memory `sizeof(PacketRef)` is runtime/ABI-dependent. On a typical
64-bit build with 8-byte alignment, the current field layout is expected to be
approximately 48 bytes because of tail padding.

### Verified current per-flow / per-connection state

Current `FlowV4` / `FlowV6` already store:

- directional packet refs
- directional packet count
- directional original-byte total

Current `ConnectionV4` / `ConnectionV6` already store:

- total packet count
- total original-byte total
- `has_fragmented_packets`
- `fragmented_packet_count`
- `protocol_hint`
- `service_hint`
- `quic_version`
- `tls_version`
- directional `flow_a` / `flow_b`
- `ConnectionAggregateStats` populated during recognized-packet insertion for
  raw/imported captures and persisted by the stable v15 index

### Verified current serialization state

Current index serialization persists:

- connection packet count
- connection total original bytes
- `has_fragmented_packets`
- `fragmented_packet_count`
- `protocol_hint`
- `service_hint`
- `quic_version`
- `tls_version`
- `ConnectionAggregateStats`
- connection-level captured-byte totals
- first/last timestamps
- truncated-packet count
- packet-size extrema
- TCP SYN/FIN/RST counts
- directional `FlowV4` / `FlowV6`, including packet counts, total original
  bytes, and all packet refs

Current index serialization does not persist:

- `hint_search_state`

### Existing data that already makes some proposed fields redundant

The following already exist and should not be duplicated unless implementation
constraints force it:

- total packet count
- total original bytes
- A->B packet count
- B->A packet count
- A->B original bytes
- B->A original bytes
- fragmented packet count
- protocol hint
- service hint
- Protocol Path identity
- endpoint identity and ports

### Existing data currently derived by rescanning packet refs

Current code derives the following by iterating packet refs:

- captured-byte totals
- first/last timestamps
- duration
- average packet size
- packets/sec
- original-byte data rate
- packet-direction and byte-direction ratios / dominance
- TCP SYN/FIN/RST counts
- max original packet length
- max captured packet length
- min packet lengths used by Analysis

## Proposed V1 Aggregate Foundation

The current preferred compact aggregate set for each canonical connection is:

```cpp
struct ConnectionAggregateStats {
    uint64_t first_timestamp_us;
    uint64_t last_timestamp_us;
    uint64_t captured_bytes;
    uint64_t truncated_packet_count;
    uint64_t tcp_syn_count;
    uint64_t tcp_fin_count;
    uint64_t tcp_rst_count;
    uint32_t max_original_packet_length;
    uint32_t max_captured_packet_length;
};
```

This exact structure and field order are not yet final.

The intent is:

- enough authoritative source data to answer v1 filter families in O(1)
- no duplication of already-persisted directional packet/original-byte counts
- no persistence of obviously derived rates or ratios

Current runtime semantics for the implemented foundation are:

- `first_timestamp_us` is the minimum observed packet timestamp, not first
  insertion order
- `last_timestamp_us` is the maximum observed packet timestamp
- packet timestamp is `ts_sec * 1_000_000 + ts_usec`
- TCP counters count packets where the corresponding bit is set
- SYN+ACK contributes to `tcp_syn_count`
- non-TCP packets do not affect TCP control counters

## Current Implementation Stage

Implemented now:

- `ConnectionAggregateStats` owned on canonical
  `ConnectionV4` / `ConnectionV6`
- aggregate updates during normal recognized-packet insertion for raw/imported
  captures
- stable v15 persistence for `quic_version`, `tls_version`, and
  `ConnectionAggregateStats`

Still pending:

- PacketRef compaction
- broader consumer migration from packet-ref rescans to the new aggregate
  structure

Current transient-migration stage now avoids relying on persistent
`PacketRef::payload_length`, `PacketRef::tcp_flags`, and
`PacketRef::is_ip_fragmented` in source-backed selected-flow packet-list
presentation, selected-packet details/checksum preparation, and bounded
selected-flow cache/reassembly/TLS/QUIC helpers. Those paths derive packet
metadata from authoritative packet bytes at runtime while leaving stable v15
serialization unchanged.

FlowAnalysis now uses `ConnectionAggregateStats` for:

- captured-byte totals
- first/last timestamp bounds and derived duration
- TCP SYN/FIN/RST counts
- maximum original packet length
- maximum captured packet length

FlowAnalysis still intentionally scans ordered `PacketRef` collections for:

- packet-size histograms
- minimum packet lengths
- inter-arrival/gap/burst calculations
- rate graph generation
- sequence preview rows

## Derived Data

The following should remain derived rather than persisted:

- `duration = last_timestamp_us - first_timestamp_us`
- `average original packet size = total_original_bytes / total_packet_count`
- `packets/sec = total_packet_count / duration`
- `average original-byte data rate = total_original_bytes / duration`
- unidirectional / bidirectional from directional packet counts
- packet ratio / dominance from directional packet counts
- byte ratio / dominance from directional original-byte counts
- `has_fragmented_packets = fragmented_packet_count != 0`
- `has_truncated_packets = truncated_packet_count != 0`
- known / unknown detected protocol from `protocol_hint`
- known / unknown service from `service_hint`

These are all O(1) derivations from already stored or newly proposed
authoritative aggregates.

## Deferred

The following possible aggregates are explicitly deferred:

- minimum original packet length
- minimum captured packet length
- largest packet gap
- TCP SYN+ACK count
- broader TCP ACK/PSH-family counters
- directional captured-byte totals
- ALPN
- detailed TLS handshake characteristics
- retransmission / out-of-order metadata
- arbitrary packet-content predicates

Rationale:

- each additional persisted field increases object size, serialized size,
  migration surface, and implementation complexity
- "might be filterable someday" is not sufficient reason to store metadata now
- v1 should optimize for the smallest stable aggregate set that answers the
  planned initial product scope

## Proposed Ownership Direction

Current preferred direction:

- aggregate metadata should be owned directly by canonical
  `ConnectionV4` / `ConnectionV6`
- avoid a separate hash table or detached global metadata store if possible
- keep existing packet-count / original-byte / fragmentation fields in their
  current locations initially to avoid unnecessary churn

Benefits:

- no second identity lookup layer
- simpler serialization ownership
- easier reasoning about what belongs to a canonical connection

Open design possibility:

- a later cleanup may consolidate older aggregate fields and newer aggregate
  fields into one clearer nested structure
- this later cleanup is not required for the initial metadata-foundation pass

## Persistent PacketRef Compaction: Proposed Direction

This is a proposed direction, not an approved code change.

The current investigation target is removing these fields from the persistent
`PacketRef` representation:

- `payload_length`
- `tcp_flags`
- `is_ip_fragmented`

### 1. `tcp_flags`

Current state:

- flow-level TCP SYN/FIN/RST counts are currently recomputed by scanning
  `packet.tcp_flags` in `FlowAnalysisService`
- packet-list/frontends currently expose `tcp_flags_text`
- flow/packet CSV export surfaces currently emit TCP flags text derived from
  persisted `PacketRef`

Proposed direction:

- flow-level TCP filter and Analysis needs should move to import-time
  aggregates such as `tcp_syn_count`, `tcp_fin_count`, and `tcp_rst_count`

Trade-off:

- if per-packet TCP flags are removed from persistent `PacketRef`, an index-only
  session without readable source capture may no longer be able to show TCP
  flags for an individual packet using only persisted metadata

### 2. `is_ip_fragmented`

Current state:

- connection-level fragmentation filter needs can already use
  `fragmented_packet_count`
- packet-level warnings, packet-list/frontends, checksum suppression paths, and
  reassembly gatekeeping currently consult `packet.is_ip_fragmented`

Proposed direction:

- flow-level fragmentation filtering should use connection aggregates
- per-packet fragmentation can be decoded from source packet bytes when source
  capture bytes are available

Trade-off:

- if per-packet fragmentation is removed from persistent `PacketRef`, index-only
  UI behavior that currently shows per-packet fragmentation warnings/flags
  would no longer be available without additional stored metadata or a revised
  product contract

### 3. `payload_length`

Current state:

- import and hint-detection paths currently use `payload_length`
- selected-packet/frontends currently show payload length fields using
  `packet.payload_length`
- reassembly and selected-flow TCP/TLS/QUIC materialization paths use
  `payload_length` for non-payload skipping, gap detection, and byte-budget
  reasoning
- the repository already contains source-byte-based helper functions such as
  `derive_captured_transport_payload_length_from_headers(...)` and
  `derive_original_transport_payload_length_from_headers(...)`

Proposed direction:

- do not assume that removing persistent `payload_length` means deleting the
  information from import/decode
- this value may remain necessary transiently in import/decode metadata
- persistent storage should only keep it if index-only behavior still requires
  it after product review

## Existing Behavior That Would Break If Persistent PacketRef Fields Were Removed

The following current behaviors rely on persistent packet-level fields and must
be reviewed before implementation:

### If persistent `tcp_flags` is removed

- selected-flow Analysis TCP SYN/FIN/RST counts as currently implemented in
  `FlowAnalysisService`
- packet-list TCP flags presentation
- frontend/Qt/Tauri/CLI packet rows and CSV exports that surface TCP flags text
- packet-level index-only views that currently read flags from `PacketRef`

### If persistent `is_ip_fragmented` is removed

- packet-list fragmented flag presentation
- packet-summary warning lines that currently say "Packet is IP-fragmented"
- checksum-warning suppression paths that branch on per-packet fragmentation
- reassembly gating that currently stops when a packet is marked fragmented
- any index-only per-packet fragmentation UI semantics

### If persistent `payload_length` is removed

- packet-list payload-length presentation
- packet-summary / frontend text that currently prints transport payload length
  from `PacketRef`
- reassembly and selected-flow TCP/TLS/QUIC logic that currently uses
  `packet.payload_length` as authoritative persisted metadata
- index-only packet/stream semantics that currently depend on stored payload
  length when source bytes are not accessible

## Approximate Size Impact

### Serialized PacketRef

Current serialized `PacketRef` size:

- 42 bytes

Approximate serialized size after removing:

- `payload_length` (4 bytes)
- `tcp_flags` (1 byte)
- `is_ip_fragmented` (1 byte)

Proposed serialized size:

- 36 bytes

Approximate saving:

- 6 serialized bytes per packet ref

### Runtime PacketRef

Current runtime size is ABI/alignment dependent.

Typical 64-bit expectation:

- current layout: approximately 48 bytes
- without those three fields: approximately 40 bytes

Approximate saving:

- about 8 runtime bytes per packet ref on a typical 64-bit build

This is an approximation, not an ABI guarantee.

## Open Questions

- Should the new aggregate structure be introduced as a nested sub-struct
  immediately, or should the first implementation place the new fields directly
  on `ConnectionV4` / `ConnectionV6` and normalize ownership later?
- Should `has_fragmented_packets` remain as an explicit persisted boolean for
  compatibility/readability, or eventually be derived everywhere from
  `fragmented_packet_count != 0`?
- Is `truncated_packet_count` sufficient for v1, or do we also need a compact
  `has_truncated_packets` boolean in memory only for convenience?
- Should TCP control counts be persisted only at the total-connection level, or
  is there any future-product requirement for directional SYN/FIN/RST counts?
- Should captured-byte totals remain aggregate-only, or is any future feature
  likely to require directional captured-byte totals early enough to justify
  storing them now?

## Risks To Resolve Before Production Implementation

- Removing persistent packet-level fields without an explicit index-only product
  contract risks silent regressions in packet list, packet details, and stream
  presentation.
- If QUIC/TLS version filtering is part of v1 product scope, version hints must
  move from in-memory-only connection state into persisted index metadata.
- Reusing packet-ref scans for multiple future filters would undermine the
  stated purpose of this metadata-foundation work.
- Overgrowing the aggregate struct with speculative fields would increase
  migration cost and serialized size before product value is proven.
