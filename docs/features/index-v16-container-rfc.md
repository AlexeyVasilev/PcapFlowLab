# Index v16 Container RFC

Status: planned and frozen target architecture for the next stable-index
migration.

Current production behavior remains the active stable v15 reader/writer until
the v16 migration is implemented.

Related RFCs:

- [Index v15 Container RFC](index-v15-container-rfc.md)
- [Statistics, Reporting, and Large-Index Architecture RFC](statistics-reporting-index-rfc.md)
- [Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md)
- [Analysis](../analysis-tab.md)
- [Presentation Contract](../ui/presentation_contract.md)

## Purpose

This document freezes the intended stable v16 index architecture before Stage
4 implementation begins.

It records:

- the outer-container compatibility boundary
- the exact planned early/metadata/detail section topology
- the fast Statistics snapshot payload scope
- the selected-flow lazy `PacketRef` architecture boundary
- the late unrecognized-detail and packet-locator boundaries

This is a target wire-format contract, not an implementation claim.

## Frozen Outer Container Identity

The stable outer container remains:

- magic: `PFLIDXV1`
- `container_format_version = 1`
- `index_revision = 16`

### Why the stable revision changes

Although the container header and per-section schema pattern remain the same,
v16 intentionally introduces a different physical architecture:

- a new early Statistics tier
- new metadata/detail separation
- new section families and IDs
- no stable requirement to preserve the old v15 full-payload layout

For that reason, Stage 4 uses a deliberate rebuild-required stable revision
boundary rather than trying to make the v16 reader load v15 payloads through
legacy section-family fallback.

### Compatibility policy

The frozen compatibility policy is:

- stable-header inspection remains independent of payload compatibility
- v16 full payload loading requires the v16 section families defined here
- v15 full payload loading remains the responsibility of the current v15
  reader path until the migration cutover is intentionally replaced
- a future v16-only production reader is allowed to reject v15 payload loading
  with a rebuild-required diagnostic

This freeze does not require a legacy fallback loader for v15 payloads once
the v16 migration becomes active.

## Stable Header

The stable header remains the authoritative lightweight inspection surface.

It continues to carry source/index identity data such as:

- writer application version
- source capture format
- source file size
- source last-write time
- source content fingerprint
- source capture path

Statistics/reporting must combine that existing source/header authority with
the v16 Statistics snapshot where needed. Source metadata is not duplicated
into the Statistics snapshot.

## Stable Section Header

Every stable payload section continues to use the same 16-byte section header:

- `u32 section_id`
- `u16 section_schema_version`
- `u16 section_flags`
- `u64 payload_size`

Section flag bit 0 remains the required-section bit.

## Frozen v16 Physical Order

The exact v16 physical order is:

1. Stable header
2. Fast Statistics tier
   - `capture_statistics_snapshot`
   - `protocol_path_registry_early`
   - `protocol_path_terminal_aggregates`
3. Fast read boundary
4. Flow metadata tier
   - `ipv4_flow_metadata`
   - `ipv6_flow_metadata`
   - `protocol_path_membership`
   - `packetref_directory`
   - `unrecognized_directory`
5. Detail tier
   - `packetref_detail_blocks`
   - `unrecognized_reason_blobs`
   - `packet_locator`

The fast reader is allowed to stop after the fast Statistics tier. Successful
fast-tier validation does not imply that later metadata or detail sections are
valid.

## Frozen v16 Section Families

v15 section IDs `2` through `7` are not reused in v16 because their old names
and payload meanings would be misleading under the new architecture.

The frozen v16 section-family table is:

| ID | Symbolic name | Required | Tier | Schema | Repeatable / chunked | Ordering dependency |
| --- | --- | --- | --- | --- | --- | --- |
| 8 | `capture_statistics_snapshot` | yes | fast Statistics | 1 | no | none |
| 9 | `protocol_path_registry_early` | yes | fast Statistics | 1 | no | after `capture_statistics_snapshot` |
| 10 | `protocol_path_terminal_aggregates` | yes | fast Statistics | 1 | yes | after `protocol_path_registry_early` |
| 11 | `ipv4_flow_metadata` | yes | flow metadata | 1 | yes | after fast Statistics tier |
| 12 | `ipv6_flow_metadata` | yes | flow metadata | 1 | yes | after fast Statistics tier |
| 13 | `protocol_path_membership` | yes | flow metadata | 1 | yes | after `protocol_path_registry_early` and flow metadata ordinals |
| 14 | `packetref_directory` | yes | flow metadata | 1 | yes | after IPv4/IPv6 flow metadata ordinals are defined |
| 15 | `unrecognized_directory` | yes | flow metadata | 1 | yes | after fast Statistics tier |
| 16 | `packetref_detail_blocks` | yes | detail | 1 | yes | after `packetref_directory` |
| 17 | `unrecognized_reason_blobs` | yes | detail | 1 | yes | after `unrecognized_directory` |
| 18 | `packet_locator` | yes | detail | 1 | yes | after metadata and unrecognized detail sections |

All v16 section families are required, even when their logical row count is
zero.

## Capture Statistics Snapshot

`capture_statistics_snapshot` is the authoritative fast-tier whole-capture
Statistics payload.

It stores raw facts only. It does not store formatted timestamps, formatted
byte strings, percentages, UI section labels, or localized text.

### Frozen completeness / partial-import provenance

The snapshot contains one small versionable completeness field:

- `CaptureStatisticsScope` encoded as `u8`

Frozen numeric encoding:

- `0 = complete`
- `1 = partial`
- `2 = reserved_unknown`

Writers should emit:

- `complete` for fully surfaced/imported captures
- `partial` when Statistics describe only the successfully surfaced/imported
  packet set

`reserved_unknown` exists as the explicit versioned escape hatch. This RFC
does not freeze presentation wording for that state.

### Frozen packet-level raw fields

The snapshot must include the following packet-level raw facts:

- `packet_count`
- `flow_count`
- `captured_bytes`
- `original_bytes`
- `has_packet_time_range`
- `earliest_packet_timestamp_us`
- `latest_packet_timestamp_us`
- `truncated_packet_count`
- `maximum_captured_packet_length`
- `maximum_original_packet_length`
- captured packet-size histogram bucket packet counts
- original packet-size histogram bucket packet counts
- `unrecognized_packet_count`
- `unrecognized_captured_bytes`
- `unrecognized_original_bytes`

These facts describe the surfaced/imported packet set, including unrecognized
packets where applicable.

### Frozen flow-derived raw fields

The snapshot must also include the raw whole-capture flow-derived facts needed
for Statistics, reporting, and fast summary rendering:

- IPv4 summary counts/bytes
- IPv6 summary counts/bytes
- TCP summary counts/bytes
- UDP summary counts/bytes
- SCTP summary counts/bytes
- Other-transport summary counts/bytes
- raw protocol-recognition category counters in a setting-independent form
- flow packet-count histogram bucket flow counts
- flow packet-count histogram bucket captured-byte totals
- flow packet-count histogram bucket original-byte totals
- `only_a_to_b_flow_count`
- `service_recognized_flow_count`
- packet-direction distribution flow counts
- original-byte-direction distribution flow counts
- whole-capture TCP `SYN` packet count
- whole-capture TCP `FIN` packet count
- whole-capture TCP `RST` packet count
- QUIC recognition/version counters
- TLS recognition/version counters

### Frozen protocol-hint representation

The persisted protocol-recognition representation must remain raw and
setting-independent.

It must support future presentation with both:

- `use_possible_tls_quic = true`
- `use_possible_tls_quic = false`

without rescanning flow metadata.

The frozen design is:

- whole-capture protocol-recognition counters are stored as raw category
  counters equivalent in meaning to the current shared `CaptureProtocolSummary`
  categories
- top-flow rows store raw `protocol_hint` plus `flow_protocol` and endpoint
  ports so the shared frontend projection can reproduce the setting-dependent
  detected-protocol presentation from fast-tier data alone

The Statistics snapshot does not store preformatted detected-protocol strings.

## Frozen Top Endpoint / Top Port / Top Flow Payloads

### Top-K limits

The fast Statistics tier stores:

- up to `20` top endpoint rows
- up to `20` top port rows
- up to `10` top flow rows

More than `20` top endpoints or ports is not part of the fast-tier contract.

### Top endpoint row

Each persisted top endpoint row contains:

- `address_family`
- raw endpoint address
- endpoint port
- `flow_count`
- `packet_count`
- `captured_bytes`
- `original_bytes`

`captured_bytes` is intentionally included for top endpoints despite not being
required by today's default UI tables because the row set is bounded and the
field is useful for future reporting and CLI expansion.

### Top port row

Each persisted top port row contains:

- port
- `flow_count`
- `packet_count`
- `captured_bytes`
- `original_bytes`

`captured_bytes` is likewise intentionally included here for the same bounded
future-use reason.

### Top flow row

Each persisted top flow row contains:

- zero-based canonical connection ordinal
- address family
- raw canonical connection key representation
- Endpoint A raw identity
- Endpoint B raw identity
- flow protocol
- raw protocol hint
- raw service hint text
- `protocol_path_id`
- `packet_count`
- `captured_bytes`
- `original_bytes`

This row is intentionally raw. It does not persist:

- compact Protocol Path display strings
- unavailable-service placeholders
- localized labels

An empty service hint remains the raw unavailable state.

## Protocol Path Fast-Tier Model

The fast Protocol Path model is frozen as two early authorities:

- the early canonical Protocol Path registry
- terminal-path aggregate rows keyed by `protocol_path_id`

### Early registry

`protocol_path_registry_early` stores the canonical registry representation
needed to reconstruct each known path's layered identity:

- `protocol_path_id`
- ordered layer sequence
- per-layer identifier kind/value metadata where present

The early registry is the shared display authority for:

- terminal-path labels
- compact path text
- identity-tree ancestry
- kind-overview grouping

### Terminal-path aggregates

`protocol_path_terminal_aggregates` stores one or more ordered chunks of rows
containing at least:

- `protocol_path_id`
- `flow_count`
- `packet_count`
- `original_bytes`

Captured bytes are intentionally not added here because there is no current
concrete Protocol Path Statistics or reporting requirement that needs them.

### Reproducibility rule

The frozen v16 design requires that the current shared presentation modes be
derivable without scanning canonical flows:

- `Terminal paths`
- `Identity tree`
- `Kind overview`

The derivation model is:

- `Terminal paths` render directly from terminal-path aggregate rows joined to
  the early registry
- `Identity tree` folds terminal-path aggregate rows by the registry-defined
  ancestry/prefix structure
- `Kind overview` folds terminal-path aggregate rows by registry-defined layer
  kind groupings

Flow membership remains a separate later-tier concern.

## Flow Metadata Tier

The flow metadata tier is frozen as metadata-only canonical connection data
without embedded `PacketRef` arrays.

It must be sufficient for:

- flow list rendering
- metadata-backed filtering and Advanced Filter
- protocol/service presentation
- selected-flow Analysis list/top-row reference preparation
- Smart Export planning
- top-row stable references

It must not require a metadata load to reconstruct global whole-capture
Statistics that are already available from the fast tier.

### Frozen per-connection metadata fields

Each canonical connection metadata record must carry enough raw data for
metadata-only sessions:

- zero-based canonical connection ordinal
- canonical connection key in first-observed A/B orientation
- `protocol_path_id`
- raw `protocol_hint`
- raw `service_hint`
- QUIC version hint where available
- TLS version hint where available
- `has_fragmented_packets`
- `fragmented_packet_count`
- aggregate first timestamp
- aggregate last timestamp
- aggregate captured bytes
- aggregate truncated-packet count
- aggregate TCP `SYN` count
- aggregate TCP `FIN` count
- aggregate TCP `RST` count
- aggregate maximum original packet length
- aggregate maximum captured packet length
- directional presence bits
- directional flow descriptors

### Frozen directional flow descriptor

Each present directional flow descriptor contains:

- directional flow key
- authoritative `packet_count`
- directional `original_bytes`
- `packetref_directory` reference

The directional packet-count authority is the persisted `packet_count` field,
not any future derived `PacketRef` vector length.

### Directional fields intentionally deferred

v16 does not add:

- directional `captured_bytes`
- directional maximum captured packet length
- directional maximum original packet length

Those remain possible future metadata extensions only if a concrete later
feature requires them.

### Metadata-only orientation validation

The v16 reader must validate first-observed A/B orientation without globally
materializing packet arrays.

Frozen rules:

- a metadata record with `B -> A` present and `A -> B` absent is invalid
- if both directions are present, the earliest directional first packet must
  belong to `A -> B`

That validation may read only the minimal bounded first-entry information
needed from the corresponding `PacketRef` detail extents.

## PacketRef Directory And Detail Storage

### PacketRef directory

`packetref_directory` stores fixed-size directional descriptors for lazy
packet-reference access.

Each descriptor contains:

- canonical connection ordinal
- direction (`A -> B` or `B -> A`)
- `packet_count`
- `packetref_detail_blocks` section occurrence index
- section-payload-relative byte offset
- encoded byte length

The offsets are relative to the payload start of the referenced
`packetref_detail_blocks` section occurrence, not absolute file offsets.

### Huge single-direction flows

The writer must keep one directional flow's persisted `PacketRef` sequence
logically contiguous and directly range-seekable.

v16 freezes the following rule:

- a directional `PacketRef` sequence must not be split across multiple detail
  sections merely to satisfy a nominal chunk-size target
- if one directional sequence is unusually large, the writer may emit one
  oversize `packetref_detail_blocks` section occurrence for that sequence

This avoids introducing a segmented directory model in v16.

### PacketRef detail blocks

`packetref_detail_blocks` store contiguous compact serialized `PacketRef`
entries only.

They do not duplicate:

- flow metadata
- aggregate Statistics
- packet payload bytes

### Random-access and bounds rules

Readers must be able to locate and validate directional `PacketRef` ranges
without materializing the entire detail section.

Frozen rules:

- section framing is discovered from the stable section headers and payload
  sizes
- the directory's section occurrence index must reference an existing
  `packetref_detail_blocks` section occurrence
- the referenced byte range must lie completely within that section payload
- the encoded byte length must match the compact `PacketRef` stride times the
  persisted `packet_count`
- the decoded directional `PacketRef` sequence must be strictly increasing by
  global `packet_index`

v16 does not introduce a new per-section or per-block checksum policy beyond
existing structural validation.

## Selected-Flow Lazy Paging

Selected-flow packet paging remains a shared C++ concern.

The frozen bidirectional paging model is:

1. Resolve the canonical connection metadata record.
2. Resolve the two directional `packetref_directory` descriptors, if present.
3. Open two bounded directional cursors over the referenced `PacketRef`
   extents.
4. Merge the two directional streams by global `packet_index`.
5. Discard merged items until the requested merged offset is reached.
6. Collect up to the requested merged limit.
7. Refill only the cursor that was consumed when its local window is
   exhausted.

The implementation must never materialize full bidirectional `PacketRef`
arrays solely to serve a bounded selected-flow page.

## Unrecognized Directory And Detail Storage

Fast-tier whole-capture Statistics cover only aggregate unrecognized packet
facts.

Detailed unrecognized rows remain a later-tier concern.

### Frozen unrecognized directory row

`unrecognized_directory` stores fixed-size per-row metadata sufficient for
list pagination and later reason lookup:

- row number
- `packet_index`
- timestamp metadata sufficient for current shared presentation formatting
- `captured_length`
- `original_length`
- `unrecognized_reason_blobs` section occurrence index
- section-payload-relative reason byte offset
- reason byte length

The detailed reason text is not eagerly loaded during normal metadata load
unless the caller actually requests unrecognized rows.

### Frozen unrecognized reason storage

`unrecognized_reason_blobs` store UTF-8 reason payloads only.

The directory row points into these blobs. The reason text is therefore lazy,
seekable, and independent from fast Statistics reads.

## Packet Locator

`packet_locator` remains the late/detail-tier authority for source-backed
packet byte lookup.

Frozen policy:

- it is not needed for fast Statistics-only reads
- it is not needed for ordinary metadata-only flow loading
- it is not eagerly loaded during fast-tier reads
- deeper redundancy review beyond this role is deferred

## Fast-Reader Validation Scopes

The v16 reader conceptually distinguishes four validation scopes:

1. header validity
2. fast Statistics-tier validity
3. flow metadata-tier validity
4. detail-block validity

Successful scope `2` does not imply successful scope `3` or `4`.

Representative mandatory consistency checks include:

- `sum(captured packet-size bucket packet counts) == packet_count`
- `sum(original packet-size bucket packet counts) == packet_count`
- `sum(flow packet-count histogram flow counts) == flow_count`
- `sum(packet-direction distribution flow counts) == flow_count`
- `sum(original-byte-direction distribution flow counts) == flow_count`
- `truncated_packet_count <= packet_count`
- `unrecognized_packet_count <= packet_count`
- each top endpoint/port/top flow list respects its frozen maximum row count
- each referenced `protocol_path_id` exists in the early registry
- each `packetref_directory` extent is fully in-bounds
- each unrecognized reason extent is fully in-bounds

Stage 4 readers should reject malformed or internally inconsistent
authoritative data at the narrowest relevant validation scope.

## Conceptual Reader API Layers

The frozen conceptual v16 reader layers are:

- `inspect_index_header(...)`
- `read_statistics(...)`
- `load_flow_metadata(...)`
- `read_flow_packet_refs(flow_ref, direction, offset, limit)`
- `read_unrecognized_rows(offset, limit)`

`summary --extended` and similar whole-capture Statistics/reporting operations
should require only:

- stable header inspection
- fast Statistics-tier read

They must not require flow metadata or late detail validation merely to prove
unrelated sections are healthy.

## Analysis Requirements

Stage 3 Analysis does not add new mandatory directional persisted metadata
requirements for v16.

The following Analysis capabilities remain selected-flow `PacketRef` derived:

- rate graphs
- packet-size histograms
- directional sequence views
- bounded selected-flow packet windows

Existing connection aggregate metadata remains sufficient for whole-connection
facts used by Statistics/reporting.

## Frozen Stage 4 Implementation Sequence

The planned reviewable implementation sequence is:

1. Stage 4B: snapshot model, serialization helpers, and focused tests
2. Stage 4C: v16 section constants/topology plus writer and fast Statistics
   reader
3. Stage 4D: early Protocol Path registry and display aggregates
4. Stage 4E: split connection/flow metadata from `PacketRef` detail and add
   the directory
5. Stage 4F: lazy `PacketRef` provider plus selected-flow paging and Analysis
   integration
6. Stage 4G: unrecognized directory/detail lazy access
7. Stage 4H: move packet locator fully late/lazy and finish the full-session
   v16 reader
8. Stage 4I: CLI stats-only fast path plus session/frontend staged-loading
   plumbing

Dependencies may be refined during implementation review, but the frozen
target architecture should not change without a deliberate RFC update.

## Required Test Matrix Categories

Stage 4 implementation must cover at least:

- header inspection across v15/v16 revision boundaries
- fast Statistics-only reads that stop before metadata/detail tiers
- malformed snapshot invariant rejection
- bounded top endpoint/port/top flow ordering and row-count limits
- protocol-hint projection with `use_possible_tls_quic` both enabled and
  disabled from fast-tier data alone
- Protocol Path `Terminal paths`, `Identity tree`, and `Kind overview`
  derivation from early registry plus terminal aggregates
- metadata-only flow load without eager global `PacketRef` arrays
- bounded selected-flow lazy paging across both directions
- huge single-direction flow persistence using one contiguous extent
- unrecognized-row lazy pagination and reason lookup
- partial vs complete Statistics provenance persistence and presentation
- late packet-locator access remaining independent from fast Statistics reads

## Review Notes

This RFC freezes the intended stable v16 layout while preserving the key
current/target distinction:

- current production is still stable v15
- current code does not yet implement the v16 layout
- this document is the frozen design target for the later migration
