# Statistics, Reporting, and Large-Index Architecture RFC

Status: design freeze for `feature/statistics-reporting-improvements`.

Current production behavior remains the stable v15 architecture until the
planned migration is implemented. The frozen v16 layout is defined in the
companion [Index v16 Container RFC](index-v16-container-rfc.md).

Related current references:

- [Current State](../current-state.md)
- [Architecture](../architecture.md)
- [Large-Capture Performance Guidelines](../large-capture-performance-guidelines.md)
- [Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md)
- [Index v15 Container RFC](index-v15-container-rfc.md)
- [Index v16 Container RFC](index-v16-container-rfc.md)
- [Analysis](../analysis-tab.md)
- [Presentation Contract](../ui/presentation_contract.md)
- [Frontend DTO Mapping](../ui/frontend_dto_mapping.md)
- [Selected Flow Contract](../selected-flow-contract.md)
- [Stream Architecture](../stream_architecture.md)
- [Selected-Flow Packet Cache RFC](../selected-flow-packet-cache-rfc.md)
- [Reassembly RFC](../reassembly-rfc.md)
- [CLI Architecture](../cli/architecture.md)

## Purpose

This RFC records the agreed target direction for Statistics, reporting, and
the next deliberate large-index architecture migration.

The sequence remains intentional:

- Stage 0: architecture audit. Complete.
- Stage 1: freeze the design and migration target before implementation.
- Stage 2: implement new runtime Statistics calculations and Statistics UI
  without changing stable-index serialization.
- Stage 3: implement selected-flow Analysis time/graph improvements without
  changing stable-index serialization.
- Stage 4: perform one deliberate stable-index migration after the Statistics
  and Analysis data requirements have been exercised in production code.
- Stage 5: add shared HTML and Markdown reporting on top of the common
  Statistics model for Qt, Tauri, and CLI.

This RFC is therefore a design freeze point, not an implementation record.

## Current Architectural Baseline

Only the current facts needed to motivate the design are summarized here.
Authoritative current index details remain in:

- [Index v15 Container RFC](index-v15-container-rfc.md)
- [Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md)

Current production behavior:

- stable v15 stores `PacketRef` records inside directional `FlowV4` /
  `FlowV6` records
- `FlowV4` / `FlowV6` own resident `std::vector<PacketRef>`
- `.pflidx` loading eagerly deserializes all persisted flow `PacketRef`
  vectors
- unrecognized packet records are also eagerly loaded
- `CaptureIndexReader` currently materializes complete known section payloads
  into temporary byte vectors before parsing them
- index loading reconstructs packet-level Statistics by scanning loaded
  `PacketRef` data
- several whole-capture Statistics sections still depend on runtime
  reconstruction or separate `O(flow_count)` passes

## Design Goals

The target design should support:

1. Whole-capture Statistics without rescanning `PacketRef` data.
2. One packet-level accumulation path during import plus one canonical
   `O(flow_count)` Statistics pass.
3. No repeated independent full-flow-list traversals for ordinary
   whole-capture Statistics.
4. Future persisted Statistics sufficient for a stats-only CLI command to read
   only a small early part of a multi-gigabyte index.
5. Future Qt/Tauri ability to show Statistics before the remainder of a large
   index has finished loading.
6. Flow metadata loading without globally materializing `PacketRef` arrays.
7. Selected-flow `PacketRef` data loaded lazily and bounded only when
   required.
8. Lazy and paged unrecognized-packet details.
9. Shared Statistics authority for Qt, Tauri, CLI, future HTML reports, and
   future Markdown reports.
10. One deliberate stable-index migration after Stages 2 and 3 validate the
    real data requirements.

## Non-Goals

This RFC does not require:

- packet payload bytes in the index
- global Stream or reassembly state
- formatted UI strings in the index
- persisted percentages as authoritative values
- HTML or Markdown stored in the index
- asynchronous partial UI open as a required Stage 4 deliverable
- removal of `possible_tls` or `possible_quic` in this design freeze

The source-byte boundary remains in force:

- packet metadata may be available from an index-only session
- features requiring packet payload or source bytes still require an attached
  source capture

## Frozen Runtime Statistics Model

Two complementary calculation layers remain the planned shared authority.

### Packet-level capture accumulator

During raw capture import, every surfaced packet should update one compact
capture-level accumulator exactly once.

Raw facts remain:

- total packet count
- total captured bytes
- total original bytes
- earliest packet timestamp
- latest packet timestamp
- truncated packet count
- maximum captured packet length
- maximum original packet length
- captured packet-size histogram
- original packet-size histogram
- unrecognized packet count
- unrecognized captured bytes
- unrecognized original bytes

Capture start and capture end include recognized and unrecognized surfaced
packets. Earliest and latest are temporal min/max, not storage-order
first/last. An empty capture has no valid time range.

### One canonical flow Statistics pass

After raw import completes and canonical connections exist, one canonical
`O(flow_count)` Statistics pass should produce:

- IPv4 / IPv6 summary
- TCP / UDP / SCTP / Other summary
- detected-protocol category counters
- flow packet-count histogram
- original bytes per flow-count bucket
- captured bytes per flow-count bucket
- Only `A -> B` flow count
- service-recognized flow count
- packet direction distribution
- original-byte direction distribution
- QUIC/TLS recognition and version statistics
- whole-capture TCP `SYN` / `FIN` / `RST` counts
- bounded top endpoints
- bounded top ports
- fixed top 10 flows by original bytes
- Protocol Path display statistics

Protocol Path display Statistics must not require flow-membership
materialization.

## Authoritative Raw vs Derived Values

Persist or carry raw facts such as:

- counts
- byte totals
- timestamps
- histogram bucket counts
- category counts

Derive inexpensive presentation values such as:

- percentages
- duration
- rates
- average sizes
- formatted byte strings
- formatted timestamps

Derived presentation must guard against zero or malformed denominators. This
RFC still does not authorize formatted UI strings as persisted index data.

## Partial Capture And Partial Import Semantics

`CaptureStatisticsSnapshot` describes the successfully surfaced and imported
packet set.

A partial capture/import must not be presented as if its Statistics
necessarily covered the complete nominal source file.

The frozen v16 design persists completeness provenance directly in the
Statistics snapshot via a versioned `CaptureStatisticsScope` field. Exact
encoding lives in the companion [Index v16 Container RFC](index-v16-container-rfc.md).

Future Qt/Tauri/CLI/HTML/Markdown presentation must therefore be able to
distinguish:

- complete capture Statistics
- partial-import Statistics

Partial Statistics must never masquerade as known-complete capture
Statistics.

## Snapshot Consistency Invariants

Authoritative persisted Statistics must be internally self-consistent.

Representative invariants include:

- `sum(captured packet-size bucket packet counts) == packet_count`
- `sum(original packet-size bucket packet counts) == packet_count`
- `sum(flow packet-count histogram flow counts) == flow_count`
- `sum(packet-direction distribution flow counts) == flow_count`
- `sum(original-byte-direction distribution flow counts) == flow_count`
- `truncated_packet_count <= packet_count`
- `unrecognized_packet_count <= packet_count`

Only categories intentionally modeled as complete partitions should carry
partition-sum invariants.

Target principle:

- Stage 4 readers should reject malformed or internally inconsistent
  authoritative Statistics rather than silently present contradictory snapshot
  values.

## Top Endpoints, Ports, And Flows

The frozen fast-tier limits are:

- up to `20` top endpoints
- up to `20` top ports
- fixed `Top 10 Flows by Original Bytes`

The frozen row direction is:

- top endpoint rows persist raw endpoint identity plus `flow_count`,
  `packet_count`, `captured_bytes`, and `original_bytes`
- top port rows persist raw port identity plus `flow_count`, `packet_count`,
  `captured_bytes`, and `original_bytes`
- top flow rows persist raw identity, transport/protocol-hint inputs,
  service hint, `protocol_path_id`, `packet_count`, `captured_bytes`, and
  `original_bytes`

Unlimited endpoint or port aggregation is not part of the fast Statistics
tier without a demonstrated requirement.

Exact row payloads are frozen in the companion
[Index v16 Container RFC](index-v16-container-rfc.md).

## Protocol Path Statistics

The frozen v16 fast display model is:

- persist the canonical Protocol Path registry early
- persist terminal-path aggregate rows keyed by `protocol_path_id`
- derive `Terminal paths`, `Identity tree`, and `Kind overview` from those
  early authorities without scanning canonical flows
- keep potentially large flow-membership data out of the fast Statistics tier

Exact section families and raw aggregate fields are frozen in the companion
[Index v16 Container RFC](index-v16-container-rfc.md).

## Frozen Future Index Physical Architecture

The frozen v16 target architecture is:

- Stable header
- Fast Statistics tier
  - `capture_statistics_snapshot`
  - `protocol_path_registry_early`
  - `protocol_path_terminal_aggregates`
- Flow metadata tier
  - `ipv4_flow_metadata`
  - `ipv6_flow_metadata`
  - `protocol_path_membership`
  - `packetref_directory`
  - `unrecognized_directory`
- Detail tier
  - `packetref_detail_blocks`
  - `unrecognized_reason_blobs`
  - `packet_locator`

The architectural rule remains:

- flow metadata should not require globally deserializing `PacketRef` arrays

Exact section IDs, ordering, and chunking rules are frozen in the companion
[Index v16 Container RFC](index-v16-container-rfc.md).

## Fast Statistics Validation Boundary

The frozen design distinguishes:

- header validity
- fast Statistics-tier validity
- flow metadata-tier validity
- detail-block validity
- full-session load validity

A successful future fast Statistics-only read does not prove that later
flow-metadata or detail sections are valid.

A Statistics-only CLI operation must be allowed to stop after the required
early Statistics data rather than scan the rest of the index merely to prove
unrelated detail validity.

This same separation keeps future progressive Qt/Tauri loading architecturally
possible without making asynchronous partial UI open a required Stage 4
deliverable.

## Lazy PacketRef And Unrecognized Architecture

The frozen v16 direction is:

- metadata-only flow loading without embedded `PacketRef` arrays
- one shared lazy `PacketRef` directory and detail-tier access model
- bounded selected-flow bidirectional paging
- fixed-size unrecognized directory rows plus separate lazy reason blobs

The exact directory/detail representation is now frozen in the companion
[Index v16 Container RFC](index-v16-container-rfc.md).

## Reporting Architecture

Future reporting should use one shared frontend-neutral Statistics/report
model for:

- Qt
- Tauri
- CLI

Planned outputs:

- self-contained HTML
- Markdown

Source/index identity metadata needed by reports, such as:

- source capture path or name
- source capture format
- source file size
- source fingerprint or other source identity where applicable

belongs to the existing stable header/source-metadata authority and should not
be duplicated into the Statistics snapshot merely because reports need it.

Future HTML/Markdown report construction may combine:

- source/index metadata
- `CaptureStatisticsSnapshot`

into one report model.

## Report Content Policy

The report should represent confident capture Statistics rather than dump all
internal heuristic categories.

Policy:

- confirmed/recognized protocol Statistics are normal report content
- `possible_tls` and `possible_quic` remain persisted/internal for current
  product behavior
- `possible_tls` and `possible_quic` are excluded from default HTML/Markdown
  report content

## One Index Migration Rule

This project decision remains explicit:

- Stage 2 does not change stable-index serialization
- Stage 3 does not change stable-index serialization
- Stage 4 performs one deliberate format/layout migration after the
  Statistics and Analysis data requirements have been validated

The frozen stable target is now v16, with exact payload topology defined in
the companion [Index v16 Container RFC](index-v16-container-rfc.md).

## Index Version And Compatibility Policy

Current production remains stable v15.

The frozen Stage 4 target is:

- stable magic remains `PFLIDXV1`
- `container_format_version` remains `1`
- `index_revision = 16`
- rebuild-required behavior across the v15/v16 full-payload boundary is
  acceptable
- stable-header inspection remains independent of full payload compatibility

`kCaptureIndexStableIndexRevision` still does not change in production until
the migration is actually implemented.

## Frozen Stage 4 Decisions

The following design points are now frozen:

- top endpoint and top port persisted limits are `20`
- top flow persisted limit is `10`
- Protocol Path fast display uses the early registry plus terminal-path
  aggregate rows keyed by `protocol_path_id`
- protocol-recognition counters remain raw and setting-independent
- directional `captured_bytes` is not a new mandatory directional flow field
- directional maximum packet-size metadata is not added
- the v16 section-family boundaries and IDs are frozen
- the `PacketRef` directory uses fixed-size contiguous directional extents
- unrecognized details use a fixed-size directory plus separate reason blobs
- the next stable compatibility boundary is v16
- partial-import/completeness provenance lives in the Statistics snapshot
- fast Statistics success is explicitly not full-index validity
- asynchronous partial UI open is not a required Stage 4 deliverable
- source/index identity metadata remains outside the Statistics snapshot
- selected-flow Analysis adds no new mandatory directional persisted fields

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
