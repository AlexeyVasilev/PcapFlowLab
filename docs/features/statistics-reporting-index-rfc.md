# Statistics, Reporting, and Large-Index Architecture RFC

Status: design draft for `feature/statistics-reporting-improvements`.
Current production behavior remains the stable v15 architecture until the
planned migration is implemented.

Related current references:

- [Current State](../current-state.md)
- [Architecture](../architecture.md)
- [Large-Capture Performance Guidelines](../large-capture-performance-guidelines.md)
- [Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md)
- [Index v15 Container RFC](index-v15-container-rfc.md)
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

The sequence is intentional:

- Stage 0: architecture audit. Complete.
- Stage 1: agree on this RFC before implementation starts.
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
- index loading reconstructs `CapturePacketSizeStatistics` by scanning the
  `PacketRef` records it has just loaded
- some Statistics helpers still scan `PacketRef` data even where
  connection-level aggregates already contain authoritative metadata
- multiple Statistics sections currently perform separate `O(flow_count)`
  passes
- current persisted `ConnectionAggregateStats` already contains many useful
  metadata-only facts
- current `PacketRef` is intentionally compact locator/ordering metadata, not
  the owner of reusable flow-level aggregates

## Design Goals

The target design should support:

1. Whole-capture Statistics without rescanning `PacketRef` data.
2. General whole-capture Statistics built from one packet-level accumulation
   path during raw import plus one canonical `O(flow_count)` final Statistics
   pass.
3. No repeated independent full-flow traversals for ordinary whole-capture
   Statistics.
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

This RFC does not currently require:

- PDF generation
- storing packet payload bytes in the index
- global Stream or reassembly state
- storing formatted UI strings in the index
- storing percentages as authoritative persisted values
- storing HTML or Markdown in the index
- making every selected-flow Analysis graph precomputed
- implementing asynchronous partial UI open in this branch immediately
- removing `possible_tls` or `possible_quic` yet

The source-byte boundary remains in force:

- packet metadata may be available from an index-only session
- features requiring packet payload or source bytes still require an attached
  source capture

## Terminology

- A user-visible "flow" is the canonical bidirectional connection.
- `A -> B` remains the direction of the first observed packet.
- `B -> A` is the reverse of that first-observed orientation.
- Do not infer client/server semantics from `A` / `B`.
- Use `captured bytes` and `original bytes` consistently.
- `original_bytes - captured_bytes` represents capture truncation or
  incompleteness, not demonstrated network loss.

## Current vs Target

| Area | Current v15 | Target design |
| --- | --- | --- |
| Statistics ownership | Split across several runtime passes and helpers | One shared whole-capture Statistics authority |
| Capture packet histogram | Captured-size histogram only | Captured and original whole-capture histograms |
| Whole-capture packet facts | Partly reconstructed from eager packet metadata | Persisted raw packet-level snapshot facts |
| PacketRef loading | Eager global deserialization on index open | Lazy and bounded access for index-backed sessions |
| Flow metadata | Interleaved with `PacketRef` arrays in connection payloads | Separated from large packet-detail storage |
| Unrecognized details | Eagerly resident | Aggregate in fast tier, detail rows in later lazy tier |
| Protocol Path display stats | Rebuilt from loaded flow metadata | Fast display aggregate available without full flow load |
| Stats-only CLI | Requires full runtime metadata path | Reads an early compact Statistics tier |
| Report data source | No dedicated shared report model yet | Shared frontend-neutral Statistics snapshot/model |
| Index open cost model | Strongly packet-count-proportional | Fast Statistics tier plus metadata/detail separation |

## Target Runtime Statistics Model

Two complementary calculation layers are planned.

### Packet-level capture accumulator

During raw capture import, every surfaced packet should update one compact
capture-level accumulator exactly once.

Tentative conceptual name:

- `CapturePacketStatistics`

The exact production type name is not frozen by this RFC.

Raw facts to support:

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

Capture start and capture end must include recognized and unrecognized
surfaced packets. Earliest and latest are temporal min/max, not storage-order
first/last. An empty capture has no valid time range.

### One canonical flow Statistics pass

After raw import completes and canonical connections exist, perform one
canonical `O(flow_count)` Statistics pass.

That pass should be capable of producing:

- IPv4 / IPv6 summary
- TCP / UDP / SCTP / Other summary
- detected protocol categories
- flow packet-count histogram
- original bytes per flow-count histogram bucket
- captured bytes per flow-count histogram bucket
- Only `A -> B` flow count
- service-recognized flow count
- packet direction distribution
- original-byte direction distribution
- QUIC/TLS recognition and version statistics
- bounded top endpoints
- bounded top ports
- fixed top 10 flows by original bytes
- Protocol Path display statistics, subject to the Protocol Path design
  decision below

This replaces the architecture of several independent whole-flow-list
Statistics passes.

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

Examples:

- capture duration = `max(0, capture_end - capture_start)`
- average captured packet size = `captured_bytes / packet_count`
- average original packet size = `original_bytes / packet_count`
- average packet rate = `packet_count / duration`
- average captured data rate = `captured_bytes / duration`
- average original data rate = `original_bytes / duration`
- not captured bytes = `max(0, original_bytes - captured_bytes)`
- capture completeness = `captured_bytes / original_bytes`

Derived presentation must guard against zero or malformed denominators:

- no packets -> averages unavailable or explicitly empty
- zero duration -> rate unavailable, never infinity
- zero original bytes -> completeness unavailable
- not-captured bytes never underflows

Formatted percentages and strings are not authoritative index data.

## Planned Statistics UI

### Top capture cards

Current top cards remain:

- Packets
- Flows
- Original bytes
- Captured bytes

Add a second row directly below them:

- Capture start
- Capture end
- Duration

Start and end should later be presented as complete absolute timestamps with
calendar date and unambiguous timezone or UTC indication. Persist raw
timestamps, not formatted text.

### Capture Metrics block

Planned compact metrics:

- Average captured packet size
- Average original packet size
- Average packet rate
- Average captured data rate
- Average original data rate
- Truncated packets: count plus percentage
- Not captured bytes
- Capture completeness

This is intended as a compact metrics block, not a large-card row.

### Flow Characteristics block

Planned metrics:

- Only `A -> B` flows: count plus percentage
- Service recognized: count plus percentage

Only `A -> B` means:

- `A` packet count `> 0`
- `B` packet count `== 0`

Because `A` is first-observed direction, there is no normal "Only `B -> A`"
category.

`Service recognized` currently means a canonical connection with a non-empty
`service_hint`.

### Packet Direction Distribution

Display:

| Category | Flows | Percent |
| --- | --- | --- |
| Mostly A -> B | count | percent |
| Balanced | count | percent |
| Mostly B -> A | count | percent |

Use the existing shared `DirectionDistribution` classifier with existing
semantics, including:

- exactly `2:1` -> `Balanced`
- strictly greater than `2:1` -> `Mostly`

Classification input is directional packet counts.

### Data Direction Distribution

Display the same categories:

| Category | Flows | Percent |
| --- | --- | --- |
| Mostly A -> B | count | percent |
| Balanced | count | percent |
| Mostly B -> A | count | percent |

Classification input is directional original-byte totals. The `Flows` column
means the number of canonical flows whose original-byte balance falls into
that category.

## Planned Statistics Graph Improvements

These requirements affect the future persisted Statistics design.

Packet Size Distribution:

- `Captured`
- `Original`

Both whole-capture histograms should eventually be available without scanning
`PacketRef` data.

Flows by Packet Count:

- `Flows`
- `Captured bytes`
- `Original bytes`

Each bucket therefore needs enough raw values to display:

- flow count
- total captured bytes
- total original bytes

## Planned Analysis Improvements

Selected-flow Analysis remains a separate cost model.

Planned changes:

- timeline presentation becomes `Start`, `End`, `Duration`
- start and end should show full absolute date/time, not only time-of-day
- Packet Size Histogram adds `Original` and `Captured`
- Flow Rate adds `Original data`, `Captured data`, and `Packets`

Direction selection remains compatible with current `A -> B`, `B -> A`, and
`Both` semantics.

These selected-flow graphs may legitimately require ordered lazy `PacketRef`
access. They do not become whole-capture precomputed Statistics.

## Flow Metadata Requirements

Current directional flow metadata already includes:

- packet count
- original byte total

Current `ConnectionAggregateStats` already includes:

- first timestamp
- last timestamp
- captured byte total
- truncated packet count
- TCP SYN/FIN/RST counts
- maximum captured packet length
- maximum original packet length

One high-value planned metadata candidate is directional captured-byte total
for Flow A and Flow B.

Benefits:

- avoids current captured-byte scans over `PacketRef`
- supports future directional captured-byte queries
- supports Statistics, filtering, reporting, and richer metadata-only flow
  analysis

This RFC records it as a planned field to freeze before Stage 4. It is not
implemented by this document.

## Possible TLS / QUIC Policy

Current project policy:

- `possible_tls` remains supported
- `possible_quic` remains supported
- their raw categories should remain representable in the future index and
  Statistics snapshot
- they are not removed in this branch at this stage

However:

- they are heuristic categories
- they are not preferred public report content
- future HTML/Markdown reports should exclude `possible_tls` and
  `possible_quic` by default
- confirmed/recognized protocol statistics should be the default
  report-facing semantics

The long-term fate of these heuristic categories remains unresolved. The
snapshot should preserve their identity without hard-wiring them into report
presentation schemas.

## Protocol Recognition Snapshot Representation

The snapshot must preserve enough raw category data to allow runtime policy to
decide whether heuristic categories participate in UI totals.

Conceptually, raw counters should remain able to distinguish:

- confirmed TLS
- possible TLS
- confirmed QUIC
- possible QUIC

Other protocol/service categories should likewise keep stable raw identity.
Do not persist localized labels as identity. Use stable enum/id semantics or
another compact stable representation consistent with current project
patterns.

The exact serialized representation remains open until Stage 4 design freeze.

## Runtime Mutability and Enrichment

Persisted Statistics represents the baseline at index-creation time.

Some canonical metadata may change during a live source-backed session, for
example selected-flow service enrichment.

Preferred runtime model:

- persisted snapshot -> initial in-memory Statistics baseline
- known canonical metadata mutations update or invalidate only the affected
  in-memory Statistics subset

Example:

- `service_hint: empty -> non-empty` may increment runtime
  service-recognized-flow statistics without requiring a `PacketRef` scan

This RFC does not require rewriting `.pflidx` files merely because an open
session performs ephemeral enrichment.

## Future Persisted Statistics Snapshot

Define a frontend-neutral whole-capture Statistics snapshot.

Tentative conceptual name:

- `CaptureStatisticsSnapshot`

Exact production type naming is not frozen yet.

The snapshot should be sufficient for:

- Qt Statistics
- Tauri Statistics
- CLI Statistics
- future HTML report generation
- future Markdown report generation

without requiring ordinary consumers to scan flows or `PacketRef` data.

Design coverage must include:

- capture totals: packets, flows, captured bytes, original bytes
- capture time: start, end
- capture packet facts: truncation, maximum packet lengths, captured
  histogram, original histogram, unrecognized aggregates
- family and transport Statistics
- recognized protocol category Statistics
- flow packet-count histogram with flow count, captured bytes, original bytes
- flow characteristics: Only `A -> B`, Service recognized
- packet direction distribution
- original-byte direction distribution
- whole-capture TCP SYN/FIN/RST packet counts
- QUIC/TLS statistics
- bounded top endpoints
- bounded top ports
- fixed top 10 flows by original bytes
- Protocol Path display statistics

Do not store presentation strings in this snapshot.

### Partial capture and partial import semantics

`CaptureStatisticsSnapshot` must describe the successfully surfaced and
imported packet set.

A partial capture/import must not be presented as if its Statistics
necessarily covered the complete nominal source file. Current product behavior
already distinguishes partial source-backed opens with an explicit warning;
this RFC extends that design requirement to future persisted Statistics
presentation as well.

Future Qt/Tauri/CLI/HTML/Markdown presentation must therefore have enough
provenance to distinguish:

- complete capture Statistics
- partial-import Statistics

This RFC does not yet freeze the exact stable persistence location of that
provenance. The key rule is that partial Statistics must never masquerade as
known-complete capture Statistics.

### Snapshot consistency invariants

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
partition-sum invariants. This RFC does not require every protocol or
heuristic grouping to form a complete partition.

Target principle:

- Stage 4 readers should reject malformed or internally inconsistent
  authoritative Statistics rather than silently present contradictory snapshot
  values.

## Top Endpoints, Ports, and Flows

Current UI semantics are bounded Top-N, currently effectively Top 5.

Preferred direction:

- persist a bounded Top-K larger than the default visible UI set
- persist endpoint rows with endpoint identity/presentation source, `flow_count`,
  `packet_count`, and `original_bytes`
- persist port rows with port, `flow_count`, `packet_count`, and
  `original_bytes`
- persist a fixed `Top 10 Flows by Original Bytes` slice with enough raw data
  to reproduce:
  - flow identity/reference
  - Endpoint A
  - Endpoint B
  - Protocol
  - Detected Protocol
  - Service
  - compact Protocol Path
  - Packets
  - Captured bytes
  - Original bytes

This allows UI and reporting to show a useful shortlist without full
flow-metadata loading.

For top flows, prefer stable/raw snapshot fields rather than redundant display
strings where current shared presentation can derive them. In particular:

- stable flow identity/reference rather than UI row position alone
- protocol identity / hint rather than localized detected text
- `protocol_path_id` plus the future early Protocol Path registry/presentation
  data rather than duplicating compact path strings everywhere

The exact `K` remains an open design decision to resolve before Stage 4.
Unlimited endpoint or port aggregation is not part of the fast Statistics
tier without a demonstrated requirement.

The `Top 10 Flows by Original Bytes` requirement is now part of the current
product direction rather than an open-ended UI convenience.

## Protocol Path Statistics

Separate:

- Protocol Path display Statistics
- Protocol Path to flow membership

Preferred design direction:

- persist one canonical compact Protocol Path aggregate representation
- derive current presentation modes from that representation if semantically
  possible
- do not blindly persist three duplicate UI-mode trees
- keep potentially large flow-membership data out of the fast display
  Statistics snapshot

This RFC does not claim that one existing terminal-path aggregate already
proves all current modes are reproducible. That proof remains required before
Stage 4:

- all current Protocol Path presentation modes must be reproducible without
  scanning canonical flows

Until proven, the exact canonical Protocol Path persisted representation
remains an open design decision.

## Future Index Physical Architecture

Preferred target architecture:

- Stable header
- Fast Statistics tier
- Flow metadata tier
- Detail tier

Conceptually:

- Fast Statistics tier
  - capture/statistics summary
  - Protocol Path display aggregates
  - other compact whole-capture reporting data
- Flow metadata tier
  - IPv4/IPv6 canonical connection metadata
  - flow metadata
  - `PacketRef` block descriptors
  - Protocol Path membership / flow mapping
  - unrecognized detail directory if needed
- Detail tier
  - `PacketRef` blocks
  - unrecognized packet detail blocks
  - packet locator and other late detail storage as appropriate

The architectural rule is:

- flow metadata should not require globally deserializing `PacketRef` arrays

Preferred direction is physical separation of metadata from large packet
detail rather than keeping today's interleaved layout and relying only on
seek tricks.

Exact final section IDs and field ordering remain open pending Stage 4 review.

## Fast Statistics Prefix

Target property:

- a future command equivalent to `pcap-flow-lab stats huge.pflidx` must be
  able to return whole-capture Statistics without reading multi-gigabyte
  flow/`PacketRef`/detail sections

The fast Statistics data must therefore be physically early in the index.

Successful fast Statistics-only access must not be treated as proof that every
later flow-metadata or detail section in a multi-gigabyte index is valid.

The design should conceptually distinguish:

- header and Statistics-tier validation
- flow-metadata-tier validation
- detail/block validation
- full-session load validity

Future APIs may conceptually separate:

- inspect index
- read Statistics
- load flow metadata
- read flow `PacketRef`
- read unrecognized details

This API split is a design goal, not an implemented contract.

A Statistics-only CLI operation must be allowed to stop after the required
early Statistics data rather than scan the rest of the index merely to prove
unrelated detail validity. The same distinction should make future
progressive Qt/Tauri loading architecturally possible.

The format should also allow future Qt/Tauri to display Statistics while flow
metadata is still loading, without making asynchronous partial UI open a
required Stage 4 deliverable.

## Lazy PacketRef Architecture

Today both raw and index-loaded sessions keep:

- `Flow -> vector<PacketRef>`

Future index-backed sessions should be able to keep flow metadata resident
without keeping all `PacketRef` values resident.

Preferred direction:

- one shared backend packet-reference source/range abstraction

It should eventually support:

- merged flow packet window by `offset + limit`
- directional prefix access
- exact selected-packet lookup
- bounded Stream/reassembly prefix access
- selected-flow Analysis packet access
- explicit full-flow iteration/streaming for export
- global packet-index lookup where required

Qt, Tauri, and CLI should not each implement lazy `PacketRef` access
independently. Shared C++ remains authoritative.

## Index-Only Semantics

Desired distinction:

An index-only session with lazy `PacketRef` access may still support
metadata-only packet/flow features such as:

- packet row metadata available from `PacketRef`
- timestamps
- captured/original length
- packet index
- flow metadata
- Statistics
- metadata-only Analysis where semantically valid

Features requiring source packet bytes still require an attached source
capture, including examples such as:

- Packet Summary requiring packet bytes
- byte views
- payload decode
- packet-backed TLS/QUIC inspection
- payload Stream/reassembly

Lazy `PacketRef` access does not imply stored payload bytes.

## Unrecognized Packet Architecture

Current unrecognized packet details are eagerly resident.

Future target:

- whole-capture Statistics uses persisted aggregate unrecognized counts/bytes
- detailed unrecognized rows are stored in a later detail tier
- detail rows can be paged or lazily read when the user opens that list

Because `reason_text` is variable-length, the exact directory/chunk layout may
need different handling from fixed-size `PacketRef` blocks. That is part of
the Stage 4 design surface.

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
be duplicated merely because reports need it.

Future HTML/Markdown report construction may combine:

- source/index metadata
- `CaptureStatisticsSnapshot`

into one report model.

HTML should support:

- tables
- simple document charts, likely inline SVG
- no dependency on screenshots
- no dependency on UI collapsible sections having been opened

Markdown should support:

- tables
- simple textual replacements for bar-chart views where appropriate
- a single useful textual report where practical

PDF is not part of the committed scope in this RFC. External printing of HTML
to PDF remains acceptable.

## Report Content Policy

The report should represent confident capture Statistics rather than dumping
all internal heuristic categories.

Policy:

- confirmed/recognized protocol Statistics are normal report content
- `possible_tls` and `possible_quic` remain persisted/internal for current
  product behavior
- `possible_tls` and `possible_quic` are excluded from default HTML/Markdown
  report content

This is report-presentation policy, not an irreversible file-format
restriction.

## One Index Migration Rule

This project decision is explicit:

- Stage 2 must not change stable-index serialization
- Stage 3 must not change stable-index serialization
- Stage 4 performs one deliberate format/layout migration after the
  Statistics and Analysis data requirements have been validated

Stage 4 may consist of multiple reviewable implementation commits, but the
wire-format contract should be defined once.

Conceptual Stage 4 sub-passes may include:

- define and write new sections
- read the fast Statistics tier
- load flow metadata without `PacketRef` arrays
- add an index-backed `PacketRef` source
- migrate selected-flow consumers
- add lazy unrecognized details
- remove old eager-loading dependencies
- add tests, docs, and performance validation

None of these are implemented by this RFC.

## Index Version and Compatibility Policy

Current production remains stable v15.

Expected direction:

- Stage 4 is likely to use one next stable revision / compatibility boundary
  after v15

However:

- `kCaptureIndexStableIndexRevision` does not change now
- current v15 serialization does not change now
- no production version constant is assigned now

Rebuild-required behavior for older indexes is acceptable where needed.
Stable outer-container principles remain preferred unless later design
discovers a reason to change them.

## Open Design Decisions

The following decisions must be resolved before Stage 4:

1. Exact bounded persisted Top-K for endpoints and ports.
2. Exact canonical persisted Protocol Path display representation that can
   reproduce all current Statistics modes without scanning flows.
3. Final persistent representation of protocol-recognition category counters.
4. Whether directional captured bytes becomes a mandatory directional flow
   metadata field.
5. Exact new section-family boundaries and IDs.
6. Exact `PacketRef` block-directory representation.
7. Exact lazy unrecognized-detail directory/chunk representation.
8. Exact next stable revision/schema compatibility boundary.
9. Whether any Stage 4 asynchronous fast-Statistics UI behavior is included
   or deliberately deferred.
10. Where partial-import/completeness provenance is persisted
    (`CaptureStatisticsSnapshot`, source/session metadata, or another
    appropriate stable field), unless Stage 4 design proves partial indexes
    cannot exist.

The following are already agreed and therefore not open here:

- capture time semantics
- first-observed A/B semantics
- one packet accumulator plus one flow Statistics pass
- no repeated index migration during Stages 2 and 3
- `possible_tls` / `possible_quic` remain persisted/internal for now
- default reports exclude `possible_tls` / `possible_quic`

## Stage 4 Completion Checklist

- [ ] current Statistics UI
- [ ] new Capture Time values
- [ ] new Capture Metrics
- [ ] Only A -> B statistic
- [ ] Service recognized statistic
- [ ] packet direction distribution
- [ ] original-byte direction distribution
- [ ] TCP Flags statistics
- [ ] captured/original Packet Size Distribution
- [ ] Flows by Packet Count: flows/captured/original
- [ ] confirmed/current protocol Statistics
- [ ] possible TLS/QUIC internal representation
- [ ] QUIC/TLS Statistics
- [ ] Top endpoints/ports
- [ ] Top 10 flows by original bytes
- [ ] Protocol Path Statistics
- [ ] CLI Statistics without full index load
- [ ] lazy selected-flow `PacketRef`
- [ ] lazy unrecognized details
- [ ] index-only metadata semantics
- [ ] future HTML report data
- [ ] future Markdown report data

## Review Notes

This RFC intentionally distinguishes:

- current production v15 behavior
- target architecture direction
- unresolved wire/layout decisions

It does not standardize final section IDs, final snapshot field ordering, or
the exact lazy-detail representation before Stage 4 design review.
