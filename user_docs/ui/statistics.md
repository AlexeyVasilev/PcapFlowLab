# Statistics workspace

Qt is the primary Pcap Flow Lab desktop UI. The screenshots on this page use
the Tauri UI because its compact layout shows the independent Statistics
sections clearly. The Statistics values documented here come from shared
backend computations rather than screenshot-only interpretation.

For a whole-window overview, see [Main window](main-window.md). For selected-
flow quantitative work, see [Analysis workspace](analysis.md). For detailed
packet, stream, and unrecognized-packet inspection, see
[Flows workspace](flows.md).

## What Statistics is for

`Statistics` is the whole-capture or whole-index quantitative workspace.

This is the key distinction from `Analysis`:

- `Analysis` explains one selected canonical flow.
- `Statistics` summarizes the active capture or index as a whole.

You do not need to select a flow first.

The top summary blocks and capture-time values are always visible. The heavier
detailed sections are collapsible and are loaded when you expand them. That
keeps the workspace fast to open while still exposing deeper capture-wide
summaries when you need them.

## Capture overview

![Statistics overview](images/statistics/statistics-overview.png)

*Whole-capture totals, capture-time values, transport/family summaries, and
unrecognized-packet totals, with deeper capture-wide metrics in collapsible
sections below.*

At the top of `Statistics`, the application shows capture-wide totals:

- `Packets`
- `Flows`
- `Original Bytes`
- `Captured Bytes`

Current semantics:

- `Packets` is the total number of imported packets surfaced from the active
  capture or index, including unrecognized packets.
- `Flows` counts recognized canonical flows.
- `Captured Bytes` is the sum of captured packet lengths across the whole
  surfaced capture.
- `Original Bytes` is the sum of original packet lengths across the whole
  surfaced capture.

The whole-capture packet and byte totals can therefore be larger than the
recognized-flow-only summary if some imported packets could not be assigned to
canonical flows.

When the active capture was opened only partially, `Statistics` shows a
warning that the values cover successfully imported packets only. The page must
not silently imply that a partial import represents the complete nominal
source file.

The always-visible capture-time row shows:

- `Capture Start`
- `Capture End`
- `Duration`

Current semantics:

- `Capture Start` is the earliest timestamp among successfully surfaced
  imported packets;
- `Capture End` is the latest timestamp among successfully surfaced imported
  packets;
- recognized and unrecognized packets both participate;
- `Duration` is the non-negative difference between end and start;
- a one-packet capture can therefore show identical start and end with a zero
  duration;
- an unavailable time range remains visually distinct from a real zero
  duration.

The UI presents absolute timestamps in UTC and does not silently switch to the
local machine timezone. Current visible formatting uses millisecond precision,
for example:

- `2026-03-22 12:26:40.000 UTC`
- `2026-03-22 12:28:34.023 UTC`
- `00:01:54.023`

### Capture Metrics

`Capture Metrics` is a collapsible section that summarizes packet-level
properties derived from the whole surfaced capture:

- `Average Captured Packet Size`
- `Average Original Packet Size`
- `Average Packet Rate`
- `Average Captured Data Rate`
- `Average Original Data Rate`
- `Truncated Packets`
- `Not Captured Bytes`
- `Capture Completeness`

Current semantics:

- average packet sizes divide captured/original byte totals by surfaced packet
  count when at least one packet is present;
- packet and data rates use capture duration, so a valid zero-duration
  one-packet capture still shows rate fields as unavailable rather than
  `inf`/`NaN`;
- data rates are byte-based values per second, not bits per second;
- `Truncated Packets` shows both count and share of surfaced packets;
- `Not Captured Bytes` is `Original Bytes - Captured Bytes` clamped at zero;
- `Capture Completeness` is the captured/original byte ratio when original-byte
  totals are non-zero.

`Not Captured Bytes` reflects truncation or capture-incompleteness semantics in
the imported data. It is not a network packet-loss measurement.

### Flow Characteristics

`Flow Characteristics` is a collapsible section that currently reports:

- `Only A -> B Flows`
- `Service Recognized`

Current semantics:

- `Only A -> B Flows` means flows whose first-observed `A -> B` direction has
  packets while the reverse `B -> A` direction has none;
- `Service Recognized` means the stored canonical flow has a non-empty service
  hint;
- both values are shown as count plus percentage of recognized canonical
  flows.

### Direction Distribution

`Direction Distribution` is one collapsible section containing two separate
tables:

- `Packet Direction`
- `Data Direction (Original Bytes)`

Both tables use the same three direction groups:

- `Mostly A -> B`
- `Balanced`
- `Mostly B -> A`

Each row shows:

- `Flows`
- `Percent`

Percentages use the recognized canonical flow total as the denominator.

`Data Direction (Original Bytes)` is based on ORIGINAL bytes, not captured
bytes. Its helper text explains that flows are grouped by directional
original-byte balance.

### Transport summary

`Transport Summary` groups recognized canonical flows by their stored canonical
transport/protocol identity:

- `TCP`
- `UDP`
- `SCTP`
- `Other`

Current columns:

- `Flows`
- `Packets`
- `Captured Bytes`
- `Original Bytes`

Current semantics:

- rows are built from recognized canonical flows only;
- unrecognized packets are not added into these rows;
- flow membership follows the canonical flow protocol stored for that flow, not
  merely an outer encapsulation layer visible in one packet;
- `Other` contains recognized canonical flows whose stored protocol is neither
  TCP, UDP, nor SCTP.

### IP family summary

`IP Family Summary` currently reports:

- `IPv4`
- `IPv6`

with the same columns:

- `Flows`
- `Packets`
- `Captured Bytes`
- `Original Bytes`

Current semantics:

- these rows summarize recognized canonical flows by stored flow family;
- unrecognized packets are excluded;
- the current user-facing table reports IPv4 and IPv6 only, rather than adding
  a separate non-IP family row.

### Unrecognized packets

The `Unrecognized Packets` block summarizes imported packets that could not be
assigned to canonical flows.

Current fields:

- `Packets`
- `Captured Bytes`
- `Original Bytes`

This block is shown only when the active capture or index actually contains
such packets.

Use it as a whole-capture signal that part of the import remained outside the
normal flow inventory. When you want to inspect those packets directly, switch
to [Flows workspace](flows.md), where the `Unrecognized packets` row provides
the packet-level workflow.

## Packet Size Distribution

![Packet Size Distribution](images/statistics/statistics-packet-size-distribution.png)

*Captured/original packet-length distribution for the active capture or index.*

Current production contract:

- it counts all surfaced imported packets;
- recognized and unrecognized packets both contribute;
- the buckets are shared across both modes;
- `Captured` uses the packet lengths actually present in the capture;
- `Original` uses the original packet lengths recorded by capture metadata.

Current bucket boundaries:

1. `0-63`
2. `64-127`
3. `128-255`
4. `256-511`
5. `512-1023`
6. `1024-1399`
7. `1400-1550`
8. `1551-2499`
9. `2500-5000`
10. `5001-9000`
11. `9001-16000`
12. `16001-25000`
13. `25001+`

The mode buttons are:

- `Captured`
- `Original`

The separate maximum line follows the selected mode:

- `Maximum captured packet size`
- `Maximum original packet size`

This intentionally differs from the selected-flow Analysis packet-size
histogram. In current production:

- `Statistics -> Packet Size Distribution` can show captured or original packet
  length across the whole capture;
- `Analysis -> Packet Size Histogram` uses original packet length.

That difference matters whenever truncation or snaplen causes captured length
and original length to differ.

## Flows by Packet Count

![Flows by Packet Count](images/statistics/statistics-flows-by-packet-count.png)

*Flow-count mode for packet-count buckets.*

![Flows by Original Bytes](images/statistics/statistics-flows-by-original-bytes.png)

*Original-bytes mode for the same packet-count buckets.*

`Flows by Packet Count` groups recognized canonical flows into packet-count
buckets.

Current bucket boundaries:

1. `1`
2. `2`
3. `3-5`
4. `6-10`
5. `11-25`
6. `26-50`
7. `51-100`
8. `101-250`
9. `251-500`
10. `501-1000`
11. `1001-5000`
12. `5001+`

Bucket membership is based on flow packet count. Changing display mode does not
move flows into different buckets.

The mode buttons are:

- `Flows`
- `Captured bytes`
- `Original bytes`

### Flows mode

In `Flows` mode, each bucket value is:

- the number of recognized canonical flows whose packet count falls inside that
  bucket.

The bar height/length is normalized against the largest bucket flow count.

### Captured bytes mode

In `Captured bytes` mode, each bucket value is:

- the sum of captured bytes for recognized canonical flows whose packet count
  falls inside that same bucket.

The bucket membership still comes from packet count. Only the aggregated value
displayed for each bucket changes.

### Original bytes mode

In `Original bytes` mode, each bucket value is:

- the sum of original bytes for recognized canonical flows whose packet count
  falls inside that same bucket.

The bucket membership still comes from packet count. Only the aggregated value
displayed for each bucket changes.

If zero-packet flows exist in stored metadata, the UI can report them
separately as `Excluded zero-packet flows`, rather than mixing them into the
normal positive packet-count buckets.

## Protocol Path Tree

`Protocol Path Tree` is the most structurally rich Statistics section.

It aggregates recognized canonical flows by their stored Protocol Path and lets
you pivot back into `Flows` using structured Protocol Path filtering.

Current columns are:

- `Layer` or `Path`
- `Flows`
- `Packets`
- `Original Bytes`

Depending on the mode, rows can be:

- expandable prefix-tree nodes;
- exact identifier-aware prefix nodes;
- full terminal paths.

### Percentages and aggregation

Protocol Path Tree percentages are source-verified and do not all use the same
denominator.

Current denominators:

- `Flows` percentage uses total recognized canonical flow count included in
  Protocol Path statistics.
- `Packets` percentage uses whole-capture total packet count, so packet shares
  stay comparable even when some packets are unrecognized and intentionally
  excluded from the Protocol Path rows.
- `Original Bytes` percentage uses the total original-byte sum of recognized
  canonical flows included in the Protocol Path statistics.

Important inclusion rules:

- unrecognized packets are excluded from Protocol Path rows;
- only recognized canonical flows with stored Protocol Paths contribute;
- prefix-tree modes are not mutually exclusive categories, because one flow can
  contribute to multiple prefix rows along its path;
- `Original Bytes` uses canonical-flow original-byte totals.

### Kind overview

![Protocol Path Tree - Kind overview](images/statistics/statistics-protocol-path-kind.png)

*Kind-only Protocol Path prefix tree.*

`Kind overview` groups by protocol-layer kind while preserving path order.

At user level, that means identifier-bearing variants are normalized to their
kind-only form. For example:

- `VLAN (VID 300)` and `VLAN (VID 320)` both contribute under `VLAN`;
- identity-bearing transport overlays still remain in their path position.

This mode is useful when you want to understand overall layering structure
without splitting rows by identifiers such as VIDs, labels, VNIs, or TEIDs.

### Identity tree

![Protocol Path Tree - Identity tree](images/statistics/statistics-protocol-path-identity.png)

*Identifier-aware Protocol Path prefix tree.*

`Identity tree` keeps identifier-bearing path detail where the current Protocol
Path model stores it.

Examples visible in the showcase capture include:

- `VLAN (VID 300)`
- `VLAN (VID 320)`
- `MPLS (label 16010)`
- `MPLS (label 16011)`

This mode is useful when you want to distinguish traffic that would collapse
together in `Kind overview`.

### Terminal paths

![Protocol Path Tree - Terminal paths](images/statistics/statistics-protocol-path-terminal.png)

*Complete stored terminal paths rather than expandable prefix rows.*

`Terminal paths` shows complete stored Protocol Paths as flat terminal rows.

Each row represents one full stored path, for example a complete encapsulation
stack from outer transport down to the final inner transport path.

Current semantics:

- rows are full terminal paths, not prefix rows;
- there are no expandable parent nodes in this mode;
- each row aggregates flows sharing the same complete stored terminal path;
- identity-bearing path text remains visible in the terminal-path label.

### Expand and Collapse

`Expand all` and `Collapse all` are available in the two tree modes:

- `Kind overview`
- `Identity tree`

They are intentionally not shown in `Terminal paths`, because that mode is a
flat list of full paths rather than an expandable tree.

### Show matching flows

![Protocol Path Tree - Show flows](images/statistics/statistics-protocol-path-show-flows.png)

*A selected Protocol Path row can pivot into the Flows workspace.*

![Protocol Path filter applied in Flows](images/statistics/statistics-protocol-path-filter-result.png)

*The selected Protocol Path becomes a structured filter in Flows rather than a
plain text search string.*

`Show flows` is the main interactive bridge from Statistics back to Flows.

When you select a Protocol Path row and activate `Show flows`, the application:

- switches to `Flows`;
- applies a structured Protocol Path filter;
- limits the visible flow inventory to the matching canonical flows;
- keeps the normal text filter as a separate control.

Mode-specific matching semantics:

- `Kind overview` filters by the selected kind-only prefix semantics.
- `Identity tree` filters by the selected identifier-aware prefix semantics.
- `Terminal paths` filters by the selected exact full terminal path.

This is not implemented as text injected into the normal text search box.

The structured Protocol Path filter and the normal text filter can both apply
at the same time:

- the Protocol Path filter restricts the allowed canonical flow set;
- the normal text filter still narrows that already filtered visible set;
- clearing the Protocol Path filter removes only the structured Protocol Path
  restriction, not the independent text filter.

### Export

`Export` writes the current Protocol Path Tree mode as a plain-text report.

Current export behavior:

- export uses the current mode (`Kind overview`, `Identity tree`, or
  `Terminal paths`);
- output is a text file, not a CSV file;
- the file starts with a mode header and then writes aligned columns:
  `Layer`, `Flows`, `Packets`, `Original Bytes`;
- mode-specific identifiers are preserved according to the selected mode;
- export is mode-based, not driven by the current visual expand/collapse state.

## Detected Protocol Hints

![Detected Protocol Hints](images/statistics/statistics-detected-protocol-hints.png)

*Capture-wide detected-protocol hint distribution.*

`Detected Protocol Hints` groups recognized canonical flows by detected
protocol-hint classification.

Current columns:

- `Group`
- `Protocol`
- `Flows`
- `Packets`
- `Captured Bytes`
- `Original Bytes`

Current group meanings:

- `Confirmed`
- `Possible`
- `Unknown`

The screenshot shows a useful example mix, but it is not a fixed exhaustive
protocol list.

User-facing interpretation:

- `Confirmed` means the current product assigned a concrete detected protocol
  hint.
- `Possible` is a heuristic category used only where the current product
  supports that possibility class.
- `Unknown` means no specific detected protocol hint was assigned.

Current percentage denominators are source-verified and are internal to this
section:

- flow percentages use the total flow count across all hint rows in this
  section;
- packet percentages use the total packet count across all hint rows in this
  section;
- captured-byte percentages use total captured bytes across all hint rows;
- original-byte percentages use total original bytes across all hint rows.

## QUIC and TLS

![QUIC, TLS, and Top Endpoints/Ports](images/statistics/statistics-quic-tls-top.png)

*Recognition-quality statistics for QUIC and TLS, followed by top endpoints and
ports.*

The upper half of this view summarizes recognition-quality and metadata-coverage
statistics for QUIC and TLS flows.

### QUIC recognition

Current QUIC fields:

- `Flows`
- `Recognized Initial`
- `Unrecognized`
- `v1`
- `draft-29`
- `v2`
- `Version unavailable`

Current semantics:

- all counts here are flow counts, not packet counts;
- `Recognized Initial` and `Unrecognized` are percentages of total QUIC flows;
- version rows count QUIC flows by recognized version classification.

### TLS recognition

Current TLS fields:

- `Flows`
- `With SNI`
- `Without SNI`
- `TLS 1.2`
- `TLS 1.3`
- `Version unavailable`

Current semantics:

- all counts here are flow counts, not packet counts;
- `With SNI` and `Without SNI` are percentages of total TLS flows;
- version rows count TLS flows by recognized version classification.

## Top Endpoints and Ports

The lower half of the same screenshot shows:

- `Top Endpoints`
- `Top Ports`

Current columns:

- `Packets`
- `Bytes`

Current ranking semantics:

- both tables rank by original bytes descending;
- packet count is the secondary tie-breaker;
- endpoint or port text is the final deterministic tie-breaker.

Current endpoint semantics:

- each recognized canonical flow contributes its full packet count and original-
  byte total to both of its endpoints;
- endpoint packet totals therefore count packets involving that endpoint across
  all matching flows.

Current port semantics:

- each recognized canonical flow contributes its full packet count and original-
  byte total to both non-zero endpoint ports;
- protocols without ports do not add port rows.

Current UI shape:

- the section shows top `5` rows in each table;
- in the current desktop UI it is shown only when the active capture or index
  has more than `30` flows.

## Raw captures and indexes

Statistics is designed to work for both:

- an active raw capture; and
- a previously created Pcap Flow Lab index.

In the inspected Statistics loading paths, these sections are driven by stored
summary metadata rather than by selected-packet byte materialization. That
means Statistics does not follow the same source-byte reattachment constraints
as packet-bytes or stream-item-data inspection.

## Related documentation

- [Main window](main-window.md)
- [Flows workspace](flows.md)
- [Analysis workspace](analysis.md)
