# CLI V2 `flow-info` Command

## Status

This document defines the planned CLI v2 contract for:

```text
pcap-flow-lab flow-info
```

This is a design-only document.

The current production CLI does not yet implement:

- `flow-info` parsing
- `flow-info` dispatch
- `flow-info` help
- `flow-info` stdout rendering

The command is documented here so the later implementation can reuse the
current shared flow-analysis and flow-presentation architecture without adding
a second semantics layer.

## Purpose

`flow-info` presents a concise detailed report for exactly one canonical flow.

It is a metadata and analysis command.

It is intentionally different from:

```text
pcap-flow-lab flows
```

which lists and queries multiple flows.

It is also intentionally different from the future:

```text
pcap-flow-lab packet-info
```

which will own packet-specific inspection.

The initial command must work:

- for raw PCAP or PCAPNG input
- for PcapFlowLab index input
- without packet payload bytes
- without source-capture attachment

## Input Forms

These forms are planned:

```text
pcap-flow-lab flow-info capture.pcap --flow-number 42
pcap-flow-lab flow-info --input capture.pcap --flow-number 42
```

Positional input and `--input` are mutually exclusive input forms.

Using both in one invocation is invalid, even if the two paths are textually
identical or resolve to the same file.

Input may be:

- PCAP
- PCAPNG
- PcapFlowLab index

Input-kind detection should reuse the existing project input-detection path.

## Initial Syntax

```text
pcap-flow-lab flow-info <input> --flow-number <N> [options]
```

Equivalent explicit-input form:

```text
pcap-flow-lab flow-info --input <input> --flow-number <N> [options]
```

Initial options:

```text
--settings <settings.json>
--progress <auto|on|off>
-h
--help
```

The initial contract intentionally does not include:

- `--flow-numbers`
- `--filter`
- `--limit`
- `--sort`
- `--source-capture`
- `--format`
- `--columns`
- `--out`

## Exactly One Flow

`--flow-number <N>` is required.

It selects exactly one canonical flow.

Public flow numbers are one-based:

```text
public flow number = internal flow_index + 1
```

The selected flow number refers directly to canonical flow identity.

It is not renumbered by:

- current list ordering
- filtering
- sorting
- limiting

### Validity Rules

`N` must be a positive integer.

The following are invalid:

- zero
- negative values
- malformed text
- numeric overflow
- out-of-range canonical flow numbers

Point lookup should later reuse the existing efficient shared access path such
as:

- `CaptureSession::flow_row(...)`
- `FrontendSessionAdapter::flow_row(...)`

The implementation must not be designed around materializing all frontend flow
rows just to inspect one flow.

## Output Philosophy

The command prints one deterministic human-readable report to `stdout`.

The initial report uses stable sections:

- `Identity`
- `Traffic`
- `Direction`
- `Packet Size Histogram`
- `Timing`

The shape must stay broadly stable across protocols.

The initial contract does not add:

- protocol-specific deep sections
- packet rows
- stream data
- stream reassembly
- packet-specific Summary or Bytes surfaces

## Identity

The Identity section contains:

- `Endpoint A`
- `Endpoint B`
- `Family`
- `Protocol`
- `Protocol Hint`
- `Service`
- `Protocol Path`

Conceptual example:

```text
Identity
  Endpoint A:       10.10.205.13:46368
  Endpoint B:       216.58.209.174:443
  Family:           IPv4
  Protocol:         UDP
  Protocol Hint:    QUIC
  Service:          www.youtube.com
  Protocol Path:    EthernetII -> IPv4 -> UDP
```

### Endpoint Orientation

`Endpoint A` and `Endpoint B` are preserved because current flow orientation
is first-observed.

The initial CLI must not relabel them as:

- Source / Destination
- Client / Server
- Initiator / Responder

unless a future shared model provides those semantics explicitly.

### Protocol, Protocol Hint, and Service

Reuse the same shared user-facing values already used by:

- Qt
- Tauri
- CLI `flows`

Do not expose raw internal hint tokens when a shared display formatter exists.

### Protocol Path

Use the full shared Protocol Path presentation.

Conceptual example:

```text
EthernetII -> IPv4 -> UDP
```

Identifier-bearing path segments must preserve existing shared representation
for cases such as:

- VLAN VID
- MPLS label
- VXLAN VNI
- Geneve VNI
- GTP-U TEID
- GRE key

Do not expose internal `protocol_path_id`.

## Traffic

The Traffic section contains:

- `Packets`
- `Original Bytes`
- `Captured Bytes`
- `Max Captured Packet Size`

Conceptual example:

```text
Traffic
  Packets:                    5 630
  Original Bytes:             5.3 MB
  Captured Bytes:             5.3 MB
  Max Captured Packet Size:   1.5 KB
```

### Packets

Use the canonical flow packet count.

### Original Bytes

Use the authoritative flow original-byte total semantics already exposed by the
current flow/session model.

### Captured Bytes

Use the sum of `PacketRef::captured_length` across packets belonging to the
selected flow.

This may require a bounded walk of the selected flow's retained packet refs.

It must not:

- read packet payload bytes
- require source-capture attachment
- reopen a source capture for index input

### Max Captured Packet Size

Use the shared per-flow analysis statistic:

```text
max_captured_packet_size_bytes
```

Definition:

```text
maximum PacketRef captured_length in the selected flow
```

Do not:

- use `original_length`
- infer it from packet-size histogram buckets
- recompute it independently in CLI logic
- read source packet bytes

Reuse the same human-readable size formatting conventions already used by the
shared application layer where practical.

## Direction

The Direction section renders directional counters as a compact table.

Required conceptual shape:

```text
Direction
  Direction       Packets      Original Bytes
  A -> B              812            711.4 KB
  B -> A            4 818              4.6 MB
  Total             5 630              5.3 MB

  Packet Direction:   Mostly B -> A
  Data Direction:     Mostly B -> A
```

### A -> B and B -> A

These use the same first-observed Endpoint A/B orientation as the rest of the
application.

The command must not infer:

- client/server
- source/destination
- initiator/responder

### Table Fields

The required table columns are:

- `Direction`
- `Packets`
- `Original Bytes`

Use the existing shared directional counters:

- `packets_a_to_b`
- `packets_b_to_a`
- `bytes_a_to_b`
- `bytes_b_to_a`

The `Total` row must correspond to the authoritative complete-flow totals.

Do not add a second independent total calculation if the shared totals already
exist.

### Direction Summary Fields

Include:

- `Packet Direction`
- `Data Direction`

Reuse the existing shared presentation text from `FlowAnalysisResult` or an
equivalent frontend-neutral layer.

Do not include in the initial CLI report:

- `Packet Ratio`
- `Byte Ratio`

Those remain available to Qt and Tauri analysis but are intentionally omitted
from the initial CLI report to avoid redundant presentation.

## Packet Size Histogram

Render one deterministic text table containing all shared packet-size buckets
and all three existing directions.

Required conceptual shape:

```text
Packet Size Histogram
  Size          All      A -> B      B -> A
  0-63            0           0           0
  64-127      1 046         120         926
  128-255       189          30         159
  256-511       177          25         152
  512-1023      213          41         172
  1024-1399   4 005         596       3 409
  1400-1550       0           0           0
  1551-2499       0           0           0
  2500-5000       0           0           0
  5001+           0           0           0
```

The numeric counts above are illustrative only.

### Shared Histogram Authority

The CLI must consume the same shared structured histogram rows and bucket
definitions already used by Qt and Tauri.

The CLI must not duplicate:

- bucket boundaries
- bucket labels
- packet classification
- A -> B counting
- B -> A counting

The current shared authority is the existing flow-analysis histogram model and
its shared rows.

### Columns

`All`
: total packet count in the bucket

`A -> B`
: count using first-observed A -> B orientation

`B -> A`
: count using first-observed B -> A orientation

### Zero Buckets

Always render every defined bucket, including zero-valued buckets.

Reasons:

- deterministic stable output
- direct parity with the shared histogram definition
- fixed, small, human-readable table

### Histogram Scale Max

Do not render the UI-only histogram scale label:

```text
max: N
```

That value is useful for graphical bar scaling in Qt and Tauri but is not an
actual packet-size statistic.

It must not be confused with:

```text
Max Captured Packet Size
```

which is a real flow statistic and belongs in the Traffic section.

## Timing

The Timing section contains:

- `First Seen`
- `Last Seen`
- `Duration`
- `Largest Gap`

Conceptual example:

```text
Timing
  First Seen:       12:34:56.123456
  Last Seen:        12:34:58.654321
  Duration:         2.53 s
  Largest Gap:      740 ms
```

Reuse existing shared timestamp, duration, and gap text where available.

Do not invent a separate CLI-only timestamp convention.

For single-packet flows, keep the existing deterministic shared semantics for:

- `Duration`
- `Largest Gap`

rather than hiding those fields.

## Formatting

The initial stdout format is deterministic human-readable text.

Use human-readable formatting for:

- grouped integer counts
- byte values
- durations
- timestamps

Conceptual style:

```text
5 630
1 046
42 B
711.4 KB
5.3 MB
```

Columns should be aligned for terminal readability, but the renderer must not
depend on terminal-width detection.

ANSI formatting is not required.

Where practical, reuse existing shared formatting conventions and helpers for:

- grouped integers
- byte sizes
- duration text

## Unknown or Empty Values

Keep the report structure stable even when some textual metadata is absent.

For genuinely unavailable textual metadata, use the existing shared display
convention, preferably:

```text
-
```

Do not remove whole Identity fields merely because a specific flow lacks:

- a protocol hint
- a service hint
- protocol-specific enrichment

## Raw, Index, and Source Requirements

All initial `flow-info` data must remain metadata-backed.

Raw capture:

- supported

Index:

- supported

Index without attached source capture:

- supported

No initial `flow-info` section requires source packet bytes.

`--source-capture` is therefore not part of `flow-info`.

The command must not:

- require source-capture attachment
- reopen a source capture
- read packet payload bytes

## Settings

Support:

```text
--settings <settings.json>
```

for raw capture input.

Reuse the same narrow CLI settings schema already used by:

- `summary`
- `flows`
- `export-flows`

Grouping settings affect which canonical flows exist and therefore affect
which flow can be selected by `--flow-number`.

For index input:

- `--settings` is invalid

The same opened/imported session must be used for:

- canonical point lookup
- flow analysis
- protocol-path presentation

## Progress

Support:

```text
--progress auto|on|off
```

using the normal existing CLI input-open progress behavior.

Do not add a separate flow-analysis-specific progress model.

Point lookup and selected-flow analysis are expected to be sufficiently small.

Progress and warnings go to `stderr`.

The flow detail report goes to `stdout`.

## Partial Raw Capture

If a raw capture opens partially:

- preserve the normal partial-open warning
- allow `flow-info` to inspect a canonical flow that exists in the surfaced
  partial session
- report values only for surfaced packet metadata

Do not fabricate missing tail data.

## Index Parity

The intended contract is:

```text
same stored flow
    ->
equivalent flow-info semantics before and after index roundtrip
```

No source attachment should be needed for initial `flow-info`.

## Help And Error Behavior

Explicit help:

```text
pcap-flow-lab flow-info -h
pcap-flow-lab flow-info --help
```

must:

- return success
- require no input
- open nothing
- print flow-info-specific help to `stdout`

Syntax errors should print:

- a concise error
- flow-info-specific help

and return non-zero.

Runtime errors such as an out-of-range canonical flow number should print:

- a concise operational error only

and return non-zero.

No-argument global help behavior remains a top-level CLI concern rather than a
flow-info-specific one.

## Applicability Matrix

| Capability | Raw capture | Index |
| --- | --- | --- |
| `--flow-number` | yes | yes |
| `--settings` | yes | no |
| `--progress` | yes | yes |
| `--source-capture` | no | no |
| Identity | yes | yes |
| Traffic | yes | yes |
| Direction | yes | yes |
| Packet Size Histogram | yes | yes |
| Timing | yes | yes |

No initial `flow-info` section requires source packet bytes.

## Relationship To `flows`

`flows` owns:

- listing multiple flows
- canonical selection sets
- filtering
- sorting
- limiting
- metadata CSV export

`flow-info` owns:

- detailed presentation of exactly one canonical flow

The command must not add multi-flow query behavior.

## Relationship To Future `packet-info`

The following do not belong in the initial `flow-info` surface:

- packet list
- packet-number selection
- packet Summary
- packet byte views
- packet payload
- stream items
- stream reassembly
- TLS, HTTP, or QUIC deep packet or stream detail

Those belong to the future packet-inspection surface.

## Structured Output

The initial contract does not define:

- JSON
- other structured formats
- `--format`

Structured output remains deferred consistently with the broader CLI v2 work.

## Fragment Metadata

Do not include fragmented-packet count in the initial `flow-info` surface.

Although fragment metadata exists in the current model, it is intentionally
outside this basic release-stage report.

Do not add a separate `Other` section solely to show fragment metadata.

## Implementation Architecture Note

Future implementation should preferably use:

```text
canonical flow index
    ->
narrow frontend-neutral flow-info or presentation DTO
    ->
CLI text renderer
```

The CLI renderer should not independently inspect arbitrary `Connection`
internals as its primary public contract.

The shared flow-info model should compose authoritative data from:

- `FlowRow`
- `FlowAnalysisResult`
- `ProtocolPathPresentation`
- shared protocol, hint, and service formatters
- shared packet-size histogram rows

Avoid requiring selected-flow mutable UI state solely to produce CLI output.

Do not materialize all flows just to inspect one.

## Examples

```text
pcap-flow-lab flow-info capture.pcap --flow-number 42
```

```text
pcap-flow-lab flow-info --input capture.pcapng --flow-number 42
```

```text
pcap-flow-lab flow-info capture.pcap \
    --settings settings.json \
    --flow-number 42
```

```text
pcap-flow-lab flow-info capture.pflidx --flow-number 42
```

## Intentionally Deferred

The following remain intentionally deferred:

- flow filtering in `flow-info`
- flow ranges in `flow-info`
- multi-flow `flow-info` output
- `--sort`
- `--limit`
- `--format`
- JSON
- output files
- packet listing
- packet details
- source-capture attachment
- stream analysis
- protocol-specific deep sections
- fragment metadata
- `Packet Ratio`
- `Byte Ratio`
- directional captured-byte counters
- inter-arrival histogram
