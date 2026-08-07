# CLI V2 `summary` Command

## Status

This document defines the planned CLI v2 contract for:

```text
pcap-flow-lab summary
```

It is a documentation-only design contract.

- Implementation has not yet caught up to this document.
- The current production CLI remains legacy.
- This document does not implement CLI parsing or rendering yet.

## Purpose

`summary` provides whole-input capture or index overview and selected
whole-capture statistics.

It works with:

- PCAP
- PCAPNG
- PcapFlowLab index

`summary` always describes the complete opened capture or index.

It does not select, filter, sort, limit, or reinterpret subsets of flows.

## Default Invocation

These forms are conceptually equivalent:

```text
pcap-flow-lab capture.pcap
pcap-flow-lab summary capture.pcap
pcap-flow-lab --input capture.pcap
pcap-flow-lab summary --input capture.pcap
```

Positional input and `--input` are mutually exclusive input forms.

Using both in the same invocation is invalid, even when both paths are
identical:

```text
pcap-flow-lab summary capture.pcap --input capture.pcap
```

`--input` may be used to disambiguate a file path that conflicts with a known
command name.

## Initial Planned Syntax

```text
pcap-flow-lab [summary] <input> [options]
```

Input and import options:

```text
--input <path>
--settings <settings.json>
```

Additional presentation:

```text
--extended
--protocol-path-tree
--protocol-path-mode <kind-overview|identity-tree|terminal-paths>
```

Side outputs:

```text
--out-index <path>
--out-flows-list <path>
--out-protocol-path-tree <path>
```

Runtime and output policy:

```text
--progress <auto|on|off>
--force
```

The initial implemented stdout format is human-readable text.

This document does not add `--format` to the initial `summary` command syntax.
Future structured formats such as JSON remain deferred.

`summary` does not accept:

```text
--source-capture
```

All Basic, Extended, and Protocol Path summary data is intended to work from an
index without source packet bytes.

## Basic Summary

Basic Summary is always printed to stdout.

Illustrative shape:

```text
PcapFlowLab Summary

Input
  File:                   Firefox_data_123.pcapng
  Type:                   PCAPNG
  File size:              49.7 MB

Capture
  Flows:                  741
  Packets:                50 751
  Captured bytes:         49.5 MB
  Original bytes:         49.5 MB
  Unrecognized packets:   17

Transport Summary

Transport    Flows       Packets       Captured Bytes    Original Bytes
TCP          ...
UDP          ...
SCTP         ...
Other        ...

IP Family Summary

Family       Flows       Packets       Captured Bytes    Original Bytes
IPv4         ...
IPv6         ...
```

Numeric values in this document are illustrative unless explicitly tied to a
verified deterministic fixture.

## Input Section

The Input section shows:

- file basename
- input type
- input file size

Input type conceptually distinguishes:

- PCAP
- PCAPNG
- PcapFlowLab Index

For index input, `summary` may also show an informational source-capture line:

```text
Source capture:          Firefox_data_123.pcapng
```

If the stored source capture is unavailable, summary must still work. A planned
informational presentation such as the following is acceptable:

```text
Source capture:          Firefox_data_123.pcapng (not available)
```

Normal summary presentation should not print full paths by default. Full paths
remain appropriate for diagnostics and errors.

## Capture Totals Semantics

Public CLI semantics for the Capture section are:

`Packets`
: whole-capture packet count, including unrecognized packets

`Captured bytes`
: whole-capture sum of captured packet lengths, including unrecognized packets

`Original bytes`
: whole-capture sum of original packet lengths, including unrecognized packets

`Flows`
: recognized and listed flows only

`Unrecognized packets`
: count of packets that did not become recognized flows under existing project
  semantics

`Captured bytes` and `Original bytes` must not be redefined as the sum of only
recognized transport rows.

### Current Implementation Note

Current shared DTO support still has an implementation gap:

- whole-capture Original Bytes already exists in backend capture summary state
- current frontend overview byte totals are recognized-flow totals
- a shared whole-capture Captured Bytes value still needs to be exposed before
  CLI summary implementation is complete

This is a known implementation gap. It is not a change to the desired public
CLI contract.

## Transport Summary

Transport Summary uses the current shared transport-category semantics.

Fixed rows:

- TCP
- UDP
- SCTP
- Other

Columns:

- Transport
- Flows
- Packets
- Captured Bytes
- Original Bytes

All four rows remain visible, including zero-valued rows.

`Other` means recognized flows whose terminal transport classification is not
TCP, UDP, or SCTP.

It does not mean unrecognized packets.

Transport row packet and byte values describe packets belonging to matching
recognized flows. Transport Summary totals therefore do not have to equal
whole-capture totals when unrecognized traffic exists.

## IP Family Summary

IP Family Summary uses the current shared IP-family semantics.

Fixed rows:

- IPv4
- IPv6

Columns:

- Family
- Flows
- Packets
- Captured Bytes
- Original Bytes

Both rows remain visible even when zero.

There is no `Other` family row in the initial contract.

Non-IP recognized flows are excluded from this table. As a result, `IPv4` +
`IPv6` totals may be smaller than:

- whole-capture totals
- Transport Summary totals

This is expected and not an error.

## No Timestamps

The initial `summary` contract does not include:

- first packet timestamp
- last packet timestamp
- duration

Those may be reconsidered later, but they are outside the current command
contract.

## Extended Summary

`--extended` appends whole-capture statistics after Basic Summary.

It does not replace Basic Summary.

The extended sections are:

1. Packet Size Distribution
2. Flows by Packet Count
3. Detected Protocol Hints
4. Top Endpoints and Ports

`--extended` does not add:

- QUIC and TLS
- Protocol Path Tree automatically

Protocol Path Tree is controlled independently.

## Packet Size Distribution

Packet Size Distribution uses the existing fixed captured-length buckets:

- 0-63
- 64-127
- 128-255
- 256-511
- 512-1023
- 1024-1399
- 1400-1550
- 1551-2499
- 2500-5000
- 5001-9000
- 9001-16000
- 16001-25000
- 25001+

Illustrative table:

```text
Packet Size Distribution

Captured Size       Packets       Percent
0-63                  8 241        16.2%
64-127               12 504        24.6%
...
```

All fixed buckets remain visible, including zero-valued buckets.

Bucket basis is captured packet length.

Unrecognized packets are included.

CLI `Percent` means:

```text
bucket packet count / total capture packet count
```

The current GUI `normalized_fraction` is only a bar-normalization value:

```text
bucket packet count / maximum bucket packet count
```

That GUI normalization value must not be printed as a CLI percentage.

## Flows by Packet Count

Flows by Packet Count is one packet-count bucketization with two metrics.

It is not a separate `Flows by Bytes` distribution.

It uses the existing fixed packet-count buckets:

- 1
- 2
- 3-5
- 6-10
- 11-25
- 26-50
- 51-100
- 101-250
- 251-500
- 501-1000
- 1001-5000
- 5001+

Illustrative table:

```text
Flows by Packet Count

Packets / Flow    Flows             Original Bytes
1                 113 (15.2%)       19.4 KB (0.04%)
2                 299 (40.4%)       84.5 KB (0.17%)
...
5001+               2 (0.27%)       10.9 MB (22%)
```

All fixed buckets remain visible, including zero-valued buckets.

The two metrics are:

`Flows`
: number of flows whose packet count falls in the bucket

`Original Bytes`
: total original bytes contributed by all flows whose packet count falls in the
  same bucket

CLI percentages are total-based:

```text
flow percentage = bucket flow count / total included histogram flow count
original-byte percentage = bucket original bytes / total included histogram original bytes
```

The existing GUI normalized fractions are bar-normalization values and must not
be used as CLI percentages.

The CLI intentionally shows both metrics at once over the same bucket axis.

## Detected Protocol Hints

Detected Protocol Hints reuses the existing shared protocol-hint model.

Shared row semantics currently include:

- protocol label or group
- flow count
- packet count
- captured bytes
- original bytes
- prepared presentation text

Illustrative table:

```text
Detected Protocol Hints

Protocol Hint          Flows       Packets       Captured Bytes    Original Bytes
Confirmed HTTP         ...
Confirmed TLS          ...
Possible TLS           ...
Confirmed DNS          ...
Confirmed QUIC         ...
Possible QUIC          ...
...
```

The existing shared ordering is retained.

Current possible rows include:

- Confirmed HTTP
- Confirmed TLS
- Possible TLS
- Confirmed DNS
- Confirmed QUIC
- Possible QUIC
- Confirmed SSH
- Confirmed STUN
- Confirmed BitTorrent
- Confirmed Mail protocols
- Confirmed DHCP
- Confirmed mDNS
- Unknown

For CLI text output:

- show non-zero rows only
- retain `Unknown` when it is non-zero
- do not invent new hint categories
- do not reclassify protocols in CLI code

If all rows are zero, print a concise empty state such as:

```text
None
```

## Top Endpoints and Ports

Top Endpoints and Ports reuses the existing shared top-summary model.

The initial CLI uses the existing default top limit:

```text
5
```

There is no `--top` option yet.

### Top Endpoints

Illustrative table:

```text
Top Endpoints

Endpoint                         Packets       Original Bytes
192.168.0.152                     14 821          18.2 MB
...
```

Use only current shared fields:

- endpoint label
- packet count
- original or total bytes

Do not add:

- flow count
- percentage
- service
- protocol

Ordering remains:

- bytes descending
- packets descending
- endpoint text tie-break

### Top Ports

Illustrative table:

```text
Top Ports

Port        Packets       Original Bytes
443          12 348          15.4 MB
53              492         102.3 KB
...
```

Use only current shared fields:

- port number
- packet count
- original or total bytes

Important semantic note:

Top Ports currently aggregates by numeric port value only.

It does not distinguish:

- TCP/443
- UDP/443

and it does not currently expose service names.

The CLI must not introduce protocol or service dimensions just for `summary`.

## Protocol Path Tree

Protocol Path Tree is independent of `--extended`.

Stdout preview is enabled with:

```text
--protocol-path-tree
```

Supported modes:

```text
--protocol-path-mode kind-overview
--protocol-path-mode identity-tree
--protocol-path-mode terminal-paths
```

Default mode:

```text
kind-overview
```

The existing shared complete plain-text exporter remains authoritative for full
Protocol Path Tree export.

### CLI Stdout Preview

When `--protocol-path-tree` is requested, append a Protocol Path Tree preview
after all Basic and Extended sections.

The stdout preview is limited to:

```text
25 logical rows
```

This limit applies only to CLI stdout presentation.

It must not modify the shared complete exporter.

If more than 25 logical rows exist, append a truncation note equivalent to:

```text
... 137 additional rows not shown.
Use --out-protocol-path-tree <file> to export the complete Protocol Path Tree.
```

If the result has 25 or fewer rows, no truncation note is needed.

Preview and full export use the same mode and data semantics.

### Mode Behavior

Valid:

```text
summary capture.pcap --protocol-path-tree
summary capture.pcap --protocol-path-tree --protocol-path-mode identity-tree
summary capture.pcap --protocol-path-mode identity-tree --out-protocol-path-tree tree.txt
summary capture.pcap --protocol-path-tree --protocol-path-mode identity-tree --out-protocol-path-tree tree.txt
```

Invalid:

```text
summary capture.pcap --protocol-path-mode identity-tree
```

when neither `--protocol-path-tree` nor `--out-protocol-path-tree` is present.

The CLI does not support different preview and export modes in one invocation.

## Side Outputs

Planned side outputs:

```text
--out-index <path>
--out-flows-list <path>
--out-protocol-path-tree <path>
```

Side outputs must not implicitly change stdout presentation.

For example:

```text
summary capture.pcap \
    --out-index capture.idx \
    --out-flows-list flows.csv \
    --out-protocol-path-tree protocol-tree.txt
```

still prints only Basic Summary to stdout unless `--extended` and-or
`--protocol-path-tree` are explicitly requested.

Successful side-output notifications belong on `stderr`, not `stdout`.

Illustrative messages:

```text
Index written to: capture.idx
Flow list written to: flows.csv
Protocol Path Tree written to: protocol-tree.txt
```

Exact wording remains an implementation detail.

### `--out-index`

`--out-index` is allowed only for raw capture input.

It creates a reusable PcapFlowLab index from the already imported capture.

It is invalid for index input.

It is not defined as an index-copy operation.

### `--out-flows-list`

`--out-flows-list` is allowed for raw capture and index input.

Under `summary`, it exports the complete canonical flow list.

It is not affected by:

- filters
- sorting
- limits

because those options are not accepted by `summary`.

Filtered, sorted, or limited flow-list export belongs to the future `flows`
command design.

The exact CSV schema remains owned by the `flows` command design and is not
duplicated here.

### `--out-protocol-path-tree`

`--out-protocol-path-tree` is allowed for raw capture and index input.

It exports the complete Protocol Path Tree for the selected mode.

The default mode is:

```text
kind-overview
```

It uses the existing shared C++ plain-text exporter.

The file export is complete and is not subject to the 25-row stdout preview
limit.

## Settings

`--settings <settings.json>` is allowed only when importing a raw capture.

It is invalid for index input.

Reason:

Import-time settings may change flow grouping.

An existing index already stores its grouping and must not be reinterpreted.

Settings apply consistently to the imported session and therefore affect:

- flow count
- flow-based summary statistics
- Protocol Path Tree
- `--out-index`
- `--out-flows-list`

The initial JSON schema is not frozen here beyond the architecture-level
flow-grouping concept.

## `--source-capture`

`summary` does not accept:

```text
--source-capture
```

All Basic, Extended, and Protocol Path summary data is intended to be available
index-only.

Source capture availability is informational only for `summary`.

## `--force`

Output files are not silently overwritten.

Without `--force`, an existing output path should cause failure.

With `--force`, existing side-output files may be replaced.

### Preflight Principle

Obvious output errors should be checked before expensive raw-capture processing
where practical.

Examples:

- output already exists without `--force`
- output directory does not exist or is not writable
- output conflicts with input
- multiple side outputs resolve to the same path

The CLI should avoid processing a very large capture only to discover a known
output-path conflict at the end.

## Progress

Supported:

```text
--progress auto
--progress on
--progress off
```

Default:

```text
auto
```

Progress belongs to `stderr`.

Requested summary content belongs to `stdout`.

The exact cross-platform dynamic terminal implementation remains deferred.

## stdout And stderr

Global stream contract for `summary`:

`stdout`
:
- Basic Summary
- Extended sections when requested
- Protocol Path preview when requested

`stderr`
:
- progress
- warnings
- errors
- diagnostics
- successful side-output notifications

Example:

```text
pcap-flow-lab summary capture.pcap > summary.txt
```

must produce a clean `summary.txt` without progress text.

## Unsupported Options

`summary` rejects flow and packet selection options rather than silently
ignoring them.

Invalid for `summary`:

- `--filter`
- `--flow-number`
- `--flow-numbers`
- `--sort`
- `--limit`
- `--packets-in-flow`
- `--packets-in-file`
- `--source-capture`

Conceptual reason:

- `summary` is whole-capture
- flow subset work belongs to `flows` and `export-flows`
- packet selection belongs to `packet-info`

## Input Applicability Matrix

| Capability | Raw capture | Index |
| --- | --- | --- |
| Basic Summary | yes | yes |
| `--extended` | yes | yes |
| `--protocol-path-tree` | yes | yes |
| `--protocol-path-mode` | yes | yes |
| `--settings` | yes | no |
| `--out-index` | yes | no |
| `--out-flows-list` | yes | yes |
| `--out-protocol-path-tree` | yes | yes |
| `--progress` | yes | yes |
| `--force` | yes | yes |
| `--source-capture` | no | no |

## Index-Only Behavior

An index-only summary must work without the original source capture for:

- Basic Summary
- Packet Size Distribution
- Flows by Packet Count
- Detected Protocol Hints
- Top Endpoints and Ports
- Protocol Path Tree

Source capture availability is informational only for `summary`.

## Formatting

Initial stdout is deterministic human-readable text.

Shared C++ formatting is preferred for:

- grouped integer counts
- byte sizes
- percentages
- combined count and percent values

The implementation should avoid locale-dependent formatting differences across:

- Windows
- Linux
- macOS

Illustrative formatting style:

```text
50 751
49.5 MB
99.3%
<0.01%
741 (100%)
```

Exact shared formatter implementation remains deferred to the later
implementation pass.

## Known Implementation Gaps

### A. Whole-Capture Captured Bytes

Desired CLI semantics require:

```text
sum of captured packet lengths across the complete capture,
including unrecognized packets
```

Current frontend overview byte totals are recognized-flow totals.

A shared whole-capture captured-byte value must be exposed before CLI summary
implementation is complete.

### B. Input Metadata DTO

Input path, type, and file size exist in current session and source metadata
but are not yet exposed as one CLI-ready frontend-neutral DTO.

A small frontend-neutral extension will likely be needed.

### C. Packet Size Percentage Presentation

Existing GUI `normalized_fraction` is bar normalization against the largest
bucket, not percentage of all packets.

CLI needs deterministic total-based percentage presentation.

### D. Flow Histogram Percentage Presentation

Existing GUI normalized fractions are bar-normalization values.

CLI needs total-based:

- flow percentage
- original-byte percentage

These are presentation or frontend-neutral gaps. No new statistics algorithms
are otherwise required for the agreed `summary` contract.

## Output Examples

### 1. Basic Raw Capture

Command:

```text
pcap-flow-lab capture.pcap
```

Stdout:

```text
PcapFlowLab Summary
...
```

Stderr:

```text
[progress and diagnostics, if any]
```

Generated files:

- none

### 2. Basic Index

Command:

```text
pcap-flow-lab summary capture.idx
```

Stdout:

```text
PcapFlowLab Summary
...
```

Generated files:

- none

### 3. Extended

Command:

```text
pcap-flow-lab summary capture.pcap --extended
```

Stdout:

```text
PcapFlowLab Summary
...

Packet Size Distribution
...

Flows by Packet Count
...
```

### 4. Protocol Path Preview

Command:

```text
pcap-flow-lab summary capture.idx \
    --protocol-path-tree \
    --protocol-path-mode identity-tree
```

Stdout:

```text
PcapFlowLab Summary
...

Protocol Path Tree
...
```

### 5. Full Protocol Path Side Output Without Preview

Command:

```text
pcap-flow-lab summary capture.idx \
    --out-protocol-path-tree protocol-path.txt
```

Stdout:

```text
PcapFlowLab Summary
...
```

Stderr:

```text
Protocol Path Tree written to: protocol-path.txt
```

Generated files:

- `protocol-path.txt`

### 6. Multiple Side Outputs From One Raw Import

Command:

```text
pcap-flow-lab summary huge.pcap \
    --settings settings.json \
    --out-index huge.idx \
    --out-flows-list flows.csv \
    --out-protocol-path-tree protocol-path.txt
```

Stdout:

```text
PcapFlowLab Summary
...
```

Stderr:

```text
[progress]
Index written to: huge.idx
Flow list written to: flows.csv
Protocol Path Tree written to: protocol-path.txt
```

Generated files:

- `huge.idx`
- `flows.csv`
- `protocol-path.txt`

### 7. Invalid Uses

Invalid:

```text
summary capture.idx --settings settings.json
summary capture.idx --out-index copy.idx
summary capture.pcap --filter QUIC
summary capture.pcap --protocol-path-mode identity-tree
```

Exact error wording remains an implementation detail.

## Intentionally Deferred Decisions

This document does not finalize:

- machine-readable `--format` output
- JSON schema design
- CSV schema design for flow-list export
- exact side-output success wording
- exact human-readable error wording
- dynamic terminal progress implementation details
- `--top` or other top-summary customization
- timestamps or duration
- QUIC and TLS summary sections
- any new statistics calculations
