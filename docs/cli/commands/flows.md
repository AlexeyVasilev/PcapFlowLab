# CLI V2 `flows` Command

## Status

This document defines the target CLI v2 contract for:

```text
pcap-flow-lab flows
```

The current production CLI now routes the explicit `flows` command through the
documented v2-style parser, help, query, preview, and subset CSV export path.

Shared canonical flow querying and subset flow-metadata CSV export remain
implemented in shared session/backend code and are reused by the production CLI
surface.

## Purpose

`flows` lists flow metadata from a complete raw capture or PcapFlowLab index.

It is a metadata-only command.

It must work without source packet bytes.

It supports:

- canonical flow-number selection
- text filtering
- sorting
- limiting the result set
- bounded stdout preview
- CSV metadata export

## Input Forms

These forms are supported conceptually:

```text
pcap-flow-lab flows capture.pcap
pcap-flow-lab flows --input capture.pcap
```

Positional input and `--input` are mutually exclusive.

Using both is invalid even when the paths are identical.

Input may be:

- PCAP
- PCAPNG
- PcapFlowLab index

Input kind detection should reuse the existing project input-detection path
rather than relying only on file extension.

## Initial Syntax

```text
pcap-flow-lab flows <input> [options]
```

Input and import:

```text
--input <path>
--settings <settings.json>
```

Selection:

```text
--flow-number <N>
--flow-numbers <ranges>
--filter <text>
--sort <field>:<asc|desc>
--limit <N>
```

Output:

```text
--out-flows-list <path>
```

Runtime:

```text
--progress <auto|on|off>
--force
```

Help:

```text
-h
--help
```

The initial contract does not include:

- `--source-capture`
- `--format`
- `--columns`

## Canonical Flow Numbering

Public CLI flow numbers are one-based.

The contract is:

```text
flow_number = internal flow_index + 1
```

Internal `flow_index` remains zero-based.

Canonical flow number is identity, not current table position.

Filtering, sorting, and limiting must never renumber flows.

Example:

```text
No.
17
203
914
```

is a valid sorted or filtered result.

Those rows must not be renumbered to:

```text
1
2
3
```

## Canonical Ordering

With no selectors, filter, or sort, logical flow ordering is the session's
existing canonical flow order.

This corresponds to ascending internal `flow_index` and ascending one-based
flow number.

Raw capture and reopened index should preserve the existing session or index
canonical ordering semantics.

The CLI must not create a new independent flow identity.

## Selection Pipeline

The command pipeline is:

```text
canonical flows
    ->
explicit flow-number selection
    ->
text filter
    ->
sorting
    ->
explicit --limit, if present
    ->
logical result set
    ->
stdout preview and-or CSV export
```

The implicit 25-row stdout preview cap is not part of the logical result-set
pipeline.

It is presentation only.

## Explicit Flow Selection

### `--flow-number`

```text
--flow-number <N>
```

Example:

```text
--flow-number 42
```

Rules:

- user-facing value is one-based
- zero is invalid
- values outside the available canonical flow range are invalid
- resulting canonical identity is preserved

### `--flow-numbers`

```text
--flow-numbers <ranges>
```

Examples:

```text
--flow-numbers 1-10
--flow-numbers 1-10,24,31-35
```

Rules:

- user-facing values are one-based
- zero is invalid
- ranges are inclusive
- duplicates are removed
- descending ranges such as `10-5` are invalid
- malformed ranges are invalid
- values outside the available canonical flow range are invalid
- resulting canonical identities are preserved

`--flow-number` and `--flow-numbers` are mutually exclusive.

Invalid flow numbers must fail rather than being silently ignored.

### Selector Ordering

Explicit selectors are applied before filtering and sorting.

For example:

```text
--flow-numbers 100-200 --filter TLS
```

means:

1. select canonical flows 100 through 200
2. retain only matching selected flows

## Text Filter

```text
--filter <text>
```

Initial CLI filter semantics are:

- case-insensitive
- substring matching
- one plain text query
- no regex syntax
- no token language

Search these semantic fields:

- family
- protocol
- protocol hint
- service hint
- address A
- address B
- endpoint A
- endpoint B
- textual port A
- textual port B

Do not search:

- fragmented-packet metadata
- the keyword `frag`
- packet counts
- byte counts
- protocol path
- Wireshark filters

### Shared-Semantics Direction

The CLI contract is the intended shared semantic direction.

Current Qt and Tauri flow text filtering already diverge slightly.

Implementation should introduce or reuse a shared semantic text-matching layer
rather than inheriting either frontend behavior implicitly.

Fragmented-packet search and `frag` matching are intentionally excluded from
the CLI contract.

## Sorting

```text
--sort <field>:<asc|desc>
```

Initial valid fields:

```text
number
protocol
service
endpoint-a
endpoint-b
packets
bytes
```

Examples:

```text
--sort number:asc
--sort packets:desc
--sort bytes:desc
--sort service:asc
--sort endpoint-a:asc
```

Direction is required explicitly.

Supported directions:

- `asc`
- `desc`

### Field Semantics

`number`
: numeric canonical one-based flow number

`protocol`
: existing flow `protocol_text`

`service`
: existing service hint

`endpoint-a`
: Endpoint A semantic value

`endpoint-b`
: Endpoint B semantic value

`packets`
: numeric `packet_count`

`bytes`
: numeric flow total or original byte count

Numeric fields must not be sorted lexicographically.

Endpoint sorting should use shared endpoint semantic fields rather than
treating the final formatted table cell as an opaque string if a structured
comparator can be shared cleanly.

### Tie-Break

Canonical flow number is the deterministic final tie-break.

Sorting changes order, not identity.

Protocol Path sorting is not part of the initial contract.

Fragmented-packet sorting is not part of the initial contract.

## `--limit`

```text
--limit <N>
```

Rules:

- `N` must be a positive integer
- zero is invalid
- negative values are invalid
- it is applied after explicit selection, filter, and sort
- it does not renumber flows

Example:

```text
pcap-flow-lab flows capture.pcap \
    --filter TLS \
    --sort bytes:desc \
    --limit 50
```

produces a logical result set of at most 50 flows.

## Default Stdout Preview

Normal stdout shows at most:

```text
25 flow rows
```

by default.

This is a terminal presentation cap only.

It is not the same as `--limit`.

Without `--limit`, the logical result set remains complete even when stdout
shows only the first 25 rows.

Conceptual footer:

```text
Showing 25 of 3 412 flows.
Use --limit <N> to show more rows or --out-flows-list <path> to export the result.
```

This footer is required only when the default 25-row stdout preview truncates
non-empty output.

### Interaction With Explicit `--limit`

If the user explicitly supplies `--limit N`, that limit constrains the logical
result set itself.

The initial design also treats explicit `--limit N` as the user's request to
allow up to `N` stdout rows.

Therefore:

- no explicit limit -> safe 25-row preview
- explicit limit -> show up to the requested result limit
- explicit limit with non-empty output -> always print `Showing X of Y flows.`

For this footer:

- `X` is the final post-limit result size rendered to stdout
- `Y` is the result count after selectors/filter/sort and before explicit limit
- CSV remains post-limit and is unaffected by the footer

Examples:

```text
Showing 30 of 64 393 flows.
Showing 50 of 3 412 flows.
Showing 7 of 7 flows.
```

Example:

```text
pcap-flow-lab flows capture.pcap --filter TLS
```

may show 25 rows while logically matching 3 412 flows.

Example:

```text
pcap-flow-lab flows capture.pcap --filter TLS --limit 50
```

has a logical result of at most 50 flows, may show all 50 rows, and should
print:

```text
Showing 50 of 3 412 flows.
```

## Default Stdout Table

Required columns:

```text
No.
Endpoint A
Endpoint B
Protocol
Detected Protocol
Service
Path
Packets
Original Bytes
```

Conceptual output:

```text
Flows

No.  Endpoint A            Endpoint B            Protocol  Detected Protocol  Service      Path         Packets  Original Bytes
1    10.10.205.13:51988   91.185.14.204:443    QUIC      ...            googlevideo  EII-Ip4-UDP  4 920    5.7 MB
...
```

Detected Protocol and Service are required default columns.

Do not remove them from the initial flow table.

Do not add Family by default unless implementation experience later proves it
necessary.

Do not add fragmented-packet metadata by default.

Do not relabel Endpoint A or Endpoint B as Source or Destination.

The project uses first-observed flow orientation, and the stable user-facing
terms remain Endpoint A and Endpoint B.

## Protocol Column

Use the existing flow-level protocol presentation.

The CLI should reuse existing `protocol_text` semantics rather than reducing
the column to raw transport only.

The CLI must not create new protocol classification logic.

## Detected Protocol

Use the existing detected-protocol presentation.

The CLI must not reclassify or infer protocols.

## Service

Use the existing service hint presentation.

Do not hide the Service column when empty.

An empty value may render as an empty cell or a consistent placeholder,
depending on the final table renderer.

## Protocol Path Column

The default flow table must include a compact Protocol Path representation.

Use the same compact flow-list presentation semantics already used by the UI.

Conceptually:

```text
EII-Ip4-UDP
```

Do not render the full verbose path in the terminal table:

```text
EthernetII->IPv4->UDP
```

Do not recreate compact abbreviations manually in CLI.

Reuse the existing shared Protocol Path compact presentation helper.

The terminal table uses compact path text.

CSV export continues using the existing full protocol path representation.

## Table Formatting

Human-readable stdout should be deterministic.

Requirements:

- spaces, not tabs
- no ANSI colors by default
- no trailing whitespace
- numeric values formatted through existing shared helpers where available
- no semantic truncation based on terminal width
- preserve complete canonical flow number
- preserve endpoint text
- preserve Detected Protocol, Service, and compact Path values

If very long strings make the table wide, the first implementation should
prefer complete data over hidden semantic truncation.

This pass does not define `--columns`.

## No Results

If the logical result set is empty after selectors or filtering, the command
prints a concise valid empty result rather than treating the condition as an
error.

Conceptually:

```text
Flows

No matching flows.
```

Exit successfully.

Invalid selectors are different and must fail.

## CSV Metadata Export

```text
--out-flows-list <path>
```

This is a metadata or flow-list export.

It is not packet or capture export.

Implementation should reuse the existing shared flow metadata CSV functionality
and schema as much as possible.

### Current Established Schema

The initial contract retains the existing CSV columns:

```text
flow_id
family
transport
protocol
protocol_hint
src_ip
src_port
dst_ip
dst_port
packet_count
captured_bytes
original_bytes
first_timestamp
last_timestamp
duration_us
protocol_path
```

This pass does not rename or redesign the schema.

It does not create a second parallel CLI CSV schema.

The existing CSV behavior should be preserved for:

- field escaping
- quoting
- UTF-8 or ASCII-compatible output
- newline behavior
- full `protocol_path` representation

## `flow_id` Semantics

For CLI v2 export:

```text
flow_id = internal flow_index + 1
```

`flow_id` must therefore represent canonical one-based flow identity even
after:

- explicit flow selection
- filtering
- sorting
- limiting

Example:

```text
--flow-numbers 100,500,900
```

must export:

```text
100
500
900
```

not:

```text
1
2
3
```

If the current shared exporter appears correct only because all-flows export
row ordinal happens to equal canonical flow number, later implementation must
preserve canonical identity when subset export is added.

The contract does not rename `flow_id`.

## CSV Ordering

CSV rows use the same logical result ordering as stdout before stdout preview.

Pipeline:

```text
selection
    ->
filter
    ->
sort
    ->
explicit limit
    ->
CSV rows
```

The implicit default 25-row terminal preview does not truncate CSV export.

Examples:

```text
pcap-flow-lab flows capture.pcap \
    --filter TLS \
    --out-flows-list tls.csv
```

may show the first 25 matching rows on stdout but write all matching rows to
`tls.csv`.

```text
pcap-flow-lab flows capture.pcap \
    --filter TLS \
    --sort bytes:desc \
    --limit 50 \
    --out-flows-list tls.csv
```

writes at most 50 rows, in the same sorted order.

## Future Summary Reuse

The future:

```text
pcap-flow-lab summary capture.pcap --out-flows-list flows.csv
```

should eventually reuse the same shared exporter with:

- no selectors
- no filter
- no custom sort
- no explicit limit

This would produce the complete canonical flow list.

That future summary-side output is intentionally not implemented in this pass.

## `--force`

Without `--force`, an existing `--out-flows-list` target causes failure.

With `--force`, the existing output file may be replaced.

`flows` should reuse the same side-output and preflight conventions already
implemented for `summary`.

Obvious output conflicts should be checked before expensive raw-capture import
where practical.

## `--progress`

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

`flows` should reuse the same CLI progress semantics already established for
`summary`.

Progress belongs to `stderr`.

Requested flow-table data belongs to `stdout`.

CSV data belongs to the output file.

This pass does not define a second independent progress system.

## Settings

`--settings <settings.json>` is supported only for raw PCAP or PCAPNG import.

It is rejected for existing index input.

`flows` reuses the current intentionally narrow CLI JSON settings contract:

- `ignore_vlan_and_mpls_layers_when_grouping_flows`
- `ignore_gtpu_teids_when_grouping_inner_flows`
- `validate_selected_packet_checksums`

The two grouping settings may affect flow identity and flow count.

`validate_selected_packet_checksums` is accepted as part of the common CLI
settings schema but has no effect on flow listing.

`flows` does not add checksum work.

`flows` does not add GUI-only settings.

## Index Behavior

All flow-list functionality must work index-only without source packet bytes:

- basic flow list
- explicit flow-number selection
- text filter
- sorting
- limit
- compact Protocol Path presentation
- CSV metadata export

`flows` must not support or require:

```text
--source-capture
```

## Help

```text
pcap-flow-lab flows -h
pcap-flow-lab flows --help
```

These forms must:

- return success
- require no input
- print flows-specific help
- perform no input opening or import
- create no output files

Syntax errors after classification as `flows` should print:

- a concise error
- flows-specific help

Runtime errors should not dump full help.

This follows the same global and per-command help policy already documented for
`summary`.

## Applicability Matrix

| Capability | Raw capture | Index |
| --- | --- | --- |
| Basic flow listing | yes | yes |
| `--flow-number` | yes | yes |
| `--flow-numbers` | yes | yes |
| `--filter` | yes | yes |
| `--sort` | yes | yes |
| `--limit` | yes | yes |
| compact Protocol Path | yes | yes |
| `--out-flows-list` | yes | yes |
| `--settings` | yes | no |
| `--progress` | yes | yes |
| `--force` | yes | yes |
| `--source-capture` | no | no |

## Performance Principles

PcapFlowLab targets very large captures.

Implementation should therefore prefer:

- avoiding every unnecessary full `FlowRow -> FrontendFlowDto` copy chain for
  CLI work
- using indexed `flow_row()` access for explicit single or small-number
  selection where practical
- materializing selected candidate rows only where filtering or sorting
  naturally requires it
- avoiding another unnecessary full `O(flow_count)` DTO layer solely for CLI
- reusing shared semantic helpers for selection, filter, sort, and export
- preserving canonical flow identity independently of vector position

This pass does not implement optimization work.

## Shared Filter And Sort Architecture

Implementation should introduce or reuse a shared semantic layer for:

- canonical selection
- text matching
- deterministic sorting and comparison

The implementation should not copy current Qt filtering logic into CLI
verbatim.

The implementation should not copy current Tauri filtering logic into CLI
verbatim.

Current Qt and Tauri semantics already diverge slightly.

The contract in this document is the intended common semantic direction.

## Future UI Parity Cleanup

Deferred follow-up:

Qt and Tauri flow text filtering should later be aligned with the shared
semantics defined here, including removal of fragmented-packet and `frag`
matching from the flow text filter.

This pass does not modify GUI behavior.

## Legacy Replacement

The previous explicit legacy command:

```text
pcap-flow-lab flows <input>
```

has now been replaced by the production v2-style `flows` implementation while
preserving important capabilities:

- raw capture input
- index input
- metadata-only operation

Intentional v2 changes include:

- one-based public flow numbers
- Detected Protocol
- Service
- compact Protocol Path
- explicit selectors
- filter
- sort
- limit
- bounded stdout preview
- CSV metadata export
- command-specific help
- shared progress and settings conventions

Legacy zero-based stdout numbering is not preserved.

## Examples

Basic:

```text
pcap-flow-lab flows capture.pcap
```

Filter:

```text
pcap-flow-lab flows capture.pcap --filter TLS
```

Explicit single flow:

```text
pcap-flow-lab flows capture.idx --flow-number 42
```

Ranges:

```text
pcap-flow-lab flows capture.idx \
    --flow-numbers 1-10,24,31-35
```

Sort:

```text
pcap-flow-lab flows capture.pcap \
    --sort bytes:desc
```

Limit:

```text
pcap-flow-lab flows capture.pcap \
    --filter QUIC \
    --sort packets:desc \
    --limit 50
```

CSV complete filtered result despite default 25-row stdout preview:

```text
pcap-flow-lab flows capture.pcap \
    --filter TLS \
    --out-flows-list tls.csv
```

CSV explicit result limit:

```text
pcap-flow-lab flows capture.pcap \
    --filter TLS \
    --sort bytes:desc \
    --limit 100 \
    --out-flows-list tls-top-100.csv
```

Settings:

```text
pcap-flow-lab flows capture.pcap \
    --settings settings.json
```

Help:

```text
pcap-flow-lab flows --help
```

## Intentionally Deferred Decisions

This document does not define:

- production implementation details
- `--columns`
- structured `--format`
- packet export
- `--source-capture`
- alternate CSV schemas
- exact human-readable error wording
- exact terminal table width policy beyond preserving semantic content
