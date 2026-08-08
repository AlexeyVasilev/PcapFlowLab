# CLI V2 `export-flows` Command

## Status

This document defines the production CLI v2 contract for:

```text
pcap-flow-lab export-flows
```

The current production CLI implements this v2 command.

The current repository already contains the shared backend capabilities that
this command is intended to expose:

- single-file classic-PCAP flow export
- Smart Export packet-retention rules
- separate-file-per-flow Smart Export
- `flows_manifest.csv` generation
- source-capture validation and reattachment

The current production CLI still exposes the legacy command:

```text
pcap-flow-lab export-flow
```

That legacy command remains in place during the migration to CLI v2.

## Purpose

`export-flows` exports actual packet data for explicitly selected canonical
flows.

It is not a metadata-only command.

It is distinct from:

```text
pcap-flow-lab flows ... --out-flows-list <path>
```

which exports flow metadata CSV only.

`export-flows` supports:

- canonical flow selection
- shared flow text filtering
- flow-count limiting
- per-flow packet-retention policies
- one merged classic-PCAP output file
- one classic-PCAP file per selected flow

It does not support:

- flow sorting
- frontend-state concepts such as current/selected/unselected UI rows
- unrecognized-packet export
- PCAPNG output

## Input Forms

These forms are planned conceptually:

```text
pcap-flow-lab export-flows capture.pcap ...
pcap-flow-lab export-flows --input capture.pcap ...
```

Positional input and `--input` are mutually exclusive input forms.

Using both in the same invocation is invalid even when the paths are identical.

Input may be:

- PCAP
- PCAPNG
- PcapFlowLab index

Input-kind detection should reuse the existing project input-detection path.

## Initial Planned Syntax

```text
pcap-flow-lab export-flows <input>
    [--flow-number <N> | --flow-numbers <ranges>]
    [--filter <text>]
    [--all-flows]
    [--limit <N>]

    [--all-packets |
     --first-packets <N> |
     --first-original-bytes <N>]

    [--include-last-packet]
    [--every-kth-packet <K>]

    (--out <output.pcap> |
     --out-dir <folder>)

    [--buffer-memory-mib <N>]
    [--source-capture <path>]
    [--settings <settings.json>]
    [--progress <auto|on|off>]
    [--force]
```

Help:

```text
-h
--help
```

The initial contract intentionally does not include:

- `--sort`
- `--format`
- `--columns`
- packet-level arbitrary ranges
- output to stdout

## Help And Error Behavior

Explicit help:

```text
pcap-flow-lab export-flows -h
pcap-flow-lab export-flows --help
```

prints export-flows-specific help to `stdout`, performs no open/import/export
work, creates no outputs, and returns success.

Syntax errors should print:

- a concise error message
- export-flows-specific help

and return non-zero.

Runtime errors after successful parsing should print only the operational error
and return non-zero.

## Flow Selector Requirement

The user must explicitly identify the flow set.

At least one of the following is required:

- `--flow-number <N>`
- `--flow-numbers <ranges>`
- `--filter <text>`
- `--all-flows`

This is invalid:

```text
pcap-flow-lab export-flows capture.pcap --out output.pcap
```

This is valid:

```text
pcap-flow-lab export-flows capture.pcap --all-flows --out output.pcap
```

`--all-flows` is mutually exclusive with:

- `--flow-number`
- `--flow-numbers`
- `--filter`

`--flow-number` and `--flow-numbers` are mutually exclusive.

An explicit canonical number selector may still be combined with `--filter`.

## Canonical Flow Numbering

Public CLI flow numbers are one-based.

The contract is:

```text
flow_number = internal flow_index + 1
```

Filtering and limiting never renumber flows.

## Flow Selection Pipeline

The command pipeline is:

```text
canonical flows
    ->
explicit flow-number selection, if present
    ->
text filter, if present
    ->
flow --limit, if present
    ->
selected canonical flow set
    ->
per-flow packet retention
    ->
packet export
```

There is no sort stage.

`export-flows` reuses the existing shared `FlowQuery` concepts for:

- canonical flow-number selection
- text filtering
- limit after filtering

The command does not introduce a second selection engine.

## `--all-flows`

`--all-flows` explicitly means:

- start from the full canonical flow set
- skip explicit number/range selection
- skip text filtering
- continue to optional `--limit`
- then apply packet retention to each selected flow

`--all-flows` exists so that exporting every flow is always an intentional act.

## `--limit` Means Flow Limit

`--limit` applies to the selected canonical flow set.

It never means packet count.

Example:

```text
--filter TLS
--limit 20
--first-packets 30
```

means:

- select at most 20 canonical TLS-matching flows
- retain up to the first 30 packets from each selected flow

## Flow Filter

`export-flows` reuses exactly the existing shared `flows` text-filter semantics.

It does not define a second filter language.

Initial filter semantics are therefore:

- case-insensitive
- substring matching
- applied to the same shared flow metadata fields used by `flows`

## Packet Base Selection

Mutually exclusive base modes:

```text
--all-packets
--first-packets <N>
--first-original-bytes <N>
```

If no base mode is provided:

```text
--all-packets
```

is the implicit default.

### `--first-packets <N>`

`N` must be positive.

This applies independently to each selected flow.

It retains the first `N` packets in that flow, capped by the flow's actual
packet count.

### `--first-original-bytes <N>`

`N` must be positive.

This applies independently to each selected flow.

It uses original packet lengths, not captured lengths.

The backend selects packets from the start of the flow until the accumulated
original-byte total reaches or exceeds the threshold.

The packet that crosses the threshold is included.

Example:

- packet original lengths: `100, 100, 100`
- `--first-original-bytes 150`

retains the first two packets.

## Additional Packet Retention

Additional retention options:

```text
--include-last-packet
--every-kth-packet <K>
```

These apply independently per selected flow.

### `--include-last-packet`

This includes the final packet of a flow when it is not already retained by the
base rule.

If the last packet is already selected, it is not duplicated.

### `--every-kth-packet <K>`

`K` must be positive.

This reuses the existing backend semantics exactly.

Counting starts after the base prefix, not from the beginning of the complete
flow.

For a base prefix of length `P`, the command retains:

- the `K`-th packet after the base prefix
- then every additional `K`-th packet after that

using 1-based counting within the post-prefix tail.

Examples:

- base prefix retains packets `1-2`
- `--every-kth-packet 2`
- remaining tail is packets `3,4,5,6,...`

The periodic rule retains packets `4,6,...`.

For `--first-original-bytes`, counting begins after the included
threshold-crossing packet, because that packet is part of the base prefix.

If a packet is already selected by the base prefix or by `--include-last-packet`,
it is still written at most once.

## All-Packets Interaction

When the base mode is:

```text
--all-packets
```

the additional retention rules cannot add anything.

For a clear CLI contract, the following combinations are invalid:

- `--all-packets --include-last-packet`
- `--all-packets --every-kth-packet <K>`

The command should reject them as redundant rather than silently pretending
they alter the result.

## Single Output Mode

```text
--out <output.pcap>
```

This writes one classic PCAP containing the union of retained packets from all
selected flows.

Packet order in the output is original capture order.

Flow-selection order does not affect packet order.

A packet is written at most once.

The current shared backend authority for this behavior is:

- direct multi-flow export sorts by `packet_index` and deduplicates
- Smart single-file export uses packet-selection marking and writes selected
  packets in source-capture order

## Separate-File-Per-Flow Output Mode

```text
--out-dir <folder>
```

This reuses the existing per-flow Smart Export folder path.

The output directory contains:

- one classic PCAP per selected bidirectional flow
- `flows_manifest.csv`

`--out` and `--out-dir` are mutually exclusive.

Exactly one is required.

### Existing Per-Flow Filename Convention

The current backend naming scheme is:

```text
000001_<protocol>_<protocol_hint>_<transport>_<src_ip>_<src_port>-<dst_ip>_<dst_port>.pcap
```

Current filename behavior:

- `flow_id` is zero-padded to 6 digits
- unsafe characters are normalized to `_`
- protocol-ish text components are truncated to 32 characters
- IPv4 dots are preserved
- IPv6 separators are sanitized so `:` does not remain in the filename
- empty components fall back to `unknown`

The CLI contract should reuse this naming scheme rather than define another.

### Existing `flows_manifest.csv` Behavior

The current Smart Export manifest header is:

```text
flow_id,file_name,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,exported_packet_count,exported_captured_bytes,exported_original_bytes,protocol_path
```

Current manifest semantics:

- `flow_id` is the per-export sequential flow id starting from 1
- `file_name` is the generated PCAP file basename
- `packet_count` / `captured_bytes` / `original_bytes` describe the complete flow
- `exported_packet_count` / `exported_captured_bytes` / `exported_original_bytes`
  describe the retained/exported subset
- `protocol_path` is quoted unconditionally in the current CSV writer

The CLI contract should reuse this manifest schema.

## Per-Flow Packet Retention

Packet-retention rules apply per flow in both output modes.

Example:

```text
10 selected flows
--first-packets 30
```

means up to 30 packets from each selected flow, not 30 packets globally.

Likewise:

```text
--first-original-bytes 50000
```

means an independent original-byte prefix for each selected flow.

Output mode does not change the logical retention result per flow.

## Buffer Memory Budget

```text
--buffer-memory-mib <N>
```

This option reuses the existing separate-file Smart Export memory budget.

It is valid only with:

```text
--out-dir
```

It is invalid with:

```text
--out
```

If omitted, the current backend default remains:

```text
128 MiB
```

The CLI contract should reuse that existing default rather than define a
different buffering policy.

## Empty Selection

If selection/filtering produces zero flows:

- the command fails
- it returns non-zero
- it must not create an empty PCAP
- it must not create an output directory

Conceptual runtime error:

```text
No flows matched the export selection.
```

This differs from metadata-only `flows`, where an empty result is valid.

## Raw, Index, And Source-Capture Behavior

Packet export requires source packet bytes.

### Raw Capture Input

For raw PCAP/PCAPNG input:

- source packet bytes come from the opened source capture
- `--settings` is valid
- `--source-capture` is invalid

### Index Input

For index input:

- packet export requires a validated source capture
- the session may already have a validated auto-attached source capture
- otherwise `--source-capture <path>` may supply an explicit source path

Existing source validation must be reused.

The CLI must not bypass current checks on:

- source format
- source file size
- source content fingerprint

If no valid source capture is available, packet export fails.

## `--settings`

`--settings <settings.json>` is valid only for raw capture import.

It reuses the same narrow CLI settings schema as `summary` and `flows`.

Grouping-related settings naturally affect which canonical flows exist and
therefore affect export selection.

For index input:

- `--settings` is invalid

## Output Format

Both output modes currently produce classic PCAP.

The command must not promise:

- PCAPNG output
- PCAPNG metadata preservation
- PCAPNG interface preservation

For PCAPNG input, PCAPNG-only structural metadata is not preserved in the
current backend export model.

## Effective Single-Link-Type Limitation

The current export model effectively treats each output file as having one
link-layer type.

Full heterogeneous-interface / heterogeneous-link-type PCAPNG preservation is
outside the supported scope of this release stage.

The CLI contract should document this as a current limitation.

It should not require a new pre-export mixed-link-type rejection scan in this
pass.

## Performance Path

The implementation may choose the appropriate existing backend path while
preserving the documented public semantics.

Preferred reuse model:

- `all packets + --out` may reuse the existing direct multi-flow export path
- Smart retention rules should reuse the existing Smart Export backend
- `--out-dir` should reuse the existing per-flow Smart Export folder exporter

The CLI should not reimplement packet-retention logic itself.

## Progress

Progress belongs to `stderr`.

The command should reuse existing CLI input-open progress policy.

Current backend export-progress reality is not uniform:

- direct full-flow export does not currently expose dedicated progress callbacks
- Smart single-file export exposes packet-scan / packet-write progress
- per-flow folder export exposes preparing/writing progress plus cancellation

The CLI must not promise fake uniform percentages across all export paths.

When Smart Export progress is enabled, CLI rendering should throttle callback
output so terminal and redirected log output remain readable.

## Success Reporting

The command should report at least:

- selected flow count
- destination path

Conceptual examples:

```text
Exported 12 flows to: selected.pcap
Exported 12 flows to: exported-flows
```

The contract should not promise exact packet-count success reporting unless the
selected backend path already provides it authoritatively and cheaply.

## Output Preflight And `--force`

### `--out`

For single-file output, the command should reuse shared CLI-style output
preflight for:

- existing target without `--force`
- missing parent directory
- directory target
- output path equal to input path
- output path equal to explicit source-capture path

### `--out-dir`

For directory output, the CLI must preserve existing backend safety.

The current backend behavior:

- creates the directory if needed
- writes individual files inside it
- writes `flows_manifest.csv`
- does not perform destructive recursive cleanup

The CLI contract should therefore be:

- no destructive recursive directory deletion
- `--force` may permit overwriting command-owned output files
- unrelated existing files in the destination directory must be preserved
- non-empty directories require safe, explicit handling rather than blind wipe

This is intentionally a conservative orchestration contract.

## UI-Only Smart Export Features Not Exposed

The CLI contract intentionally does not expose frontend-state Smart Export
targets such as:

- current flow
- selected flows
- unselected flows
- matching current filter
- not matching current filter

CLI equivalents are explicit canonical selectors:

- `--flow-number`
- `--flow-numbers`
- `--filter`
- `--all-flows`

The CLI also does not expose the UI-only unrecognized-packets Smart Export
target here.

## Unrecognized Packets

Unrecognized packets are intentionally not part of `export-flows`.

They are not canonical flows.

Any future export surface for them belongs to a packet-oriented command, not to
flow export.

## Legacy `export-flow`

The current legacy command:

```text
pcap-flow-lab export-flow
```

remains temporarily.

The planned v2 command:

```text
pcap-flow-lab export-flows
```

is intended to cover both single-flow and multi-flow export while also
exposing the existing Smart Export retention and per-flow output capabilities.

This document does not remove or redefine the legacy command.

## Examples

Complete single flow:

```text
pcap-flow-lab export-flows capture.pcap \
    --flow-number 42 \
    --out flow-42.pcap
```

Several complete flows:

```text
pcap-flow-lab export-flows capture.pcap \
    --flow-numbers 1-10,24 \
    --out selected.pcap
```

Smart first-packet prefix:

```text
pcap-flow-lab export-flows capture.pcap \
    --filter TLS \
    --limit 20 \
    --first-packets 30 \
    --include-last-packet \
    --out tls-sample.pcap
```

Byte prefix plus periodic retention:

```text
pcap-flow-lab export-flows capture.pcap \
    --filter QUIC \
    --first-original-bytes 50000 \
    --every-kth-packet 10 \
    --out quic-sample.pcap
```

Separate file per flow:

```text
pcap-flow-lab export-flows capture.pcap \
    --filter TLS \
    --first-packets 30 \
    --include-last-packet \
    --out-dir tls-flows
```

Explicit full-flow set:

```text
pcap-flow-lab export-flows capture.pcap \
    --all-flows \
    --first-packets 10 \
    --out-dir sampled-flows
```

Index with source override:

```text
pcap-flow-lab export-flows capture.pflidx \
    --source-capture original.pcapng \
    --flow-numbers 10-20 \
    --first-packets 50 \
    --out selected.pcap
```

## Applicability Matrix

| Capability | Raw capture | Index with valid source | Index without valid source |
| --- | --- | --- | --- |
| flow selectors | yes | yes | yes |
| `--filter` | yes | yes | yes |
| `--all-flows` | yes | yes | yes |
| `--limit` | yes | yes | yes |
| packet base modes | yes | yes | no |
| additional retention | yes | yes | no |
| `--out` | yes | yes | no |
| `--out-dir` | yes | yes | no |
| `--buffer-memory-mib` | yes, only with `--out-dir` | yes, only with `--out-dir` | no |
| `--settings` | yes | no | no |
| `--source-capture` | no | yes | yes |
| `--progress` | yes | yes | yes |
| `--force` | yes | yes | yes |

For index without valid source, selection can still be resolved at the metadata
level, but packet export cannot proceed until a valid source capture is
available.

## Intentionally Deferred

The following remain deferred:

- PCAPNG output
- PCAPNG interface preservation
- heterogeneous-link-type modeling
- packet-level arbitrary ranges
- export to stdout
- structured `--format`
- `--sort`
- unrecognized-packet export
- exact packet-count success reporting where backend does not already expose it
- frontend-state concepts such as selected/unselected current UI rows
