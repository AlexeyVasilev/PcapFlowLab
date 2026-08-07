# CLI V2 Overview

This directory documents the PcapFlowLab CLI v2 architecture and staged
implementation direction.

- It is not current command help.
- The current production CLI now includes an initial v2-style `summary` path.
- Other public CLI commands remain legacy.
- Implementation may not yet match the documents in this folder.

For the full architecture contract, see [architecture.md](./architecture.md).
For the detailed `summary` command contract, see
[commands/summary.md](./commands/summary.md).

## What The CLI Is For

CLI v2 is intended to support:

- complete capture or index summary work
- flow-list querying
- flow packet export
- selected-flow analysis
- packet inspection

The five planned primary public commands are:

- `summary`
- `flows`
- `export-flows`
- `flow-info`
- `packet-info`

There is no separate top-level `statistics` command in the planned v2 model.

## Default Command Behavior

These forms are conceptually equivalent:

```text
pcap-flow-lab capture.pcap
pcap-flow-lab summary capture.pcap
pcap-flow-lab --input capture.pcap
```

The default command is `summary`.

## Input Forms

CLI v2 is planned to support:

- positional input path
- `--input <path>`

These input forms are mutually exclusive and must not be combined in one
invocation.

Supported analysis input concepts are:

- PCAP
- PCAPNG
- PcapFlowLab index

For byte-backed operations against an index, CLI v2 also reserves:

```text
--source-capture <path>
```

## Common Option Concepts

| Option | Planned role |
| --- | --- |
| `--input <path>` | Explicit input path |
| `--source-capture <path>` | Source-capture override for byte-backed index operations |
| `--settings <settings.json>` | Narrow CLI JSON settings subset for raw-capture summary import |
| `--filter <text>` | Flow-text filtering for flow-oriented commands |
| `--sort <field>:<asc\|desc>` | Flow sorting for flow-oriented commands |
| `--limit <N>` | Limit result flow count after selection, filter, and sort |
| `--flow-number <N>` | Select one canonical user-facing flow |
| `--flow-numbers <range>` | Select a set of canonical user-facing flows |
| `--packets-in-flow <range>` | Select packets by position inside one flow |
| `--packets-in-file <range>` | Select packets by number in the complete capture |
| `--format <format>` | Command- or artifact-specific output format |
| `--force` | Allow overwriting existing output files |
| `--progress auto\|on\|off` | Progress display policy |

## Summary Versus Flow-Oriented Commands

`summary` is always whole-capture or whole-index.

- It is not flow-filtered.
- It does not accept flow-selection options.
- It prints Basic Summary by default.
- `--extended` adds selected whole-capture statistics sections.
- Protocol Path Tree preview belongs to `summary` and is controlled
  independently.
- Protocol Path Tree belongs to the summary/statistics domain.

Filtering, sorting, and limiting belong to flow-oriented commands such as:

- `flows`
- `export-flows`

## Numbering Model

All CLI v2 user-facing flow and packet numbers are planned to be 1-based.

- flow numbers refer to canonical session flows
- sorting does not renumber flows
- packet numbering in file and packet numbering in flow are separate coordinate
  systems

## stdout And stderr

Planned stream contract:

`stdout`
: requested command data

`stderr`
: progress, warnings, errors, diagnostics

This keeps shell pipelines predictable.

## Progress

CLI v2 reserves:

```text
--progress auto
--progress on
--progress off
```

Default behavior is planned to be `auto`.

- long-running interactive operations may show progress
- non-interactive contexts should avoid noisy terminal-style progress output
- progress belongs on `stderr`

## Examples

Default summary invocation:

```text
pcap-flow-lab capture.pcap
```

Explicit summary against an index:

```text
pcap-flow-lab summary capture.idx
```

Filtered and sorted flow list:

```text
pcap-flow-lab flows capture.idx \
    --filter "QUIC" \
    --sort bytes:desc \
    --limit 100
```

Selected flow export:

```text
pcap-flow-lab export-flows capture.idx \
    --filter "192.168.0.152" \
    --out-flows-data selected.pcap
```

Selected-flow analysis:

```text
pcap-flow-lab flow-info capture.idx --flow-number 42
```

Packet inspection by packet number inside a selected flow:

```text
pcap-flow-lab packet-info capture.pcap \
    --flow-number 42 \
    --packets-in-flow 1-5,8,14
```

## Next Documentation Layer

Detailed command documentation is intended to be added incrementally as
individual command designs are finalized:

- `docs/cli/commands/summary.md` (now defined)
- `docs/cli/commands/flows.md`
- `docs/cli/commands/export_flows.md`
- `docs/cli/commands/flow_info.md`
- `docs/cli/commands/packet_info.md`

Only `summary.md` exists in this pass. The other command documents are still
deferred.
