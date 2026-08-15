# `flows` Command

This document defines the current production contract for:

```text
pcap-flow-lab flows ...
```

The dispatcher also accepts the compatibility alias `flow`, but this reference
documents the canonical command name.

## Purpose

`flows` queries canonical flows and renders a terminal table preview and/or a
CSV export.

## Syntax

```text
pcap-flow-lab flows <input> [options]
pcap-flow-lab flows --input <input> [options]
```

## Supported options

- `--flow-number <N>`
- `--flow-numbers <ranges>`
- `--filter <text>`
- `--sort number|protocol|service|endpoint-a|endpoint-b|packets|bytes[:asc|desc]`
- `--limit <N>`
- `--out-flows-list <path>`
- `--settings <path>`
- `--progress auto|on|off`
- `--force`

## Unsupported options

`flows` does not implement:

- `--source-capture`
- `--format`
- `--columns`

## Input rules

- Raw captures are supported.
- Indexes are supported.
- `--settings` is valid only for raw capture input.

## Selection and query pipeline

The command applies query stages in this order:

1. canonical flow set;
2. explicit flow-number selection, if provided;
3. text filter, if provided;
4. sort, if provided;
5. limit, if provided.

Important consequences:

- `--flow-number` and `--flow-numbers` are mutually exclusive.
- `--flow-numbers` accepts inclusive one-based ranges such as `1-10,24,31-35`.
- Duplicates may be supplied in the textual range expression, but the resolved
  flow set is deduplicated before final output.

## Default preview behavior

Without `--limit`, stdout preview is capped at 25 rows.

If the result set is larger than 25 flows, the command appends:

- `Showing 25 of X flows.`
- `Use --limit <N> to show more rows or --out-flows-list <path> to export the result.`

When `--limit` is supplied, stdout renders the final limited result and reports
the limited-versus-prelimit counts.

If no flows match, the command succeeds and prints:

```text
Flows

No matching flows.
```

## Table columns

The terminal table currently renders these columns:

- `No.`
- `Endpoint A`
- `Endpoint B`
- `Protocol`
- `Detected Protocol`
- `Service`
- `Path`
- `Packets`
- `Original Bytes`

`Path` is the compact Protocol Path presentation for the flow.

## Filtering

`--filter <text>` applies the shared flow text filter used by the query layer.

This is a free-text flow filter. The command documentation does not define a
separate fragment-only or flag-only mini-language.

## Sorting

Supported sort keys are:

- `number`
- `protocol`
- `service`
- `endpoint-a`
- `endpoint-b`
- `packets`
- `bytes`

Direction defaults to ascending unless `:desc` is supplied.

## CSV export

`--out-flows-list <path>` exports the final queried flow set as CSV.

That exported set reflects the same selection/filter/sort/limit pipeline as the
stdout preview.

## Help and errors

- `flows --help` prints flows-specific help and exits successfully.
- Parse errors print an error plus flows help and exit non-zero.

## Examples

Top 15 flows by service descending:

```text
pcap-flow-lab flows capture.pcap --sort service:desc --limit 15
```

Specific flow numbers:

```text
pcap-flow-lab flows capture.pcap --flow-numbers 1-5,10,12-15
```

Filtered CSV export:

```text
pcap-flow-lab flows capture.pcap --filter example.test --out-flows-list flows.csv
```
