# `export-flows` Command

This document defines the current production contract for:

```text
pcap-flow-lab export-flows ...
```

The dispatcher also accepts the compatibility alias `export-flow`, but this
reference documents the canonical command name.

## Purpose

`export-flows` writes packet-backed exports for either:

- selected recognized flows; or
- the alternative unrecognized-packet export mode.

## Syntax

```text
pcap-flow-lab export-flows <input> [selection] [retention] [output] [options]
pcap-flow-lab export-flows --input <input> [selection] [retention] [output] [options]
```

## Flow selection

- `--flow-number <N>`
- `--flow-numbers <ranges>`
- `--filter <text>`
- `--all-flows`
- `--limit <N>`

Flow numbers are one-based canonical identities.

`--limit` limits flows, not packets.

## Alternative unrecognized-packet mode

- `--unrecognized-packets`
- `--packet-limit <N>`

This mode is an alternative selection mode for exporting unrecognized packets in
capture order.

`--packet-limit` limits the number of unrecognized packets exported.

## Selection requirements

A selection mode is required:

- a recognized-flow selector; or
- `--unrecognized-packets`.

Flow selectors are:

- `--flow-number`
- `--flow-numbers`
- `--filter`
- `--all-flows`

`--unrecognized-packets` is mutually exclusive with flow selectors.

## Packet-retention modes for recognized-flow export

- `--all-packets`
- `--first-packets <N>`
- `--first-original-bytes <N>`

Optional modifiers:

- `--include-last-packet`
- `--every-kth-packet <N>`

Rules:

- `--include-last-packet` and `--every-kth-packet` require a bounded base mode.
- Those modifiers apply only with `--first-packets` or `--first-original-bytes`.
- Unrecognized-packet mode does not use these retention options.

## Output options

Exactly one output mode is required:

- `--out <path>`
- `--out-dir <directory>`

Additional output control:

- `--buffer-memory-mib <N>` is supported only with `--out-dir`.

Unrecognized-packet mode restrictions:

- `--out-dir` is invalid with `--unrecognized-packets`;
- `--buffer-memory-mib` is invalid with `--unrecognized-packets`.

## Additional supported options

- `--source-capture <path>`
- `--settings <path>`
- `--progress auto|on|off`
- `--force`

## Unsupported options

`export-flows` does not implement:

- `--sort`
- `--format`
- `--columns`

## Input rules

- Raw captures are supported.
- Indexes are supported.
- `--settings` is valid only for raw capture input.
- `--source-capture` is valid only for index input.

For packet-backed export from an index, source capture access is required. If
the stored source capture is not accessible, the command fails and instructs the
user to provide `--source-capture <path>` or reopen the original capture
directly.

## Recognized-flow export pipeline

For recognized-flow export, the selection pipeline is:

1. canonical flow set;
2. explicit flow-number selection, if provided;
3. text filter, if provided;
4. flow limit, if provided;
5. packet-retention mode;
6. export.

Unlike `flows`, this command does not expose a sort stage.

## Unrecognized-packet mode behavior

- Packets are exported in original capture order.
- If `--packet-limit` is provided, the first `N` unrecognized packets are
  exported.
- If no unrecognized packets exist, the command fails with a runtime error.

## Output safety

The runtime performs conservative output preflight checks, including:

- refusing to overwrite existing paths unless `--force` is supplied;
- refusing obvious input/output path collisions;
- requiring valid parent directories.

## Success reporting

On success, the command writes summary completion text to `stderr`.

Recognized-flow mode reports the number of exported flows.

Unrecognized-packet mode reports the number of exported unrecognized packets.

## Examples

Export the first 10 packets from one flow:

```text
pcap-flow-lab export-flows capture.pcap --flow-number 12 --first-packets 10 --out flow12.pcap
```

Export filtered flows into a directory:

```text
pcap-flow-lab export-flows capture.pcap --filter example.test --all-packets --out-dir exported_flows
```

Export the first 20 unrecognized packets:

```text
pcap-flow-lab export-flows capture.pcap --unrecognized-packets --packet-limit 20 --out unrecognized.pcap
```
