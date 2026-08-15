# `flow-info` Command

This document defines the current production contract for:

```text
pcap-flow-lab flow-info ...
```

The dispatcher also accepts the compatibility alias `flows-info`, but this
reference documents the canonical command name.

## Purpose

`flow-info` renders a detailed terminal report for exactly one flow.

## Syntax

```text
pcap-flow-lab flow-info <input> --flow-number <N> [options]
pcap-flow-lab flow-info --input <input> --flow-number <N> [options]
```

## Supported options

- `--flow-number <N>`
- `--settings <path>`
- `--progress auto|on|off`

## Unsupported options

`flow-info` does not implement:

- `--source-capture`
- `--filter`
- `--sort`
- `--limit`
- `--flow-numbers`
- `--out`
- `--format`
- `--columns`

## Input rules

- Raw captures are supported.
- Indexes are supported.
- `--settings` is valid only for raw capture input.

The command requires exactly one `--flow-number`.

If the requested flow number is outside the available range, the command fails.

## Report structure

The report currently renders these sections:

- `Identity`
- `Traffic`
- `Direction`
- `Packet Size Histogram`
- `Timing`

## Identity section

The `Identity` section renders:

- `Endpoints`
- `Family`
- `Protocol`
- `Detected Protocol`
- `Service`
- `Protocol Path`

Endpoint output is intentionally a single combined line:

```text
Endpoints: 176.108.85.0:4415 <-> 103.122.221.143:443
```

There are no separate `Endpoint A:` or `Endpoint B:` lines in CLI output.

## Traffic section

The `Traffic` section renders:

- `Packets`
- `Original Bytes`
- `Captured Bytes`
- `Max Captured Packet Size`

## Direction section

The `Direction` section renders a table with columns:

- `Metric`
- `A->B`
- `B->A`
- `Total`

It currently includes packet and original-byte totals, followed by:

- `Packet Direction`
- `Data Direction`

First-observed endpoint orientation remains authoritative for `A` and `B`.

## Packet Size Histogram section

The packet-size histogram renders these columns:

- `Bucket`
- `All`
- `A -> B`
- `B -> A`

## Timing section

The `Timing` section renders:

- `First Packet`
- `Last Packet`
- `Duration`
- `Largest Gap`

These are presentation labels only. They do not alter the underlying timestamp
or duration semantics.

## Source-byte requirements

`flow-info` is metadata/report oriented. It does not require source packet bytes
and does not expose packet-body inspection surfaces.

## Help and errors

- `flow-info --help` prints flow-info-specific help and exits successfully.
- Parse errors print an error plus flow-info help and exit non-zero.

## Examples

Inspect one flow from a raw capture:

```text
pcap-flow-lab flow-info capture.pcap --flow-number 11724
```

Inspect one flow from an index:

```text
pcap-flow-lab flow-info capture.idx --flow-number 11724
```
