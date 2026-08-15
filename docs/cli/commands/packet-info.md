# `packet-info` Command

This document defines the current production contract for:

```text
pcap-flow-lab packet-info ...
```

The dispatcher also accepts the compatibility alias `packets-info`, but this
reference documents the canonical command name.

## Purpose

`packet-info` renders packet summary information for either:

- one packet addressed by file-wide packet number; or
- one packet addressed by flow number plus packet-in-flow number.

It can optionally append a byte-backed packet view.

## Syntax

```text
pcap-flow-lab packet-info <input> --packet-in-file <N> [options]
pcap-flow-lab packet-info <input> --flow-number <F> --packet-in-flow <P> [options]
pcap-flow-lab packet-info --input <input> ...
```

## Selector modes

Exactly one selector mode is required:

- `--packet-in-file <N>`; or
- `--flow-number <F>` together with `--packet-in-flow <P>`.

Both numbering schemes are 1-based.

## Supported options

- `--packet-in-file <N>`
- `--flow-number <N>`
- `--packet-in-flow <N>`
- `--bytes`
- `--source-capture <path>`
- `--settings <path>`
- `--progress auto|on|off`

## Unsupported options

`packet-info` does not implement:

- `--packet-number`
- `--packet-numbers`
- `--flow-numbers`
- `--byte-view`
- `--list-byte-views`
- `--bytes-layer`
- `--format`
- `--json`
- `--out`
- `--filter`
- `--sort`
- `--limit`

## Input rules

- Raw captures are supported.
- Indexes are supported.
- `--settings` is valid only for raw capture input.
- `--source-capture` is valid only for index input.

If the command requires source bytes and they are not available for the opened
index, it fails and instructs the user to attach the original capture with
`--source-capture <path>`.

## Output shape

### Global packet selection

When using `--packet-in-file`, the report begins with:

```text
Packet <N>
```

It then renders:

- `Packet`
- `Summary`
- optional `Bytes`

### Flow-scoped packet selection

When using `--flow-number` plus `--packet-in-flow`, the report begins with:

```text
Flow <F> / Packet <P>
```

It then renders:

- `Flow Context`
- `Packet`
- `Summary`
- optional `Bytes`

`Flow Context` includes:

- `Endpoints`
- `Direction`

## Packet section

The `Packet` section renders:

- `Packet in File`
- `Time`
- `Captured Length`
- `Original Length`

## Summary section

The `Summary` section renders the shared structured packet-summary tree.

CLI output uses current terminology:

- `Summary`
- `Bytes`

There is no CLI Protocol tab, Raw tab, TCP Payload tab, or UDP Payload tab.

## Bytes section

`--bytes` appends a single byte-backed packet view:

- the selected captured-packet byte surface label;
- the available byte length;
- formatted byte text.

The current CLI does not expose arbitrary byte-view selection. It renders one
shared packet-bytes surface when `--bytes` is requested and source-backed byte
inspection is available.

## Help and errors

- `packet-info --help` prints packet-info-specific help and exits successfully.
- Parse errors print an error plus packet-info help and exit non-zero.

## Examples

Inspect one packet by file position:

```text
pcap-flow-lab packet-info capture.pcap --packet-in-file 2048
```

Inspect one packet within a flow:

```text
pcap-flow-lab packet-info capture.pcap --flow-number 12 --packet-in-flow 3
```

Inspect one packet and include bytes:

```text
pcap-flow-lab packet-info capture.pcap --packet-in-file 2048 --bytes
```
