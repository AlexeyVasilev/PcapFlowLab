# `summary` Command

This document defines the current production contract for:

```text
pcap-flow-lab summary ...
```

It also covers the default top-level summary path:

```text
pcap-flow-lab <input>
pcap-flow-lab --input <input>
```

## Purpose

`summary` renders capture-wide or index-wide summary information. It is not a
flow-selection command and it does not expose packet- or flow-level inspection.

## Syntax

```text
pcap-flow-lab summary <input> [options]
pcap-flow-lab summary --input <input> [options]
pcap-flow-lab <input> [summary options]
pcap-flow-lab --input <input> [summary options]
```

## Supported options

- `--extended`
- `--protocol-path-tree`
- `--protocol-path-mode kind-overview|identity-tree|terminal-paths`
- `--out-index <path>`
- `--out-flows-list <path>`
- `--out-protocol-path-tree <path>`
- `--settings <path>`
- `--progress auto|on|off`
- `--force`

## Unsupported options

The command rejects flow/packet selection options and other command-specific
flags, including:

- `--filter`
- `--flow-number`
- `--flow-numbers`
- `--sort`
- `--limit`
- `--packets-in-flow`
- `--packets-in-file`
- `--source-capture`

`--format` is also not implemented for `summary`.

## Input rules

- Raw captures are supported.
- Indexes are supported.
- `--settings` is valid only for raw capture input.
- `--out-index` is valid only for raw capture input.
- `--protocol-path-mode` is valid only together with `--protocol-path-tree` or
  `--out-protocol-path-tree`.

## Basic output

The default summary output renders:

- `Input`
- `Capture`
- `Transport Summary`
- `IP Family Summary`

`Input` includes file identity and type metadata. For index input, it may also
include the stored source-capture basename when that metadata exists.

`Capture` includes:

- flow count;
- packet count;
- captured bytes;
- original bytes;
- unrecognized packet count.

`Transport Summary` renders the fixed groups:

- TCP
- UDP
- SCTP
- Other

`IP Family Summary` renders the fixed groups:

- IPv4
- IPv6

## Extended output

`--extended` appends exactly these sections:

- `Packet Size Distribution`
- `Flows by Packet Count`
- `Detected Protocol Hints`
- `Top Endpoints and Ports`

Important details:

- `Packet Size Distribution` uses total-based percentages.
- `Flows by Packet Count` reports flow counts and original bytes by bucket.
- `Detected Protocol Hints` omits zero rows and prints `None` when empty.
- `Top Endpoints and Ports` is limited to the top 5 rows.

## Protocol Path Tree

`--protocol-path-tree` appends a text preview of the Protocol Path Tree.

That preview is intentionally bounded. It renders up to 25 logical rows and, if
truncated, appends a note indicating how many additional rows were omitted and
that `--out-protocol-path-tree <path>` exports the complete tree.

`--protocol-path-mode` controls the tree mode:

- `kind-overview`
- `identity-tree`
- `terminal-paths`

## Side outputs

`summary` can produce side outputs during the same invocation:

- `--out-index`
- `--out-flows-list`
- `--out-protocol-path-tree`

Successful side-output notifications are written to `stderr`.

## Help and errors

- `summary --help` prints summary-specific help and exits successfully.
- Parse errors print an error plus summary help and exit non-zero.
- Top-level no-argument help is global help, not summary help.

## Examples

Basic summary:

```text
pcap-flow-lab summary capture.pcap
```

Default-summary form:

```text
pcap-flow-lab capture.pcap
```

Extended summary with Protocol Path preview:

```text
pcap-flow-lab summary capture.pcap --extended --protocol-path-tree
```

Export complete Protocol Path Tree:

```text
pcap-flow-lab summary capture.pcap --out-protocol-path-tree protocol_paths.txt
```
