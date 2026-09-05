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
- `--out-statistics-html <path>`
- `--out-statistics-markdown <path>`
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

For current stable v16 indexes, compatible summary invocations use the
Statistics fast tier directly. The fast path is used for the basic summary,
`--extended`, Protocol Path Tree preview, Protocol Path Tree export, and full
Statistics report side outputs because those outputs are backed by the stable
header, capture Statistics snapshot, early Protocol Path registry, and terminal
Protocol Path aggregates.

The fast path intentionally stops before later flow-metadata and packet-detail
sections. A successful fast summary read therefore proves only the header and
Statistics-tier data needed by `summary`; it does not validate the complete
index. Options that require full flow metadata, such as `--out-flows-list`, use
the normal full-session index path instead. Raw capture input continues to use
the normal import/session path.

Fast v16 index summaries do not open, fingerprint, or otherwise probe the
recorded source capture. If the `Input` section shows a stored source-capture
name, it is recorded index identity only, not an accessibility verdict.

## Basic output

The default summary output renders:

- `Input`
- `Capture`
- `Capture Time`
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

`Capture` uses whole-capture packet and byte totals. It does not fall back to a
recognized-flow-only packet total.

`Capture Time` includes:

- `Start`
- `End`
- `Duration`

The CLI reuses the shared runtime presentation strings:

- absolute UTC timestamps in `YYYY-MM-DD HH:MM:SS.mmm UTC` form;
- `HH:MM:SS.mmm` duration formatting;
- `Nd HH:MM:SS.mmm` when the duration spans one or more full days.

When the current open result is partial, the basic summary also prints a visible
warning:

```text
Statistics cover successfully imported packets only; the capture was opened partially.
```

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

- `Capture Metrics`
- `Flow Characteristics`
- `Direction Distribution`
- `TCP Flags`
- `Packet Size Distribution`
- `Flows by Packet Count`
- `Detected Protocol Hints`
- `QUIC and TLS`
- `Top Flows by Original Bytes`
- `Top Endpoints and Ports`

Important details:

- `Capture Metrics` renders:
  - average captured packet size;
  - average original packet size;
  - average packet rate;
  - average captured data rate;
  - average original data rate;
  - truncated packets;
  - not captured bytes;
  - capture completeness.
- `Not captured bytes` means capture truncation or incompleteness
  (`original bytes - captured bytes` when positive). It does not imply network
  loss.
- `Flow Characteristics` renders `Only A -> B flows` and `Service recognized`
  as count-plus-percentage values.
- `Direction Distribution` contains two subtables:
  - `Packet Direction`;
  - `Data Direction (Original Bytes)`.
- `TCP Flags` contains only `SYN`, `FIN`, and `RST`.
- TCP flag percentages use total TCP packet count.
- `SYN` includes packets with SYN+ACK set.
- `Packet Size Distribution` uses one combined table with:
  - `Captured Packets`;
  - `Captured %`;
  - `Original Packets`;
  - `Original %`.
- `Packet Size Distribution` appends `Maximum captured packet size` and
  `Maximum original packet size`.
- `Flows by Packet Count` uses one combined table with:
  - `Flows`;
  - `Captured Bytes`;
  - `Original Bytes`.
- `Detected Protocol Hints` omits zero rows and prints `None` when empty.
- `Detected Protocol Hints` follows the shared runtime protocol-hint
  projection. The CLI does not apply a separate hint-suppression policy for
  this section.
- `QUIC and TLS` renders whole-capture flow-count-oriented QUIC and TLS
  recognition/version statistics.
- `Top Flows by Original Bytes` renders the fixed top-10 table ranked by
  original bytes descending.
- `Top Endpoints and Ports` remains limited to the top 5 rows for each table.
- `Top Endpoints` and `Top Ports` rank rows by original bytes.
- In `Top Endpoints` and `Top Ports`, `Flows` means canonical flows involving
  that endpoint or port identity.
- Histogram sections use aligned text tables only. They do not render ASCII bar
  charts.

`--extended` does not automatically append a Protocol Path Tree. Protocol Path
preview/export remains controlled only by the explicit Protocol Path options.

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
- `--out-statistics-html`
- `--out-statistics-markdown`

Successful side-output notifications are written to `stderr`.

Side outputs do not change the normal summary text written to `stdout`.
Existing output files are rejected unless `--force` is supplied, and all side
output paths in one invocation must be distinct.

## Statistics reports

`--out-statistics-markdown <path>` writes a UTF-8 Markdown report.
`--out-statistics-html <path>` writes a self-contained HTML5 report with
embedded CSS and no JavaScript or external assets.

Both report formats use the shared frontend Statistics projection rather than
CLI-specific recalculation. Reports include:

- report information;
- input/source identity;
- overview;
- capture time;
- Protocol Summary with Transport and IP Family subtables;
- unrecognized packet totals;
- captured/original packet size distribution;
- flow packet-count histogram;
- detected protocol hints;
- capture metrics;
- flow characteristics;
- packet and original-byte direction distributions;
- TCP flag statistics;
- QUIC and TLS recognition/version summaries;
- top flows, top endpoints, and top ports;
- Protocol Path statistics in Identity tree form at the end of the report.

Report information includes:

- Application: `Pcap Flow Lab`
- Version: the current application version
- Client: `CLI`
- Generated at: UTC timestamp in `YYYY-MM-DD HH:MM:SS UTC` form
- Statistics scope: `Complete` or `Partial`

For fast v16 index reports, report metadata may also include the stable index
revision already read from the index header.

The full report intentionally includes only the Protocol Path Identity tree. It
does not duplicate the standalone Protocol Path `kind-overview` or
`terminal-paths` export views.

For v16 index input, report generation can use the Statistics fast tier without
opening the recorded source capture and without validating later flow-metadata
or packet-detail sections.

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

Write full Statistics reports:

```text
pcap-flow-lab summary capture.idx --out-statistics-html statistics.html --out-statistics-markdown statistics.md
```
