# `summary`

`summary` shows a whole-input overview for a raw capture or a Pcap Flow Lab
index. Use it when you want a quick answer to questions like:

- what is in this file;
- how large it is in packet and byte terms;
- how traffic is split across transport families;
- whether it is worth creating an index for later work.

It is also the default CLI command. If you pass an input file without naming a
command, Pcap Flow Lab runs `summary`.

The examples below were captured from the 0.3.0 CLI using the repository
showcase raw capture. Shell-specific executable prefixes such as `.\` are
omitted.

## Quick start with the showcase capture

This is the most useful first workflow: summarize a raw capture and save the
two most common reusable side outputs at the same time.

Command:

```text
pcap-flow-lab summary pcap_flow_lab_showcase.pcap --out-index showcase.idx --out-flows-list showcase_flows.csv
```

Verified output:

```text
Opening capture: 100% (728.9 KB / 728.9 KB)

PcapFlowLab Summary

Input
  File:            pcap_flow_lab_showcase.pcap
  Type:            PCAP
  File size:       728.9 KB

Capture
  Flows:                 58
  Packets:               1 557
  Captured bytes:        704.6 KB
  Original bytes:        706 KB
  Unrecognized packets:  5

Transport Summary

Transport  Flows  Packets  Captured Bytes  Original Bytes
TCP           33    1 125        455.4 KB        456.8 KB
UDP           20      419        248.6 KB        248.6 KB
SCTP           1        1            66 B            66 B
Other          4        7           360 B           360 B

IP Family Summary

Family  Flows  Packets  Captured Bytes  Original Bytes
IPv4       56    1 267        657.8 KB        659.2 KB
IPv6        2      285         46.6 KB         46.6 KB

Index written to: showcase.idx
Flow list written to: showcase_flows.csv
```

This single run demonstrates four things:

- one raw-capture pass;
- the standard whole-capture summary;
- reusable index creation with `--out-index`;
- canonical flow-list CSV creation with `--out-flows-list`.

The shown values are already enough to answer several practical questions:

- the showcase currently opens as `58` recognized flows across `1 557` packets;
- TCP is the dominant transport family in this capture;
- most bytes are carried by IPv4 rather than IPv6;
- only `5` packets remain unrecognized under current product semantics.

### What the standard summary output means

The normal `summary` output always starts with four sections:

- `Input`
- `Capture`
- `Transport Summary`
- `IP Family Summary`

`Input` identifies the opened file and input type.

`Capture` gives the whole-input totals:

- `Flows`
- `Packets`
- `Captured bytes`
- `Original bytes`
- `Unrecognized packets`

`Transport Summary` groups recognized flows into the fixed transport categories:

- `TCP`
- `UDP`
- `SCTP`
- `Other`

`IP Family Summary` shows the IPv4 and IPv6 split for recognized IP flows.

## Create reusable side outputs while summarizing

The previous example is worth keeping in mind as the default "do useful work
while opening a raw capture" pattern.

`--out-index` saves a reusable Pcap Flow Lab index:

```text
--out-index showcase.idx
```

Use it when you expect to come back to the same data later and want faster,
index-backed reopen workflows.

`--out-flows-list` writes the complete canonical flow list as CSV:

```text
--out-flows-list showcase_flows.csv
```

Use it when you want to inspect or post-process the full flow inventory outside
the CLI.

Because `summary` is always whole-input, this CSV is not filtered or limited.

## Summarize an existing index

Once an index exists, you can read the same summary data from the index instead
of reopening the raw capture.

Command:

```text
pcap-flow-lab summary showcase.idx --out-protocol-path-tree showcase_tree.txt --protocol-path-mode identity-tree
```

Verified excerpt:

```text
Opening index: 100% (72.4 KB / 72.4 KB)

PcapFlowLab Summary

Input
  File:            showcase.idx
  Type:            PcapFlowLab Index
  File size:       72.4 KB
  Source capture:  pcap_flow_lab_showcase.pcap

Capture
  Flows:                 58
  Packets:               1 557
  Captured bytes:        704.6 KB
  Original bytes:        706 KB
  Unrecognized packets:  5

...

Protocol Path Tree written to: showcase_tree.txt
```

In this excerpt, `...` means repeated standard summary lines were omitted from
the documentation for brevity.

This workflow shows that:

- the same summary data can be read from the saved index;
- the index can display its recorded `Source capture` metadata;
- the full Protocol Path Tree can be exported as a side output;
- this summary workflow does not require packet-byte-backed inspection.

For current v16 indexes, standard summary output, `--extended`, Protocol Path
Tree preview, and Protocol Path Tree export are read from the index's fast
Statistics tier. This means the command can report summary data without
opening the original capture file and without scanning the later flow-detail
parts of the index.

Flow-list CSV export is different: `--out-flows-list` needs flow metadata, so
it uses the normal full index-opening path.

## Get a deeper overview with `--extended`

Use `--extended` when the standard summary is not enough and you want a broader
statistical picture of the whole input.

The next example also shows the default-command shorthand, because `summary` is
the default command when you provide only an input file.

Command:

```text
pcap-flow-lab showcase.idx --extended
```

Verified excerpts:

```text
Packet Size Distribution

Captured Size  Packets  Percent
0-63               207      13%
64-127             494      32%
128-255            234      15%
256-511            176      11%
...
1400-1550           85       5%
...
25001+               1    0.06%
```

```text
Flows by Packet Count

Packets / Flow     Flows  Original Bytes
1               27 (47%)  3.9 KB (0.55%)
2                 4 (7%)   888 B (0.12%)
3-5              9 (16%)  106.6 KB (15%)
...
101-250           1 (2%)  121.7 KB (17%)
251-500           3 (5%)  395.2 KB (56%)
```

```text
Detected Protocol Hints

Protocol Hint      Flows     Packets  Captured Bytes  Original Bytes
HTTP              3 (5%)     53 (3%)      23 KB (3%)      23 KB (3%)
TLS               5 (9%)   725 (47%)  381.9 KB (54%)  381.9 KB (54%)
DNS               2 (3%)  12 (0.77%)  1.3 KB (0.18%)  1.3 KB (0.18%)
QUIC              4 (7%)     57 (4%)    35.9 KB (5%)    35.9 KB (5%)
...
Unknown         34 (59%)   654 (42%)  257.5 KB (37%)  258.8 KB (37%)
```

```text
Top Endpoints

Endpoint            Packets  Original Bytes
192.0.2.10:41000        457        244.5 KB
198.51.100.10:443       457        244.5 KB
192.0.2.140:43000       226        121.7 KB
...
```

```text
Top Ports

Port   Packets  Original Bytes
443        804          421 KB
41000      457        244.5 KB
43000      226        121.7 KB
...
```

Here, `...` marks documentation truncation. It is not literal CLI output.

These sections help you notice different kinds of structure:

- `Packet Size Distribution` shows that the showcase includes both many small
  packets and some much larger packet-size buckets.
- `Flows by Packet Count` shows that many flows are one-packet flows, while a
  small number of larger flows contribute most of the bytes.
- `Detected Protocol Hints` shows that TLS is a major detected-protocol
  component in this showcase.
- `Top Endpoints` and `Top Ports` quickly show the most active participants and
  the prominence of port `443`.

## Explore protocol paths

Protocol Path Tree is a whole-input view of the protocol-layer shapes found in
the capture or index.

You can preview it in standard output:

```text
pcap-flow-lab summary showcase.idx --protocol-path-tree
```

You can export the full tree to a file:

```text
pcap-flow-lab summary showcase.idx --out-protocol-path-tree showcase_tree.txt
```

You can choose the mode explicitly:

```text
pcap-flow-lab summary showcase.idx --out-protocol-path-tree showcase_tree.txt --protocol-path-mode identity-tree
```

### Real exported identity-tree excerpt

The following is an excerpt from the full exported `showcase_tree.txt`:

```text
Protocol Path Tree
Mode: Identity tree

Layer                               Flows        Packets    Original Bytes
Ethernet II                    57 (98.3%)  1 551 (99.9%)   705.7 KB (100%)
  IPv4                         44 (75.9%)    710 (45.7%)  432.1 KB (61.2%)
    UDP                        21 (36.2%)     100 (6.4%)  144.1 KB (20.4%)
      GTP-U (TEID 0x01020304)    1 (1.7%)      1 (0.06%)     112 B (0.02%)
        IPv4                     1 (1.7%)      1 (0.06%)     112 B (0.02%)
          TCP                    1 (1.7%)      1 (0.06%)     112 B (0.02%)
      Geneve (VNI 100)           1 (1.7%)      1 (0.06%)     106 B (0.01%)
        Ethernet II              1 (1.7%)      1 (0.06%)     106 B (0.01%)
          IPv4                   1 (1.7%)      1 (0.06%)     106 B (0.01%)
            TCP                  1 (1.7%)      1 (0.06%)     106 B (0.01%)
      VXLAN (VNI 100)            1 (1.7%)      1 (0.06%)     118 B (0.02%)
        Ethernet II              1 (1.7%)      1 (0.06%)     118 B (0.02%)
          IPv4                   1 (1.7%)      1 (0.06%)     118 B (0.02%)
            TCP                  1 (1.7%)      1 (0.06%)     118 B (0.02%)
```

This kind of view is useful when you want to see not just "which protocols
exist", but how complete protocol stacks are layered in the input. In the
excerpt above, you can immediately see that the showcase contains direct UDP
traffic plus multiple overlay patterns such as GTP-U, Geneve, and VXLAN, each
leading into inner IPv4 and TCP traffic.

### Protocol Path Tree modes

The available modes are:

- `kind-overview`
- `identity-tree`
- `terminal-paths`

Current default mode:

```text
kind-overview
```

These mode descriptions match the verified CLI behavior:

- `kind-overview`
  groups path layers by protocol kind only. Identifier details are normalized
  away, so this is the broadest aggregate view.
- `identity-tree`
  keeps the full stored path identity, including distinguishing metadata such
  as tunnel identifiers where they are part of the path identity.
- `terminal-paths`
  aggregates by complete terminal path strings rather than rendering a nested
  prefix tree.

### Preview vs export

The stdout preview is intentionally limited. If the preview would be longer
than the CLI preview window, the CLI prints a note telling you to use
`--out-protocol-path-tree <file>` for the complete tree.

The file export is not limited by that preview size.

### Option dependency

`--protocol-path-mode` is only valid when at least one of these is present:

- `--protocol-path-tree`
- `--out-protocol-path-tree <path>`

This is invalid:

```text
pcap-flow-lab summary showcase.idx --protocol-path-mode identity-tree
```

## Other useful workflows

Use the explicit input form when you want a more explicit command line:

```text
pcap-flow-lab summary --input showcase.idx
```

Use `--settings` when you want a raw capture import to use a supported settings
file:

```text
pcap-flow-lab summary pcap_flow_lab_showcase.pcap --settings settings.json
```

For the accepted `settings.json` fields, defaults, and validation rules, see
[Capture processing settings](../reference/settings.md).

Use `--force` when a side-output file already exists and you intentionally want
to replace it:

```text
pcap-flow-lab summary showcase.idx --out-protocol-path-tree showcase_tree.txt --force
```

Use `--progress` to control live open-progress reporting on `stderr`:

```text
pcap-flow-lab summary showcase.idx --progress auto
pcap-flow-lab summary showcase.idx --progress on
pcap-flow-lab summary showcase.idx --progress off
```

## Command reference

### Syntax

Supported forms:

```text
pcap-flow-lab summary <input> [options]
pcap-flow-lab summary --input <input> [options]
pcap-flow-lab <input> [summary options]
```

Help:

```text
pcap-flow-lab -h
pcap-flow-lab --help
pcap-flow-lab summary --help
```

### Supported inputs

`summary` accepts:

- PCAP captures
- PCAPNG captures
- Pcap Flow Lab indexes

You can provide the input either:

- as a positional path;
- or with `--input <path>`.

These forms are mutually exclusive. Do not use both in the same command, even
if they point to the same file.

The CLI recognizes both `.idx` and `.pflidx` as index file extensions.

### Options

| Option | Value | Description |
| --- | --- | --- |
| `--input` | `<path>` | Provide the input path explicitly instead of using a positional path. |
| `--settings` | `<settings.json>` | Apply supported raw-import settings. Valid only for raw capture input. |
| `--extended` | none | Append additional whole-input statistics sections. |
| `--protocol-path-tree` | none | Show a Protocol Path Tree preview in stdout. |
| `--protocol-path-mode` | `kind-overview`, `identity-tree`, `terminal-paths` | Choose the Protocol Path Tree mode. Default is `kind-overview`. |
| `--out-index` | `<path>` | Save a Pcap Flow Lab index from a raw capture. Invalid for index input. |
| `--out-flows-list` | `<path>` | Export the complete canonical flow list as CSV. |
| `--out-protocol-path-tree` | `<path>` | Export the complete Protocol Path Tree to a text file. |
| `--progress` | `auto`, `on`, `off` | Control live open-progress reporting on `stderr`. Default is `auto`. |
| `--force` | none | Allow existing side-output files to be overwritten. |
| `-h`, `--help` | none | Show summary-specific help and exit successfully. |

### Raw capture vs index

| Capability | Raw capture | Index |
| --- | --- | --- |
| Standard summary output | Yes | Yes |
| `--extended` | Yes | Yes |
| Protocol Path Tree preview | Yes | Yes |
| Protocol Path Tree file export | Yes | Yes |
| `--settings` | Yes | No |
| `--out-index` | Yes | No |
| `--out-flows-list` | Yes | Yes |
| `--progress` | Yes | Yes |

For `summary`, an index is meant to be self-sufficient for summary data.
Unlike byte-backed inspection commands, `summary` does not need
`--source-capture`.

For current v16 indexes, summary-style outputs use the index fast Statistics
tier when possible. This is a quick metadata read, not a full validation of
every later flow-detail section in the index.

## Invalid combinations and errors

Important rules:

- positional input and `--input` cannot be combined;
- `--settings` is raw-capture only;
- `--out-index` is raw-capture only;
- `--protocol-path-mode` requires Protocol Path preview or export;
- `summary` does not accept flow-selection or packet-selection options;
- an input path is required unless you are asking for help.

Examples of options that are intentionally not valid for `summary`:

- `--filter`
- `--flow-number`
- `--flow-numbers`
- `--sort`
- `--limit`
- `--packets-in-flow`
- `--packets-in-file`
- `--source-capture`

`summary` rejects these instead of silently ignoring them.

Side-output rules also matter:

- output files are not overwritten unless you add `--force`;
- side outputs cannot overwrite the input file;
- side outputs must point to distinct paths;
- output parent directories must already exist.

## Notes and limitations

`summary` is a whole-input command. It does not:

- filter flows;
- choose one flow;
- inspect one packet;
- export selected flow packets.

For that work, use the other CLI commands:

- `flows`
- `flow-info`
- `packet-info`
- `export-flows`

The stdout format is human-readable text. It is meant for direct inspection or
redirection into a text file, not as a structured machine-readable API.

Progress, warnings, and side-output messages are written to `stderr`, while the
requested summary text is written to `stdout`.

## Related commands

After `summary`, the next most relevant commands are:

- `flows` for listing, filtering, sorting, and exporting flow metadata;
- `flow-info` for detailed analysis of one canonical flow;
- `packet-info` for inspecting one packet;
- `export-flows` for exporting packet data for selected flows.
