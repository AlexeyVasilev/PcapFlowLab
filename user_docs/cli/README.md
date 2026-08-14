# Pcap Flow Lab CLI

Pcap Flow Lab CLI helps you work with packet captures and saved indexes from
the command line. It uses the same analysis backend to:

- summarize captures and indexes;
- list and inspect canonical flows;
- inspect individual packets;
- export selected packet data to new PCAP files.

Supported input categories:

- PCAP;
- PCAPNG;
- Pcap Flow Lab indexes.

## Quick start

Start with a raw capture:

```text
pcap-flow-lab summary pcap_flow_lab_showcase.pcap
```

The CLI also treats `summary` as the default command, so this is equivalent:

```text
pcap-flow-lab pcap_flow_lab_showcase.pcap
```

Create a reusable index:

```text
pcap-flow-lab summary pcap_flow_lab_showcase.pcap --out-index showcase.idx
```

List flows:

```text
pcap-flow-lab flows showcase.idx --limit 10
```

Inspect one flow:

```text
pcap-flow-lab flow-info showcase.idx --flow-number 1
```

Inspect one packet:

```text
pcap-flow-lab packet-info pcap_flow_lab_showcase.pcap --flow-number 1 --packet-in-flow 4
```

Export one flow:

```text
pcap-flow-lab export-flows pcap_flow_lab_showcase.pcap --flow-number 1 --out flow_1_full.pcap
```

## Choose a command

| Goal | Command |
| --- | --- |
| Understand the input as a whole | [summary](summary.md) |
| Find, rank, and select flows | [flows](flows.md) |
| Analyze one canonical flow | [flow-info](flow-info.md) |
| Inspect one captured packet | [packet-info](packet-info.md) |
| Write selected packet data to PCAP | [export-flows](export-flows.md) |

## Typical workflow

```text
capture / index
      |
      v
   summary
      |
      v
    flows
   /     \
  v       v
flow-info export-flows
  |
  v
packet-info
```

This is a common workflow, not a required sequence.

- `summary` can be used by itself.
- `export-flows` often follows `flows` directly.
- `packet-info --packet-in-file <N>` can be used directly when you already know
  the global packet number.

## Raw captures and indexes

Raw capture means directly opening a PCAP or PCAPNG file.

Index means opening a previously saved Pcap Flow Lab index that already stores
the materialized flow inventory and related metadata.

| Input type | What it is good for | Key behavior |
| --- | --- | --- |
| Raw capture | First-time analysis, export, packet-byte-backed inspection | Flow inventory is built when opened, `--settings` may be applied, packet bytes are immediately available. |
| Index | Repeated metadata workflows and convenient reopen | Stored flow inventory is reused, raw grouping settings are not reapplied, packet-byte-backed operations can still need the original source capture. |

### When a source capture is needed

Source capture means the original raw packet file associated with an index.

This matters for index-backed commands that need packet bytes rather than only
stored metadata. The main current cases are:

- [packet-info](packet-info.md)
- [export-flows](export-flows.md)

If the original packet file is not automatically available, provide it
explicitly:

```text
--source-capture original.pcap
```

Keep the terms distinct:

- input index = the `.idx` or `.pflidx` file you opened;
- source capture = the original packet file that can supply packet bytes.

Metadata-oriented workflows such as [summary](summary.md),
[flows](flows.md), and [flow-info](flow-info.md) do not need source packet
bytes for their documented reports.

## Canonical flow numbers

The `No.` column shown by [flows](flows.md) is the one-based canonical flow
number within the currently opened flow inventory.

That number is then used by:

- [flow-info](flow-info.md)
- flow-scoped [packet-info](packet-info.md)
- [export-flows](export-flows.md)

These numbers belong to the specific imported or indexed flow inventory you
opened. If grouping settings change that inventory, the numbering can change
too.

For details, see [flows](flows.md) and
[Capture processing settings](../reference/settings.md).

## Packet numbers

[packet-info](packet-info.md) supports two different packet coordinates:

- `--packet-in-file <N>` selects the N-th captured packet in the whole capture
  timeline;
- `--flow-number <F> --packet-in-flow <P>` selects the P-th packet inside
  canonical flow F.

Use `Packet in File` when you already know the global capture position.
Use `Packet in Flow` when you are moving from a selected canonical flow down to
one packet inside that flow.

## Capture processing settings

`--settings settings.json` is optional configuration for raw capture
processing.

Current public settings cover:

- flow grouping identity;
- selected-packet checksum validation.

The accepted fields, defaults, and validation rules are documented centrally
in [Capture processing settings](../reference/settings.md).

## Exporting packet data

[export-flows](export-flows.md) supports two main output styles:

- `--out <path>`
  writes one combined classic PCAP;
- `--out-dir <path>`
  writes one PCAP per selected flow and also creates `flows_manifest.csv`.

It also supports bounded retention for smaller diagnostic subsets, such as
keeping only the beginning of each selected flow or exporting unrecognized
packets as a separate mode.

See [export-flows](export-flows.md) for the detailed selectors and retention
options.

## Common workflows

Find the largest TLS flows:

```text
pcap-flow-lab flows showcase.idx --filter TLS --sort bytes:desc
```

Inspect one selected TLS flow:

```text
pcap-flow-lab flow-info showcase.idx --flow-number 1
```

Inspect a packet with bytes:

```text
pcap-flow-lab packet-info pcap_flow_lab_showcase.pcap --flow-number 16 --packet-in-flow 1 --bytes
```

Export a bounded TLS sample:

```text
pcap-flow-lab export-flows pcap_flow_lab_showcase.pcap --filter TLS --first-packets 30 --include-last-packet --out tls_sample.pcap
```

## Progress and help

The documented commands support progress control where applicable through:

```text
--progress auto
--progress on
--progress off
```

For help:

```text
pcap-flow-lab --help
pcap-flow-lab <command> --help
```

The documentation uses the platform-neutral executable name
`pcap-flow-lab`. Actual invocation depends on where the executable is located.
For example, a local Windows build may be invoked as:

```text
.\pcap-flow-lab.exe
```

Compatibility aliases exist in the dispatcher, but this overview uses only the
canonical command names.

## Documentation

Detailed command references:

- [summary](summary.md)
- [flows](flows.md)
- [flow-info](flow-info.md)
- [packet-info](packet-info.md)
- [export-flows](export-flows.md)

Reference:

- [Capture processing settings](../reference/settings.md)
