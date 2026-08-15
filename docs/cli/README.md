# CLI Overview

This directory contains the technical reference for the current Pcap Flow Lab
command-line interface.

The public command surface is:

- `summary`
- `flows`
- `export-flows`
- `flow-info`
- `packet-info`

Global help documents only those canonical command names. The dispatcher also
accepts a small compatibility alias set, but this reference uses the canonical
names throughout.

## Command index

- [Architecture](architecture.md)
- [summary](commands/summary.md)
- [flows](commands/flows.md)
- [export-flows](commands/export-flows.md)
- [flow-info](commands/flow-info.md)
- [packet-info](commands/packet-info.md)

## Input model

All commands accept either:

- a positional input path; or
- `--input <path>`

Those two forms are mutually exclusive. Using both in the same invocation is
invalid, even if both paths are identical or resolve to the same file.

Examples:

```text
pcap-flow-lab summary capture.pcap
pcap-flow-lab summary --input capture.pcap
pcap-flow-lab capture.pcap
pcap-flow-lab --input capture.pcap
```

Invalid:

```text
pcap-flow-lab summary capture.pcap --input capture.pcap
```

## Supported input types

The CLI auto-detects:

- raw capture files;
- capture indexes.

Some commands can operate fully on an index. Commands that need source bytes may
require the original capture to be available, or may require
`--source-capture <path>` when opening an index.

## Settings JSON

The CLI settings JSON parser currently accepts only these boolean fields:

- `ignore_vlan_and_mpls_layers_when_grouping_flows`
- `ignore_gtpu_teids_when_grouping_inner_flows`
- `validate_selected_packet_checksums`

Unknown fields are rejected.

Example:

```json
{
  "ignore_vlan_and_mpls_layers_when_grouping_flows": true,
  "ignore_gtpu_teids_when_grouping_inner_flows": false,
  "validate_selected_packet_checksums": true
}
```

## Progress and help

- Top-level `pcap-flow-lab --help` prints global help and exits successfully.
- Top-level `pcap-flow-lab` prints the same global help body but exits
  non-zero because no command or input was provided.
- Command-specific parse errors print an error followed by command help.
- `--progress` is supported where documented by each command.

## Numbering

All user-facing flow numbers and packet numbers are 1-based.

## Related end-user docs

The technical CLI reference in `docs/cli/**` describes command contracts and
behavior. End-user workflow guides live separately in `user_docs/cli/**`.
