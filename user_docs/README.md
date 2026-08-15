# Pcap Flow Lab user documentation

This documentation is organized around three entry points:

- `Desktop UI` for interactive capture exploration and analysis
- `CLI` for terminal-oriented inspection and export
- `Reference` for focused contract details such as CLI `settings.json`

If you are new to the project, start with the desktop or CLI overview that
matches how you plan to use Pcap Flow Lab.

## Start here

### Using the desktop application?

Start with [Desktop interface](ui/README.md).

It is the visual overview of the desktop workflow: moving from canonical flows
into packet and Stream inspection, then into per-flow `Analysis`,
whole-capture `Statistics`, `Protocol Path`, and capture/index management.

### Using the command line?

Start with [CLI guide](cli/README.md).

The CLI is organized around five canonical commands:

- `summary`
- `flows`
- `flow-info`
- `packet-info`
- `export-flows`

### Looking for settings or reference material?

Use [Capture processing settings reference](reference/settings.md) for the CLI
`settings.json` contract.

If you are looking for the desktop dialog instead, use [GUI Settings](ui/settings.md).

## Desktop UI guides

The desktop UI and CLI use the same core capture and canonical-flow concepts,
but they support different workflows:

- Desktop UI focuses on interactive exploration and analysis.
- CLI focuses on terminal and file-oriented inspection and export.

| Guide | Use it for |
| --- | --- |
| [Desktop interface](ui/README.md) | Visual overview of the flow-first desktop workflow |
| [Main window](ui/main-window.md) | Top-level layout, workspaces, menus, and global navigation |
| [Flows](ui/flows.md) | Canonical flow navigation, packets, Stream inspection, Packet Details, and Bytes |
| [Analysis](ui/analysis.md) | Quantitative analysis of one selected canonical flow |
| [Statistics](ui/statistics.md) | Whole-capture or whole-index summaries and aggregations |
| [Captures and indexes](ui/capture-and-index.md) | Raw capture import, index reuse, source-byte availability, and attachment |
| [Flow actions and export](ui/flow-actions.md) | Desktop export actions, Smart Export, and flow-info CSV output |
| [Settings](ui/settings.md) | GUI behavior, capture-processing rules, and reopen/import lifecycle |

## CLI guides

| Guide | Use it for |
| --- | --- |
| [CLI overview](cli/README.md) | Command-line overview, command selection, and typical workflow |
| [summary](cli/summary.md) | Capture or index overview and optional summary exports |
| [flows](cli/flows.md) | List, filter, sort, and select canonical flows |
| [flow-info](cli/flow-info.md) | Detailed analysis of one canonical flow |
| [packet-info](cli/packet-info.md) | Inspect one captured packet |
| [export-flows](cli/export-flows.md) | Export selected packet data with retention controls |

## Reference

| Guide | Use it for |
| --- | --- |
| [Capture processing settings reference](reference/settings.md) | The accepted CLI `settings.json` fields for raw-capture processing |

## Raw captures and indexes

Pcap Flow Lab can open raw `PCAP` / `PCAPNG` directly, or reopen a previously
saved index that reuses an already materialized flow inventory. Byte-backed
inspection and export can still depend on access to the original source capture
bytes.

Use [Captures and indexes](ui/capture-and-index.md) for the detailed session
lifecycle.
