# CLI V2 Architecture

## Status

This document describes the current PcapFlowLab CLI v2 architecture.

- It remains primarily architectural.
- The current production CLI public surface is:
  `summary`, `flows`, `export-flows`, `flow-info`, and `packet-info`.

## Goals

CLI v2 is intended to provide a stable public command surface for capture-wide
summary work, flow-oriented queries, flow export, selected-flow analysis, and
packet inspection.

The intended public shape is:

```text
pcap-flow-lab <command> <input> [selection options] [command options] [output options]
```

The primary public commands are:

- `summary`
- `flows`
- `export-flows`
- `flow-info`
- `packet-info`

There is intentionally no separate top-level `statistics` command. Statistics
and whole-capture overview belong to `summary`.

## Command Model

### Global help

CLI v2 supports:

```text
pcap-flow-lab -h
pcap-flow-lab --help
```

These forms show global CLI help, require no input, and return success.

Global help should:

- show the CLI title
- show the default-summary invocation shape
- list current commands with short descriptions
- point to command-specific help through `pcap-flow-lab <command> --help`

### Command-specific help

Commands should support:

```text
pcap-flow-lab <command> -h
pcap-flow-lab <command> --help
```

Explicit help must be handled before ordinary required-argument validation.

### Syntax versus runtime errors

CLI v2 distinguishes between:

- syntax or argument errors
- runtime or operational errors

Syntax errors should use command-specific help.

Runtime errors should report the actual operational failure and should not dump
full command help after parsing has already succeeded.

### Default summary invocation

CLI v2 supports all of the following forms:

```text
pcap-flow-lab summary data.pcap
pcap-flow-lab data.pcap
pcap-flow-lab --input data.pcap
```

The latter two forms are equivalent to:

```text
pcap-flow-lab summary --input data.pcap
```

If a positional token later conflicts with a known command name, `--input` can
be used to disambiguate the intended input path.

### `summary`

`summary` is the whole-capture and whole-index overview command.

- It corresponds broadly to the Statistics and capture-overview domain.
- It always operates on the complete opened capture or index.
- It supports multiple summary sections and multiple side outputs.
- Protocol Path Tree belongs to this summary/statistics domain.
- The detailed command contract is documented in
  [commands/summary.md](./commands/summary.md).

`summary` must not accept flow-selection options. In particular, it must not
support:

- `--filter`
- `--flow-number`
- `--flow-numbers`
- `--sort`
- `--limit`
- `--packets-in-flow`
- `--packets-in-file`

The exact `summary` contract is now defined in
[commands/summary.md](./commands/summary.md).

### `flows`

`flows` is the flow-list presentation and flow-oriented selection command.

- It operates on selected subsets of canonical flows.
- It owns filtering, sorting, limiting, and flow-list presentation.
- It supports console rendering and flow-list file export.
- The detailed command contract is documented in
  [commands/flows.md](./commands/flows.md).

Current working output vocabulary for this command includes:

```text
--out-flows-list <path>
```

This document does not repeat the detailed `flows` semantics.

The `flows` contract now defines:

- one-based canonical flow numbering
- the exact selection pipeline
- initial flow text-filter semantics
- initial sort fields and tie-break rules
- the distinction between the default 25-row stdout preview and explicit
  `--limit`
- reuse of the existing flow metadata CSV schema

The `flows` command is implemented.

### `export-flows`

`export-flows` is the Smart-Export-like flow packet export command.

- It applies the same canonical flow-selection pipeline shape as `flows`,
  without a sort stage.
- It exports packet records belonging to the resulting flow set.
- It supports documented Smart Export packet-retention rules.
- It supports either one merged classic-PCAP output or one classic-PCAP file
  per selected flow.
- The detailed command contract is documented in
  [commands/export-flows.md](./commands/export-flows.md).

This document does not repeat the detailed `export-flows` packet-retention,
source-capture, manifest, or output-directory semantics.

### `flow-info`

`flow-info` is the selected-flow analysis command.

- It corresponds conceptually to the application's Analysis surface.
- It operates on one selected canonical flow.
- It is documented in detail in
  [commands/flow-info.md](./commands/flow-info.md).
- It is implemented in the current production CLI.

### `packet-info`

`packet-info` is the packet inspection command.

It is implemented in the current production CLI.

The detailed contract is documented in
[commands/packet-info.md](./commands/packet-info.md).

## Input Model

Primary input syntax:

```text
pcap-flow-lab summary data.pcap
pcap-flow-lab flows data.idx
```

Explicit input syntax:

```text
--input <path>
```

Positional input and `--input` are mutually exclusive input forms. Using both
in the same invocation is invalid.

Supported analysis input concepts are:

- PCAP
- PCAPNG
- PcapFlowLab index

The eventual implementation should auto-detect capture versus index using the
real supported file/header/index detection path, not just filename extension.

### Source capture

CLI v2 uses:

```text
--source-capture <path>
```

This is used for index-based operations that require original packet bytes,
including current cases such as:

- packet inspection
- packet byte inspection
- flow packet export

The original packet bytes are not stored inside the index itself.

The application may attempt automatic source-capture resolution first. An
explicit `--source-capture` acts as a user-supplied source path or override.

Command-specific error wording for missing or mismatched source captures is
deferred.

### Index compatibility

The current capture index format is version 14.

From a user-facing perspective, this means the normal index compatibility
policy applies:

- current-version indexes open normally
- unsupported older indexes must be rebuilt before use with the current CLI

This CLI work therefore does affect index compatibility, even though the
top-level command set remains the same.

## Settings Model

CLI v2 reserves:

```text
--settings <settings.json>
```

The configuration format is JSON.

The initial intended contents are a deliberately small headless-relevant
subset of application settings. The first production schema is:

```json
{
  "ignore_vlan_and_mpls_layers_when_grouping_flows": true,
  "ignore_gtpu_teids_when_grouping_inner_flows": false,
  "validate_selected_packet_checksums": false
}
```

It is intentionally narrower than the GUI settings model.

Important semantic rule:

- Import-time flow-grouping settings apply when importing raw captures.
- They must not reinterpret grouping already stored in an existing index.

This is intended to remain consistent with the current GUI behavior.

## User-Facing Numbering

All CLI v2 user-facing flow and packet numbers are 1-based.

- This matches normal PcapFlowLab UI and Wireshark-style numbering.
- Internal C++ indices may remain zero-based.
- Documentation and implementation should clearly distinguish user-facing
  numbers from internal indices.

## Flow Number Identity

A flow number identifies the canonical session flow before filtering, sorting,
or limiting.

- Sorting changes presentation and processing order.
- Sorting does not renumber flows.

Example:

- A flow known as flow 42 remains flow 42 even after sorting by byte count.

## Flow Selection Options

Current working option names are:

```text
--flow-number <N>
--flow-numbers <range>
--filter <text>
--sort <field>:<asc|desc>
--limit <N>
```

These names are documented here as working public API names and are not being
renamed in this pass.

### `--flow-number`

`--flow-number` selects one user-facing canonical flow number.

This is the natural selector for commands such as:

- `flow-info`
- `packet-info` with `--packets-in-flow`

### `--flow-numbers`

`--flow-numbers` selects a set of user-facing canonical flow numbers.

Conceptual range grammar:

```text
1-100,234,236,301-305
```

Rules to document:

- ranges are inclusive
- a single value may also be represented
- duplicates are removed
- descending ranges such as `10-5` are invalid

The final parser implementation is intentionally deferred.

### `--filter`

```text
--filter <text>
```

The exact searched fields and semantics are now defined by the detailed
`flows` command contract.

Protocol Path-specific filtering remains out of scope for the initial CLI
design.

### `--sort`

Working syntax:

```text
--sort <field>:<asc|desc>
```

Example:

```text
--sort bytes:desc
```

The initial allowed field set and semantic rules are now defined by the
detailed `flows` command contract.

### `--limit`

```text
--limit <N>
```

`--limit` applies after explicit selection, filtering, and sorting.

It limits the number of flows remaining for command-specific output or
processing.

The default 25-row stdout preview used by `flows` is separate from this
explicit result-set limit.

## Flow Selection Pipeline

For flow-oriented commands, the canonical processing order is:

```text
all canonical flows
    ->
explicit flow-number selection
    ->
text filter
    ->
sorting
    ->
limit
    ->
command-specific output/processing
```

This is a core CLI semantic contract.

Example:

```text
--flow-numbers 1-1000
--filter "QUIC"
--sort bytes:desc
--limit 100
```

means:

1. begin with canonical flows 1 through 1000
2. retain only flows matching the text filter
3. sort the matches by bytes descending
4. keep the first 100
5. pass exactly that resulting set and order to the command

Consequences:

- `flows` presents or exports that resulting set
- `export-flows` exports packet records for that resulting set
- `summary` is explicitly excluded from this pipeline

## Packet Selection Options

Current working option names are:

```text
--packets-in-flow <range>
--packets-in-file <range>
```

The explicit wording is intentional so the coordinate system stays clear.

Examples:

```text
--flow-number 42 --packets-in-flow 1-5,8,14
--packets-in-file 2685,2686,2700-2705
```

Rules:

- both coordinate systems are user-facing and 1-based
- `--packets-in-flow` is relative to one selected flow
- `--packets-in-file` is relative to the complete file packet sequence
- using both coordinate systems together in one packet-selection operation is
  ambiguous and should be treated as invalid

Detailed validation wording is deferred.

## Capture-Global Packet Lookup

The current CLI supports capture-global packet-oriented lookup for:

```text
packet-info --packet-in-file <N>
```

The high-level architecture now includes a capture-level sparse packet locator
persisted in capture indexes.

At a high level this uses:

- capture-global packet index plus file-offset anchors
- approximately 400 MiB file-distance anchors
- no packet-to-flow reverse map

For classic PCAP, lookup can seek from the nearest sparse anchor efficiently.

For PCAPNG, source-backed lookup may still require additional structural
walking before the anchor to restore required section and interface context, so
the architecture should not promise the same strict bounded lookup cost as
classic PCAP.

## Output Vocabulary

Current working output option vocabulary includes:

```text
--out-flows-list <path>
--out-index <path>
--out-protocol-path-tree <path>
```

Not every output applies to every command.

`export-flows` now has its own detailed output contract in
[commands/export-flows.md](./commands/export-flows.md), including `--out` and
`--out-dir`.

Intended ownership:

- `--out-flows-list`: flow metadata or flow-list export
- `--out-index`: reusable PcapFlowLab index output
- `--out-protocol-path-tree`: complete-capture Protocol Path Tree export from
  `summary`, using the shared plain-text Protocol Path Tree exporter

These names remain working API names and may still be refined in later
per-command design.

One important design idea is that `summary` may produce multiple side outputs
during one raw-capture import, for example:

```text
pcap-flow-lab summary huge.pcap \
    --out-index huge.idx \
    --out-flows-list flows.csv \
    --out-protocol-path-tree protocol-tree.txt
```

This avoids repeated re-import of very large captures just to materialize
separate outputs.

However:

- `summary --out-flows-list` means the complete flow list
- filtered, sorted, or limited flow-list export belongs to `flows`

## Output Overwrite Policy

CLI v2 reserves:

```text
--force
```

Outputs should not be silently overwritten by default.

- Without `--force`, writing to an existing path should fail.
- Exact error wording and exit mapping are deferred.

## Output Formats

CLI v2 reserves a command or output-specific concept:

```text
--format <format>
```

Potential formats include:

- `text`
- `csv`
- `json`

Important constraints:

- not every command will support every format
- each command or artifact will later document its supported formats explicitly
- the initial implementation may support only a subset

## stdout And stderr Contract

CLI v2 should follow this stream contract:

Explicit `-h` and `--help` output belongs on `stdout`.

Argument-error responses should keep both the concise error text and the
associated help on `stderr`.

`stdout`
: requested command data

`stderr`
: progress, warnings, errors, diagnostics

This is important for shell pipelines.

For example:

```text
pcap-flow-lab flows capture.pcap --filter "QUIC" > quic.txt
```

must not mix progress messages into the requested flow output on `stdout`.

## Progress Model

CLI v2 reserves:

```text
--progress auto
--progress on
--progress off
```

Default:

```text
auto
```

Intended behavior:

- `auto`: show live progress only when `stderr` is an interactive terminal
- `on`: explicitly request live progress even when `stderr` is redirected
- `off`: disable progress

Progress must be written to `stderr`.

Normal command data remains buffered for `stdout`.

An example conceptual progress line is:

```text
Opening capture: 42% [21.0 GB / 50.0 GB]
```

Interactive implementations may update one terminal line. Exact
platform-specific terminal behavior is intentionally not specified here.

## Exit Status

CLI v2 should have stable exit semantics for:

- success
- invalid command line
- input, open, or validation failure
- requested object not found
- output or write failure
- general runtime failure

The numeric exit-code mapping is intentionally deferred unless a later design
pass decides to standardize a public contract.

## Removed Legacy Surface

The public CLI no longer exposes the old top-level commands:

- `inspect-packet`
- `hex`
- `export-flow`
- `save-index`
- `load-index-summary`
- `chunked-import`
- `resume-import`
- `finalize-import`

The current user-facing surface is the five-command CLI listed above.

Some shared backend capabilities that those commands used still remain in
production code where they are needed by current CLI commands, frontend code,
or internal infrastructure. That backend retention does not imply that the old
command names remain supported.

## Shared Architecture Direction

CLI v2 should reuse shared core, session, and frontend-neutral semantic models.

It must not create an independent second interpretation of:

- flow identity
- flow presentation
- packet Summary
- Packet Bytes
- Analysis
- statistics
- Protocol Path
- Stream semantics

The intended direction is:

```text
core/session
    ->
frontend-neutral DTO/presentation layer
    ->
CLI command orchestration
    ->
CLI renderers / file exporters
```

Existing CLI-specific code may still be reused where appropriate, but new CLI
v2 work should prefer shared frontend-neutral models over:

- parsing Qt or Tauri presentation strings
- duplicating protocol logic
- introducing an unrelated second semantics layer

## Future Detailed Documentation

Command-specific documentation is intended to live at:

```text
docs/cli/commands/summary.md
docs/cli/commands/flows.md
docs/cli/commands/export-flows.md
docs/cli/commands/flow-info.md
docs/cli/commands/packet-info.md
```

These documents should contain:

- complete syntax
- supported options
- exact semantics
- validation rules
- supported output formats
- example output
- detailed examples
- capture, index, and source-capture differences
- error cases

At this stage:

- `docs/cli/commands/summary.md` is defined
- `docs/cli/commands/flows.md` is defined
- `docs/cli/commands/export-flows.md` is defined and implemented
- `docs/cli/commands/flow-info.md` is defined and implemented
- `docs/cli/commands/packet-info.md` is now defined and implemented

## Intentionally Deferred Decisions

This architecture pass does not decide:

- exact summary sections or modes
- Smart Export packet-limit policy
- `flow-info` presentation modes
- `packet-info` presentation modes
- exact CSV schemas
- exact JSON schemas
- exact numeric exit codes

These belong to later per-command design iterations.
