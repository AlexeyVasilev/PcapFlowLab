# CLI V2 Architecture

## Status

This document describes the planned PcapFlowLab CLI v2 architecture.

- It is a forward-looking design document.
- Implementation has not yet caught up to this contract.
- The current production CLI remains legacy and may not match this design.

## Goals

CLI v2 is intended to provide a stable public command surface for capture-wide
summary work, flow-oriented queries, flow export, selected-flow analysis, and
packet inspection.

The intended public shape is:

```text
pcap-flow-lab <command> <input> [selection options] [command options] [output options]
```

The planned primary public commands are:

- `summary`
- `flows`
- `export-flows`
- `flow-info`
- `packet-info`

There is intentionally no separate top-level `statistics` command. Statistics
and whole-capture overview belong to `summary`.

## Command Model

### Default summary invocation

CLI v2 should support all of the following conceptual forms:

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
- It may later include multiple summary sections and multiple side outputs.
- Protocol Path Tree belongs to this summary/statistics domain.

`summary` must not accept flow-selection options. In particular, it must not
support:

- `--filter`
- `--flow-number`
- `--flow-numbers`
- `--sort`
- `--limit`
- `--packets-in-flow`
- `--packets-in-file`

A future Protocol Path Tree export therefore belongs under `summary`, for
example through a future command-specific output option such as:

```text
--out-protocol-path-tree <path>
```

That future CLI output is intended to reuse the shared C++ Protocol Path Tree
plain-text formatter/exporter already used by the Qt and Tauri Statistics UIs.

The exact summary sections, views, text output, and detailed output options are
intentionally deferred to later per-command design work.

### `flows`

`flows` is the flow-list presentation and flow-oriented selection command.

- It operates on selected subsets of canonical flows.
- It owns filtering, sorting, limiting, and flow-list presentation.
- It may later support console rendering and flow-list file export.

Current working output vocabulary for this command includes:

```text
--out-flows-list <path>
```

The exact flow-list columns, text layout, and file schemas are not finalized in
this document.

### `export-flows`

`export-flows` is the Smart-Export-like flow packet export command.

- It applies the same flow-selection pipeline as `flows`.
- It exports packet records belonging to the resulting flow set.

Current working output vocabulary for this command includes:

```text
--out-flows-data <path>
```

Future work will define Smart Export policies such as packet limits per flow.
Those policies are explicitly out of scope for this architecture pass.

### `flow-info`

`flow-info` is the selected-flow analysis command.

- It corresponds conceptually to the application's Analysis surface.
- It operates on one selected canonical flow.
- It will later support multiple presentation modes.

The current working single-flow selector is:

```text
--flow-number <N>
```

The detailed presentation modes are intentionally deferred.

### `packet-info`

`packet-info` is the packet inspection command.

It supports two distinct packet coordinate systems:

1. Packet number inside one selected flow:

   ```text
   --flow-number <N>
   --packets-in-flow <range>
   ```

2. Packet number in the complete capture or file:

   ```text
   --packets-in-file <range>
   ```

The detailed Summary, Bytes, hex, short, and full output modes are deferred to
later command design work.

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

CLI v2 reserves:

```text
--source-capture <path>
```

This is intended for index-based operations that require original packet bytes,
including future cases such as:

- packet byte inspection
- packet hex output
- flow packet export
- stream or other byte-backed inspection

The application may attempt automatic source-capture resolution first. An
explicit `--source-capture` acts as a user-supplied source path or override.

Command-specific error wording for missing or mismatched source captures is
deferred.

## Settings Model

CLI v2 reserves:

```text
--settings <settings.json>
```

The configuration format is JSON.

The initial intended contents are import-related settings, such as
flow-grouping policy. An illustrative structure is:

```json
{
  "import": {
    "flowGrouping": {
      "ignoreVlanAndMpls": true,
      "ignoreGtpuTeids": false
    }
  }
}
```

This is illustrative architecture only. It is not yet a frozen schema.

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

This uses the same conceptual primitive text-flow filtering model as the UI
flow list.

- Protocol Path-specific filtering is out of scope for the initial CLI design.
- The exact searched fields are deferred to the detailed `flows` command
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

The full allowed field set is intentionally deferred. It should later be based
on useful PcapFlowLab flow-list sorting semantics.

### `--limit`

```text
--limit <N>
```

`--limit` applies after explicit selection, filtering, and sorting.

It limits the number of flows remaining for command-specific output or
processing.

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

## Output Vocabulary

Current working output option vocabulary includes:

```text
--out-flows-list <path>
--out-flows-data <path>
--out-index <path>
--out-protocol-path-tree <path>
```

Not every output applies to every command.

Intended ownership:

- `--out-flows-list`: flow metadata or flow-list export
- `--out-flows-data`: packet or capture export for selected flows
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

- interactive terminal plus long-running operation: show progress
- non-interactive or scripted contexts: avoid terminal-style dynamic output
  where appropriate
- `on`: explicitly request progress
- `off`: disable progress

Progress must be written to `stderr`.

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

## Legacy CLI Migration Direction

The current CLI contains legacy commands and options.

CLI v2 does not require preserving the following as top-level public commands:

- `load-index-summary`
- `hex`
- `save-index`
- `chunked-import`
- `resume-import`
- `finalize-import`

Conceptual replacement direction:

- `load-index-summary` -> `summary <index>`
- `hex` -> future `packet-info` byte or hex presentation mode
- `save-index` -> `summary <capture> --out-index <index>`

Checkpoint-oriented commands expose lower-level implementation mechanics and
are not part of the planned primary CLI v2 public surface.

This document does not remove them from production code.

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

Later command-specific documentation is intended to live at:

```text
docs/cli/commands/summary.md
docs/cli/commands/flows.md
docs/cli/commands/export_flows.md
docs/cli/commands/flow_info.md
docs/cli/commands/packet_info.md
```

Those future documents should contain:

- complete syntax
- supported options
- exact semantics
- validation rules
- supported output formats
- example output
- detailed examples
- capture, index, and source-capture differences
- error cases

Those files are intentionally not created in this pass.

## Intentionally Deferred Decisions

This architecture pass does not decide:

- exact `summary` output
- exact summary sections or modes
- exact `flows` columns
- exact sorting field set
- exact flow filter fields
- Smart Export packet-limit policy
- `flow-info` presentation modes
- `packet-info` presentation modes
- exact CSV schemas
- exact JSON schemas
- exact numeric exit codes

These belong to later per-command design iterations.
