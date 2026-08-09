# CLI V2 `packet-info` Command

## Status

This document defines the current CLI v2 contract for:

```text
pcap-flow-lab packet-info
```

The current production CLI implements:

- `packet-info` parsing
- `packet-info` dispatch
- `packet-info` help
- `packet-info` stdout rendering

Alias: `packets-info`

The command is documented here so the implemented path can continue to reuse
the current shared packet-inspection and packet-presentation architecture
without adding a second semantics layer.

## Purpose

`packet-info` inspects exactly one captured packet.

It supports two public packet-addressing models:

1. one packet within one canonical flow
2. one packet by its capture-global packet number

The initial report contains:

- Flow Context
- basic Packet metadata
- structured Packet Summary

Optional:

```text
--bytes
```

adds exactly one whole-captured-packet hex dump.

The initial contract does not expose arbitrary byte-view selection.

## Input Forms

These forms are planned conceptually:

```text
pcap-flow-lab packet-info capture.pcap --packet-in-file 2574112
pcap-flow-lab packet-info --input capture.pcap --packet-in-file 2574112
```

Positional input and `--input` are mutually exclusive input forms.

Using both in one invocation is invalid even if they identify the same file.

Input may be:

- PCAP
- PCAPNG
- PcapFlowLab index

Input-kind detection should reuse the existing project input-detection path.

## Initial Syntax

```text
pcap-flow-lab packet-info <input>
    (--packet-in-file <N> |
     --flow-number <F> --packet-in-flow <P>)
    [--bytes]
    [--source-capture <path>]
    [--settings <settings.json>]
    [--progress <auto|on|off>]
```

Equivalent explicit-input form:

```text
pcap-flow-lab packet-info --input <input> ...
```

Help:

```text
-h
--help
```

The initial contract intentionally does not include:

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

## Selector Mode A: Flow-Scoped

The flow-scoped selector requires the pair:

```text
--flow-number <F>
--packet-in-flow <P>
```

### Flow Number

`F` is the existing canonical one-based flow number:

```text
public flow number = internal flow_index + 1
```

### Packet In Flow

`P` is the one-based packet ordinal within that canonical flow.

Contract:

```text
packet 1 = first packet of the flow in original capture order
```

It must match the packet numbering already presented by the packet-list UI.

It must not use `PacketRef::packet_index` as the public selector.

## Selector Mode B: Capture-Global

The capture-global selector is:

```text
--packet-in-file <N>
```

`N` is the one-based capture-global packet number.

Exact mapping:

```text
public packet-in-file = PacketRef::packet_index + 1
```

`PacketRef::packet_index` remains internal and zero-based.

The numbering namespace includes both:

- recognized packets
- unrecognized packets

It follows original capture order.

## Selector Mutual Exclusivity

Exactly these selector states are valid:

- `--flow-number F --packet-in-flow P`
- `--packet-in-file N`

The following are invalid:

- `--flow-number F`
- `--packet-in-flow P`
- `--flow-number F --packet-in-file N`
- `--packet-in-flow P --packet-in-file N`
- `--flow-number F --packet-in-flow P --packet-in-file N`
- duplicate selector options

All public numeric selectors must be positive integers.

Zero, malformed values, negative values, and overflow are syntax errors.

A syntactically valid but out-of-range flow or packet is a runtime error.

## Headings

Flow-scoped selection:

```text
Flow 11724 / Packet 7
```

Capture-global selection:

```text
Packet 2574112
```

The CLI must not expose zero-based internal indices.

## Flow Context

Flow Context appears near the beginning of the report, before protocol Summary.

Its purpose is to make canonical flow-key context explicit.

This is especially important for tunneled packets where Packet Summary may
contain multiple outer and inner address or transport layers.

### Recognized Flow-Scoped Packet

Conceptual shape:

```text
Flow Context
  Endpoints:        176.108.85.0:4415 <-> 103.122.221.143:443
  Direction:        A -> B
```

Because the heading already identifies:

```text
Flow F / Packet P
```

the Flow Context section should not redundantly repeat those fields.

### Recognized Capture-Global Packet

Conceptual shape:

```text
Flow Context
  Flow:             11724
  Packet in Flow:   7
  Endpoints:        176.108.85.0:4415 <-> 103.122.221.143:443
  Direction:        A -> B
```

Flow number is canonical and one-based.

Packet in Flow is the same one-based ordinal used by flow-scoped selection.

### Canonical Endpoints

Endpoints must come from the canonical flow model used by:

- `flows`
- `flow-info`

Use the same `FlowRow` and listed-flow endpoint presentation.

Do not derive Flow Context endpoints from:

- the first IP layer
- the first transport layer
- outer tunnel headers
- Packet Summary text

For tunneled packets, Flow Context must identify the endpoints actually used by
the recognized canonical flow.

### Direction

Use existing first-observed:

- `A -> B`
- `B -> A`

semantics.

Do not infer:

- Source / Destination
- Client / Server
- Initiator / Responder

### Unrecognized Global Packet

`--packet-in-file` may select a packet that belongs to no recognized canonical
flow.

In that case use:

```text
Flow Context
  Recognized Flow:  No
```

Do not fabricate:

- Flow number
- Packet in Flow
- Endpoints
- Direction

## Packet Section

The Packet section renders stable basic metadata.

Conceptual shape:

```text
Packet
  Packet in File:   2 574 112
  Time:             08:22:25.790620
  Captured Length:  1.5 KB
  Original Length:  1.5 KB
```

### Packet In File

Always show the one-based capture-global packet number.

This remains useful even when the packet was selected through:

- `--flow-number`
- `--packet-in-flow`

### Time

Reuse existing packet timestamp presentation.

Do not invent a CLI-only timestamp convention.

### Captured Length

Use authoritative captured packet length.

### Original Length

Use authoritative original packet length.

### Payload Length

The initial contract does not require a top-level `Payload Length` field.

It should be omitted unless an implementation pass confirms that it already
exists as an authoritative shared presentation field with sufficiently uniform
semantics across supported packet classes.

The CLI must not add a new CLI-only payload-length calculation just to force
the field into v1.

### Avoid Duplicate Packet Details

Do not add basic Packet fields that are already better represented inside
structured Summary unless they provide useful top-level packet identity.

For example, the CLI should not add a top-level TCP Flags field merely because
`PacketRef` retains TCP flags.

## Structured Summary

After Packet metadata, render:

```text
Summary
```

using the same structured Packet Summary architecture as the application.

Authoritative model:

```text
PacketSummaryLayer
```

and the existing selected-packet summary preparation/projection path.

The CLI must not:

- parse protocol text
- resurrect removed Protocol Details
- independently decode protocols in CLI
- build CLI-specific protocol parsers

Preserve:

- layer order
- field order
- child ordering
- nested structured rows
- malformed and truncated diagnostics
- existing bounded reassembly and contribution information already present in
  normal Packet Summary semantics

CLI responsibility is text-tree rendering only.

## Hierarchy Rendering

Conceptual example:

```text
Summary

Ethernet II
  Source: ...
  Destination: ...
  Type: IPv4

IPv4
  Source: ...
  Destination: ...
  TTL: ...
  Protocol: TCP

TCP
  Source Port: ...
  Destination Port: ...
  Flags: ...
```

Use deterministic indentation.

ANSI formatting is not required.

Do not flatten Summary into legacy protocol text.

## Unrecognized Summary

For globally selected unrecognized packets, reuse the existing best-effort
structured inspection path.

If partial decode produces structured layers, render them normally.

Examples may include partial:

- Frame
- Ethernet
- IPv4
- other safely decoded layers

Do not require canonical-flow recognition before building Summary.

Do not use legacy Protocol Details as a fallback.

## Source Requirement

Full structured Packet Summary requires source packet bytes.

Therefore successful initial `packet-info` requires readable validated source
bytes.

### Raw Input

Raw PCAP or PCAPNG provides its source bytes directly.

`--source-capture` is invalid for raw input.

### Index Input

Index input may already auto-attach its validated original source capture.

If so, `packet-info` works normally.

Otherwise support:

```text
--source-capture <path>
```

using the existing validated attachment path.

Do not create new source validation logic.

### Index Without Source

Although packet metadata lookup is possible index-only, initial `packet-info`
requires structured Summary.

Therefore index input without a valid source capture must:

- fail
- return non-zero
- not silently emit a degraded metadata-only report

Conceptual error:

```text
Packet inspection requires source capture data.
Use --source-capture <path> to attach the capture used to create this index.
```

## Settings

Support:

```text
--settings <settings.json>
```

for raw capture input only.

Reuse the exact current narrow CLI settings schema.

Grouping settings affect:

- canonical flows
- packet-in-flow membership
- flow-relative numbering

For index input:

- `--settings` is invalid

The CLI must not mix separately imported or regrouped state with an already
stored index.

## `--bytes`

Support one optional flag:

```text
--bytes
```

Default output:

- Flow Context
- Packet
- Summary

With `--bytes`:

- Flow Context
- Packet
- Summary
- Bytes

`--bytes` adds Bytes after Summary.

It does not replace Summary.

## Initial Bytes Scope

Initial v1 exposes exactly one byte view:

```text
complete captured packet bytes
```

Do not support:

- `--byte-view`
- `--list-byte-views`
- `--bytes-layer`

The authoritative byte view is the existing shared whole-captured-packet
presentation labeled:

```text
label:      Captured Packet
```

Its internal stable id may differ between normal protocol-aware presentations
and fallback-only presentations.

Use shared byte-presentation APIs.

Do not special-case Ethernet.

## Whole Captured Semantics

The intended semantics are:

```text
all captured bytes belonging to this packet
```

This remains true whether the capture packet contains:

- Ethernet II
- another supported link type
- malformed or truncated L2
- an unrecognized packet

Use the existing complete-capture fallback or root semantics.

Do not label the feature:

- Ethernet Bytes
- L2 Bytes

because not every capture uses ordinary Ethernet II.

## Bytes Presentation

Conceptual shape:

```text
Bytes

Captured Packet - 1514 bytes

00000000  ...
00000010  ...
...
```

Use the existing shared byte materialization and hex formatter:

- `materialize_selected_packet_byte_view(...)`
- `HexDumpService::format(...)`

Reuse the shared hex format:

- 8-digit hexadecimal offsets
- 16 bytes per row
- ASCII column
- current shared spacing

Do not add a separate CLI hex formatter.

Do not expose internal stable ids to the user in normal output.

## Bytes Size Policy

Print the full captured packet selected by the user.

Do not introduce in v1:

- arbitrary truncation
- pagination
- byte limits
- multiple views

The output is bounded by the captured length of one selected packet.

The user must request it explicitly with `--bytes`.

## Source Requirement For Bytes

Bytes use the same source-availability requirement as structured Summary.

Raw:

- available

Index + validated source:

- available

Index without source:

- unavailable, and `packet-info` already fails because Summary is mandatory

The CLI should not create a second separate source policy for `--bytes`.

## Global Lookup Architecture Note

Current capture-global lookup uses:

```text
CaptureSession::find_packet(packet_index)
```

and is not O(1).

It scans existing recognized packet refs or connections and then unrecognized
packet metadata.

This is an implementation characteristic, not a user-visible syntax issue.

The initial design does not introduce:

- a new persistent packet index
- a new packet-index-to-flow reverse index
- an index-format redesign

## Flow Membership For Global Selector

For a globally selected recognized packet, resolve Flow Context through
existing session ownership.

Do not infer flow membership by reparsing packet bytes.

If obtaining:

```text
Packet in Flow
```

requires a flow-local metadata walk after the owning flow is found, that is
acceptable for one-packet inspection.

## Partial Raw Capture

Preserve existing partial-open behavior.

`--packet-in-file N` may target a surfaced packet in the readable part of the
capture.

Flow-scoped selection may target a packet belonging to a surfaced canonical
flow.

Report only surfaced information.

Do not fabricate missing tail packets.

A packet beyond surfaced metadata is out of range.

If the selected surfaced packet's source bytes cannot be read, return a
runtime error.

## Progress

Support:

```text
--progress auto|on|off
```

Reuse normal input-open progress.

`auto` shows live progress only when `stderr` is an interactive terminal.

`on` forces live progress even when `stderr` is redirected.

`off` disables progress.

Do not introduce:

- packet lookup progress
- Summary progress
- byte-materialization progress

One-packet operations remain synchronous point inspection.

## stdout And stderr

Successful default output on `stdout`:

- heading
- Flow Context
- Packet
- Summary

With `--bytes`:

- heading
- Flow Context
- Packet
- Summary
- Bytes

`stderr`:

- input-open progress
- partial-open warnings
- source attachment and validation errors
- runtime errors

Do not print success chatter after the report.

## Help And Error Policy

Explicit:

```text
packet-info -h
packet-info --help
```

must:

- succeed
- require no input
- require no selectors
- require no source
- open nothing
- print packet-info-specific help to `stdout`

Syntax errors should print:

- a concise error
- packet-info-specific help

and return non-zero.

Runtime errors include:

- flow out of range
- packet-in-flow out of range
- packet-in-file out of range
- source unavailable
- source validation failure
- packet read failure

Runtime errors should print:

- a concise operational error only

and return non-zero.

## Raw, Index, And Source Matrix

| Capability | Raw | Index + source | Index without source |
| --- | --- | --- | --- |
| flow + packet-in-flow lookup | yes | yes | yes |
| packet-in-file recognized lookup | yes | yes | yes |
| packet-in-file unrecognized lookup | yes | yes | yes |
| Flow Context metadata | yes | yes | yes |
| basic Packet metadata | yes | yes | yes |
| structured Summary | yes | yes | no |
| whole captured packet materialization | yes | yes | no |
| successful packet-info | yes | yes | no |
| `--bytes` | yes | yes | no |
| `--source-capture` | no | yes | yes |

Index-only metadata lookup exists, but initial `packet-info` deliberately
requires structured Summary and therefore does not degrade to metadata-only
success.

## Performance

Intended implementation remains point-oriented.

Flow-scoped:

```text
flow index
    ->
packet-in-flow ordinal
    ->
PacketRef
    ->
source read
    ->
structured Summary
    ->
optional captured bytes
```

Global:

```text
packet-in-file
    ->
capture-global PacketRef lookup
    ->
optional owning flow/context lookup
    ->
source read
    ->
structured Summary
    ->
optional captured bytes
```

The implementation should not:

- scan source capture bytes sequentially to find the requested packet
- construct unrelated streams
- materialize all frontend packet DTOs
- parse unrelated packets
- duplicate byte buffers unnecessarily

Existing metadata lookup may currently be linear over retained packet refs.

That is acceptable for the initial release stage.

## Relationship To `flow-info`

`flow-info` owns:

- full flow identity
- flow traffic totals
- directional flow statistics
- packet-size histogram
- flow timing

`packet-info` repeats only the small amount of flow context needed to explain
how the selected packet belongs to the canonical flow:

- canonical endpoints
- direction
- flow number and packet-in-flow when globally selected

It must not embed the full `flow-info` report.

## Relationship To Bytes UI

The application may expose multiple protocol-aware byte views.

Initial CLI intentionally does not reproduce that full selector surface.

It exposes only:

```text
Captured Packet
```

with:

```text
--bytes
```

Future CLI work may add stable view selection using existing machine-stable
byte-view ids, but that syntax is intentionally undefined here.

## Relationship To Stream Inspection

The initial command does not include:

- stream packet lists
- Stream Item Summary
- Stream Item Data
- full stream reports

Packet Summary may retain existing bounded packet-contribution or
reassembly-derived information that is already part of normal selected-packet
Summary semantics.

The CLI must not add new stream processing for this command.

## Examples

Flow-scoped:

```text
pcap-flow-lab packet-info capture.pcap \
    --flow-number 11724 \
    --packet-in-flow 7
```

Flow-scoped with bytes:

```text
pcap-flow-lab packet-info capture.pcap \
    --flow-number 11724 \
    --packet-in-flow 7 \
    --bytes
```

Capture-global:

```text
pcap-flow-lab packet-info capture.pcap \
    --packet-in-file 2574112
```

Capture-global with bytes:

```text
pcap-flow-lab packet-info capture.pcap \
    --packet-in-file 2574112 \
    --bytes
```

Index with automatic source:

```text
pcap-flow-lab packet-info capture.idx \
    --packet-in-file 2574112
```

Index with explicit source:

```text
pcap-flow-lab packet-info capture.idx \
    --source-capture original.pcap \
    --flow-number 11724 \
    --packet-in-flow 7
```

## Intentionally Deferred

The following remain intentionally deferred:

- arbitrary byte-view selection
- `--byte-view`
- byte-view listing
- multiple byte views
- bytes truncation and pagination controls
- global packet search or filtering
- packet ranges
- multi-packet output
- `--format`
- JSON
- output files
- legacy Protocol Details
- stream item output
- full stream inspection
- persistent `packet_index -> flow` reverse-index optimization
- special SLL or SLL2 presentation expansion
