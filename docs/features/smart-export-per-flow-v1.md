# Smart Export Per-Flow v1

## Goal

Add a second output mode to Smart Export:

- Single output file
- Separate file per flow

The new mode reuses Smart Export v1 packet-selection rules, but writes one output file per user-visible bidirectional flow plus a manifest CSV.

## Flow semantics

- One exported per-flow file corresponds to one user-visible bidirectional flow.
- Packets from both `A->B` and `B->A` must go into the same file.
- Do NOT split directions into separate files.
- Packets inside each exported file must remain in original capture order.

## UI placement

This mode lives inside the existing Smart Export dialog.

### Output mode

- Single output file
- Separate file per flow

### Behavior

- Single output file behaves like current Smart Export v1.
- Separate file per flow writes one file per chosen bidirectional flow, requires a destination folder, and also writes `flows_manifest.csv`.

## Shared packet-selection policy

Separate-file mode reuses the same Smart Export v1 rules.

### Flows to export

Exactly one radio choice:

- Current flow
- Selected flows
- Unselected flows
- All flows

### Base packet selection

Exactly one radio choice:

- All packets
- First N packets
- First M original bytes

### Base-rule semantics

- All packets: export all packets from the chosen flows.
- First N packets: export the first `N` packets of each chosen flow.
- First M original bytes:
  - accumulate original packet length
  - walk packets in flow order
  - include packets until the threshold is reached
  - include the packet that crosses the threshold

### Additional packet retention

Optional checkboxes:

- Include last packet
- Include every K-th packet after the base prefix

### Additional-rule semantics

- Include last packet: include the last packet even if it was not already selected by the base rule.
- Include every K-th packet after the base prefix:
  - applies only after the base prefix ends
  - adds sparse packets later in the flow

### Base mode = All packets

If base mode is All packets, additional retention options should be disabled in the UI.

## Final packet-inclusion semantics

For each chosen flow, a packet is exported if it matches:

- the base rule
- OR Include last packet
- OR Include every K-th packet after the base prefix

A packet must never be exported more than once.

Do NOT implement this by building duplicate packet lists and deduplicating later.

## Output artifacts

- One output PCAP per exported user-visible bidirectional flow
- One `flows_manifest.csv` written into the destination folder

## Filename scheme

Generated file names must:

- include `flow_id` first
- include protocol, hint, transport, and endpoints in sanitized form
- sanitize invalid filesystem characters
- support IPv6-safe sanitization
- avoid user-configurable naming templates in v1

Example shape:
`000001_tls_google.com_TCP_10.10.123.123_54321-123.123.123.123_443.pcap`

Rules:

- `flow_id` must always be first
- invalid filesystem characters must be removed or normalized
- empty components become `unknown`
- very long components may be trimmed
- IPv6 addresses must be sanitized so raw `:` does not remain in file names

## Manifest CSV

The manifest should contain at least:

- `flow_id`
- `file_name`
- `family`
- `transport`
- `protocol`
- `protocol_hint`
- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `packet_count`
- `captured_bytes`
- `original_bytes`
- `first_timestamp`
- `last_timestamp`
- `duration_us`

Strongly recommended additional fields:

- `exported_packet_count`
- `exported_captured_bytes`
- `exported_original_bytes`

## Performance model

The per-flow mode must scale better on large captures and large flow counts.

It must avoid:

- opening one output file handle per flow for the whole export
- rescanning the source capture once per flow
- sorting giant packet lists
- building duplicate-prone packet arrays
- unbounded memory growth

## Packet ownership model

For Separate file per flow mode, always use:

- `std::vector<uint32_t> packet_owner`

Semantics:

- `0` = packet is not exported
- `1..N` = packet belongs to exported flow file with that export-flow id

Keep current single-file Smart Export behavior unchanged:

- single-file mode continues using the existing `uint8_t` marker-array approach

## Required high-level algorithm

1. Choose flows.
2. Assign export-flow ids.
3. For each chosen flow, iterate its ordered packet refs once and, for selected packets, set `packet_owner[packet_index] = export_flow_id`.
4. Perform one final sequential pass over the source capture.
5. If `packet_owner[packet_index] == 0`, skip.
6. Otherwise append the packet to that flow's per-flow output pipeline.

This must preserve original capture order inside each exported file and avoid rescanning the source capture per flow.

## Buffered output design

Per-flow mode must not keep one output file open per flow for the entire export.

Instead, use:

- a shared pool of fixed-size resident buffer slots
- plus a small bounded open-file-handle cache

Per-flow mode must not use one dynamically growing per-flow buffer under only a global byte cap.

## Shared fixed-size buffer pool

Per-flow output must use:

- a shared pool of fixed-size buffer slots
- not one dynamically growing per-flow buffer per exported flow

## Buffer size

Use a fixed buffer size of:

- `32 KB` per buffer slot

## Buffer memory budget

When Separate file per flow is selected, the dialog must also show:

- destination folder
- note that `flows_manifest.csv` will also be written
- Buffer memory budget

UI form:

- numeric field in MB

Default:

- `128 MB`

Validation:

- minimum `1 MB`

This budget determines the number of resident buffer slots.

Formula:

- `buffer_count = floor(memory_budget_bytes / 32 KB)`
- ensure at least one buffer slot exists

## Per-flow buffer state

Distinguish clearly between:

1. lightweight flow state objects:
   - one per exported flow
2. resident data buffers:
   - only as many as fit in the fixed-size pool

A flow may exist without currently owning a resident buffer slot.

Each exported flow should have a lightweight state object containing at least:

- `export_flow_id`
- output path
- whether the file has already been initialized
- current resident buffer slot ownership, if any
- exported packet counters
- exported byte counters

Each resident buffer slot should keep its own LRU bookkeeping.

## Buffer contents

Each resident buffer slot should store:

- already serialized output bytes for packet records

Do NOT store:

- packet refs
- high-level temporary export structures

## Buffer-slot ownership

Each resident buffer slot can belong to at most one flow at a time.

A flow may have:

- one current buffer slot
- or no current buffer slot

## Buffer eviction policy

Use LRU across resident buffer slots.

Evict when:

- a flow needs a buffer slot and none are free

Eviction action:

- select the least-recently-used slot
- flush its contents to file
- detach it from its old flow
- reassign it to the new flow

## Open file handle cache

Use a small bounded cache of open output file handles in addition to the memory buffers.

Default limit:

- `64` open file handles

Required behavior:

- keep only a limited number of file handles open at once
- use LRU or a similarly simple policy
- when the limit is exceeded:
  - close the least-recently-used open file handle

## File initialization and append semantics

For each per-flow file:

First write:

- create the file
- write the global PCAP header
- append buffered packet-record bytes

Later writes:

- reopen in append mode if needed
- append only packet-record bytes
- do not rewrite the global PCAP header

## Oversized packet rule

If one serialized packet record is larger than the fixed buffer size:

- flush that flow's current buffer first
- write the oversized packet directly to the destination file
- do not require the oversized packet to fit inside a resident buffer slot

## Manifest robustness

- manifest creation failure must be reported explicitly
- manifest must not silently disappear
- manifest writing must not depend on keeping all output files open
- if export fails after partial output creation, the user should still get a meaningful reason

## Progress reporting

Separate-file export can be long-running and must expose progress.

Preferred progress basis:

- source packet scan progress

Suggested visible progress:

- progress bar
- optionally processed packets / total packets

## Error reporting

Do not collapse all failures into a generic message.

Prefer more specific failure reasons where practical, such as:

- failed to create destination folder
- failed to create manifest
- failed to open output file
- failed to append to output file
- source read failure
- export interrupted by internal ownership/state error

## What must NOT be done

Do not:

- open one output writer per flow for the whole export
- rescan the source capture once per flow
- export in per-flow source-read passes
- build a giant duplicate-prone packet list and sort it later
- split one bidirectional flow into two files
- add protocol-specific policies in this pass
- add time-based activity rules in this pass
- add filename-template editing in this pass
- add archive/zip output modes in this pass

## Scope boundary

This pass is intentionally limited to:

- shared Smart Export selection policy
- separate file per bidirectional user-visible flow
- manifest CSV
- bounded buffered output
- bounded open-file-handle cache
- one linear source pass
- clearer progress reporting
- clearer failure reporting

Anything more advanced belongs to a later version.
