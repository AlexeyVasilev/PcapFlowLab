# `export-flows`

`export-flows` writes packet data to new classic PCAP files.

In the normal CLI workflow:

```text
summary
-> flows
-> export-flows
```

`flows` helps you find the canonical flow numbers you want. `export-flows`
then writes packet data for those selected flows. It also has a separate
unrecognized-packet mode for packets that were not assigned to a normal flow.

The examples below were captured from the 0.3.0 CLI using the repository
showcase raw capture and index. Shell-specific executable prefixes such as
`.\` are omitted.

## Export one complete flow

This is the most direct workflow: export one canonical flow as a single PCAP.

Command:

```text
pcap-flow-lab export-flows pcap_flow_lab_showcase.pcap --flow-number 1 --out flow_1_full.pcap
```

Verified output:

```text
Opening capture: 100% (728.9 KB / 728.9 KB)
Exporting packets: scanned 0 / 457, wrote 0 of 457.
Exporting packets: scanned 457 / 457, wrote 457 of 457.
Exported 1 flows to: flow_1_full.pcap
```

What happened here:

- `--flow-number 1` selected one canonical flow.
- No explicit packet-retention base mode was supplied.
- The CLI therefore used the effective default base mode:
  `--all-packets`.
- All `457` packets attributed to Flow 1 were written to one classic PCAP.

This is the best opening pattern when you already know the canonical flow
number and want a complete packet-level export.

## Create a bounded TLS sample

This is the most practical workflow when you want a smaller diagnostic sample
instead of full flows.

Command:

```text
pcap-flow-lab export-flows pcap_flow_lab_showcase.pcap --filter TLS --first-packets 30 --include-last-packet --out tls_sample.pcap
```

Verified output:

```text
Opening capture: 100% (728.9 KB / 728.9 KB)
Smart export: scanned 0 / 1 557 packets, wrote 0 of 103.
Smart export: scanned 1 557 / 1 557 packets, wrote 103 of 103.
Exported 5 flows to: tls_sample.pcap
```

The verified semantics for this workflow are:

- `--filter TLS` performs case-insensitive matching against the recognized-flow
  inventory and selected five showcase flows.
- `--first-packets 30` applies per selected flow, not globally.
- `--include-last-packet` is a per-flow modifier. It adds the final packet of
  each selected flow only when that packet was not already selected by the base
  retention rule.
- duplicate packet selection is suppressed.

This makes `export-flows` useful for "give me the beginning of each matching
flow, but keep the tail packet too" diagnostic sampling.

## Export one PCAP per flow

Use `--out-dir` when you want one output PCAP per selected flow instead of one
combined file.

Command:

```text
pcap-flow-lab export-flows showcase.idx --source-capture pcap_flow_lab_showcase.pcap --flow-numbers 1-3 --out-dir selected_flows
```

Verified output:

```text
Opening index: 100% (72.4 KB / 72.4 KB)
Preparing per-flow export: prepared 0 / 3 flows.
Preparing per-flow export: prepared 3 / 3 flows.
Writing per-flow export: scanned 0 / 1 525 packets, wrote 0.
Writing per-flow export: scanned 1 525 / 1 525 packets, wrote 1 003.
Exported 3 flows to: selected_flows
```

Generated directory contents:

```text
000001_tls_bulk_download_example_test_TCP_192.0.2.10_41000-198.51.100.10_443.pcap
000002_tls_gre_analysis_example_test_TCP_192.0.2.140_43000-198.51.100.140_443.pcap
000003_unknown_unknown_UDP_192.0.2.30_50000-198.51.100.30_7000.pcap
flows_manifest.csv
```

This mode creates:

- one classic PCAP per selected flow;
- deterministic descriptive file names;
- `flows_manifest.csv` with both source-flow totals and exported totals.

### Directory contents

Per-flow file names currently include:

- a zero-padded export flow id;
- normalized protocol text;
- normalized protocol-hint text;
- normalized transport text;
- source and destination addresses and ports.

User-relevant filename behavior:

- non-alphanumeric characters are normalized to underscores;
- address components preserve dots where possible;
- empty values fall back to `unknown`;
- components are truncated to keep names manageable.

### Manifest

Verified manifest header:

```text
flow_id,file_name,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,exported_packet_count,exported_captured_bytes,exported_original_bytes,protocol_path
```

Verified first row:

```text
1,000001_tls_bulk_download_example_test_TCP_192.0.2.10_41000-198.51.100.10_443.pcap,IPv4,TCP,tls,bulk-download.example.test,192.0.2.10,41000,198.51.100.10,443,457,250352,250352,1774182400.000000,1774182445.750000,45750000,457,250352,250352,"EthernetII->IPv4->TCP"
```

The important distinction is:

- `packet_count`, `captured_bytes`, `original_bytes` describe the full source
  flow as selected from the input.
- `exported_packet_count`, `exported_captured_bytes`,
  `exported_original_bytes` describe what was actually written for that flow.

In this verified all-packets example, the exported totals equal the source
totals because nothing was trimmed.

## Export from an index

Packet-export commands need packet bytes, not just flow metadata.

That is why the previous workflow used:

```text
--source-capture pcap_flow_lab_showcase.pcap
```

Current CLI behavior is:

- an index can provide the flow and packet metadata needed to select what to
  export;
- actual packet export still requires valid source packet bytes;
- if the index already points to an accessible source capture, export can work
  without an explicit `--source-capture`;
- if the source capture is missing or no longer accessible, export fails and
  asks you to re-run with `--source-capture <path>` or open the original
  capture directly;
- raw capture input rejects `--source-capture`.

`summary`, `flows`, and `flow-info` can work from index metadata alone.
`export-flows` is different because it writes packet bytes.

## Export unrecognized packets

Unrecognized-packet export is a separate selector mode.

Command:

```text
pcap-flow-lab export-flows pcap_flow_lab_showcase.pcap --unrecognized-packets --packet-limit 3 --out unrecognized_first_3.pcap
```

Verified output:

```text
Opening capture: 100% (728.9 KB / 728.9 KB)
Smart export: scanned 0 / 1 435 packets, wrote 0 of 3.
Smart export: scanned 1 435 / 1 435 packets, wrote 3 of 3.
Exported 3 unrecognized packets to: unrecognized_first_3.pcap
```

Important current rules:

- `--unrecognized-packets` is an alternative selector mode.
- It is mutually exclusive with all normal flow selectors.
- `--packet-limit` limits unrecognized packets, not flows.
- unrecognized mode requires `--out`;
- `--out-dir` is not allowed in unrecognized mode;
- packet-retention options such as `--first-packets`,
  `--first-original-bytes`, `--include-last-packet`, and
  `--every-kth-packet` are not allowed in unrecognized mode.

This makes the distinction between `--limit` and `--packet-limit` important:

- `--limit` trims how many recognized flows remain in scope;
- `--packet-limit` trims how many unrecognized packets are exported.

## Retain packets by byte budget

This workflow shows why `--first-original-bytes` needs careful reading.

Command:

```text
pcap-flow-lab export-flows pcap_flow_lab_showcase.pcap --flow-number 4 --first-original-bytes 25000 --out flow_4_first_25k.pcap
```

Verified output:

```text
Opening capture: 100% (728.9 KB / 728.9 KB)
Smart export: scanned 0 / 524 packets, wrote 0 of 3.
Smart export: scanned 524 / 524 packets, wrote 3 of 3.
Exported 1 flows to: flow_4_first_25k.pcap
```

The verified semantics are:

- `--first-original-bytes <N>` applies per selected flow.
- packets are selected in flow order until the cumulative original-byte count
  reaches or exceeds `N`;
- the packet that reaches or crosses the threshold is included;
- selection is packet-atomic, not byte-sliced.

That is why the verified Flow 4 example exported `3` packets for a
`25 000`-byte threshold: the first two packets alone were still below the
requested original-byte budget, so the third packet was included as the packet
that reached or crossed the threshold.

This option does **not** mean "write at most N bytes exactly".

## Packet retention strategies

`export-flows` has three base packet-retention modes and two modifiers.

| Option | Kind | Current semantics |
| --- | --- | --- |
| `--all-packets` | Base mode | Export every packet from each selected flow. |
| `--first-packets <N>` | Base mode | Export the first `N` packets of each selected flow. |
| `--first-original-bytes <N>` | Base mode | Export packets from each selected flow until cumulative original bytes reach or exceed `N`, including the packet that crosses the threshold. |
| `--include-last-packet` | Modifier | After a bounded base mode, also include the last packet of each selected flow if it was not already selected. |
| `--every-kth-packet <K>` | Modifier | After a bounded base mode, also include every K-th packet after that base prefix, per flow. |

### Exact combination rules

Current CLI rules are:

- exactly one effective base mode is used;
- `--all-packets`, `--first-packets`, and `--first-original-bytes` are
  mutually exclusive;
- if no base mode is supplied, the effective default is `--all-packets`;
- `--include-last-packet` and `--every-kth-packet` are valid only with
  `--first-packets` or `--first-original-bytes`;
- `--include-last-packet` and `--every-kth-packet` are invalid with
  `--all-packets`;
- duplicate packet selection is suppressed.

### `--first-packets`

`--first-packets <N>` is per selected flow, not global.

That means:

- one selected flow with `--first-packets 10` can export up to `10` base
  packets;
- five selected flows with `--first-packets 10` can export up to `50` base
  packets before modifiers such as `--include-last-packet`.

### `--include-last-packet`

`--include-last-packet` is also per selected flow.

Current behavior:

- if the flow's last packet is already inside the base selection, nothing extra
  is added;
- if it is not already selected, it is added once;
- the command never writes the same packet twice because duplicate selection is
  suppressed.

### `--every-kth-packet`

`--every-kth-packet <K>` is a per-flow modifier that starts counting after the
base prefix.

For example, after the bounded base selection ends:

- packet `K` after the base prefix is added;
- then packet `2K` after the base prefix;
- then packet `3K` after the base prefix;
- and so on while packets remain in that flow.

This makes it useful as a sparse "sample the remainder of each flow" modifier.

## Flow selection

Recognized-flow selection currently supports:

- `--flow-number <N>`
- `--flow-numbers <ranges>`
- `--filter <text>`
- `--all-flows`
- `--limit <N>`

### Selector semantics

Current CLI rules are:

- `--flow-number <N>` selects one positive one-based canonical flow number.
- `--flow-numbers <ranges>` selects inclusive one-based ranges such as
  `1-10,24,31-35`.
- `--flow-number` and `--flow-numbers` are mutually exclusive.
- `--all-flows` is mutually exclusive with explicit canonical-number
  selection.
- `--all-flows` is also mutually exclusive with `--filter`.
- `--filter` may be combined with explicit canonical-number selection.
- `--limit <N>` applies after flow selection and filtering.

The current recognized-flow selection pipeline is:

```text
explicit canonical selection (optional)
-> text filter (optional)
-> limit (optional)
```

### What `--filter` searches

Current CLI behavior is case-insensitive text matching across these
recognized-flow fields:

- IP family text;
- `Protocol`;
- `Detected Protocol`;
- `Service`;
- endpoint addresses;
- endpoint address-and-port strings;
- port numbers rendered as text.

It does **not** currently search the compact protocol-path presentation.

### `--limit`

`--limit <N>` limits flows, not packets.

It does not change packet-retention rules inside each selected flow. It only
reduces how many recognized flows remain in scope for export.

## Output modes

`export-flows` has two output modes for recognized-flow export.

### `--out`

`--out <path>` writes one classic PCAP containing the retained packets from the
entire selected flow set.

Current CLI behavior:

- output format is classic PCAP;
- retained packets are written in capture order;
- when multiple selected flows contribute packets, they are merged into that
  one output file in capture order.

### `--out-dir`

`--out-dir <path>` writes:

- one classic PCAP per selected flow;
- `flows_manifest.csv`.

Current CLI behavior:

- per-flow files are generated even when the output directory already exists
  and is empty;
- a non-empty existing directory is rejected unless `--force` is used;
- `--buffer-memory-mib` applies only to this mode.

## Other useful workflows

### Apply raw-capture import settings before exporting

`--settings <settings.json>` is valid only for raw capture input.

Use it when the canonical flow inventory itself can change under different
import/grouping settings. That matters because `export-flows` selects from the
resulting recognized-flow inventory.

For the accepted `settings.json` fields, defaults, and validation rules, see
[Capture processing settings](../reference/settings.md). For the detailed
grouping example, see [flows](flows.md).

### Control overwrite behavior

Use `--force` when:

- `--out` targets an existing file;
- `--out-dir` targets an existing non-empty directory.

Without `--force`, those cases are rejected.

### Control progress output

`--progress <auto|on|off>` controls whether progress lines are emitted.

Safe user-facing takeaway:

- `export-flows` reports progress while opening and exporting;
- different export modes use different progress wording.

The exact progress denominators are intentionally not explained here because
they vary by export path and are not the main thing you need for day-to-day
use.

### Tune per-flow export buffering

`--buffer-memory-mib <N>` is valid only with `--out-dir`.

Current user-relevant behavior:

- it affects the per-flow directory export path only;
- it changes buffering/resource usage, not export content;
- the CLI value is specified in MiB and must be a positive integer;
- if omitted, the underlying per-flow export path uses its built-in default
  buffer budget of `128 MiB`.

Most users should leave it alone unless they need to reduce or increase the
memory budget for a large per-flow directory export.

## Command reference

### Syntax

```text
pcap-flow-lab export-flows <input> [options]
pcap-flow-lab export-flows --input <input> [options]
```

Positional input and `--input` are mutually exclusive input forms.

### Supported inputs

- raw captures;
- Pcap Flow Lab indexes.

### Flow selection options

- `--flow-number <N>`
- `--flow-numbers <ranges>`
- `--filter <text>`
- `--all-flows`
- `--limit <N>`

### Unrecognized-packet selection

- `--unrecognized-packets`
- `--packet-limit <N>`

### Packet retention options

- `--all-packets`
- `--first-packets <N>`
- `--first-original-bytes <N>`
- `--include-last-packet`
- `--every-kth-packet <K>`

### Output options

- `--out <path>`
- `--out-dir <path>`
- `--buffer-memory-mib <N>`

### Input/import options

- `--input <path>`
- `--source-capture <path>`
- `--settings <settings.json>`

### Runtime options

- `--progress <auto|on|off>`
- `--force`
- `-h`
- `--help`

### Raw capture vs index

- raw capture input accepts `--settings`;
- raw capture input rejects `--source-capture`;
- index input can require `--source-capture` for packet export;
- index input rejects `--settings`.

## Invalid combinations and errors

The most important current invalid combinations are:

- no selector at all;
- both positional input and `--input`;
- `--out` together with `--out-dir`;
- `--unrecognized-packets` together with any flow selector;
- `--unrecognized-packets` together with `--limit`;
- `--unrecognized-packets` together with packet-retention options;
- `--unrecognized-packets` together with `--out-dir`;
- `--buffer-memory-mib` without `--out-dir`;
- `--include-last-packet` or `--every-kth-packet` without
  `--first-packets` or `--first-original-bytes`;
- output path equal to the input path;
- output file equal to the source capture;
- missing parent directory for `--out`;
- non-empty `--out-dir` without `--force`.

Common failure cases also include:

- no matched recognized flows;
- no unrecognized packets to export;
- missing or invalid source capture for index export;
- missing settings file;
- invalid settings JSON.

## Notes and limitations

- recognized-flow export and unrecognized-packet export are separate modes;
- unrecognized mode currently writes only one combined output PCAP;
- packet retention is packet-based, not byte-sliced;
- `--first-original-bytes` can legitimately export more than the requested byte
  threshold because the threshold-crossing packet is included whole;
- directory export produces machine-readable manifest metadata in addition to
  PCAP files.

## Related commands

- [summary](summary.md)
- [flows](flows.md)
- [flow-info](flow-info.md)
- [packet-info](packet-info.md)
