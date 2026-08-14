# `flow-info`

`flow-info` shows a detailed analysis report for exactly one canonical flow.

The normal CLI workflow is:

```text
summary
-> flows
-> flow-info
```

In practice, you usually:

- run `flows` to find the canonical `No.` you care about;
- then run `flow-info ... --flow-number N` to inspect that one flow in detail.

The examples below were captured from the 0.3.0 CLI using the repository
showcase raw capture. Shell-specific executable prefixes such as `.\` are
omitted.

## Analyze one flow

This is the most useful opening workflow because it shows the full report for a
large, clearly directional flow.

Command:

```text
pcap-flow-lab flow-info showcase.idx --flow-number 1
```

Verified output:

```text
Opening index: 100% (72.4 KB / 72.4 KB)
Flow 1

Identity
Endpoints: 192.0.2.10:41000 <-> 198.51.100.10:443
Family: IPv4
Protocol: TCP
Detected Protocol: TLS
Service: bulk-download.example.test
Protocol Path: EthernetII -> IPv4 -> TCP

Traffic
Packets: 457
Original Bytes: 244.5 KB
Captured Bytes: 244.5 KB
Max Captured Packet Size: 1.4 KB (1 459 B)

Direction
Metric             A->B    B->A  Total
Packets             142     315  457
Original Bytes  10.5 KB  234 KB  244.5 KB
Packet Direction: Mostly B->A
Data Direction: Mostly B->A

Packet Size Histogram
Bucket     All  A -> B  B -> A
0-63        84      82  2
64-127      55      54  1
128-255     62       6  56
256-511     52       0  52
512-1023   113       0  113
1024-1399   43       0  43
1400-1550   48       0  48
1551-2499    0       0  0
2500-5000    0       0  0
5001+        0       0  0

Timing
First Packet: 12:26:40.000000
Last Packet: 12:27:25.750000
Duration: 45.750 s
Largest Gap: 700.001 ms
```

This single report already tells you several practical things:

- the selected flow is a TCP flow with detected TLS traffic;
- the service metadata identifies `bulk-download.example.test`;
- the flow contains `457` packets and `244.5 KB` original bytes;
- the stored B side carries substantially more packets and bytes than the A
  side;
- the histogram is dominated by medium and large B->A packets;
- the flow lasts `45.750 s`;
- the largest observed gap between consecutive packets in the flow is about
  `700 ms`.

## Reading the report

The report is organized into five sections:

- `Identity`
- `Traffic`
- `Direction`
- `Packet Size Histogram`
- `Timing`

### Identity

`Identity` explains what flow you selected.

- `Endpoints` shows the stored endpoint pair for the flow.
- `Family` shows the IP family text associated with the flow.
- `Protocol` shows the transport/network protocol category reported by the CLI.
- `Detected Protocol` shows a higher-level detected classification when one is
  available.
- `Service` shows protocol-derived service or descriptive metadata when one is
  available.
- `Protocol Path` shows the full human-readable protocol path for that flow.

In the opening example, the flow is:

- IPv4;
- TCP at the protocol-category level;
- detected as TLS;
- associated with `bulk-download.example.test`;
- represented by the path `EthernetII -> IPv4 -> TCP`.

`Protocol` and `Detected Protocol` are intentionally separate:

- `Protocol` is the transport/network category carried by the flow;
- `Detected Protocol` is a higher-level classification inferred for that flow
  when available.

### Traffic

`Traffic` gives the whole-flow totals.

- `Packets` is the number of packets attributed to the flow.
- `Original Bytes` is the sum of packet original lengths attributed to the
  flow.
- `Captured Bytes` is the sum of packet captured lengths attributed to the
  flow.
- `Max Captured Packet Size` is the largest captured packet length seen in the
  flow.

In the opening example, `Original Bytes` and `Captured Bytes` are equal, which
means the packets contributing to this flow were captured at full length under
current product semantics.

### Direction

`Direction` splits the same flow totals across the two stored endpoint sides:

- `A->B`
- `B->A`

These labels refer to the flow's stored/oriented endpoint sides. They are safe
to read as:

- packets or bytes sent from Endpoint A toward Endpoint B;
- packets or bytes sent from Endpoint B toward Endpoint A.

They should **not** be read as guaranteed client/server or request/response
roles.

The table shows:

- directional packet counts;
- directional original-byte totals;
- the corresponding totals across both directions.

The two summary lines are derived separately:

- `Packet Direction` is classified from directional packet counts;
- `Data Direction` is classified from directional original-byte totals.

The CLI uses three qualitative labels:

- `Balanced`
- `Mostly A->B`
- `Mostly B->A`

The current classification rule is simple:

- if one side has more than twice the packets or bytes of the other, the report
  says `Mostly ...`;
- otherwise it says `Balanced`;
- special zero-only cases are also mapped to the corresponding `Mostly ...` or
  `Balanced` label.

In the opening example:

- packet counts are `142` vs `315`, so `Packet Direction` is `Mostly B->A`;
- original-byte totals are `10.5 KB` vs `234 KB`, so `Data Direction` is also
  `Mostly B->A`.

### Packet Size Histogram

`Packet Size Histogram` shows the packet-length shape of the flow.

Important current semantics:

- the histogram buckets **original packet sizes**, not captured packet sizes;
- the bucket set is fixed for every flow;
- rows are shown even when the counts are zero.

Current fixed bucket labels are:

- `0-63`
- `64-127`
- `128-255`
- `256-511`
- `512-1023`
- `1024-1399`
- `1400-1550`
- `1551-2499`
- `2500-5000`
- `5001+`

The columns mean:

- `All`: total packets in that size bucket;
- `A -> B`: packets in that bucket traveling from Endpoint A to Endpoint B;
- `B -> A`: packets in that bucket traveling from Endpoint B to Endpoint A.

Because the bucket set is always fixed, zero rows are useful rather than
noise: they make it easier to compare the shape of two different flows.

### Timing

`Timing` describes when the flow occurred inside the capture timeline.

- `First Packet` is the formatted timestamp of the earliest packet in the flow.
- `Last Packet` is the formatted timestamp of the latest packet in the flow.
- `Duration` is the difference between those two timestamps.
- `Largest Gap` is the largest observed gap between consecutive packets in the
  time-ordered flow.

The displayed times are formatted capture timestamps in `HH:MM:SS.ffffff`
form. They are not documented here as timezone-aware wall-clock values.

## Inspect a nested protocol path

The next example shows why `flow-info` is a useful follow-up to `flows` even
when you already know the flow number.

Command:

```text
pcap-flow-lab flow-info showcase.idx --flow-number 2
```

Verified excerpt:

```text
Flow 2

Identity
Endpoints: 192.0.2.140:43000 <-> 198.51.100.140:443
Family: IPv4
Protocol: TCP
Detected Protocol: TLS
Service: gre-analysis.example.test
Protocol Path: EthernetII -> VLAN(vid=320) -> MPLS(label=16010) -> MPLS(label=16011) -> IPv4 -> GRE -> IPv4 -> TCP

Traffic
Packets: 226
Original Bytes: 121.7 KB
Captured Bytes: 121.7 KB
Max Captured Packet Size: 1.3 KB (1 347 B)

Direction
Metric            A->B      B->A  Total
Packets             65       161  226
Original Bytes  7.1 KB  114.6 KB  121.7 KB
Packet Direction: Mostly B->A
Data Direction: Mostly B->A

...

Timing
First Packet: 12:27:00.000000
Last Packet: 12:27:49.080000
Duration: 49.080 s
Largest Gap: 5.675 s
```

Here `...` marks documentation truncation rather than literal CLI output.

This example is most useful for the `Protocol Path` line.

Compared with the compact `Path` column from `flows`, `flow-info` shows the
full human-readable path, including identifiers such as:

- `VLAN(vid=320)`
- `MPLS(label=16010)`
- `MPLS(label=16011)`
- `GRE`

That makes `flow-info` the better tool when you want to inspect the exact
layering and identifying path metadata for one selected flow.

## Understand unusual packet-size distributions

The next example is intentionally different from the TLS-heavy flows above.

Command:

```text
pcap-flow-lab flow-info showcase.idx --flow-number 4
```

Verified output:

```text
Flow 4

Identity
Endpoints: 192.0.2.202:52002 <-> 198.51.100.202:9202
Family: IPv4
Protocol: UDP
Detected Protocol:
Service: -
Protocol Path: EthernetII -> IPv4 -> UDP

Traffic
Packets: 4
Original Bytes: 90 KB
Captured Bytes: 90 KB
Max Captured Packet Size: 58.6 KB (60 000 B)

Direction
Metric             A->B     B->A  Total
Packets               2        2  4
Original Bytes  19.7 KB  70.3 KB  90 KB
Packet Direction: Balanced
Data Direction: Mostly B->A

Packet Size Histogram
Bucket     All  A -> B  B -> A
0-63         0       0  0
64-127       0       0  0
128-255      1       1  0
256-511      0       0  0
512-1023     0       0  0
1024-1399    0       0  0
1400-1550    0       0  0
1551-2499    0       0  0
2500-5000    0       0  0
5001+        3       1  2

Timing
First Packet: 12:27:05.700000
Last Packet: 12:27:06.380000
Duration: 680.000 ms
Largest Gap: 310.000 ms
```

This example is useful because it shows structure that a single total would
hide:

- the flow has only `4` packets;
- it still accounts for `90 KB`;
- the largest captured packet is `60 000 B`;
- three packets land in the `5001+` bucket;
- packet direction is `Balanced` because the packet counts are `2` vs `2`;
- data direction is `Mostly B->A` because the original-byte totals are heavily
  skewed toward B->A.

It is also the clearest verified example of missing higher-level metadata:

- `Detected Protocol:` renders as an empty value when no higher-level detection
  is available;
- `Service: -` renders a dash when service metadata is unavailable.

## How import settings affect flow identity

Like `flows`, `flow-info` treats raw-capture import settings as import
semantics, not just display preferences.

For the accepted `settings.json` fields, defaults, and validation rules, see
[Capture processing settings](../reference/settings.md).

Command:

```text
pcap-flow-lab flow-info --input pcap_flow_lab_showcase.pcap --flow-number 2 --settings settings.json
```

The verified settings file for this run was:

```json
{
  "ignore_vlan_and_mpls_layers_when_grouping_flows": true,
  "ignore_gtpu_teids_when_grouping_inner_flows": true,
  "validate_selected_packet_checksums": false
}
```

Verified excerpt:

```text
Flow 2

Identity
Endpoints: 192.0.2.140:43000 <-> 198.51.100.140:443
Family: IPv4
Protocol: TCP
Detected Protocol: TLS
Service: gre-analysis.example.test
Protocol Path: EthernetII -> IPv4 -> GRE -> IPv4 -> TCP

Traffic
Packets: 226
Original Bytes: 121.7 KB
Captured Bytes: 121.7 KB
Max Captured Packet Size: 1.3 KB (1 347 B)

Direction
Metric            A->B      B->A  Total
Packets             65       161  226
Original Bytes  7.1 KB  114.6 KB  121.7 KB
Packet Direction: Mostly B->A
Data Direction: Mostly B->A

...

Duration: 49.080 s
Largest Gap: 5.675 s
```

Compared with the index-backed Flow 2 example above, the important difference
is the path identity:

Index-backed Flow 2:

```text
EthernetII -> VLAN(vid=320) -> MPLS(label=16010) -> MPLS(label=16011) -> IPv4 -> GRE -> IPv4 -> TCP
```

Raw import with grouping settings:

```text
EthernetII -> IPv4 -> GRE -> IPv4 -> TCP
```

At the same time, this verified example keeps the same:

- `226` packets;
- `121.7 KB`;
- directional totals;
- timing values.

The safe way to interpret this is:

- `--settings` applies during raw capture import;
- grouping-related settings can change the imported canonical flow inventory and
  the resulting flow identity/path presentation;
- `--flow-number 2` therefore means flow 2 in **that** imported inventory;
- canonical flow numbers should not be treated as globally stable across
  differently grouped imports.

For index input, this does not apply the same way:

- the index already contains its stored flow inventory;
- raw-import settings are not reapplied;
- `--settings` is invalid for index input.

## Other useful workflows

Use explicit `--input` form if you prefer it:

```text
pcap-flow-lab flow-info --input showcase.idx --flow-number 1
```

Control progress reporting:

```text
pcap-flow-lab flow-info showcase.idx --flow-number 1 --progress auto
pcap-flow-lab flow-info showcase.idx --flow-number 1 --progress on
pcap-flow-lab flow-info showcase.idx --flow-number 1 --progress off
```

## Command reference

### Syntax

Supported forms:

```text
pcap-flow-lab flow-info <input> --flow-number <N> [options]
pcap-flow-lab flow-info --input <input> --flow-number <N> [options]
```

Help:

```text
pcap-flow-lab flow-info --help
pcap-flow-lab flow-info -h
```

### Supported inputs

`flow-info` accepts:

- PCAP captures;
- PCAPNG captures;
- Pcap Flow Lab indexes.

You can provide the input either:

- as a positional path;
- or with `--input <path>`.

These forms are mutually exclusive.

### Selection

`flow-info` requires exactly one:

```text
--flow-number <N>
```

This is a one-based canonical flow number within the specific imported or
indexed flow inventory currently being opened.

The normal discovery workflow is:

```text
pcap-flow-lab flows ...
-> identify No.
-> pcap-flow-lab flow-info ... --flow-number N
```

### Options

| Option | Value | Description |
| --- | --- | --- |
| `--input` | `<path>` | Provide the input path explicitly instead of using a positional path. |
| `--flow-number` | `<N>` | Select exactly one one-based canonical flow. |
| `--settings` | `<settings.json>` | Apply supported raw-import settings during raw capture import. Invalid for index input. |
| `--progress` | `auto`, `on`, `off` | Control live open-progress reporting on `stderr`. |
| `-h`, `--help` | none | Show flow-info-specific help and exit successfully. |

### Raw capture vs index

| Capability | Raw capture | Index |
| --- | --- | --- |
| Analyze one canonical flow | Yes | Yes |
| `--settings` | Yes | No |
| `--progress` | Yes | Yes |
| Uses stored flow inventory already present in input | No, inventory is built during import | Yes |
| Requires source packet bytes for this report | No | No |

Verified behavior shows that index-backed `flow-info` can render the
same report without needing source-capture bytes.

## Invalid combinations and errors

Important verified rules:

- an input path is required;
- exactly one `--flow-number` is required;
- positional input and `--input` cannot be combined;
- `--settings` is valid only for raw capture input.

`flow-info` intentionally does **not** accept the flow-list style selectors and
table options from other commands, including:

- `--flow-numbers`
- `--filter`
- `--sort`
- `--limit`
- `--packets-in-flow`
- `--packets-in-file`
- `--source-capture`
- `--format`
- `--columns`
- `--out`

Out-of-range flow numbers fail instead of being silently ignored. Current CLI
wording reports:

```text
Flow N is out of range for this input.
```

## Notes and limitations

`flow-info` is intentionally focused on one selected canonical flow.

It does not:

- discover flows for you;
- select multiple canonical flows;
- filter the whole flow inventory;
- sort the whole flow inventory;
- export packet data.

If you need to find the right canonical flow first, use `flows`.

If you need packet-level inspection, use `packet-info`.

If you need packet export, use `export-flows`.

Progress and warnings are written to `stderr`. The flow analysis report itself
is written to `stdout`.

## Related commands

The most relevant companion commands are:

- `summary` for whole-input overview;
- `flows` for listing and selecting canonical flows;
- `packet-info` for packet-level inspection;
- `export-flows` for packet export workflows.
