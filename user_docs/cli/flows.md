# `flows`

`flows` lists the canonical flow inventory for a capture or a Pcap Flow Lab
index. In practice it is usually the next CLI step after `summary`:

- `summary` tells you what is in the input as a whole;
- `flows` lets you inspect, filter, rank, select, and export the recognized
  flow list.

The examples below were captured from the 0.3.0 CLI using the repository
showcase raw capture. Shell-specific executable prefixes such as `.\` are
omitted.

## List flows from an index

This is the best starting workflow when you already have an index and want to
see the flow inventory.

Command:

```text
pcap-flow-lab flows showcase.idx --limit 12
```

Verified output:

```text
Opening index: 100% (72.4 KB / 72.4 KB)
Flows

No.  Endpoint A                                       Endpoint B                                      Protocol  Detected Protocol  Service                      Path                        Packets  Original Bytes
  1  192.0.2.10:41000                                 198.51.100.10:443                               TCP       TLS                bulk-download.example.test   EII|Ip4|TCP                     457  244.5 KB
  2  192.0.2.140:43000                                198.51.100.140:443                              TCP       TLS                gre-analysis.example.test    EII|Vl|M|M|Ip4|GRE|Ip4|TCP      226  121.7 KB
  3  192.0.2.30:50000                                 198.51.100.30:7000                              UDP                                                       EII|Vl|Ip4|UDP                  320  104.5 KB
  4  192.0.2.202:52002                                198.51.100.202:9202                             UDP                                                       EII|Ip4|UDP                       4  90 KB
  5  [2001:0db8:0010:0000:0000:0000:0000:0010]:42000  [2001:0db8:0020:0000:0000:0000:0000:0020]:9000  TCP                                                       EII|Ip6|TCP                     284  46.2 KB
  6  192.0.2.180:48180                                198.51.100.180:80                               TCP       HTTP               large-http.example.test      EII|Ip4|TCP                      26  21.2 KB
  7  192.0.2.44:44024                                 198.51.100.44:443                               TCP       TLS                                             EII|Ip4|TCP                      32  15 KB
  8  192.0.2.72:55070                                 198.51.100.72:443                               UDP       QUIC               web.whatsapp.com             EII|Ip4|UDP                      23  12.3 KB
  9  192.0.2.70:55070                                 198.51.100.70:443                               UDP       QUIC               www.youtube.com              EII|Ip4|UDP                      17  11.8 KB
 10  192.0.2.73:55070                                 198.51.100.73:443                               UDP       QUIC               ep2.adtrafficquality.google  EII|Ip4|UDP                      16  11.7 KB
 11  192.0.2.201:52001                                198.51.100.201:9201                             UDP                                                       EII|Ip4|UDP                       3  8.9 KB
 12  192.0.2.200:52000                                198.51.100.200:9200                             UDP                                                       EII|Ip4|UDP                       4  5.1 KB

Showing 12 of 58 flows.
```

The flow table is designed for quick inventory work:

- `No.` is the one-based canonical flow number.
- `Endpoint A` and `Endpoint B` are the oriented flow endpoints stored for the
  flow.
- `Protocol` is the flow transport/network protocol category shown by the CLI.
- `Detected Protocol` is a higher-level detected classification when one is
  available.
- `Service` is protocol-derived user-facing service or description metadata
  when one is available.
- `Path` is the compact Protocol Path representation for that flow.
- `Packets` is the packet count attributed to the flow.
- `Original Bytes` is the original byte total attributed to the flow.

The canonical flow number matters because other commands such as `flow-info`
and `packet-info` use it to identify one flow within the current flow
inventory.

## Filter and rank matching flows

Once you know the inventory exists, the next common step is narrowing it down
and ranking the matches.

Command:

```text
pcap-flow-lab flows showcase.idx --filter TLS --sort bytes:desc
```

Verified output:

```text
Opening index: 100% (72.4 KB / 72.4 KB)
Flows

No.  Endpoint A         Endpoint B            Protocol  Detected Protocol  Service                     Path                        Packets  Original Bytes
  1  192.0.2.10:41000   198.51.100.10:443     TCP       TLS                bulk-download.example.test  EII|Ip4|TCP                     457  244.5 KB
  2  192.0.2.140:43000  198.51.100.140:443    TCP       TLS                gre-analysis.example.test   EII|Vl|M|M|Ip4|GRE|Ip4|TCP      226  121.7 KB
  7  192.0.2.44:44024   198.51.100.44:443     TCP       TLS                                            EII|Ip4|TCP                      32  15 KB
 18  192.0.2.42:44020   198.51.100.42:443     TCP       TLS                tls-mini.example.test       EII|Ip4|TCP                       9  630 B
 31  3.223.63.250:443   192.168.20.251:42644  TCP       TLS                                            EII|Vl|Ip4|TCP                    1  166 B
```

This is a practical workflow:

```text
find relevant flows
-> rank the matching flows by byte volume
```

In the verified showcase output, five flows match and are ordered from
`244.5 KB` down to `166 B`.

### What `--filter` actually searches

Current CLI behavior is case-insensitive text matching across these
user-visible flow fields:

- IP family text;
- `Protocol`;
- `Detected Protocol`;
- `Service`;
- endpoint addresses;
- endpoint address-and-port strings;
- individual port numbers rendered as text.

In other words, `--filter` can match things like:

- `TLS`
- `HTTP`
- `mDNS`
- `198.51.100.44`
- `:443`
- a full endpoint string such as `192.0.2.10:41000`

It does **not** currently search the compact `Path` column.

## Find the busiest flows

Filtering and sorting solve different problems.

- filtering decides which flows remain in scope;
- sorting decides how the remaining flows are ordered.

If you simply want the busiest flows, sort by packet count and cap the visible
result.

Command:

```text
pcap-flow-lab flows showcase.idx --sort packets:desc --limit 10
```

Verified excerpt:

```text
No.  Endpoint A                                       Endpoint B                                      Protocol  Detected Protocol  Service                      Path                        Packets  Original Bytes
  1  192.0.2.10:41000                                 198.51.100.10:443                               TCP       TLS                bulk-download.example.test   EII|Ip4|TCP                     457  244.5 KB
  3  192.0.2.30:50000                                 198.51.100.30:7000                              UDP                                                       EII|Vl|Ip4|UDP                  320  104.5 KB
  5  [2001:0db8:0010:0000:0000:0000:0000:0010]:42000  [2001:0db8:0020:0000:0000:0000:0000:0020]:9000  TCP                                                       EII|Ip6|TCP                     284  46.2 KB
  2  192.0.2.140:43000                                198.51.100.140:443                              TCP       TLS                gre-analysis.example.test    EII|Vl|M|M|Ip4|GRE|Ip4|TCP      226  121.7 KB
  7  192.0.2.44:44024                                 198.51.100.44:443                               TCP       TLS                                             EII|Ip4|TCP                      32  15 KB
  ...
 15  192.0.2.40:44000                                 198.51.100.40:80                                TCP       HTTP               http.example.test            EII|Ip4|TCP                      16  1.1 KB

Showing 10 of 58 flows.
```

Here `...` marks documentation truncation rather than literal CLI output.

This example is useful because it separates two ideas cleanly:

- `--sort packets:desc` ranks flows by packet count;
- `--limit 10` trims the logical result to the first ten rows after sorting.

## Select flows by canonical number

If you already know the flows you want, you can select them directly by their
canonical flow numbers.

Command:

```text
pcap-flow-lab flows showcase.idx --flow-numbers 1-10,24,31-35 --sort number:asc --out-flows-list selected_flows.csv
```

Verified facts for this run:

- stdout contains canonical flow numbers `1-10`, `24`, and `31-35`;
- they are displayed in ascending canonical-number order;
- the selection covers multiple protocol families, including HTTP, TLS, QUIC,
  BitTorrent, STUN, IPv6, and nested VXLAN traffic;
- the CLI reports:

```text
Flows list written to: selected_flows.csv
```

### Selection rules

Current production rules are:

- `--flow-number <N>` selects exactly one one-based canonical flow number;
- `--flow-numbers <ranges>` accepts inclusive ranges and comma-separated values
  such as `1-10,24,31-35`;
- `--flow-number` and `--flow-numbers` are mutually exclusive;
- `--flow-number` or `--flow-numbers` may still be combined with `--filter`,
  `--sort`, and `--limit`.

The selection pipeline is:

```text
explicit canonical selection
-> text filter
-> sort
-> limit
```

That matters when you combine options. For example, a selected canonical subset
can still be filtered down further before sorting and limiting.

## Export a flow list

`--out-flows-list <path>` writes a CSV of the final logical flow result.

For `flows`, that means the exported CSV follows the same selection pipeline as
the command result itself:

```text
explicit canonical selection (if any)
-> filter (if any)
-> sort (if any)
-> limit (if any)
-> export
```

Important consequences from the verified command behavior:

- without an explicit `--limit`, stdout may show only the default 25-row
  preview while the CSV still contains the full matching result;
- with an explicit `--limit`, both stdout and CSV are constrained to the same
  limited result set;
- with no matches, the CSV still writes the header row;
- existing files are not overwritten unless `--force` is supplied.

This is different from `summary --out-flows-list`, which always exports the
complete whole-input flow inventory because `summary` has no flow filtering or
selection stage.

## How import settings affect the flow inventory

This is the most important non-obvious `flows` behavior for raw capture input.

`--settings` is **not** just a display preference here. When the input is a raw
capture, the settings file is applied during import, and the grouping settings
can change the flow inventory itself.

For the accepted `settings.json` fields, defaults, and validation rules, see
[Capture processing settings](../reference/settings.md).

### Baseline grouping

With the grouping-related settings left at their default `false` values, the
following workflow reported `58` flows:

```text
pcap-flow-lab flows --input pcap_flow_lab_showcase.pcap --settings settings.json --sort service:desc --limit 15
```

Observed result:

```text
Showing 15 of 58 flows.
```

One important GRE-related row appeared as:

```text
No. 2
192.0.2.140:43000 -> 198.51.100.140:443
TCP
TLS
gre-analysis.example.test
EII|Vl|M|M|Ip4|GRE|Ip4|TCP
226 packets
121.7 KB
```

### Relaxed grouping configuration

The settings file was then changed to:

```json
{
  "ignore_vlan_and_mpls_layers_when_grouping_flows": true,
  "ignore_gtpu_teids_when_grouping_inner_flows": true,
  "validate_selected_packet_checksums": false
}
```

Running the same raw-capture workflow then reported `55` flows instead of `58`:

```text
Showing 15 of 55 flows.
```

The corresponding GRE-related row appeared as:

```text
No. 2
192.0.2.140:43000 -> 198.51.100.140:443
TCP
TLS
gre-analysis.example.test
EII|Ip4|GRE|Ip4|TCP
226 packets
121.7 KB
```

### What this means

The practical meaning is:

- `--settings` is applied while importing a raw capture;
- grouping-related settings can change which packets are considered part of the
  same flow inventory;
- that can change the number of canonical flows;
- it can also change canonical flow numbers;
- and it can change the compact Path presentation associated with the grouped
  flow.

In the verified example, the GRE flow's displayed Path changed from:

```text
EII|Vl|M|M|Ip4|GRE|Ip4|TCP
```

to:

```text
EII|Ip4|GRE|Ip4|TCP
```

Documented carefully, this means the grouping settings can affect the stored
flow identity and the resulting flow-path presentation that `flows` renders for
that grouped result. It should not be read as a general-purpose Path rendering
toggle independent of import semantics.

Because canonical flow numbers come from the imported or indexed flow
inventory, you should always interpret a number such as `42` within the
specific inventory that produced it.

### Raw capture versus index

Existing indexes behave differently.

If you run `flows` against an index:

- the index already represents the grouping decisions used when it was created;
- raw-import settings are not reapplied;
- `--settings` is invalid for index input.

## Other useful workflows

Open the same command with explicit `--input` form:

```text
pcap-flow-lab flows --input showcase.idx
```

Control live progress reporting:

```text
pcap-flow-lab flows showcase.idx --progress auto
pcap-flow-lab flows showcase.idx --progress on
pcap-flow-lab flows showcase.idx --progress off
```

Replace an existing CSV intentionally:

```text
pcap-flow-lab flows showcase.idx --out-flows-list selected_flows.csv --force
```

## Command reference

### Syntax

Supported forms:

```text
pcap-flow-lab flows <input> [options]
pcap-flow-lab flows --input <input> [options]
```

Help:

```text
pcap-flow-lab flows --help
pcap-flow-lab flows -h
```

### Supported inputs

`flows` accepts:

- PCAP captures;
- PCAPNG captures;
- Pcap Flow Lab indexes.

You can provide the input either:

- as a positional path;
- or with `--input <path>`.

These forms are mutually exclusive. Do not use both in the same invocation,
even if both paths point to the same file.

### Selection and filtering

Supported selection and filtering options:

| Option | Meaning |
| --- | --- |
| `--flow-number <N>` | Select one one-based canonical flow. |
| `--flow-numbers <ranges>` | Select inclusive one-based ranges such as `1-10,24,31-35`. |
| `--filter <text>` | Apply case-insensitive text matching across the verified flow fields. |
| `--limit <N>` | Limit the logical result flow count after selection, filtering, and sorting. |

Verified filter fields:

- family text;
- protocol text;
- detected protocol text;
- service text;
- endpoint addresses;
- endpoint strings;
- port numbers as text.

### Sort keys

Supported sort form:

```text
--sort <field>:<asc|desc>
```

Supported keys:

| Key | Meaning |
| --- | --- |
| `number` | Canonical flow number order. |
| `protocol` | Case-insensitive `Protocol` text order. |
| `service` | Case-insensitive `Service` text order. |
| `endpoint-a` | Endpoint A address/port order. |
| `endpoint-b` | Endpoint B address/port order. |
| `packets` | Packet count order. |
| `bytes` | Original byte total order. |

Current tie behavior is stable and falls back to canonical flow number order.

### Options

| Option | Value | Description |
| --- | --- | --- |
| `--input` | `<path>` | Provide the input path explicitly instead of using a positional path. |
| `--settings` | `<settings.json>` | Apply supported raw-import settings during raw capture import. Invalid for index input. |
| `--flow-number` | `<N>` | Select one one-based canonical flow number. |
| `--flow-numbers` | `<ranges>` | Select one-based inclusive ranges such as `1-10,24,31-35`. |
| `--filter` | `<text>` | Apply case-insensitive flow-text filtering. |
| `--sort` | `<field>:<asc\|desc>` | Sort the selected flow set. |
| `--limit` | `<N>` | Limit the final logical flow result. |
| `--out-flows-list` | `<path>` | Export the final logical flow result as CSV. |
| `--progress` | `auto`, `on`, `off` | Control live open-progress reporting on `stderr`. |
| `--force` | none | Allow an existing export target to be overwritten. |
| `-h`, `--help` | none | Show flows-specific help and exit successfully. |

### Raw capture vs index

| Capability | Raw capture | Index |
| --- | --- | --- |
| List flows | Yes | Yes |
| Filter / sort / select | Yes | Yes |
| `--limit` | Yes | Yes |
| `--out-flows-list` | Yes | Yes |
| `--settings` | Yes | No |
| `--progress` | Yes | Yes |
| Uses existing stored flow inventory | No, inventory is built during import | Yes, inventory comes from the saved index |

For `flows`, an index is self-sufficient for flow metadata listing. This
command does not require `--source-capture`.

## Invalid combinations and errors

Important verified rules:

- positional input and `--input` cannot be combined;
- `--flow-number` and `--flow-numbers` are mutually exclusive;
- `--settings` is valid only for raw capture input;
- `--limit` must be a positive flow count;
- out-of-range canonical flow numbers fail instead of silently disappearing;
- unknown options are rejected instead of ignored.

Out-of-range selection behaves as an error. Current CLI wording reports:

```text
Requested flow number is outside the available canonical flow range
```

### Range, duplicate, and overlap behavior

Current verified behavior for `--flow-numbers`:

- ranges are inclusive;
- duplicates and overlaps are accepted in the input syntax;
- the resolved canonical selection is deduplicated before querying;
- the resolved canonical selection is ordered in ascending canonical-number
  order before later filter/sort/limit stages run.

For example, an input such as:

```text
--flow-numbers 1-2,2,4
```

resolves to canonical flows `1`, `2`, and `4`.

## Notes and limitations

Without an explicit `--limit`, `flows` renders only the first 25 rows in
stdout when more matches exist. That is a preview limit, not a logical result
limit.

So the current behavior is:

- stdout preview defaults to 25 rows;
- `Showing 25 of N flows.` appears when the preview is truncated;
- the CLI adds a hint to use `--limit` or `--out-flows-list`;
- the logical result remains complete unless you explicitly add `--limit`.

This distinction matters most when you export a CSV:

- preview truncation affects stdout only;
- explicit `--limit` affects both stdout and CSV export.

`flows` is a metadata-oriented command. It lists recognized flows, but it does
not inspect packet bytes or stream item bytes directly.

Progress, warnings, and export-status lines are written to `stderr`. The flow
table itself is written to `stdout`.

## Related commands

After `flows`, the most relevant follow-up commands are:

- `summary` for whole-input overview;
- `flow-info` for detailed analysis of one canonical flow;
- `packet-info` for packet-level inspection;
- `export-flows` for packet-data export based on flow selection.
